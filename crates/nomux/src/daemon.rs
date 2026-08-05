//! The session daemon: owns the PTY, the ring buffer and the listening socket.
//!
//! Single-threaded around `poll`, with at most one client (`IMPLEMENTATION.md`
//! § 6.4), so the poll set is small: the listener, the PTY master, the client, the
//! connection that has not greeted yet, the self-pipe a stop signal writes to, and —
//! when agent forwarding is on — the agent socket plus one entry per live channel.
//!
//! What this process does to *itself* on the way in is `startup`, none of it touching
//! session state.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nomux_proto::{
    ErrorCode, ExitKind, Frame, FrameType, Hello, HelloOk, Linger, PROTOCOL_VERSION,
    RESUME_FROM_START, WinSize,
};
use rustix::event::{PollFd, PollFlags, Timespec};

use crate::agent::{self, Agent, MAX_AGENT_CHANNELS};
use crate::conn::Conn;
use crate::linger;
use crate::pty::{self, Pty};
use crate::rundir::{SessionPaths, session_id_of};
use crate::startup::{arm_stop_signals, leave_login_session, release_startup_state};

/// Default ring capacity. See `DESIGN.md` § 10 — this bounds how long a
/// disconnect can last before scrollback is lost, and is multiplied by the
/// per-host session count, which [`MAX_SESSIONS`] is the backstop on.
const DEFAULT_RING_CAPACITY: usize = 4 << 20;

/// Environment override for the ring capacity, in bytes. Also what makes overflow
/// behaviour testable without generating megabytes of output.
const RING_BYTES_ENV: &str = "NOMUX_RING_BYTES";

/// Largest ring this daemon will honour, whatever [`RING_BYTES_ENV`] asks for.
///
/// `VecDeque::with_capacity` answers a request it cannot serve by aborting the
/// process, so a value mistyped *upwards* would cost the session rather than the
/// tuning (`IMPLEMENTATION.md` § 4).
const MAX_RING_CAPACITY: usize = 1 << 30;

/// Resolves the ring capacity, honouring [`RING_BYTES_ENV`].
///
/// Nothing here refuses, per § 4. Zero in particular has to be filtered here rather
/// than passed on: `Ring::new` clamps it to one byte, and a ring that makes every
/// write a gap is not a tuning choice — the default is.
fn ring_capacity() -> usize {
    std::env::var(RING_BYTES_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .map_or(DEFAULT_RING_CAPACITY, |bytes| bytes.min(MAX_RING_CAPACITY))
}

/// Most sessions a run directory may already hold before this daemon refuses to add
/// another to it.
///
/// A backstop against a runaway, never a policy: eight times the limit `DESIGN.md`
/// § 5.1 puts at eight and leaves to the client, which is low enough that a broken one
/// cannot leave hundreds of shells on somebody else's host for [`IDLE_TIMEOUT`], a
/// week and a ring apiece. `IMPLEMENTATION.md` § 6.3 has the rest of the argument.
const MAX_SESSIONS: usize = 64;

/// How long a detached session survives before reaping itself.
///
/// One rule whether or not the child is still running (`IMPLEMENTATION.md` § 6.5): an
/// exit is no reason to throw away the status, the final output and the ring while the
/// client that asked for them is still on a train.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_days is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long to keep retrying `waitpid` after the PTY reports end of file before
/// reporting a status the daemon had to invent. What it bounds is how long a client
/// that is *watching* waits to be told anything at all.
const STATUS_GRACE: Duration = Duration::from_secs(2);

/// How often to retry while waiting for the child to become reapable. The wait is
/// normally over within microseconds; this only bounds the pathological case.
const STATUS_RETRY: Duration = Duration::from_millis(5);

/// Longest the poll loop sleeps with nothing else pending.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_hours is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TICK: Duration = Duration::from_secs(60 * 60);

/// How long to wait for the very first client before giving up. Without this a
/// daemon spawned by a connection that died mid-handshake would live forever.
const FIRST_ATTACH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the stale-socket probe waits before giving the id up as unanswerable.
///
/// Shorter than [`control`](crate::control)'s own probe, and not by taste: this one
/// runs while `<id>.lock` is held (§ 6.3), and a `kill` waiting on that lock gives up
/// after `SPAWN_LOCK_GRACE`. Matching that budget would let one wedged start consume
/// the whole of it, so the start yields first.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the listener stays out of the poll set after an `accept` that failed for
/// something other than a signal.
///
/// A descriptor shortage leaves the connection queued, so the listener goes on
/// reporting `POLLIN` and every pass answers it with the same failure. No timeout
/// helps — a readable descriptor in the set is what makes `poll` return immediately —
/// so the listener leaves the set for this long instead: short enough that a client on
/// the far side of a shortage that has just cleared does not notice, long enough that a
/// host under `ENFILE` is not made worse by every nomux daemon on it burning a core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Backlog for the session socket: as deep as this host allows.
///
/// `IMPLEMENTATION.md` § 6.3 has what `-1` asks the kernel for, why [`publish`] has
/// to restate it when it calls `listen` a second time, and why it must not restate it
/// as a literal.
const SOCKET_BACKLOG: libc::c_int = -1;

/// Fault injection: restores the pre-fix event ordering of § 6.4.1, where the
/// takeover was serviced before the client it was replacing.
///
/// Exists so the regression test that guards that ordering can be *shown* to fail on
/// the bug it describes, rather than merely passing on correct code; see
/// `scripts/verify-takeover-guard.sh`. A `const` rather than a `#[cfg]` block so both
/// orderings stay compiled and type-checked, and so the shipped binary is
/// byte-identical either way — the branch folds away.
const ACCEPT_BEFORE_READ: bool = cfg!(nomux_fault_injection);

/// Fault injection: pause before each `poll`, so a client's input and the takeover
/// that follows it arrive in the same wakeup.
///
/// The bug above bites only on that interleaving, which is otherwise a matter of
/// microseconds. `--cfg nomux_fault_settle` enables this alone, and the guard must
/// still *pass* under it, which is what proves the delay is not doing the work.
const SETTLE_BEFORE_POLL: bool = cfg!(nomux_fault_injection) || cfg!(nomux_fault_settle);

/// How long that pause is.
const FAULT_SETTLE: Duration = Duration::from_millis(20);

/// Stop accepting client input once this much is already queued for a PTY that is
/// not taking it.
///
/// `IMPLEMENTATION.md` § 4.1 has the argument: why neither of the cheaper answers is
/// available in this direction, and why the queue overshoots by the one frame that
/// crossed the cap.
const MAX_PENDING_INPUT: usize = 1 << 20;

/// The attached client, and the state that means nothing without one.
///
/// One `Option` rather than separate fields on the daemon: the four beside the
/// connection all belong to a *particular* one of them, so every arrival and departure
/// resets all four by moving the whole thing rather than by an agreement between fields
/// that has to be kept by hand.
#[derive(Debug)]
struct Attached {
    conn: Conn,
    /// Set once this connection's `Hello` has been answered.
    greeted: bool,
    /// Whether this connection has already been told the child exited. Per connection,
    /// and load-bearing now that the session outlives its child (§ 6.5): every attach
    /// after the fact must hear the status again, behind the replay that precedes it.
    exit_sent: bool,
    /// Output offset already queued to this connection.
    sent_through: u64,
    /// Whether a gap has been reported to this connection that the repaint (§ 4.3) has
    /// not answered yet. Cleared by [`Daemon::pump_output`] once this client holds the
    /// whole ring, rather than at the gap.
    repaint_due: bool,
}

impl Attached {
    /// Takes over the session with a connection that has just said `Hello`.
    ///
    /// `sent_through` is provisional: `on_hello` resolves where this client actually
    /// resumes from, which is the first thing that happens to it.
    const fn new(conn: Conn) -> Self {
        Self {
            conn,
            greeted: false,
            exit_sent: false,
            sent_through: 0,
            repaint_due: false,
        }
    }
}

/// Session state for the lifetime of the daemon process.
struct Daemon {
    paths: SessionPaths,
    listener: UnixListener,
    /// Read end of the self-pipe [`crate::startup::arm_stop_signals`] armed, or
    /// `None` on a host where it could not be armed at all.
    stop_pipe: Option<OwnedFd>,
    /// Set once a stop signal has been seen. The loop leaves on its next pass, so
    /// the exit goes out through `shutdown` like every other one.
    stopping: bool,
    ring: crate::ring::Ring,
    pty: Option<Pty>,
    client: Option<Attached>,
    /// A connection that has been accepted but has not said `Hello` yet, and so
    /// has not taken the session over. Usually a liveness probe from `list`.
    pending: Option<Conn>,
    /// Agent socket and its channels, once a session created with
    /// [`nomux_proto::HELLO_AGENT_FORWARD`] has bound one.
    agent: Option<Agent>,
    /// Where the child starts, captured before the daemon moved to `/`.
    child_dir: PathBuf,
    /// Whether `logind` will let this session outlive the user's logout, for
    /// `HelloOk`. Named for what it is rather than for the bare "linger" the wire
    /// spells it with, which is a word § 6.5 could also read as a grace period.
    logind_linger: Linger,
    /// Post-gap repaint policy, restated by each client's `Hello`.
    repaint_ctrl_l: bool,
    /// Authoritative input offset: everything below this has been accepted for the
    /// PTY and must never be applied twice.
    in_applied: u64,
    /// Input accepted but not yet written, because the PTY was not writable.
    pending_input: VecDeque<u8>,
    win: WinSize,
    /// When the PTY master reported end of file. Distinct from `exited`: the status is
    /// usually not readable yet at that moment.
    child_gone: Option<Instant>,
    /// The child's status, `None` until `waitpid` hands it over.
    exited: Option<(i32, ExitKind)>,
    /// When the listener may be polled again, after an `accept` that failed for a
    /// reason that will still be there next pass. `None` is the ordinary state.
    accept_retry: Option<Instant>,
    /// The same for the agent socket. Two deadlines rather than one because either
    /// listener can fail on its own, and holding the session socket out of the set
    /// over an agent's `EMFILE` is an attach that cannot get in.
    agent_accept_retry: Option<Instant>,
    /// When the session last lost its client, for idle reaping.
    ///
    /// The timestamp alone. *Whether* that deadline is armed is `client.is_none()`,
    /// so the two cannot disagree: a stamp left standing under a live client reaps
    /// the session out from under it at [`IDLE_TIMEOUT`], a week later and with
    /// nothing to point at.
    last_detach: Instant,
}

/// Runs the daemon for `session_id` until the child exits or the session is reaped.
///
/// `label` is the advisory display name for `nomux list` (`IMPLEMENTATION.md` § 6.6).
///
/// # Errors
///
/// Fails if the run directory or socket cannot be created, or if another daemon already
/// owns this session.
pub(crate) fn run(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let result = start(session_id, label);
    if let Err(err) = &result {
        // Also to syslog, not only through the `Err` the caller prints: a failure past
        // `release_startup_state` has no stderr left to reach anybody through, and the
        // daemon's failures belong in one place either way.
        crate::syslog::error(session_id, &err.to_string());
    }
    result
}

/// The body of [`run`], separated so that every way out of it is logged once.
fn start(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    paths.ensure_dir()?;

    // Held across the whole of claiming the id — the stale-socket probe, the bind,
    // the pidfile — because all of it decides on the evidence `list` and `kill` decide
    // on and must not interleave with them. Never blocking, and it goes ahead without
    // the lock rather than refusing, since on the ordinary path the holder is the
    // attach that started this process. `IMPLEMENTATION.md` § 6.3 has both arguments.
    let publishing = paths.try_lock_spawn();

    // Inside that locked region and before the bind, per § 6.3. Taking the lock is what
    // created `<id>.lock`, and `session_id_of` counts a bare one as a session — so a
    // refusal that left it behind would add a counted id on every rejected spawn of a
    // *new* one, ratcheting this backstop against itself until somebody ran `list`.
    // Removed only where the lock was taken, that being the only case where this
    // process created the file, and while it is still held, which is what § 6.3 asks of
    // that name: whoever locks next creates a fresh one, and no unlink follows this to
    // land on the session they bring up.
    let dir = crate::rundir::run_dir()?;
    if at_session_ceiling(&dir, paths.id()) {
        if publishing.is_some() {
            drop(fs::remove_file(dir.join(format!("{}.lock", paths.id()))));
        }
        return Err(io::Error::new(
            io::ErrorKind::QuotaExceeded,
            format!(
                "{} already holds {MAX_SESSIONS} sessions, which is as many as one host \
                 will run: `nomux list` collects the ones that have stopped, and \
                 `nomux kill <id>` ends one that has not",
                dir.display()
            ),
        ));
    }

    // The whole of the bind before the fork, and not only the refusal an id already in
    // use earns: past § 6.2's fork the process a caller is waiting on has already
    // `_exit`ed with a status of its own, so every errno after it reads as success.
    // `ssh -t host 'nomux daemon <id>'` is exactly the shape that forks, so a session
    // that never started would be a session reported as started.
    let listener = bind_socket(&paths)?;

    // Past the bind nothing can be reported to anybody, for that same reason, and
    // `<id>.sock` is on disk besides — so a failure there must not leave the id claimed
    // by a process that is not going to serve it. One fallible region rather than a
    // cleanup per call site: whatever fails inside [`publish`], what it published goes.
    let stop_pipe = match publish(&paths, &listener, label) {
        Ok(stop_pipe) => stop_pipe,
        Err(err) => {
            // Released first, because `unlink_all` takes this same lock and `flock`
            // conflicts between two open descriptions of one file even within a
            // process — collecting while still holding it would collect nothing. It
            // then skips the collection outright if somebody took the lock in between,
            // which is § 6.6's rule: what is left is a socket whose `connect` is
            // refused, which every mode already reads as stale.
            drop(publishing);
            paths.unlink_all();
            return Err(err);
        }
    };
    // Released the instant the id is published, and never carried into the event
    // loop: `kill` waits two seconds for this lock and then reports a session it
    // could not remove (§ 6.6), so a daemon still holding it would be one nothing
    // could stop.
    drop(publishing);

    // Everything above resolved its paths already, so the daemon can let go of the
    // directory it inherited from the attaching connection (§ 6.2): holding it would
    // keep a removable or network mount busy for as long as the session lives, which
    // could be days. The child does not follow — it starts in the user's home.
    let child_dir = pty::child_dir(std::env::current_dir().ok().as_deref());
    release_startup_state();

    let mut daemon = Daemon {
        paths,
        listener,
        stop_pipe,
        stopping: false,
        ring: crate::ring::Ring::new(ring_capacity()),
        pty: None,
        client: None,
        pending: None,
        agent: None,
        child_dir,
        logind_linger: linger::detect(),
        repaint_ctrl_l: false,
        in_applied: 0,
        pending_input: VecDeque::new(),
        win: WinSize::default(),
        child_gone: None,
        exited: None,
        accept_retry: None,
        agent_accept_retry: None,
        last_detach: Instant::now(),
    };

    // The first thing said from the far side of `release_startup_state`, and the only
    // record that this session ever existed once its run files are gone.
    crate::syslog::info(session_id, "started");
    let result = daemon.event_loop();
    // `None` where the loop ended for a reason that is not one of its stop
    // conditions, which is `event_loop` returning on a failed `poll`.
    let reason = daemon.stop_reason().unwrap_or("the event loop ended");
    crate::syslog::info(session_id, &format!("exiting: {reason}"));
    daemon.shutdown();
    result
}

/// Hands the id to the process that will actually serve it: § 6.2's detachment, the
/// stop signals, and the two files `list` and `kill` read.
///
/// One region because everything in it runs past the bind, where a failure can no
/// longer be reported to the caller waiting on the far side of § 6.2's fork — so
/// [`start`] has one place to undo rather than a cleanup at each step.
///
/// # Errors
///
/// Propagates the failure to write `<id>.pid`, and only that: a daemon sharing a login
/// session, one without a stop pipe and one without a label in `list` are worse daemons
/// rather than reasons to have no session.
fn publish(
    paths: &SessionPaths,
    listener: &UnixListener,
    label: Option<&str>,
) -> io::Result<Option<OwnedFd>> {
    // Before the pidfile, so the pid `nomux kill` reads belongs to the process that
    // survives.
    leave_login_session();
    // That process then claims the socket it inherited, for the backlog: `listen`
    // installs one rather than keeping the one in force, so the fork would otherwise
    // leave the queue at whatever the parent asked for (§ 6.2, § 6.3). It also
    // re-stamps `SO_PEERCRED`, which nothing reads now that § 6.6 identifies a daemon
    // from `<id>.pid` alone. A failure is discarded rather than propagated: a queue at
    // the wrong depth is not a reason to refuse a session that is ready to serve.
    //
    // SAFETY: `listen` is passed a descriptor `listener` owns and keeps open across
    // the call, and a backlog. `UnixListener` has no safe spelling of a second
    // `listen`, and rustix's would mean adding its `net` feature to the whole crate.
    let _ = unsafe { libc::listen(listener.as_raw_fd(), SOCKET_BACKLOG) };

    // Before the pidfile, because that file is what `nomux kill` (§ 6.6) reads to find
    // this process, so arming after it would leave a window where the signal it sends
    // lands on the default disposition and the child's process group outlives the
    // daemon. And after the fork above, so that a parent leaving through `_exit` cannot
    // answer a signal by writing a byte into the pipe the child inherits.
    let stop_pipe = arm_stop_signals().ok();

    paths.write_pid()?;
    if let Some(label) = label {
        // Advisory: a session is worth more than its name in a listing.
        drop(paths.write_label(label));
    }
    Ok(stop_pipe)
}

/// Binds the session socket, replacing a stale one.
///
/// A socket whose `connect` is refused belongs to a dead daemon; anything else —
/// including `EACCES` — is left alone, removing it being how a live session belonging
/// to somebody else's run gets destroyed.
fn bind_socket(paths: &SessionPaths) -> io::Result<UnixListener> {
    let path = paths.socket();
    match crate::rundir::connect_within(&path, PROBE_TIMEOUT) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("session {} is already running", paths.id()),
            ));
        }
        // Nothing is listening either way — the same evidence a collection decides on
        // one `connect` earlier (§ 6.6). Split inside rather than into two arms because
        // only the refused half leaves a socket file behind to replace, and an absent
        // name must not be unlinked on the chance somebody has just created one there.
        Err(err) if crate::rundir::nothing_is_listening(&err) => {
            if err.kind() == io::ErrorKind::ConnectionRefused {
                // Forced here because there is nowhere else it can be forced from: the
                // probe above and the removal below are two syscalls on one name, so
                // the test for losing that race has to be inside the window.
                #[cfg(test)]
                tests::collect_the_stale_socket(&path);
                // Losing that race is ordinary, and the file being gone is the state
                // this call exists to reach: propagating the `ENOENT` would refuse a
                // perfectly startable session over a socket that is gone either way.
                if let Err(err) = fs::remove_file(&path)
                    && err.kind() != io::ErrorKind::NotFound
                {
                    return Err(err);
                }
            }
        }
        Err(err) => return Err(err),
    }

    // Only the socket is replaced when an id is rebound, and a `<id>.pid` outliving it
    // is what lets `attach`'s wait for that path to *exist* be satisfied by the dead
    // daemon's number — after which a `kill` taking the spawn lock finds a live socket
    // and a stale pid at once, and signals an unrelated process of the user's. Here
    // rather than after the `bind`, so there is no window: past the match above any
    // pidfile beside the socket is a dead daemon's by the same evidence that licensed
    // removing it, and a live session took the early return.
    paths.clear_pid();

    let listener = crate::rundir::bind_socket_private(&path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Whether `dir` already holds [`MAX_SESSIONS`] sessions other than `mine`.
///
/// `IMPLEMENTATION.md` § 6.3 has the policy: why names are counted rather than sockets
/// probed, why `mine` never counts against itself, and why a directory that cannot be
/// read is not a refusal. Through [`session_id_of`] because that is the rule `list`
/// discovers sessions with (§ 6.6), in the module that owns the layout.
fn at_session_ceiling(dir: &Path, mine: &str) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    let mut ids: Vec<String> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(id) = session_id_of(&path) else {
            continue;
        };
        if id == mine || ids.iter().any(|known| known == id) {
            continue;
        }
        ids.push(id.to_owned());
        if ids.len() >= MAX_SESSIONS {
            return true;
        }
    }
    false
}

/// What one entry of the poll set belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The session socket, where clients arrive.
    Listener,
    /// Read end of the self-pipe a stop signal writes to.
    Signal,
    /// The PTY master.
    Pty,
    /// The attached client.
    Client,
    /// A connection that has not greeted yet.
    Pending,
    /// The agent socket, where the child's `ssh-agent` connections arrive.
    AgentListener,
    /// One proxied agent connection, by channel id rather than by index: the table
    /// can lose an entry while this iteration is still dispatching.
    AgentChannel(u32),
}

/// Every source that appears in the poll set at most once, in the order
/// [`Daemon::watches`] registers them.
///
/// The list is what registers them — `watches` walks it and asks
/// [`Daemon::watch_for`] about each — so a seventh source cannot be *polled* without
/// being added here, which cannot be done without changing the length this declares
/// and so [`POLL_SLOTS`].
const SINGLE_SOURCES: [Source; 6] = [
    Source::Listener,
    Source::Signal,
    Source::Pty,
    Source::Client,
    Source::Pending,
    Source::AgentListener,
];

/// Slots the poll set can ever need at once: [`SINGLE_SOURCES`] plus one per agent
/// channel, which `Agent::accept` caps at [`MAX_AGENT_CHANNELS`].
const POLL_SLOTS: usize = SINGLE_SOURCES.len() + MAX_AGENT_CHANNELS as usize;

/// What one `poll` came back with: the readiness of each source in the order
/// [`Daemon::watches`] registered them, and how many of the slots it used.
type Ready = ([(Source, PollFlags); POLL_SLOTS], usize);

impl Daemon {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut scratch = Vec::new();
        let mut read_buf = vec![0u8; 64 * 1024];

        loop {
            if self.stop_reason().is_some() {
                return Ok(());
            }
            self.poll_once(&mut read_buf, &mut scratch)?;
            // Given back at the end of the pass that grew it, so that one large
            // `Input` does not leave a `MAX_PAYLOAD` — 256 KiB — held for a session
            // that can last a week. Cleared first because `shrink_to` will not go
            // below the length and `take_frame` leaves the last payload here.
            // `read_buf` is left alone because every pass reads into it, so giving
            // that back would be an allocation per pass rather than one saved.
            scratch.clear();
            scratch.shrink_to(0);
        }
    }

    /// How long this session may stay clientless before reaping itself.
    ///
    /// Shared by `stop_reason` and `poll_timeout` so the deadline and the wakeup that
    /// enforces it cannot drift apart — a limit nothing wakes up for is documentation
    /// rather than behaviour.
    ///
    /// The test is whether a PTY was ever *started*, not whether its child is still
    /// running: `self.pty` outlives the child, so a session that has served somebody
    /// stays on the week whatever became of the shell (§ 6.5).
    const fn detach_limit(&self) -> Duration {
        if self.pty.is_none() {
            FIRST_ATTACH_TIMEOUT
        } else {
            IDLE_TIMEOUT
        }
    }

    /// When idle reaping falls due, if the session is clientless.
    ///
    /// An `Instant` rather than an `elapsed() >= limit` predicate, and derived rather
    /// than stored, for the reason [`Daemon::detach_limit`] gives: `stop_reason` needs
    /// the rule as a predicate and `poll_timeout` needs it as a duration. The one
    /// deadline there is, the child's exit not being a second beside it (§ 6.5).
    fn detach_deadline(&self) -> Option<Instant> {
        self.client
            .is_none()
            .then(|| self.last_detach + self.detach_limit())
    }

    /// Whether the PTY queue has reached [`MAX_PENDING_INPUT`].
    fn input_is_saturated(&self) -> bool {
        self.pending_input.len() >= MAX_PENDING_INPUT
    }

    /// Queues a control frame for the attached client, if there is one.
    ///
    /// Most control frames are answers — a `Pong` per `Ping`, an `InputAck` per
    /// `Input` — and a session with nobody attached simply has nowhere to put them.
    fn tell_client(&mut self, frame: &Frame<'_>) {
        if let Some(client) = self.client.as_mut() {
            client.conn.send(frame);
        }
    }

    /// Why the daemon should stop, if it should — `None` is "keep going".
    ///
    /// One function rather than a predicate beside a matching list of reasons, so the
    /// sentence in syslog names the rule that actually fired — and a session that
    /// outlived its child names that too, since the run files are gone by the time
    /// anyone reads it and this is the only record that the shell had already
    /// finished.
    fn stop_reason(&self) -> Option<&'static str> {
        if self.stopping {
            Some("signalled")
        } else if self
            .detach_deadline()
            .is_some_and(|at| Instant::now() >= at)
        {
            Some(if self.pty.is_none() {
                "no client ever attached"
            } else if self.child_gone.is_some() {
                "idle with no client, the child having exited"
            } else {
                "idle with no client"
            })
        } else {
            None
        }
    }

    /// What to ask `poll` about `source`, or `None` where it is not in the set now.
    ///
    /// Exhaustive over [`Source`] on purpose: that is the half of [`SINGLE_SOURCES`]'s
    /// invariant this function carries.
    fn watch_for(&self, source: Source) -> Option<(BorrowedFd<'_>, PollFlags)> {
        match source {
            // Out of the set while an `accept` that failed is being waited out, which
            // is the only way to stand back from it ([`ACCEPT_BACKOFF`]).
            Source::Listener => self
                .accept_retry
                .is_none()
                .then(|| (self.listener.as_fd(), PollFlags::IN)),
            Source::Signal => Some((self.stop_pipe.as_ref()?.as_fd(), PollFlags::IN)),
            // Dropped from the set once the child is gone: the master reports `HUP`
            // from then on and would spin the loop at full tilt for the rest of the
            // session's life — up to [`IDLE_TIMEOUT`] (§ 6.5) — having nothing left to
            // read. `on_child_exit` empties the input queue for the same reason: with
            // the master out of the set, `write_pty` will never run again to drain it.
            Source::Pty => {
                let pty = self.pty.as_ref().filter(|_| self.child_gone.is_none())?;
                let mut flags = PollFlags::IN;
                if !self.pending_input.is_empty() {
                    flags |= PollFlags::OUT;
                }
                Some((pty.master(), flags))
            }
            Source::Client => {
                let client = self.client.as_ref()?;
                // Held out of `POLLIN` while the PTY queue is full — § 4.1's back
                // pressure, of which this is only the throttling half: what *bounds*
                // the queue is `read_client` declining to decode past the cap.
                let mut flags = if self.input_is_saturated() {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                // Ring bytes still owed count as wanting to write, not just bytes
                // already encoded: `pump_output` stops at `MAX_PENDING_WRITE`, so a
                // large replay routinely ends a pass with the queue drained and the
                // ring still ahead. The `OutputAck` that papers over it is advisory
                // (§ 3), so it cannot be what the loop relies on.
                if client.conn.wants_write()
                    || (client.greeted && client.sent_through < self.ring.end())
                {
                    flags |= PollFlags::OUT;
                }
                // Registered even when the mask is empty, since `HUP` and `ERR` are
                // reported whatever it says and are the only way to hear that a
                // held-back peer has died (§ 4.1). `poll_once` answers that wakeup by
                // letting the client go, so it cannot repeat.
                Some((client.conn.stream().as_fd(), flags))
            }
            Source::Pending => Some((self.pending.as_ref()?.stream().as_fd(), PollFlags::IN)),
            // Out of the set on the same terms as the session listener above, and for
            // the same failure.
            Source::AgentListener => {
                let agent = self
                    .agent
                    .as_ref()
                    .filter(|_| self.agent_accept_retry.is_none())?;
                Some((agent.listener(), PollFlags::IN))
            }
            // Never asked for — `watches` takes the channels from the agent's own
            // table, with a mask that depends on the channel — and here only for the
            // exhaustiveness above.
            Source::AgentChannel(_) => None,
        }
    }

    /// Everything the poll set watches, in the order it is registered, written into
    /// `sources` and `fds` in step. Returns how many slots were used.
    ///
    /// Named rather than positional because the set is variable-length, and index
    /// arithmetic there would silently apply one fd's readiness to another. Into the
    /// caller's arrays rather than a `Vec` because this is the steady-state relay loop
    /// and the set has a compile-time maximum ([`POLL_SLOTS`]).
    fn watches<'a>(
        &'a self,
        sources: &mut [Source; POLL_SLOTS],
        fds: &mut [PollFd<'a>; POLL_SLOTS],
    ) -> usize {
        let mut len = 0;
        let mut watch = |source, fd, flags| {
            // Through `get_mut` rather than by index. The budget cannot be reached, so
            // this is only about what the unreachable state may cost: a wakeup missed
            // rather than a write past the end of the caller's frame.
            if let (Some(slot), Some(entry)) = (sources.get_mut(len), fds.get_mut(len)) {
                *slot = source;
                *entry = PollFd::from_borrowed_fd(fd, flags);
                len += 1;
            }
        };

        for source in SINGLE_SOURCES {
            if let Some((fd, flags)) = self.watch_for(source) {
                watch(source, fd, flags);
            }
        }

        if let Some(agent) = self.agent.as_ref() {
            let saturated = self
                .client
                .as_ref()
                .is_some_and(|client| client.conn.is_write_saturated());
            for (id, fd, wants_write, wants_read) in agent.watches() {
                // A saturated client is the one back pressure signal available: stop
                // draining agent sockets until the queue it feeds has room, and the
                // bytes wait in the kernel's socket buffer where the peer blocks on
                // them.
                let mut flags = if saturated || !wants_read {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                if wants_write {
                    flags |= PollFlags::OUT;
                }
                if !flags.is_empty() {
                    watch(Source::AgentChannel(id), fd, flags);
                }
            }
        }
        len
    }

    /// Blocks until something in the poll set is ready, and returns what.
    ///
    /// Split out so that [`Daemon::poll_once`] is the § 6.4.1 ordering policy and
    /// nothing else. `None` is the `EINTR` case, which is not an event. Confining the
    /// borrows of `self` here is what lets the caller take `&mut self` freely while
    /// handling what this returns, so the readiness comes back by value.
    fn wait(&self) -> io::Result<Option<Ready>> {
        let mut sources = [Source::Listener; POLL_SLOTS];
        let mut fds = std::array::from_fn(|_| {
            PollFd::from_borrowed_fd(self.listener.as_fd(), PollFlags::empty())
        });
        let len = self.watches(&mut sources, &mut fds);

        let timeout = self.poll_timeout();
        match rustix::event::poll(fds.get_mut(..len).unwrap_or(&mut []), Some(&timeout)) {
            Ok(_) => {}
            // A stop signal delivered while blocked here lands as `EINTR`, and
            // `poll` is never restarted whatever the handler's flags say. That
            // costs nothing: the handler wrote its byte before the syscall
            // returned, so coming round the loop finds the pipe readable and
            // the notification outlives being dropped on the floor here.
            Err(rustix::io::Errno::INTR) => return Ok(None),
            Err(err) => return Err(err.into()),
        }

        let mut ready = [(Source::Listener, PollFlags::empty()); POLL_SLOTS];
        for (slot, (source, fd)) in ready.iter_mut().zip(sources.iter().zip(fds.iter())) {
            *slot = (*source, fd.revents());
        }
        Ok(Some((ready, len)))
    }

    fn poll_once(&mut self, read_buf: &mut [u8], scratch: &mut Vec<u8>) -> io::Result<()> {
        if SETTLE_BEFORE_POLL {
            std::thread::sleep(FAULT_SETTLE);
        }
        // Cleared here rather than tested at each of the two places each is read, so
        // "the listener is back in the set" and "there is no wakeup left to arrange for
        // it" cannot disagree.
        let now = Instant::now();
        for retry in [&mut self.accept_retry, &mut self.agent_accept_retry] {
            if retry.is_some_and(|at| now >= at) {
                *retry = None;
            }
        }
        let Some((ready, used)) = self.wait()? else {
            return Ok(());
        };
        let events = ready.get(..used).unwrap_or(&[]);
        let revents = |want: Source| {
            events
                .iter()
                .find(|(source, _)| *source == want)
                .map_or(PollFlags::empty(), |(_, flags)| *flags)
        };
        let readable = PollFlags::IN | PollFlags::HUP | PollFlags::ERR;

        // A stop request rather than an event to service, so nothing is read from the
        // pipe: the byte says only that a signal arrived, and the loop leaves on its
        // next pass, too soon for a permanently readable descriptor to spin on. The
        // rest of this iteration still runs, so whatever the client was owed is queued
        // before `shutdown` flushes it.
        if revents(Source::Signal).intersects(readable) {
            self.stopping = true;
        }

        let pty_events = revents(Source::Pty);
        let client_events = revents(Source::Client);
        if pty_events.intersects(PollFlags::OUT) {
            self.write_pty();
        }
        if pty_events.intersects(readable) {
            self.read_pty(read_buf);
        }
        // Frames the input cap left undecoded are not announced a second time, so
        // draining the queue just above is itself the event that lets them through.
        let client_ready = client_events.intersects(readable)
            || (!self.input_is_saturated()
                && self
                    .client
                    .as_ref()
                    .is_some_and(|client| client.conn.has_buffered_input()));
        // Before the greeting, always (§ 6.4.1): one poll can report both a readable
        // client and a `Hello` from its replacement.
        if !ACCEPT_BEFORE_READ && client_ready {
            self.read_client(scratch)?;
        }
        // `HUP` is the peer gone for good, and reading is not an answer to it while
        // input is being held back: nothing will consume what is left in the socket, so
        // `fill` never reaches the zero-length read that would notice. Letting the
        // client go here is what arms the idle deadline and fails the agent's waiting
        // callers now rather than at reattach (§ 6.7).
        if client_events.intersects(PollFlags::HUP | PollFlags::ERR) && self.client.is_some() {
            self.drop_client();
        }
        // Nothing arriving now can be served: the loop leaves on its next pass, and a
        // takeover here would spend a second bounded 500 ms flush on evicting a client
        // the daemon is about to drop anyway, past § 6.5's shutdown budget. Whoever
        // knocked finds the socket unlinked and spawns a session of their own.
        if !self.stopping {
            if revents(Source::Pending).intersects(readable) {
                self.read_pending(scratch)?;
            }
            // The same `IN | HUP | ERR` every other source is tested with. A listener
            // reporting `ERR` alone is not a state `AF_UNIX` is known to reach, but
            // `contains(IN)` would leave it in the set with nothing servicing it: a
            // `poll` that returns at once on every pass and no backoff armed, which is
            // the one shape [`ACCEPT_BACKOFF`] exists to make unreachable.
            if revents(Source::Listener).intersects(readable) {
                self.accept();
            }
        }
        if ACCEPT_BEFORE_READ && client_ready {
            self.read_client(scratch)?;
        }

        for (source, flags) in events {
            if let Source::AgentChannel(id) = *source {
                self.service_agent_channel(id, *flags, read_buf);
            }
        }
        // On the same terms as the session listener above, and for the same reason.
        if revents(Source::AgentListener).intersects(readable) {
            self.accept_agent();
        }

        // Immediately before the pump that turns a status into a frame, never at the
        // top of the loop: `poll_timeout` only clamps to `STATUS_RETRY` while the
        // status is still outstanding, so the pass that collects one would otherwise
        // sleep until something woke it before `pump_output` ran — and nothing can,
        // the master having left the poll set with the child. The session is on no
        // clock at all (§ 6.5), so that costs the client an answer until it sends
        // something.
        self.collect_status();
        self.pump_output();
        // Unconditional: `flush_some` on an empty queue makes no syscall, so asking
        // every pass costs nothing and there is no readiness test to get wrong.
        self.write_client();
        Ok(())
    }

    /// Sleeps until the next deadline that could stop the daemon, and no longer.
    ///
    /// Every reaping rule is checked when `poll` returns, so a rule with no wakeup
    /// behind it does not hold: waiting an hour before noticing a 30-second timeout
    /// makes that timeout documentation rather than behaviour. The hourly floor is the
    /// backstop for a session that is simply quiet.
    fn poll_timeout(&self) -> Timespec {
        let mut remaining = self.detach_deadline().map_or(IDLE_TICK, |at| {
            at.saturating_duration_since(Instant::now()).min(IDLE_TICK)
        });
        // The child has let go of the terminal but `waitpid` has not produced its
        // status yet; come back promptly rather than reporting one this invented.
        if self.child_gone.is_some() && self.exited.is_none() {
            remaining = remaining.min(STATUS_RETRY);
        }
        // A listener is out of the poll set until its own deadline passes
        // (`Daemon::accept`, `Daemon::accept_agent`), so nothing else is left to wake
        // the loop up and put it back.
        if let Some(at) = [self.accept_retry, self.agent_accept_retry]
            .into_iter()
            .flatten()
            .min()
        {
            remaining = remaining.min(at.saturating_duration_since(Instant::now()));
        }
        Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        }
    }

    /// Takes a new connection, which waits as `pending` until it says `Hello`.
    ///
    /// Connecting is *not* attaching (`IMPLEMENTATION.md` § 6.4): `nomux list` and the
    /// § 6.3 spawn race both probe every socket with a bare `connect`, and counting that
    /// as a takeover would evict the user from every session merely for listing them.
    ///
    /// Never fails, per § 6.4.1. Transient is not the same as *gone*, though, which is
    /// what [`ACCEPT_BACKOFF`] is for — and both halves hold for the agent listener too.
    fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                // One at a time: an unanswered probe is replaced rather than
                // accumulated, so nobody can queue connections at the daemon.
                Ok((stream, _)) => {
                    self.pending = Conn::new(stream).ok();
                    return;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                // Named rather than folded in with the rest, the way every other
                // non-blocking call site in this tree names it: an empty backlog is an
                // ordinary answer and not something to stand back from, so it must not
                // share an arm with a descriptor shortage.
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.accept_retry = Some(Instant::now() + ACCEPT_BACKOFF);
                    return;
                }
            }
        }
    }

    /// Reads from the connection that has not attached yet.
    ///
    /// Its first frame decides everything: a `Hello` promotes it and evicts whoever held
    /// the session, anything else is a protocol error, and an EOF was a liveness probe.
    fn read_pending(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        // A greeting arrives once per attach, so this buffer is not worth sharing, and
        // keeping it separate leaves `scratch` free for the outgoing client's final
        // drain below, which happens while the `Hello` is still borrowed.
        let mut buf = Vec::new();
        let Some(pending) = self.pending.as_mut() else {
            return Ok(());
        };
        if pending.fill().is_err() {
            self.pending = None;
            return Ok(());
        }
        let ty = match pending.take_frame(&mut buf) {
            Ok(Some(ty)) => ty,
            Ok(None) => {
                if pending.is_eof() {
                    self.pending = None;
                }
                return Ok(());
            }
            Err(_) => {
                self.reject_pending(ErrorCode::Protocol, "unparseable frame header");
                return Ok(());
            }
        };
        if ty != FrameType::Hello {
            self.reject_pending(
                ErrorCode::Protocol,
                "first frame from a client must be Hello",
            );
            return Ok(());
        }
        let Ok(Frame::Hello(hello)) = Frame::decode(ty, &buf) else {
            self.reject_pending(ErrorCode::Protocol, "unparseable Hello");
            return Ok(());
        };
        // Before the eviction below, not after: a `Hello` this daemon cannot answer is
        // refused on its own terms and the session keeps the client it has (§ 6.4).
        // Checked inside `on_hello` — which runs once the takeover has already
        // happened — a newer client's *failed* handshake threw the working one off with
        // `Error{TAKEOVER}` and dropped the newcomer too, leaving nobody attached and no
        // reconnect coming. `on_hello` keeps its own copy for the other caller, where a
        // `Hello` arrives on a connection that is already the client.
        if hello.protocol != PROTOCOL_VERSION {
            self.reject_pending(ErrorCode::Version, "protocol version mismatch");
            return Ok(());
        }

        // Final drain of the outgoing connection: it may have written between the
        // poll and this moment, and input it already delivered must not be lost to
        // the takeover (§ 6.4.1).
        if !ACCEPT_BEFORE_READ && self.client.is_some() {
            drop(self.read_client(scratch));
        }
        // Hands the session over: the connection being replaced is usually one the
        // daemon has not yet noticed is dead (`IMPLEMENTATION.md` § 6.4). It leaves by
        // the same door as any other refusal, which also drops its agent channels — the
        // arriving client knows nothing of them, and their ids are never reissued. With
        // nobody attached this does nothing at all.
        self.reject(ErrorCode::Takeover, "another client attached");
        self.client = self.pending.take().map(Attached::new);
        self.on_hello(&hello)?;
        // Clients pipeline: input riding behind the `Hello` in the same read is
        // already buffered in the connection that was just promoted.
        self.read_client(scratch)
    }

    /// Turns away a connection that cannot have the session, leaving the session
    /// alone.
    ///
    /// The `code` is a parameter because not every refusal here is a protocol error: a
    /// version mismatch is the peer being from another release rather than misbehaving,
    /// and the client acts on the two differently (`DESIGN.md` § 6.4).
    fn reject_pending(&mut self, code: ErrorCode, message: &'static str) {
        if let Some(pending) = self.pending.take() {
            pending.send_last(&Frame::Error { code, message });
        }
    }

    fn read_pty(&mut self, buf: &mut [u8]) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        // [`pty::read_pty`] answers a stray errno with `Eof` rather than propagating
        // it, for the reason [`Daemon::write_pty`] gives about the other half.
        match pty::read_pty(pty.master(), buf) {
            // Always drain, attached or not: a full ring drops its oldest bytes,
            // but a PTY that is not read blocks the child on write.
            pty::Read::Data(n) => self.ring.push(buf.get(..n).unwrap_or(&[])),
            pty::Read::Eof => self.on_child_exit(),
            pty::Read::WouldBlock => {}
        }
    }

    fn write_pty(&mut self) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        // No PTY error ends the session, in either direction. § 6.4.1 says a failing
        // *client* socket is never propagated out of the event loop, and neither half
        // of a PTY is the one place a stray errno may destroy the session this daemon
        // exists to keep. Linux does not appear to produce one on this side at all — a
        // write to a master whose slave has gone *succeeds* — so this is for the kernel
        // that answers differently.
        //
        // Whatever the errno, the child is gone or unreachable and the queue goes with
        // it, which is also what drops `PollFlags::OUT` from the master's mask. What
        // this must not do is record the exit: `child_gone` is what drops the master
        // from the poll set, and the read side can still be holding everything the
        // child wrote on its way out — so stamping it here would end the session on
        // output that was still readable, the one thing § 9 forbids without a `Gap`.
        if crate::nbio::drain_to(&mut self.pending_input, pty.master()).is_err() {
            self.pending_input.clear();
        }
        // Given back on the way through empty, because the capacity that is left
        // otherwise outlives the client that caused it and is held for the rest of the
        // session — one paste into a child that has stopped reading is
        // `MAX_PENDING_INPUT` plus a frame, 1.25 MiB, kept for up to seven days. Only
        // where it has gone empty: the master asks for `POLLOUT` exactly while this
        // queue is non-empty, so the pass that empties it is the last one here until
        // the client sends again, and the cost is an allocation and a free per
        // keystroke rather than per burst.
        if self.pending_input.is_empty() {
            self.pending_input.shrink_to(0);
        }
    }

    /// Records that the child has let go of the terminal.
    ///
    /// The stamp starts no clock (§ 6.5) and is kept for the two things that read it:
    /// `pump_output` licenses the `Exit` frame on it and measures `since_exit_secs`
    /// from it. No status is *invented* here and none is collected either — the master
    /// reports end of file while `waitpid` still answers "not yet", for about a third
    /// of exits on this kernel, so committing one here reports `exit 3` as `exit 0`.
    /// [`Daemon::collect_status`] runs later in this very pass and every pass after it.
    fn on_child_exit(&mut self) {
        if self.child_gone.is_none() {
            self.child_gone = Some(Instant::now());
        }
        // There is nothing left to apply it to, and — the stamp above having just
        // taken the master out of the poll set — nothing that would ever run
        // `write_pty` again to drain it. A queue standing at [`MAX_PENDING_INPUT`] at
        // this moment therefore stays there: `input_is_saturated` goes on holding the
        // client out of `POLLIN` and `read_client` goes on returning before it
        // decodes, so no `Ping` is answered, no `Detach` is seen and a fresh attach is
        // equally mute — for as long as somebody stays attached, which is a session
        // with no deadline at all (§ 6.5) and so one only `nomux kill` ends. The
        // capacity goes with the bytes, as it does in `write_pty`.
        self.pending_input.clear();
        self.pending_input.shrink_to(0);
        // The exit frame itself is left to `pump_output`, which sends it once the last
        // of the child's output has gone out. Announcing the exit ahead of the
        // words that caused it is how a client ends up closing the tab on a
        // transcript it never showed.
    }

    /// Collects the child's status once `waitpid` will give it up.
    ///
    /// Called every pass, and not only while the terminal has been let go of. The child
    /// can exit while something it started still holds the slave — `sleep 3600 &` and
    /// then `exit` — so a collection gated on end of file leaves the session's own child
    /// a zombie for the whole life of the session, nothing else reaping it.
    ///
    /// Collecting is not reporting: whether the client is *told* is
    /// [`Daemon::pump_output`]'s decision, gated on `child_gone` there, an `Exit` frame
    /// being a promise that the session's output is finished. What it costs is the
    /// child's pid, and this call is what makes [`Pty::pid_reissued`] load-bearing.
    fn collect_status(&mut self) {
        if self.exited.is_some() {
            return;
        }
        if let Some(status) = self
            .pty
            .as_mut()
            .and_then(|pty| pty.try_wait().ok().flatten())
        {
            self.exited = Some(pty::exit_parts(status));
        } else if self
            .child_gone
            .is_some_and(|gone_at| gone_at.elapsed() >= STATUS_GRACE)
        {
            // The child closed the terminal without exiting — a program that
            // daemonises itself does exactly this — so there is no status to report and
            // never will be, and the client is still owed an `Exit`.
            self.exited = Some((0, ExitKind::Exited));
        }
    }

    fn read_client(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        let Some(client) = self.client.as_mut() else {
            return Ok(());
        };
        if client.conn.fill().is_err() {
            // A connection failing is the normal case, not a daemon failure (§ 6.4.1).
            // Whatever that `fill` had already buffered goes with the connection,
            // undecoded: on AF_UNIX the bytes did arrive — the error is reported after
            // the last of them, not instead of them — so this is where the input § 3
            // calls unsafe is actually lost, rather than in the kernel. Deliberately,
            // the peer being gone and the client resending from `in_applied` anyway.
            self.drop_client();
            return Ok(());
        }

        loop {
            // The cap that actually bounds the queue (§ 4.1), and the reason it is
            // enforced here rather than only in the poll set: the takeover path
            // reaches this loop twice without passing through the poll set at all.
            if self.input_is_saturated() {
                // Returning rather than breaking, so the end-of-file test below is
                // skipped. A peer's end of file is not an answer to frames it is still
                // owed: `attach` shuts its write half down on stdin EOF and goes on
                // draining output (§ 7), so letting it go here would discard complete,
                // already-delivered `Input` frames, the one thing § 4.1 says is never
                // stranded in that buffer.
                //
                // Nothing wedges. What re-arms this loop is `poll_once`'s
                // `has_buffered_input` test once `write_pty` has taken some of the
                // queue, or `on_child_exit` emptying it outright when there is no
                // longer a `write_pty` to come. A peer that is gone for good still
                // goes, on the `HUP` a full close reports whatever the mask says.
                return Ok(());
            }
            let Some(client) = self.client.as_mut() else {
                return Ok(());
            };
            let ty = match client.conn.take_frame(scratch) {
                Ok(Some(ty)) => ty,
                Ok(None) => break,
                Err(_) => {
                    self.reject(ErrorCode::Protocol, "unparseable frame header");
                    return Ok(());
                }
            };
            let Ok(frame) = Frame::decode(ty, scratch) else {
                self.reject(ErrorCode::Protocol, "unparseable frame payload");
                return Ok(());
            };
            self.handle_frame(&frame)?;
        }

        if self
            .client
            .as_ref()
            .is_some_and(|client| client.conn.is_eof())
        {
            self.drop_client();
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: &Frame<'_>) -> io::Result<()> {
        match *frame {
            Frame::Hello(hello) => self.on_hello(&hello)?,
            Frame::Input { offset, data } => self.on_input(offset, data),
            Frame::Resize(win) => {
                self.win = win;
                if let Some(pty) = self.pty.as_ref() {
                    drop(pty.resize(win));
                }
            }
            // Empty on purpose, and load-bearing for it: `OutputAck` is advisory
            // (§ 3), and what the frame does is *arrive*, which wakes the loop and lets
            // a replay that stopped on a full socket resume.
            Frame::OutputAck => {}
            Frame::Ping { nonce } => self.tell_client(&Frame::Pong { nonce }),
            Frame::Detach => self.drop_client(),
            Frame::AgentData { chan, data } => {
                if let Some(agent) = self.agent.as_mut()
                    && !agent.deliver(chan, data)
                {
                    self.close_agent_channel(chan);
                }
            }
            Frame::AgentClose { chan } => {
                if let Some(agent) = self.agent.as_mut() {
                    agent.close_from_client(chan);
                }
            }
            _ => self.reject(ErrorCode::Protocol, "frame is not valid from a client"),
        }
        Ok(())
    }

    /// Binds the agent socket and spawns the child, on the `Hello` that creates the
    /// session.
    ///
    /// Separated from [`Daemon::on_hello`] because the two answer unrelated questions
    /// that merely arrive together: what this session *is*, decided once and never
    /// again, against where this particular client resumes from, decided on every
    /// attach.
    fn start_session(&mut self, hello: &Hello<'_>) -> io::Result<()> {
        // Only the creating `Hello` can turn forwarding on: `SSH_AUTH_SOCK` goes into
        // the child's environment, which cannot be changed afterwards (§ 5.3).
        if hello.agent_forward {
            match Agent::bind(&self.paths.agent()) {
                Ok(agent) => self.agent = Some(agent),
                // A session without an agent is worth having; one that refuses to start
                // is not. `HelloOk` reports the outcome only as a bare `agent: false`,
                // which tells the user who opted in per host nothing about why — so the
                // reason goes where every other degradation's does.
                Err(err) => {
                    crate::syslog::error(self.paths.id(), &format!("agent socket: {err}"));
                }
            }
        }
        let config = pty::Spawn {
            term: hello.term,
            win: hello.win,
            session_id: self.paths.id(),
            cwd: &self.child_dir,
            agent_sock: self.agent.as_ref().map(Agent::path),
        };
        match Pty::spawn(&config) {
            Ok(pty) => self.pty = Some(pty),
            Err(err) => {
                self.reject(ErrorCode::Internal, "failed to start the session shell");
                return Err(err);
            }
        }
        Ok(())
    }

    fn on_hello(&mut self, hello: &Hello<'_>) -> io::Result<()> {
        if hello.protocol != PROTOCOL_VERSION {
            self.reject(ErrorCode::Version, "protocol version mismatch");
            return Ok(());
        }
        self.win = hello.win;
        self.repaint_ctrl_l = hello.repaint_ctrl_l;

        if let Some(pty) = self.pty.as_ref() {
            drop(pty.resize(hello.win));
        } else {
            self.start_session(hello)?;
        }

        let base = self.ring.base();
        let resume_from = if hello.out_offset == RESUME_FROM_START {
            base
        } else {
            // Clamped at both ends. Above `end` is a client claiming output the session
            // never produced; left alone it would set `sent_through` past the stream
            // and the session would look dead until the child happened to catch up.
            // `min` then `max` rather than `clamp`, which asserts its bounds are
            // ordered: a shipping build compiles that assert down to a bare trap with
            // no message and no symbol, so the cheapest form that cannot abort wins.
            hello.out_offset.min(self.ring.end()).max(base)
        };
        // Not a field on the wire: `resume_from` above already decides it, and the
        // client derives the same answer from the two numbers it has (`HelloOk::gap`).
        let gap = resume_from > hello.out_offset;
        if let Some(client) = self.client.as_mut() {
            client.sent_through = resume_from;
            client.greeted = true;
            // Re-armed with the other two, because a second `Hello` on an established
            // connection rewinds the stream and asks for it again — and would otherwise
            // wait for ever for an `Exit` that was sent against the offsets it has just
            // abandoned.
            client.exit_sent = false;
            // Owed rather than issued here, so that an attach-time gap and a
            // mid-stream one share one repaint policy. Never cleared by a greeting:
            // a second `Hello` that reports no gap does not undo the one this
            // connection was already told about.
            client.repaint_due |= gap;
        }
        self.tell_client(&Frame::HelloOk(HelloOk {
            resume_from,
            in_applied: self.in_applied,
            win: self.win,
            linger: self.logind_linger,
            agent: self.agent.is_some(),
        }));
        Ok(())
    }

    /// Asks the child to redraw after a gap, by whichever means this client chose.
    ///
    /// `IMPLEMENTATION.md` § 4.3, which has why the choice belongs to the client — the
    /// only side that knows what is on the screen.
    fn repaint(&mut self) {
        if self.repaint_ctrl_l {
            // Through the same queue as client input rather than written straight to
            // the master, so it cannot overtake keystrokes already accepted or block on
            // a full PTY buffer. Not client input, so `in_applied` does not move.
            self.pending_input.push_back(0x0c);
        } else if let Some(pty) = self.pty.as_ref() {
            drop(pty.nudge_repaint(self.win));
        }
    }

    /// Applies client input exactly once.
    ///
    /// `in_applied` is authoritative. A client that lost an `InputAck` replays from an
    /// older offset, and the overlap is trimmed here rather than rejected — re-applying
    /// it would duplicate keystrokes, which is how a truncated `rm -rf` gets run.
    fn on_input(&mut self, offset: u64, data: &[u8]) {
        let end = offset.saturating_add(data.len() as u64);
        if offset > self.in_applied {
            self.reject(ErrorCode::InputGap, "input stream skipped ahead");
            return;
        }
        if end > self.in_applied {
            // Queued only while there is still a terminal to write it to. Past the
            // child's exit the master is out of the poll set and `write_pty` never
            // runs again, so anything queued here is queued for ever — and a client
            // that goes on sending refills what `on_child_exit` emptied, back to
            // [`MAX_PENDING_INPUT`] and back into the same wedge. `in_applied` moves
            // either way: the offset is a promise never to apply a byte twice
            // (§ 3), and a session whose child has gone is one where "applied" and
            // "discarded" are the same fate.
            if self.child_gone.is_none() {
                let skip = usize::try_from(self.in_applied - offset).unwrap_or(data.len());
                self.pending_input.extend(data.get(skip..).unwrap_or(&[]));
            }
            self.in_applied = end;
        }
        self.tell_client(&Frame::InputAck {
            applied_through: self.in_applied,
        });
    }

    fn pump_output(&mut self) {
        let base = self.ring.base();
        let end = self.ring.end();
        // Both, because a status is collected as soon as `waitpid` has one and that can
        // be long before the terminal is free: a backgrounded job holding the slave
        // keeps the session's output coming after its own shell has gone. The `Exit`
        // frame says the transcript is complete, so end of file on the master is what
        // licenses it — and that moment is what `since_exit_secs` is measured from.
        let exit = self.child_gone.zip(self.exited);
        let Some(client) = self.client.as_mut() else {
            return;
        };
        if !client.greeted {
            return;
        }
        if !client.conn.is_write_saturated() && client.sent_through < end {
            if client.sent_through < base {
                // Overflowed while this client was slow or away: the stream is
                // discontinuous and the client must reset its emulator.
                client.conn.send(&Frame::Gap {
                    new_base_offset: base,
                });
                client.sent_through = base;
                client.repaint_due = true;
            }

            // Both halves of the wrapped deque are addressed in one call, so the
            // second half's offset is only correct if the first was queued whole.
            // Stopping on short progress keeps that true; without it a saturated queue
            // labels the second half too low, which is a corrupted stream rather than
            // a slow one.
            for part in self.ring.slices_from(client.sent_through) {
                if part.is_empty() {
                    continue;
                }
                let want = client.sent_through + part.len() as u64;
                client.sent_through = client.conn.send_output(client.sent_through, part);
                if client.sent_through != want {
                    break;
                }
            }
        }

        // Last, and only once everything the child wrote has been queued. This one
        // guard is the whole of § 6.5's ordering promise, and what makes a client
        // arriving a week after the exit indistinguishable from one that watched it
        // happen: `on_hello` rewound `sent_through` to where this client resumes and
        // cleared `exit_sent`, and the ring still holds what the child said on its way
        // out.
        if !client.exit_sent
            && client.sent_through >= end
            && let Some((gone, (status, kind))) = exit
        {
            client.conn.send(&Frame::Exit {
                status,
                kind,
                since_exit_secs: u32::try_from(gone.elapsed().as_secs()).unwrap_or(u32::MAX),
            });
            client.exit_sent = true;
        }
        // Coalesced onto the moment this client holds the whole ring rather than
        // issued per gap: while the child is outrunning it, every redraw a repaint asks
        // for is output the next overflow discards, and asking again is what produced
        // that overflow (§ 4.3).
        let repainting = client.repaint_due && client.sent_through >= end;
        if repainting {
            client.repaint_due = false;
        }
        // Outside the borrow above, because the repaint may write to the PTY queue
        // rather than to the client. Mid-stream overflow is the same discontinuity as a
        // gap reported at attach time, and gets the same treatment.
        if repainting {
            self.repaint();
        }
    }

    /// Takes one agent connection off the listener and announces it.
    ///
    /// The backoff is [`ACCEPT_BACKOFF`]'s, for its reason and with its effect.
    fn accept_agent(&mut self) {
        // Serving means a client is attached *and* past its `Hello`: a frame sent
        // before `HelloOk` would arrive ahead of the handshake it answers.
        let serving = self.client.as_ref().is_some_and(|client| client.greeted);
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        match agent.accept(serving) {
            agent::Accept::Opened(chan) => self.tell_client(&Frame::AgentOpen { chan }),
            agent::Accept::Failed => {
                self.agent_accept_retry = Some(Instant::now() + ACCEPT_BACKOFF);
            }
            agent::Accept::Idle => {}
        }
    }

    /// Moves bytes for one agent channel in whichever direction is ready.
    fn service_agent_channel(&mut self, chan: u32, events: PollFlags, buf: &mut [u8]) {
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        if events.contains(PollFlags::OUT) {
            match agent.flush(chan) {
                agent::Flush::Open => {}
                // The client closed this one and has already forgotten it.
                agent::Flush::Finished | agent::Flush::Gone => {
                    let _ = agent.forget(chan);
                    return;
                }
                agent::Flush::Failed => {
                    self.close_agent_channel(chan);
                    return;
                }
            }
        }
        if !events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            return;
        }
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        match agent.read(chan, buf) {
            agent::Read::Data(n) => {
                let data = buf.get(..n).unwrap_or(&[]);
                if let Some(client) = self.client.as_mut() {
                    client.conn.send_agent_data(chan, data);
                }
            }
            agent::Read::Closed => self.close_agent_channel(chan),
            agent::Read::WouldBlock => {}
        }
    }

    /// Drops one channel and tells the client, which is holding the other end.
    ///
    /// Silent if the channel was already gone: the client can close one in the same
    /// poll iteration that its socket reports readable, and answering that with a close
    /// for a channel it has already forgotten is noise.
    fn close_agent_channel(&mut self, chan: u32) {
        if self.agent.as_mut().is_some_and(|agent| agent.forget(chan)) {
            self.tell_client(&Frame::AgentClose { chan });
        }
    }

    /// Pushes out what is queued, letting the connection go if it cannot be served.
    ///
    /// Neither condition here goes through [`Daemon::drop_client`], and neither wants
    /// its final flush: the socket has already failed, or the peer is past
    /// `ABANDON_PENDING_WRITE` and so is not reading *by definition* (§ 4.1), where
    /// `flush_final` would park the whole daemon for its 500 ms deadline. `drop_client`
    /// keeps the flush for the departures that have somewhere to go.
    fn write_client(&mut self) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        if client.conn.flush_some().is_err() || client.conn.is_write_hopeless() {
            self.client = None;
            self.on_detached();
        }
    }

    /// Sends a final `Error` and closes the connection.
    fn reject(&mut self, code: ErrorCode, message: &'static str) {
        if let Some(client) = self.client.take() {
            client.conn.send_last(&Frame::Error { code, message });
            self.on_detached();
        }
    }

    fn drop_client(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.conn.flush_final());
            self.on_detached();
        }
    }

    /// Stamps the session clientless. Everything that belonged to the departing
    /// connection went with it when the `Attached` was dropped.
    ///
    /// A child that has already exited changes nothing here, which is the point: the
    /// stamp is what the session is reaped on either way (§ 6.5), so the departure
    /// that leaves a finished session alone starts the same week as the one that
    /// leaves a running one.
    fn on_detached(&mut self) {
        self.last_detach = Instant::now();
        // Nothing can answer a signature request with the client gone, so the
        // waiting process should fail now rather than at reattach (§ 6.7).
        if let Some(agent) = self.agent.as_mut() {
            agent.forget_all();
        }
    }

    fn shutdown(&mut self) {
        self.drop_client();
        self.pending = None;
        if let Some(mut pty) = self.pty.take() {
            pty.terminate();
        }
        self.paths.unlink_all();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::Path;

    use super::*;

    use crate::scratch::Scratch;

    thread_local! {
        /// Whether the next stale socket [`bind_socket`] proves dead is to be removed
        /// out from under it. Per thread, because `cargo test` runs this crate's unit
        /// tests as threads of one process and nothing else may see the fault.
        static COLLECT_ONCE: Cell<bool> = const { Cell::new(false) };
    }

    /// A § 6.6 collection, forced into the window it cannot otherwise be scheduled
    /// into. Called from [`bind_socket`], which says why it has to be.
    pub(super) fn collect_the_stale_socket(path: &Path) {
        if COLLECT_ONCE.replace(false) {
            drop(fs::remove_file(path));
        }
    }

    /// Regression: losing the race to remove a stale socket must not turn a session
    /// that is perfectly startable into one that refuses to start.
    ///
    /// A `list` collects a dead session on exactly the evidence `bind_socket`
    /// acts on — a `connect` that was refused — so the two reach for the same file
    /// and the collection can get there first. What is left then is the state
    /// `bind_socket` was trying to reach, and it used to answer it with the
    /// `ENOENT` from its own `remove_file`, which `daemon::start` propagates: no
    /// session, because somebody else had already tidied up.
    #[test]
    fn a_stale_socket_collected_from_under_the_bind_still_starts_the_session() {
        // The real run directory of whoever is running the suite, since `run_dir` is
        // resolved from the environment and this process must not rewrite that out
        // from under the tests it shares a process with. The id is this process's
        // own, so nothing but this test can be looking at these two names.
        let paths = SessionPaths::new(&format!("bindrace_{}", std::process::id()))
            .expect("resolve the run directory");
        paths.ensure_dir().expect("create the run directory");
        // A name whose `connect` is refused, which is the whole of what § 6.6 means by
        // stale. A plain file earns that answer from the kernel — it is not a socket —
        // and needs no listener of this process's own, which under `cargo test` a
        // concurrent `fork` elsewhere in the suite would keep alive past its drop.
        fs::write(paths.socket(), b"").expect("plant a stale socket");
        COLLECT_ONCE.set(true);

        let bound = bind_socket(&paths);
        assert!(
            !COLLECT_ONCE.get(),
            "the socket was never probed, so nothing was raced"
        );
        drop(fs::remove_file(paths.socket()));
        drop(bound.expect("a stale socket somebody else removed first is not a failure"));
    }

    /// A daemon with an agent socket and nothing else, for the poll-set questions.
    ///
    /// Both sockets are bound inside `root`, and the resolved [`SessionPaths`] is never
    /// used, so nothing is created in the run directory of whoever runs the suite.
    fn with_agent(root: &Scratch) -> Daemon {
        Daemon {
            paths: SessionPaths::new(&format!("pollset_{}", std::process::id()))
                .expect("resolve the run directory"),
            listener: UnixListener::bind(root.join("session.sock")).expect("bind a session socket"),
            stop_pipe: None,
            stopping: false,
            ring: crate::ring::Ring::new(1024),
            pty: None,
            client: None,
            pending: None,
            agent: Some(Agent::bind(&root.join("session.agent")).expect("bind an agent socket")),
            child_dir: PathBuf::from("/"),
            logind_linger: Linger::Unknown,
            repaint_ctrl_l: false,
            in_applied: 0,
            pending_input: VecDeque::new(),
            win: WinSize::default(),
            child_gone: None,
            exited: None,
            accept_retry: None,
            agent_accept_retry: None,
            last_detach: Instant::now(),
        }
    }

    /// Regression: the agent listener had the error *tolerance* of the session
    /// listener and none of its backoff, so a descriptor shortage — which leaves the
    /// connection queued, and so the descriptor readable — was answered by a `poll`
    /// that returned at once on every pass for as long as the shortage lasted.
    #[test]
    fn the_agent_listener_leaves_the_poll_set_while_its_accept_backoff_is_armed() {
        let root = Scratch::new("agent-backoff");
        let mut daemon = with_agent(&root);
        assert!(
            daemon.watch_for(Source::AgentListener).is_some(),
            "a listener nothing is wrong with is in the set"
        );

        daemon.agent_accept_retry = Some(Instant::now() + ACCEPT_BACKOFF);
        assert!(
            daemon.watch_for(Source::AgentListener).is_none(),
            "leaving the set is the only way to stand back from a readable descriptor"
        );
        assert!(
            daemon.watch_for(Source::Listener).is_some(),
            "and the session socket, which is answering perfectly well, stays in it"
        );

        // The listener is out of the set, so the deadline is the only thing left that
        // can put it back.
        let timeout = daemon.poll_timeout();
        assert_eq!(
            timeout.tv_sec, 0,
            "the loop must not sleep past the backoff"
        );
        assert!(
            timeout.tv_nsec > 0
                && timeout.tv_nsec <= i64::try_from(ACCEPT_BACKOFF.as_nanos()).unwrap(),
            "a listener nothing else wakes up for needs a wakeup of its own"
        );
    }

    /// The § 5.1 backstop: a run directory already holding [`MAX_SESSIONS`] sessions
    /// refuses to take another, and the id being started never counts against itself.
    #[test]
    fn a_run_directory_at_the_session_ceiling_takes_no_more() {
        let root = Scratch::new("session-ceiling");
        let dir = root.path();
        // One short of the ceiling, and each of them spelled with all five names a
        // session leaves, so what is counted is plainly ids rather than files.
        for n in 0..MAX_SESSIONS - 1 {
            for extension in ["sock", "pid", "lock", "label", "agent"] {
                fs::write(dir.join(format!("s{n}.{extension}")), b"").expect("plant a run file");
            }
        }
        // The two edges of `<id>.*`: a name with no extension at all is nobody's, and a
        // name this build has never written is still the session whose id it carries
        // rather than a session of its own.
        fs::write(dir.join("notes"), b"").expect("plant a name with no extension");
        fs::write(dir.join("s0.journal"), b"").expect("plant a name from a later version");
        assert!(
            !at_session_ceiling(dir, "mine"),
            "{} sessions is below the ceiling",
            MAX_SESSIONS - 1
        );

        // `try_lock_spawn` has already created this daemon's own `<id>.lock` by the
        // time the count is taken.
        fs::write(dir.join("mine.lock"), b"").expect("plant this session's own lock");
        assert!(
            !at_session_ceiling(dir, "mine"),
            "a session that is starting must not count against itself"
        );

        fs::write(dir.join("last.sock"), b"").expect("plant the session that fills it");
        assert!(
            at_session_ceiling(dir, "mine"),
            "{MAX_SESSIONS} sessions besides this one is the ceiling"
        );
        assert!(
            !at_session_ceiling(&root.join("never-created"), "mine"),
            "a directory that cannot be read is not a reason to refuse a session"
        );
    }
}
