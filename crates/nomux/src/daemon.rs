//! The session daemon: owns the PTY, the ring buffer and the listening socket.
//!
//! Single-threaded around `poll`. There is at most one client
//! (`IMPLEMENTATION.md` § 6.4), so the poll set is small: the listener, the PTY
//! master, the client if one is attached, the connection that has not greeted yet,
//! the self-pipe a stop signal writes to, and — when agent forwarding is on — the
//! agent socket plus one entry per live channel.
//!
//! What this process does to *itself* on the way in — leaving the login session,
//! arming that self-pipe — is `startup`, since none of it touches session state.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nomux_proto::{
    ErrorCode, ExitKind, Frame, FrameType, Hello, HelloOk, Linger, MAX_AGENT_CHANNELS,
    PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
};
use rustix::event::{PollFd, PollFlags, Timespec};

use crate::agent::{self, Agent};
use crate::conn::Conn;
use crate::linger;
use crate::pty::{self, Pty};
use crate::rundir::SessionPaths;
use crate::startup::{arm_stop_signals, leave_login_session, release_startup_state};

/// Default ring capacity. See `DESIGN.md` § 10 — this bounds how long a
/// disconnect can last before scrollback is lost, and is multiplied by the
/// per-host session cap.
const DEFAULT_RING_CAPACITY: usize = 4 << 20;

/// Environment override for the ring capacity, in bytes.
///
/// Exists because the right value is host-dependent — a machine running eight
/// sessions pays this eight times over — and because it makes overflow behaviour
/// testable without generating megabytes of output.
const RING_BYTES_ENV: &str = "NOMUX_RING_BYTES";

/// Largest ring this daemon will honour, whatever [`RING_BYTES_ENV`] asks for.
///
/// The number matters less than the fact that there is one: `VecDeque::with_capacity`
/// answers a request it cannot serve by aborting the process, so without a ceiling the
/// promise below holds for a value that is mistyped but not for one that is mistyped
/// upwards.
const MAX_RING_CAPACITY: usize = 1 << 30;

/// Resolves the ring capacity, honouring [`RING_BYTES_ENV`].
///
/// Nothing here refuses: a mistyped tuning variable should not stop a session from
/// starting. An unparseable or zero value falls back to the default, and one that is
/// merely too large is clamped to [`MAX_RING_CAPACITY`] — which is a different answer
/// from the default, and the right one, since a caller asking for more than the
/// ceiling is asking for as much as it can have. Zero in particular has to be filtered
/// here rather than passed on: `Ring::new` clamps it to one byte, and a ring that
/// makes every write a gap is not a tuning choice — the default is.
fn ring_capacity() -> usize {
    std::env::var(RING_BYTES_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .map_or(DEFAULT_RING_CAPACITY, |bytes| bytes.min(MAX_RING_CAPACITY))
}

/// How long a detached session survives before reaping itself.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_days is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long to keep serving after the child exits, so a client reconnecting into
/// the race still collects the final output and status.
const EXIT_LINGER: Duration = Duration::from_secs(5);

/// How long to keep retrying `waitpid` after the PTY reports end of file before
/// reporting a status the daemon had to invent.
///
/// Comfortably inside [`EXIT_LINGER`], so the `Exit` frame still goes out within
/// the window a reconnecting client is promised.
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

/// How long the listener stays out of the poll set after an `accept` that failed for
/// something other than a signal.
///
/// A descriptor shortage — `EMFILE` for this process, `ENFILE` for the host — leaves
/// the connection queued, so the listener goes on reporting `POLLIN` and every pass
/// answers it with the same failure, for as long as the shortage lasts. Clamping the
/// sleep is not enough on its own and neither is any timeout: a readable descriptor
/// in the set is what makes `poll` return immediately. So the listener leaves the set
/// for this long instead, which is short enough that a client waiting on the far side
/// of a shortage that has just cleared does not notice, and long enough that a host
/// under `ENFILE` is not being made worse by every nomux daemon on it burning a core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Fault injection: restores the pre-fix event ordering of § 6.4.1, where the
/// takeover was serviced before the client it was replacing.
///
/// Exists so the regression test that guards that ordering can be *shown* to fail
/// on the bug it describes, rather than merely passing on correct code. Enabled by
/// `--cfg nomux_fault_injection`; see `scripts/verify-takeover-guard.sh`. It is a
/// `const` rather than a `#[cfg]` block so both orderings stay compiled and
/// type-checked, and so the shipped binary is byte-identical either way — the
/// branch folds away.
const ACCEPT_BEFORE_READ: bool = cfg!(nomux_fault_injection);

/// Fault injection: pause before each `poll`, so a client's input and the takeover
/// that follows it arrive in the same wakeup.
///
/// The bug above only bites on that interleaving, and whether it happens is
/// otherwise a matter of microseconds — which is what made the guard probabilistic.
/// Forcing it makes the guard deterministic in both directions: `--cfg
/// nomux_fault_settle` enables only this, and the guard must still *pass*, which is
/// what proves the delay is not doing the work.
const SETTLE_BEFORE_POLL: bool = cfg!(nomux_fault_injection) || cfg!(nomux_fault_settle);

/// How long that pause is.
const FAULT_SETTLE: Duration = Duration::from_millis(20);

/// Stop accepting client input once this much is already queued for a PTY that is
/// not taking it.
///
/// The mirror of the output direction's budget, and for the same reason: the socket
/// stops being drained, the bytes wait in the kernel's buffer, and the peer blocks
/// on them. Neither of the cheaper answers is available here — `in_applied` is
/// authoritative and exactly-once (`IMPLEMENTATION.md` § 3), so a byte cannot be
/// dropped once acknowledged, and refusing one with an `InputGap` would tell a
/// well-behaved client it had skipped ahead when it had not.
///
/// A ceiling rather than a limit, by one frame: the cap is tested between frames, so
/// the last one decoded can carry the queue up to `MAX_PAYLOAD` past it.
const MAX_PENDING_INPUT: usize = 1 << 20;

/// The attached client, and the state that means nothing without one.
///
/// One `Option` rather than separate fields on the daemon: the three beside the
/// connection all belong to a *particular* one of them — how far it has been sent,
/// whether its `Hello` has been answered, whether it has heard about the exit — so
/// every arrival and departure resets all three by moving the whole thing, rather
/// than by an agreement between fields that has to be kept by hand.
#[derive(Debug)]
struct Attached {
    conn: Conn,
    /// Set once this connection's `Hello` has been answered.
    greeted: bool,
    /// Whether this connection has already been told the child exited. Per
    /// connection: a client that reattaches after the fact must hear it again.
    exit_sent: bool,
    /// Output offset already queued to this connection.
    sent_through: u64,
}

impl Attached {
    /// Takes over the session with a connection that has just said `Hello`.
    ///
    /// `sent_through` is provisional: `on_hello` resolves where this client
    /// actually resumes from, which is the first thing that happens to it.
    const fn new(conn: Conn) -> Self {
        Self {
            conn,
            greeted: false,
            exit_sent: false,
            sent_through: 0,
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
    /// `HelloOk`. Unrelated to [`Daemon::exit_deadline`], which is the post-exit
    /// grace period.
    logind_linger: Linger,
    /// Post-gap repaint policy, restated by each client's `Hello`.
    repaint_ctrl_l: bool,
    /// Authoritative input offset: everything below this has been accepted for the
    /// PTY and must never be applied twice.
    in_applied: u64,
    /// Input accepted but not yet written, because the PTY was not writable.
    pending_input: VecDeque<u8>,
    win: WinSize,
    /// When the PTY master reported end of file, i.e. when the child let go of the
    /// terminal. Distinct from `exited`: the status is not readable yet at that
    /// moment, and on this kernel usually is not.
    child_gone: Option<Instant>,
    /// The child's status, `None` until `waitpid` hands it over.
    exited: Option<(i32, ExitKind)>,
    /// When the listener may be polled again, after an `accept` that failed for a
    /// reason that will still be there on the next pass. `None` is the ordinary
    /// state, where the listener is in the set.
    accept_retry: Option<Instant>,
    /// When the session last lost its client, for idle reaping.
    ///
    /// The timestamp alone. *Whether* that deadline is armed is `client.is_none()`,
    /// so the two cannot disagree — this used to be an `Option` carrying both, and
    /// keeping the arming half in step with the client was done by hand, including
    /// one assignment whose whole job was to undo a stamp made two lines earlier.
    /// A stamp left standing under a live client reaps the session out from under
    /// it at [`IDLE_TIMEOUT`], a week later and with nothing to point at.
    last_detach: Instant,
}

/// Runs the daemon for `session_id` until the child exits or the session is reaped.
///
/// `label` is the advisory display name for `nomux list`; see
/// `IMPLEMENTATION.md` § 6.6.
///
/// # Errors
///
/// Fails if the run directory or socket cannot be created, or if another daemon
/// already owns this session.
pub(crate) fn run(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let result = start(session_id, label);
    if let Err(err) = &result {
        // Also to syslog, not only through the `Err` the caller prints. A failure
        // before `release_startup_state` still has a stderr for `attach` to read, and
        // one after it has nowhere at all — logging both here means the daemon's
        // failures are in one place regardless of which side of that line they fell.
        crate::syslog::error(session_id, &err.to_string());
    }
    result
}

/// The body of [`run`], separated so that every way out of it is logged once.
fn start(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    paths.ensure_dir()?;

    // Held across the whole of claiming the id, because everything below decides on
    // the same evidence `list` and `kill` decide on and must not interleave with
    // them (§ 6.3): `clear_stale_socket` reads a refused `connect` as a dead daemon
    // and removes its socket and pidfile, which is exactly what a collection does one
    // `connect` earlier. Without this, a `list` that probed the stale socket and was
    // then descheduled unlinks what this daemon has bound in the meantime — the live
    // session's socket and pidfile, which § 6.6 promises never happens — and a `kill`
    // landing in the same window exits 0 reporting no such session while a daemon
    // holds the user's shell, invisible to `list` and unkillable by it. `attach`
    // never reached that state because it holds this lock across the spawn; a
    // `nomux daemon <id>` started by hand, which § 6.2 is written for, held nothing.
    //
    // Never blocking, and it goes ahead without the lock rather than refusing. On the
    // ordinary path the attach that spawned this process is holding this very lock on
    // its behalf until `<id>.pid` exists, so waiting would park the session's own
    // creation until that attach gave up at its spawn timeout — and nothing here can
    // tell that holder from a `kill`'s. So what closes is every interleaving where
    // the lock was free to be taken, which is every one that does not start inside
    // somebody else's locked region; what remains open is the case where it was
    // already held, and there this is no worse than taking nothing at all.
    let publishing = paths.try_lock_spawn();

    // Before the fork, so a session that is already running is still refused to
    // whoever asked with an exit status they can see. The bind is on the other side
    // of it; `clear_stale_socket` argues both halves.
    clear_stale_socket(&paths)?;
    // Before the pidfile, so the pid `nomux kill` reads belongs to the process that
    // survives.
    leave_login_session();
    // After the fork, so that the process `SO_PEERCRED` reports as the socket's
    // creator is the one that is still there to be signalled.
    let listener = crate::rundir::bind_socket_private(&paths.socket())?;
    listener.set_nonblocking(true)?;

    // Before the pidfile, because that file is what `nomux kill` (§ 6.6) reads to
    // find this process: arming after writing it would leave a window, however
    // narrow, where the signal it sends lands on the default disposition and the
    // child's process group outlives the daemon. And after the fork above, so that a
    // parent leaving through `_exit` cannot answer a signal by writing a byte into
    // the pipe the child inherits and then reads as a stop request of its own.
    //
    // Without it the daemon dies on the default disposition and the child's process
    // group outlives it — worse than today's session, but still a session, so a pipe
    // that cannot be made is not worth refusing to start over.
    let stop_pipe = arm_stop_signals().ok();

    paths.write_pid()?;
    if let Some(label) = label {
        // Advisory: a session is worth more than its name in a listing.
        drop(paths.write_label(label));
    }
    // Released the instant the id is published, and never carried into the event
    // loop: `kill` waits two seconds for this lock and then reports a session it
    // could not remove (§ 6.6), so a daemon still holding it would be one nothing
    // could stop.
    drop(publishing);

    // Everything above resolved its paths already, so the daemon can let go of the
    // directory it inherited from the attaching connection. Holding it would keep
    // a removable or network mount busy for as long as the session lives, which
    // could be days. The child does not follow — it starts in the user's home,
    // like any login shell.
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

/// Establishes that the id is free, and removes what a dead daemon left at it.
///
/// A socket whose `connect` is refused belongs to a dead daemon; anything else —
/// including `EACCES` — is left alone, since removing it could destroy a live
/// session belonging to someone else's run.
///
/// Separate from the `bind` that follows it in [`start`] because § 6.2's fork goes
/// between them, and the two halves want opposite sides of it. The refusal has to
/// come *before*: past the fork the process a caller is waiting on has already
/// `_exit`ed with a status of its own, so an id that is already running would be
/// reported as success. And the bind has to come *after*: `kill` identifies the
/// daemon from the socket's `SO_PEERCRED`, which names whichever process called
/// `listen`, so binding first hands the frozen control surface the number of the
/// parent that is about to vanish — a number the kernel is then free to reissue,
/// which is the whole hazard reading the socket exists to close.
///
/// What that costs is one `fork` of extra width in the window where the id is
/// claimed but nothing is bound. The spawn lock `start` holds spans it — a `fork`
/// duplicates the descriptor rather than the lock, so the surviving child holds the
/// one the parent took — and that is what keeps a collection out of it.
fn clear_stale_socket(paths: &SessionPaths) -> io::Result<()> {
    let path = paths.socket();
    match UnixStream::connect(&path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("session {} is already running", paths.id()),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            // Forced here because there is nowhere else it can be forced from: the
            // probe above and the removal below are two syscalls on one name, with
            // nothing in between for another process to be scheduled into, so the
            // test for losing that race has to be inside the window. Compiled out of
            // every build but this crate's own unit tests.
            #[cfg(test)]
            tests::collect_the_stale_socket(&path);
            // A collection decides on the same evidence one `connect` earlier
            // (§ 6.6), so losing the race to remove this file is ordinary rather than
            // exceptional — and the file being gone is the state this call exists to
            // reach. Propagating that `ENOENT` turns a session that is perfectly
            // startable into one that refuses to start, over a socket that is gone
            // either way. Absence is success here for the same reason it is in the
            // arm below.
            if let Err(err) = fs::remove_file(&path)
                && err.kind() != io::ErrorKind::NotFound
            {
                return Err(err);
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    // Only the socket is replaced when an id is rebound, and a `<id>.pid` outliving
    // it is what lets `attach`'s wait for that path to *exist* be satisfied by the
    // dead daemon's number — the spawn lock is then released before this daemon has
    // published anything, and a `kill` taking it in the window finds a live socket
    // and a stale pid at once. Since pids are reused, that is `kill` signalling an
    // unrelated process of the user's, which checking liveness first cannot catch:
    // the session really is live, and it is the pidfile that belongs to the previous
    // one.
    //
    // Here rather than after the `bind`, so there is no window at all: past the
    // match above, either nothing was at the socket or what was there refused a
    // connection, so any pidfile beside it is a dead daemon's by the same evidence
    // that licensed removing the socket. A live session took the early return and
    // reaches none of this.
    paths.clear_pid();
    Ok(())
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

/// Slots the poll set can ever need at once: the six sources that exist at most once
/// each — the listener, the signal pipe, the PTY master, the client, the connection
/// that has not greeted, the agent listener — plus one per agent channel, which
/// `Agent::accept` caps at [`MAX_AGENT_CHANNELS`].
///
/// Derived from that cap rather than counted out, so raising it cannot leave a number
/// here behind.
const POLL_SLOTS: usize = 6 + MAX_AGENT_CHANNELS as usize;

/// What one `poll` came back with: the readiness of each source in the order
/// [`Daemon::watches`] registered them, and how many of the slots it used.
type Ready = ([(Source, PollFlags); POLL_SLOTS], usize);

impl Daemon {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut scratch = Vec::new();
        let mut read_buf = vec![0u8; 64 * 1024];

        loop {
            if self.should_stop() {
                return Ok(());
            }
            self.poll_once(&mut read_buf, &mut scratch)?;
            // Given back at the end of the pass that grew it. `take_frame` copies each
            // payload in here, so a single large `Input` leaves one `MAX_PAYLOAD` —
            // 256 KiB — held for the rest of the session, which can be a week, over a
            // frame nothing will look at again. It costs the steady state nothing: a
            // pass that decoded no frame leaves the capacity where the last shrink put
            // it, and `shrink_to` below its own argument makes no call at all.
            //
            // `read_buf` is left alone deliberately. It is a fixed 64 KiB that every
            // pass reads into, so giving it back would be one allocation per pass
            // rather than one saved.
            scratch.shrink_to(0);
        }
    }

    /// How long this session may stay clientless before reaping itself.
    ///
    /// Shared by `should_stop` and `poll_timeout` so the deadline and the wakeup
    /// that enforces it cannot drift apart — a limit nothing wakes up for is
    /// documentation rather than behaviour.
    const fn detach_limit(&self) -> Duration {
        if self.pty.is_none() {
            FIRST_ATTACH_TIMEOUT
        } else {
            IDLE_TIMEOUT
        }
    }

    /// When the post-exit linger window closes, if the child has already gone.
    ///
    /// Derived rather than stored, for the reason [`Daemon::detach_limit`] gives.
    /// Deriving it also settles a question a field had to answer by hand — the
    /// window is armed by the child exiting and is *not* collapsed by the client
    /// leaving. Doing that on the reasoning that there is nobody left to tell keeps
    /// § 6.5's promise only in the ordering where the client goes first: a client
    /// that watched the child exit and then closed would take the window with it, and
    /// the reconnect the window exists for would find the socket already unlinked.
    /// The whole point is the client that has not arrived yet.
    fn exit_deadline(&self) -> Option<Instant> {
        self.child_gone.map(|gone| gone + EXIT_LINGER)
    }

    /// When idle reaping falls due, if the session is clientless.
    ///
    /// An `Instant` rather than an `elapsed() >= limit` predicate, and derived rather
    /// than stored, for the reason [`Daemon::detach_limit`] gives: `should_stop` needs
    /// the rule as a predicate and `poll_timeout` needs it as a duration.
    fn detach_deadline(&self) -> Option<Instant> {
        self.client
            .is_none()
            .then(|| self.last_detach + self.detach_limit())
    }

    /// The soonest a deadline could stop the daemon, if either is armed.
    fn stop_deadline(&self) -> Option<Instant> {
        [self.exit_deadline(), self.detach_deadline()]
            .into_iter()
            .flatten()
            .min()
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
            client.conn.send_control(frame);
        }
    }

    /// Why the daemon should stop, if it should — `None` is "keep going".
    ///
    /// One function rather than a predicate beside a matching list of reasons: the
    /// two were the same three conditions in the same order, held that way by a
    /// comment saying so, which is a drift hazard written down rather than removed.
    /// The sentence in syslog now names the rule that actually fired because it is
    /// the rule that fired.
    fn stop_reason(&self) -> Option<&'static str> {
        let now = Instant::now();
        if self.stopping {
            Some("signalled")
        } else if self.exit_deadline().is_some_and(|at| now >= at) {
            Some("the child exited")
        } else if self.detach_deadline().is_some_and(|at| now >= at) {
            Some(if self.pty.is_none() {
                "no client ever attached"
            } else {
                "idle with no client"
            })
        } else {
            None
        }
    }

    fn should_stop(&self) -> bool {
        self.stop_reason().is_some()
    }

    /// Everything the poll set watches, in the order it is registered, written into
    /// `sources` and `fds` in step. Returns how many slots were used.
    ///
    /// Named rather than positional because the set is variable-length: agent
    /// forwarding adds the socket plus one entry per live channel, and an index
    /// arithmetic bug there would silently apply one fd's readiness to another. The
    /// two arrays are written and read back together, so the tag still travels with
    /// the descriptor and nothing downstream counts slots.
    ///
    /// Into the caller's arrays rather than a `Vec` because this is the steady-state
    /// relay loop: one pass per ≤ 64 KiB of terminal output, doing three syscalls,
    /// and the set has a compile-time maximum ([`POLL_SLOTS`]). The `Vec` here, the
    /// `Vec<PollFd>` built from it and the `Vec` of results were three allocations and
    /// three frees on every one of them.
    fn watches<'a>(
        &'a self,
        sources: &mut [Source; POLL_SLOTS],
        fds: &mut [PollFd<'a>; POLL_SLOTS],
    ) -> usize {
        let mut len = 0;
        let mut watch = |source, fd, flags| {
            // Through `get_mut` rather than by index: the count below is bounded by
            // the same constants [`POLL_SLOTS`] is derived from, so this cannot be
            // reached, and an entry that could not be placed is a wakeup missed
            // rather than a write past the end of the caller's frame.
            if let (Some(slot), Some(entry)) = (sources.get_mut(len), fds.get_mut(len)) {
                *slot = source;
                *entry = PollFd::from_borrowed_fd(fd, flags);
                len += 1;
            }
        };

        // Out of the set while an `accept` that failed is being waited out, which is
        // the only way to stand back from it: the queued connection that failure left
        // behind keeps the descriptor readable, so a `poll` that still asks about it
        // returns immediately however long the timeout says.
        if self.accept_retry.is_none() {
            watch(Source::Listener, self.listener.as_fd(), PollFlags::IN);
        }
        if let Some(stop) = self.stop_pipe.as_ref() {
            watch(Source::Signal, stop.as_fd(), PollFlags::IN);
        }

        // Dropped from the set once the child is gone: the master reports `HUP`
        // from then on and would spin the loop at full tilt for the whole linger
        // window, having nothing left to read.
        if let Some(pty) = self.pty.as_ref().filter(|_| self.child_gone.is_none()) {
            let mut flags = PollFlags::IN;
            if !self.pending_input.is_empty() {
                flags |= PollFlags::OUT;
            }
            watch(Source::Pty, pty.master(), flags);
        }

        if let Some(client) = self.client.as_ref() {
            // Held out of `POLLIN` while the PTY queue is full, which is § 4.1's back
            // pressure: the bytes wait in the kernel's socket buffer where the peer
            // blocks on them, the same argument the agent channels make below. Nothing
            // can wedge, because a non-empty queue is exactly what puts the master in
            // the set asking for `POLLOUT`, and draining it re-arms this on the pass
            // after. This holds back the *socket* only; what bounds the queue is
            // `read_client` declining to decode past the cap, since the takeover path
            // reaches that loop without passing through here at all.
            let mut flags = if self.input_is_saturated() {
                PollFlags::empty()
            } else {
                PollFlags::IN
            };
            // Ring bytes still owed count as wanting to write, not just bytes already
            // encoded: `pump_output` stops at `MAX_PENDING_WRITE`, so a large replay
            // routinely ends a pass with the queue drained and the ring still ahead,
            // and without this the daemon would sleep on output it could send. The
            // `OutputAck` that papers over it is advisory (§ 3), so it cannot be what
            // the loop relies on.
            if client.conn.wants_write()
                || (client.greeted && client.sent_through < self.ring.end())
            {
                flags |= PollFlags::OUT;
            }
            // Registered even when the mask is empty, since `HUP` and `ERR` are
            // reported whatever the mask says and are the only way to hear that a
            // held-back peer has died (§ 4.1). `poll_once` answers that wakeup by
            // letting the client go, so it cannot repeat, and it is what arms the idle
            // deadline and fails the agent's waiting callers (§ 6.7).
            watch(Source::Client, client.conn.stream().as_fd(), flags);
        }
        if let Some(pending) = self.pending.as_ref() {
            watch(Source::Pending, pending.stream().as_fd(), PollFlags::IN);
        }

        if let Some(agent) = self.agent.as_ref() {
            let saturated = self
                .client
                .as_ref()
                .is_some_and(|client| client.conn.is_write_saturated());
            watch(Source::AgentListener, agent.listener(), PollFlags::IN);
            for (id, fd, wants_write, wants_read) in agent.watches() {
                // A saturated client is the one back pressure signal available:
                // stop draining agent sockets until the queue it feeds has room.
                // The bytes wait in the kernel's socket buffer, where the peer
                // blocks on them, which is exactly the right place for them.
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
    /// nothing else: which source is serviced before which, and why, is the part of
    /// this file worth reading, and poll mechanics sitting in front of it only get in
    /// the way. `None` is the `EINTR` case, which is not an event. Confining the
    /// borrows of `self` here is also what lets the caller take `&mut self` freely
    /// while handling what this returns — which is why the readiness comes back by
    /// value: a `PollFd` borrows the descriptor it was built from, and a `Source` and
    /// its flags borrow nothing.
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
        // Cleared here rather than tested at each of the two places it is read, so
        // that "the listener is back in the set" and "there is no longer a wakeup to
        // arrange for it" cannot disagree.
        if self.accept_retry.is_some_and(|at| Instant::now() >= at) {
            self.accept_retry = None;
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

        // A stop request rather than an event to service, so nothing is read from
        // the pipe: the byte says only that a signal arrived, and the loop leaves
        // on its next pass, which is too soon for a permanently readable descriptor
        // to spin on. The rest of this iteration still runs, so whatever the client
        // was owed is queued before `shutdown` flushes it.
        if revents(Source::Signal).intersects(readable) {
            self.stopping = true;
        }

        let pty_events = revents(Source::Pty);
        let client_events = revents(Source::Client);
        if pty_events.intersects(PollFlags::OUT) {
            self.write_pty();
        }
        if pty_events.intersects(readable) {
            self.read_pty(read_buf)?;
        }
        // Frames the input cap left undecoded are not announced a second time — the
        // socket reported them once and has nothing new to say — so draining the
        // queue just above is itself the event that lets them through.
        let client_ready = client_events.intersects(readable)
            || (!self.input_is_saturated()
                && self
                    .client
                    .as_ref()
                    .is_some_and(|client| client.conn.has_buffered_input()));
        // Before the greeting, always: one poll can report both a readable client
        // and a `Hello` from its replacement, and handling the takeover first would
        // drop the outgoing `Conn` with input still unread in its socket buffer.
        if !ACCEPT_BEFORE_READ && client_ready {
            self.read_client(scratch)?;
        }
        // `HUP` is the peer gone for good, and reading is not an answer to it while
        // input is being held back: nothing will consume what is left in the socket,
        // so `fill` never reaches the zero-length read that would notice. Letting the
        // client go here is what stamps `detached_since` and fails the agent's
        // waiting callers now rather than at reattach (§ 6.7).
        if client_events.intersects(PollFlags::HUP | PollFlags::ERR) && self.client.is_some() {
            self.drop_client();
        }
        // Nothing arriving now can be served: the loop leaves on its next pass. It is
        // also what keeps the shutdown inside its budget (§ 6.5) — a takeover here
        // would spend a second bounded 500 ms flush on evicting a client the daemon
        // is about to drop anyway. Whoever knocked finds the socket unlinked and
        // spawns a session of their own.
        if !self.stopping {
            if revents(Source::Pending).intersects(readable) {
                self.read_pending(scratch)?;
            }
            if revents(Source::Listener).contains(PollFlags::IN) {
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
        if revents(Source::AgentListener).contains(PollFlags::IN) {
            self.accept_agent();
        }

        // Immediately before the pump that turns a status into a frame, never at the
        // top of the loop: `poll_timeout` only clamps to `STATUS_RETRY` while the
        // status is still outstanding, so the pass that collects one would otherwise
        // sleep out the rest of the linger window before `pump_output` ran — and
        // nothing can wake it, the master having left the poll set with the child.
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
    /// behind it does not hold: waiting an hour before noticing a 30-second
    /// timeout makes that timeout 30 seconds of documentation and an hour of
    /// behaviour. The hourly floor stays as the backstop for a session that is
    /// simply quiet.
    fn poll_timeout(&self) -> Timespec {
        let mut remaining = self.stop_deadline().map_or(IDLE_TICK, |at| {
            at.saturating_duration_since(Instant::now()).min(IDLE_TICK)
        });
        // The child has let go of the terminal but `waitpid` has not produced its
        // status yet; come back promptly rather than reporting one we invented.
        if self.child_gone.is_some() && self.exited.is_none() {
            remaining = remaining.min(STATUS_RETRY);
        }
        // The listener is out of the poll set until this passes (`Daemon::accept`),
        // so nothing else is left to wake the loop up and put it back.
        if let Some(at) = self.accept_retry {
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
    /// § 6.3 spawn race both probe every socket with a bare `connect`, and counting
    /// that as a takeover would evict the user from every session merely for listing
    /// them — permanently, since a client never auto-reconnects after `TAKEOVER`. The
    /// `Hello` is what takes over; a connection that never greets costs nothing.
    ///
    /// Never fails, per § 6.4.1's rule that a failing client socket is never
    /// propagated out of the event loop: `EMFILE`, `ECONNABORTED` and friends belong
    /// to one connection and are transient, and losing a live session to a descriptor
    /// shortage is the worse answer. `Agent::accept` does the same for the other
    /// listener.
    ///
    /// Transient is not the same as *gone*, though, which is what
    /// [`ACCEPT_BACKOFF`] is for. A descriptor shortage leaves the connection queued,
    /// so returning to retry on the next pass is retrying immediately and for ever —
    /// and the peer closing does not clear it, since an aborted connection sits in
    /// the backlog until something accepts it.
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
                Err(_) => {
                    self.accept_retry = Some(Instant::now() + ACCEPT_BACKOFF);
                    return;
                }
            }
        }
    }

    /// Reads from the connection that has not attached yet.
    ///
    /// Its first frame decides everything: a `Hello` promotes it and evicts whoever
    /// held the session, anything else is a protocol error, and an EOF was a
    /// liveness probe that never wanted the session at all.
    fn read_pending(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        // A greeting arrives once per attach, so this buffer is not worth sharing —
        // and keeping it separate leaves `scratch` free for the outgoing client's
        // final drain below, which must happen while the `Hello` is still borrowed.
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
        // happened — a newer client's *failed* handshake threw the working one off
        // with `Error{TAKEOVER}` and then dropped the newcomer too, leaving nobody
        // attached and no reconnect coming. `on_hello` keeps its own copy of this
        // check for the other caller, where a `Hello` arrives on a connection that is
        // already the client.
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
        // daemon has not yet noticed is dead (`IMPLEMENTATION.md` § 6.4). It leaves
        // by the same door as any other refusal, which also drops its agent channels
        // — the arriving client knows nothing of them, and their ids are never
        // reissued. That departure stamps `last_detach`, which is harmless here and
        // used to need undoing: the idle deadline is armed by `client.is_none()`
        // rather than by the stamp, and the next line installs the replacement.
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
    /// The `code` is a parameter because not every refusal here is a protocol
    /// error: a version mismatch is the peer being from another release rather than
    /// misbehaving, and the client acts on the two differently (`DESIGN.md` § 6.4).
    fn reject_pending(&mut self, code: ErrorCode, message: &'static str) {
        if let Some(pending) = self.pending.take() {
            pending.send_last(&Frame::Error { code, message });
        }
    }

    fn read_pty(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let Some(pty) = self.pty.as_ref() else {
            return Ok(());
        };
        match pty::read_pty(pty.master(), buf)? {
            // Always drain, attached or not: a full ring drops its oldest bytes,
            // but a PTY that is not read blocks the child on write.
            pty::Read::Data(n) => self.ring.push(buf.get(..n).unwrap_or(&[])),
            pty::Read::Eof => self.on_child_exit(),
            pty::Read::WouldBlock => {}
        }
        Ok(())
    }

    fn write_pty(&mut self) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        // No write error ends the session. Linux does not appear to produce one at
        // all — a write to a master whose slave has gone *succeeds*, and the
        // departure is reported on the read side alone, as the `EIO` that
        // `pty::read_pty` turns into end of file. Measured, not assumed, including
        // against a session leader holding the slave as its controlling terminal,
        // which is the shape this daemon makes. So this is for the kernel that
        // answers differently rather than for one that does, and it covers the whole
        // class rather than the one errno that was foreseen: § 6.4.1 already says a
        // failing *client* socket is never propagated out of the event loop, and
        // there is no reason the input half of a PTY should be the one place a
        // stray errno destroys the session this daemon exists to keep.
        //
        // Whatever the errno, the child is gone or unreachable, so the queue goes
        // with it — there is no longer anything to apply it to, and clearing it is
        // also what drops `PollFlags::OUT` from the master's mask in `watches`, so
        // no spin follows. What this must not do is record the exit. `child_gone` is
        // what drops the master from the poll set, and the read side can still be
        // holding everything the child wrote on its way out — the line discipline
        // hands it over 4 KiB at a time — so stamping it here would end the session
        // on output that was still readable, which is the one thing § 9 says never
        // happens without a `Gap`. Left to `read_pty`, which reaches `Read::Eof`
        // only once the master is dry.
        if crate::nbio::drain_to(&mut self.pending_input, pty.master()).is_err() {
            self.pending_input.clear();
        }
        // Given back on the way through empty, because the capacity that is left
        // otherwise outlives the client that caused it and is held for the rest of the
        // session — one paste into a child that has stopped reading is
        // `MAX_PENDING_INPUT` plus a frame, 1.25 MiB, kept for up to seven days.
        //
        // Here rather than anywhere the queue merely shrinks, and only where it has
        // gone empty, which is what keeps it off the steady state: the master is in
        // the poll set asking for `POLLOUT` exactly while this queue is non-empty, so
        // the pass that empties it is the last one to call this until the client
        // sends again. What that costs is one allocation per burst of typing, against
        // a relay loop that goes round once per 64 KiB of *output* and never comes
        // through here at all.
        if self.pending_input.is_empty() {
            self.pending_input.shrink_to(0);
        }
    }

    /// Records that the child has let go of the terminal, and starts the linger
    /// window.
    ///
    /// No status is *invented* here, and none is collected either. The master reports
    /// end of file while `waitpid` still answers "not yet" — on this kernel for about
    /// a third of exits (§ 6.5) — so committing a status at this moment makes one up,
    /// and `exit 3` is reported to the client as `exit 0`. [`Daemon::collect_status`]
    /// runs later in this very pass and every pass after it, so an exit `waitpid` is
    /// already ready for costs nothing and the rest wait out [`STATUS_RETRY`].
    fn on_child_exit(&mut self) {
        if self.child_gone.is_none() {
            self.child_gone = Some(Instant::now());
        }
        // The frame itself is left to `pump_output`, which sends it once the last
        // of the child's output has gone out. Announcing the exit ahead of the
        // words that caused it is how a client ends up closing the tab on a
        // transcript it never showed.
    }

    /// Collects the child's status once `waitpid` will give it up.
    ///
    /// Called every pass, and not only while the terminal has been let go of. The
    /// child can exit while something it started still holds the slave — `sleep 3600 &`
    /// and then `exit` is the whole of it — and then the master never reaches end of
    /// file, so a collection gated on that leaves the session's own child a zombie
    /// for as long as the session lasts, which is up to [`IDLE_TIMEOUT`]. Nothing
    /// else reaps it: `Pty::try_wait` has no other caller until `terminate`.
    ///
    /// Collecting is not reporting. Whether the client is *told* is
    /// [`Daemon::pump_output`]'s decision and is gated on `child_gone` there, because
    /// an `Exit` frame is a promise that the session's output is finished — and while
    /// the slave is still held it plainly is not.
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
            // daemonises itself does exactly this — so there is no status to
            // report and never will be. The client is still owed an `Exit` rather
            // than a connection that simply goes quiet.
            self.exited = Some((0, ExitKind::Exited));
        }
    }

    fn read_client(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        let Some(client) = self.client.as_mut() else {
            return Ok(());
        };
        if client.conn.fill().is_err() {
            // A connection failing is the normal case, not a daemon failure. A
            // client that closes with output still queued makes the kernel send
            // RST, and reading that yields ECONNRESET — propagating it would kill
            // the session, which is precisely what this daemon exists to prevent.
            //
            // Whatever that `fill` had already buffered goes with the connection,
            // undecoded. On AF_UNIX the bytes did arrive — the error is reported
            // after the last of them, not instead of them — so this is where the
            // input § 3 calls unsafe is actually lost, rather than in the kernel.
            // It stays this way deliberately: the peer is gone, so the frames are
            // owed to nobody, and the client resends from `in_applied` anyway.
            self.drop_client();
            return Ok(());
        }

        loop {
            // The cap that actually bounds the queue (§ 4.1). Holding the client out
            // of the poll set only throttles the one caller that arrives through it;
            // the takeover path reaches this loop twice without passing through the
            // poll set at all, and a connection promoted with a megabyte already
            // buffered would otherwise decode all of it. What is left stays in the
            // receive buffer, which is capped in its own right, and is picked up on a
            // later pass once the PTY has taken some of the queue.
            if self.input_is_saturated() {
                break;
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
            // Empty on purpose, and load-bearing for it. `OutputAck` is advisory
            // (§ 3): it never trims the ring, and the daemon tracks what it has sent
            // by itself. What the frame does is *arrive*, which wakes the loop and
            // lets a replay that stopped on a full socket resume.
            Frame::OutputAck { .. } => {}
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
    /// Separated from [`Daemon::on_hello`] because the two answer unrelated
    /// questions that merely arrive together: what this session *is*, decided once
    /// and never again, against where this particular client resumes from, decided
    /// on every attach. They shared only `hello.win`.
    fn start_session(&mut self, hello: &Hello<'_>) -> io::Result<()> {
        // Only the creating `Hello` can turn forwarding on: `SSH_AUTH_SOCK` goes
        // into the child's environment, and a running process's environment cannot
        // be changed afterwards (`DESIGN.md` § 5.3).
        if hello.agent_forward() {
            match Agent::bind(&self.paths.agent()) {
                Ok(agent) => self.agent = Some(agent),
                // A session without an agent is worth having; one that refuses to
                // start is not. `HelloOk` reports the outcome either way — but only
                // as a bare `agent: false`, which tells the user who opted in per
                // host nothing about why. This is the daemon's one remaining silent
                // degradation, so it says so where everything else does.
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
        self.repaint_ctrl_l = hello.repaint_ctrl_l();

        if let Some(pty) = self.pty.as_ref() {
            drop(pty.resize(hello.win));
        } else {
            self.start_session(hello)?;
        }

        let base = self.ring.base();
        let gap = hello.out_offset != RESUME_FROM_START && hello.out_offset < base;
        let resume_from = if hello.out_offset == RESUME_FROM_START {
            base
        } else {
            // Clamped at both ends. Above `end` is a client claiming output the
            // session never produced; left alone it would set `sent_through` past
            // the stream and the session would look dead until the child happened
            // to catch up.
            // `min` then `max` rather than `clamp`, which asserts its bounds are
            // ordered. They are — `end` is `base + len` — but a shipping build
            // compiles that assert down to a bare trap with no message and no
            // symbol, so the cheapest form that cannot abort is the one to use.
            hello.out_offset.min(self.ring.end()).max(base)
        };
        if let Some(client) = self.client.as_mut() {
            client.sent_through = resume_from;
            client.greeted = true;
            // Re-armed with the other two, because a second `Hello` on an
            // established connection rewinds the stream and asks for it again. A
            // client that greets after the child has gone would otherwise have its
            // output replayed and wait for ever for an `Exit` that was sent against
            // the offsets it just abandoned.
            client.exit_sent = false;
        }
        self.tell_client(&Frame::HelloOk(HelloOk {
            protocol: PROTOCOL_VERSION,
            resume_from,
            in_applied: self.in_applied,
            win: self.win,
            gap,
            linger: self.logind_linger,
            agent: self.agent.is_some(),
        }));
        if gap {
            self.repaint();
        }
        Ok(())
    }

    /// Asks the child to redraw after a gap, by whichever means this client chose.
    ///
    /// `IMPLEMENTATION.md` § 4.3. The `winch` default suits full-screen programs;
    /// `ctrl_l` suits a bare shell prompt, which ignores `SIGWINCH` entirely, and
    /// is destructive inside an editor — so the choice belongs to the client, which
    /// is the only side that knows what is on the screen.
    fn repaint(&mut self) {
        if self.repaint_ctrl_l {
            // Through the same queue as client input rather than written straight
            // to the master, so it cannot overtake keystrokes already accepted or
            // block on a full PTY buffer. It is not client input, so `in_applied`
            // does not move.
            self.pending_input.push_back(0x0c);
        } else if let Some(pty) = self.pty.as_ref() {
            drop(pty.nudge_repaint(self.win));
        }
    }

    /// Applies client input exactly once.
    ///
    /// `in_applied` is authoritative. A client that lost an `InputAck` replays from
    /// an older offset, and the overlap is trimmed here rather than rejected —
    /// re-applying it would duplicate keystrokes, which is how a truncated
    /// `rm -rf` gets run.
    fn on_input(&mut self, offset: u64, data: &[u8]) {
        let end = offset.saturating_add(data.len() as u64);
        if offset > self.in_applied {
            self.reject(ErrorCode::InputGap, "input stream skipped ahead");
            return;
        }
        if end > self.in_applied {
            let skip = usize::try_from(self.in_applied - offset).unwrap_or(data.len());
            self.pending_input.extend(data.get(skip..).unwrap_or(&[]));
            self.in_applied = end;
        }
        self.tell_client(&Frame::InputAck {
            applied_through: self.in_applied,
        });
    }

    fn pump_output(&mut self) {
        let base = self.ring.base();
        let end = self.ring.end();
        // Both, because a status is collected as soon as `waitpid` has one
        // (`Daemon::collect_status`) and that can be long before the terminal is
        // free: a backgrounded job holding the slave keeps the session's output
        // coming after its own shell has gone. The `Exit` frame says the transcript
        // is complete, so end of file on the master is what licenses it.
        let exited = self.child_gone.and(self.exited);
        let mut gapped = false;
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
                client.conn.send_control(&Frame::Gap {
                    new_base_offset: base,
                });
                client.sent_through = base;
                gapped = true;
            }

            // Both halves of the wrapped deque were addressed in one call, so
            // the second half's offset is only correct if the first was queued
            // whole. Stopping on short progress keeps that true; without it a
            // saturated queue would label the second half with an offset that
            // is too low, which is a corrupted stream rather than a slow one.
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

        // Last, and only once everything the child wrote has been queued: the
        // whole point of the linger window (§ 6.5) is that a client arriving
        // into the race still collects the final output *and* the status, in
        // that order.
        if !client.exit_sent
            && client.sent_through >= end
            && let Some((status, kind)) = exited
        {
            client.conn.send_control(&Frame::Exit { status, kind });
            client.exit_sent = true;
        }
        // Outside the borrow above, because the repaint may write to the PTY queue
        // rather than to the client. Mid-stream overflow gets the same treatment as a
        // gap reported at attach time: it is the same discontinuity, and the client
        // chose how to recover from it.
        if gapped {
            self.repaint();
        }
    }

    /// Takes one agent connection off the listener and announces it.
    fn accept_agent(&mut self) {
        // Serving means a client is attached *and* past its `Hello`: a frame sent
        // before `HelloOk` would arrive ahead of the handshake it answers.
        let serving = self.client.as_ref().is_some_and(|client| client.greeted);
        if let Some(chan) = self.agent.as_mut().and_then(|agent| agent.accept(serving)) {
            self.tell_client(&Frame::AgentOpen { chan });
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
    /// Silent if the channel was already gone: the client can close a channel in
    /// the same poll iteration that its socket reports readable, and answering
    /// that with a close for a channel the client has already forgotten is noise.
    fn close_agent_channel(&mut self, chan: u32) {
        if self.agent.as_mut().is_some_and(|agent| agent.forget(chan)) {
            self.tell_client(&Frame::AgentClose { chan });
        }
    }

    /// Pushes out what is queued, letting the connection go if it cannot be served.
    ///
    /// Neither condition here goes through [`Daemon::drop_client`], and neither
    /// wants its final flush: the socket has already failed, or the peer is past
    /// `ABANDON_PENDING_WRITE` and so is not reading *by definition* (§ 4.1).
    /// `flush_final` puts the socket back into blocking mode and writes against a
    /// 500 ms deadline, so on the second branch it would park the whole daemon —
    /// no PTY drained, no agent channel served, no reaping — for half a second, to
    /// deliver eight megabytes to a peer that has stopped reading. What is in that
    /// queue is `Pong`s and `InputAck`s besides, which a reattaching client
    /// re-derives from `in_applied`.
    ///
    /// `drop_client` keeps the flush for the departures that have somewhere to go:
    /// an explicit `Detach`, and the half-close the attach relay makes with
    /// `shutdown(SHUT_WR)` while still reading.
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
        }
        self.on_detached();
    }

    fn drop_client(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.conn.flush_final());
        }
        self.on_detached();
    }

    /// Stamps the session clientless. Everything that belonged to the departing
    /// connection went with it when the `Attached` was dropped.
    ///
    /// The post-exit linger window is untouched, and deliberately so — see
    /// [`Daemon::exit_deadline`], which derives it from the child's departure rather
    /// than the client's for exactly that reason.
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
    /// A `list` collects a dead session on exactly the evidence `clear_stale_socket`
    /// acts on — a `connect` that was refused — so the two reach for the same file
    /// and the collection can get there first. What is left then is the state
    /// `clear_stale_socket` was trying to reach, and it used to answer it with the
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

        let cleared = clear_stale_socket(&paths);
        assert!(
            !COLLECT_ONCE.get(),
            "the socket was never probed, so nothing was raced"
        );
        drop(fs::remove_file(paths.socket()));
        cleared.expect("a stale socket somebody else removed first is not a failure");
    }
}
