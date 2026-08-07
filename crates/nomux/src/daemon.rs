//! The session daemon: owns the PTY, the ring buffer and the listening socket.
//!
//! Single-threaded around `poll`, with at most one client (`IMPLEMENTATION.md` § 6.4)
//! and one served agent connection (§ 6.7), so the poll set is fixed: the sources in
//! `SINGLE_SOURCES` and nothing else. What this process does to *itself* on the way in
//! is `startup`.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nomux::{
    ErrorCode, ExitKind, Frame, FrameType, Hello, HelloOk, PROTOCOL_VERSION, RESUME_FROM_START,
    WinSize,
};
use rustix::event::{PollFd, PollFlags, Timespec};

use crate::agent::{self, Agent};
use crate::conn::Conn;
use crate::linger;
use crate::nbio;
use crate::pty::{self, Pty};
use crate::rundir::{SessionPaths, ensure_run_dir, session_ids};
use crate::startup::{
    arm_child_signal, arm_stop_signals, detach_from_controlling_terminal, release_startup_state,
};
use crate::usock::{Liveness, liveness};

/// Default ring capacity: how long a disconnect can last before scrollback is lost,
/// times the per-host session count `MAX_SESSIONS` backstops (`IMPLEMENTATION.md` § 4).
const DEFAULT_RING_CAPACITY: usize = 4 << 20;

/// Environment override for the ring capacity, in bytes.
const RING_BYTES_ENV: &str = "NOMUX_RING_BYTES";

/// Largest ring this daemon will honour, whatever [`RING_BYTES_ENV`] asks for (§ 4). A
/// policy ceiling; allocation refusal is reported before the session is published.
const MAX_RING_CAPACITY: usize = 1 << 30;

/// Resolves the ring capacity from what [`RING_BYTES_ENV`] asked for; nothing here
/// refuses (`IMPLEMENTATION.md` § 4). Zero is filtered rather than passed on, since
/// `Ring::try_new` clamps it to one byte and a ring that makes every write a gap is no
/// tuning choice.
fn ring_capacity(requested: Option<&str>) -> usize {
    requested
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .map_or(DEFAULT_RING_CAPACITY, |bytes| bytes.min(MAX_RING_CAPACITY))
}

/// Reserves this session's one large allocation while startup can still report failure
/// and before any socket or pidfile says the session exists.
fn allocate_ring(session_id: &str) -> io::Result<crate::ring::Ring> {
    let requested = ring_capacity(std::env::var(RING_BYTES_ENV).ok().as_deref());
    crate::ring::Ring::try_new(requested).map_err(|err| {
        io::Error::other(format!(
            "could not reserve the {requested}-byte output ring before starting session \
             {session_id}: {err}"
        ))
    })
}

/// Most sessions a run directory may already hold before this daemon refuses to add
/// another: eight times the limit `DESIGN.md` § 5.1 leaves to the client (§ 6.3).
const MAX_SESSIONS: usize = 64;

/// How long a detached session survives before reaping itself. One rule whether or not
/// the child is still running (`IMPLEMENTATION.md` § 6.5).
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_days is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long an outcome may stay unreadable before the daemon reports it as unknown, and
/// so how long after end of file the loop wakes to try a last `waitpid` (§ 6.5).
const OUTCOME_GRACE: Duration = Duration::from_secs(2);

/// Longest the poll loop sleeps with nothing else pending.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_hours is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TICK: Duration = Duration::from_secs(60 * 60);

/// How long to wait for the very first client before giving up (§ 6.5).
const FIRST_ATTACH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the stale-socket probe waits before giving the id up as unanswerable.
/// Shorter than [`control`](crate::control)'s own: this one runs while `<id>.lock` is
/// held, and a `kill` waiting on that lock gives up after `SPAWN_LOCK_GRACE` (§ 6.3).
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the listener stays out of the poll set after an `accept` that failed for
/// something other than a signal: a descriptor shortage leaves the connection queued, so
/// the descriptor stays readable and `poll` returns at once on every pass. Leaving the
/// set is the only way to stand back from that.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long a connection that has not said `Hello` keeps the one pending slot: a peer
/// that connects and then says nothing would otherwise hold every later attach off for
/// the life of the session. Generous against a relayed `Hello`'s round trip (§ 7).
const PENDING_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Stop accepting client input once this much is queued for a PTY not taking it (§ 4.1).
///
/// The first of the four caps § 4.1 presents as one table, and they are here together
/// because the figures are chosen against each other rather than one at a time: the two
/// receive-side megabytes bound a connection's undecoded buffer against the queue it
/// feeds, and the gap between the two output bounds is clear of the first plus a whole
/// output chunk, so only the frames that *answer* a client can reach the second. Two of
/// them are enforced in [`Conn`] rather than measured for the daemon: [`Conn::fill`]
/// stops at [`MAX_PENDING_READ`], [`Conn::send_output`] at [`MAX_PENDING_WRITE`].
const MAX_PENDING_INPUT: usize = 1 << 20;

/// Stop queueing output once this much is already waiting for a slow client (§ 4.1).
pub(crate) const MAX_PENDING_WRITE: usize = 1 << 20;

/// Queue size at which a client is treated as gone rather than slow (§ 4.1).
const ABANDON_PENDING_WRITE: usize = 8 << 20;

/// Stop reading from a connection once this much undecoded input is already buffered.
///
/// [`Conn::fill`] loops until `EAGAIN`, which against a peer that keeps writing has no
/// natural end: every chunk it takes frees exactly that much room for the peer to refill.
/// The cap leaves the bytes where the peer blocks on them instead — load-bearing rather
/// than defensive, nothing emptying that buffer while the daemon has stopped *decoding*
/// (§ 4.1).
pub(crate) const MAX_PENDING_READ: usize = 1 << 20;

/// Capacity the decode scratch keeps between passes rather than hand back.
const SCRATCH_RETAINED: usize = 64 * 1024;

/// Capacity the PTY input queue keeps once drained, for [`SCRATCH_RETAINED`]'s reason at
/// the other end of the same pass. Small because this holds keystrokes: a queue that has
/// just gone empty overwhelmingly carried a handful of bytes, and the paste the shrink
/// exists for is four orders of magnitude above this floor.
const PENDING_INPUT_RETAINED: usize = 4096;

/// The attached client, and the state that means nothing without one.
///
/// One `Option` rather than four fields on the daemon: each belongs to a *particular*
/// client, so an arrival or a departure resets them by moving the whole thing.
#[derive(Debug)]
struct Attached {
    conn: Conn,
    /// Whether this connection has been told the terminal transcript ended. Per
    /// connection, because every later attach hears the outcome behind its replay (§ 6.5).
    terminal_end_sent: bool,
    /// Output offset already queued to this connection.
    sent_through: u64,
    /// Post-gap repaint policy, as this connection's `Hello` stated it (§ 4.3).
    repaint_ctrl_l: bool,
    /// Whether a gap reported to this connection is still owed its repaint (§ 4.3).
    /// Cleared by [`Daemon::pump_output`] once this client holds the whole ring.
    repaint_due: bool,
}

impl Attached {
    /// The connection promoted by a `Hello` that has not been answered yet.
    ///
    /// Three of the four are what [`Daemon::on_hello`] decides next, off that same
    /// greeting. `terminal_end_sent` is the one it does not touch: a connection hears
    /// the end once, and this is the only place a fresh one starts owed it.
    const fn greeting(conn: Conn) -> Self {
        Self {
            conn,
            terminal_end_sent: false,
            sent_through: 0,
            repaint_ctrl_l: false,
            repaint_due: false,
        }
    }
}

/// Session state for the lifetime of the daemon process.
struct Daemon {
    paths: SessionPaths,
    listener: UnixListener,
    /// Read end of the self-pipe [`crate::startup::arm_stop_signals`] armed. `None`
    /// exists only for event-loop unit fixtures; startup refuses a session without it.
    stop_pipe: Option<OwnedFd>,
    /// The same for `SIGCHLD` ([`crate::startup::arm_child_signal`]), which is a
    /// descriptor of its own for the reason that function gives. As above, `None` is
    /// only a unit-fixture fallback; startup refuses a session without the wakeup.
    child_pipe: Option<OwnedFd>,
    /// Why this session is ending, once anything has decided it should: a stop signal,
    /// or something it could not do without having failed. The loop leaves on its next
    /// pass (§ 6.5), and until then nothing new is accepted.
    stop: Option<&'static str>,
    ring: crate::ring::Ring,
    pty: Option<Pty>,
    client: Option<Attached>,
    /// A connection accepted but not yet greeting, and so not yet the client, with the
    /// deadline by which it must. Usually a liveness probe from `list`.
    pending: Option<(Conn, Instant)>,
    /// Agent socket and the connection it is serving, once a session created with
    /// [`nomux::Hello::agent_forward`] has bound one.
    agent: Option<Agent>,
    /// Where the child starts, captured before the daemon moved to `/`.
    child_dir: PathBuf,
    /// Authoritative input offset: everything below this has been accepted for the
    /// PTY and must never be applied twice.
    in_applied: u64,
    /// Input accepted but not yet written, because the PTY was not writable.
    pending_input: VecDeque<u8>,
    /// The size the client last asked for, which is not necessarily the one the PTY has:
    /// [`Daemon::apply_win`] closes the difference once a pass.
    win: WinSize,
    /// The size this daemon last *successfully* gave the PTY, so a pass that decoded a
    /// hundred `Resize` frames still issues at most one `TIOCSWINSZ`. `None` is "no longer
    /// known": the daemon is not the only thing that can call it — `stty rows` in the
    /// session is the everyday spelling — so this records what was sent and never what the
    /// terminal is. Every `Hello` clears it, which is what keeps § 2.2's authoritative
    /// winsize true of a reattach at an unchanged size.
    applied_win: Option<WinSize>,
    /// Whether a `SIGCHLD` has arrived that no `waitpid` has been spent on yet. Set by the
    /// pass that empties [`Daemon::child_pipe`] and cleared by the ask it pays for, in that
    /// order — so a signal landing between the two leaves its byte in an emptied pipe,
    /// which is the next wakeup rather than a reap nobody makes.
    child_signalled: bool,
    /// When the PTY master reported end of file. Distinct from `outcome`: `waitpid`
    /// usually has no result yet at that moment.
    terminal_closed_at: Option<Instant>,
    /// The child's known outcome, or `Unknown` once the terminal has been closed for
    /// [`OUTCOME_GRACE`] without one.
    outcome: Option<(i32, ExitKind)>,
    /// When the listener may be polled again, after an `accept` that failed for a
    /// reason that will still be there next pass. `None` is the ordinary state.
    accept_retry: Option<Instant>,
    /// The same for the agent socket, kept apart: holding the session socket out of the
    /// set over an agent's `EMFILE` is an attach that cannot get in.
    agent_accept_retry: Option<Instant>,
    /// When the session last lost its client, for idle reaping. The timestamp alone —
    /// *whether* it is armed is `client.is_none()`, so the two cannot disagree.
    last_detach: Instant,
}

/// Runs the daemon for `session_id` until the session is stopped or reaped.
///
/// `label` is the advisory display name for `nomux list` (`IMPLEMENTATION.md` § 6.6).
///
/// # Errors
///
/// Fails if the run directory or socket cannot be created, or if another daemon already
/// owns this session.
pub(crate) fn run(
    session_id: &str,
    label: Option<&str>,
    inherited_lock_fd: Option<i32>,
) -> io::Result<()> {
    let result = start(session_id, label, inherited_lock_fd);
    if let Err(err) = &result {
        // Also to syslog, not only through the `Err` the caller prints: past
        // `release_startup_state` there is no stderr left to reach anybody through.
        crate::sanitize::error(session_id, &err.to_string());
    }
    result
}

/// The body of [`run`], separated so that every way out of it is logged once.
fn start(session_id: &str, label: Option<&str>, inherited_lock_fd: Option<i32>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    let ring = allocate_ring(session_id)?;
    ensure_run_dir(paths.dir())?;

    // The authority to probe, replace and bind this id. `spawn` hands its already-locked
    // open-file description across exec; a daemon invoked directly has to acquire the
    // same lock for itself. Proceeding without either is the probe/unlink race that can
    // leave two live daemons owning one id.
    let publishing = match inherited_lock_fd {
        Some(raw) => paths.inherit_spawn_lock(raw)?,
        None => paths.try_lock_spawn_or_refuse()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "session {} is being started or removed by another process",
                    paths.id()
                ),
            )
        })?,
    };
    // Only an acquisition that atomically created the directory entry may scrub it on
    // a refusal. For an inherited authority the parent owns failed-handoff cleanup.
    let scrub_lock = publishing.created_name();

    // Inside that locked region and before the bind, per § 6.3: taking the lock created
    // `<id>.lock`, which `session_id_of` counts as a session, so a refusal that left it
    // behind would ratchet this backstop against itself.
    let dir = paths.dir();
    let at_ceiling = match at_session_ceiling(dir, paths.id()) {
        Ok(at_ceiling) => at_ceiling,
        Err(err) => {
            if scrub_lock {
                drop(fs::remove_file(paths.lock()));
            }
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "{} could not be enumerated before starting session {}: {err}",
                    dir.display(),
                    paths.id()
                ),
            ));
        }
    };
    if at_ceiling {
        if scrub_lock {
            drop(fs::remove_file(paths.lock()));
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

    // The whole of the bind before the fork: past § 6.2's fork the process a caller is
    // waiting on has already `_exit`ed with a status of its own, so every errno after it
    // reads as success — a session that never started, reported as started. Matched rather
    // than `?`d for the reason the ceiling above scrubs: this is the *next* way out of the
    // locked region, and a `?` here left `<id>.lock` behind on every full disk.
    let listener = match bind_socket(&paths) {
        Ok(listener) => listener,
        Err(err) => {
            if scrub_lock {
                drop(fs::remove_file(paths.lock()));
            }
            return Err(err);
        }
    };

    // One fallible region rather than a cleanup per call site: nothing past the bind can
    // be reported, so whatever fails inside `publish`, what it published goes.
    let (stop_pipe, child_pipe) = match publish(&paths, label) {
        Ok(pipes) => pipes,
        Err(err) => {
            // This is still the publication authority, including when `spawn` retains
            // another reference to the same inherited open-file description. Cleaning
            // through it avoids releasing and then parking behind the parent that is
            // waiting for this startup to finish.
            drop(paths.unlink_all_locked(&publishing));
            return Err(err);
        }
    };
    // Never carried into the event loop: `kill` waits two seconds for this lock and then
    // reports a session it could not remove (§ 6.6).
    drop(publishing);

    // Everything above resolved its paths already, so the daemon lets go of the directory
    // it inherited (§ 6.2), which would otherwise keep a removable or network mount busy
    // for the life of the session. The child does not follow — it starts in the home.
    let child_dir = pty::child_dir(std::env::current_dir().ok().as_deref());
    release_startup_state();

    let mut daemon = Daemon {
        paths,
        listener,
        stop_pipe,
        child_pipe,
        stop: None,
        ring,
        pty: None,
        client: None,
        pending: None,
        agent: None,
        child_dir,
        in_applied: 0,
        pending_input: VecDeque::new(),
        win: WinSize::default(),
        applied_win: None,
        child_signalled: false,
        terminal_closed_at: None,
        outcome: None,
        accept_retry: None,
        agent_accept_retry: None,
        last_detach: Instant::now(),
    };

    // The only record that this session ever existed, once its run files are gone.
    crate::sanitize::info(session_id, "started");
    let result = daemon.event_loop();
    // `None` where the loop ended for a reason that is not one of its stop
    // conditions, which is `event_loop` returning on a failed `poll`.
    let reason = daemon.stop_reason().unwrap_or("the event loop ended");
    crate::sanitize::info(session_id, &format!("exiting: {reason}"));
    daemon.shutdown();
    result
}

/// Hands the id to the process that will actually serve it: § 6.2's detachment, the
/// signals, and the two files `list` and `kill` read. Answers with the read ends of the
/// two self-pipes, stop first.
///
/// # Errors
///
/// Propagates failures to arm either required signal path or write `<id>.pid`. Detachment
/// and the advisory label remain best effort: neither can make the event loop unsafe.
fn publish(
    paths: &SessionPaths,
    label: Option<&str>,
) -> io::Result<(Option<OwnedFd>, Option<OwnedFd>)> {
    // Before the pidfile, so the pid `nomux kill` reads belongs to the process that
    // survives.
    detach_from_controlling_terminal();
    // No second `listen` here. `UnixListener::bind` already issues one at the maximum
    // depth on Linux, and a backlog belongs to the socket's open file description, so
    // `detach_from_controlling_terminal`'s fork shares it rather than resetting it.

    // Both between the fork and the pidfile: arming after the pidfile `nomux kill` reads
    // (§ 6.6) leaves a window where its signal lands on the default disposition, and arming
    // before the fork lets the parent's `_exit` answer a signal into the pipe. `SIGCHLD`
    // here rather than at `Pty::spawn`, a disposition belonging to the process and the pipe
    // having to exist before the first `poll` builds its set — and *first*, because
    // `arm_stop_signals` is the call that clears the inherited mask and a signal blocked
    // and pending is delivered the instant it does, so a handler installed afterwards
    // silently misses the first notification.
    let child_pipe = Some(arm_child_signal()?);
    let stop_pipe = Some(arm_stop_signals()?);

    paths.write_pid()?;
    if let Some(label) = label {
        // Advisory: a session is worth more than its name in a listing.
        drop(paths.write_label(label));
    }
    Ok((stop_pipe, child_pipe))
}

/// Binds the session socket, replacing a stale one: a socket whose `connect` is refused
/// belongs to a dead daemon, and anything else — including `EACCES` — is left alone,
/// removing it being how somebody else's live session gets destroyed.
fn bind_socket(paths: &SessionPaths) -> io::Result<UnixListener> {
    let path = paths.socket();
    match liveness(&path, PROBE_TIMEOUT) {
        Liveness::Alive(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("session {} is already running", paths.id()),
            ));
        }
        // Only the refused half leaves a socket file behind to replace; an absent name
        // must not be unlinked on the chance somebody has just created one there.
        Liveness::Stale(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            // The probe above and the removal below are two syscalls on one name, so
            // the test for losing that race has to be forced inside the window.
            #[cfg(test)]
            tests::collect_the_stale_socket(&path);
            // The file being gone is the state this call exists to reach, so an `ENOENT`
            // must not refuse a perfectly startable session.
            if let Err(err) = fs::remove_file(&path)
                && err.kind() != io::ErrorKind::NotFound
            {
                return Err(err);
            }
        }
        Liveness::Stale(_) => {}
        Liveness::Unknown(err) => return Err(err),
    }

    // A `<id>.pid` outliving its socket lets `attach`'s wait for that path to *exist* be
    // satisfied by a dead daemon's number, after which `kill` signals an unrelated
    // process. Before the `bind` so there is no window: past the match above, both names
    // are a dead daemon's by the evidence that licensed removing the socket.
    paths.clear_pid();
    // The same for the name `list` prints, and here rather than left to `write_pid`'s own
    // clear for the timing: between the bind and that call this daemon has forked (§ 6.2),
    // and for the whole of it the socket answers as a live session under the display name
    // of the one whose id it took.
    paths.clear_label();

    let listener = crate::rundir::bind_socket_private(&path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Whether `dir` already holds [`MAX_SESSIONS`] sessions other than `mine`.
/// `IMPLEMENTATION.md` § 6.3 has the policy, and [`session_ids`] is the rule `list`
/// discovers sessions with (§ 6.6). Every contender has created its locked name before
/// this call, so those names are reservations and two different ids cannot both observe
/// the same final slot as free.
fn at_session_ceiling(dir: &Path, mine: &str) -> io::Result<bool> {
    Ok(session_ids(dir)?
        .iter()
        .filter(|id| id.as_str() != mine)
        .count()
        >= MAX_SESSIONS)
}

/// What one entry of the poll set belongs to.
///
/// The discriminant is also the slot in the readiness array [`Daemon::wait`] hands back,
/// which is why nothing indexes that array without a `get`: a variant added here and not
/// to [`SINGLE_SOURCES`] sits past its end, and must read as "nothing ready" and not trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The session socket, where clients arrive.
    Listener,
    /// Read end of the self-pipe a stop signal writes to.
    Stop,
    /// Read end of the self-pipe `SIGCHLD` writes to, which is a second one for the
    /// reason [`crate::startup::arm_child_signal`] gives.
    Child,
    /// The PTY master.
    Pty,
    /// The attached client.
    Client,
    /// A connection that has not greeted yet.
    Pending,
    /// The agent socket, where the child's `ssh-agent` connections arrive.
    AgentListener,
    /// The proxied agent connection, of which there is at most one (§ 6.7).
    AgentChannel,
}

/// Every source that appears in the poll set at most once, in the order
/// [`Daemon::watches`] registers them. This list is what registers them, so a source
/// added here is one [`POLL_SLOTS`] has already accounted for.
const SINGLE_SOURCES: [Source; 8] = [
    Source::Listener,
    Source::Stop,
    Source::Child,
    Source::Pty,
    Source::Client,
    Source::Pending,
    Source::AgentListener,
    Source::AgentChannel,
];

/// Slots the poll set can ever need at once, every source being a single one.
const POLL_SLOTS: usize = SINGLE_SOURCES.len();

/// What "this source has something to service" is, and the same for every source.
///
/// `contains(IN)` would leave one reporting `ERR` or `NVAL` in the set with nothing
/// servicing it and no backoff armed — [`ACCEPT_BACKOFF`]'s spin, reached without an
/// `accept` failure.
const READABLE: PollFlags = PollFlags::IN
    .union(PollFlags::HUP)
    .union(PollFlags::ERR)
    .union(PollFlags::NVAL);

/// Takes back out of a self-pipe whatever its handler put there.
///
/// A short read is an empty pipe, so the ordinary one byte costs one syscall rather than
/// one and the `EAGAIN` behind it. `nbio::read` retries `EINTR`; any other error ends the
/// loop and leaves the descriptor readable, a wasted pass rather than a lost wakeup —
/// reading on and hoping is the spin, on a descriptor that has genuinely failed.
fn drain_signals(pipe: BorrowedFd<'_>) {
    let mut sink = [0u8; 64];
    while nbio::read(pipe, &mut sink).is_ok_and(|read| read == sink.len()) {}
}

impl Daemon {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut scratch = Vec::new();
        let mut read_buf = vec![0u8; 64 * 1024];

        loop {
            if self.stop_reason().is_some() {
                return Ok(());
            }
            let ready = self.wait()?;
            self.poll_once(&ready, &mut read_buf, &mut scratch);
            // Given back so one large `Input` does not leave 256 KiB held for a week, and
            // only down to [`SCRATCH_RETAINED`]: every pass reaches here. `read_buf` never
            // moves.
            scratch.clear();
            if scratch.capacity() > SCRATCH_RETAINED {
                scratch.shrink_to(SCRATCH_RETAINED);
            }
        }
    }

    /// When idle reaping falls due, if the session is clientless — the one deadline there
    /// is, the child's exit not being a second beside it. Shared by `stop_reason` and
    /// `poll_timeout` so the rule and the wakeup enforcing it cannot drift apart, and the
    /// test is whether a PTY was ever *started*, `self.pty` outliving the child (§ 6.5).
    fn detach_deadline(&self) -> Option<Instant> {
        let limit = if self.pty.is_none() {
            FIRST_ATTACH_TIMEOUT
        } else {
            IDLE_TIMEOUT
        };
        self.client.is_none().then(|| self.last_detach + limit)
    }

    /// Whether the PTY queue has reached [`MAX_PENDING_INPUT`].
    fn input_is_saturated(&self) -> bool {
        self.pending_input.len() >= MAX_PENDING_INPUT
    }

    /// Whether the client holds bytes the input cap left undecoded and the queue has since
    /// made room: no second `POLLIN` announces them (§ 4.1), so [`Daemon::poll_once`] tests
    /// this itself on both sides of the `write_pty` that makes the room.
    fn input_backlog(&self) -> bool {
        !self.input_is_saturated()
            && self
                .client
                .as_ref()
                .is_some_and(|client| client.conn.buffered() > 0)
    }

    /// Queues a control frame for the attached client, if there is one: these are
    /// answers, and a session with nobody attached has nowhere to put them.
    fn tell_client(&mut self, frame: &Frame<'_>) {
        if let Some(client) = self.client.as_mut() {
            client.conn.send(frame);
        }
    }

    /// Why the daemon should stop, if it should — `None` is "keep going". The string is
    /// what goes to syslog, the run files being gone by the time anyone reads it.
    fn stop_reason(&self) -> Option<&'static str> {
        self.stop.or_else(|| {
            self.detach_deadline()
                .is_some_and(|at| Instant::now() >= at)
                .then(|| {
                    if self.pty.is_none() {
                        "no client ever attached"
                    } else {
                        "idle with no client"
                    }
                })
        })
    }

    /// What to ask `poll` about `source`, or `None` where it is not in the set now.
    fn watch_for(&self, source: Source) -> Option<(BorrowedFd<'_>, PollFlags)> {
        match source {
            // Out of the set while an `accept` failure is waited out ([`ACCEPT_BACKOFF`])
            // and while the pending slot is taken: a connection left in the backlog greets
            // when the slot frees, where one accepted on top of the incumbent goes unheard.
            Source::Listener => (self.accept_retry.is_none() && self.pending.is_none())
                .then(|| (self.listener.as_fd(), PollFlags::IN)),
            Source::Stop => Some((self.stop_pipe.as_ref()?.as_fd(), PollFlags::IN)),
            Source::Child => Some((self.child_pipe.as_ref()?.as_fd(), PollFlags::IN)),
            // Dropped once the child is gone: the master reports `HUP` from then on, which
            // would spin the loop for the rest of the session (§ 6.5) with nothing to read.
            Source::Pty => {
                let pty = self
                    .pty
                    .as_ref()
                    .filter(|_| self.terminal_closed_at.is_none())?;
                let mut flags = PollFlags::IN;
                if !self.pending_input.is_empty() {
                    flags |= PollFlags::OUT;
                }
                Some((pty.master(), flags))
            }
            Source::Client => {
                let client = self.client.as_ref()?;
                // § 4.1's back pressure, and only the throttling half of it: what *bounds*
                // the queue is `read_client` declining to decode past the cap. A peer that
                // half-closed leaves the read set for good rather than for a while — end of
                // file is readable for ever, so asking for `IN` again is a `poll` that
                // returns at once for the rest of the session.
                let mut flags = if self.input_is_saturated() || client.conn.is_eof() {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                // Ring bytes still owed count as wanting to write: `pump_output` stops at
                // [`MAX_PENDING_WRITE`], so a replay ends passes with the queue drained.
                if client.conn.queued() > 0 || client.sent_through < self.ring.end() {
                    flags |= PollFlags::OUT;
                }
                // Registered even when the mask is empty: `HUP` and `ERR` are reported
                // whatever it says, and past a half-close that is the *only* thing
                // left that can report this peer dead (§ 4.1).
                Some((client.conn.stream().as_fd(), flags))
            }
            Source::Pending => Some((self.pending.as_ref()?.0.stream().as_fd(), PollFlags::IN)),
            // Out of the set on both of the session listener's terms above: an `accept`
            // failure being waited out, and the one slot already taken (§ 6.7) — which
            // matters twice over here, `Agent::accept` declining a second connection
            // whatever the poll set says.
            Source::AgentListener => {
                let agent = self
                    .agent
                    .as_ref()
                    .filter(|agent| self.agent_accept_retry.is_none() && !agent.is_serving())?;
                Some((agent.listener(), PollFlags::IN))
            }
            Source::AgentChannel => {
                let (fd, wants_write, wants_read) = self.agent.as_ref()?.watch()?;
                // Stop draining the agent socket until the queue it feeds has room; the
                // bytes then wait in the kernel's buffer, where the peer blocks on them.
                let saturated = self
                    .client
                    .as_ref()
                    .is_some_and(|client| client.conn.queued() >= MAX_PENDING_WRITE);
                let mut flags = if saturated || !wants_read {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                if wants_write {
                    flags |= PollFlags::OUT;
                }
                // Dropped on an empty mask rather than registered for `HUP` alone, as the
                // client above is: a peer that died while the client could not take what it
                // said is nothing anyone can act on yet, and its end of file is still there
                // on the pass that gives the queue its room back.
                (!flags.is_empty()).then_some((fd, flags))
            }
        }
    }

    /// Registers everything the poll set watches into `fds`, and which source each slot
    /// belongs to into `order`; answers with how many of each were filled. `poll` takes a
    /// compacted array, so the two are needed in step: the set is variable-length, where
    /// index arithmetic would apply one fd's readiness to another.
    fn watches<'a>(
        &'a self,
        order: &mut [Source; POLL_SLOTS],
        fds: &mut [PollFd<'a>; POLL_SLOTS],
    ) -> usize {
        let mut used = 0;
        for source in SINGLE_SOURCES {
            // Through `get_mut` rather than by index: the budget cannot be reached, so
            // the unreachable state costs a missed wakeup rather than a panic.
            if let Some((fd, flags)) = self.watch_for(source)
                && let Some(slot) = fds.get_mut(used)
                && let Some(place) = order.get_mut(used)
            {
                *slot = PollFd::from_borrowed_fd(fd, flags);
                *place = source;
                used += 1;
            }
        }
        used
    }

    /// Expires the deadlines that decide the poll set, blocks until something in it is
    /// ready, and answers with what each source has to service — indexed by the source, so
    /// [`Daemon::poll_once`] asks rather than searches. All empty is the `EINTR` case.
    ///
    /// A failing `poll` deliberately ends the session, where client I/O never does
    /// ([`Daemon::read_client`]): this is the loop itself, and `shutdown` still signals the
    /// child and clears the run files.
    fn wait(&mut self) -> io::Result<[PollFlags; POLL_SLOTS]> {
        // Cleared in one place rather than tested at each of the two that read them, so
        // "back in the set" and "no wakeup left to arrange" cannot disagree.
        let now = Instant::now();
        for retry in [&mut self.accept_retry, &mut self.agent_accept_retry] {
            if retry.is_some_and(|at| now >= at) {
                *retry = None;
            }
        }
        if self.pending.as_ref().is_some_and(|(_, at)| now >= *at) {
            self.pending = None;
        }
        // Against the same reading of the clock, and for the pending slot's reason: the one
        // agent slot is held by whoever has it until something takes it away (§ 6.7).
        if let Some(generation) = self
            .agent
            .as_mut()
            .and_then(|agent| agent.close_if_idle(now))
        {
            self.tell_client(&Frame::AgentClose { generation });
        }

        // A fixed frame, the set having a compile-time maximum. `PollFd` has no vacant
        // spelling, so slots past `used` are seeded and never shown to `poll`.
        let mut fds: [PollFd<'_>; POLL_SLOTS] = std::array::from_fn(|_| {
            PollFd::from_borrowed_fd(self.listener.as_fd(), PollFlags::empty())
        });
        let mut order = [Source::Listener; POLL_SLOTS];
        let used = self.watches(&mut order, &mut fds);

        let timeout = self.poll_timeout();
        let mut ready = [PollFlags::empty(); POLL_SLOTS];
        match rustix::event::poll(fds.get_mut(..used).unwrap_or(&mut []), Some(&timeout)) {
            Ok(_) => {
                for (source, fd) in order.iter().zip(fds.iter()).take(used) {
                    if let Some(slot) = ready.get_mut(*source as usize) {
                        *slot = fd.revents();
                    }
                }
            }
            // Never restarted, and nothing is lost by that: the handler wrote its byte
            // before the syscall returned, so the next pass finds the pipe readable.
            Err(rustix::io::Errno::INTR) => {}
            Err(err) => return Err(err.into()),
        }
        Ok(ready)
    }

    fn poll_once(
        &mut self,
        ready: &[PollFlags; POLL_SLOTS],
        read_buf: &mut [u8],
        scratch: &mut Vec<u8>,
    ) {
        let revents = |want: Source| {
            ready
                .get(want as usize)
                .copied()
                .unwrap_or_else(PollFlags::empty)
        };

        // Nothing is read from the pipe: the byte says only that a signal arrived, and
        // the loop leaves on its next pass, too soon to spin on a readable descriptor.
        if revents(Source::Stop).intersects(READABLE) {
            // Never over a reason already recorded: a session that has just lost its
            // shell says so, and the signal is what it was going to do anyway.
            if self.stop.is_none() {
                self.stop = Some("signalled");
            }
        }
        // Emptied, where the pipe just above deliberately is not: this session goes on, and
        // a byte left in a watched descriptor is [`ACCEPT_BACKOFF`]'s spin with nothing
        // wrong at all. Before the `waitpid` [`Daemon::collect_outcome`] spends at the end
        // of this pass, in [`Daemon::child_signalled`]'s order.
        if revents(Source::Child).intersects(READABLE) {
            self.child_signalled = true;
            if let Some(pipe) = self.child_pipe.as_ref() {
                drain_signals(pipe.as_fd());
            }
        }

        let pty_events = revents(Source::Pty);
        let client_events = revents(Source::Client);
        if pty_events.intersects(PollFlags::OUT) {
            self.write_pty();
        }
        if pty_events.intersects(READABLE) {
            self.read_pty(read_buf);
        }
        let client_ready = client_events.intersects(READABLE) || self.input_backlog();
        // Before the greeting below, always. One `poll` can report both a readable client
        // and, from the connection replacing it, the `Hello` that evicts it — and the
        // eviction ends that connection for good, nothing resending what was left in its
        // receive buffer. Read, then accept (§ 6.4).
        if client_ready {
            self.read_client(read_buf, scratch);
        }
        // Reading is not an answer to `HUP` while input is held back: nothing consumes what
        // is left, so `fill` never reaches the zero-length read that would notice.
        if client_events.intersects(PollFlags::HUP | PollFlags::ERR) && self.client.is_some() {
            self.drop_client();
        }
        // Nothing arriving now can be served: a takeover here would spend a second 500 ms
        // flush evicting a client about to be dropped, past § 6.5's shutdown budget, and a
        // session whose shell could not be started would take a connection's `shutdown` and
        // then drop it unanswered.
        if self.stop.is_none() {
            if revents(Source::Pending).intersects(READABLE) {
                self.read_pending(read_buf, scratch);
            }
            if revents(Source::Listener).intersects(READABLE) {
                self.accept();
            }
        }

        let agent_events = revents(Source::AgentChannel);
        if !agent_events.is_empty() {
            self.service_agent_channel(agent_events, read_buf);
        }
        // Under the same guard as the session listener above, for a reason of its own: a
        // peer accepted on the last pass mints a generation and queues an `AgentOpen` that
        // `shutdown` flushes with no `AgentClose` behind it, the whole `Agent` going with
        // the process — a channel that opens and never closes.
        if self.stop.is_none() && revents(Source::AgentListener).intersects(READABLE) {
            self.accept_agent();
        }

        self.apply_win();
        // Here rather than only on the master's `POLLOUT`, which [`Daemon::watch_for`]
        // decided before `read_client` had queued anything: every keystroke would otherwise
        // cost a whole extra pass. That `POLLOUT` still wakes the pass for a master that
        // had no room, which is the case this one cannot serve.
        self.write_pty();
        // Again for what that drain un-blocked: `client_ready` was decided before it, and a
        // pass ending on a decodable frame with the master out of the poll set sleeps for
        // [`IDLE_TICK`]. In the pass rather than as a [`Daemon::poll_timeout`] term, which
        // would spin — [`Conn::buffered`] counts a half-arrived frame too. Nothing is left
        // owed: this stops on the cap, which owes a `POLLOUT`, or on a frame `POLLIN` ends.
        if self.input_backlog() {
            self.read_client(read_buf, scratch);
        }
        // Immediately before the pump that turns an outcome into a frame: nothing
        // arranges a wakeup for one already collected, so with the master out of the
        // poll set an `Exit` left for the next pass waits on [`IDLE_TICK`].
        self.collect_outcome();
        self.pump_output();
        self.write_client();
    }

    /// Sleeps until the next deadline that could stop the daemon, and no longer: every
    /// reaping rule is checked when `poll` returns, so a rule with no wakeup behind it
    /// is documentation rather than behaviour. [`IDLE_TICK`] backstops a quiet session.
    fn poll_timeout(&self) -> Timespec {
        let mut remaining = self.detach_deadline().map_or(IDLE_TICK, |at| {
            at.saturating_duration_since(Instant::now()).min(IDLE_TICK)
        });
        // A listener out of the poll set, a pending connection that says nothing, an agent
        // connection gone quiet, and an unknown outcome § 6.5 is about to report have no
        // other wakeup behind them. The grace itself rather than a retry regime: an
        // ordinary exit arrives as a `SIGCHLD` byte within microseconds, and a host with no
        // child pipe —
        // where [`Daemon::worth_a_waitpid`] already asks every pass — hears about one up to
        // [`OUTCOME_GRACE`] late rather than within 5 ms.
        if let Some(at) = [
            self.accept_retry,
            self.agent_accept_retry,
            self.pending.as_ref().map(|(_, at)| *at),
            self.agent.as_ref().and_then(Agent::deadline),
            self.terminal_closed_at
                .filter(|_| self.outcome.is_none())
                .map(|closed_at| closed_at + OUTCOME_GRACE),
        ]
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

    /// Takes a new connection, which waits as `pending` until it says `Hello`: connecting
    /// is *not* attaching (§ 6.4). Never fails — no client I/O does, which is the rule
    /// [`Daemon::read_client`] states — and [`ACCEPT_BACKOFF`] covers a transient failure.
    fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                // One at a time: the listener is only in the poll set while the slot is free
                // ([`Daemon::watch_for`]), so nobody is accepted only to be dropped unheard.
                Ok((stream, _)) => {
                    // Before the slot is taken and before a byte is read, so a peer that is
                    // not this uid's never becomes the session's business. And no
                    // [`ACCEPT_BACKOFF`]: what was refused is the connection, the listener
                    // being in perfect health.
                    if !crate::usock::peer_is_ours(stream.as_fd(), self.paths.id()) {
                        return;
                    }
                    self.pending = Conn::new(stream)
                        .ok()
                        .map(|conn| (conn, Instant::now() + PENDING_HELLO_TIMEOUT));
                    return;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                // An empty backlog is an ordinary answer, not something to stand back
                // from, so it must not share an arm with a descriptor shortage.
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
    fn read_pending(&mut self, read_buf: &mut [u8], scratch: &mut Vec<u8>) {
        // Separate from `scratch`, which the outgoing client's final drain below needs
        // while the `Hello` is still borrowed.
        let mut buf = Vec::new();
        let Some((pending, _)) = self.pending.as_mut() else {
            return;
        };
        if pending.fill(read_buf).is_err() {
            self.pending = None;
            return;
        }
        let ty = match pending.take_frame(&mut buf) {
            Ok(Some(ty)) => ty,
            Ok(None) => {
                if pending.is_eof() {
                    self.pending = None;
                }
                return;
            }
            Err(_) => {
                self.reject_pending(ErrorCode::Protocol, "unparseable frame header");
                return;
            }
        };
        if ty != FrameType::Hello {
            self.reject_pending(
                ErrorCode::Protocol,
                "first frame from a client must be Hello",
            );
            return;
        }
        let Ok(Frame::Hello(hello)) = Frame::decode(ty, &buf) else {
            self.reject_pending(ErrorCode::Protocol, "unparseable Hello");
            return;
        };
        // Before the eviction below, not after (§ 6.4): a `Hello` this daemon cannot
        // answer must not cost the incumbent its session on the way to being refused.
        if hello.protocol != PROTOCOL_VERSION {
            self.reject_pending(ErrorCode::Version, "protocol version mismatch");
            return;
        }

        // Final drain of the outgoing connection, for the reason [`Daemon::poll_once`] gives
        // about the same rule one step earlier.
        if self.client.is_some() {
            self.read_client(read_buf, scratch);
        }
        // Hands the session over (§ 6.4) by the same door as any other refusal, which also
        // drops the agent connection the arriving client knows nothing of. With nobody
        // attached this does nothing at all.
        self.reject(ErrorCode::Takeover, "another client attached");
        self.client = self
            .pending
            .take()
            .map(|(conn, _)| Attached::greeting(conn));
        self.on_hello(&hello);
        // Clients pipeline: input riding behind the `Hello` in the same read is
        // already buffered in the connection that was just promoted.
        self.read_client(read_buf, scratch);
    }

    /// Turns away a connection that cannot have the session, leaving the session alone.
    /// The `code` is a parameter because a client acts on a version mismatch and a
    /// protocol error differently (`DESIGN.md` § 6.4).
    fn reject_pending(&mut self, code: ErrorCode, message: &'static str) {
        if let Some((pending, _)) = self.pending.take() {
            pending.close_with(Some(&Frame::Error { code, message }));
        }
    }

    fn read_pty(&mut self, buf: &mut [u8]) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        match nbio::read_or_eof(pty.master(), buf) {
            // Always drain, attached or not: an unread PTY blocks the child on write (§ 4).
            nbio::ReadOutcome::Data(n) => self.ring.push(buf.get(..n).unwrap_or(&[])),
            nbio::ReadOutcome::Eof => self.on_terminal_closed(),
            nbio::ReadOutcome::WouldBlock => {}
            nbio::ReadOutcome::Failed(_) => {
                crate::sanitize::error(self.paths.id(), "PTY read failed");
                self.reject(ErrorCode::Internal, "terminal read failed");
                if self.stop.is_none() {
                    self.stop = Some("the terminal failed");
                }
            }
        }
    }

    fn write_pty(&mut self) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        // No PTY error ends the session, in either direction ([`Daemon::read_client`] states
        // the rule). What this must *not* do is record the exit: `terminal_closed_at` drops the
        // master from the poll set, and the read side can still be holding everything the
        // child wrote on its way out.
        if nbio::drain_to(&mut self.pending_input, pty.master()).is_err() {
            self.pending_input.clear();
        }
        // Given back on the way through empty, or one paste into a child that stopped
        // reading holds 1.25 MiB for the rest of the session. Down to a floor rather than to
        // nothing: `shrink_to(0)` on an empty `VecDeque` *frees*, so an interactive path
        // through here would pay a free and a malloc for every keystroke.
        if self.pending_input.is_empty() && self.pending_input.capacity() > PENDING_INPUT_RETAINED {
            self.pending_input.shrink_to(PENDING_INPUT_RETAINED);
        }
    }

    /// Records that the child has let go of the terminal; the stamp starts no clock (§ 6.5).
    ///
    /// No status is collected here: end of file usually arrives first, for the reason
    /// [`Daemon::collect_outcome`] gives, and it runs later this same pass.
    fn on_terminal_closed(&mut self) {
        if self.terminal_closed_at.is_none() {
            self.terminal_closed_at = Some(Instant::now());
        }
        // The stamp above just took the master out of the poll set, so `write_pty` will
        // never run again to drain this — and a queue left at [`MAX_PENDING_INPUT`]
        // would hold the client out of `POLLIN` for the rest of the session (§ 6.5).
        self.pending_input.clear();
        self.pending_input.shrink_to(0);
    }

    /// Collects the child's status once `waitpid` will give it up; § 6.5 has when that is
    /// and [`Daemon::worth_a_waitpid`] is the gate the syscall is spent behind.
    ///
    /// End of file is not the exit and does not even follow it: `do_exit` closes the dying
    /// process's descriptors — the PTY slave among them — well before it makes the process
    /// reapable, so on this kernel the master reports end of file ahead of `waitpid` for
    /// about a third of exits. What the ask costs is the pid, which makes
    /// [`Pty::pid_reissued`] load-bearing; whether the client is *told* is
    /// [`Daemon::pump_output`]'s decision.
    ///
    /// The `waitpid` runs ahead of the `self.outcome` test, that call being the reaping
    /// itself: § 6.5's unknown outcome names a child that may still be running, so
    /// stopping these asks after reporting it held the later zombie for the rest of the
    /// session.
    fn collect_outcome(&mut self) {
        let reaped = if self.worth_a_waitpid() {
            self.pty
                .as_mut()
                .and_then(|pty| pty.try_wait().ok().flatten())
        } else {
            None
        };
        // Spent whether or not anything came back, and after the ask: a `SIGCHLD` from here
        // on leaves its byte in the pipe [`Daemon::poll_once`] emptied, which is a wakeup.
        self.child_signalled = false;
        if self.outcome.is_some() {
            return;
        }
        if let Some(status) = reaped {
            self.outcome = Some(pty::exit_parts(status));
        } else if self
            .terminal_closed_at
            .is_some_and(|closed_at| closed_at.elapsed() >= OUTCOME_GRACE)
        {
            // The child closed the terminal without exiting — anything that daemonises
            // itself — so no outcome is available by the transcript deadline. The
            // client is still owed its end, explicitly without a process outcome.
            self.outcome = Some((0, ExitKind::Unknown));
        }
    }

    /// Whether this pass has any reason to ask `waitpid` — § 6.5's three, and the whole of
    /// what makes a gate safe here.
    ///
    /// A `SIGCHLD` is the strong condition rather than a hint: `exit_notify` sets the dying
    /// task `EXIT_ZOMBIE` before it queues the signal, so a byte in the child pipe is a
    /// `waitpid` that will not come back empty. The second clause serves [`OUTCOME_GRACE`]
    /// whether the signal arrived or not; the third is the pipe-free unit fixture, where
    /// the safe conservative answer is always yes as every pass used to be.
    ///
    /// Deliberately *not* `terminal_closed_at.is_some()` on its own: past § 6.5's
    /// unknown outcome that stays true over a child that daemonised itself and may run
    /// for days — the every-pass `waitpid` this exists to delete, back in the longest
    /// sessions.
    const fn worth_a_waitpid(&self) -> bool {
        self.child_signalled
            || (self.terminal_closed_at.is_some() && self.outcome.is_none())
            || self.child_pipe.is_none()
    }

    fn read_client(&mut self, read_buf: &mut [u8], scratch: &mut Vec<u8>) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        // Nothing is asked of a socket whose peer has closed its write half, and what it
        // delivered before it is already in the buffer the loop below reads. Such a peer is
        // not gone — `attach` half-closes on stdin EOF and goes on draining output (§ 7) —
        // so what ends this connection is the *write* side, in [`Daemon::write_client`].
        if !client.conn.is_eof() && client.conn.fill(read_buf).is_err() {
            // The rule for every client I/O failure, in either direction and on either
            // socket: a connection failing is the normal case and never the daemon's, so
            // nothing here is propagated out of the event loop. What `fill` had buffered
            // goes undecoded, and the client resends from `in_applied` (§ 3).
            self.drop_client();
            return;
        }

        loop {
            // The cap that actually bounds the queue (§ 4.1), enforced here and not only
            // in the poll set: the takeover path reaches this loop without polling.
            if self.input_is_saturated() {
                // Returning rather than breaking, so the end-of-file test below is
                // skipped: `attach` shuts its write half down on stdin EOF and goes on
                // draining output (§ 7). `poll_once`'s [`Conn::buffered`] test re-arms
                // this loop once `write_pty` has taken some of the queue.
                return;
            }
            let Some(client) = self.client.as_mut() else {
                return;
            };
            let ty = match client.conn.take_frame(scratch) {
                Ok(Some(ty)) => ty,
                Ok(None) => break,
                // The wire says only "unparseable": [`ErrorCode`] is a small closed set and
                // the message is a `&'static str`, so `ProtoError`'s taxonomy has nowhere
                // to go. Logged, or a client that cannot attach over one bad byte is
                // diagnosed nowhere.
                Err(err) => {
                    crate::sanitize::error(self.paths.id(), &format!("client frame: {err}"));
                    self.reject(ErrorCode::Protocol, "unparseable frame header");
                    return;
                }
            };
            let frame = match Frame::decode(ty, scratch) {
                Ok(frame) => frame,
                Err(err) => {
                    crate::sanitize::error(self.paths.id(), &format!("client {ty:?}: {err}"));
                    self.reject(ErrorCode::Protocol, "unparseable frame payload");
                    return;
                }
            };
            self.handle_frame(&frame);
        }

        // A clean half-close is how `attach` says it has no more input while it keeps
        // reading output (§ 7), but a half-close behind part of a frame can never become
        // clean: no byte will arrive to complete it. Leaving that connection attached
        // disables idle reaping indefinitely and keeps an invalid stream as the current
        // client until a takeover. Complete frames have all been consumed above, so any
        // remainder at EOF is necessarily a truncated header or payload.
        if self
            .client
            .as_ref()
            .is_some_and(|client| client.conn.is_eof() && client.conn.buffered() != 0)
        {
            self.reject(ErrorCode::Protocol, "truncated frame at end of input");
        }
    }

    /// Services one decoded frame from the attached client.
    ///
    /// A second `Hello` is not among them: greeting is what *makes* a connection the client
    /// (§ 6.4), so one arriving on a connection that already is rewinds both streams under
    /// a running session. Its refusal is worded apart from the catch-all's, which would
    /// tell a client that greeted perfectly well that `Hello` is a frame it may not send.
    fn handle_frame(&mut self, frame: &Frame<'_>) {
        match *frame {
            Frame::Input { offset, data } => self.on_input(offset, data),
            // Recorded rather than applied: [`Daemon::apply_win`] runs once a pass.
            Frame::Resize(win) => self.win = win,
            Frame::Ping => self.tell_client(&Frame::Pong),
            Frame::Detach => self.drop_client(),
            Frame::AgentData { generation, data } => {
                if let Some(agent) = self.agent.as_mut()
                    && !agent.deliver(generation, data)
                {
                    self.close_agent_channel();
                }
            }
            Frame::AgentClose { generation } => {
                if let Some(agent) = self.agent.as_mut() {
                    agent.close_from_client(generation);
                }
            }
            Frame::Hello(_) => {
                self.reject(ErrorCode::Protocol, "this connection has already greeted");
            }
            _ => self.reject(ErrorCode::Protocol, "frame is not valid from a client"),
        }
    }

    /// Binds the agent socket and spawns the child, on the `Hello` that creates the
    /// session — what this session *is*, decided once, as against where a particular
    /// client resumes from, which is [`Daemon::on_hello`]'s job on every attach.
    fn start_session(&mut self, hello: &Hello<'_>) {
        // Only the creating `Hello` can turn forwarding on: `SSH_AUTH_SOCK` goes into
        // the child's environment, which cannot be changed afterwards (§ 5.3).
        if hello.agent_forward {
            match Agent::bind(&self.paths.agent()) {
                Ok(agent) => self.agent = Some(agent),
                // A session without an agent is worth having; one that refuses to start is
                // not. `HelloOk` says only `agent: false`, so the reason goes to syslog.
                Err(err) => {
                    crate::sanitize::error(self.paths.id(), &format!("agent socket: {err}"));
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
            // Recorded rather than returned: past `release_startup_state` there is no
            // stderr for an `Err` to surface on, so carrying one up would buy nothing but
            // six `io::Result` signatures.
            Err(err) => {
                self.reject(ErrorCode::Internal, "failed to start the session shell");
                crate::sanitize::error(self.paths.id(), &format!("session shell: {err}"));
                self.stop = Some("the session shell could not be started");
            }
        }
    }

    /// Gives the PTY the size the client last asked for, at most once per pass.
    ///
    /// `Resize` touches no queue, so it never breaks [`Daemon::read_client`]'s decode loop:
    /// a peer sending nothing else fills `MAX_PENDING_READ` with 12-byte frames and would,
    /// applied per frame, spend one wakeup on ~87 000 `TIOCSWINSZ` calls and as many
    /// `SIGWINCH`s — with the PTY undrained throughout, which is the one thing § 4.1 does
    /// not allow a client to cause. Only the last size was ever real.
    fn apply_win(&mut self) {
        if self.applied_win == Some(self.win) {
            return;
        }
        if let Some(pty) = self.pty.as_ref() {
            // Recorded only where the ioctl took. A failed one leaves the size unknown
            // rather than applied, so the next pass tries again instead of reading its
            // own record back as agreement.
            self.applied_win = pty.resize(self.win).is_ok().then_some(self.win);
        }
    }

    /// Settles the arriving client onto the session, creating it if there is none yet.
    ///
    /// Checks no version, deliberately, though it is handed the field.
    /// [`Daemon::read_pending`] makes that check *before* the eviction because § 6.4
    /// requires it, so a second copy here could only refuse a client the session has just
    /// been handed to — leaving nobody attached, which is what the first check prevents.
    fn on_hello(&mut self, hello: &Hello<'_>) {
        self.win = hello.win;
        // Restated to the terminal rather than assumed (§ 2.2): the child may have moved
        // the master itself since the last `Hello` — `stty rows` needs no permission from
        // this daemon — and a reattach at an unchanged size is the only chance to put that
        // right, so it may not be the pass that skips the ioctl.
        self.applied_win = None;

        if self.pty.is_none() {
            self.start_session(hello);
            // Tested again rather than answered for: a session with no terminal has
            // nothing to resume anybody from, and the refusal has already gone out.
            if self.pty.is_none() {
                return;
            }
        }

        let base = self.ring.base();
        let resume_from = if hello.out_offset == RESUME_FROM_START {
            base
        } else {
            // Clamped at both ends (§ 4.2). `min` then `max` rather than `clamp`, which
            // panics on unordered bounds — a bare trap with no message in a shipping build.
            hello.out_offset.min(self.ring.end()).max(base)
        };
        let ok = HelloOk {
            resume_from,
            in_applied: self.in_applied,
            // Read here rather than held from startup: this advisory systemd marker can
            // change over a session's life, even though it does not by itself move this
            // daemon out of the login scope (§ 6.2).
            linger: linger::detect(),
            agent: self.agent.is_some(),
        };
        // Not a field on the wire: both ends compute it, through the one helper (§ 4.2).
        let gap = ok.gap(hello.out_offset);
        if let Some(client) = self.client.as_mut() {
            client.sent_through = resume_from;
            client.repaint_ctrl_l = hello.repaint_ctrl_l;
            // Owed rather than issued here, so an attach-time gap and a mid-stream one
            // share one repaint policy.
            client.repaint_due = gap;
        }
        self.tell_client(&Frame::HelloOk(ok));
    }

    /// Asks the child to redraw after a gap, by whichever means this client chose;
    /// `IMPLEMENTATION.md` § 4.3 has why the choice belongs to the client.
    fn repaint(&mut self) {
        if self.terminal_closed_at.is_some() {
            return;
        }
        if self
            .client
            .as_ref()
            .is_some_and(|client| client.repaint_ctrl_l)
        {
            // Queued rather than written, and not client input: `in_applied` stays (§ 4.3).
            self.pending_input.push_back(0x0c);
        } else if let Some(pty) = self.pty.as_ref() {
            // Two resizes, and a failure between them leaves the master a column narrow
            // with nothing to say so: forget the size rather than record one that was
            // never reached, and the next pass sets it again.
            if pty.nudge_repaint(self.win).is_err() {
                self.applied_win = None;
            }
        }
    }

    /// Applies client input exactly once, trimming an overlapping replay (§ 3).
    fn on_input(&mut self, offset: u64, data: &[u8]) {
        let end = offset.saturating_add(data.len() as u64);
        if offset > self.in_applied {
            self.reject(ErrorCode::InputGap, "input stream skipped ahead");
            return;
        }
        if end > self.in_applied {
            // Only while there is a terminal to write to: past the child's exit `write_pty`
            // never runs again, so a client that kept sending would refill what
            // `on_terminal_closed` emptied. `in_applied` moves either way (§ 3).
            if self.terminal_closed_at.is_none() {
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
        // Both, a status often being collected long before the terminal is free. The
        // `Exit` frame promises the transcript is complete, so end of file on the master
        // is what licenses it — and `since_terminal_closed_secs` is measured from that
        // moment.
        let terminal_end = self.terminal_closed_at.zip(self.outcome);
        let Some(client) = self.client.as_mut() else {
            return;
        };
        if client.conn.queued() < MAX_PENDING_WRITE && client.sent_through < end {
            if client.sent_through < base {
                // Overflowed while this client was slow or away: the stream is
                // discontinuous and the client must reset its emulator.
                client.conn.send(&Frame::Gap {
                    new_base_offset: base,
                });
                client.sent_through = base;
                client.repaint_due = true;
            }

            // Defence in depth against a second short-return path ever appearing: the back
            // half of a wrapped deque is only labelled correctly if the front was queued
            // whole, and a stream contiguous and wrong is what no client can detect.
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

        // Last, and only once everything the child wrote is queued: § 6.5's ordering
        // promise, enforced in this one place.
        if !client.terminal_end_sent
            && client.sent_through >= end
            && let Some((closed_at, (status, kind))) = terminal_end
        {
            client.conn.send(&Frame::Exit {
                status,
                kind,
                since_terminal_closed_secs: u32::try_from(closed_at.elapsed().as_secs())
                    .unwrap_or(u32::MAX),
            });
            client.terminal_end_sent = true;
        }
        // Coalesced onto the moment this client holds the whole ring rather than issued
        // per gap (§ 4.3).
        let repainting = client.repaint_due && client.sent_through >= end;
        client.repaint_due &= !repainting;
        if repainting {
            self.repaint();
        }
    }

    /// Takes one agent connection off the listener and announces it; the backoff is
    /// [`ACCEPT_BACKOFF`]'s, for its reason and with its effect.
    fn accept_agent(&mut self) {
        let serving = self.client.is_some();
        let id = self.paths.id();
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        match agent.accept(serving, id) {
            agent::Accept::Opened(generation) => {
                self.tell_client(&Frame::AgentOpen { generation });
            }
            agent::Accept::Failed => {
                self.agent_accept_retry = Some(Instant::now() + ACCEPT_BACKOFF);
            }
            agent::Accept::Idle => {}
        }
    }

    /// Moves bytes for the served agent connection in whichever direction is ready.
    fn service_agent_channel(&mut self, events: PollFlags, buf: &mut [u8]) {
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        if events.contains(PollFlags::OUT) {
            match agent.flush() {
                agent::Flush::Open => {}
                // The client closed this one and has already forgotten it.
                agent::Flush::Finished => {
                    let _ = agent.forget();
                    return;
                }
                agent::Flush::Failed => {
                    self.close_agent_channel();
                    return;
                }
            }
        }
        if !events.intersects(READABLE) {
            return;
        }
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        let generation = agent.generation();
        match agent.read(buf) {
            nbio::ReadOutcome::Data(n) => {
                let data = buf.get(..n).unwrap_or(&[]);
                if let Some((generation, client)) = generation.zip(self.client.as_mut()) {
                    client.conn.send_agent_data(generation, data);
                }
            }
            nbio::ReadOutcome::Eof | nbio::ReadOutcome::Failed(_) => self.close_agent_channel(),
            nbio::ReadOutcome::WouldBlock => {}
        }
    }

    /// Drops the served connection and tells the client, which is holding the other end.
    /// Silent if it was already gone: the client can close it in the same poll iteration
    /// that its socket reports readable.
    fn close_agent_channel(&mut self) {
        if let Some(generation) = self.agent.as_mut().and_then(Agent::forget) {
            self.tell_client(&Frame::AgentClose { generation });
        }
    }

    /// Pushes out what is queued, and is three of the six endings § 6.4 lists.
    ///
    /// Out through [`Daemon::drop_client`] like every other departure — the flush inside
    /// it costs one refused write on a socket that has just refused one, against two
    /// paths that would otherwise have to be kept saying the same thing.
    fn write_client(&mut self) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        // Read after the flush, an unfinished queue being exactly what the `Exit` has
        // not been delivered through yet.
        let finished = client.conn.flush_some().is_err()
            || client.conn.queued() >= ABANDON_PENDING_WRITE
            || (client.terminal_end_sent && client.conn.is_eof() && client.conn.queued() == 0);
        if finished {
            self.drop_client();
        }
    }

    /// The same for the attached client, which also leaves the session clientless.
    fn reject(&mut self, code: ErrorCode, message: &'static str) {
        if let Some(client) = self.client.take() {
            client
                .conn
                .close_with(Some(&Frame::Error { code, message }));
            self.on_detached();
        }
    }

    /// Lets the attached client go, with only what the socket takes this instant: § 4.1's
    /// dropped rather than flushed send queue.
    ///
    /// [`Conn::close_with`] goes blocking for up to 500 ms and this loop is the only thing
    /// draining the PTY, so flushing a detach from a peer that has stopped reading — the
    /// departure this project exists to survive — would stop the user's child dead for it.
    fn drop_client(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.conn.flush_some());
            self.on_detached();
        }
    }

    /// Stamps the session clientless; everything that belonged to the departing
    /// connection went with it when the `Attached` was dropped. A child that has already
    /// exited changes nothing — the stamp is what reaps either way (§ 6.5).
    fn on_detached(&mut self) {
        self.last_detach = Instant::now();
        // Nothing can answer a signature request with the client gone, so the waiting
        // process should fail now rather than at reattach (§ 6.7). Through the client's own
        // door rather than by dropping the channel: one poll pass can carry both the reply
        // to a signature request and the `Detach` behind it, and `forget` here threw that
        // reply away — a `git push` failing on an agent that hung up mid-answer. With
        // nothing queued this is `forget` exactly.
        if let Some(agent) = self.agent.as_mut()
            && let Some(generation) = agent.generation()
        {
            agent.close_from_client(generation);
        }
    }

    fn shutdown(&mut self) {
        // The one *departure* [`Daemon::drop_client`]'s argument does not reach: nothing
        // survives this to replay from, the ring going with the process, so what the client
        // is owed is owed now. § 6.5's 500 ms is spent here and in the eviction `reject`
        // closes with and nowhere else, inside `nomux kill`'s two seconds.
        if let Some(client) = self.client.take() {
            client.conn.close_with(None);
            self.on_detached();
        }
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
    use std::os::unix::net::UnixStream;
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
        ensure_run_dir(paths.dir()).expect("create the run directory");
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

    /// A daemon with a listening socket and nothing else — no terminal, no client, no
    /// agent — for the questions that are about the event loop rather than a session.
    ///
    /// Every socket is bound inside `root`, and the resolved [`SessionPaths`] is never
    /// used, so nothing is created in the run directory of whoever runs the suite. `name`
    /// only has to differ between the daemons one test builds.
    fn blank(root: &Scratch, name: &str) -> Daemon {
        Daemon {
            paths: SessionPaths::new(&format!("{name}_{}", std::process::id()))
                .expect("resolve the run directory"),
            listener: UnixListener::bind(root.join(&format!("{name}.sock")))
                .expect("bind a session socket"),
            stop_pipe: None,
            child_pipe: None,
            stop: None,
            ring: crate::ring::Ring::new(1024),
            pty: None,
            client: None,
            pending: None,
            agent: None,
            child_dir: PathBuf::from("/"),
            in_applied: 0,
            pending_input: VecDeque::new(),
            win: WinSize::default(),
            applied_win: None,
            child_signalled: false,
            terminal_closed_at: None,
            outcome: None,
            accept_retry: None,
            agent_accept_retry: None,
            last_detach: Instant::now(),
        }
    }

    /// [`blank`] with an agent socket, for the poll-set questions about one.
    fn with_agent(root: &Scratch) -> Daemon {
        let mut daemon = blank(root, "pollset");
        daemon.agent =
            Some(Agent::bind(&root.join("session.agent")).expect("bind an agent socket"));
        daemon
    }

    /// Hands `daemon` a connection in `slot`, and gives back the peer end a test writes
    /// frames into. Blocking, where the daemon's own half is not: a frame this small
    /// reaches the kernel's buffer in one write and the daemon reads it from there.
    fn attach_peer(conn: impl FnOnce(Conn)) -> UnixStream {
        let (peer, ours) = UnixStream::pair().expect("a socketpair");
        conn(Conn::new(ours).expect("a connection"));
        peer
    }

    /// Writes `frame` down `peer` as a client would.
    fn deliver(peer: &mut UnixStream, frame: &Frame<'_>) {
        use std::io::Write as _;

        let mut wire = Vec::new();
        frame.encode(&mut wire).expect("a valid frame");
        peer.write_all(&wire)
            .expect("deliver a frame to the daemon");
    }

    /// Reads whatever `peer` has been sent, giving up rather than parking the run.
    fn collect(peer: &mut UnixStream) -> Vec<u8> {
        use std::io::Read as _;

        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("bound the read");
        let mut got = vec![0u8; 4096];
        let n = peer.read(&mut got).unwrap_or(0);
        got.truncate(n);
        got
    }

    /// A terminal with a shell on it, so an arriving `Hello` resumes a session rather
    /// than starting one — `pty.rs`'s own tests spawn the same way.
    fn shell(session_id: &str) -> Pty {
        Pty::spawn(&pty::Spawn {
            term: "dumb",
            win: WinSize::default(),
            session_id,
            cwd: Path::new("/tmp"),
            agent_sock: None,
        })
        .expect("spawn a shell on a pty")
    }

    /// Regression: a takeover keeps what the client it evicts had already delivered
    /// (`IMPLEMENTATION.md` § 6.4).
    ///
    /// One `poll` can report both a readable client and, from the connection replacing it,
    /// the `Hello` that evicts it, and the last thing typed before a reattach was dropped
    /// whenever the two landed in the same wakeup — [`Daemon::poll_once`] has why.
    ///
    /// Two things hold the rule up, and this pins the rule rather than either of them:
    /// `poll_once` decodes before it services the greeting, and [`Daemon::read_pending`]
    /// drains again before the eviction. They are deliberately redundant.
    ///
    /// The readiness array is handed straight to `poll_once`, which is what makes "the
    /// same wakeup" a fact of the test rather than a race it has to win — no sleep can
    /// promise the interleaving this states outright.
    #[test]
    fn a_takeover_keeps_the_input_the_client_it_evicts_had_delivered() {
        /// No newline, so this reaches the shell's line buffer and never its command
        /// line: what is under test is the daemon's accounting, not the child.
        const TYPED: &[u8] = b"the last keystrokes";

        let root = Scratch::new("takeover-order");
        let mut daemon = blank(&root, "takeover");
        daemon.pty = Some(shell("takeover-order"));

        let mut leaving = attach_peer(|conn| daemon.client = Some(Attached::greeting(conn)));
        // Delivered and never `fill`ed: these bytes are in the kernel's buffer, exactly
        // where a keystroke that arrived between the `poll` and this moment sits.
        deliver(
            &mut leaving,
            &Frame::Input {
                offset: 0,
                data: TYPED,
            },
        );

        let mut arriving = attach_peer(|conn| {
            daemon.pending = Some((conn, Instant::now() + PENDING_HELLO_TIMEOUT));
        });
        deliver(
            &mut arriving,
            &Frame::Hello(Hello {
                protocol: PROTOCOL_VERSION,
                agent_forward: false,
                repaint_ctrl_l: false,
                out_offset: RESUME_FROM_START,
                win: WinSize::default(),
                term: "dumb",
            }),
        );

        let mut ready = [PollFlags::empty(); POLL_SLOTS];
        ready[Source::Client as usize] = PollFlags::IN;
        ready[Source::Pending as usize] = PollFlags::IN;
        let mut read_buf = vec![0u8; 64 * 1024];
        let mut scratch = Vec::new();
        daemon.poll_once(&ready, &mut read_buf, &mut scratch);

        // Read out before the shell is collected, so a failing assertion below still
        // leaves no `dash` behind: `Pty` has no `Drop` of its own, deliberately.
        let applied = daemon.in_applied;
        let promoted = daemon.pending.is_none() && daemon.client.is_some();
        let evicted = collect(&mut leaving);
        if let Some(mut pty) = daemon.pty.take() {
            pty.terminate();
        }

        assert!(
            promoted,
            "the arriving connection never took the session, so nothing here was a \
             takeover"
        );
        assert_eq!(
            evicted,
            {
                let mut wire = Vec::new();
                Frame::Error {
                    code: ErrorCode::Takeover,
                    message: "another client attached",
                }
                .encode(&mut wire)
                .expect("a valid frame");
                wire
            },
            "the evicted connection was told something other than why it was evicted"
        );
        assert_eq!(
            applied,
            TYPED.len() as u64,
            "the {} bytes this client delivered before the takeover went with the \
             connection: the arriving one resumes from {applied}, so they are typed into \
             nothing and nobody will resend them",
            TYPED.len()
        );
    }

    /// A write half closed behind an incomplete frame cannot be the clean stdin EOF
    /// `attach` uses: there is no future byte that can complete it, so it must release
    /// the attached slot rather than keeping the session non-idle for ever.
    #[test]
    fn an_eof_mid_frame_releases_the_client() {
        use std::io::Write as _;

        let root = Scratch::new("truncated-client");
        let mut daemon = blank(&root, "truncated");
        let mut peer = attach_peer(|conn| {
            daemon.client = Some(Attached::greeting(conn));
        });
        daemon.last_detach = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or(daemon.last_detach);
        let detached_before = daemon.last_detach;

        let mut wire = Vec::new();
        Frame::Input {
            offset: 0,
            data: b"never complete",
        }
        .encode(&mut wire)
        .expect("a valid frame");
        peer.write_all(&wire[..=nomux::HEADER_LEN])
            .expect("deliver an incomplete frame");
        peer.shutdown(std::net::Shutdown::Write)
            .expect("close only the input half");

        let mut read_buf = vec![0u8; 64 * 1024];
        daemon.read_client(&mut read_buf, &mut Vec::new());

        assert!(daemon.client.is_none(), "the invalid client kept the slot");
        assert!(
            daemon.last_detach > detached_before,
            "releasing the client must arm detached-session reaping"
        );
        assert_eq!(
            collect(&mut peer),
            {
                let mut expected = Vec::new();
                Frame::Error {
                    code: ErrorCode::Protocol,
                    message: "truncated frame at end of input",
                }
                .encode(&mut expected)
                .expect("a valid frame");
                expected
            },
            "the peer must learn that its half-close was not a clean input EOF"
        );
    }

    /// Whether the child pipe `daemon` is holding has anything to read, without reading
    /// it: a zero timeout, so this answers rather than waits.
    fn child_pipe_is_readable(daemon: &Daemon) -> bool {
        let pipe = daemon
            .child_pipe
            .as_ref()
            .expect("the pipe this test put there");
        let mut fds = [PollFd::from_borrowed_fd(pipe.as_fd(), PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&now)).is_ok_and(|ready| ready > 0)
    }

    /// The pass that reads the child pipe empties it, which is the one thing a second
    /// self-pipe must do that the stop pipe does not.
    ///
    /// A byte left in a watched descriptor is [`ACCEPT_BACKOFF`]'s spin reached with nothing
    /// wrong at all. The stop pipe is licensed never to be read because its byte is the last
    /// thing that loop ever wants; `SIGCHLD` shares neither the pipe nor the licence, the
    /// session going on afterwards.
    ///
    /// Two bytes, as two signals close together leave — the handler writes one apiece and
    /// a pipe coalesces nothing — so a drain that took a byte a pass would be the same
    /// spin one wakeup slower and pass this on one byte.
    ///
    /// The readiness array is handed straight to `poll_once`, so what is under test is
    /// this daemon's answer to a source being ready rather than a signal a unit test
    /// would have to install a process-wide handler to raise.
    #[test]
    fn a_child_signal_is_taken_back_out_of_the_pipe_that_carried_it() {
        let root = Scratch::new("child-signal");
        let mut daemon = blank(&root, "childsig");
        let (read, write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .expect("a self-pipe");
        daemon.child_pipe = Some(read);

        assert!(
            daemon.watch_for(Source::Child).is_some(),
            "a pipe nothing is wrong with belongs in the poll set"
        );
        rustix::io::write(&write, b"\0\0").expect("what two handlers would have left");
        assert!(
            child_pipe_is_readable(&daemon),
            "the pipe must be readable, or nothing below is measuring anything"
        );

        let mut ready = [PollFlags::empty(); POLL_SLOTS];
        ready[Source::Child as usize] = PollFlags::IN;
        daemon.poll_once(&ready, &mut vec![0u8; 1024], &mut Vec::new());

        assert!(
            !child_pipe_is_readable(&daemon),
            "the pass that read the child pipe left something in it, so every later \
             `poll` returns at once with nothing to serve"
        );
    }

    /// The four states of the gate the `waitpid` is spent behind, and the one that used
    /// to be the whole rule.
    ///
    /// Asked directly because the syscall it elides is not observable from out here: what
    /// a test can pin is the decision, and the decision is the change. The third state is
    /// the one with a defect behind it — `terminal_closed_at` alone stays true for the
    /// rest of a session whose child daemonised itself, so a gate written on it would
    /// put the every-pass `waitpid` back in exactly the sessions most likely to last days.
    #[test]
    fn a_waitpid_is_asked_for_only_where_something_says_it_may_be_ready() {
        let root = Scratch::new("waitpid-gate");
        let mut daemon = blank(&root, "gate");
        assert!(
            daemon.worth_a_waitpid(),
            "a pipe-free fixture has nothing else to go on, and must ask as every \
             pass used to"
        );

        let (read, _write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .expect("a self-pipe");
        daemon.child_pipe = Some(read);
        assert!(
            !daemon.worth_a_waitpid(),
            "a running child answers `None` to every one of these, which is the syscall \
             this exists to delete"
        );

        daemon.child_signalled = true;
        assert!(
            daemon.worth_a_waitpid(),
            "the kernel sets the task `EXIT_ZOMBIE` before it queues the signal, so this \
             is a `waitpid` that will not come back empty"
        );

        // End of file ahead of the exit, which is [`OUTCOME_GRACE`]'s whole subject: asked
        // on every pass until the grace expires, whether the signal arrived or not.
        daemon.child_signalled = false;
        daemon.terminal_closed_at = Some(Instant::now());
        assert!(daemon.worth_a_waitpid());

        daemon.outcome = Some((0, ExitKind::Unknown));
        assert!(
            !daemon.worth_a_waitpid(),
            "§ 6.5's unknown outcome leaves `terminal_closed_at` set over a child that may run \
             for days, so the end of file cannot be the condition on its own"
        );
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

    /// A served agent connection takes the listener out of the poll set and puts its own
    /// deadline into the timeout — the two halves of § 6.7's one-at-a-time rule that live
    /// out here rather than inside `Agent`.
    ///
    /// `Agent::accept` declines a second connection whatever the poll set says, so a
    /// listener left in it costs no correctness and a whole core: the waiting connection
    /// keeps that descriptor readable, which is [`ACCEPT_BACKOFF`]'s shape arrived at by
    /// a taken slot rather than by an error. And nothing but the clock ends a connection
    /// that says nothing, so a loop that slept past the deadline would never reach it.
    #[test]
    fn a_served_agent_connection_holds_the_listener_out_and_sets_the_next_wakeup() {
        let root = Scratch::new("agent-serving");
        let mut daemon = with_agent(&root);
        // Attached, so the deadline under test is not shadowed by the session's own:
        // a clientless daemon already wakes for `FIRST_ATTACH_TIMEOUT`, well before it.
        let (_peer, ours) = UnixStream::pair().expect("a socketpair");
        daemon.client = Some(Attached::greeting(Conn::new(ours).expect("a connection")));

        let agent = daemon.agent.as_mut().expect("an agent socket");
        let _served = UnixStream::connect(agent.path()).expect("connect to the agent socket");
        assert_eq!(
            agent.accept(true, "agent-serving"),
            agent::Accept::Opened(0),
            "the slot was free, so this one is served"
        );

        assert!(
            daemon.watch_for(Source::AgentListener).is_none(),
            "a backlog nothing is willing to accept from is a poll that returns at once"
        );
        assert!(
            daemon.watch_for(Source::AgentChannel).is_some(),
            "and the connection being served is what the loop watches in its place"
        );

        // Inside the minute `AGENT_IDLE_TIMEOUT` gives it, and nowhere near `IDLE_TICK`,
        // which is what an attached daemon with nothing else pending would sleep for.
        let timeout = daemon.poll_timeout();
        assert!(
            (55..60).contains(&timeout.tv_sec),
            "the loop slept {}s, past the deadline that is the only thing able to give \
             the slot back",
            timeout.tv_sec
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
            !at_session_ceiling(dir, "mine").expect("enumerate the run directory"),
            "{} sessions is below the ceiling",
            MAX_SESSIONS - 1
        );

        // `try_lock_spawn` has already created this daemon's own `<id>.lock` by the
        // time the count is taken.
        fs::write(dir.join("mine.lock"), b"").expect("plant this session's own lock");
        assert!(
            !at_session_ceiling(dir, "mine").expect("enumerate the run directory"),
            "a session that is starting must not count against itself"
        );

        fs::write(dir.join("last.sock"), b"").expect("plant the session that fills it");
        assert!(
            at_session_ceiling(dir, "mine").expect("enumerate the run directory"),
            "{MAX_SESSIONS} sessions besides this one is the ceiling"
        );
        assert!(
            at_session_ceiling(&root.join("never-created"), "mine").is_err(),
            "a directory that was not read cannot honestly be reported below the ceiling"
        );
    }

    /// The two clamps `IMPLEMENTATION.md` § 4 documents, told apart from the fallback
    /// they share: a value past the ceiling is capped, not defaulted.
    #[test]
    fn a_ring_capacity_past_the_ceiling_is_clamped_rather_than_defaulted() {
        assert_eq!(ring_capacity(Some("99999999999999999")), MAX_RING_CAPACITY);
        assert_eq!(ring_capacity(Some(" 8192 ")), 8192);
        for refused in [None, Some("0"), Some("-1"), Some("many")] {
            assert_eq!(
                ring_capacity(refused),
                DEFAULT_RING_CAPACITY,
                "{refused:?} is not a tuning choice and must fall back"
            );
        }
    }
}
