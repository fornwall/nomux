//! The session daemon: owns the PTY, the ring buffer and the listening socket.
//!
//! Single-threaded around `poll`, with at most one client (`IMPLEMENTATION.md` § 6.4)
//! and one served agent connection (§ 6.7), so the poll set is fixed: the sources in
//! `SINGLE_SOURCES` and nothing else. What this process does to *itself* on the way in
//! is `startup`.

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

use crate::agent::{self, Agent};
use crate::conn::Conn;
use crate::control::{Liveness, liveness};
use crate::linger;
use crate::nbio;
use crate::pty::{self, Pty};
use crate::rundir::{SessionPaths, session_ids};
use crate::startup::{arm_stop_signals, leave_login_session, release_startup_state};

/// Default ring capacity: how long a disconnect can last before scrollback is lost,
/// times the per-host session count `MAX_SESSIONS` backstops (`IMPLEMENTATION.md` § 4).
const DEFAULT_RING_CAPACITY: usize = 4 << 20;

/// Environment override for the ring capacity, in bytes.
const RING_BYTES_ENV: &str = "NOMUX_RING_BYTES";

/// Largest ring this daemon will honour, whatever [`RING_BYTES_ENV`] asks for:
/// `VecDeque::with_capacity` answers a request it cannot serve by aborting the process.
const MAX_RING_CAPACITY: usize = 1 << 30;

/// Resolves the ring capacity from what [`RING_BYTES_ENV`] asked for; nothing here
/// refuses (`IMPLEMENTATION.md` § 4). Zero is filtered rather than passed on, since
/// `Ring::new` clamps it to one byte and a ring that makes every write a gap is no
/// tuning choice.
fn ring_capacity(requested: Option<&str>) -> usize {
    requested
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .map_or(DEFAULT_RING_CAPACITY, |bytes| bytes.min(MAX_RING_CAPACITY))
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

/// How long to keep retrying `waitpid` before reporting a status the daemon invented (§ 6.5).
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

/// Backlog for the session socket: as deep as this host allows (§ 6.3).
const SOCKET_BACKLOG: libc::c_int = -1;

/// Fault injection: restores the pre-fix event ordering of § 6.4.1, where the takeover
/// was serviced before the client it was replacing, so the regression test guarding it
/// can be *shown* to fail (`scripts/verify-takeover-guard.sh`). A `const` rather than a
/// `#[cfg]` block, so both orderings stay compiled and the branch folds away.
const ACCEPT_BEFORE_READ: bool = cfg!(nomux_fault_injection);

/// Fault injection: pause before each `poll`, so a client's input and the takeover that
/// follows it arrive in the same wakeup. `--cfg nomux_fault_settle` enables this alone,
/// under which the guard must still *pass* — proof the delay is not doing the work.
const SETTLE_BEFORE_POLL: bool = cfg!(nomux_fault_injection) || cfg!(nomux_fault_settle);

/// How long that pause is.
const FAULT_SETTLE: Duration = Duration::from_millis(20);

/// How long a connection that has not said `Hello` keeps the one pending slot: a peer
/// that connects and then says nothing would otherwise hold every later attach off for
/// the life of the session. Generous against a relayed `Hello`'s round trip (§ 7).
const PENDING_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Stop accepting client input once this much is queued for a PTY not taking it (§ 4.1).
const MAX_PENDING_INPUT: usize = 1 << 20;

/// The attached client, and the state that means nothing without one.
///
/// One `Option` rather than four fields on the daemon: each belongs to a *particular*
/// client, so an arrival or a departure resets them by moving the whole thing.
#[derive(Debug)]
struct Attached {
    conn: Conn,
    /// Whether this connection has been told the child exited. Per connection, the session
    /// outliving its child (§ 6.5): every later attach hears the status behind its replay.
    exit_sent: bool,
    /// Output offset already queued to this connection.
    sent_through: u64,
    /// Post-gap repaint policy, as this connection's `Hello` stated it (§ 4.3).
    repaint_ctrl_l: bool,
    /// Whether a gap reported to this connection is still owed its repaint (§ 4.3).
    /// Cleared by [`Daemon::pump_output`] once this client holds the whole ring.
    repaint_due: bool,
}

impl Attached {
    /// Takes over the session with a connection that has just said `Hello`; `on_hello`
    /// runs next and resolves everything left provisional here.
    const fn new(conn: Conn) -> Self {
        Self {
            conn,
            exit_sent: false,
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
    /// Read end of the self-pipe [`crate::startup::arm_stop_signals`] armed, or
    /// `None` on a host where it could not be armed at all.
    stop_pipe: Option<OwnedFd>,
    /// Set once a stop signal has been seen; the loop leaves on its next pass (§ 6.5).
    stopping: bool,
    ring: crate::ring::Ring,
    pty: Option<Pty>,
    client: Option<Attached>,
    /// A connection accepted but not yet greeting, and so not yet the client, with the
    /// deadline by which it must. Usually a liveness probe from `list`.
    pending: Option<(Conn, Instant)>,
    /// Agent socket and the connection it is serving, once a session created with
    /// [`nomux_proto::HELLO_AGENT_FORWARD`] has bound one.
    agent: Option<Agent>,
    /// Where the child starts, captured before the daemon moved to `/`.
    child_dir: PathBuf,
    /// Whether `logind` will let this session outlive the user's logout, for `HelloOk`.
    /// Named for what it is: § 6.5 could read the wire's bare "linger" as a grace period.
    logind_linger: Linger,
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
    /// The same for the agent socket, kept apart: holding the session socket out of the
    /// set over an agent's `EMFILE` is an attach that cannot get in.
    agent_accept_retry: Option<Instant>,
    /// When the session last lost its client, for idle reaping. The timestamp alone —
    /// *whether* it is armed is `client.is_none()`, so the two cannot disagree.
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
        // Also to syslog, not only through the `Err` the caller prints: past
        // `release_startup_state` there is no stderr left to reach anybody through.
        crate::syslog::error(session_id, &err.to_string());
    }
    result
}

/// The body of [`run`], separated so that every way out of it is logged once.
fn start(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    paths.ensure_dir()?;

    // Held across the whole of claiming the id, which turns on the evidence `list` and
    // `kill` read. Never blocking, and going ahead unlocked rather than refusing (§ 6.3).
    let publishing = paths.try_lock_spawn();

    // Inside that locked region and before the bind, per § 6.3: taking the lock created
    // `<id>.lock`, which counts as a session, so a refusal that left it behind would
    // ratchet this backstop against itself. Only where a lock came back, and still held.
    let dir = paths.dir();
    if at_session_ceiling(dir, paths.id()) {
        if publishing.is_some() {
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
    // reads as success — a session that never started, reported as started.
    let listener = bind_socket(&paths)?;

    // One fallible region rather than a cleanup per call site: nothing past the bind can
    // be reported, so whatever fails inside `publish`, what it published goes.
    let stop_pipe = match publish(&paths, &listener, label) {
        Ok(stop_pipe) => stop_pipe,
        Err(err) => {
            // Released first: `unlink_all` takes this same lock, and `flock` conflicts
            // between two open descriptions of one file even within a process (§ 6.6).
            drop(publishing);
            paths.unlink_all();
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
        stopping: false,
        ring: crate::ring::Ring::new(ring_capacity(std::env::var(RING_BYTES_ENV).ok().as_deref())),
        pty: None,
        client: None,
        pending: None,
        agent: None,
        child_dir,
        logind_linger: linger::detect(),
        in_applied: 0,
        pending_input: VecDeque::new(),
        win: WinSize::default(),
        child_gone: None,
        exited: None,
        accept_retry: None,
        agent_accept_retry: None,
        last_detach: Instant::now(),
    };

    // The only record that this session ever existed, once its run files are gone.
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
    // A second `listen` for the backlog: it installs one rather than keeping the one in
    // force, so the fork would otherwise leave the queue at the parent's depth (§ 6.2,
    // § 6.3). A wrong depth is no reason to refuse a session, so failure is discarded.
    //
    // SAFETY: `listen` is passed a descriptor `listener` owns and keeps open across
    // the call, and a backlog. `UnixListener` has no safe spelling of a second
    // `listen`, and rustix's would mean adding its `net` feature to the whole crate.
    let _ = unsafe { libc::listen(listener.as_raw_fd(), SOCKET_BACKLOG) };

    // Between the fork and the pidfile: arming after the pidfile `nomux kill` reads
    // (§ 6.6) leaves a window where its signal lands on the default disposition, and
    // arming before the fork lets the parent's `_exit` answer a signal into the pipe.
    let stop_pipe = arm_stop_signals().ok();

    paths.write_pid()?;
    if let Some(label) = label {
        // Advisory: a session is worth more than its name in a listing.
        drop(paths.write_label(label));
    }
    Ok(stop_pipe)
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
    // process. Before the `bind` so there is no window: past the match above, any pidfile
    // here is a dead daemon's by the evidence that licensed removing the socket.
    paths.clear_pid();

    let listener = crate::rundir::bind_socket_private(&path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Whether `dir` already holds [`MAX_SESSIONS`] sessions other than `mine`.
/// `IMPLEMENTATION.md` § 6.3 has the policy, and [`session_ids`] is the rule `list`
/// discovers sessions with (§ 6.6).
fn at_session_ceiling(dir: &Path, mine: &str) -> bool {
    session_ids(dir)
        .iter()
        .filter(|id| id.as_str() != mine)
        .count()
        >= MAX_SESSIONS
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
    /// The proxied agent connection, of which there is at most one (§ 6.7).
    AgentChannel,
}

/// Every source that appears in the poll set at most once, in the order
/// [`Daemon::watches`] registers them. This list is what registers them, so a source
/// added here is one [`POLL_SLOTS`] has already accounted for.
const SINGLE_SOURCES: [Source; 7] = [
    Source::Listener,
    Source::Signal,
    Source::Pty,
    Source::Client,
    Source::Pending,
    Source::AgentListener,
    Source::AgentChannel,
];

/// Slots the poll set can ever need at once, every source being a single one.
const POLL_SLOTS: usize = SINGLE_SOURCES.len();

impl Daemon {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut scratch = Vec::new();
        let mut read_buf = vec![0u8; 64 * 1024];
        let mut ready = Vec::new();

        loop {
            if self.stop_reason().is_some() {
                return Ok(());
            }
            self.poll_once(&mut read_buf, &mut scratch, &mut ready)?;
            // Given back so one large `Input` does not leave 256 KiB held for a week.
            // Cleared first, `shrink_to` not going below the length; `read_buf` stays.
            scratch.clear();
            scratch.shrink_to(0);
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
        if self.stopping {
            Some("signalled")
        } else if self
            .detach_deadline()
            .is_some_and(|at| Instant::now() >= at)
        {
            Some(if self.pty.is_none() {
                "no client ever attached"
            } else {
                "idle with no client"
            })
        } else {
            None
        }
    }

    /// What to ask `poll` about `source`, or `None` where it is not in the set now.
    fn watch_for(&self, source: Source) -> Option<(BorrowedFd<'_>, PollFlags)> {
        match source {
            // Out of the set while an `accept` failure is waited out ([`ACCEPT_BACKOFF`])
            // and while the pending slot is taken: a connection left in the backlog greets
            // when the slot frees, where one accepted on top of the incumbent goes unheard.
            Source::Listener => (self.accept_retry.is_none() && self.pending.is_none())
                .then(|| (self.listener.as_fd(), PollFlags::IN)),
            Source::Signal => Some((self.stop_pipe.as_ref()?.as_fd(), PollFlags::IN)),
            // Dropped once the child is gone: the master reports `HUP` from then on, which
            // would spin the loop for the rest of the session (§ 6.5) with nothing to read.
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
                // § 4.1's back pressure, and only the throttling half of it: what
                // *bounds* the queue is `read_client` declining to decode past the cap.
                let mut flags = if self.input_is_saturated() {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                // Ring bytes still owed count as wanting to write: `pump_output` stops at
                // `MAX_PENDING_WRITE`, so a replay ends passes with the queue drained.
                if client.conn.wants_write() || client.sent_through < self.ring.end() {
                    flags |= PollFlags::OUT;
                }
                // Registered even when the mask is empty: `HUP` and `ERR` are reported
                // whatever it says, the only way to hear a held-back peer die (§ 4.1).
                Some((client.conn.stream().as_fd(), flags))
            }
            Source::Pending => Some((self.pending.as_ref()?.0.stream().as_fd(), PollFlags::IN)),
            // Out of the set on both of the session listener's terms above: an `accept`
            // failure being waited out, and the one slot already taken (§ 6.7). The
            // second matters twice over here — a backlog left readable with nothing
            // willing to accept from it returns from every `poll` at once.
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
                    .is_some_and(|client| client.conn.is_write_saturated());
                let mut flags = if saturated || !wants_read {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                if wants_write {
                    flags |= PollFlags::OUT;
                }
                // Dropped on an empty mask rather than registered for `HUP` alone, as
                // the client above is: a peer that died while the client could not take
                // what it said is nothing anyone can act on yet, and the end of file is
                // still there on the pass that gives the queue its room back.
                (!flags.is_empty()).then_some((fd, flags))
            }
        }
    }

    /// Everything the poll set watches, in the order it is registered, into `ready` and
    /// `fds` in step. Named rather than positional because the set is variable-length,
    /// where index arithmetic would apply one fd's readiness to another.
    fn watches<'a>(&'a self, ready: &mut Vec<(Source, PollFlags)>, fds: &mut [PollFd<'a>]) {
        let mut watch = |source, fd, flags| {
            // Through `get_mut` rather than by index: the budget cannot be reached, so
            // the unreachable state costs a missed wakeup rather than a panic.
            if let Some(slot) = fds.get_mut(ready.len()) {
                *slot = PollFd::from_borrowed_fd(fd, flags);
                ready.push((source, PollFlags::empty()));
            }
        };

        for source in SINGLE_SOURCES {
            if let Some((fd, flags)) = self.watch_for(source) {
                watch(source, fd, flags);
            }
        }
    }

    /// Blocks until something in the poll set is ready, and records what into `ready`.
    /// Split out so [`Daemon::poll_once`] is the § 6.4.1 ordering policy and nothing else,
    /// and so the borrows of `self` end here. An empty `ready` is the `EINTR` case.
    ///
    /// A failing `poll` deliberately ends the session — § 6.4.1's "never propagated" is
    /// about client I/O — and `shutdown` still signals the child and clears the run files.
    fn wait(&self, ready: &mut Vec<(Source, PollFlags)>) -> io::Result<()> {
        ready.clear();
        // A fixed frame, the set having a compile-time maximum. `PollFd` has no vacant
        // spelling, so slots past `ready.len()` are seeded and never shown to `poll`.
        let mut fds: [PollFd<'_>; POLL_SLOTS] = std::array::from_fn(|_| {
            PollFd::from_borrowed_fd(self.listener.as_fd(), PollFlags::empty())
        });
        self.watches(ready, &mut fds);

        let timeout = self.poll_timeout();
        match rustix::event::poll(
            fds.get_mut(..ready.len()).unwrap_or(&mut []),
            Some(&timeout),
        ) {
            Ok(_) => {}
            // Never restarted, and nothing is lost by that: the handler wrote its byte
            // before the syscall returned, so the next pass finds the pipe readable.
            Err(rustix::io::Errno::INTR) => ready.clear(),
            Err(err) => return Err(err.into()),
        }

        for ((_, flags), fd) in ready.iter_mut().zip(fds.iter()) {
            *flags = fd.revents();
        }
        Ok(())
    }

    fn poll_once(
        &mut self,
        read_buf: &mut [u8],
        scratch: &mut Vec<u8>,
        ready: &mut Vec<(Source, PollFlags)>,
    ) -> io::Result<()> {
        if SETTLE_BEFORE_POLL {
            std::thread::sleep(FAULT_SETTLE);
        }
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
        // Against the same reading of the clock, and for the same reason the pending
        // slot has a deadline: the one agent slot is held by whoever has it until
        // something takes it away (§ 6.7).
        if self
            .agent
            .as_mut()
            .is_some_and(|agent| agent.close_if_idle(now))
        {
            self.tell_client(&Frame::AgentClose);
        }
        self.wait(ready)?;
        let revents = |want: Source| {
            ready
                .iter()
                .find(|(source, _)| *source == want)
                .map_or(PollFlags::empty(), |(_, flags)| *flags)
        };
        let readable = PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL;

        // Nothing is read from the pipe: the byte says only that a signal arrived, and
        // the loop leaves on its next pass, too soon to spin on a readable descriptor.
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
        // Reading is not an answer to `HUP` while input is held back: nothing consumes what
        // is left, so `fill` never reaches the zero-length read that would notice.
        if client_events.intersects(PollFlags::HUP | PollFlags::ERR) && self.client.is_some() {
            self.drop_client();
        }
        // Nothing arriving now can be served: a takeover here would spend a second 500 ms
        // flush evicting a client about to be dropped, past § 6.5's shutdown budget.
        if !self.stopping {
            if revents(Source::Pending).intersects(readable) {
                self.read_pending(scratch)?;
            }
            // The same `IN | HUP | ERR` every other source is tested with: `contains(IN)`
            // would leave a listener reporting `ERR` alone in the set with nothing
            // servicing it and no backoff armed, the shape [`ACCEPT_BACKOFF`] rules out.
            if revents(Source::Listener).intersects(readable) {
                self.accept();
            }
        }
        if ACCEPT_BEFORE_READ && client_ready {
            self.read_client(scratch)?;
        }

        let agent_events = revents(Source::AgentChannel);
        if !agent_events.is_empty() {
            self.service_agent_channel(agent_events, read_buf);
        }
        // On the same terms as the session listener above, and for the same reason.
        if revents(Source::AgentListener).intersects(readable) {
            self.accept_agent();
        }

        // Immediately before the pump that turns a status into a frame: `poll_timeout`
        // stops clamping to `STATUS_RETRY` once the status is collected, and with the
        // master out of the poll set nothing would wake the pass that sends the `Exit`.
        self.collect_status();
        self.pump_output();
        self.write_client();
        Ok(())
    }

    /// Sleeps until the next deadline that could stop the daemon, and no longer: every
    /// reaping rule is checked when `poll` returns, so a rule with no wakeup behind it
    /// is documentation rather than behaviour. [`IDLE_TICK`] backstops a quiet session.
    fn poll_timeout(&self) -> Timespec {
        let mut remaining = self.detach_deadline().map_or(IDLE_TICK, |at| {
            at.saturating_duration_since(Instant::now()).min(IDLE_TICK)
        });
        // Come back before [`STATUS_GRACE`] expires on a status merely not readable yet.
        if self.child_gone.is_some() && self.exited.is_none() {
            remaining = remaining.min(STATUS_RETRY);
        }
        // A listener out of the poll set, a pending connection that says nothing, and an
        // agent connection that has gone quiet have no other wakeup that would give the
        // slot back.
        if let Some(at) = [
            self.accept_retry,
            self.agent_accept_retry,
            self.pending.as_ref().map(|(_, at)| *at),
            self.agent.as_ref().and_then(Agent::deadline),
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
    /// is *not* attaching (§ 6.4). Never fails, per § 6.4.1; [`ACCEPT_BACKOFF`] is what
    /// covers a transient one.
    fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                // One at a time: the listener is only in the poll set while the slot is free
                // ([`Daemon::watch_for`]), so nobody is accepted only to be dropped unheard.
                Ok((stream, _)) => {
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
    fn read_pending(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        // Separate from `scratch`, which the outgoing client's final drain below needs
        // while the `Hello` is still borrowed.
        let mut buf = Vec::new();
        let Some((pending, _)) = self.pending.as_mut() else {
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
        // Before the eviction below, not after (§ 6.4). `on_hello` keeps its own copy of
        // the check, for the client that greets again on an established connection.
        if hello.protocol != PROTOCOL_VERSION {
            self.reject_pending(ErrorCode::Version, "protocol version mismatch");
            return Ok(());
        }

        // Final drain of the outgoing connection: input it delivered between the poll
        // and this moment must not be lost to the takeover (§ 6.4.1).
        if !ACCEPT_BEFORE_READ && self.client.is_some() {
            drop(self.read_client(scratch));
        }
        // Hands the session over (`IMPLEMENTATION.md` § 6.4), by the same door as any
        // other refusal — which also drops the agent connection the arriving client
        // knows nothing of. With nobody attached this does nothing at all.
        self.reject(ErrorCode::Takeover, "another client attached");
        self.client = self.pending.take().map(|(conn, _)| Attached::new(conn));
        self.on_hello(&hello)?;
        // Clients pipeline: input riding behind the `Hello` in the same read is
        // already buffered in the connection that was just promoted.
        self.read_client(scratch)
    }

    /// Turns away a connection that cannot have the session, leaving the session alone.
    /// The `code` is a parameter because the client acts on a version mismatch and a
    /// protocol error differently (`DESIGN.md` § 6.4).
    fn reject_pending(&mut self, code: ErrorCode, message: &'static str) {
        if let Some((pending, _)) = self.pending.take() {
            pending.send_last(&Frame::Error { code, message });
        }
    }

    fn read_pty(&mut self, buf: &mut [u8]) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        // [`nbio::read_or_eof`] answers a stray errno with `Eof` rather than propagating
        // it, for the reason [`Daemon::write_pty`] gives about the other half.
        match nbio::read_or_eof(pty.master(), buf) {
            // Always drain, attached or not: an unread PTY blocks the child on write (§ 4).
            nbio::Read::Data(n) => self.ring.push(buf.get(..n).unwrap_or(&[])),
            nbio::Read::Eof => self.on_child_exit(),
            nbio::Read::WouldBlock => {}
        }
    }

    fn write_pty(&mut self) {
        let Some(pty) = self.pty.as_ref() else {
            return;
        };
        // No PTY error ends the session, in either direction — § 6.4.1's rule for the
        // client socket. What this must *not* do is record the exit: `child_gone` drops
        // the master from the poll set, and the read side can still be holding everything
        // the child wrote on its way out.
        if nbio::drain_to(&mut self.pending_input, pty.master()).is_err() {
            self.pending_input.clear();
        }
        // Given back on the way through empty, or one paste into a child that stopped
        // reading holds 1.25 MiB for the rest of the session. The master asks for
        // `POLLOUT` only while this is non-empty, so the pass that empties it is the last.
        if self.pending_input.is_empty() {
            self.pending_input.shrink_to(0);
        }
    }

    /// Records that the child has let go of the terminal; the stamp starts no clock (§ 6.5).
    ///
    /// No status is collected here: end of file precedes reapability for about a third of
    /// exits on this kernel (§ 6.5). [`Daemon::collect_status`] runs later this pass.
    fn on_child_exit(&mut self) {
        if self.child_gone.is_none() {
            self.child_gone = Some(Instant::now());
        }
        // The stamp above just took the master out of the poll set, so `write_pty` will
        // never run again to drain this — and a queue left at [`MAX_PENDING_INPUT`]
        // would hold the client out of `POLLIN` for the rest of the session (§ 6.5).
        self.pending_input.clear();
        self.pending_input.shrink_to(0);
    }

    /// Collects the child's status once `waitpid` will give it up.
    ///
    /// Every pass, not only past end of file: the child can exit while something it
    /// started still holds the slave — `sleep 3600 &` then `exit` — and nothing else would
    /// reap it. Whether the client is *told* is [`Daemon::pump_output`]'s decision; what
    /// this costs is the pid, which makes [`Pty::pid_reissued`] load-bearing.
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
            // The child closed the terminal without exiting — anything that daemonises
            // itself — so no status is coming and the client is still owed an `Exit`.
            self.exited = Some((0, ExitKind::Exited));
        }
    }

    fn read_client(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        let Some(client) = self.client.as_mut() else {
            return Ok(());
        };
        if client.conn.fill().is_err() {
            // A connection failing is the normal case, not a daemon failure (§ 6.4.1). What
            // `fill` had buffered goes undecoded: the client resends from `in_applied` (§ 3).
            self.drop_client();
            return Ok(());
        }

        loop {
            // The cap that actually bounds the queue (§ 4.1), enforced here and not only
            // in the poll set: the takeover path reaches this loop without polling.
            if self.input_is_saturated() {
                // Returning rather than breaking, so the end-of-file test below is
                // skipped: `attach` shuts its write half down on stdin EOF and goes on
                // draining output (§ 7). `poll_once`'s `has_buffered_input` test re-arms
                // this loop once `write_pty` has taken some of the queue.
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
            Frame::Ping => self.tell_client(&Frame::Pong),
            Frame::Detach => self.drop_client(),
            Frame::AgentData { data } => {
                if let Some(agent) = self.agent.as_mut()
                    && !agent.deliver(data)
                {
                    self.close_agent_channel();
                }
            }
            Frame::AgentClose => {
                if let Some(agent) = self.agent.as_mut() {
                    agent.close_from_client();
                }
            }
            _ => self.reject(ErrorCode::Protocol, "frame is not valid from a client"),
        }
        Ok(())
    }

    /// Binds the agent socket and spawns the child, on the `Hello` that creates the
    /// session — what this session *is*, decided once, as against where a particular
    /// client resumes from, which is [`Daemon::on_hello`]'s job on every attach.
    fn start_session(&mut self, hello: &Hello<'_>) -> io::Result<()> {
        // Only the creating `Hello` can turn forwarding on: `SSH_AUTH_SOCK` goes into
        // the child's environment, which cannot be changed afterwards (§ 5.3).
        if hello.agent_forward {
            match Agent::bind(&self.paths.agent()) {
                Ok(agent) => self.agent = Some(agent),
                // A session without an agent is worth having; one that refuses to start is
                // not. `HelloOk` says only `agent: false`, so the reason goes to syslog.
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

        if let Some(pty) = self.pty.as_ref() {
            drop(pty.resize(hello.win));
        } else {
            self.start_session(hello)?;
        }

        let base = self.ring.base();
        let resume_from = if hello.out_offset == RESUME_FROM_START {
            base
        } else {
            // Clamped at both ends (§ 4.2). `min` then `max` rather than `clamp`, which
            // panics on unordered bounds — a bare trap with no message in a shipping build.
            hello.out_offset.min(self.ring.end()).max(base)
        };
        // Not a field on the wire: both ends compute it — `HelloOk::gap` (§ 4.2).
        let gap = resume_from > hello.out_offset;
        if let Some(client) = self.client.as_mut() {
            client.sent_through = resume_from;
            client.repaint_ctrl_l = hello.repaint_ctrl_l;
            // Re-armed, because a second `Hello` on an established connection rewinds the
            // stream and would wait for ever for an `Exit` sent against old offsets.
            client.exit_sent = false;
            // Owed rather than issued here, so an attach-time gap and a mid-stream one
            // share one repaint policy; never cleared by a greeting that reports none.
            client.repaint_due |= gap;
        }
        self.tell_client(&Frame::HelloOk(HelloOk {
            resume_from,
            in_applied: self.in_applied,
            linger: self.logind_linger,
            agent: self.agent.is_some(),
        }));
        Ok(())
    }

    /// Asks the child to redraw after a gap, by whichever means this client chose;
    /// `IMPLEMENTATION.md` § 4.3 has why the choice belongs to the client.
    fn repaint(&mut self) {
        if self.child_gone.is_some() {
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
            drop(pty.nudge_repaint(self.win));
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
            // `on_child_exit` emptied. `in_applied` moves either way (§ 3).
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
        // Both, a status often being collected long before the terminal is free. The
        // `Exit` frame promises the transcript is complete, so end of file on the master
        // is what licenses it — and `since_exit_secs` is measured from that moment.
        let exit = self.child_gone.zip(self.exited);
        let Some(client) = self.client.as_mut() else {
            return;
        };
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

            // The second half of the wrapped deque is only labelled correctly if the first
            // was queued whole, so short progress stops the loop: otherwise a saturated
            // queue labels it too low, corrupting the stream rather than slowing it.
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
        // Coalesced onto the moment this client holds the whole ring rather than issued
        // per gap (§ 4.3).
        let repainting = client.repaint_due && client.sent_through >= end;
        if repainting {
            client.repaint_due = false;
        }
        // Outside the borrow above, the repaint writing to the PTY queue rather than to
        // the client.
        if repainting {
            self.repaint();
        }
    }

    /// Takes one agent connection off the listener and announces it; the backoff is
    /// [`ACCEPT_BACKOFF`]'s, for its reason and with its effect.
    fn accept_agent(&mut self) {
        let serving = self.client.is_some();
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        match agent.accept(serving) {
            agent::Accept::Opened => self.tell_client(&Frame::AgentOpen),
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
        if !events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            return;
        }
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        match agent.read(buf) {
            nbio::Read::Data(n) => {
                let data = buf.get(..n).unwrap_or(&[]);
                if let Some(client) = self.client.as_mut() {
                    client.conn.send_agent_data(data);
                }
            }
            nbio::Read::Eof => self.close_agent_channel(),
            nbio::Read::WouldBlock => {}
        }
    }

    /// Drops the served connection and tells the client, which is holding the other end.
    /// Silent if it was already gone: the client can close it in the same poll iteration
    /// that its socket reports readable.
    fn close_agent_channel(&mut self) {
        if self.agent.as_mut().is_some_and(Agent::forget) {
            self.tell_client(&Frame::AgentClose);
        }
    }

    /// Pushes out what is queued, letting the connection go if it cannot be served.
    ///
    /// Neither condition here wants [`Daemon::drop_client`]'s final flush: the socket has
    /// already failed, or the peer is past `ABANDON_PENDING_WRITE` and so is not reading
    /// (§ 4.1), where `flush_final` would park the daemon for its 500 ms deadline.
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

    /// Stamps the session clientless; everything that belonged to the departing
    /// connection went with it when the `Attached` was dropped. A child that has already
    /// exited changes nothing — the stamp is what reaps either way (§ 6.5).
    fn on_detached(&mut self) {
        self.last_detach = Instant::now();
        // Nothing can answer a signature request with the client gone, so the
        // waiting process should fail now rather than at reattach (§ 6.7).
        if let Some(agent) = self.agent.as_mut() {
            let _ = agent.forget();
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
        daemon.client = Some(Attached::new(Conn::new(ours).expect("a connection")));

        let agent = daemon.agent.as_mut().expect("an agent socket");
        let _served = UnixStream::connect(agent.path()).expect("connect to the agent socket");
        assert_eq!(
            agent.accept(true),
            agent::Accept::Opened,
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
