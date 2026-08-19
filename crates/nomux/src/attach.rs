//! The relay behind `nomux spawn` and `nomux attach`.
//!
//! Deliberately dumb: it moves bytes between stdio and the session socket and never
//! parses a frame, so this side never needs a version bump (`IMPLEMENTATION.md` § 7).
//! It exists for hosts where the client cannot open a `direct-streamlocal` channel
//! straight to the socket.
//!
//! One relay, two ways in ([`Intent`]). Everything past the connection is shared.
//!
//! # Probe outcomes
//!
//! Both modes decide on one probe of the socket, and § 6.3 makes a `connect` that failed
//! for anything but a refusal evidence of nothing.
//!
//! | probe             | `attach`, wanting a session            | `spawn`, wanting a free id |
//! |-------------------|-----------------------------------------|----------------------------|
//! | refused or absent | [`MissingSession`][FailureClass], 127   | start a daemon             |
//! | accepted, this uid's | relay to it                          | [`Collision`][FailureClass], 126 |
//! | accepted, another uid's | [`UnsafeHost`][FailureClass], 126 | [`Uncertain`][FailureClass], 126 |
//! | neither           | [`Retryable`][FailureClass] or [`Uncertain`][FailureClass], 126 | [`Uncertain`][FailureClass], 126 |
//!
//! `usock::connect_within`, behind [`crate::usock::liveness`], has why the last row is the
//! wedged daemon rather than an absent one, and why the third is not an accepted
//! connection at all.

use std::collections::VecDeque;
use std::env;
use std::fmt;
use std::io::{self, Read, Write};
use std::mem::{MaybeUninit, size_of};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{ChildStderr, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};

use crate::rundir::{
    MAX_PID_LEN, SessionPaths, check_run_dir, ensure_run_dir, parse_pid, read_prefix,
};
use crate::usock::{Liveness, liveness};

/// Legacy status for a runtime refusal that does not establish absence.
const EXIT_UNATTACHABLE: u8 = 126;
/// Legacy status for an absent session or a daemon that never became reachable.
const EXIT_NO_SESSION: u8 = 127;

/// How long to wait for a freshly spawned daemon to bind its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Delay between connect retries while waiting for the daemon.
const SPAWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How long any one `connect` to the session socket waits out a full backlog.
///
/// `usock::connect_within` has why every `connect` here is bounded and this one is not a
/// plain `UnixStream::connect` (§ 6.3). Short, because the state it waits out clears in
/// one `accept` and this is on the path of every attach.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay between checks for the pidfile the daemon publishes just after its socket.
///
/// Shorter than [`SPAWN_POLL_INTERVAL`] because the window it covers is two
/// syscalls wide and is usually already over, while the wait itself is on the path
/// of every session creation.
const PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Largest transfer either direction makes in one call, and — by [`Pump::has_data`]'s
/// invariant — the whole of what a [`Pump`] can be holding.
const RELAY_CHUNK: usize = 16 * 1024;

/// How long the final flush waits on a stdout that has moved *nothing*.
///
/// Spent against the worker's last delivery rather than against the whole wait: what is
/// still in flight when the session closes is the worker channel's kernel buffer and one
/// [`RELAY_CHUNK`] behind it — the session's last output, and far more of it than any
/// figure here could assume a destination takes in half a second. A pipe into a congested
/// `sshd`, a serial console, a pager being read a page at a time: each takes all of it,
/// none of them fast, and none of them the stopped stdout this bound is for, which moves
/// nothing at all. The one case the two still look alike from this side is a single write
/// that outlasts the window on its own, and that is what keeps the wait bounded rather
/// than merely long.
const STDOUT_FLUSH_TIMEOUT: Duration = Duration::from_millis(500);

/// How often the final flush looks up from the status read to see whether the worker has
/// delivered anything since the last look.
///
/// Only granularity: it bounds how much of a window a delivery that arrives just after a
/// look can lose, and nothing waits for it in the ordinary case, where the status itself
/// ends the read.
const STDOUT_PROGRESS_INTERVAL: Duration = Duration::from_millis(25);

/// Whether this invocation may bring the session into being — the whole of the
/// distinction between the two modes (`DESIGN.md` § 5.1).
#[derive(Clone, Copy)]
pub(crate) enum Intent<'a> {
    /// `nomux spawn <id>`: creates the session and attaches to it in one exec, and
    /// refuses an id something is already serving. Carries the label the new daemon is
    /// started with — a label belongs to the session rather than to the connection
    /// (§ 6.6), so this is the only mode with anywhere to put one.
    Create(Option<&'a str>),
    /// `nomux attach <id>`: relays to a session that exists, and refuses one that
    /// does not rather than quietly starting a second.
    Resume,
}

/// Stable machine-readable reason a relay invocation failed.
///
/// The variants deliberately describe the client's next decision instead of an errno:
/// several different syscalls can say that retrying is safe, while the same `TimedOut`
/// means retrying an `attach` but not a `spawn` whose id was never proved free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureClass {
    /// `spawn` found a live session already occupying the requested id.
    Collision,
    /// Repeating the same invocation after bounded backoff is safe.
    Retryable,
    /// This host cannot currently provide a trusted run-directory or locking boundary.
    UnsafeHost,
    /// The invocation established neither that the session exists nor that it is absent.
    Uncertain,
    /// `attach` found no session at the requested id.
    MissingSession,
    /// `spawn` proved the id free and could not launch a daemon at all. A daemon that
    /// *was* launched and then missed its publication deadline is [`Self::Uncertain`]:
    /// nothing here can prove it will not bind the socket a moment later.
    StartupFailure,
    /// The relay reached the session and subsequently failed locally.
    PostConnect,
}

impl FailureClass {
    const fn details(self) -> (&'static str, u8) {
        match self {
            Self::Collision => ("collision", EXIT_UNATTACHABLE),
            Self::Retryable => ("retryable", EXIT_UNATTACHABLE),
            Self::UnsafeHost => ("unsafe-host", EXIT_UNATTACHABLE),
            Self::Uncertain => ("uncertain", EXIT_UNATTACHABLE),
            Self::MissingSession => ("missing-session", EXIT_NO_SESSION),
            Self::StartupFailure => ("startup-failure", EXIT_NO_SESSION),
            Self::PostConnect => ("post-connect", 1),
        }
    }

    /// Token carried by the versioned stderr record.
    pub(crate) const fn token(self) -> &'static str {
        self.details().0
    }

    /// Existing process status retained for clients that do not read the stderr record.
    pub(crate) const fn exit_code(self) -> u8 {
        self.details().1
    }
}

/// A classified runtime failure of `spawn` or `attach`.
#[derive(Debug)]
pub(crate) struct Failure {
    class: FailureClass,
    source: io::Error,
}

impl Failure {
    const fn new(class: FailureClass, source: io::Error) -> Self {
        Self { class, source }
    }

    /// Machine-readable class of this failure.
    pub(crate) const fn class(&self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

/// Either malformed session input or a classified runtime relay failure.
///
/// Usage remains exit 64 and is intentionally absent from the runtime record's closed set.
#[derive(Debug)]
pub(crate) enum RunError {
    /// A session id that cannot name a session on this command line.
    Usage(io::Error),
    /// A runtime outcome carrying a stable [`FailureClass`].
    Classified(Failure),
}

impl From<Failure> for RunError {
    fn from(failure: Failure) -> Self {
        Self::Classified(failure)
    }
}

/// Reaches the session `session_id` names, per `intent`, and relays stdio to it.
///
/// # Errors
///
/// Fails if the session cannot be reached or created, or if relaying fails. The two are
/// separate kinds, which is [`relay_failed`]'s whole job.
pub(crate) fn run(session_id: &str, intent: Intent<'_>) -> Result<(), RunError> {
    let paths = SessionPaths::new(session_id).map_err(|err| {
        if err.kind() == io::ErrorKind::InvalidInput {
            RunError::Usage(err)
        } else {
            Failure::new(FailureClass::UnsafeHost, err).into()
        }
    })?;
    let stream = match intent {
        Intent::Create(label) => create(&paths, label)?,
        Intent::Resume => resume(&paths)?,
    };
    relay(&stream).map_err(|err| relay_failed(&err).into())
}

/// Classifies a failure of the relay itself, which has already had the session.
///
/// Everything else out of [`run`] describes why this mode could not reach the session. A
/// relay that connected, ran for an hour and then met `ENOSPC` writing the stdout the user
/// redirected has already established that the host and session were usable. Calling that
/// [`FailureClass::PostConnect`] is what tells a client to retry `attach`, rather than to
/// take the host out of rotation over a full disk.
///
/// One class for all of them, since none of what `relay` can propagate — `poll`,
/// [`Pump::fill_from`], [`Pump::drain_to`] — says anything about the session, and nothing
/// else in this crate constructs it.
fn relay_failed(err: &io::Error) -> Failure {
    Failure::new(
        FailureClass::PostConnect,
        io::Error::other(format!("relaying to the session failed: {err}")),
    )
}

/// Connects to a session that is already there, and refuses to invent one that is not.
fn resume(paths: &SessionPaths) -> Result<UnixStream, Failure> {
    // Checked and never created, which is `list` and `kill`'s rule (§ 6.3) and is
    // this mode's now that it creates nothing either. A directory that is not there
    // holds no session, which is the refusal below rather than a failure of its own.
    if !check_run_dir(paths.dir()).map_err(|err| Failure::new(FailureClass::UnsafeHost, err))? {
        return Err(no_such_session(paths));
    }
    match liveness(&paths.socket(), CONNECT_TIMEOUT) {
        Liveness::Alive(stream) => Ok(stream),
        Liveness::Stale(_) => Err(no_such_session(paths)),
        Liveness::Unknown(err) => Err(unattachable(paths, &err)),
    }
}

/// `attach` on an id nothing is serving — never created here, or reaped, which are not
/// told apart because both want the same next command.
fn no_such_session(paths: &SessionPaths) -> Failure {
    Failure::new(
        FailureClass::MissingSession,
        io::Error::other(format!(
            "no session {id}: nothing answers on {sock}. `nomux spawn {id}` starts one",
            id = paths.id(),
            sock = paths.socket().display(),
        )),
    )
}

/// `attach` on an id whose socket did not answer with life or death.
///
/// The error is quoted rather than summarised: it is the whole of what was established,
/// and it is not always about a probe that failed — a socket somebody else bound answered
/// perfectly well (`usock::Foreign`).
fn unattachable(paths: &SessionPaths, err: &io::Error) -> Failure {
    Failure::new(
        resume_probe_class(err),
        io::Error::other(format!(
            "session {id} could not be joined: {err}. `nomux list` says what this host holds",
            id = paths.id(),
        )),
    )
}

/// Transient resource pressure under which repeating an `attach` is safe, and the one
/// refusal that establishes something instead: a socket this uid may not speak to.
fn resume_probe_class(err: &io::Error) -> FailureClass {
    let transient_kind = matches!(
        err.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::OutOfMemory
    );
    let transient_errno = matches!(
        err.raw_os_error(),
        Some(libc::EAGAIN | libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS)
    );
    if transient_kind || transient_errno {
        FailureClass::Retryable
    } else if err.kind() == io::ErrorKind::PermissionDenied {
        // A socket bound by another uid, or one this uid may not reach through the run
        // directory's modes: either way the boundary § 6.3 requires is not there, which is
        // a fact about the host and not an outcome that a retry could settle.
        FailureClass::UnsafeHost
    } else {
        FailureClass::Uncertain
    }
}

/// `spawn` on an id something is already serving: the client's own state disagreeing with
/// the host's rather than a race to retry.
fn already_running(paths: &SessionPaths) -> Failure {
    Failure::new(
        FailureClass::Collision,
        io::Error::other(format!(
            "session {id} already exists: something answers on {sock}. \
             `nomux attach {id}` joins it",
            id = paths.id(),
            sock = paths.socket().display(),
        )),
    )
}

/// `spawn` on an id whose socket answered neither death nor life: [`already_running`]'s
/// kind on weaker evidence, `spawn` being allowed to create only an id it can say is free.
/// The error is quoted for [`unattachable`]'s reason.
fn may_be_running(paths: &SessionPaths, err: &io::Error) -> Failure {
    Failure::new(
        FailureClass::Uncertain,
        io::Error::other(format!(
            "session {id} may already exist: {err}. `nomux attach {id}` joins it if so",
            id = paths.id(),
        )),
    )
}

/// Creates the session under an exclusive lock, and refuses an id that answers.
///
/// The lock serialises concurrent spawns so two clients racing on the same id
/// produce one daemon, not two fighting over the socket path. It is held to the end
/// of the function rather than released after the spawn, because garbage collection
/// takes the same lock (`IMPLEMENTATION.md` § 6.6): while it is held, nothing can
/// unlink the socket this is waiting for.
fn create(paths: &SessionPaths, label: Option<&str>) -> Result<UnixStream, Failure> {
    // Before the lock and the probe below, not on the way to spawning a daemon. The
    // socket this is about to hand the user's keystrokes to is a *name* in the run
    // directory (§ 6.3), and where that directory is a symlink into somewhere another
    // user can write, the name is theirs to make: checking only when nothing answers
    // checks only the case where nothing was planted.
    ensure_run_dir(paths.dir()).map_err(|err| Failure::new(FailureClass::UnsafeHost, err))?;

    // A collector may unlink `<id>.lock` while this call is blocked on it, which
    // `rundir::SpawnLock` has: the lock that comes back is the one on the file now at
    // the path.
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    let spawn_lock = paths.lock_spawn_until(deadline).map_err(|err| {
        let class = if err.kind() == io::ErrorKind::ResourceBusy {
            FailureClass::Retryable
        } else {
            FailureClass::UnsafeHost
        };
        Failure::new(class, err)
    })?;

    let socket = paths.socket();
    // Once, and under the lock: another spawn may have created the session while we
    // waited for it, and the loser of that race is refused rather than handed the
    // winner's session — two tabs both told they created this one is exactly the
    // confusion the split exists to end.
    match liveness(&socket, CONNECT_TIMEOUT) {
        // Dropped on the spot, which costs the daemon a pending connection that
        // closes without greeting — the same nothing `list`'s probe costs it (§ 6.4).
        Liveness::Alive(_) => return Err(already_running(paths)),
        Liveness::Stale(_) => {}
        Liveness::Unknown(err) => return Err(may_be_running(paths, &err)),
    }

    let complaint = match daemon_command(paths.id(), label, spawn_lock.raw_fd())
        .and_then(|mut command| command.spawn())
        .map(|mut child| child.stderr.take())
    {
        Ok(complaint) => complaint,
        // The one failure with nothing of anyone's behind it: no daemon was started, and
        // the probe above has just said nobody else is serving the id either, so the
        // name is this call's own to give back — where this acquisition is what made it,
        // which `release_lock_name` is what decides.
        Err(err) => {
            paths.release_lock_name(&spawn_lock);
            return Err(Failure::new(FailureClass::StartupFailure, err));
        }
    };

    loop {
        match liveness(&socket, CONNECT_TIMEOUT) {
            Liveness::Alive(stream) => {
                if await_publication(paths, deadline) {
                    return Ok(stream);
                }
                return Err(start_timed_out(paths, complaint));
            }
            Liveness::Stale(_) => {
                if Instant::now() >= deadline {
                    return Err(start_timed_out(paths, complaint));
                }
                std::thread::sleep(SPAWN_POLL_INTERVAL);
            }
            // The daemon this call started may be the very thing that would not answer,
            // so this says as little about the id as the probe before the spawn did —
            // and the name is left alone for that reason rather than for the other one.
            Liveness::Unknown(err) => return Err(may_be_running(paths, &err)),
        }
    }
}

/// A daemon that did not finish publishing before the spawn deadline.
fn start_timed_out(paths: &SessionPaths, complaint: Option<ChildStderr>) -> Failure {
    let id = paths.id();
    let complaint = daemon_complaint(complaint).map_or_else(
        || format!("daemon for session {id} did not finish starting"),
        |said| format!("daemon for session {id} did not finish starting: {said}"),
    );
    Failure::new(
        FailureClass::Uncertain,
        io::Error::new(io::ErrorKind::TimedOut, complaint),
    )
}

/// Keeps the spawn lock until the daemon this spawn started has published
/// `<id>.pid`.
///
/// This is what makes the lock mean what the rest of the layout assumes it means.
/// The daemon binds its socket before it writes the pidfile (§ 6.2), so a `connect`
/// that succeeds says the id is claimed and not that anything on disk says so yet —
/// and a `kill` taking the lock inside that window finds a live daemon and no pid,
/// which § 6.6 forbids it to unlink over.
///
/// Bounded by the caller's own deadline. A successful `connect` alone is not publication:
/// the listener is bound before the daemon arms its signals and writes the pidfile, so any
/// failure in that window closes a stream the relay would otherwise already have returned.
/// A complete pidfile is the frozen control surface's witness that startup finished.
fn await_publication(paths: &SessionPaths, deadline: Instant) -> bool {
    // Built once. `SessionPaths::pid` allocates, and this loop runs every
    // millisecond for as long as the caller's deadline allows.
    let pid = paths.pid();
    let mut buf = [0u8; MAX_PID_LEN];
    loop {
        if read_prefix(&pid, &mut buf).is_ok_and(|body| parse_pid(body).is_some()) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(PUBLISH_POLL_INTERVAL.min(remaining));
    }
}

/// Whatever the daemon managed to say before it stopped saying anything.
///
/// Read without waiting. This is only ever called once the daemon has already missed
/// its deadline, and one that is wedged with its stderr still open must not take the
/// relay down with it — a blocking read here would turn a five-second timeout into a
/// hang.
fn daemon_complaint(stderr: Option<ChildStderr>) -> Option<String> {
    let stderr = stderr?;
    let fd = stderr.as_fd();
    // Added to what is there rather than assigned over it: `fcntl_setfl` replaces the
    // whole status word, and every other site in the tree does the `getfl`-then-or.
    let flags = rustix::fs::fcntl_getfl(fd).ok()?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).ok()?;
    let mut buf = [0u8; 512];
    // Through `nbio`, like every other read in the tree: a signal landing on this one
    // would report a daemon that explained itself as one that said nothing. `EAGAIN`
    // still falls through to `None`, which is what "it wrote nothing" means here.
    let read = crate::nbio::read(fd, &mut buf).ok()?;
    let text = String::from_utf8_lossy(buf.get(..read)?).into_owned();
    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    // The daemon reached this through `main`'s reporter, which prefixes the binary's
    // own name. Keeping it would render as `nomux: ... : nomux: ...`.
    let line = line.strip_prefix("nomux: ").unwrap_or(line);
    // Escaped, like the pidfile bodies `control` quotes with `{:?}` and for the same
    // reason: this is another process's stderr on its way to a terminal, where the
    // `lines` above stops a second line being forged but not an `ESC ]0;` retitling
    // the window of whoever ran the attach.
    Some(line.escape_debug().collect())
}

/// Moves bytes between stdio and the socket until either side closes.
fn relay(stream: &UnixStream) -> io::Result<()> {
    // A blocking socket could park one direction while leaving the other unserved.
    stream.set_nonblocking(true)?;

    let stdin = io::stdin();
    // stdout may share its open-file description with the caller's shell, so a worker
    // owns its blocking writes behind a bounded, non-blocking socketpair (§ 7).
    let stdout = StdoutWorker::spawn()?;
    let stdin_fd = stdin.as_fd();
    let stdout_fd = stdout.fd();
    let sock_fd = stream.as_fd();

    let mut to_socket = Pump::default();
    let mut to_stdout = Pump::default();
    // Neither direction transfers during the other's call, so one buffer serves both.
    let mut chunk = [0u8; RELAY_CHUNK];
    let mut stdin_open = true;
    let mut socket_open = true;
    // Unlike the other two, this describes a destination.
    let mut stdout_open = true;

    while stdout_open && (socket_open || to_stdout.has_data()) {
        let mut stdin_flags = PollFlags::empty();
        stdin_flags.set(PollFlags::IN, stdin_open && !to_socket.has_data());
        let mut socket_flags = PollFlags::empty();
        socket_flags.set(PollFlags::IN, socket_open && !to_stdout.has_data());
        socket_flags.set(PollFlags::OUT, to_socket.has_data());
        let mut stdout_flags = PollFlags::empty();
        stdout_flags.set(PollFlags::OUT, to_stdout.has_data());
        // A fixed frame, seeded as `daemon::wait` seeds its slots and for its reasons.
        let mut fds: [PollFd<'_>; 3] =
            std::array::from_fn(|_| PollFd::from_borrowed_fd(sock_fd, PollFlags::empty()));
        let mut watched = 0;
        for (fd, flags, always_watch) in [
            (stdin_fd, stdin_flags, false),
            (sock_fd, socket_flags, false),
            // Even while nothing is queued, the worker closing its channel is the
            // notification that actual stdout failed. An fd with no requested events
            // sleeps normally and still reports `HUP`/`ERR`.
            (stdout_fd, stdout_flags, true),
        ] {
            if (always_watch || !flags.is_empty())
                && let Some(slot) = fds.get_mut(watched)
            {
                *slot = PollFd::from_borrowed_fd(fd, flags);
                watched += 1;
            }
        }
        // The live relay has no deadline; every wakeup it needs is a readiness event.
        match rustix::event::poll(fds.get_mut(..watched).unwrap_or(&mut []), None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(err.into()),
        }
        // Reuse the registration masks so state changes cannot shift these positions.
        let mut events = fds.iter().map(PollFd::revents);
        let mut revents = |registered: bool| {
            if registered {
                events.next().unwrap_or_else(PollFlags::empty)
            } else {
                PollFlags::empty()
            }
        };
        let stdin_events = revents(!stdin_flags.is_empty());
        let socket_events = revents(!socket_flags.is_empty());
        let stdout_events = revents(true);

        // `ERR` and `NVAL` alongside `HUP`, as `daemon::wait` has them: a source
        // reporting one of those alone would otherwise never be read, never be closed,
        // and spin in the poll set.
        let readable = PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL;

        // `NVAL` is the one of those three the read cannot then report: an fd `poll` says
        // is not open answers `EBADF`, which is none of the endings [`Pump::fill_from`]
        // folds in, so it would come back out of here as a failure of a relay whose
        // output direction is still perfectly good. A stdin that is gone is an ending,
        // and it ends this direction exactly as end of file does.
        let stdin_gone = stdin_events.contains(PollFlags::NVAL);
        if stdin_events.intersects(readable)
            && (stdin_gone || !to_socket.fill_from(stdin_fd, &mut chunk)?)
        {
            stdin_open = false;
            // Half-close propagation (§ 7).
            drop(stream.shutdown(Shutdown::Write));
        }
        // `HUP` and `ERR` arrive unrequested, so an `OUT`-only pass reaches here too:
        // without the emptiness check that would read a second chunk into a full pump.
        if socket_events.intersects(readable)
            && !to_stdout.has_data()
            && !to_stdout.fill_from(sock_fd, &mut chunk)?
        {
            socket_open = false;
        }
        // Speculative on a non-empty buffer as well as on `POLLOUT`: this descriptor was
        // made non-blocking at the top, so an optimistic write costs at worst one
        // `EAGAIN`. An `EPIPE` ends only this upload direction; the peer may still have
        // output to deliver.
        if (socket_events.contains(PollFlags::OUT) || to_socket.has_data())
            && !to_socket.drain_to(sock_fd)?
        {
            stdin_open = false;
        }
        // The destination here is the worker channel, not inherited stdout. It is
        // non-blocking, and its peer closing is how a stdout failure wakes this loop
        // even when the output pump happens to be empty.
        if stdout_events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            stdout_open = false;
        } else if stdout_events.contains(PollFlags::OUT) {
            stdout_open = to_stdout.drain_to(stdout_fd)?;
        }
    }

    // Closing the channel puts EOF behind queued bytes. Errors bypass this wait, and
    // the process's exit ends a detached worker still blocked in abandoned stdout.
    stdout.finish()
}

/// The blocking half of the relay's stdout boundary.
///
/// The main loop owns one non-blocking endpoint and never writes inherited stdout.
/// This worker thread owns the other endpoint and at most one [`RELAY_CHUNK`] in
/// userspace; the socketpair's kernel buffer is the remaining fixed bound. A blocked
/// terminal, pipe, socket or regular file therefore backpressures session output
/// without preventing the main loop from forwarding input.
struct StdoutWorker {
    channel: UnixStream,
    /// How many batches the worker has got into inherited stdout, which is the only sign
    /// of life [`Self::finish`] has while the write itself is another thread's blocking
    /// syscall. Its *value* is never used, only its changing.
    ///
    /// Not a byte on the channel, which would have been the obvious place for it: nothing
    /// reads that direction until [`Self::finish`] does, so a heartbeat per batch would
    /// accumulate in the socketpair's buffer for the whole session and eventually leave
    /// the worker's own status write with nowhere to go — turning the stdout failure it
    /// reports into a relay that hangs instead.
    progress: Arc<AtomicU64>,
}

/// What [`StdoutWorker::spawn`] hands the thread it starts: `pthread_create` carries one
/// pointer, and the worker needs both its end of the channel and the counter.
struct Handoff {
    channel: UnixStream,
    progress: Arc<AtomicU64>,
}

impl StdoutWorker {
    fn spawn() -> io::Result<Self> {
        let (channel, worker_channel) = UnixStream::pair()?;
        channel.set_nonblocking(true)?;
        let progress = Arc::new(AtomicU64::new(0));
        // A thread cannot outlive an abruptly killed relay, and the socketpair reports
        // completion. A bare pthread also keeps about 20 KiB of generic thread machinery
        // out of § 8's 400 KiB release budget; remeasure before replacing it.
        let handoff = Box::into_raw(Box::new(Handoff {
            channel: worker_channel,
            progress: Arc::clone(&progress),
        }));
        let mut worker = MaybeUninit::uninit();
        // SAFETY: `handoff` owns a valid, Send allocation which the entry point takes
        // exactly once. `worker` points at storage for pthread_t, and the default
        // attributes remain valid for the thread's lifetime.
        let error = unsafe {
            libc::pthread_create(
                worker.as_mut_ptr(),
                std::ptr::null(),
                stdout_worker,
                handoff.cast(),
            )
        };
        if error != 0 {
            // SAFETY: pthread_create failed, so no thread took this allocation.
            drop(unsafe { Box::from_raw(handoff) });
            return Err(io::Error::from_raw_os_error(error));
        }
        // SAFETY: a successful pthread_create initialized `worker`.
        let worker = unsafe { worker.assume_init() };
        // The channel carries completion as well as output, so no join handle is needed.
        // SAFETY: the successful pthread_create returned a live, joinable thread.
        let error = unsafe { libc::pthread_detach(worker) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(Self { channel, progress })
    }

    fn fd(&self) -> BorrowedFd<'_> {
        self.channel.as_fd()
    }

    /// Closes after queued bytes and waits for proof they were delivered.
    ///
    /// The wait ends [`STDOUT_FLUSH_TIMEOUT`] after the last thing the worker moved, so a
    /// stdout that stops draining cannot keep an already-closed relay alive forever and a
    /// slow one is not cut off with the session's last output still in flight. Every pass
    /// computes the window that is left rather than handing the whole of it to the read:
    /// `SO_RCVTIMEO` restarts per `recv` — as `conn::flush_final` has for `SO_SNDTIMEO` —
    /// so a bound set once would be a bound per syscall, and this read takes up to four.
    fn finish(mut self) -> io::Result<()> {
        self.channel.set_nonblocking(false)?;
        drop(self.channel.shutdown(Shutdown::Write));
        let mut status = [0; size_of::<i32>()];
        let mut filled = 0;
        // Relaxed throughout: nothing is published *with* the counter, and a comparison
        // against the last value seen needs no more than that this location's own writes
        // arrive in order.
        let mut seen = self.progress.load(Ordering::Relaxed);
        let mut window = Instant::now() + STDOUT_FLUSH_TIMEOUT;
        while filled < status.len() {
            let remaining = window.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.channel
                .set_read_timeout(Some(remaining.min(STDOUT_PROGRESS_INTERVAL)))?;
            let delivered = match self
                .channel
                .read(status.get_mut(filled..).unwrap_or(&mut []))
            {
                // The worker closes its end without writing a status only if it died
                // before it could, which is not something to report as a clean flush.
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(read) => {
                    filled += read;
                    true
                }
                // Every one of these three is "come back and look again": the interval
                // above expiring, a signal, and a socket that answered neither.
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    false
                }
                Err(err) => return Err(err),
            };
            let progress = self.progress.load(Ordering::Relaxed);
            if delivered || progress != seen {
                seen = progress;
                window = Instant::now() + STDOUT_FLUSH_TIMEOUT;
            }
        }
        match i32::from_ne_bytes(status) {
            0 => Ok(()),
            error if error > 0 => Err(io::Error::from_raw_os_error(error)),
            _ => Err(io::Error::other("relay stdout worker failed")),
        }
    }
}

extern "C" fn stdout_worker(handoff: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: spawn passed ownership of a Box<Handoff> as this pointer.
    let handoff = unsafe { Box::from_raw(handoff.cast::<Handoff>()) };
    let Handoff {
        mut channel,
        progress,
    } = *handoff;
    let status = match copy_channel_to_stdout(&channel, &progress) {
        Ok(()) => 0,
        Err(error) => error.raw_os_error().filter(|raw| *raw > 0).unwrap_or(-1),
    };
    drop(channel.write_all(&status.to_ne_bytes()));
    std::ptr::null_mut()
}

/// Copies the bounded worker channel to actual stdout.
///
/// One chunk at a time and one write per readiness event. The write may still block
/// after making partial progress — that is exactly why it lives on this thread — while
/// an inherited non-blocking stdout remains correct because `EAGAIN` goes back through
/// `poll`. `EPIPE` is the ordinary "stdout's reader left" ending [`Pump::drain_to`]
/// already defines.
///
/// `progress` counts the writes that actually moved something, which is the whole of what
/// [`StdoutWorker::finish`] has to tell a slow stdout from a stopped one. Moved rather
/// than merely attempted, because an inherited stdout may itself be non-blocking: a
/// descriptor answering `POLLOUT` and then `EAGAIN` for ever is precisely the stall that
/// wait exists to give up on.
fn copy_channel_to_stdout(channel: &UnixStream, progress: &AtomicU64) -> io::Result<()> {
    let stdout = io::stdout();
    let stdout_fd = stdout.as_fd();
    let channel_fd = channel.as_fd();
    let mut pump = Pump::default();
    let mut chunk = [0u8; RELAY_CHUNK];

    loop {
        if !pump.has_data() && !pump.fill_from(channel_fd, &mut chunk)? {
            return Ok(());
        }
        while pump.has_data() {
            let mut ready = [PollFd::from_borrowed_fd(stdout_fd, PollFlags::OUT)];
            match rustix::event::poll(&mut ready, None) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(err) => return Err(err.into()),
            }
            let events = ready.first().map_or_else(PollFlags::empty, PollFd::revents);
            if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                return Ok(());
            }
            let owed = pump.owed();
            if events.contains(PollFlags::OUT) && !pump.drain_to(stdout_fd)? {
                return Ok(());
            }
            if pump.owed() < owed {
                progress.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// One direction of the relay, whose whole state is whatever the destination would not
/// take yet: which of the two ends the poll set wants is that and its negation.
#[derive(Debug, Default)]
struct Pump {
    /// Bytes the destination would not take yet, never more than one [`RELAY_CHUNK`].
    buf: VecDeque<u8>,
}

impl Pump {
    /// Whether anything is still held in userspace for the destination: the only reason
    /// to poll that destination for writability, and — negated — the only condition under
    /// which the source is read at all, so nothing can overtake bytes already owed.
    fn has_data(&self) -> bool {
        self.owed() != 0
    }

    /// How much the destination has still not taken, which a caller comparing it across a
    /// [`Self::drain_to`] uses to tell a write that moved something from one that did not.
    fn owed(&self) -> usize {
        self.buf.len()
    }

    /// Takes one batch off `src` for the destination. `false` means `src` reached EOF.
    fn fill_from(&mut self, src: BorrowedFd<'_>, chunk: &mut [u8]) -> io::Result<bool> {
        match crate::nbio::read(src, chunk) {
            // Four shapes of one ending. A PTY-backed peer reports end of session as `EIO`
            // rather than 0; a socket peer that closed with bytes of *ours* still unread
            // hands over the last of its own and then answers `ECONNRESET` — the ordinary
            // way a session ends here (§ 4.1), and a failure here would cost the relay the
            // exit status § 10 gives a delivered `Exit` frame; and `ENOTCONN` where the
            // connection is already gone by the time the read lands.
            Ok(0)
            | Err(
                rustix::io::Errno::IO | rustix::io::Errno::CONNRESET | rustix::io::Errno::NOTCONN,
            ) => Ok(false),
            Ok(n) => {
                self.buf.extend(chunk.get(..n).unwrap_or(&[]));
                Ok(true)
            }
            // Nothing pending is not EOF: the peer is still there with nothing to say.
            Err(rustix::io::Errno::AGAIN) => Ok(true),
            Err(err) => Err(err.into()),
        }
    }

    /// Hands the destination whatever is owed it. `false` means the destination has
    /// stopped reading.
    fn drain_to(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        match crate::nbio::drain_to(&mut self.buf, fd) {
            // `EPIPE` is `nbio`'s to report and each caller's to interpret: here it is
            // the destination's reader having gone — an ordinary ending rather than a
            // failure — so what was owed it is dropped and the answer comes back as
            // `false`. Which direction that ends is `relay`'s to say, not this
            // method's, and only one of the two stops the loop.
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                self.buf.clear();
                Ok(false)
            }
            outcome => outcome.map(|()| true),
        }
    }
}

/// The daemon [`create`] starts, up to the `fork`.
///
/// Execs the exact inode this relay is already running rather than whatever the install
/// path names by the time the child gets there — between the two loads that path decides
/// what the daemon *is*. `arg0` puts the ordinary name back on the command line, so what
/// `ps` shows is the program rather than the link it was reached through.
fn daemon_command(session_id: &str, label: Option<&str>, lock_fd: i32) -> io::Result<Command> {
    let mut command = Command::new("/proc/self/exe");
    command
        .arg0(env::current_exe()?)
        .arg("daemon")
        .arg(session_id)
        .arg("--lock-fd")
        .arg(lock_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The caller reads this pipe only if publication misses its deadline.
        .stderr(Stdio::piped());
    // Cut and escaped on this side of the exec: the daemon records the label it is given
    // (§ 6.6), so the bound is this side's to spend.
    let label = label
        .map(crate::sanitize::sanitize_label)
        .filter(|label| !label.is_empty());
    if let Some(label) = label.as_deref() {
        command.arg("--label").arg(label);
    }
    let pre_exec = move || -> io::Result<()> {
        rustix::process::setsid()?;
        // `SpawnLock` opens `CLOEXEC`. Clear it only in the forked child, so the descriptor
        // survives the exec. The daemon validates it against the current lock path and
        // restores `CLOEXEC` before the shell.
        // SAFETY: `lock_fd` belongs to the lock held across `Command::spawn` by the caller.
        let lock = unsafe { BorrowedFd::borrow_raw(lock_fd) };
        rustix::io::fcntl_setfd(lock, rustix::io::FdFlags::empty())?;
        Ok(())
    };
    // SAFETY: the closure runs after fork and calls only async-signal-safe operations.
    unsafe {
        command.pre_exec(pre_exec);
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::{self, Write as _};
    use std::time::Instant;

    use super::{
        ChildStderr, FailureClass, SessionPaths, await_publication, daemon_command,
        daemon_complaint, resume_probe_class, unattachable,
    };
    use crate::scratch::Scratch;
    use crate::usock::Foreign;

    /// The caller's label reaches `exec` already cut and already stripped of the terminal
    /// control it arrived with — the daemon records what it is given, so the bound and the
    /// escaping both have to be spent on this side of the handoff.
    #[test]
    fn launched_labels_are_bounded_before_the_daemon_exec() {
        let label = format!("\u{1b}]0;ignored\u{7}  $HOME/{}", "é".repeat(200));
        let expected = crate::sanitize::sanitize_label(&label);
        assert!(expected.len() <= crate::sanitize::MAX_LABEL_LEN);
        assert!(label.len() > crate::sanitize::MAX_LABEL_LEN, "cut nothing");

        let direct = daemon_command("session", Some(&label), 19).unwrap();
        assert_eq!(
            direct.get_args().last().and_then(OsStr::to_str),
            Some(&*expected)
        );
    }

    #[test]
    fn the_daemon_command_line_carries_the_lock_and_the_raw_label() {
        let command = daemon_command("session", Some("cost $5"), 23).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            ["daemon", "session", "--lock-fd", "23", "--label", "cost $5"]
        );
    }

    /// A socket can accept before the daemon has written the pidfile. Only the complete
    /// regular-file body `kill` can later act on makes that connection a finished startup.
    #[test]
    fn publication_requires_a_complete_pidfile() {
        let root = Scratch::new("attach-publication");
        let paths = SessionPaths::in_dir(root.path(), "session").expect("resolve session paths");
        let pid = paths.pid();

        assert!(
            !await_publication(&paths, Instant::now()),
            "absence is not publication"
        );
        fs::create_dir(&pid).expect("plant a directory at the pidfile");
        assert!(
            !await_publication(&paths, Instant::now()),
            "a node that merely exists is not publication"
        );
        fs::remove_dir(&pid).expect("remove the planted directory");

        for incomplete in [b"".as_slice(), b"1234"] {
            fs::write(&pid, incomplete).expect("write an incomplete pidfile");
            assert!(
                !await_publication(&paths, Instant::now()),
                "an incomplete pidfile was accepted: {incomplete:?}"
            );
        }
        fs::write(&pid, b"1234\n").expect("write a complete pidfile");
        assert!(
            await_publication(&paths, Instant::now()),
            "the daemon's complete pidfile must publish it"
        );
    }

    #[test]
    fn failure_classes_have_stable_tokens_and_legacy_statuses() {
        let cases = [
            (FailureClass::Collision, "collision", 126),
            (FailureClass::Retryable, "retryable", 126),
            (FailureClass::UnsafeHost, "unsafe-host", 126),
            (FailureClass::Uncertain, "uncertain", 126),
            (FailureClass::MissingSession, "missing-session", 127),
            (FailureClass::StartupFailure, "startup-failure", 127),
            (FailureClass::PostConnect, "post-connect", 1),
        ];
        for (class, token, status) in cases {
            assert_eq!(class.token(), token);
            assert_eq!(class.exit_code(), status);
        }
    }

    #[test]
    fn only_safe_attach_retries_are_called_retryable() {
        for err in [
            io::Error::new(io::ErrorKind::TimedOut, "full backlog"),
            io::Error::from_raw_os_error(libc::EMFILE),
            io::Error::from_raw_os_error(libc::ENFILE),
            io::Error::from_raw_os_error(libc::ENOBUFS),
        ] {
            assert_eq!(resume_probe_class(&err), FailureClass::Retryable);
        }
        assert_eq!(
            resume_probe_class(&io::Error::from_raw_os_error(libc::ENOTRECOVERABLE)),
            FailureClass::Uncertain
        );
    }

    /// A session socket somebody else bound is reported as that, to the stderr this mode
    /// still has, rather than as a probe that established nothing.
    ///
    /// The refusal is `usock`'s own — the suite cannot become a second uid to provoke one
    /// — and the two halves that were wrong are both here: the class, which said the host
    /// was fine and the answer unknown, and the sentence, which said the socket could not
    /// be probed when it had been probed and had answered.
    #[test]
    fn a_socket_another_user_bound_names_that_user_rather_than_an_unprobeable_socket() {
        let paths = SessionPaths::in_dir(std::path::Path::new("/run/nomux"), "work").unwrap();
        let failure = unattachable(&paths, &Foreign::Uid(4242).refusal());
        let said = failure.to_string();

        assert_eq!(failure.class(), FailureClass::UnsafeHost);
        assert!(
            said.contains("uid 4242"),
            "the one fact established is whose socket this is: {said:?}"
        );
        assert!(
            !said.contains("could not be probed"),
            "it was probed, and it answered: {said:?}"
        );
    }

    /// Reads back what a daemon writing `bytes` to its stderr would be reported as.
    ///
    /// The write end is dropped before the read: `daemon_complaint` never waits, so a
    /// pipe still open at the other end would answer `EAGAIN` and race the test.
    fn complaint_of(bytes: &[u8]) -> Option<String> {
        let (read, write) = rustix::pipe::pipe().unwrap();
        File::from(write).write_all(bytes).unwrap();
        daemon_complaint(Some(ChildStderr::from(read)))
    }

    #[test]
    fn a_complaint_cannot_drive_the_terminal_it_is_printed_to() {
        assert_eq!(
            complaint_of(b"nomux: \x1b]0;pwned\x07boom\nsecond line").as_deref(),
            Some("\\u{1b}]0;pwned\\u{7}boom"),
            "this reaches `main`'s `eprintln!` verbatim, so it must carry no escape \
             sequence — nor the daemon's own `nomux: `, nor a second line"
        );
    }

    #[test]
    fn a_legible_complaint_is_left_legible() {
        assert_eq!(
            complaint_of("nomux: /hëm/fornwall: permission denied".as_bytes()).as_deref(),
            Some("/hëm/fornwall: permission denied"),
            "escaping is for what a terminal acts on, not for every byte above ASCII"
        );
    }
}
