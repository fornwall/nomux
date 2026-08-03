//! The attach relay.
//!
//! Deliberately dumb: it moves bytes between stdio and the session socket and
//! never parses a frame. The protocol lives only in the daemon, so this side never
//! needs a version bump. It exists for hosts where the client cannot open a
//! `direct-streamlocal` channel straight to the socket.

use std::collections::VecDeque;
use std::env;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::PollFlags;
use rustix::pipe::SpliceFlags;

use crate::rundir::SessionPaths;

/// How long to wait for a freshly spawned daemon to bind its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Delay between connect retries while waiting for the daemon.
const SPAWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Delay between checks for the pidfile the daemon publishes just after its socket.
///
/// Shorter than [`SPAWN_POLL_INTERVAL`] because the window it covers is two
/// syscalls wide and is usually already over, while the wait itself is on the path
/// of every session creation.
const PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Largest transfer asked of `splice` in one call.
///
/// A pipe holds 64 KiB by default, so a larger request only comes back short while
/// a smaller one buys nothing but extra syscalls.
const SPLICE_CHUNK: usize = 64 * 1024;

/// Connects to `session_id`, spawning its daemon if absent, then relays stdio.
///
/// `label` is passed on to a daemon this call creates, and ignored when the
/// session already exists — the label belongs to the session, not the connection.
///
/// # Errors
///
/// Fails if the session cannot be reached or created, or if relaying fails.
pub(crate) fn run(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    let stream = connect_or_spawn(&paths, label)?;
    relay(&stream)
}

/// Connects, spawning the daemon under an exclusive lock if nothing is listening.
///
/// The lock serialises concurrent attaches so two clients racing to create the
/// same session produce one daemon, not two fighting over the socket path. It is
/// held to the end of the function rather than released after the spawn, because
/// garbage collection takes the same lock (`IMPLEMENTATION.md` § 6.6): while it
/// is held, nothing can unlink the socket this is waiting for.
fn connect_or_spawn(paths: &SessionPaths, label: Option<&str>) -> io::Result<UnixStream> {
    // Before the first `connect`, not on the way to spawning a daemon. The socket
    // this is about to hand the user's keystrokes to is a *name* in the run
    // directory (§ 6.3), and where that directory is a symlink into somewhere
    // another user can write, the name is theirs to make: checking only when
    // nothing answers checks only the case where nothing was planted. It costs the
    // warm path one `open` and one `fstat`.
    paths.ensure_dir()?;
    match UnixStream::connect(paths.socket()) {
        Ok(stream) => return Ok(stream),
        Err(err) if is_absent(&err) => {}
        Err(err) => return Err(err),
    }

    // `lock_spawn` is where the subtlety lives: a collector may have unlinked
    // `<id>.lock` while this call was blocked on it, and a lock on a file that no
    // longer has that name is not this mutex — the next attach would create a new
    // file there and lock that. It checks and goes back for the real one.
    let _spawn_lock = paths.lock_spawn()?;

    // Another attach may have created the session while we waited for the lock.
    match UnixStream::connect(paths.socket()) {
        Ok(stream) => return Ok(stream),
        Err(err) if is_absent(&err) => {}
        Err(err) => return Err(err),
    }

    spawn_daemon(paths.id(), label)?;

    let deadline = Instant::now() + SPAWN_TIMEOUT;
    loop {
        match UnixStream::connect(paths.socket()) {
            Ok(stream) => {
                await_publication(paths, deadline);
                return Ok(stream);
            }
            Err(err) if is_absent(&err) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("daemon for session {} did not start", paths.id()),
                    ));
                }
                std::thread::sleep(SPAWN_POLL_INTERVAL);
            }
            Err(err) => return Err(err),
        }
    }
}

/// Keeps the spawn lock until the daemon this attach started has published
/// `<id>.pid`.
///
/// This is what makes the lock mean what the rest of the layout assumes it means.
/// The daemon binds its socket before it writes the pidfile (§ 6.2), so a `connect`
/// that succeeds says the id is claimed — not that anything on disk says so yet.
/// Returning here the instant it succeeded would drop the lock inside that window,
/// and "the lock is free" would not imply "the id is unclaimed": a `kill` taking it
/// there finds a live daemon and no pid, and the version of `kill` that answered
/// that by unlinking all five files left a daemon holding the user's shell with no
/// socket to reach it by, and the id free for a second daemon to bind.
///
/// Bounded by the caller's own deadline and never fatal. The pidfile belongs to
/// `kill`, not to the relay, so a daemon that never writes one still gets its
/// client — `kill` has its own answer for that (`control::resolve`), and it is not
/// this connection's business.
fn await_publication(paths: &SessionPaths, deadline: Instant) {
    while !paths.pid().exists() && Instant::now() < deadline {
        std::thread::sleep(PUBLISH_POLL_INTERVAL);
    }
}

/// Whether the error means "no daemon is listening there", as opposed to a real
/// failure. A refused connection is a stale socket; the daemon unlinks it on bind.
fn is_absent(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

/// Starts the daemon detached from this process's session.
///
/// Both halves of that are the daemon's own job as of `IMPLEMENTATION.md` § 6.2,
/// and both are still done here, because the daemon cannot do either of them soon
/// enough. Between this `exec` and its own `setsid` there is a window where a
/// hangup would take the session with it; and until it redirects its own stdio it
/// holds *this relay's* descriptors, so anything it writes — a session that already
/// exists, a backtrace — lands in the middle of the client's frame stream. Both
/// windows close before the daemon exists, and cost it nothing: it finds itself
/// already a session leader and does nothing more.
fn spawn_daemon(session_id: &str, label: Option<&str>) -> io::Result<()> {
    let exe = env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg(session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(label) = label {
        // As two arguments, never `--label=<text>`: the label is free-form text
        // from a tab title and this way nothing has to be escaped.
        command.arg("--label").arg(label);
    }

    // SAFETY: runs in the forked child before exec and must be async-signal-safe.
    // `setsid` is.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    command.spawn().map(drop)
}

/// Moves bytes between stdio and the socket until either side closes.
fn relay(stream: &UnixStream) -> io::Result<()> {
    // `splice` honours `SPLICE_F_NONBLOCK` only for the pipe end of the pair, so a
    // blocking socket would park the whole relay inside the kernel with the other
    // direction unserved — measurably, not theoretically. Everything below already
    // reads `EAGAIN` as "not now", so switching the socket over costs nothing and
    // is what makes the zero-copy path safe to take.
    stream.set_nonblocking(true)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let stdin_fd = stdin.as_fd();
    let stdout_fd = stdout.as_fd();
    let sock_fd = stream.as_fd();

    let mut to_socket = Pump::default();
    let mut to_stdout = Pump::default();
    let mut stdin_open = true;
    let mut socket_open = true;
    // The third of the three, and the only one about a *destination*. The relay
    // exists to put the session's output somewhere; once that somewhere has no
    // reader left, there is nothing for it to go on doing, so it ends the loop the
    // way the two above do rather than carrying on with nowhere to deliver.
    let mut stdout_open = true;

    while stdout_open && (socket_open || to_stdout.has_data()) {
        let mut fds = Vec::with_capacity(3);
        let want_stdin = stdin_open && to_socket.wants_source();
        if want_stdin {
            fds.push(rustix::event::PollFd::new(&stdin_fd, PollFlags::IN));
        }
        // Built up the way `daemon::watches` builds the same mask, rather than
        // through a helper enumerating four combinations of two booleans: one
        // spelling for one idea, and the conditions stay next to the flag each one
        // asks for.
        let mut socket_flags = PollFlags::empty();
        if socket_open && to_stdout.wants_source() {
            socket_flags |= PollFlags::IN;
        }
        if to_socket.wants_dest() {
            socket_flags |= PollFlags::OUT;
        }
        if !socket_flags.is_empty() {
            fds.push(rustix::event::PollFd::new(&sock_fd, socket_flags));
        }
        let want_stdout = to_stdout.wants_dest();
        if want_stdout {
            fds.push(rustix::event::PollFd::new(&stdout_fd, PollFlags::OUT));
        }
        if fds.is_empty() {
            break;
        }

        // No deadline of our own: the relay lives exactly as long as the channel,
        // and every wakeup it can act on is a readiness event.
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(err.into()),
        }
        // Read back by position, which `daemon::watches` deliberately does not do —
        // it tags each entry, because a poll set whose size depends on how many agent
        // channels are live is one an index slip silently misreads. Safe here for the
        // reason that does not hold there: the set is three fixed entries, and the
        // same three conditions that decided whether each was pushed are reused
        // below rather than recomputed, so a `Pump` that changed state during the
        // `poll` cannot shift the mapping under it.
        let mut events = fds.iter().map(rustix::event::PollFd::revents);
        let mut revents = |registered: bool| {
            if registered {
                events.next().unwrap_or_else(PollFlags::empty)
            } else {
                PollFlags::empty()
            }
        };
        let stdin_events = revents(want_stdin);
        let socket_events = revents(!socket_flags.is_empty());
        let stdout_events = revents(want_stdout);

        // `ERR` alongside `HUP`, as the socket direction below and
        // `daemon::poll_once` both have it: a source reporting only `ERR` would
        // otherwise never be read and never be closed, and stdin stays in the poll
        // set, so the relay would spin on it exactly as stdout used to.
        if stdin_events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            && !to_socket.transfer(stdin_fd, sock_fd)?
        {
            stdin_open = false;
            // Propagate the half-close so the daemon sees our EOF while we keep
            // draining its output.
            drop(stream.shutdown(Shutdown::Write));
        }
        if socket_events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            && !to_stdout.transfer(sock_fd, stdout_fd)?
        {
            socket_open = false;
        }
        // Deliberately not read back into an ending. An `EPIPE` towards the socket
        // is a client that has gone, and the relay already ends on that: the same
        // departure arrives as EOF from the socket's *read* side above, where
        // `socket_open` is cleared. Anything still queued for it is dropped there
        // and then, which is all that is owed to a peer that has stopped listening.
        if socket_events.contains(PollFlags::OUT) || to_socket.has_data() {
            let _client_still_reading = to_socket.drain_to(sock_fd)?;
        }
        // Before the drain, and one of the two ways the same fact arrives.
        // `POLLOUT` is the only thing that clears `Pump::dest_full`, and a
        // destination whose reader has gone never reports it — a full pipe with no
        // reader is not writable, it is broken. So the relay would poll a
        // descriptor that answers `ERR` forever, match neither this condition nor
        // the one below (the buffer is empty: `splice` moved those bytes inside the
        // kernel), change nothing, and come straight back round — a busy loop at
        // the speed of the scheduler, for as long as the socket stayed open.
        if stdout_events.intersects(PollFlags::ERR | PollFlags::HUP) {
            stdout_open = false;
        } else if stdout_events.contains(PollFlags::OUT) || to_stdout.has_data() {
            // The other way, and the only one available while this direction is
            // idle: an empty buffer wants nothing from `poll`, so stdout is not in
            // the set and `ERR` above is never delivered. A reader that dies then
            // is discovered by writing to it and by nothing else — which is why an
            // `EPIPE` here has to be the ending rather than a cleared buffer.
            // Swallowing it left the relay reading the socket into a buffer it
            // emptied over a dead pipe, for as long as the session went on
            // producing output, while holding the session's one client slot.
            stdout_open = to_stdout.drain_to(stdout_fd)?;
        }
    }

    // The loop can exit still owing the last batch — the socket reaches EOF with
    // the buffer non-empty — but only a destination that is still there is owed
    // anything.
    if stdout_open && to_stdout.drain_to(stdout_fd)? {
        stdout.lock().flush()?;
    }
    Ok(())
}

/// Reads once into `buf`. `false` means the source reached EOF.
fn copy_in(fd: BorrowedFd<'_>, buf: &mut VecDeque<u8>) -> io::Result<bool> {
    let mut chunk = [0u8; 16 * 1024];
    match crate::nbio::read(fd, &mut chunk) {
        // A PTY-backed peer reports end of session as EIO rather than 0.
        Ok(0) | Err(rustix::io::Errno::IO) => Ok(false),
        Ok(n) => {
            buf.extend(chunk.get(..n).unwrap_or(&[]));
            Ok(true)
        }
        // Nothing pending is not EOF; the peer is still there, it just had
        // nothing to say.
        Err(rustix::io::Errno::AGAIN) => Ok(true),
        Err(err) => Err(err.into()),
    }
}

/// What one `splice` attempt achieved.
#[derive(Debug)]
enum Spliced {
    /// Bytes handed over inside the kernel; 0 means the source is at EOF.
    Moved(usize),
    /// The destination would not take them yet. Neither an error nor EOF.
    Full,
    /// The kernel will not splice this pair — now or ever.
    Unusable,
}

/// Moves up to [`SPLICE_CHUNK`] bytes from `src` to `dst` without them ever
/// entering this process.
///
/// `splice` demands that one end be a pipe, and whether that holds is a property
/// of the host rather than of this code: under sshd our stdio is a pipe on some
/// builds and a socketpair on others, while the peer is always a unix socket. So
/// it is discovered by trying, and every failure that is not "try again" collapses
/// into [`Spliced::Unusable`]. Deliberately blunt: the copying path below handles
/// every case correctly anyway, so there is nothing to be won by telling `EINVAL`
/// from `ENOSYS` from a socket that just died.
fn splice_once(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> Spliced {
    let flags = SpliceFlags::MOVE | SpliceFlags::NONBLOCK;
    loop {
        return match rustix::pipe::splice(src, None, dst, None, SPLICE_CHUNK, flags) {
            Ok(moved) => Spliced::Moved(moved),
            Err(rustix::io::Errno::INTR) => continue,
            // Only ever reached with the source already reported readable, so this
            // is the destination refusing and never a source that had nothing.
            Err(rustix::io::Errno::AGAIN) => Spliced::Full,
            Err(_) => Spliced::Unusable,
        };
    }
}

/// One direction of the relay.
///
/// Two paths through the single component that must never break, which is worth
/// being uneasy about — so they are kept from ever interleaving: `splice` is
/// attempted only when the buffer is empty, and a `splice` never leaves anything
/// behind in it. Bytes therefore leave in the order they arrived under either
/// path, and the choice between them cannot reorder anything.
#[derive(Debug, Default)]
struct Pump {
    /// Bytes the destination would not take yet. Only ever filled by the copying
    /// path.
    buf: VecDeque<u8>,
    /// Set for good the first time `splice` refuses this pair. Never reconsidered:
    /// the reason it refuses — neither end is a pipe — cannot change while the
    /// relay runs, and retrying would buy a wasted syscall per wakeup forever.
    ///
    /// Named for the refusal rather than for the capability so that the default is
    /// the optimistic one, which is the behaviour wanted: one refused syscall is
    /// the entire cost of finding out whether this host can splice, and it is paid
    /// once per direction.
    splice_refused: bool,
    /// `splice` reported the destination full. Distinct from a non-empty buffer in
    /// that nothing is held here; it only records that the source must be left
    /// alone until the destination reports `POLLOUT`, since re-reading it would
    /// spin on `EAGAIN`.
    dest_full: bool,
}

impl Pump {
    /// Whether the source is worth polling: only with the destination caught up,
    /// so nothing can overtake bytes that are already owed to it.
    ///
    /// Written as the negation rather than as `!has_data && !dest_full`, which is
    /// the same predicate by De Morgan and says nothing about being the same. The
    /// two are exclusive and exhaustive, which is exactly what the type's own doc
    /// claims — `splice` is attempted only when the buffer is empty, so the choice
    /// between the two directions cannot reorder anything — and stating it this way
    /// makes it a fact about the code rather than a coincidence each reader has to
    /// re-derive.
    fn wants_source(&self) -> bool {
        !self.wants_dest()
    }

    /// Whether the destination is worth polling for writability.
    fn wants_dest(&self) -> bool {
        self.has_data() || self.dest_full
    }

    /// Whether anything is still held in userspace for the destination.
    fn has_data(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Moves one batch from `src` towards `dst`. `false` means `src` reached EOF.
    ///
    /// Falling back within the same call keeps a host that cannot splice from
    /// losing a wakeup to the discovery.
    fn transfer(&mut self, src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> io::Result<bool> {
        if !self.splice_refused && !self.has_data() {
            match splice_once(src, dst) {
                Spliced::Moved(moved) => return Ok(moved != 0),
                Spliced::Full => {
                    self.dest_full = true;
                    return Ok(true);
                }
                Spliced::Unusable => self.splice_refused = true,
            }
        }
        copy_in(src, &mut self.buf)
    }

    /// Hands the destination whatever is owed it, and forgets that it was full.
    /// `false` means the destination has stopped reading.
    ///
    /// Called on `POLLOUT`, and also speculatively whenever something is buffered —
    /// an optimistic write that either saves a wakeup or costs one `EAGAIN`.
    /// Clearing [`Pump::dest_full`] is sound either way: it only ever gates
    /// re-reading the source, and the write below is what establishes whether the
    /// destination has room.
    fn drain_to(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        self.dest_full = false;
        match crate::nbio::drain_to(&mut self.buf, fd) {
            // `EPIPE` is `nbio`'s to report and each caller's to interpret: to an
            // agent channel it is a dead socket, and here it is the destination's
            // reader having gone, which is an ordinary ending rather than a
            // failure — so what was owed it is dropped and the answer comes back as
            // `false` rather than as an error nobody could act on.
            //
            // Which direction that ends is `relay`'s to say and not this method's,
            // because the two do not agree: towards the socket it is a client that
            // has left, which the socket's own read side reports again as EOF, and
            // towards stdout it is the relay's entire purpose gone. Both arrive
            // here identically, and only one of them stops the loop.
            Err(rustix::io::Errno::PIPE) => {
                self.buf.clear();
                Ok(false)
            }
            outcome => outcome.map(|()| true).map_err(Into::into),
        }
    }
}
