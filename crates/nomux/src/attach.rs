//! The attach relay.
//!
//! Deliberately dumb: it moves bytes between stdio and the session socket and
//! never parses a frame. The protocol lives only in the daemon, so this side never
//! needs a version bump. It exists for hosts where the client cannot open a
//! `direct-streamlocal` channel straight to the socket.

use std::collections::VecDeque;
use std::env;
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{ChildStderr, Command, Stdio};
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

    let complaint = spawn_daemon(paths.id(), label)?;

    let deadline = Instant::now() + SPAWN_TIMEOUT;
    loop {
        match UnixStream::connect(paths.socket()) {
            Ok(stream) => {
                await_publication(paths, deadline);
                return Ok(stream);
            }
            Err(err) if is_absent(&err) => {
                if Instant::now() >= deadline {
                    let id = paths.id();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        daemon_complaint(complaint).map_or_else(
                            || format!("daemon for session {id} did not start"),
                            |said| format!("daemon for session {id} did not start: {said}"),
                        ),
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
/// there finds a live daemon and no pid, which § 6.6 forbids it to unlink over.
///
/// Bounded by the caller's own deadline and never fatal. The pidfile belongs to
/// `kill`, not to the relay, so a daemon that never writes one still gets its
/// client — `kill` has its own answer for that (`control::resolve`), and it is not
/// this connection's business.
fn await_publication(paths: &SessionPaths, deadline: Instant) {
    // Built once. `SessionPaths::pid` allocates, and this loop runs every
    // millisecond for as long as the caller's deadline allows.
    let pid = paths.pid();
    while !pid.exists() && Instant::now() < deadline {
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
/// Both halves — `setsid` and `/dev/null` stdio — are the daemon's own job as of
/// `IMPLEMENTATION.md` § 6.2, and both are still done here because it cannot reach
/// either soon enough; that section has the two windows this closes. They cost it
/// nothing: it finds itself already a session leader and does nothing more.
fn spawn_daemon(session_id: &str, label: Option<&str>) -> io::Result<Option<ChildStderr>> {
    let exe = env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg(session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // A pipe rather than `/dev/null`, which is the only reason a failure to start
        // has a reason attached to it. The daemon writes its diagnostics to stderr up
        // until `release_startup_state` points the descriptor at `/dev/null` — so
        // everything that can go wrong before a session exists arrives here, and the
        // pipe reaching end of file is itself the daemon reporting it got past that
        // point. Afterwards it has syslog and this end has nothing left to read.
        .stderr(Stdio::piped());
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
    command.spawn().map(|mut child| child.stderr.take())
}

/// Whatever the daemon managed to say before it stopped saying anything.
///
/// Read without waiting. This is only ever called once the daemon has already missed
/// its deadline, and one that is wedged with its stderr still open must not take the
/// relay down with it — a blocking read here would turn a five-second timeout into a
/// hang. Anything it did write is sitting in the pipe by now.
fn daemon_complaint(stderr: Option<ChildStderr>) -> Option<String> {
    let stderr = stderr?;
    let fd = stderr.as_fd();
    // Added to what is there rather than assigned over it. This descriptor is a
    // freshly created pipe read end with nothing else set, so the two are the same
    // today — but `fcntl_setfl` replaces the whole status word, and every other
    // site in the tree does the `getfl`-then-or for a reason.
    let flags = rustix::fs::fcntl_getfl(fd).ok()?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).ok()?;
    let mut buf = [0u8; 512];
    // Through `nbio`, like every other read in the tree: a signal landing on this
    // one would discard the only account of the failure anybody is going to get,
    // and report a daemon that explained itself as one that said nothing. `EAGAIN`
    // still falls through to `None`, which is what "it wrote nothing" means here.
    let read = crate::nbio::read(fd, &mut buf).ok()?;
    let text = String::from_utf8_lossy(buf.get(..read)?).into_owned();
    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    // The daemon reached this through `main`'s reporter, which prefixes the binary's
    // own name. Keeping it would render as `nomux: ... : nomux: ...`.
    Some(line.strip_prefix("nomux: ").unwrap_or(line).to_owned())
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
    // The third of the three, and the only one about a *destination*: the relay
    // exists to put the session's output somewhere, so once that somewhere has no
    // reader left it ends the loop the way the two above do.
    let mut stdout_open = true;

    while stdout_open && (socket_open || to_stdout.has_data()) {
        let mut fds = Vec::with_capacity(3);
        let want_stdin = stdin_open && to_socket.wants_source();
        if want_stdin {
            fds.push(rustix::event::PollFd::new(&stdin_fd, PollFlags::IN));
        }
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
        // Read back by position, which `daemon::watches` deliberately does not do:
        // its set is variable-length. Safe here because the three conditions that
        // decided whether each entry was pushed are reused below rather than
        // recomputed, so a `Pump` that changed state during `poll` cannot shift it.
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
        // otherwise never be read, never be closed, and spin in the poll set.
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
        // departure arrives as EOF from the socket's *read* side above.
        //
        // Speculative on a non-empty buffer as well as on `POLLOUT`, which stdout
        // below deliberately is not: this descriptor was switched to non-blocking at
        // the top, so an optimistic write here either saves a wakeup or costs one
        // `EAGAIN`.
        if socket_events.contains(PollFlags::OUT) || to_socket.has_data() {
            let _client_still_reading = to_socket.drain_to(sock_fd)?;
        }
        // One of the two ways a dead stdout arrives. `POLLOUT` is the only thing
        // that clears `Pump::dest_full`, and a destination whose reader has gone
        // never reports it — a full pipe with no reader is not writable, it is
        // broken — so without this the relay would poll a descriptor that answers
        // `ERR` forever and never act on it.
        if stdout_events.intersects(PollFlags::ERR | PollFlags::HUP) {
            stdout_open = false;
        } else if stdout_events.contains(PollFlags::OUT) {
            // On `POLLOUT` alone, and never speculatively on a non-empty buffer the
            // way the socket above is drained. Stdout is left in the blocking mode it
            // was inherited in, and cannot safely be taken out of it: it may be a
            // terminal whose open file description the user's shell shares, where
            // `O_NONBLOCK` is not this process's to set. A write it is not ready for
            // therefore parks the whole relay inside the kernel with the other
            // direction unserved — exactly what the socket was switched over to
            // avoid. Nothing is lost by waiting, because a non-empty buffer is what
            // puts stdout in the poll set asking for `POLLOUT` in the first place, so
            // the wait is one wakeup and never a byte.
            //
            // `EPIPE` from that write is still an ending rather than a cleared
            // buffer, and is the other of the two ways. A unix socket whose peer has
            // stopped reading reports itself writable and then refuses the write, so
            // for that shape of destination this is the only place the death can be
            // discovered: `ERR` above is what a pipe gives, and this is what a socket
            // gives.
            stdout_open = to_stdout.drain_to(stdout_fd)?;
        }
    }

    // Nothing is owed here. Every exit from the loop leaves `to_stdout` empty
    // whenever stdout is still open: the `while` condition keeps going round while
    // it has data, and the `fds.is_empty()` break needs `wants_dest()` to be false,
    // which is that same emptiness. The last batch is handed over inside the loop,
    // on the `POLLOUT` that a non-empty buffer is what asks for.
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
/// Whether `splice` works for a pair is a property of the host rather than of this
/// code (`IMPLEMENTATION.md` § 7), so it is discovered by trying: every failure that
/// is not "try again" collapses into [`Spliced::Unusable`]. Deliberately blunt,
/// because the copying path below handles all of them correctly anyway.
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
/// The two paths through it are kept from ever interleaving (`IMPLEMENTATION.md`
/// § 7): `splice` is attempted only when the buffer is empty, and a `splice` never
/// leaves anything behind in it, so the choice between them cannot reorder bytes.
#[derive(Debug, Default)]
struct Pump {
    /// Bytes the destination would not take yet. Only ever filled by the copying
    /// path.
    buf: VecDeque<u8>,
    /// Set for good the first time `splice` refuses this pair. Never reconsidered:
    /// the reason it refuses — neither end is a pipe — cannot change while the
    /// relay runs, and retrying would buy a wasted syscall per wakeup forever.
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
    /// Called on `POLLOUT`, and towards the socket also speculatively whenever
    /// something is buffered — which is safe only there, because only that
    /// descriptor is non-blocking. Clearing [`Pump::dest_full`] is sound either way:
    /// it only ever gates re-reading the source, and the write below is what
    /// establishes whether the destination has room.
    fn drain_to(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        self.dest_full = false;
        match crate::nbio::drain_to(&mut self.buf, fd) {
            // `EPIPE` is `nbio`'s to report and each caller's to interpret: to an
            // agent channel it is a dead socket, and here it is the destination's
            // reader having gone — an ordinary ending rather than a failure, so what
            // was owed it is dropped and the answer comes back as `false`. Which
            // direction that ends is `relay`'s to say and not this method's: towards
            // the socket it is a client that has left, which the socket's own read
            // side reports again as EOF, and towards stdout it is the relay's entire
            // purpose gone. Both arrive here identically, and only one stops the loop.
            Err(rustix::io::Errno::PIPE) => {
                self.buf.clear();
                Ok(false)
            }
            outcome => outcome.map(|()| true).map_err(Into::into),
        }
    }
}
