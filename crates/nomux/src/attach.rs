//! The attach relay.
//!
//! Deliberately dumb: it moves bytes between stdio and the session socket and
//! never parses a frame. The protocol lives only in the daemon, so this side never
//! needs a version bump. It exists for hosts where the client cannot open a
//! `direct-streamlocal` channel straight to the socket.

use std::env;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::PollFlags;
use rustix::fs::{FlockOperation, Mode, OFlags};
use rustix::pipe::SpliceFlags;

use crate::rundir::SessionPaths;

/// How long to wait for a freshly spawned daemon to bind its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Delay between connect retries while waiting for the daemon.
const SPAWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

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
/// same session produce one daemon, not two fighting over the socket path.
fn connect_or_spawn(paths: &SessionPaths, label: Option<&str>) -> io::Result<UnixStream> {
    match UnixStream::connect(paths.socket()) {
        Ok(stream) => return Ok(stream),
        Err(err) if is_absent(&err) => {}
        Err(err) => return Err(err),
    }

    paths.ensure_dir()?;
    let lock = rustix::fs::open(
        paths.lock(),
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    rustix::fs::flock(&lock, FlockOperation::LockExclusive)?;

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
            Ok(stream) => return Ok(stream),
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

    while socket_open || to_stdout.has_data() {
        let mut fds = Vec::with_capacity(3);
        let want_stdin = stdin_open && to_socket.wants_source();
        if want_stdin {
            fds.push(rustix::event::PollFd::new(&stdin_fd, PollFlags::IN));
        }
        let socket_flags = read_write_flags(
            socket_open && to_stdout.wants_source(),
            to_socket.wants_dest(),
        );
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
        let mut events = fds.iter().map(rustix::event::PollFd::revents);
        let stdin_events = if want_stdin {
            events.next().unwrap_or_else(PollFlags::empty)
        } else {
            PollFlags::empty()
        };
        let socket_events = if socket_flags.is_empty() {
            PollFlags::empty()
        } else {
            events.next().unwrap_or_else(PollFlags::empty)
        };
        let stdout_events = if want_stdout {
            events.next().unwrap_or_else(PollFlags::empty)
        } else {
            PollFlags::empty()
        };
        drop(events);
        drop(fds);

        if stdin_events.intersects(PollFlags::IN | PollFlags::HUP)
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
        if socket_events.contains(PollFlags::OUT) || to_socket.has_data() {
            to_socket.drain_to(sock_fd)?;
        }
        if stdout_events.contains(PollFlags::OUT) || to_stdout.has_data() {
            to_stdout.drain_to(stdout_fd)?;
        }
    }

    to_stdout.drain_to(stdout_fd)?;
    stdout.lock().flush()
}

const fn read_write_flags(want_read: bool, want_write: bool) -> PollFlags {
    match (want_read, want_write) {
        (true, true) => PollFlags::IN.union(PollFlags::OUT),
        (true, false) => PollFlags::IN,
        (false, true) => PollFlags::OUT,
        (false, false) => PollFlags::empty(),
    }
}

/// Reads once into `buf`. `false` means the source reached EOF.
fn copy_in(fd: BorrowedFd<'_>, buf: &mut Buffer) -> io::Result<bool> {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        return match rustix::io::read(fd, &mut chunk) {
            // A PTY-backed peer reports end of session as EIO rather than 0.
            Ok(0) | Err(rustix::io::Errno::IO) => Ok(false),
            Ok(n) => {
                buf.push(chunk.get(..n).unwrap_or(&[]));
                Ok(true)
            }
            Err(rustix::io::Errno::INTR) => continue,
            // Nothing pending is not EOF; the peer is still there, it just had
            // nothing to say.
            Err(rustix::io::Errno::AGAIN) => Ok(true),
            Err(err) => Err(err.into()),
        };
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
/// attempted only when [`Buffer`] is empty, and a `splice` never leaves anything
/// behind in it. Bytes therefore leave in the order they arrived under either
/// path, and the choice between them cannot reorder anything.
#[derive(Debug)]
struct Pump {
    /// Bytes the destination would not take yet. Only ever filled by the copying
    /// path.
    buf: Buffer,
    /// Cleared for good the first time `splice` refuses this pair. Never retried:
    /// the reason it refuses — neither end is a pipe — cannot change while the
    /// relay runs, and retrying would buy a wasted syscall per wakeup forever.
    splice_usable: bool,
    /// `splice` reported the destination full. Distinct from a non-empty buffer in
    /// that nothing is held here; it only records that the source must be left
    /// alone until the destination reports `POLLOUT`, since re-reading it would
    /// spin on `EAGAIN`.
    dest_full: bool,
}

impl Default for Pump {
    /// Starts optimistic. One refused syscall is the entire cost of finding out
    /// whether this host can splice, and it is paid once per direction.
    fn default() -> Self {
        Self {
            buf: Buffer::default(),
            splice_usable: true,
            dest_full: false,
        }
    }
}

impl Pump {
    /// Whether the source is worth polling: only with the destination caught up,
    /// so nothing can overtake bytes that are already owed to it.
    const fn wants_source(&self) -> bool {
        !self.buf.has_data() && !self.dest_full
    }

    /// Whether the destination is worth polling for writability.
    const fn wants_dest(&self) -> bool {
        self.buf.has_data() || self.dest_full
    }

    /// Whether anything is still held in userspace for the destination.
    const fn has_data(&self) -> bool {
        self.buf.has_data()
    }

    /// Moves one batch from `src` towards `dst`. `false` means `src` reached EOF.
    ///
    /// Falling back within the same call keeps a host that cannot splice from
    /// losing a wakeup to the discovery.
    fn transfer(&mut self, src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> io::Result<bool> {
        if self.splice_usable && !self.buf.has_data() {
            match splice_once(src, dst) {
                Spliced::Moved(moved) => return Ok(moved != 0),
                Spliced::Full => {
                    self.dest_full = true;
                    return Ok(true);
                }
                Spliced::Unusable => self.splice_usable = false,
            }
        }
        copy_in(src, &mut self.buf)
    }

    /// Hands the destination whatever is owed it, and forgets that it was full.
    ///
    /// Called on `POLLOUT`, and also speculatively whenever something is buffered —
    /// an optimistic write that either saves a wakeup or costs one `EAGAIN`.
    /// Clearing [`Pump::dest_full`] is sound either way: it only ever gates
    /// re-reading the source, and the write below is what establishes whether the
    /// destination has room.
    fn drain_to(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.dest_full = false;
        self.buf.drain_to(fd)
    }
}

/// A byte queue awaiting a writable destination.
#[derive(Debug, Default)]
struct Buffer {
    data: Vec<u8>,
    pos: usize,
}

impl Buffer {
    const fn has_data(&self) -> bool {
        self.pos < self.data.len()
    }

    fn push(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    fn drain_to(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        while self.has_data() {
            let pending = self.data.get(self.pos..).unwrap_or(&[]);
            match rustix::io::write(fd, pending) {
                Ok(0) | Err(rustix::io::Errno::AGAIN) => break,
                Ok(n) => self.pos += n,
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::PIPE) => {
                    self.data.clear();
                    self.pos = 0;
                    return Ok(());
                }
                Err(err) => return Err(err.into()),
            }
        }
        if !self.has_data() {
            self.data.clear();
            self.pos = 0;
        }
        Ok(())
    }
}
