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

use rustix::event::{PollFlags, Timespec};
use rustix::fs::{FlockOperation, Mode, OFlags};

use crate::rundir::SessionPaths;

/// How long to wait for a freshly spawned daemon to bind its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Delay between connect retries while waiting for the daemon.
const SPAWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Connects to `session_id`, spawning its daemon if absent, then relays stdio.
///
/// # Errors
///
/// Fails if the session cannot be reached or created, or if relaying fails.
pub(crate) fn run(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    let stream = connect_or_spawn(&paths)?;
    relay(&stream)
}

/// Connects, spawning the daemon under an exclusive lock if nothing is listening.
///
/// The lock serialises concurrent attaches so two clients racing to create the
/// same session produce one daemon, not two fighting over the socket path.
fn connect_or_spawn(paths: &SessionPaths) -> io::Result<UnixStream> {
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

    spawn_daemon(paths.id())?;

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
/// `setsid` is what lets it outlive the SSH connection that spawned it; stdio goes
/// to `/dev/null` so it does not hold the SSH channel open.
fn spawn_daemon(session_id: &str) -> io::Result<()> {
    let exe = env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg(session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

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
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stdin_fd = stdin.as_fd();
    let stdout_fd = stdout.as_fd();
    let sock_fd = stream.as_fd();

    let mut to_socket = Buffer::default();
    let mut to_stdout = Buffer::default();
    let mut stdin_open = true;
    let mut socket_open = true;

    while socket_open || to_stdout.has_data() {
        let mut fds = Vec::with_capacity(3);
        let want_stdin = stdin_open && !to_socket.has_data();
        if want_stdin {
            fds.push(rustix::event::PollFd::new(&stdin_fd, PollFlags::IN));
        }
        let socket_flags =
            read_write_flags(socket_open && !to_stdout.has_data(), to_socket.has_data());
        if !socket_flags.is_empty() {
            fds.push(rustix::event::PollFd::new(&sock_fd, socket_flags));
        }
        if to_stdout.has_data() {
            fds.push(rustix::event::PollFd::new(&stdout_fd, PollFlags::OUT));
        }
        if fds.is_empty() {
            break;
        }

        // No deadline of our own: the relay lives exactly as long as the channel.
        let forever = Timespec {
            tv_sec: 3600,
            tv_nsec: 0,
        };
        match rustix::event::poll(&mut fds, Some(&forever)) {
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
        let stdout_events = if to_stdout.has_data() {
            events.next().unwrap_or_else(PollFlags::empty)
        } else {
            PollFlags::empty()
        };
        drop(events);
        drop(fds);

        if stdin_events.intersects(PollFlags::IN | PollFlags::HUP)
            && copy_in(stdin_fd, &mut to_socket)? == 0
        {
            stdin_open = false;
            // Propagate the half-close so the daemon sees our EOF while we keep
            // draining its output.
            drop(stream.shutdown(Shutdown::Write));
        }
        if socket_events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            && copy_in(sock_fd, &mut to_stdout)? == 0
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

/// Reads once into `buf`, returning the byte count; 0 means EOF.
fn copy_in(fd: BorrowedFd<'_>, buf: &mut Buffer) -> io::Result<usize> {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        return match rustix::io::read(fd, &mut chunk) {
            // A PTY-backed peer reports end of session as EIO rather than 0.
            Ok(0) | Err(rustix::io::Errno::IO) => Ok(0),
            Ok(n) => {
                buf.push(chunk.get(..n).unwrap_or(&[]));
                Ok(n)
            }
            Err(rustix::io::Errno::INTR) => continue,
            // Nothing pending is not EOF; report a non-zero count so the caller
            // does not mistake it for a closed peer.
            Err(rustix::io::Errno::AGAIN) => Ok(usize::MAX),
            Err(err) => Err(err.into()),
        };
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
