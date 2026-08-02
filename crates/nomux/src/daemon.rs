//! The session daemon: owns the PTY, the ring buffer and the listening socket.
//!
//! Single-threaded around `poll`. There is at most one client (`DESIGN.md` § 6.4),
//! so the poll set is small and fixed: the listener, the PTY master, and the client
//! if one is attached.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use nomux_proto::{
    ErrorCode, ExitKind, Frame, FrameType, Hello, HelloOk, PROTOCOL_VERSION, RESUME_FROM_START,
    WinSize,
};
use rustix::event::{PollFlags, Timespec};

use crate::conn::Conn;
use crate::pty::{self, Pty};
use crate::rundir::{SOCKET_MODE, SessionPaths};

/// Default ring capacity. See `DESIGN.md` § 10 — this bounds how long a
/// disconnect can last before scrollback is lost, and is multiplied by the
/// per-host session cap.
pub(crate) const DEFAULT_RING_CAPACITY: usize = 4 << 20;

/// Environment override for the ring capacity, in bytes.
///
/// Exists because the right value is host-dependent — a machine running eight
/// sessions pays this eight times over — and because it makes overflow behaviour
/// testable without generating megabytes of output.
pub(crate) const RING_BYTES_ENV: &str = "NOMUX_RING_BYTES";

/// Resolves the ring capacity, honouring [`RING_BYTES_ENV`].
///
/// An unparseable or zero value falls back to the default rather than failing:
/// a mistyped tuning variable should not stop a session from starting.
pub(crate) fn ring_capacity() -> usize {
    std::env::var(RING_BYTES_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_RING_CAPACITY)
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

/// Longest the poll loop sleeps with nothing else pending.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_hours is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TICK: Duration = Duration::from_secs(60 * 60);

/// How long to wait for the very first client before giving up. Without this a
/// daemon spawned by a connection that died mid-handshake would live forever.
const FIRST_ATTACH_TIMEOUT: Duration = Duration::from_secs(30);

/// Session state for the lifetime of the daemon process.
struct Daemon {
    paths: SessionPaths,
    listener: UnixListener,
    ring: crate::ring::Ring,
    pty: Option<Pty>,
    client: Option<Conn>,
    /// Set once the attached client's `Hello` has been answered.
    greeted: bool,
    /// Authoritative input offset: everything below this has been accepted for the
    /// PTY and must never be applied twice.
    in_applied: u64,
    /// Input accepted but not yet written, because the PTY was not writable.
    pending_input: VecDeque<u8>,
    /// Output offset already queued to the current client.
    sent_through: u64,
    win: WinSize,
    /// `None` until the child exits.
    exited: Option<(i32, ExitKind)>,
    /// When the session became clientless, for idle reaping.
    detached_since: Option<Instant>,
    /// Deadline after the child exits.
    linger_until: Option<Instant>,
}

/// Runs the daemon for `session_id` until the child exits or the session is reaped.
///
/// # Errors
///
/// Fails if the run directory or socket cannot be created, or if another daemon
/// already owns this session.
pub(crate) fn run(session_id: &str, capacity: usize) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    paths.ensure_dir()?;

    let listener = bind_socket(&paths)?;
    write_pidfile(&paths)?;

    let mut daemon = Daemon {
        paths,
        listener,
        ring: crate::ring::Ring::new(capacity),
        pty: None,
        client: None,
        greeted: false,
        in_applied: 0,
        pending_input: VecDeque::new(),
        sent_through: 0,
        win: WinSize::default(),
        exited: None,
        detached_since: Some(Instant::now()),
        linger_until: None,
    };

    let result = daemon.event_loop();
    daemon.shutdown();
    result
}

/// Binds the session socket, replacing a stale one.
///
/// A socket whose `connect` is refused belongs to a dead daemon; anything else —
/// including `EACCES` — is left alone, since removing it could destroy a live
/// session belonging to someone else's run.
fn bind_socket(paths: &SessionPaths) -> io::Result<UnixListener> {
    let path = paths.socket();
    match UnixStream::connect(&path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("session {} is already running", paths.id()),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            fs::remove_file(&path)?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn write_pidfile(paths: &SessionPaths) -> io::Result<()> {
    let mut file = fs::File::create(paths.pid())?;
    writeln!(file, "{}", std::process::id())
}

impl Daemon {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut scratch = Vec::new();
        let mut read_buf = vec![0u8; 64 * 1024];

        loop {
            if self.should_stop() {
                return Ok(());
            }
            self.poll_once(&mut read_buf, &mut scratch)?;
        }
    }

    fn should_stop(&self) -> bool {
        if let Some(deadline) = self.linger_until
            && Instant::now() >= deadline
        {
            return true;
        }
        if let Some(since) = self.detached_since {
            let limit = if self.pty.is_none() {
                FIRST_ATTACH_TIMEOUT
            } else {
                IDLE_TIMEOUT
            };
            if since.elapsed() >= limit {
                return true;
            }
        }
        false
    }

    fn poll_once(&mut self, read_buf: &mut [u8], scratch: &mut Vec<u8>) -> io::Result<()> {
        // Index 0 is always the listener; the PTY and client follow if present.
        let listener_fd = self.listener.as_fd();
        let pty_fd = self.pty.as_ref().map(Pty::master);
        let client_fd = self.client.as_ref().map(|c| c.stream().as_fd());

        let mut fds = Vec::with_capacity(3);
        fds.push(rustix::event::PollFd::new(&listener_fd, PollFlags::IN));
        if let Some(fd) = pty_fd.as_ref() {
            let mut flags = PollFlags::IN;
            if !self.pending_input.is_empty() {
                flags |= PollFlags::OUT;
            }
            fds.push(rustix::event::PollFd::new(fd, flags));
        }
        if let (Some(fd), Some(conn)) = (client_fd.as_ref(), self.client.as_ref()) {
            let mut flags = PollFlags::IN;
            if conn.wants_write() {
                flags |= PollFlags::OUT;
            }
            fds.push(rustix::event::PollFd::new(fd, flags));
        }

        let timeout = self.poll_timeout();
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => return Ok(()),
            Err(err) => return Err(err.into()),
        }

        let listener_events = fds
            .first()
            .map_or(PollFlags::empty(), rustix::event::PollFd::revents);
        let mut index = 1;
        let pty_events = if pty_fd.is_some() {
            let events = fds
                .get(index)
                .map_or(PollFlags::empty(), rustix::event::PollFd::revents);
            index += 1;
            events
        } else {
            PollFlags::empty()
        };
        let client_events = if client_fd.is_some() {
            fds.get(index)
                .map_or(PollFlags::empty(), rustix::event::PollFd::revents)
        } else {
            PollFlags::empty()
        };
        drop(fds);

        if pty_events.intersects(PollFlags::OUT) {
            self.write_pty()?;
        }
        if pty_events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            self.read_pty(read_buf)?;
        }
        // Before the listener, always: one poll can report both a readable client
        // and a pending connection, and accepting first would drop the outgoing
        // `Conn` with its input still unread in the socket buffer.
        if client_events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            self.read_client(scratch)?;
        }
        if listener_events.contains(PollFlags::IN) {
            self.accept(scratch)?;
        }
        self.pump_output();
        if client_events.contains(PollFlags::OUT)
            || self.client.as_ref().is_some_and(Conn::wants_write)
        {
            self.write_client();
        }
        Ok(())
    }

    fn poll_timeout(&self) -> Timespec {
        // Wake hourly even with nothing pending, so idle reaping is not deferred
        // indefinitely by a session that is simply quiet.
        let remaining = self.linger_until.map_or(IDLE_TICK, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        }
    }

    fn accept(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // Final drain of the outgoing connection: it may have written
                    // between the poll and this accept, and input it already
                    // delivered must not be lost to the takeover.
                    if self.client.is_some() {
                        drop(self.read_client(scratch));
                    }
                    // Takeover: the previous connection is usually one the daemon
                    // has not yet noticed is dead (DESIGN.md § 6.4).
                    if let Some(mut old) = self.client.take() {
                        old.send_control(&Frame::Error {
                            code: ErrorCode::Takeover,
                            message: "another client attached",
                        });
                        drop(old.flush_blocking());
                    }
                    self.client = Some(Conn::new(stream)?);
                    self.greeted = false;
                    self.detached_since = None;
                    return Ok(());
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
    }

    fn read_pty(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let Some(pty) = self.pty.as_ref() else {
            return Ok(());
        };
        let n = pty::read_pty(pty.master(), buf)?;
        if n == 0 {
            self.on_child_exit();
            return Ok(());
        }
        // Always drain, attached or not: a full ring drops its oldest bytes, but a
        // PTY that is not read blocks the child on write.
        self.ring.push(buf.get(..n).unwrap_or(&[]));
        Ok(())
    }

    fn write_pty(&mut self) -> io::Result<()> {
        let Some(pty) = self.pty.as_ref() else {
            return Ok(());
        };
        while !self.pending_input.is_empty() {
            let (front, _) = self.pending_input.as_slices();
            if front.is_empty() {
                self.pending_input.make_contiguous();
                continue;
            }
            match rustix::io::write(pty.master(), front) {
                Ok(0) | Err(rustix::io::Errno::AGAIN) => break,
                Ok(n) => drop(self.pending_input.drain(..n)),
                Err(rustix::io::Errno::INTR) => {}
                // The child is gone; report it rather than failing the daemon, so
                // the attached client still receives `Exit`.
                Err(rustix::io::Errno::IO) => {
                    self.pending_input.clear();
                    self.on_child_exit();
                    break;
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn on_child_exit(&mut self) {
        if self.exited.is_some() {
            return;
        }
        let status = self
            .pty
            .as_mut()
            .and_then(|pty| pty.try_wait().ok().flatten());
        let parts = status
            .as_ref()
            .map_or((0, ExitKind::Exited), |s| pty::exit_parts(*s));
        self.exited = Some(parts);
        self.linger_until = Some(Instant::now() + EXIT_LINGER);
        if let Some(client) = self.client.as_mut() {
            client.send_control(&Frame::Exit {
                status: parts.0,
                kind: parts.1,
            });
        }
    }

    fn read_client(&mut self, scratch: &mut Vec<u8>) -> io::Result<()> {
        let Some(client) = self.client.as_mut() else {
            return Ok(());
        };
        if client.fill().is_err() {
            // A connection failing is the normal case, not a daemon failure. A
            // client that closes with output still queued makes the kernel send
            // RST, and reading that yields ECONNRESET — propagating it would kill
            // the session, which is precisely what this daemon exists to prevent.
            self.drop_client();
            return Ok(());
        }

        loop {
            let Some(client) = self.client.as_mut() else {
                return Ok(());
            };
            let ty = match client.take_frame(scratch) {
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

        if self.client.as_ref().is_some_and(Conn::is_eof) {
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
            Frame::OutputAck { .. } => {}
            Frame::Ping { nonce } => {
                if let Some(client) = self.client.as_mut() {
                    client.send_control(&Frame::Pong { nonce });
                }
            }
            Frame::Detach => self.drop_client(),
            _ => self.reject(ErrorCode::Protocol, "frame is not valid from a client"),
        }
        Ok(())
    }

    fn on_hello(&mut self, hello: &Hello<'_>) -> io::Result<()> {
        if hello.protocol != PROTOCOL_VERSION {
            self.reject(ErrorCode::Version, "protocol version mismatch");
            return Ok(());
        }
        self.win = hello.win;

        if self.pty.is_none() {
            match Pty::spawn(hello.term, hello.win, self.paths.id()) {
                Ok(pty) => self.pty = Some(pty),
                Err(err) => {
                    self.reject(ErrorCode::Internal, "failed to start the session shell");
                    return Err(err);
                }
            }
        } else if let Some(pty) = self.pty.as_ref() {
            drop(pty.resize(hello.win));
        }

        let base = self.ring.base();
        let gap = hello.out_offset != RESUME_FROM_START && hello.out_offset < base;
        let resume_from = if hello.out_offset == RESUME_FROM_START {
            base
        } else {
            hello.out_offset.max(base)
        };
        self.sent_through = resume_from;
        self.greeted = true;

        if let Some(client) = self.client.as_mut() {
            client.send_control(&Frame::HelloOk(HelloOk {
                protocol: PROTOCOL_VERSION,
                resume_from,
                in_applied: self.in_applied,
                win: self.win,
                gap,
            }));
            if let Some((status, kind)) = self.exited {
                client.send_control(&Frame::Exit { status, kind });
            }
        }
        if gap && let Some(pty) = self.pty.as_ref() {
            drop(pty.nudge_repaint(self.win));
        }
        Ok(())
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
            self.pending_input
                .extend(data.get(skip..).unwrap_or(&[]).iter().copied());
            self.in_applied = end;
        }
        if let Some(client) = self.client.as_mut() {
            client.send_control(&Frame::InputAck {
                applied_through: self.in_applied,
            });
        }
    }

    fn pump_output(&mut self) {
        if !self.greeted {
            return;
        }
        let Some(client) = self.client.as_mut() else {
            return;
        };
        if client.is_write_saturated() || self.sent_through >= self.ring.end() {
            return;
        }

        let base = self.ring.base();
        if self.sent_through < base {
            // Overflowed while this client was slow or away: the stream is
            // discontinuous and the client must reset its emulator.
            client.send_control(&Frame::Gap {
                new_base_offset: base,
            });
            self.sent_through = base;
            if let Some(pty) = self.pty.as_ref() {
                drop(pty.nudge_repaint(self.win));
            }
        }

        for part in self.ring.slices_from(self.sent_through) {
            if part.is_empty() {
                continue;
            }
            match client.send_output(self.sent_through, part) {
                Ok(next) => self.sent_through = next,
                Err(_) => break,
            }
        }
    }

    fn write_client(&mut self) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        if client.flush_some().is_err() {
            self.drop_client();
        }
    }

    /// Sends a final `Error` and closes the connection.
    fn reject(&mut self, code: ErrorCode, message: &'static str) {
        if let Some(mut client) = self.client.take() {
            client.send_control(&Frame::Error { code, message });
            drop(client.flush_blocking());
        }
        self.on_detached();
    }

    fn drop_client(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.flush_blocking());
        }
        self.on_detached();
    }

    fn on_detached(&mut self) {
        self.greeted = false;
        self.detached_since = Some(Instant::now());
        // A session whose child already exited has nothing left to serve.
        if self.exited.is_some() {
            self.linger_until = Some(Instant::now());
        }
    }

    fn shutdown(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.flush_blocking());
        }
        if let Some(mut pty) = self.pty.take() {
            pty.terminate();
        }
        self.paths.unlink_all();
    }
}

/// Frame types a client may send. Anything else is a protocol error.
#[expect(dead_code, reason = "documents the client-to-daemon subset for review")]
const CLIENT_FRAMES: [FrameType; 6] = [
    FrameType::Hello,
    FrameType::Input,
    FrameType::OutputAck,
    FrameType::Resize,
    FrameType::Detach,
    FrameType::Ping,
];
