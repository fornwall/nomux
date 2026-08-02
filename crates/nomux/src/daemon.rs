//! The session daemon: owns the PTY, the ring buffer and the listening socket.
//!
//! Single-threaded around `poll`. There is at most one client
//! (`IMPLEMENTATION.md` § 6.4), so the poll set is small: the listener, the PTY
//! master, the client if one is attached, the connection that has not greeted yet,
//! and — when agent forwarding is on — the agent socket plus one entry per live
//! channel.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nomux_proto::{
    ErrorCode, ExitKind, Frame, FrameType, Hello, HelloOk, Linger, PROTOCOL_VERSION,
    RESUME_FROM_START, WinSize,
};
use rustix::event::{PollFd, PollFlags, Timespec};

use crate::agent::{self, Agent};
use crate::conn::Conn;
use crate::linger;
use crate::pty::{self, Pty};
use crate::rundir::SessionPaths;

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

/// How long to keep retrying `waitpid` after the PTY reports end of file before
/// reporting a status the daemon had to invent.
///
/// Comfortably inside [`EXIT_LINGER`], so the `Exit` frame still goes out within
/// the window a reconnecting client is promised.
const REAP_GRACE: Duration = Duration::from_secs(2);

/// How often to retry while waiting for the child to become reapable. The wait is
/// normally over within microseconds; this only bounds the pathological case.
const REAP_RETRY: Duration = Duration::from_millis(5);

/// Longest the poll loop sleeps with nothing else pending.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_hours is unstable on the pinned 1.97.1 toolchain"
)]
const IDLE_TICK: Duration = Duration::from_secs(60 * 60);

/// How long to wait for the very first client before giving up. Without this a
/// daemon spawned by a connection that died mid-handshake would live forever.
const FIRST_ATTACH_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Session state for the lifetime of the daemon process.
struct Daemon {
    paths: SessionPaths,
    listener: UnixListener,
    ring: crate::ring::Ring,
    pty: Option<Pty>,
    client: Option<Conn>,
    /// A connection that has been accepted but has not said `Hello` yet, and so
    /// has not taken the session over. Usually a liveness probe from `list`.
    pending: Option<Conn>,
    /// Agent socket and its channels, once a session created with
    /// [`nomux_proto::HELLO_AGENT_FORWARD`] has bound one.
    agent: Option<Agent>,
    /// Where the child starts, captured before the daemon moved to `/`.
    child_dir: PathBuf,
    /// Whether `logind` will let this session outlive the user's logout, for
    /// `HelloOk`. Unrelated to `linger_until`, which is the post-exit grace period.
    logind_linger: Linger,
    /// Post-gap repaint policy, restated by each client's `Hello`.
    repaint_ctrl_l: bool,
    /// Set once the attached client's `Hello` has been answered.
    greeted: bool,
    /// Whether this client has already been told the child exited. Per connection:
    /// a client that reattaches after the fact must hear it again.
    exit_sent: bool,
    /// Authoritative input offset: everything below this has been accepted for the
    /// PTY and must never be applied twice.
    in_applied: u64,
    /// Input accepted but not yet written, because the PTY was not writable.
    pending_input: VecDeque<u8>,
    /// Output offset already queued to the current client.
    sent_through: u64,
    win: WinSize,
    /// When the PTY master reported end of file, i.e. when the child let go of the
    /// terminal. Distinct from `exited`: the status is not readable yet at that
    /// moment, and on this kernel usually is not.
    child_gone: Option<Instant>,
    /// The child's status, `None` until `waitpid` hands it over.
    exited: Option<(i32, ExitKind)>,
    /// When the session became clientless, for idle reaping.
    detached_since: Option<Instant>,
    /// Deadline after the child exits.
    linger_until: Option<Instant>,
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
pub(crate) fn run(session_id: &str, capacity: usize, label: Option<&str>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    paths.ensure_dir()?;

    let listener = bind_socket(&paths)?;
    write_pidfile(&paths)?;
    if let Some(label) = label {
        // Advisory: a session is worth more than its name in a listing.
        drop(paths.write_label(label));
    }

    // Everything above resolved its paths already, so the daemon can let go of the
    // directory it inherited from the attaching connection. Holding it would keep
    // a removable or network mount busy for as long as the session lives, which
    // could be days. The child does not follow — it starts in the user's home,
    // like any login shell.
    let child_dir = pty::child_dir(std::env::current_dir().ok().as_deref());
    detach_from_startup_state();

    let mut daemon = Daemon {
        paths,
        listener,
        ring: crate::ring::Ring::new(capacity),
        pty: None,
        client: None,
        pending: None,
        agent: None,
        child_dir,
        logind_linger: linger::detect(),
        repaint_ctrl_l: false,
        greeted: false,
        exit_sent: false,
        in_applied: 0,
        pending_input: VecDeque::new(),
        sent_through: 0,
        win: WinSize::default(),
        child_gone: None,
        exited: None,
        detached_since: Some(Instant::now()),
        linger_until: None,
    };

    let result = daemon.event_loop();
    daemon.shutdown();
    result
}

/// Cuts the daemon loose from the state it inherited: the working directory and
/// `SIGHUP`.
///
/// `IMPLEMENTATION.md` § 6.2. `setsid` already left the daemon without a
/// controlling terminal, so no `SIGHUP` can currently reach it — this is the belt
/// to that braces, since a session that dies on hangup is the one failure this
/// whole program exists to prevent. `SIGPIPE` needs nothing: the Rust runtime
/// ignores it at startup and restores it for the child.
///
/// Failures are not propagated. A daemon that cannot `chdir` still works; refusing
/// to start over it would be a worse outcome than the mount it might pin.
fn detach_from_startup_state() {
    let _ = rustix::process::chdir("/");
    // SAFETY: `signal` with SIG_IGN is safe to call on a single-threaded process
    // with no handler installed; the disposition is reset in the child before exec
    // (see `pty::Pty::spawn`) so the child still dies on hangup as it should.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
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

    let listener = crate::rundir::bind_socket_private(&path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn write_pidfile(paths: &SessionPaths) -> io::Result<()> {
    let mut file = fs::File::create(paths.pid())?;
    writeln!(file, "{}", std::process::id())
}

/// What one entry of the poll set belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The session socket, where clients arrive.
    Listener,
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

impl Daemon {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut scratch = Vec::new();
        let mut read_buf = vec![0u8; 64 * 1024];

        loop {
            self.reap();
            if self.should_stop() {
                return Ok(());
            }
            self.poll_once(&mut read_buf, &mut scratch)?;
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

    fn should_stop(&self) -> bool {
        if let Some(deadline) = self.linger_until
            && Instant::now() >= deadline
        {
            return true;
        }
        if let Some(since) = self.detached_since
            && since.elapsed() >= self.detach_limit()
        {
            return true;
        }
        false
    }

    /// Everything the poll set watches, in the order it is registered.
    ///
    /// Named rather than positional because the set is variable-length: agent
    /// forwarding adds the socket plus one entry per live channel, and an index
    /// arithmetic bug there would silently apply one fd's readiness to another.
    fn watches(&self) -> Vec<(Source, BorrowedFd<'_>, PollFlags)> {
        let mut watches = Vec::with_capacity(4);
        watches.push((Source::Listener, self.listener.as_fd(), PollFlags::IN));

        // Dropped from the set once the child is gone: the master reports `HUP`
        // from then on and would spin the loop at full tilt for the whole linger
        // window, having nothing left to read.
        if let Some(pty) = self.pty.as_ref().filter(|_| self.child_gone.is_none()) {
            let mut flags = PollFlags::IN;
            if !self.pending_input.is_empty() {
                flags |= PollFlags::OUT;
            }
            watches.push((Source::Pty, pty.master(), flags));
        }

        let saturated = self.client.as_ref().is_some_and(Conn::is_write_saturated);
        if let Some(client) = self.client.as_ref() {
            let mut flags = PollFlags::IN;
            // Ring bytes still owed count as wanting to write, not just bytes
            // already encoded. `pump_output` stops at `MAX_PENDING_WRITE`, so a
            // large replay routinely ends an iteration with the queue drained and
            // the ring still ahead — and without this the daemon would then sleep
            // until something else happened to wake it, holding output it could
            // send. `OutputAck` papers over it in practice and is advisory (§ 3),
            // so it cannot be what the loop relies on.
            if client.wants_write() || (self.greeted && self.sent_through < self.ring.end()) {
                flags |= PollFlags::OUT;
            }
            watches.push((Source::Client, client.stream().as_fd(), flags));
        }
        if let Some(pending) = self.pending.as_ref() {
            watches.push((Source::Pending, pending.stream().as_fd(), PollFlags::IN));
        }

        if let Some(agent) = self.agent.as_ref() {
            watches.push((Source::AgentListener, agent.listener(), PollFlags::IN));
            for (id, fd, wants_write) in agent.watches() {
                // A saturated client is the one back pressure signal available:
                // stop draining agent sockets until the queue it feeds has room.
                // The bytes wait in the kernel's socket buffer, where the peer
                // blocks on them, which is exactly the right place for them.
                let mut flags = if saturated {
                    PollFlags::empty()
                } else {
                    PollFlags::IN
                };
                if wants_write {
                    flags |= PollFlags::OUT;
                }
                if !flags.is_empty() {
                    watches.push((Source::AgentChannel(id), fd, flags));
                }
            }
        }
        watches
    }

    fn poll_once(&mut self, read_buf: &mut [u8], scratch: &mut Vec<u8>) -> io::Result<()> {
        if SETTLE_BEFORE_POLL {
            std::thread::sleep(FAULT_SETTLE);
        }
        // The borrows of `self` end with this block, before anything is handled.
        let events = {
            let watches = self.watches();
            let mut fds: Vec<PollFd<'_>> = watches
                .iter()
                .map(|(_, fd, flags)| PollFd::from_borrowed_fd(*fd, *flags))
                .collect();

            let timeout = self.poll_timeout();
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => return Ok(()),
                Err(err) => return Err(err.into()),
            }

            watches
                .iter()
                .zip(fds.iter())
                .map(|((source, _, _), fd)| (*source, fd.revents()))
                .collect::<Vec<_>>()
        };
        let revents = |want: Source| {
            events
                .iter()
                .find(|(source, _)| *source == want)
                .map_or(PollFlags::empty(), |(_, flags)| *flags)
        };
        let readable = PollFlags::IN | PollFlags::HUP | PollFlags::ERR;

        let pty_events = revents(Source::Pty);
        let client_events = revents(Source::Client);
        if pty_events.intersects(PollFlags::OUT) {
            self.write_pty()?;
        }
        if pty_events.intersects(readable) {
            self.read_pty(read_buf)?;
        }
        // Before the greeting, always: one poll can report both a readable client
        // and a `Hello` from its replacement, and handling the takeover first would
        // drop the outgoing `Conn` with input still unread in its socket buffer.
        if !ACCEPT_BEFORE_READ && client_events.intersects(readable) {
            self.read_client(scratch)?;
        }
        if revents(Source::Pending).intersects(readable) {
            self.read_pending(scratch)?;
        }
        if revents(Source::Listener).contains(PollFlags::IN) {
            self.accept();
        }
        if ACCEPT_BEFORE_READ && client_events.intersects(readable) {
            self.read_client(scratch)?;
        }

        for (source, flags) in &events {
            if let Source::AgentChannel(id) = *source {
                self.service_agent_channel(id, *flags, read_buf);
            }
        }
        if revents(Source::AgentListener).contains(PollFlags::IN) {
            self.accept_agent();
        }

        self.pump_output();
        if client_events.contains(PollFlags::OUT)
            || self.client.as_ref().is_some_and(Conn::wants_write)
        {
            self.write_client();
        }
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
        let mut remaining = IDLE_TICK;
        if let Some(deadline) = self.linger_until {
            remaining = remaining.min(deadline.saturating_duration_since(Instant::now()));
        }
        if let Some(since) = self.detached_since {
            remaining = remaining.min(self.detach_limit().saturating_sub(since.elapsed()));
        }
        // The child has let go of the terminal but `waitpid` has not produced its
        // status yet; come back promptly rather than reporting one we invented.
        if self.child_gone.is_some() && self.exited.is_none() {
            remaining = remaining.min(REAP_RETRY);
        }
        Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        }
    }

    /// Takes a new connection, which waits as `pending` until it says `Hello`.
    ///
    /// Connecting is *not* attaching. `nomux list` probes every socket with a bare
    /// `connect` to decide which daemons are still alive (§ 6.6), and so does the
    /// spawn race in § 6.3 — if that counted as a takeover, listing sessions would
    /// evict the user from all of them, and the client is told never to
    /// auto-reconnect after `TAKEOVER`. So the takeover is triggered by the
    /// `Hello`, exactly as `IMPLEMENTATION.md` § 6.4 words it, and a connection that never
    /// greets costs the session nothing.
    /// Never fails. `EMFILE`, `ECONNABORTED` and friends belong to one connection
    /// and are transient; propagating them would destroy a live session over a
    /// descriptor shortage that has nothing to do with it. § 6.4.1 states the rule —
    /// a failing client socket is never propagated out of the event loop — and
    /// `Agent::accept` already implements it for the other listener.
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
                Err(_) => return,
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
                self.reject_pending("unparseable frame header");
                return Ok(());
            }
        };
        if ty != FrameType::Hello {
            self.reject_pending("first frame from a client must be Hello");
            return Ok(());
        }
        let Ok(Frame::Hello(hello)) = Frame::decode(ty, &buf) else {
            self.reject_pending("unparseable Hello");
            return Ok(());
        };

        // Final drain of the outgoing connection: it may have written between the
        // poll and this moment, and input it already delivered must not be lost to
        // the takeover (§ 6.4.1).
        if !ACCEPT_BEFORE_READ && self.client.is_some() {
            drop(self.read_client(scratch));
        }
        self.evict_client();
        self.client = self.pending.take();
        self.greeted = false;
        self.exit_sent = false;
        self.detached_since = None;
        self.on_hello(&hello)?;
        // Clients pipeline: input riding behind the `Hello` in the same read is
        // already buffered in the connection that was just promoted.
        self.read_client(scratch)
    }

    /// Turns away a connection that spoke out of turn, leaving the session alone.
    fn reject_pending(&mut self, message: &'static str) {
        if let Some(mut pending) = self.pending.take() {
            pending.send_last(&Frame::Error {
                code: ErrorCode::Protocol,
                message,
            });
        }
    }

    /// Hands the session over: the previous connection is usually one the daemon
    /// has not yet noticed is dead (`IMPLEMENTATION.md` § 6.4).
    fn evict_client(&mut self) {
        if let Some(mut old) = self.client.take() {
            old.send_last(&Frame::Error {
                code: ErrorCode::Takeover,
                message: "another client attached",
            });
            // The arriving client knows nothing of the outgoing one's channels,
            // and their ids are never reissued.
            self.forget_agent_channels();
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

    /// Records that the child has let go of the terminal, and starts the linger
    /// window.
    ///
    /// The status is deliberately *not* resolved here. The kernel closes the
    /// child's descriptors in `do_exit` before the task becomes reapable, so the
    /// master reports end of file while `waitpid` still answers "not yet" — on this
    /// kernel for about a third of exits. Committing a status at this moment
    /// therefore invents one, and `exit 3` is reported to the client as `exit 0`.
    fn on_child_exit(&mut self) {
        if self.child_gone.is_none() {
            self.child_gone = Some(Instant::now());
            self.linger_until = Some(Instant::now() + EXIT_LINGER);
        }
        self.reap();
        // The frame itself is left to `pump_output`, which sends it once the last
        // of the child's output has gone out. Announcing the exit ahead of the
        // words that caused it is how a client ends up closing the tab on a
        // transcript it never showed.
    }

    /// Collects the child's status once `waitpid` will give it up.
    ///
    /// Called every pass while the status is outstanding, so the wait costs a few
    /// milliseconds rather than a wrong answer.
    fn reap(&mut self) {
        let Some(gone_at) = self.child_gone else {
            return;
        };
        if self.exited.is_some() {
            return;
        }
        if let Some(status) = self
            .pty
            .as_mut()
            .and_then(|pty| pty.try_wait().ok().flatten())
        {
            self.exited = Some(pty::exit_parts(status));
        } else if gone_at.elapsed() >= REAP_GRACE {
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

    fn on_hello(&mut self, hello: &Hello<'_>) -> io::Result<()> {
        if hello.protocol != PROTOCOL_VERSION {
            self.reject(ErrorCode::Version, "protocol version mismatch");
            return Ok(());
        }
        self.win = hello.win;
        self.repaint_ctrl_l = hello.repaint_ctrl_l();

        if self.pty.is_none() {
            // Only the creating `Hello` can turn forwarding on: `SSH_AUTH_SOCK`
            // goes into the child's environment, and a running process's
            // environment cannot be changed afterwards (`DESIGN.md` § 5.3).
            if hello.agent_forward() {
                match Agent::bind(&self.paths.agent()) {
                    Ok(agent) => self.agent = Some(agent),
                    // A session without an agent is worth having; one that refuses
                    // to start is not. `HelloOk` reports the outcome either way.
                    Err(_) => self.agent = None,
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
        } else if let Some(pty) = self.pty.as_ref() {
            drop(pty.resize(hello.win));
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
            hello.out_offset.clamp(base, self.ring.end())
        };
        self.sent_through = resume_from;
        self.greeted = true;

        let agent = self.agent.is_some();
        let linger = self.logind_linger;
        if let Some(client) = self.client.as_mut() {
            client.send_control(&Frame::HelloOk(HelloOk {
                protocol: PROTOCOL_VERSION,
                resume_from,
                in_applied: self.in_applied,
                win: self.win,
                gap,
                linger,
                agent,
            }));
        }
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
        let mut gapped = false;
        {
            let Some(client) = self.client.as_mut() else {
                return;
            };
            if !client.is_write_saturated() && self.sent_through < self.ring.end() {
                let base = self.ring.base();
                if self.sent_through < base {
                    // Overflowed while this client was slow or away: the stream is
                    // discontinuous and the client must reset its emulator.
                    client.send_control(&Frame::Gap {
                        new_base_offset: base,
                    });
                    self.sent_through = base;
                    gapped = true;
                }

                // Both halves of the wrapped deque were addressed in one call, so
                // the second half's offset is only correct if the first was queued
                // whole. Stopping on short progress keeps that true; without it a
                // saturated queue would label the second half with an offset that
                // is too low, which is a corrupted stream rather than a slow one.
                for part in self.ring.slices_from(self.sent_through) {
                    if part.is_empty() {
                        continue;
                    }
                    let want = self.sent_through + part.len() as u64;
                    match client.send_output(self.sent_through, part) {
                        Ok(next) => {
                            self.sent_through = next;
                            if next != want {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }

            // Last, and only once everything the child wrote has been queued: the
            // whole point of the linger window (§ 6.5) is that a client arriving
            // into the race still collects the final output *and* the status, in
            // that order.
            if !self.exit_sent
                && self.sent_through >= self.ring.end()
                && let Some((status, kind)) = self.exited
            {
                client.send_control(&Frame::Exit { status, kind });
                self.exit_sent = true;
            }
        }
        // Outside the borrow above, because the repaint may write to the PTY queue
        // rather than to the client. Mid-stream overflow gets the same treatment as
        // a gap reported at attach time — it is the same discontinuity, and the
        // client chose how to recover from it.
        if gapped {
            self.repaint();
        }
    }

    /// Takes one agent connection off the listener and announces it.
    fn accept_agent(&mut self) {
        // Serving means a client is attached *and* past its `Hello`: a frame sent
        // before `HelloOk` would arrive ahead of the handshake it answers.
        let serving = self.greeted && self.client.is_some();
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        if let Some(chan) = agent.accept(serving)
            && let Some(client) = self.client.as_mut()
        {
            client.send_control(&Frame::AgentOpen { chan });
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
                    let _ = client.send_agent_data(chan, data);
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
        let was_open = self.agent.as_mut().is_some_and(|agent| agent.forget(chan));
        if was_open && let Some(client) = self.client.as_mut() {
            client.send_control(&Frame::AgentClose { chan });
        }
    }

    /// Drops every channel without notifying anyone, for when the client is gone.
    fn forget_agent_channels(&mut self) {
        if let Some(agent) = self.agent.as_mut() {
            agent.forget_all();
        }
    }

    fn write_client(&mut self) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        if client.flush_some().is_err() || client.is_write_hopeless() {
            self.drop_client();
        }
    }

    /// Sends a final `Error` and closes the connection.
    fn reject(&mut self, code: ErrorCode, message: &'static str) {
        if let Some(mut client) = self.client.take() {
            client.send_last(&Frame::Error { code, message });
        }
        self.on_detached();
    }

    fn drop_client(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.flush_final());
        }
        self.on_detached();
    }

    fn on_detached(&mut self) {
        self.greeted = false;
        self.exit_sent = false;
        self.detached_since = Some(Instant::now());
        // Nothing can answer a signature request with the client gone, so the
        // waiting process should fail now rather than at reattach (§ 6.7).
        self.forget_agent_channels();
        // A session whose child already exited has nothing left to serve. Keyed on
        // the terminal being let go rather than on the status having arrived: with
        // nobody left to tell, waiting out the reap grace buys nothing.
        if self.child_gone.is_some() {
            self.linger_until = Some(Instant::now());
        }
    }

    fn shutdown(&mut self) {
        if let Some(mut client) = self.client.take() {
            drop(client.flush_final());
        }
        self.pending = None;
        if let Some(mut pty) = self.pty.take() {
            pty.terminate();
        }
        self.paths.unlink_all();
    }
}
