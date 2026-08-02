//! Shared scaffolding for the end-to-end test binaries.
//!
//! Each integration test crate compiles its own copy of this module and uses a
//! subset of it, so unused items here are expected rather than a smell.
//!
//! Every test owns a run directory of its own, and wipes it on the way in. The name
//! is a hash of the test's name and the pid of the process running it: the hash
//! keeps two tests apart, and the pid keeps two runs apart, so a second copy of a
//! binary started in a second terminal no longer deletes the first one's sockets.
//! Nothing ever reuses a directory once its process is gone, so [`run_root`] sweeps
//! away the ones whose pid has left.
//!
//! Both halves are kept short because these paths carry unix sockets and
//! `sockaddr_un` truncates at 108 bytes. What the suite adds to
//! `CARGO_TARGET_TMPDIR` is at most 38 of them — `/<hash>-<pid>/nomux/<hash>.agent`,
//! with the widest pid Linux will issue — which puts the longest socket a checkout
//! in a home directory binds at 73 bytes, against 89 for the names this replaces,
//! and leaves 69 for the checkout itself. That is what makes a worktree under
//! `.claude/worktrees/` runnable.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "shared by several test binaries, each using a subset; and the \
              allow-*-in-tests settings in clippy.toml cover only #[cfg(test)] \
              modules, not integration test crates"
)]

use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{
    Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
    decode_header,
};

pub(crate) const WIN: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

/// A daemon running in an isolated run directory, killed on drop.
pub(crate) struct Session {
    pub(crate) child: Child,
    pub(crate) root: PathBuf,
    pub(crate) socket: PathBuf,
    pub(crate) id: String,
}

/// Ring capacity for tests that do not name one.
///
/// Small enough that a test about overflow reaches it in a few hundred kilobytes of
/// shell output rather than megabytes, and far larger than anything a test that is
/// not about overflow produces — so a `Gap` in one of those is a defect rather than
/// the ring being tight.
pub(crate) const DEFAULT_TEST_RING: usize = 64 * 1024;

impl Session {
    /// Starts a daemon with [`DEFAULT_TEST_RING`].
    pub(crate) fn start(name: &str) -> Self {
        Self::start_with_ring(name, DEFAULT_TEST_RING)
    }

    pub(crate) fn start_with_ring(name: &str, ring_bytes: usize) -> Self {
        let root = run_root(name);
        let id = intern(name);
        let child = Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["daemon", &id])
            .env("XDG_RUNTIME_DIR", &root)
            // A predictable shell keeps assertions independent of the developer's
            // login environment.
            .env("SHELL", "/bin/sh")
            .env("PS1", "")
            // The child's working directory, so `pwd` is assertable.
            .env("HOME", &root)
            .env("NOMUX_RING_BYTES", ring_bytes.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");

        let socket = root.join("nomux").join(format!("{id}.sock"));
        wait_for(&socket);
        Self {
            child,
            root,
            socket,
            id,
        }
    }

    pub(crate) fn connect(&self) -> Client {
        let stream = UnixStream::connect(&self.socket).expect("connect to session");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("set read timeout");
        Client {
            stream,
            pending: Vec::new(),
        }
    }

    /// A daemon with one client attached to it, greeted from the start of both
    /// streams.
    ///
    /// Start, connect, greet is how most of the suite opens, and those three lines say
    /// nothing about the test that follows them: a session nobody has touched before,
    /// a single client, and a `HelloOk` whose `resume_from` is where the first
    /// [`Client::read_until`] begins. Saying it once leaves each test starting at the
    /// thing it is actually about.
    ///
    /// The [`Session`] comes back alongside the client because it owns the daemon and
    /// kills it on drop, so the caller has to bind it for as long as the client is
    /// used — `let (_session, ..)` where the test never names it again, never `let (_,
    /// ..)`, which would end the session on the spot.
    ///
    /// Not for the connections that need the three steps apart: one that asserts on
    /// the run directory before anything connects, one that resumes from an offset it
    /// worked out for itself, one that wants a ring other than [`DEFAULT_TEST_RING`],
    /// or one whose own handshake is the subject. Those spell it out, because there
    /// the spelling is the test — and it is per *connection* rather than per test,
    /// since the tests about a refused greeting still open with an ordinary attached
    /// client and then bring on the connection they are really about.
    pub(crate) fn attached(name: &str) -> (Self, Client, nomux_proto::HelloOk) {
        Self::attached_with(name, 0)
    }

    /// [`Session::attached`], with `flags` in the greeting.
    ///
    /// Its own function rather than an argument on the common one so that the sessions
    /// asking for nothing in particular do not all carry a `0` that reads like a
    /// decision somebody made.
    pub(crate) fn attached_with(name: &str, flags: u16) -> (Self, Client, nomux_proto::HelloOk) {
        let session = Self::start(name);
        let mut client = session.connect();
        let ok = client.hello_with(flags, RESUME_FROM_START, 0);
        (session, client, ok)
    }

    /// The directory the daemon publishes its five files in.
    pub(crate) fn run_dir(&self) -> PathBuf {
        self.root.join("nomux")
    }

    /// The pidfile `nomux kill` reads to find out what to signal.
    pub(crate) fn pid_file(&self) -> PathBuf {
        self.run_dir().join(format!("{}.pid", self.id))
    }

    /// The session's `ssh-agent` socket, which exists only once a client has
    /// created the session with agent forwarding on.
    pub(crate) fn agent_socket(&self) -> PathBuf {
        self.run_dir().join(format!("{}.agent", self.id))
    }

    /// Opens a connection to the agent socket, the way a child process would.
    pub(crate) fn connect_agent(&self) -> UnixStream {
        let stream = UnixStream::connect(self.agent_socket()).expect("connect to agent socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("set read timeout");
        stream
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// An empty run directory belonging to `name` and to this process alone.
///
/// Every test that needs one comes through here, so the naming argument in this
/// module's header holds for all of them rather than for the ones that remembered.
pub(crate) fn run_root(name: &str) -> PathBuf {
    sweep_finished_runs();
    let owned = format!("{}-{}", intern(name), std::process::id());
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(owned);
    // A pid is reused eventually, and a run that crashed hard leaves its directory
    // behind, so the wipe stays even though the name is this process's own.
    drop(fs::remove_dir_all(&root));
    fs::create_dir_all(&root).expect("create run root");
    root
}

/// Removes the run directories of test processes that have exited.
///
/// The pid in the name is what lets two runs proceed at once, and it is equally
/// what stops a run from reusing what the last one left: without this,
/// `CARGO_TARGET_TMPDIR` would grow by a directory per test per run, for ever. A
/// directory goes only once `/proc` says its process is gone — a live pid is either
/// this one or a run in flight, and taking either away is the exact fault the naming
/// exists to prevent.
fn sweep_finished_runs() {
    let Ok(entries) = fs::read_dir(env!("CARGO_TARGET_TMPDIR")) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let owner = name
            .to_string_lossy()
            .rsplit_once('-')
            .and_then(|(_, pid)| pid.parse::<u32>().ok());
        if owner.is_some_and(|pid| !Path::new(&format!("/proc/{pid}")).exists()) {
            drop(fs::remove_dir_all(entry.path()));
        }
    }
}

/// A short, stable, filesystem- and session-id-safe name for `name`.
///
/// FNV-1a rendered in base 36, which is eight characters of `[0-9a-z]` for any test
/// name at all — the whole point, since the long names these replace are what put
/// the socket path over `sockaddr_un`'s limit on a deep checkout. Eight characters
/// is 2.8e12 values against the few dozen names in the suite, so a collision would
/// be remarkable.
fn intern(name: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut interned = String::with_capacity(8);
    for _ in 0..8 {
        let digit = u32::try_from(hash % 36).expect("a digit below the radix");
        interned.push(char::from_digit(digit, 36).expect("a digit below the radix"));
        hash /= 36;
    }
    interned
}

/// Runs `nomux` against the run directory under `root`, and waits for it to finish.
///
/// `list` and `kill` reach a session only through the files on disk (§ 6.6), so
/// pointing `XDG_RUNTIME_DIR` at the right place is the whole of what they need to
/// be told — as it is for any other mode expected to refuse before it starts
/// anything. A mode that would go on to serve must not come through here: waiting
/// for it is waiting for ever.
pub(crate) fn control(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nomux"))
        .args(args)
        .env("XDG_RUNTIME_DIR", root)
        .output()
        .expect("run nomux")
}

pub(crate) fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("daemon never bound {}", path.display());
}

/// A protocol client: enough of one to assert on daemon behaviour.
pub(crate) struct Client {
    stream: UnixStream,
    pending: Vec<u8>,
}

/// Where the two streams stand once the child is ready. See [`Client::make_ready`].
pub(crate) struct Ready {
    /// The setup line as it was sent, for the test that has to be able to resend it.
    pub(crate) line: String,
    /// One past that line on the input stream.
    pub(crate) in_offset: u64,
    /// One past the marker on the output stream.
    pub(crate) offset: u64,
}

/// What the shell is asked to say once the terminal is configured, and what that
/// becomes once it has. The arithmetic is the point of both: see
/// [`Client::make_ready`].
const READY_ECHO: &str = "echo \"NOMUX-$((6*7))-READY\"";
const READY_MARKER: &str = "NOMUX-42-READY";

impl Client {
    pub(crate) fn send(&mut self, frame: &Frame<'_>) {
        write_frame(&mut self.stream, frame);
    }

    pub(crate) fn hello(&mut self, out_offset: u64, in_offset: u64) -> nomux_proto::HelloOk {
        self.hello_with(0, out_offset, in_offset)
    }

    pub(crate) fn hello_with(
        &mut self,
        flags: u16,
        out_offset: u64,
        in_offset: u64,
    ) -> nomux_proto::HelloOk {
        self.send(&hello_frame(flags, out_offset, in_offset));
        match self.next_frame() {
            (FrameType::HelloOk, payload) => {
                match Frame::decode(FrameType::HelloOk, &payload).expect("decode HelloOk") {
                    Frame::HelloOk(ok) => ok,
                    other => panic!("expected HelloOk, got {other:?}"),
                }
            }
            (ty, _) => panic!("expected HelloOk, got {ty:?}"),
        }
    }

    /// Puts the child's terminal into `mode`, waits for proof that it is already in
    /// effect, and leaves `then` running behind it.
    ///
    /// The one shape every test that asserts on raw bytes needs first, and the one
    /// the several hand-written copies of it reconciled to: `stty <mode>`, then a
    /// marker, then whatever the test wants running — `-echo -onlcr` for a
    /// comparison that must be literal, `raw -echo` with a `sleep` for a child that
    /// holds the terminal without reading it.
    ///
    /// The marker comes *after* the `stty` because that is what makes arriving at it
    /// proof the mode is in effect rather than merely reached: input sent while the
    /// line discipline was still canonical is discarded by it rather than delivered,
    /// and the test would then accuse the daemon of losing what the terminal threw
    /// away. It is built out of `$((6*7))` because the line discipline echoes the
    /// command line itself before any of it runs — that echo carries the arithmetic
    /// unexpanded, so it cannot be what satisfies the wait.
    ///
    /// Sent at input offset 0: a session that is not ready yet has had nothing else
    /// sent to it.
    pub(crate) fn make_ready(&mut self, mode: &str, then: Option<&str>, from: u64) -> Ready {
        let mut line = format!("stty {mode}; {READY_ECHO}");
        if let Some(then) = then {
            line.push_str("; ");
            line.push_str(then);
        }
        line.push('\n');
        self.send(&Frame::Input {
            offset: 0,
            data: line.as_bytes(),
        });
        let (_, offset) = self.read_until(READY_MARKER, from);
        Ready {
            in_offset: line.len() as u64,
            line,
            offset,
        }
    }

    pub(crate) fn next_frame(&mut self) -> (FrameType, Vec<u8>) {
        loop {
            if self.pending.len() >= HEADER_LEN {
                let head: [u8; HEADER_LEN] = self.pending[..HEADER_LEN].try_into().unwrap();
                let header = decode_header(&head).expect("decode header");
                let total = HEADER_LEN + header.len as usize;
                if self.pending.len() >= total {
                    let payload = self.pending[HEADER_LEN..total].to_vec();
                    self.pending.drain(..total);
                    return (header.ty, payload);
                }
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).expect("read from daemon");
            assert!(n > 0, "daemon closed the connection unexpectedly");
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }

    /// Reads frames until one of type `want` arrives, returning its payload and
    /// ignoring the session's own chatter. Anything else is a bug in the daemon's
    /// frame ordering.
    pub(crate) fn next_of(&mut self, want: FrameType) -> Vec<u8> {
        loop {
            let (ty, payload) = self.next_frame();
            if ty == want {
                return payload;
            }
            assert!(
                matches!(
                    ty,
                    FrameType::Output | FrameType::InputAck | FrameType::Pong
                ),
                "unexpected {ty:?} while waiting for {want:?}"
            );
        }
    }

    /// The channel id carried by the next frame of type `want`.
    pub(crate) fn next_chan(&mut self, want: FrameType) -> u32 {
        let payload = self.next_of(want);
        match Frame::decode(want, &payload).expect("decode channel frame") {
            Frame::AgentOpen { chan } | Frame::AgentClose { chan } => chan,
            other => panic!("expected a channel frame, got {other:?}"),
        }
    }

    /// Consumes whatever the daemon has already sent, without waiting for more.
    ///
    /// For tests that are about to close on purpose: a socket closed with data
    /// still unread makes the kernel send RST, which discards *both* directions —
    /// including bytes this client wrote and the daemon had not yet read. Draining
    /// first turns the close into an orderly FIN, so what happens to that input is
    /// the daemon's behaviour rather than the kernel's timing.
    pub(crate) fn drain_available(&mut self) {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("shorten read timeout");
        let mut chunk = [0u8; 8192];
        while let Ok(n) = self.stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
        self.stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("restore read timeout");
    }

    /// Reads until the daemon has acknowledged input through `through`, tolerating
    /// whatever else arrives on the way.
    ///
    /// For tests that are about to disconnect on purpose: an `Input` frame that was
    /// written but not yet read is lost when the socket closes with output still
    /// queued, so waiting for the ack is what makes "the daemon has this" true.
    pub(crate) fn wait_for_input_ack(&mut self, through: u64) {
        loop {
            let (ty, payload) = self.next_frame();
            if ty == FrameType::InputAck
                && let Frame::InputAck { applied_through } =
                    Frame::decode(ty, &payload).expect("decode ack")
                && applied_through >= through
            {
                return;
            }
        }
    }

    /// Collects output until `needle` appears, returning everything consumed and
    /// the offset one past the last output byte.
    pub(crate) fn read_until(&mut self, needle: &str, from: u64) -> (String, u64) {
        let mut seen = Vec::new();
        let mut offset = from;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let (ty, payload) = self.next_frame();
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(at, offset, "output offsets must be contiguous");
                    offset += data.len() as u64;
                    seen.extend_from_slice(data);
                    if String::from_utf8_lossy(&seen).contains(needle) {
                        return (String::from_utf8_lossy(&seen).into_owned(), offset);
                    }
                }
                Frame::InputAck { .. } | Frame::Pong { .. } => {}
                other => panic!("unexpected frame while awaiting {needle:?}: {other:?}"),
            }
        }
        panic!(
            "timed out waiting for {needle:?}; saw: {:?}",
            String::from_utf8_lossy(&seen)
        );
    }
}

/// The greeting the tests send: the current protocol, [`WIN`], and a terminal type
/// the daemon has no opinion about.
///
/// One literal rather than four, since the three sites that write it straight at a
/// socket are exactly the ones that would be missed if it ever changed.
pub(crate) const fn hello_frame(flags: u16, out_offset: u64, in_offset: u64) -> Frame<'static> {
    Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        flags,
        out_offset,
        in_offset,
        win: WIN,
        term: "xterm-256color",
    })
}

/// Encodes `frame` straight into `sink`.
///
/// For the tests that hold a socket or a relay's stdin rather than a [`Client`],
/// because what they measure is what the far end does with the bytes rather than
/// the conversation that follows.
pub(crate) fn write_frame(sink: &mut impl Write, frame: &Frame<'_>) {
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    sink.write_all(&buf).expect("write frame");
}

/// Pushes `bytes` at a non-blocking socket until it has refused all of them for
/// `patience`, and reports how many it took.
///
/// Not `write_all`: these tests ask how much the daemon will accept before it stops
/// accepting, and a blocking write has no way to say. A socket that has refused
/// everything for a while is the daemon having stopped reading, which is the
/// behaviour under test rather than a timeout — so the caller chooses how long a
/// while is, against how long its own workload takes to settle.
pub(crate) fn push_until_refused(
    socket: &mut UnixStream,
    bytes: &[u8],
    patience: Duration,
) -> usize {
    let mut sent = 0;
    let mut progressed = Instant::now();
    while sent < bytes.len() && progressed.elapsed() < patience {
        match socket.write(&bytes[sent..]) {
            Ok(0) => break,
            Ok(n) => {
                sent += n;
                progressed = Instant::now();
            }
            // A fiftieth of the patience: short enough that what ends the loop is
            // the deadline rather than the sleep it overshot by, long enough not to
            // spin on a socket that is going to stay full.
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(patience / 50);
            }
            Err(_) => break,
        }
    }
    sent
}

/// A child killed and collected when it goes out of scope, however it goes out of
/// scope.
///
/// The processes these tests start put a daemon in a session of its own, so an
/// assertion firing before a hand-written kill leaks both past the end of the run —
/// and that daemon goes on owning a run directory nothing else will collect.
/// Read-then-kill-then-assert says the same thing where the ordering is simple
/// enough to arrange, and several tests do exactly that; this covers everything
/// before that point, and every path out that is not the one the author had in mind.
pub(crate) struct Spawned(Option<Child>);

impl Spawned {
    pub(crate) fn spawn(command: &mut Command) -> Self {
        Self(Some(command.spawn().expect("spawn a child")))
    }

    pub(crate) fn is_running(&mut self) -> bool {
        self.0
            .as_mut()
            .is_some_and(|child| child.try_wait().expect("wait for a child").is_none())
    }

    /// Hands back a child that has already exited, so its output can be collected.
    pub(crate) fn into_exited(mut self) -> Child {
        self.0.take().expect("the child is still held")
    }
}

impl Deref for Spawned {
    type Target = Child;

    fn deref(&self) -> &Child {
        self.0.as_ref().expect("the child is still held")
    }
}

impl DerefMut for Spawned {
    fn deref_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("the child is still held")
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            drop(child.kill());
            drop(child.wait());
        }
    }
}

/// xorshift64; a dependency-free generator whose only requirement here is that it
/// is reproducible from its seed.
pub(crate) struct Rng(u64);

impl Rng {
    /// The low bit is forced on because zero is the one state xorshift cannot leave,
    /// and a seed can arrive from an environment variable.
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub(crate) const fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `0..n`.
    pub(crate) const fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    /// `len` bytes of the stream.
    ///
    /// For traffic that is compared byte for byte at the far end: a repeating
    /// pattern would let a chunk that was dropped, duplicated or reordered pass that
    /// comparison unnoticed.
    pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + size_of::<u64>());
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}
