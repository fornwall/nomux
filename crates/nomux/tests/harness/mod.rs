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
//! `sockaddr_un` truncates at 108 bytes.

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

use std::io::{ErrorKind, Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{
    ErrorCode, Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
    decode_header,
};

pub(crate) const WIN: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

/// How long the harness waits for something it has asked a daemon for.
///
/// One value rather than one per call site: every wait here is on a daemon that is
/// either about to answer or never going to, so the only thing a longer bound buys
/// is patience with a slow machine — and that is the same question everywhere.
const PATIENCE: Duration = Duration::from_secs(15);

/// How long a socket read blocks before the caller's own deadline is looked at
/// again.
///
/// Deliberately far below [`PATIENCE`], so the logical deadline is the one that
/// always fires: it is the only one that knows what the wait was about, where a
/// socket that gave up first could only report an errno.
const SOCKET_POLL: Duration = Duration::from_millis(100);

/// How long [`poll_until`] waits between attempts.
///
/// Short enough that a test measuring how long the daemon took is measuring the
/// daemon rather than the sleep it overshot by — the tightest such bound in the
/// suite is 400 ms against a 500 ms floor — and long enough that a condition which
/// shells out to `nomux list` is not run back to back.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Waits up to `within` for `condition` to hold, and reports whether it ever did.
pub(crate) fn poll_until(within: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Joins `handle`, failing rather than parking if it will not come back.
///
/// The relay tests move megabytes on four threads at once, and a relay that stalls in
/// either direction would otherwise hang the whole run: `JoinHandle::join` has no
/// deadline, and the guard in `.config/nextest.toml` can only kill the process
/// without saying which wait never ended.
pub(crate) fn join_within<T>(handle: thread::JoinHandle<T>, within: Duration, what: &str) -> T {
    assert!(
        poll_until(within, || handle.is_finished()),
        "the {what} thread never finished"
    );
    handle
        .join()
        .unwrap_or_else(|_| panic!("the {what} thread panicked"))
}

/// Reads into `buf`, resuming a call a signal ended.
///
/// Every socket this harness hands out carries a receive timeout, and that is
/// precisely the case the kernel refuses to restart: with `SO_RCVTIMEO` set, a read
/// the kernel finds a pending signal on comes back `EINTR` whatever `SA_RESTART` the
/// handler asked for (`signal(7)`). So `EINTR` here is a call that has not happened
/// yet, not news about the daemon. Anything reading one of these sockets by hand
/// wants this rather than `Read::read`.
///
/// Everything else is passed through untouched: the zero that means the daemon closed
/// the connection, and the `WouldBlock` that is the receive timeout expiring, which is
/// each caller's cue to look at its own deadline.
pub(crate) fn read_uninterrupted(
    socket: &mut UnixStream,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        match socket.read(buf) {
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            outcome => return outcome,
        }
    }
}

/// Writes what `socket` will take of `buf`, resuming a call a signal ended.
///
/// [`read_uninterrupted`] in the other direction, and needed on its own account
/// rather than for symmetry: the only caller is measuring how much the daemon will
/// accept before it stops accepting, and an interruption counted as a refusal ends
/// that measurement early — understating the answer, in the direction that makes the
/// assertion pass. A call a signal reaches after it has transferred anything reports
/// the short count instead, so nothing here can put a byte on the wire twice.
fn write_uninterrupted(socket: &mut UnixStream, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        match socket.write(buf) {
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            outcome => return outcome,
        }
    }
}

/// Accepts one connection, or fails saying what never arrived.
///
/// A blocking `accept` on a listener nothing connects to parks the thread for ever,
/// and a test parked there never returns — so its [`Spawned`] guards never run and
/// the whole run hangs instead of failing. The listener is put in non-blocking mode
/// here rather than at the call site so that no caller can forget; the connection it
/// hands back is blocking, as `accept` does not pass the flag on.
pub(crate) fn accept_within(
    listener: &UnixListener,
    within: Duration,
    awaiting: &str,
) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("a listener the test must not park on");
    let mut accepted = None;
    let arrived = poll_until(within, || match listener.accept() {
        Ok((stream, _)) => {
            accepted = Some(stream);
            true
        }
        // Two ways of saying "ask again on the next pass": `WouldBlock` is the
        // non-blocking listener reporting that nobody has arrived, and `Interrupted`
        // is a signal having ended the call before it could report anything at all.
        Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => false,
        Err(err) => panic!("accepting {awaiting} failed: {err}"),
    });
    assert!(arrived, "timed out waiting for {awaiting}");
    accepted.expect("the connection the wait above returned for")
}

/// A daemon running in an isolated run directory, killed on drop.
pub(crate) struct Session {
    pub(crate) child: Child,
    pub(crate) root: PathBuf,
    pub(crate) socket: PathBuf,
    pub(crate) id: String,
    /// The name the test knows this session by.
    ///
    /// Carried only so that a failure can say it: [`Session::id`] and every path
    /// under [`Session::root`] are built from [`intern`], which is a hash, so
    /// nothing else a session that will not come up has to offer says which test it
    /// belonged to — and a test that starts one per row of a table then fails
    /// identically for every row.
    name: String,
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
        Self::start_with_raw_ring(name, &ring_bytes.to_string())
    }

    /// Starts a daemon with `NOMUX_RING_BYTES` set to exactly `value`.
    ///
    /// Takes the text rather than a number for the one test that is about a value
    /// the daemon cannot parse (`IMPLEMENTATION.md` § 4), which is the thing
    /// [`Session::start_with_ring`] cannot say.
    pub(crate) fn start_with_raw_ring(name: &str, value: &str) -> Self {
        let root = run_root(name);
        let id = intern(name);
        let child = launch(
            nomux_with_shell(&root, &["daemon", &id])
                .env("PS1", "")
                // The child's working directory, so `pwd` is assertable.
                .env("HOME", &root)
                .env("NOMUX_RING_BYTES", value)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .expect("spawn daemon");

        let socket = root.join("nomux").join(format!("{id}.sock"));
        wait_until_answering(&socket);
        Self {
            child,
            root,
            socket,
            id,
            name: name.to_owned(),
        }
    }

    pub(crate) fn connect(&self) -> Client {
        // Named rather than `expect`ed, and never retried. `Session::start` waits
        // until the daemon answers rather than until it has made the name, so a
        // refusal here is a daemon that has stopped answering since — which is a
        // failure whatever else the test was about, and this is where a test that
        // starts a session per case learns which of them it was.
        let stream = UnixStream::connect(&self.socket)
            .unwrap_or_else(|err| panic!("connect to session {:?}: {err}", self.name));
        stream
            .set_read_timeout(Some(SOCKET_POLL))
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
    pub(crate) fn attached(name: &str) -> (Self, Client, nomux_proto::HelloOk) {
        Self::attached_with(name, 0)
    }

    /// [`Session::attached`], with `flags` in the greeting.
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
        let stream = UnixStream::connect(self.agent_socket())
            .unwrap_or_else(|err| panic!("connect to the agent socket of {:?}: {err}", self.name));
        stream
            .set_read_timeout(Some(PATIENCE))
            .expect("set read timeout");
        stream
    }
}

/// Reconnects until the daemon reports a gap, and hands back the greeting that did.
///
/// Whether the ring has overflowed *yet* is a question about when the daemon was
/// last scheduled, not about the property any of these tests are pinning — so a test
/// that sleeps and then asserts `gap` is really asserting that the machine got round
/// to it, under nextest's full-core parallelism, while doing something else.
/// Reconnecting until the daemon itself says so turns that into a wait on the thing
/// being waited for, which either happens or fails with the numbers that explain why
/// not.
pub(crate) fn reconnect_until_gap(
    session: &Session,
    flags: u16,
    out_offset: u64,
    in_offset: u64,
) -> (Client, nomux_proto::HelloOk) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut client = session.connect();
        let resumed = client.hello_with(flags, out_offset, in_offset);
        if resumed.gap {
            return (client, resumed);
        }
        drop(client);
        assert!(
            Instant::now() < deadline,
            "the ring never overflowed while detached: base={} in_applied={} \
             (resuming from {out_offset})",
            resumed.resume_from,
            resumed.in_applied
        );
        thread::sleep(POLL_INTERVAL);
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

/// Held shared by every `fork` this process performs, and exclusively by a test that
/// needs a descriptor of its own to be closed *process-wide*.
///
/// `fork` copies the whole descriptor table, so a child started by one test carries a
/// duplicate of everything every other test had open at that instant, and keeps it
/// until it reaches `exec`. Until then a pipe or socket the other test has closed on
/// purpose is not closed at all: it still has a reader, and a peer writing to it gets
/// its bytes taken rather than the `EPIPE` the test set up. `PLAN.md` § P2 records the
/// same hazard against `flock`; this is the general form of it, and it is invisible
/// under `cargo nextest`, which gives each test a process of its own.
static FORKS: RwLock<()> = RwLock::new(());

/// Starts `command`, holding [`FORKS`] across the `fork` it performs.
///
/// Every process this suite starts comes through here, which is what makes
/// [`while_nothing_forks`] mean anything. Releasing the guard on return is enough:
/// `Command::spawn` does not come back until the child has `exec`ed — the `vfork` of
/// `posix_spawn` suspends the caller until then, and the `fork` path std takes when a
/// `pre_exec` closure is set waits on a close-on-exec pipe that the `exec` is what
/// closes — so by then the copies are gone.
fn launch(command: &mut Command) -> std::io::Result<Child> {
    let _one_at_a_time = FORKS.read().unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

/// Runs `f` with no `fork` in flight anywhere in this process, and none able to start.
///
/// For the window in which a test creates a descriptor it is going to close and then
/// depend on being gone. Keep it to the descriptor work: everything else in the
/// process that wants to start a child waits on it.
pub(crate) fn while_nothing_forks<T>(f: impl FnOnce() -> T) -> T {
    let _sole_owner = FORKS.write().unwrap_or_else(PoisonError::into_inner);
    f()
}

/// A `nomux` invocation against the run directory under `root`, ready for whatever
/// stdio and tuning the caller wants on top.
///
/// Every mode the suite starts is started this way, so the one thing no test may
/// forget is said once rather than at each site: the run directory, which is the
/// whole of what the frozen control surface is told (§ 6.6). Nothing else is added
/// here, because that is a claim about the surface rather than a convenience — an
/// invocation handed more than the run directory is no longer the thing § 6.6
/// describes, and [`control`] beneath would be documenting something it does not do.
pub(crate) fn nomux(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nomux"));
    command.args(args).env("XDG_RUNTIME_DIR", root);
    command
}

/// [`nomux`] with a `SHELL` the developer's login environment cannot vary.
///
/// For every invocation that could put a shell behind a PTY — including the ones
/// where doing so would *be* the failure, since a refusal that regressed should
/// leave a predictable `/bin/sh` to be found rather than whatever the developer
/// logs in with. One caller runs `list` and `kill` through here as well, because
/// the `attach` it shares the call with is the one under test.
///
/// What is left on [`nomux`] alone is what could not start a shell under any
/// regression: `list` and `kill`, and a relay onto a socket the test bound itself,
/// which finds a session already there and so never spawns a daemon.
pub(crate) fn nomux_with_shell(root: &Path, args: &[&str]) -> Command {
    let mut command = nomux(root, args);
    command.env("SHELL", "/bin/sh");
    command
}

/// Runs `nomux` against the run directory under `root`, and waits for it to finish.
///
/// `list` and `kill` reach a session only through the files on disk (§ 6.6), so
/// pointing `XDG_RUNTIME_DIR` at the right place is the whole of what they need to
/// be told — as it is for any other mode expected to refuse before it starts
/// anything. A mode that would go on to serve must not come through here: waiting
/// for it is waiting for ever.
pub(crate) fn control(root: &Path, args: &[&str]) -> Output {
    collect(
        nomux(root, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
}

/// [`Command::output`] with the `fork` under [`FORKS`] and the wait outside it.
///
/// Waiting for the child under the gate would shut every other test out of `fork` for
/// as long as this one ran, where all that has to be exclusive is the `fork` itself.
pub(crate) fn collect(command: &mut Command) -> Output {
    launch(command)
        .expect("start the process")
        .wait_with_output()
        .expect("collect what the process said")
}

/// Fails with `what` unless the process exited successfully, quoting whatever it
/// complained about on the way out.
///
/// The sentence stays at the call site because it is the only part of these
/// assertions that was ever its own. The stderr behind it is not optional: an exit
/// status alone says that something was refused and nothing about what.
pub(crate) fn succeeded(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} ({}): {:?}",
        out.status,
        stderr(out)
    );
}

/// What the process wrote to standard error.
pub(crate) fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// What the process wrote to standard output.
pub(crate) fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Waits for a file the daemon publishes on its way up.
///
/// Named for the file rather than for binding a socket: two of the callers wait on a
/// pidfile, and a failure that says the daemon "never bound" one sends the reader
/// looking in the wrong place.
///
/// Not for a socket a caller then means to *connect* to — see
/// [`wait_until_answering`], which is a different question and the one those callers
/// are really asking.
pub(crate) fn wait_for(path: &Path) {
    assert!(
        poll_until(Duration::from_secs(10), || path.exists()),
        "the daemon never created {}",
        path.display()
    );
}

/// Waits for a daemon to be *answering* on `path`, rather than merely to have made
/// the name.
///
/// A unix socket enters the filesystem at `bind` and starts answering at `listen`,
/// and those are two syscalls: in between, the path exists and every `connect` is
/// refused. So [`wait_for`] on a socket is satisfied one step before the thing every
/// one of its callers goes on to do, and that step is wide enough to lose on a
/// machine with more runnable threads than cores.
///
/// The connection is dropped as soon as it is made, and costs the session nothing:
/// § 6.4 has the daemon promote a connection on its `Hello` and never on the
/// `connect`, precisely so that the liveness probe `nomux list` makes cannot evict a
/// client. So this is not an attach, and does not stop the clock an attach stops.
pub(crate) fn wait_until_answering(path: &Path) {
    let answered = poll_until(Duration::from_secs(10), || {
        UnixStream::connect(path).is_ok()
    });
    assert!(answered, "the daemon never answered on {}", path.display());
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

    /// Sends keystrokes at `offset`.
    ///
    /// The most-sent frame in the suite by a wide margin, and the only one whose
    /// struct literal outweighs its content.
    pub(crate) fn input(&mut self, offset: u64, data: &[u8]) {
        self.send(&Frame::Input { offset, data });
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
    /// `raw` in particular is what makes the line discipline apply back pressure
    /// rather than quietly dropping an overflow: in canonical mode a line longer than
    /// the buffer is discarded and the master never stops accepting, so a test about
    /// a write that cannot complete would measure nothing at all.
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
        self.input(0, line.as_bytes());
        let (_, offset) = self.read_until(READY_MARKER, from);
        Ready {
            in_offset: line.len() as u64,
            line,
            offset,
        }
    }

    pub(crate) fn next_frame(&mut self) -> (FrameType, Vec<u8>) {
        let awaiting = "a frame from the daemon";
        self.frame_before(Instant::now() + PATIENCE, awaiting)
            .unwrap_or_else(|| panic!("timed out waiting for {awaiting}"))
    }

    /// The next frame, or `None` once `deadline` has passed without one.
    ///
    /// The deadline belongs to the caller rather than to this function, so that a
    /// wait made of many frames — [`Client::read_until`] taking output until a needle
    /// appears — is bounded as a whole rather than per frame. Returning rather than
    /// panicking on the deadline leaves the failure to whoever knows what the wait
    /// was for, which is the only place that can also say what it saw instead.
    /// Everything that is *not* a timeout is fatal here and says `awaiting`, because
    /// none of it leaves the caller anything to add.
    fn frame_before(&mut self, deadline: Instant, awaiting: &str) -> Option<(FrameType, Vec<u8>)> {
        loop {
            if let Some(frame) = self.take_pending_frame() {
                return Some(frame);
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut chunk = [0u8; 8192];
            match read_uninterrupted(&mut self.stream, &mut chunk) {
                Ok(0) => panic!("the daemon closed the connection while awaiting {awaiting}"),
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                // What a read timeout is reported as; the deadline above is the one
                // that ends this loop.
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => panic!("reading from the daemon while awaiting {awaiting}: {err}"),
            }
        }
    }

    /// The next whole frame already in the receive buffer, if there is one.
    fn take_pending_frame(&mut self) -> Option<(FrameType, Vec<u8>)> {
        let head: [u8; HEADER_LEN] = self.pending.get(..HEADER_LEN)?.try_into().unwrap();
        let header = decode_header(&head).expect("decode header");
        let total = HEADER_LEN + header.len as usize;
        if self.pending.len() < total {
            return None;
        }
        let payload = self.pending[HEADER_LEN..total].to_vec();
        self.pending.drain(..total);
        Some((header.ty, payload))
    }

    /// Reads frames until one of type `want` arrives, returning its payload and
    /// ignoring the session's own chatter. Anything else is a bug in the daemon's
    /// frame ordering.
    pub(crate) fn next_of(&mut self, want: FrameType) -> Vec<u8> {
        let awaiting = format!("a {want:?} frame");
        let deadline = Instant::now() + PATIENCE;
        loop {
            let (ty, payload) = self
                .frame_before(deadline, &awaiting)
                .unwrap_or_else(|| panic!("timed out waiting for {awaiting}"));
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

    /// Asserts that the very next frame is a refusal carrying `code`, failing with
    /// `what` and the daemon's own words when it is not.
    ///
    /// The *next* frame rather than the next `Error`, because when a refusal arrives
    /// is half of what these tests are about: a `Hello` the daemon cannot answer must
    /// be refused before it takes the session over, and a client handed the right
    /// code after its replacement has already evicted it was given the wrong answer.
    pub(crate) fn expect_error(&mut self, code: ErrorCode, what: &str) {
        let (ty, payload) = self.next_frame();
        assert_refusal(ty, &payload, code, what);
    }

    /// [`Client::expect_error`] for a connection the session is also writing output
    /// to, where the refusal is not the only thing that can be in flight.
    pub(crate) fn expect_error_among_output(&mut self, code: ErrorCode, what: &str) {
        let payload = self.next_of(FrameType::Error);
        assert_refusal(FrameType::Error, &payload, code, what);
    }

    /// Waits for the daemon to close the connection after `after`, without
    /// complaining on the way out.
    ///
    /// Whatever it still had queued is flushed and consumed here — that is a
    /// departing daemon doing its job. An `Error` among it is not, and is checked for
    /// because otherwise almost nothing distinguishes a frame that was *honoured*
    /// from one that fell through to the daemon's "not valid from a client" arm:
    /// both end with a closed connection, and only one of them is the behaviour a
    /// caller is asking about.
    pub(crate) fn expect_eof(&mut self, after: &str) {
        let deadline = Instant::now() + PATIENCE;
        let mut chunk = [0u8; 8192];
        loop {
            while let Some((ty, _)) = self.take_pending_frame() {
                assert_ne!(
                    ty,
                    FrameType::Error,
                    "the daemon refused {after} rather than acting on it"
                );
            }
            match read_uninterrupted(&mut self.stream, &mut chunk) {
                Ok(0) => return,
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => panic!("reading after {after}: {err}"),
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never closed the connection after {after}"
            );
        }
    }

    /// Leaves the daemon with something written that this client has not read.
    ///
    /// For the test that closes on purpose to provoke `ECONNRESET`: the kernel sends
    /// RST rather than FIN only when data is still queued unread, so a close raced
    /// against the daemon's next write exercises the orderly path instead of the one
    /// the regression was about. The ping is what makes there be something to queue —
    /// the session's own output arrives when the child gets round to it, and a client
    /// that has just waited for an ack may already hold all of it. Peeked rather than
    /// read, so the bytes stay where the kernel can still see them.
    pub(crate) fn wait_for_unread_bytes(&mut self) {
        self.send(&Frame::Ping { nonce: 0xDEAD });
        let stream = &self.stream;
        let queued = poll_until(PATIENCE, || has_unread_bytes(stream));
        assert!(
            queued,
            "the daemon wrote nothing, so closing here would be an orderly FIN \
             rather than the reset this is about"
        );
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
    /// For tests that are about to close on purpose: a socket closed with data still
    /// unread makes the kernel send RST, and the daemon answers the `ECONNRESET` that
    /// follows by letting the connection go without decoding what its last `fill`
    /// had already buffered — so an `Input` frame written but not yet decoded is
    /// lost. Not to the kernel, which delivers every byte and reports the error only
    /// after the last of them, but to `Conn::fill` (`IMPLEMENTATION.md` § 3).
    /// Draining first turns the close into an orderly FIN, where `fill` reports end
    /// of file instead and those frames are decoded — so what happens to that input
    /// is the daemon's behaviour rather than a matter of timing.
    ///
    /// A silent socket ends this after [`SOCKET_POLL`], which is the read timeout
    /// every client here carries — there is nothing to shorten, because nothing waits
    /// long in the first place.
    pub(crate) fn drain_available(&mut self) {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = read_uninterrupted(&mut self.stream, &mut chunk) {
            if n == 0 {
                break;
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }

    /// Reads until the daemon has acknowledged input through `through`, tolerating
    /// whatever else arrives on the way.
    ///
    /// For tests that are about to disconnect on purpose: an `Input` frame that was
    /// written but not yet *decoded* is lost when the socket closes with output
    /// still queued — see [`Client::drain_available`] for where it actually goes —
    /// so waiting for the ack is what makes "the daemon has this" true.
    pub(crate) fn wait_for_input_ack(&mut self, through: u64) {
        let awaiting = format!("an InputAck through offset {through}");
        let deadline = Instant::now() + PATIENCE;
        loop {
            let (ty, payload) = self
                .frame_before(deadline, &awaiting)
                .unwrap_or_else(|| panic!("timed out waiting for {awaiting}"));
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
        self.read_until_inner(needle, from, false)
    }

    /// Collects the child's output until `needle` appears, following the ring over any
    /// overflow it hits on the way.
    ///
    /// [`Client::read_until`] refuses a `Gap`, which is right everywhere else in this
    /// suite: an unannounced discontinuity is most of what these tests exist to catch.
    /// It is wrong for the two callers that have deliberately sized the ring below what
    /// the child is producing — a kilobyte against tens of kilobytes of echoed filler,
    /// and 32 against the 64 KiB the daemon takes off the PTY in one pass. There
    /// overflow *while attached* is the ordinary case rather than a surprise, § 9
    /// obliges the daemon to announce it, and refusing the announcement would fail the
    /// test for the behaviour it was written to demand. Waiting for the child to fall
    /// quiet first is exactly the sleep this was written to be rid of.
    ///
    /// What the caller is looking for survives it either way, because both needles are
    /// the newest bytes on the stream: the repaint keystroke and the fence behind it are
    /// the last few the child writes, `yes` writes nothing but the needle, and the
    /// newest kilobyte is the one thing the ring never discards. What is *not* relaxed
    /// is contiguity — output between gaps is still asserted to be unbroken, so the
    /// hole this tolerates is only ever one the daemon owned up to.
    pub(crate) fn read_past_gaps(&mut self, needle: &str, from: u64) -> (String, u64) {
        self.read_until_inner(needle, from, true)
    }

    /// The body of both, differing only in whether a `Gap` moves the stream on or
    /// fails the test.
    fn read_until_inner(&mut self, needle: &str, from: u64, follow_gaps: bool) -> (String, u64) {
        let mut seen = Vec::new();
        let mut offset = from;
        let awaiting = format!("{needle:?} in the session's output");
        let deadline = Instant::now() + PATIENCE;
        while let Some((ty, payload)) = self.frame_before(deadline, &awaiting) {
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(at, offset, "output offsets must be contiguous");
                    offset += data.len() as u64;
                    seen.extend_from_slice(data);
                    if String::from_utf8_lossy(&seen).contains(needle) {
                        return (String::from_utf8_lossy(&seen).into_owned(), offset);
                    }
                }
                Frame::Gap { new_base_offset } if follow_gaps => offset = new_base_offset,
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

/// Asserts that a frame the daemon sent is an `Error` carrying `code`.
///
/// Shared by the two ways of arriving at one, so that what a refusal has to satisfy
/// is written once and the entry points differ only in how strictly they read.
fn assert_refusal(ty: FrameType, payload: &[u8], code: ErrorCode, what: &str) {
    assert_eq!(
        ty,
        FrameType::Error,
        "{what}; the daemon answered with {ty:?} rather than a refusal"
    );
    match Frame::decode(ty, payload).expect("decode the refusal") {
        Frame::Error { code: got, message } => {
            assert_eq!(got, code, "{what}; the daemon said {message:?}");
        }
        other => panic!("{what}; got {other:?}"),
    }
}

/// Whether the kernel is holding bytes for `stream` that nothing has read yet.
///
/// `MSG_PEEK`, so asking does not consume them — which is the entire point at the
/// one call site. `UnixStream::peek` says this safely but is unstable on the pinned
/// toolchain, and adding rustix's `net` feature to reach `RecvFlags::PEEK` would be
/// a dependency change for a single test.
pub(crate) fn has_unread_bytes(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;

    let mut byte = 0u8;
    loop {
        // SAFETY: `recv` is given a valid one-byte buffer with the length that
        // matches it, on a descriptor the borrow above keeps open for the call.
        // `MSG_DONTWAIT` keeps it from blocking regardless of the socket's own
        // timeout.
        let peeked = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                std::ptr::from_mut(&mut byte).cast::<libc::c_void>(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        // `MSG_DONTWAIT` makes an interruption unlikely rather than impossible, and
        // the answer it would otherwise produce is the wrong one: "nothing queued" is
        // exactly what the caller is asking about, and it would report it of a socket
        // that has bytes waiting. Retried for the same reason as
        // [`read_uninterrupted`], which cannot be used here because peeking is the
        // whole point and `Read` has no way to ask for it.
        if peeked < 0 && std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
            continue;
        }
        return peeked > 0;
    }
}

/// Shrinks `socket`'s send buffer to `bytes`, so that a write larger than it cannot
/// complete in one go.
///
/// A unix socket splits a write into segments of half its send buffer and waits for
/// room for each in turn, so the size of that buffer is what decides whether a write
/// bigger than the space available comes back short or blocks with nothing
/// transferred. The default 208 KiB is larger than anything this suite writes in one
/// call, which makes every write all-or-nothing; a small one is what puts a
/// destination into the state § 7's relay has to survive.
///
/// Through `libc` because rustix's socket options live behind its `net` feature,
/// which this tree does not enable — the same reason [`has_unread_bytes`] is written
/// by hand.
pub(crate) fn shrink_send_buffer(socket: &UnixStream, bytes: libc::c_int) {
    use std::os::fd::AsRawFd;

    // SAFETY: `setsockopt` is given the address and length of a `c_int` that
    // outlives the call, on a descriptor the borrow keeps open for it.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::from_ref(&bytes).cast::<libc::c_void>(),
            u32::try_from(size_of::<libc::c_int>()).expect("the size of a c_int"),
        )
    };
    assert_eq!(
        set,
        0,
        "shrinking the send buffer failed: {}",
        std::io::Error::last_os_error()
    );
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
///
/// The one call here that needs nothing added for [`read_uninterrupted`]'s sake:
/// `write_all` already treats `Interrupted` as "go round again", so a signal costs it
/// a loop iteration rather than a frame.
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
        match write_uninterrupted(socket, &bytes[sent..]) {
            Ok(0) => break,
            Ok(n) => {
                sent += n;
                progressed = Instant::now();
            }
            // A fiftieth of the patience: short enough that what ends the loop is
            // the deadline rather than the sleep it overshot by, long enough not to
            // spin on a socket that is going to stay full.
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
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
        Self(Some(launch(command).expect("spawn a child")))
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

/// Kills a pid when it goes out of scope.
///
/// The processes these tests background are backgrounded *on purpose*, so nothing
/// else reaps them: a `sleep 300` left behind by a failing assertion is still there
/// when the next run starts, and the failure it caused is now accompanied by one it
/// did not. Read-then-kill-then-assert says the same thing where the ordering is
/// simple enough to arrange; this covers the case where it is not, and it fires on a
/// panic from anywhere in between.
pub(crate) struct Reaper(pub(crate) u32);

impl Drop for Reaper {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.cast_signed()) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
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
