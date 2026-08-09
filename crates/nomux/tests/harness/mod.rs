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

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use nomux_protocol::{
    ErrorCode, Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, RESUME_FROM_START,
    SERVER_PREAMBLE, WinSize, decode_header,
};

pub(crate) const WIN: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

/// How long a test waits for what a daemon owes it, whether that is one frame or a
/// sequence of them.
///
/// Spent once per [`Client`] rather than renewed per wait, for [`poll_by`]'s reason; a
/// test whose waits legitimately outlast it says so with [`Client::waits_by`], and one
/// that makes a client per round asks for them with [`Session::connect_by`] so that all
/// the rounds share the one budget. One value rather than one per site, since every wait
/// here is on a daemon that is either about to answer or never going to.
pub(crate) const FRAME_PATIENCE: Duration = Duration::from_secs(15);

/// How long a test waits for something outside the protocol — a file appearing, a
/// `/proc` state, a process going away — to catch up.
pub(crate) const SETTLE: Duration = Duration::from_secs(10);

/// How long a socket read blocks before the caller's own deadline is looked at
/// again.
///
/// Deliberately far below [`FRAME_PATIENCE`], so the logical deadline is the one that
/// always fires: it is the only one that knows what the wait was about, where a
/// socket that gave up first could only report an errno.
const SOCKET_POLL: Duration = Duration::from_millis(100);

/// How long [`poll_until`] waits between attempts.
///
/// Short enough not to add meaningfully to what is being waited for, long enough
/// that a condition which shells out to `nomux list` is not run back to back.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// `daemon::MAX_PENDING_INPUT`: what § 4.1 lets a session queue for a child that is
/// not reading. Private to the daemon, mirrored here, and the two must move together.
pub(crate) const MAX_PENDING_INPUT: u64 = 1 << 20;

/// `conn::MAX_PENDING_WRITE`: what § 4.1 lets a client fall behind by before the daemon
/// stops queueing output for it. Private to the daemon, mirrored here, and the two must
/// move together.
pub(crate) const MAX_PENDING_WRITE: usize = 1 << 20;

/// `conn::ABANDON_PENDING_WRITE`: the queue § 4.1 lets a client reach before it counts
/// as gone rather than slow. Private to the daemon, mirrored here, and the two must
/// move together.
pub(crate) const ABANDON_PENDING_WRITE: usize = 8 << 20;

/// Waits up to `within` for `condition` to hold, and reports whether it ever did.
pub(crate) fn poll_until(within: Duration, condition: impl FnMut() -> bool) -> bool {
    poll_by(Instant::now() + within, condition)
}

/// [`poll_until`] against a deadline the caller shares between several waits.
///
/// One deadline per test rather than one bound per wait, and the canonical statement
/// of why. A test that waits for two things one after another with a bound each is
/// bounded by their *sum*, which can outlast the runner's kill and then have nothing
/// to point at (`.config/nextest.toml`); a bound renewed per frame or per round is
/// worse still, being satisfied by every arrival — a peer dribbling one frame just
/// inside it is never late, and the loop around it has no bound at all. Everything in
/// this suite that takes an `Instant` where a `Duration` would have done —
/// [`join_before`], [`Client::frame_before`], [`Client::waits_by`], and the `PATIENCE`
/// constants the test binaries define — is here for this reason and says no more about
/// it.
pub(crate) fn poll_by(deadline: Instant, mut condition: impl FnMut() -> bool) -> bool {
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

/// Joins `handle` against a deadline the caller shares between several waits,
/// failing rather than parking if it will not come back.
///
/// `JoinHandle::join` has no deadline, so a relay that stalls in either direction
/// hangs the whole run rather than failing it. The deadline is the caller's rather
/// than a bound per join for [`poll_by`]'s reason.
pub(crate) fn join_before<T>(handle: thread::JoinHandle<T>, deadline: Instant, what: &str) -> T {
    let remaining = deadline.saturating_duration_since(Instant::now());
    assert!(
        poll_until(remaining, || handle.is_finished()),
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
/// [`read_uninterrupted`] in the other direction: the only caller measures how much the
/// daemon will accept before it stops, and an interruption counted as a refusal
/// understates that in the direction that makes the assertion pass. A call a signal
/// reaches after it has transferred anything reports the short count instead, so
/// nothing here can put a byte on the wire twice.
fn write_uninterrupted(socket: &mut UnixStream, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        match socket.write(buf) {
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            outcome => return outcome,
        }
    }
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
    /// Appended to every failure raised by a [`Client`] of this session.
    ///
    /// For what only the test knows and no harness failure could otherwise say — the
    /// seed a randomised test promises to print with each one (`IMPLEMENTATION.md`
    /// § 9). Held by the session rather than set on each client, because the clients a
    /// chaos test fails in are the ones it did not write down: the reconnect inside
    /// [`reconnect_until_gap`], the fresh one per round. One setting covers all of them.
    context: String,
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
        Self::start_with(name, &ring_bytes.to_string(), "/bin/sh")
    }

    /// Starts a daemon in `cwd` and with **no** `HOME`, so the child falls back to the
    /// directory the daemon was started in (`pty::child_dir`).
    ///
    /// The one shape that can see § 6.2's ordering. Every other session here is given a
    /// `HOME`, which `child_dir` prefers — so the fallback is never consulted and a
    /// daemon that captured its directory *after* moving to `/` would look identical.
    pub(crate) fn start_homeless_in(name: &str, cwd: &Path) -> Self {
        let root = run_root(name);
        let id = intern(name);
        let child = launch(
            nomux_with_shell(&root, &["daemon", &id])
                .env("PS1", "")
                .env_remove("HOME")
                .current_dir(cwd)
                .env("NOMUX_RING_BYTES", DEFAULT_TEST_RING.to_string())
                .env_remove("SSH_AUTH_SOCK")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .expect("spawn daemon");

        let socket = root.join("nomux/run").join(format!("{id}.sock"));
        wait_until_answering(&socket);
        Self {
            child,
            root,
            socket,
            id,
            name: name.to_owned(),
            context: String::new(),
        }
    }

    /// The body every daemon in this suite goes through, so what each of them is told
    /// is said once. `ring_bytes` reaches `NOMUX_RING_BYTES` verbatim, for the one test
    /// about a value the daemon cannot parse (`IMPLEMENTATION.md` § 4), and `shell`
    /// reaches `SHELL` however unusable, for the one test about a session that cannot
    /// be created.
    pub(crate) fn start_with(name: &str, ring_bytes: &str, shell: &str) -> Self {
        let root = run_root(name);
        let id = intern(name);
        let child = launch(
            nomux_with_shell(&root, &["daemon", &id])
                .env("SHELL", shell)
                .env("PS1", "")
                // The child's working directory, so `pwd` is assertable.
                .env("HOME", &root)
                .env("NOMUX_RING_BYTES", ring_bytes)
                // § 6.7 has the daemon overwrite this and § 5.1 has it change nothing
                // else, so a developer's own agent reaches the child untouched on
                // every session whose forwarding is off or failed — and a test asking
                // what the child was pointed at would be reading the host.
                .env_remove("SSH_AUTH_SOCK")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .expect("spawn daemon");

        let socket = root.join("nomux/run").join(format!("{id}.sock"));
        wait_until_answering(&socket);
        Self {
            child,
            root,
            socket,
            id,
            name: name.to_owned(),
            context: String::new(),
        }
    }

    /// Appends `context` to every failure any client of this session raises.
    ///
    /// See [`Session::context`]. Written to read as part of the construction:
    /// `Session::start(..).in_context(format!(" (seed {seed})"))`.
    #[must_use]
    pub(crate) fn in_context(mut self, context: String) -> Self {
        self.context = context;
        self
    }

    pub(crate) fn connect(&self) -> Client {
        // Named rather than `expect`ed, and never retried. `Session::start` waits
        // until the daemon answers rather than until it has made the name, so a
        // refusal here is a daemon that has stopped answering since — which is a
        // failure whatever else the test was about, and this is where a test that
        // starts a session per case learns which of them it was.
        let stream = UnixStream::connect(&self.socket).unwrap_or_else(|err| {
            panic!("connect to session {:?}: {err}{}", self.name, self.context)
        });
        stream
            .set_read_timeout(Some(SOCKET_POLL))
            .expect("set read timeout");
        Client {
            stream,
            pending: Vec::new(),
            preamble_seen: false,
            in_offset: 0,
            out_offset: 0,
            deadline: Instant::now() + FRAME_PATIENCE,
            context: self.context.clone(),
        }
    }

    /// [`Session::connect`] against a deadline the caller already holds.
    ///
    /// [`Session::connect`] mints a [`FRAME_PATIENCE`] of its own, which is what a client
    /// made once per test wants: the budget is that connection's and nothing else is
    /// spending it. A loop that reconnects is the case [`poll_by`] is written against — a
    /// client per round renews a budget meant to be spent once, so what bounds the test is
    /// [`FRAME_PATIENCE`] times the rounds rather than [`FRAME_PATIENCE`], and past
    /// `.config/nextest.toml`'s kill there is no wait left to name. This is the same
    /// connection carrying the caller's deadline instead, so a test of many rounds spends
    /// one budget across all of them.
    ///
    /// A second constructor rather than an argument on [`Session::connect`], because
    /// sharing is the exception: the two dozen clients in this suite that are the only one
    /// in their test have nothing to share with, and `connect(Instant::now() +
    /// FRAME_PATIENCE)` at each of them would say only what the default already says — and
    /// would let a loop mint a fresh budget while looking deliberate. It is the pairing the
    /// rest of the harness has, [`poll_until`] beside [`poll_by`] and
    /// [`Client::frame_owed`] beside [`Client::frame_before`], where the sibling taking an
    /// `Instant` is the one for a caller that is bounding several waits at once.
    pub(crate) fn connect_by(&self, deadline: Instant) -> Client {
        let mut client = self.connect();
        client.waits_by(deadline);
        client
    }

    /// A daemon with one client attached to it, greeted from the start of both
    /// streams: how most of the suite opens.
    ///
    /// The [`Session`] comes back alongside the client because it owns the daemon and
    /// kills it on drop, so the caller has to bind it for as long as the client is
    /// used — `let (_session, ..)`, never `let (_, ..)`, which would end the session
    /// on the spot.
    pub(crate) fn attached(name: &str) -> (Self, Client, nomux_protocol::HelloOk) {
        Self::attached_with(name, false, false)
    }

    /// [`Session::attached`], with `agent_forward` and `repaint_ctrl_l` asked for in
    /// that order — the order they sit in on the wire, and in [`Client::hello_with`].
    pub(crate) fn attached_with(
        name: &str,
        agent_forward: bool,
        repaint_ctrl_l: bool,
    ) -> (Self, Client, nomux_protocol::HelloOk) {
        let session = Self::start(name);
        let mut client = session.connect();
        let ok = client.hello_with(agent_forward, repaint_ctrl_l, RESUME_FROM_START);
        (session, client, ok)
    }

    /// The directory the daemon publishes its five files in.
    fn run_dir(&self) -> PathBuf {
        self.root.join("nomux/run")
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
            .set_read_timeout(Some(FRAME_PATIENCE))
            .expect("set read timeout");
        stream
    }
}

/// A FIFO named `cue` in a session's run root, which the child blocks on until the
/// test lets it through.
///
/// The child's line is `read cue < cue; <what the test is about>`: the whole line is
/// parsed before any of it runs, so past the [`Client::make_ready`] marker the child
/// never touches its terminal until [`Cue::release`]. That is what lets a test compose
/// a state around a child instead of waiting for one to happen.
pub(crate) struct Cue(PathBuf);

impl Cue {
    pub(crate) fn new(root: &Path) -> Self {
        let path = root.join("cue");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .expect("create the FIFO the child waits on");
        Self(path)
    }

    /// Lets the child on.
    ///
    /// Opened without blocking, so a child that never reached its own `open` fails
    /// here rather than parking the test: a FIFO answers `ENXIO` until a reader is
    /// there, and the child counts as one from the moment it enters the wait.
    pub(crate) fn release(self) {
        use std::os::unix::fs::OpenOptionsExt;

        let mut go = None;
        assert!(
            poll_until(FRAME_PATIENCE, || {
                go = fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&self.0)
                    .ok();
                go.is_some()
            }),
            "the child never reached the cue it waits on"
        );
        go.expect("the FIFO the wait above opened")
            .write_all(b"go\n")
            .expect("cue the child");
    }
}

/// Reconnects until the daemon reports a gap, and hands back the greeting that did.
///
/// Whether the ring has overflowed *yet* is a question about when the daemon was last
/// scheduled rather than about the property under test, so a sleep followed by an
/// assertion on `gap` really asserts that the machine got round to it. Reconnecting
/// until the daemon itself says so turns that into a wait on the thing being waited
/// for.
///
/// `deadline` is the caller's, spent here rather than renewed ([`Session::connect_by`]):
/// a fresh [`Client`] per round would otherwise mint a fresh frame budget every time
/// round, which is the case [`poll_by`] is written against.
///
/// Only the repaint flag, since every greeting here resumes a session that is already
/// there and `agent_forward` is honoured on the one that creates it.
pub(crate) fn reconnect_until_gap(
    session: &Session,
    deadline: Instant,
    repaint_ctrl_l: bool,
    out_offset: u64,
) -> (Client, nomux_protocol::HelloOk) {
    loop {
        let mut client = session.connect_by(deadline);
        let resumed = client.hello_with(false, repaint_ctrl_l, out_offset);
        if resumed.gap(out_offset) {
            return (client, resumed);
        }
        drop(client);
        assert!(
            Instant::now() < deadline,
            "the ring never overflowed while detached: base={} in_applied={} \
             (resuming from {out_offset}){}",
            resumed.resume_from,
            resumed.in_applied,
            session.context
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
    /// Room a run root must leave for the session id inside it. Not
    /// `rundir::MAX_SESSION_ID_LEN`, which is 64: no test mints an id near that, and
    /// demanding the protocol's maximum would refuse working directories. Double the
    /// longest id the suite actually uses, which leaves the check about the environment
    /// rather than about the names.
    const ID_HEADROOM: usize = 32;

    let base = integration_tmpdir();
    sweep_finished_runs(&base);
    let owned = format!("{}-{}", intern(name), std::process::id());
    let root = base.join(owned);
    // A pid is reused eventually, and a run that crashed hard leaves its directory
    // behind, so the wipe stays even though the name is this process's own.
    drop(fs::remove_dir_all(&root));
    fs::create_dir_all(&root).expect("create run root");
    // Checked here rather than at the bind, because the bind's failure is 10 s of a
    // daemon that never answers, repeated once per session test — fifty timeouts none of
    // which names the cause. `sun_path` is 108 bytes with room for the NUL, and the
    // longest name a session can put under this root is a maximum-length id plus the
    // longest extension the run directory uses.
    // `<root>/nomux/run/<id>.agent` is the longest name a session puts here.
    let fixed = root.join("nomux/run").join(".agent").as_os_str().len();
    assert!(
        fixed + ID_HEADROOM <= 107,
        "this run root leaves {} bytes for a session id, and the suite needs {ID_HEADROOM}: \
         {}\nset a shorter CARGO_TARGET_DIR — `sockaddr_un` carries 107, and past it every \
         session test fails alike on a daemon that never answers, for a reason that is the \
         environment rather than the change under test",
        107_usize.saturating_sub(fixed),
        root.display()
    );
    root
}

/// A short, owner-only base under the platform temporary directory.
///
/// Production refuses an unprotected writable ancestor. The checkout containing
/// `CARGO_TARGET_TMPDIR` may itself be group-writable, so using it would make every
/// integration test assert on the developer's directory policy rather than nomux. A
/// uid-named child of sticky `/tmp` is protected by the kernel and matches a valid runtime
/// fallback. An entry another uid planted first is refused, never followed or repaired.
fn integration_tmpdir() -> PathBuf {
    let us = rustix::process::getuid().as_raw();
    let base = env::temp_dir().join(format!("nomux-it-{us}"));
    match fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => panic!("create integration-test base {}: {err}", base.display()),
    }
    let metadata = fs::symlink_metadata(&base)
        .unwrap_or_else(|err| panic!("examine integration-test base {}: {err}", base.display()));
    assert!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == us
            && metadata.mode() & 0o022 == 0,
        "integration-test base {} is not an unshared real directory owned by uid {us}",
        base.display()
    );
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|err| panic!("secure integration-test base {}: {err}", base.display()));
    base
}

/// Removes the run directories of test processes that have exited.
///
/// The pid in the name is what lets two runs proceed at once, and it is equally
/// what stops a run from reusing what the last one left: without this,
/// the integration-test base would grow by a directory per test per run, for ever. A
/// directory goes only once `/proc` says its process is gone — a live pid is either
/// this one or a run in flight, and taking either away is the exact fault the naming
/// exists to prevent.
fn sweep_finished_runs(base: &Path) {
    let Ok(entries) = fs::read_dir(base) else {
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
/// needs a descriptor of its own to be closed *process-wide* — for `cargo test`, which
/// `README.md` tells contributors to run and which puts every test in one process, where
/// another test's `fork` would otherwise duplicate that descriptor and keep it open.
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
/// The run-directory environment is the whole of what the control surface is told
/// (§ 6.6), and nothing else is added here: that is a claim about the surface rather
/// than a convenience.
pub(crate) fn nomux(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nomux"));
    // Production prefers persistent state (§ 6.3), and the general integration path
    // exercises that choice. Pinning it explicitly keeps an inherited developer HOME out
    // of the result; a test may still set HOME for the shell without moving the socket.
    command
        .args(args)
        .env("XDG_STATE_HOME", root)
        .env("XDG_RUNTIME_DIR", root);
    command
}

/// Makes what `command` starts a process-group leader, so `setsid` answers `EPERM`
/// and § 6.2's detachment has to fork.
///
/// `Command` never calls `setpgid`, so a daemon it starts is not a leader and the
/// fork is unreachable: a test that skipped this would pass against the ordering it
/// exists to catch. It is also the shape a shell with job control produces.
pub(crate) fn leads_a_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: the closure runs in the forked child before exec, so it must be
    // async-signal-safe. `setpgid` is, and nothing here allocates or takes a lock.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

/// [`nomux`] with a `SHELL` the developer's login environment cannot vary.
///
/// For every invocation that could put a shell behind a PTY — including the ones where
/// doing so would *be* the failure, since a refusal that regressed should leave a
/// predictable `/bin/sh` to be found rather than whatever the developer logs in with.
/// What is left on [`nomux`] alone could not start a shell under any regression.
pub(crate) fn nomux_with_shell(root: &Path, args: &[&str]) -> Command {
    let mut command = nomux(root, args);
    command.env("SHELL", "/bin/sh");
    command
}

/// Runs `nomux` against the run directory under `root`, and waits for it to finish.
///
/// `list` and `kill` reach a session only through the files on disk (§ 6.6), so
/// pointing `XDG_STATE_HOME` at the right place is the whole of what they need to
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

/// [`control`] with [`nomux_with_shell`]'s pinned `SHELL`.
///
/// For invocations that could put a shell behind a PTY and still return: a refusal
/// whose regression would be a session starting, which should then at least start a
/// predictable `/bin/sh`, and a `spawn` whose relay ends with the closed stdin —
/// where [`control`] itself is for modes that never reach a shell at all.
pub(crate) fn control_with_shell(root: &Path, args: &[&str]) -> Output {
    collect(
        nomux_with_shell(root, args)
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

/// [`collect`] against a deadline the caller shares between several runs, handing back
/// `None` for a process that never came back — and killing it on the way out.
///
/// For the modes whose defect *is* a wait with no end: a plain `wait` there hangs the
/// run instead of failing it, and the runner's own kill (`.config/nextest.toml`) reports
/// a slow test rather than which call never returned. The deadline is the caller's per
/// [`poll_by`], and the stdio is set here because every caller wants the same three.
pub(crate) fn collect_by(command: &mut Command, deadline: Instant) -> Option<Output> {
    let mut running = Spawned::spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    poll_by(deadline, || !running.is_running()).then(|| {
        running
            .into_exited()
            .wait_with_output()
            .expect("collect what the process said")
    })
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
/// Not for a socket a caller then means to *connect* to — see [`wait_until_answering`],
/// which is a different question.
pub(crate) fn wait_for(path: &Path) {
    assert!(
        poll_until(SETTLE, || path.exists()),
        "the daemon never created {}",
        path.display()
    );
}

/// Waits for the daemon `id` published a pidfile under `root` for, and hands back
/// its pid alongside a guard that collects it however the test ends.
///
/// For tests that bring a session up through `nomux spawn` or `nomux daemon` rather
/// than through [`Session`], which kills its own child on drop. Such a daemon has
/// `setsid`ed away, so killing the relay does not reach it and no [`Spawned`] covers
/// it: an assertion firing before the explicit `nomux kill` would leave it holding its
/// run directory for the whole first-attach timeout, while the *next* run's
/// [`sweep_finished_runs`] deletes that directory out from under it.
pub(crate) fn daemon_reaper(root: &Path, id: &str) -> (u32, Reaper) {
    let pid_file = root.join("nomux/run").join(format!("{id}.pid"));
    wait_for(&pid_file);
    let pid: u32 = fs::read_to_string(&pid_file)
        .expect("read the pidfile")
        .trim()
        .parse()
        .expect("the pidfile holds a pid");
    (pid, Reaper(pid))
}

/// Everything `/proc/<pid>/stat` holds after the parenthesised command name, or
/// `None` once the process is gone.
///
/// Read from after that name, because counting fields from the front stops working
/// the moment a command name contains a space or a bracket — and `sh` starting
/// `a b )` is enough. What is left begins with the single-letter run state, and the
/// fields [`StatField`] numbers follow it — so [`process_state`] and [`stat_field`]
/// are one parse asked two questions rather than two copies of the rule above.
fn stat_after_command(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')').map(|(_, tail)| tail.to_owned())
}

/// The single-letter run state `/proc` reports for `pid`, or `None` once it is gone.
pub(crate) fn process_state(pid: u32) -> Option<char> {
    stat_after_command(pid)?.trim_start().chars().next()
}

/// A numeric field of `/proc/<pid>/stat`, by what it means.
///
/// Numbered from the run state that follows the command name, which is where
/// [`stat_after_command`] leaves off.
#[derive(Clone, Copy)]
pub(crate) enum StatField {
    /// The process group the process belongs to.
    ProcessGroup = 2,
    /// The session it belongs to, which is its own pid exactly when it leads one.
    Session = 3,
    /// Clock ticks spent in user mode.
    UserTime = 11,
    /// Clock ticks spent in the kernel on this process's own behalf.
    SystemTime = 12,
}

/// Reads one field of `/proc/<pid>/stat`.
pub(crate) fn stat_field(pid: u32, field: StatField) -> Option<u32> {
    stat_after_command(pid)?
        .split_whitespace()
        .nth(field as usize)?
        .parse()
        .ok()
}

/// How long a spin is measured over.
///
/// Half a second rather than the 300 ms one caller used, because no figure can be
/// quoted for a spin — it is whatever share of a core the scheduler hands the daemon,
/// and three measurements of it spread from the twenties to the forties. What a
/// threshold rests on is the other answer, which is not a share of anything: a daemon
/// that is asleep measures zero, and no amount of load moves zero.
pub(crate) const SPIN_WINDOW: Duration = Duration::from_millis(500);

/// How much processor time `daemon` is charged over [`SPIN_WINDOW`], in the clock
/// ticks `/proc` counts in.
///
/// A wall-clock interval rather than a wait for a condition, since it *is* the
/// measurement. User and system together, because the two states this has to tell
/// apart are "asleep in `poll`" and "going round the loop as fast as the scheduler
/// allows", and the second spends its time on both sides of the syscall boundary. A
/// process that has gone reports nothing, which reads here as zero — the answer the
/// caller's assertion wants, and one no live daemon can produce falsely, since these
/// counters never go down.
pub(crate) fn cpu_ticks(daemon: u32) -> u64 {
    let charged = || -> u64 {
        [StatField::UserTime, StatField::SystemTime]
            .into_iter()
            .filter_map(|field| stat_field(daemon, field))
            .map(u64::from)
            .sum()
    };
    let began = charged();
    thread::sleep(SPIN_WINDOW);
    charged().saturating_sub(began)
}

/// Whether `pid` is still a process rather than gone or a zombie nobody has
/// collected.
///
/// A zombie counts as gone because it has already run its `exit`, which is the whole
/// of what a `kill` has to establish — and it is a state a test cannot rule out by
/// waiting: a daemon that `setsid`ed away is reaped by init rather than by anything
/// in this process, and inside a container that may be a pid 1 that never calls
/// `wait`. A collected process group reaches one of those two states promptly.
pub(crate) fn process_alive(pid: u32) -> bool {
    process_state(pid).is_some_and(|state| state != 'Z')
}

/// Waits for a daemon to be *answering* on `path`, rather than merely to have made
/// the name.
///
/// A unix socket enters the filesystem at `bind` and starts answering at `listen`, and
/// those are two syscalls: in between, the path exists and every `connect` is refused,
/// so [`wait_for`] on a socket is satisfied one step early.
///
/// The connection costs the session nothing: § 6.4 has the daemon promote a connection
/// on its `Hello` and never on the `connect`, so this is not an attach and does not
/// stop the clock an attach stops.
fn wait_until_answering(path: &Path) {
    let answered = poll_until(SETTLE, || UnixStream::connect(path).is_ok());
    assert!(answered, "the daemon never answered on {}", path.display());
}

/// What the run directory holds, sorted, or nothing where there is no run directory.
///
/// Both readings are the same answer to the same question — which of a session's five
/// files exist — so the absent directory is folded in here rather than at the call
/// sites, where it would read as a case to handle rather than as an empty set.
pub(crate) fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort_unstable();
    names
}

/// Binds `path` and makes every later `connect` to it wait rather than be answered.
///
/// What a daemon whose event loop has stopped calling `accept` looks like from
/// outside, and the only way to produce it: a backlog of zero still takes one
/// connection — the kernel refuses at *more* than the backlog, not at it — so one
/// queued `connect` is the whole wedge, and every one after it waits for an `accept`
/// that is never coming.
///
/// Both ends are handed back because both are load-bearing: closing the listener
/// refuses the queue instead of holding it, and closing the queued connection empties
/// the backlog again.
pub(crate) fn wedge_socket(path: &Path) -> (UnixListener, UnixStream) {
    use std::os::fd::AsRawFd;

    let listener = UnixListener::bind(path).expect("plant a listening socket");
    // SAFETY: `listen` is passed a descriptor the borrow above keeps open across the
    // call, and a backlog. `UnixListener` has no safe spelling of a second `listen` —
    // `bind` chose the backlog and nothing revisits it — and rustix's would mean
    // adding its `net` feature to the whole crate for one line of one test.
    let shrunk = unsafe { libc::listen(listener.as_raw_fd(), 0) };
    assert_eq!(
        shrunk,
        0,
        "shrink the backlog: {}",
        std::io::Error::last_os_error()
    );
    let queued = UnixStream::connect(path).expect("fill the backlog");
    (listener, queued)
}

/// The spawn lock at `<id>.lock`, held until the guard is dropped, and released as a
/// property of the open file description rather than by closing a descriptor.
///
/// `fork` duplicates the descriptor into every other test's children ([`FORKS`]), and
/// `flock(2)` holds the lock until *all* of those duplicates are closed — but releases it
/// on an explicit `LOCK_UN` through any one of them, because they share one open file
/// description. So this is the same shape as the `shutdown` that abandons a listening
/// socket: the release is a property of the object rather than of a descriptor, and no
/// stray copy can undo it.
pub(crate) struct HeldLock(fs::File);

impl HeldLock {
    /// Takes the lock at `path` the way `spawn` takes it (§ 6.3), creating the file if
    /// nothing is there — which is what `rundir::try_lock_spawn` does, and what makes
    /// the inode this hands back the one another process will queue behind.
    pub(crate) fn take(path: &Path) -> Self {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open the spawn lock");
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("take the spawn lock");
        Self(file)
    }

    /// What was locked, for a caller naming its `dev:ino` to [`wait_until_flock`] — the
    /// file this guard holds rather than whatever is at the path by then, which is the
    /// whole distinction one of those callers is about.
    pub(crate) fn metadata(&self) -> std::io::Result<fs::Metadata> {
        self.0.metadata()
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

/// Which of the two states `/proc/locks` reports an `flock` request in.
#[derive(Clone, Copy)]
pub(crate) enum Flock {
    /// Still queued behind somebody else's lock on the same file.
    Queued,
    /// Granted, and held until whoever took it lets go.
    Granted,
}

/// Waits until an `flock` on `dev:ino` is in `state`, or says what never happened.
///
/// Every caller is trying to catch another process mid-operation, and without this each
/// would race the very thing it means to observe: `tests/lifecycle.rs`'s spawn test would
/// collect the lock before anything was waiting on it, and `tests/control.rs`'s `kill`
/// test would move the ground under `kill` before it had reached the region it is about.
/// None asserts anything then, and none says so — which is what makes a fixed sleep the
/// wrong tool for any of them. `/proc/locks` lists queued requests alongside granted ones,
/// so both are conditions to wait on.
///
/// The deadline is the caller's, per [`poll_by`].
pub(crate) fn wait_until_flock(state: Flock, dev: u64, ino: u64, what: &str, deadline: Instant) {
    let reached = poll_by(deadline, || {
        // A kernel without `/proc/locks` cannot be waited on, and the assertions
        // that follow would then pass without ever having reached the window they
        // are about. Failing loudly is the point: a guard that quietly stops
        // guarding is worse than one that is not there.
        let locks = fs::read_to_string("/proc/locks").unwrap_or_else(|err| {
            panic!(
                "/proc/locks is unreadable ({err}), so nothing here can tell \
                    whether {what}"
            )
        });
        locks.lines().any(|line| is_flock(line, state, dev, ino))
    });
    assert!(reached, "nothing ever showed that {what}, for inode {ino}");
}

/// Whether one `/proc/locks` line reports an `flock` on `dev:ino` in `state`:
///
/// ```text
/// 1:    FLOCK  ADVISORY  WRITE 3389 08:01:7746 0 EOF
/// 2: -> FLOCK  ADVISORY  WRITE 3390 08:01:7746 0 EOF
/// ```
///
/// The `->` is the whole of the difference between the two: it marks a request still
/// queued behind the lock above it, and a line without one is a lock somebody holds.
/// Neither that field nor the file's is recognised by position, since the columns
/// before them vary with the lock type.
fn is_flock(line: &str, state: Flock, dev: u64, ino: u64) -> bool {
    if line.contains("->") != matches!(state, Flock::Queued) {
        return false;
    }
    line.contains("FLOCK")
        && line
            .split_whitespace()
            .any(|field| names_the_file(field, dev, ino))
}

/// Whether a `/proc/locks` field is the `MAJOR:MINOR:INODE` of one file.
///
/// The kernel prints it as `%02x:%02x:%llu` — the device in hex, the inode in
/// decimal — and all three are checked. Inode numbers are unique only within a
/// filesystem, and the run root need not be on the same one as anything
/// else this process has open, so matching the inode alone would match a stranger's
/// lock on a stranger's file.
fn names_the_file(field: &str, dev: u64, ino: u64) -> bool {
    let mut parts = field.split(':');
    let (Some(major), Some(minor), Some(inode), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    u32::from_str_radix(major, 16) == Ok(libc::major(dev))
        && u32::from_str_radix(minor, 16) == Ok(libc::minor(dev))
        && inode.parse::<u64>() == Ok(ino)
}

/// A protocol client: enough of one to assert on daemon behaviour.
pub(crate) struct Client {
    stream: UnixStream,
    pending: Vec<u8>,
    /// Whether the one server-to-client synchronization sequence has been consumed.
    preamble_seen: bool,
    /// Where this client stands on each stream: one past the last byte it has sent,
    /// and one past the last it has read. Kept so that [`still_serving`] can ask the
    /// session a question without being handed the two offsets to ask it at.
    in_offset: u64,
    out_offset: u64,
    /// When everything this client is still owed must have arrived by.
    ///
    /// [`FRAME_PATIENCE`] from the moment it connected, spent across every wait it
    /// makes rather than minted per wait, for [`poll_by`]'s reason.
    deadline: Instant,
    /// [`Session::context`], appended to every failure this client raises.
    context: String,
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

/// What the shell is asked to say once the terminal is configured.
///
/// `printf` rather than `echo`, and with no newline behind the marker, so that the
/// marker is the *last* thing the setup line puts on the stream — which is what makes
/// [`Ready::offset`] one past the marker rather than one past whatever the daemon
/// read with it. See [`Client::make_ready`] for what a terminator behind it costs.
const READY_ECHO: &str = "printf \"NOMUX-$((6*7))-READY\"";

/// What [`READY_ECHO`] becomes once a shell has run it, and the canonical statement of
/// why every marker in this suite is arithmetic.
///
/// The line discipline echoes the command line itself before any shell reads it, and
/// that echo carries `$((6*7))` unexpanded — so `42` can only have come from a shell
/// that ran the line. A marker written out whole would be found in the echo of the
/// request for it, and the wait would be over before anything happened. Every other
/// `$((6*7))` in these tests is here for this reason and says no more about it.
const READY_MARKER: &str = "NOMUX-42-READY";

impl Client {
    /// Hands this client `deadline` in place of the [`FRAME_PATIENCE`] it connected
    /// with.
    ///
    /// For the test whose waits legitimately outlast that, and — through
    /// [`Session::connect_by`], which is this call and nothing else — for the loop that
    /// reconnects, where a client per round renews a budget meant to be spent once.
    pub(crate) const fn waits_by(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    pub(crate) fn send(&mut self, frame: &Frame<'_>) {
        write_frame(&mut self.stream, frame);
    }

    /// Writes bytes at the socket without going through the codec.
    ///
    /// For the frames the encoder cannot be made to produce: a header carrying a
    /// discriminant no [`FrameType`] has, and a payload too short for the type it
    /// declares. Both are what a peer from another release — or a confused one —
    /// would put on the wire, and the daemon has an answer for each that nothing
    /// else here asks it for.
    pub(crate) fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("write raw bytes");
    }

    /// Sends keystrokes at `offset`.
    ///
    /// The most-sent frame in the suite by a wide margin, and the only one whose
    /// struct literal outweighs its content.
    pub(crate) fn input(&mut self, offset: u64, data: &[u8]) {
        self.in_offset = self.in_offset.max(offset + data.len() as u64);
        self.send(&Frame::Input { offset, data });
    }

    pub(crate) fn hello(&mut self, out_offset: u64) -> nomux_protocol::HelloOk {
        self.hello_with(false, false, out_offset)
    }

    /// Greets only if the daemon has no attached client, for the lifecycle test of the
    /// third `Hello` flag. Unlike [`Client::hello`], this is deliberately not used by
    /// general setup: unconditional takeover remains the protocol default.
    pub(crate) fn hello_if_detached(&mut self, out_offset: u64) -> nomux_protocol::HelloOk {
        self.send(&Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            agent_forward: false,
            repaint_ctrl_l: false,
            if_detached: true,
            out_offset,
            win: WIN,
            term: "xterm-256color",
        }));
        let greeting = self.frame_owed("a conditional HelloOk from the daemon");
        self.take_hello_ok(greeting)
    }

    pub(crate) fn hello_with(
        &mut self,
        agent_forward: bool,
        repaint_ctrl_l: bool,
        out_offset: u64,
    ) -> nomux_protocol::HelloOk {
        self.send(&hello_frame(agent_forward, repaint_ctrl_l, out_offset));
        let greeting = self.frame_owed("a HelloOk from the daemon");
        self.take_hello_ok(greeting)
    }

    /// Decodes the greeting and moves this client's two offsets onto it.
    fn take_hello_ok(&mut self, (ty, payload): (FrameType, Vec<u8>)) -> nomux_protocol::HelloOk {
        assert_eq!(ty, FrameType::HelloOk, "expected HelloOk, got {ty:?}");
        match Frame::decode(ty, &payload).expect("decode HelloOk") {
            Frame::HelloOk(ok) => {
                self.in_offset = ok.in_applied;
                self.out_offset = ok.resume_from;
                ok
            }
            other => panic!("expected HelloOk, got {other:?}"),
        }
    }

    /// Puts the child's terminal into `mode`, waits for proof that it is already in
    /// effect, and leaves `then` running behind it.
    ///
    /// `stty <mode>`, then a marker, then whatever the test wants running — the shape
    /// every test that asserts on raw bytes needs first.
    ///
    /// `raw` in particular is what makes the line discipline apply back pressure
    /// rather than quietly dropping an overflow: in canonical mode a line longer than
    /// the buffer is discarded and the master never stops accepting, so a test about
    /// a write that cannot complete would measure nothing at all.
    ///
    /// The marker comes *after* the `stty` because that is what makes arriving at it
    /// proof the mode is in effect rather than merely reached: input sent while the
    /// line discipline was still canonical is discarded by it rather than delivered.
    /// It is built out of `$((6*7))` for [`READY_MARKER`]'s reason.
    ///
    /// Nothing may follow the marker on that line, which is why [`READY_ECHO`] is a
    /// `printf` with no newline in it. [`Ready::offset`] is one past the frame the
    /// marker completed in rather than one past the marker, so a terminator behind it
    /// is accounted for only when the daemon read it in the same pass — a race, since
    /// the master can be woken between the line and the `\r\n` that `onlcr` expands
    /// behind it. The two bytes left over are then dropped by the next
    /// [`Client::next_of`] as session chatter, and the read after that starts short
    /// and fails [`Client::read_until`]'s contiguity assertion.
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

    /// The next frame by this client's deadline, or the failure naming what was owed.
    ///
    /// Reachable from the test binaries so that a test waiting on frames this harness
    /// has no name for — `agent.rs` taking whichever of `AgentOpen` and `AgentClose`
    /// comes first — says what it is owed in its own words, per
    /// [`Client::next_of_awaiting`]'s reason.
    pub(crate) fn frame_owed(&mut self, awaiting: &str) -> (FrameType, Vec<u8>) {
        self.frame_before(self.deadline, awaiting)
            .unwrap_or_else(|| out_of_time(awaiting, &self.context))
    }

    /// The next frame, or `None` once `deadline` has passed without one.
    ///
    /// The deadline belongs to the caller rather than to this function, per
    /// [`poll_by`], so that a wait made of many frames — [`Client::read_until`] taking
    /// output until a needle appears — is bounded as a whole rather than per frame.
    /// Returning rather than panicking on the deadline leaves the failure to whoever
    /// knows what the wait was for, which is the only place that can also say what it
    /// saw instead. Everything that is *not* a timeout is fatal here and says
    /// `awaiting`, because none of it leaves the caller anything to add.
    ///
    /// Reachable from the test binaries for that same first reason: a test reading
    /// many frames wants one deadline, and this is where it gets it.
    pub(crate) fn frame_before(
        &mut self,
        deadline: Instant,
        awaiting: &str,
    ) -> Option<(FrameType, Vec<u8>)> {
        loop {
            if let Some(frame) = self.take_pending_frame() {
                return Some(frame);
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut chunk = [0u8; 8192];
            match read_uninterrupted(&mut self.stream, &mut chunk) {
                Ok(0) => panic!(
                    "the daemon closed the connection while awaiting {awaiting}{}",
                    self.context
                ),
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                // What a read timeout is reported as; the deadline above is the one
                // that ends this loop.
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => panic!(
                    "reading from the daemon while awaiting {awaiting}: {err}{}",
                    self.context
                ),
            }
        }
    }

    /// The next whole frame already in the receive buffer, if there is one.
    fn take_pending_frame(&mut self) -> Option<(FrameType, Vec<u8>)> {
        if !self.preamble_seen {
            let preamble = self.pending.get(..SERVER_PREAMBLE.len())?;
            assert_eq!(
                preamble, SERVER_PREAMBLE,
                "the daemon's first response must start with the synchronization preamble"
            );
            self.pending.drain(..SERVER_PREAMBLE.len());
            self.preamble_seen = true;
        }
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
        self.next_of_awaiting(want, &format!("a {want:?} frame"))
    }

    /// [`Client::next_of`] where the caller can say what the wait was *for*.
    ///
    /// A table-driven test runs the same wait once per row, so "timed out waiting
    /// for a Error frame" names neither the row nor the behaviour — and every row
    /// fails identically. The sentence belongs to whoever built the table.
    fn next_of_awaiting(&mut self, want: FrameType, awaiting: &str) -> Vec<u8> {
        loop {
            let (ty, payload) = self.frame_owed(awaiting);
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
        let (ty, payload) = self.frame_owed(&format!("a refusal ({what})"));
        assert_refusal(ty, &payload, code, None, what);
    }

    /// [`Client::expect_error`] for a connection the session is also writing output
    /// to, where the refusal is not the only thing that can be in flight.
    pub(crate) fn expect_error_among_output(&mut self, code: ErrorCode, what: &str) {
        self.expect_refusal_among_output(code, None, what);
    }

    /// [`Client::expect_error_among_output`] where the caller also knows a distinctive
    /// fragment of the daemon's own words for the refusal it is owed.
    ///
    /// [`ErrorCode`] is a small closed set, and `Protocol` is what seven separate sites
    /// in the daemon answer with — so a test asking for the code alone is satisfied by
    /// any of them, and cannot say which one answered. Where two of those sites are
    /// reachable from the *same* frame the message is the only thing that separates
    /// them: a second `Hello` has a refusal of its own precisely so that a connection
    /// which greeted perfectly well is not told `Hello` is a frame it may not send,
    /// and that arm and the catch-all behind it differ in nothing else. A fragment
    /// rather than the whole sentence, so a site that rewords itself around what it is
    /// still saying does not fail every row that named it.
    pub(crate) fn expect_error_saying(&mut self, code: ErrorCode, saying: &str, what: &str) {
        self.expect_refusal_among_output(code, Some(saying), what);
    }

    /// The body of both, differing only in whether the daemon's words are read too.
    fn expect_refusal_among_output(&mut self, code: ErrorCode, saying: Option<&str>, what: &str) {
        let payload = self.next_of_awaiting(FrameType::Error, &format!("a refusal ({what})"));
        assert_refusal(FrameType::Error, &payload, code, saying, what);
    }

    /// One past the last input byte this client has delivered.
    ///
    /// The daemon's `in_applied` is authoritative and comes back on every `HelloOk`,
    /// so what a test checks it against is the client's own count of what it sent —
    /// which is how "the refusal cost the session nothing" is asked as a number rather
    /// than as a session that still answers.
    pub(crate) const fn in_offset(&self) -> u64 {
        self.in_offset
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
                Err(err) => panic!("reading after {after}: {err}{}", self.context),
            }
            if Instant::now() >= self.deadline {
                out_of_time(
                    &format!("the daemon to close the connection after {after}"),
                    &self.context,
                );
            }
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
        self.send(&Frame::Ping);
        let stream = &self.stream;
        let queued = poll_by(self.deadline, || has_unread_bytes(stream));
        assert!(
            queued,
            "the daemon wrote nothing, so closing here would be an orderly FIN \
             rather than the reset this is about"
        );
    }

    /// Reads until the daemon has acknowledged input through `through`, tolerating
    /// whatever else arrives on the way.
    ///
    /// For tests that are about to disconnect on purpose: a socket closed with output
    /// still queued makes the kernel send RST, and the daemon answers the
    /// `ECONNRESET` by letting the connection go without decoding what `Conn::fill`
    /// had already buffered (`IMPLEMENTATION.md` § 3) — so an `Input` frame written
    /// but not yet decoded is lost. Waiting for the ack is what makes "the daemon has
    /// this" true.
    pub(crate) fn wait_for_input_ack(&mut self, through: u64) {
        let awaiting = format!("an InputAck through offset {through}");
        loop {
            let (ty, payload) = self.frame_owed(&awaiting);
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
    /// hole this tolerates is only ever one the daemon owned up to. Bytes collected
    /// before a gap are discarded: otherwise the end of one retained range and the
    /// beginning of the next could combine into a needle that never existed in the
    /// child's stream.
    pub(crate) fn read_past_gaps(&mut self, needle: &str, from: u64) -> (String, u64) {
        self.read_until_inner(needle, from, true)
    }

    /// The body of both, differing only in whether a `Gap` moves the stream on or
    /// fails the test.
    fn read_until_inner(&mut self, needle: &str, from: u64, follow_gaps: bool) -> (String, u64) {
        let context = self.context.clone();
        let mut seen = Vec::new();
        let mut offset = from;
        let awaiting = format!("{needle:?} in the session's output");
        while let Some((ty, payload)) = self.frame_before(self.deadline, &awaiting) {
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(at, offset, "output offsets must be contiguous{context}");
                    offset += data.len() as u64;
                    seen.extend_from_slice(data);
                    if String::from_utf8_lossy(&seen).contains(needle) {
                        self.out_offset = offset;
                        return (String::from_utf8_lossy(&seen).into_owned(), offset);
                    }
                }
                Frame::Gap { new_base_offset } if follow_gaps => {
                    assert!(
                        new_base_offset > offset,
                        "a Gap must move output forward: current offset {offset}, new base \
                         {new_base_offset}{context}"
                    );
                    offset = new_base_offset;
                    seen.clear();
                }
                Frame::InputAck { .. } | Frame::Pong => {}
                other => panic!("unexpected frame while awaiting {needle:?}: {other:?}{context}"),
            }
        }
        out_of_time(
            &format!(
                "{awaiting}, having seen {:?}",
                String::from_utf8_lossy(&seen)
            ),
            &context,
        );
    }
}

/// The failure every wait against a [`Client::deadline`] ends in.
///
/// One sentence for all of them, and the whole of what one deadline per client buys:
/// the wait still owed when it ran out names itself, where the runner's kill
/// (`.config/nextest.toml`) could only say the test was slow. *Shared*, because an
/// earlier wait may have spent most of it: what is named is the wait that did not
/// finish rather than necessarily the slow one.
///
/// `context` is [`Session::context`] — the seed, where a test set one.
fn out_of_time(awaiting: &str, context: &str) -> ! {
    panic!(
        "timed out waiting for {awaiting}; the deadline this client shares between its \
         waits is spent{context}"
    );
}

/// Asks the session for a marker no shell that failed to run the line could produce,
/// and waits for it. The arithmetic is the assertion — see [`READY_MARKER`].
pub(crate) fn still_serving(client: &mut Client, tag: &str) {
    client.input(
        client.in_offset,
        format!("echo {tag}-$((6*7))\n").as_bytes(),
    );
    client.read_until(&format!("{tag}-42"), client.out_offset);
}

/// Asserts that a frame the daemon sent is an `Error` carrying `code`, and — where the
/// caller named one — a fragment of the words that says which site produced it.
///
/// Shared by the three ways of arriving at one, so that what a refusal has to satisfy
/// is written once and the entry points differ only in how strictly they read.
fn assert_refusal(
    ty: FrameType,
    payload: &[u8],
    code: ErrorCode,
    saying: Option<&str>,
    what: &str,
) {
    assert_eq!(
        ty,
        FrameType::Error,
        "{what}; the daemon answered with {ty:?} rather than a refusal"
    );
    match Frame::decode(ty, payload).expect("decode the refusal") {
        Frame::Error { code: got, message } => {
            assert_eq!(got, code, "{what}; the daemon said {message:?}");
            if let Some(saying) = saying {
                assert!(
                    message.contains(saying),
                    "{what}; the daemon said {message:?}, which says nothing about \
                     {saying:?} — the right code from the wrong place in the daemon"
                );
            }
        }
        other => panic!("{what}; got {other:?}"),
    }
}

/// Fails saying which offset the stream stopped meaning what the child wrote there,
/// quoted from both sides: the number alone does not say which way the error went — a
/// stream that resumed too early repeats bytes the client has, one that resumed too
/// late is missing bytes it never will.
///
/// The one sentence every test that models the child's output fails with, so that the
/// two binaries which do it — `tests/session.rs` against a blob, `tests/chaos.rs`
/// against a full-screen transcript — say the same thing about the same fault rather
/// than each keeping a copy of the reasoning.
///
/// `sits_in` is whatever the caller alone can say about the byte the two part company
/// at, appended to the offset: the seed a randomised test promises to print with every
/// failure (`IMPLEMENTATION.md` § 9), and, where the model knows its own escape
/// sequences, which one the boundary fell inside. A closure because only the comparison
/// below knows the index there is anything to say about.
fn assert_same_stream(want: &[u8], got: &[u8], at: u64, sits_in: impl FnOnce(usize) -> String) {
    if want == got {
        return;
    }
    let diff = want
        .iter()
        .zip(got)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| want.len().min(got.len()));
    panic!(
        "the daemon labelled a byte with an offset that is not where the child wrote \
         it: at offset {}{}, the session sent\n  {}\nwhere the child wrote\n  {}\nThe \
         stream is contiguous and wrong, which is what an off-by-N ring base or a slice \
         resumed at the wrong byte looks like from a client",
        at + diff as u64,
        sits_in(diff),
        quote(got, diff),
        quote(want, diff),
    );
}

/// A window of `bytes` around `at`, with the control bytes spelled out.
///
/// Read back raw, a stream of escape sequences would put the terminal running the test
/// into the state the failure is about — alternate screen, scroll region and all — which
/// is a poor way to report one.
fn quote(bytes: &[u8], at: usize) -> String {
    let mut out = String::new();
    let window = bytes
        .get(at.saturating_sub(24)..(at + 24).min(bytes.len()))
        .unwrap_or_default();
    for byte in window {
        match byte {
            0x1b => out.push_str("<ESC>"),
            0x20..=0x7e => out.push(char::from(*byte)),
            other => drop(write!(out, "<{other:02x}>")),
        }
    }
    out
}

/// A byte stream the test knows in full — everything the child writes from
/// [`StreamModel::stream_start`] on — for checking the session's output against by
/// absolute offset.
///
/// The assertion the gap and boundary tests exist for, and the reason the model is
/// indexed by the offset the daemon labelled each byte with: contiguity checked
/// *relative to* the base the daemon reported cannot fail whatever it says. A base N
/// too low replays N bytes the client already has, one N too high drops N it never
/// will, and both produce a perfectly contiguous stream that corrupts the user's
/// scrollback. Only a model of the child's own output makes that falsifiable.
pub(crate) struct StreamModel<'a> {
    /// The whole of what the child writes: index `i` is stream offset
    /// `stream_start + i`.
    pub(crate) bytes: &'a [u8],
    /// Absolute output offset of `bytes[0]`.
    pub(crate) stream_start: u64,
    /// Appended to every failure, carrying what only the caller can say — the seed a
    /// randomised test promises to print with each one (`IMPLEMENTATION.md` § 9), or
    /// nothing.
    pub(crate) context: String,
}

/// What [`StreamModel::follow`] took from the stream.
pub(crate) struct StreamTaken {
    /// One past the last output byte taken.
    pub(crate) offset: u64,
    /// Every gap followed, as the offset the stream stood at and the base it resumed
    /// on.
    pub(crate) gaps: Vec<(u64, u64)>,
    /// The offset each `Output` frame opened at, for a caller asking where the
    /// daemon's own boundaries fell.
    pub(crate) frame_starts: Vec<u64>,
}

impl StreamModel<'_> {
    /// Takes output until the stream reaches `through` or `budget` bytes of it have
    /// been taken, whichever comes first, checking every byte against the byte its
    /// offset names and following any gap the daemon announces. A gap must move the
    /// stream forward and is recorded rather than judged: how many were owed, and at
    /// what base, is the caller's arithmetic.
    ///
    /// `deadline` is the caller's, per [`poll_by`]. `sits_in` is
    /// [`assert_same_stream`]'s, handed the index into [`StreamModel::bytes`] of the
    /// first differing byte.
    pub(crate) fn follow(
        &self,
        client: &mut Client,
        from: u64,
        through: u64,
        budget: usize,
        deadline: Instant,
        sits_in: impl Fn(usize) -> String,
    ) -> StreamTaken {
        let context = &self.context;
        let mut taken = StreamTaken {
            offset: from,
            gaps: Vec::new(),
            frame_starts: Vec::new(),
        };
        let mut spent = 0usize;
        let awaiting = format!("the {} bytes the child wrote{context}", self.bytes.len());
        while taken.offset < through && spent < budget {
            let (ty, payload) = client.frame_before(deadline, &awaiting).unwrap_or_else(|| {
                panic!(
                    "the session stopped {} bytes short of everything the child wrote, \
                     with the stream standing at {}{context}",
                    through - taken.offset,
                    taken.offset
                )
            });
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(
                        at,
                        taken.offset,
                        "output must join up unless a Gap said otherwise, and this \
                         frame opens {} bytes from where the stream stood{context}",
                        at.abs_diff(taken.offset)
                    );
                    let index = usize::try_from(at.saturating_sub(self.stream_start))
                        .expect("an offset within a stream this test wrote");
                    let want = self
                        .bytes
                        .get(index..index + data.len())
                        .unwrap_or_else(|| {
                            panic!(
                                "the daemon sent {} bytes at offset {at}, running {} past \
                             the end of everything the child ever wrote{context}",
                                data.len(),
                                index
                                    .saturating_add(data.len())
                                    .saturating_sub(self.bytes.len())
                            )
                        });
                    assert_same_stream(want, data, at, |diff| sits_in(index + diff));
                    taken.frame_starts.push(at);
                    taken.offset += data.len() as u64;
                    spent += data.len();
                }
                Frame::Gap { new_base_offset } => {
                    assert!(
                        new_base_offset > taken.offset,
                        "a Gap must name a base past what the client was sent: \
                         {new_base_offset} against {}{context}",
                        taken.offset
                    );
                    taken.gaps.push((taken.offset, new_base_offset));
                    taken.offset = new_base_offset;
                }
                Frame::InputAck { .. } | Frame::Pong => {}
                other => {
                    panic!("unexpected {other:?} while reading the session's output{context}")
                }
            }
        }
        taken
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

/// The greeting the tests send: the current protocol, [`WIN`], and a terminal type
/// the daemon has no opinion about.
///
/// One literal rather than four, since the three sites that write it straight at a
/// socket are exactly the ones that would be missed if it ever changed.
///
/// Two bools rather than the flags byte, all the way up through [`Client::hello_with`]
/// and [`Session::attached_with`]: nothing in the suite writes a bit, it builds a
/// [`Hello`] and lets `encode` emit the byte. What pins the bit *values* is the fixed
/// vector table in `tests/codec.rs`, which is why the wire constants need not be
/// exported at all.
pub(crate) const fn hello_frame(
    agent_forward: bool,
    repaint_ctrl_l: bool,
    out_offset: u64,
) -> Frame<'static> {
    Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        agent_forward,
        repaint_ctrl_l,
        if_detached: false,
        out_offset,
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

/// How much a unix socket on this host takes from a peer that has stopped reading.
///
/// Measured rather than assumed: the limit is the *sender's* send buffer, which is a
/// sysctl away from any number written down here, and both callers turn on sending
/// more than it. Asking a socketpair is asking the same kernel the same question —
/// nothing about the pair the daemon accepts is different.
pub(crate) fn socket_capacity() -> usize {
    let (mut probe, _other_end) = UnixStream::pair().expect("a socketpair to measure");
    probe.set_nonblocking(true).expect("stop blocking");
    push_until_refused(&mut probe, &vec![0u8; 8 << 20], Duration::from_millis(100))
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
    /// Zero is the one state xorshift cannot leave, and a seed can arrive from an
    /// environment variable, so that single value is mapped aside.
    ///
    /// Only that one. Forcing the low bit on instead made every even seed unreachable
    /// and every odd seed the answer to two of them — seeds 2 and 3 replaying the same
    /// run — which is a promise of reproducibility that quietly halves the space it is
    /// reproducing from. Every other seed is its own state, and xorshift is a bijection
    /// on the states, so distinct seeds give distinct streams.
    pub(crate) const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
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
