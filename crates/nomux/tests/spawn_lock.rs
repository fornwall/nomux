//! The frozen control surface against the run directory.
//!
//! `list` and `kill` reach a session only through the five files on disk
//! (`IMPLEMENTATION.md` § 6.6), so everything they can get wrong is here: the spawn
//! lock they must take before removing anything (§ 6.3), the order they remove it
//! in, what they do with a session that is alive, and the directory those files
//! live in. These tests drive the real binary, because most of that is only wrong
//! across process boundaries.
//!
//! Session ids are kept short on purpose: they carry unix sockets, and
//! `sockaddr_un` truncates the path at 108 bytes. The directory they sit in is
//! [`run_root`]'s business.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "the allow-*-in-tests settings in clippy.toml reach `#[test]` bodies \
              and `#[cfg(test)]` modules, not the helpers an integration test \
              crate shares between them"
)]

mod harness;

use std::env;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use nomux_proto::PROTOCOL_VERSION;

use harness::{
    Reaper, Spawned, collect, control, nomux, nomux_with_shell, poll_until, run_root, stderr,
    stdout, succeeded, wait_for,
};

/// A `list` that finds the spawn lock held leaves the whole entry alone, and
/// collects it on the next pass once the lock is free.
#[test]
fn a_held_spawn_lock_survives_a_concurrent_list() {
    let session = StaleSession::create("lk1");
    let lock = session.hold_lock();

    let listed = session.run(&["list"]);
    succeeded(&listed, "list failed");
    assert!(
        !stdout(&listed).contains(&session.id),
        "nothing is listening, so the session is not live: {:?}",
        stdout(&listed)
    );
    assert!(
        session.socket().exists(),
        "collection ran while the spawn lock was held"
    );
    assert_eq!(
        inode(&session.lock_path()),
        lock.metadata().expect("stat the held lock").ino(),
        "the lock file at the path must still be the one this test holds"
    );

    drop(lock);
    collected_within(&session, Duration::from_secs(10));
}

/// Runs `list` until the run directory is empty, or says so loudly.
///
/// Asserted over a window rather than on one pass, and not because collection is
/// unreliable: `list` gives the spawn lock up rather than waiting for it (§ 6.6), so
/// anything still holding it leaves the entry correctly alone for that pass. The lock
/// this test held is given up through the open file description rather than by
/// closing a descriptor (see [`HeldLock`]), so no `fork` duplicate can be what holds
/// it — the window stays because what § 6.6 promises is that an entry which stays
/// dead stays collectable, not that it is collected on any particular pass.
fn collected_within(session: &StaleSession, within: Duration) {
    let collected = poll_until(within, || {
        succeeded(&session.run(&["list"]), "list failed");
        entries(&session.dir).is_empty()
    });
    assert!(
        collected,
        "the entry was never collected once the lock was free: {:?}",
        entries(&session.dir)
    );
}

/// `kill` reports failure rather than success when the spawn lock keeps it from
/// establishing its postcondition.
///
/// The alternative — skipping the entry quietly — would have `nomux kill` exit 0
/// on a session that `nomux list` then reports as alive, and the exit status is
/// the only thing the caller has to go on.
#[test]
fn kill_refuses_to_leave_a_locked_session_behind() {
    let session = StaleSession::create("lk2");
    let lock = session.hold_lock();

    let killed = session.run(&["kill", "lk2"]);
    assert!(
        !killed.status.success(),
        "kill claimed success for a session it could not remove: {:?}",
        stderr(&killed)
    );
    assert!(
        session.socket().exists() && session.lock_path().exists(),
        "kill removed files while the spawn lock was held"
    );

    drop(lock);
    succeeded(
        &session.run(&["kill", "lk2"]),
        "kill failed with the lock free",
    );
    assert!(
        !session.socket().exists() && !session.lock_path().exists(),
        "kill must unlink the run files"
    );
}

/// An attach whose spawn lock is collected while it waits goes back for the file
/// that is now at the path.
///
/// This is the half of the fix that is not "take the lock first": `flock` attaches
/// to the inode, so an attach that was blocked on a lock file somebody unlinked
/// wakes up holding a lock nobody else can see. The next attach creates a fresh
/// file at the same path, locks that, and both spawn a daemon for one session.
///
/// The interleaving is forced rather than hoped for: the collection happens only
/// once `/proc/locks` shows something blocked on this test's lock.
#[test]
fn an_attach_re_takes_a_spawn_lock_that_was_collected() {
    let session = StaleSession::empty("lk3");
    let lock = session.hold_lock();
    let held = lock.metadata().expect("stat the held lock");
    let orphan = held.ino();
    // A second descriptor on the same file, carrying no lock of its own: an inode
    // number is reusable the moment its last reference goes, and the attach closes
    // the orphan before reopening the path. ext4 then hands the same number
    // straight back to the file created there, and the assertion below compares a
    // genuinely fresh file against a number it inherited — which is why this test
    // passes on tmpfs, where numbers are allocated monotonically, and fails on
    // ext4. Holding the inode open keeps its number out of circulation, so what
    // the assertion reports is the identity of the file rather than the
    // allocation policy of whichever filesystem the target directory sits on.
    let pinned = File::open(session.lock_path()).expect("pin the orphan inode");

    let _relay = Spawned::spawn(
        nomux_with_shell(&session.root, &["attach", &session.id])
            .env("NOMUX_RING_BYTES", "65536")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );

    wait_until_flock(
        Flock::Queued,
        held.dev(),
        orphan,
        "the attach waited for the spawn lock",
    );

    // Exactly what collection used to do to a lock in use.
    fs::remove_file(session.lock_path()).expect("unlink the lock");
    drop(lock);

    wait_for(&session.socket());
    // The daemon this attach spawned has `setsid`ed away, so killing the relay does
    // not reach it: without this it outlives the test by its whole 30-second
    // first-attach timeout, holding a run directory that the *next* run's sweep
    // deletes out from under it. Every other test here that brings a session up
    // collects it; this one is the exception, and a `Reaper` covers a failing
    // assertion below as well as a passing one.
    wait_for(&session.pid_path());
    let pid = fs::read_to_string(session.pid_path())
        .expect("read the pidfile")
        .trim()
        .parse()
        .expect("the pidfile holds a pid");
    let _reaper = Reaper(pid);

    assert!(
        session.lock_path().exists(),
        "the session came up without the spawn lock the layout promises, so the \
         attach spawned it holding an unlinked inode"
    );
    assert_ne!(
        inode(&session.lock_path()),
        orphan,
        "the file at the path must be a new one, not the inode that was unlinked"
    );
    drop(pinned);
}

/// Regression: a daemon holds `<id>.lock` across claiming its id, so nothing can
/// collect the session it is in the middle of publishing.
///
/// `attach` holds that lock from before the fork until `<id>.pid` exists (§ 6.3), and
/// `list` and `kill` take it before they unlink anything (§ 6.6) — so the mutual
/// exclusion the frozen control surface rests on existed only where an attach
/// happened to be the spawner. A `nomux daemon <id>` started by hand, which the usage
/// text documents and § 6.2 is written for, took nothing at all: a `list` that had
/// already probed the stale socket and found it refused went on to unlink the socket
/// and the pidfile this daemon had bound in between, which is the one thing § 6.6
/// promises never happens. Through `kill` the same interleaving exits 0 reporting no
/// such session while a daemon holds the user's shell.
///
/// The window is three syscalls wide, so it is held open here rather than waited for.
/// A unix `connect` blocks for as long as the listener's backlog is full, and
/// `bind_socket` probes the socket before it touches anything — so a listener with a
/// backlog of nothing and one connection already queued parks the daemon inside the
/// region under test for as long as this test likes.
#[test]
fn a_daemon_holds_the_spawn_lock_while_it_claims_the_id() {
    let session = StaleSession::empty("lka");
    // Created here so the wait below has an inode to name; the daemon opens this same
    // path, and `SpawnLock` checks that what it locked is still the file at it.
    let lock = File::create(session.lock_path()).expect("create the spawn lock");
    let lock = lock.metadata().expect("stat the spawn lock");

    let blocker = UnixListener::bind(session.socket()).expect("plant a listening socket");
    // SAFETY: `listen` is passed a descriptor the borrow above keeps open across the
    // call, and a backlog. `UnixListener` has no safe spelling of a second `listen` —
    // `bind` chose the backlog and nothing revisits it — and rustix's would mean
    // adding its `net` feature to the whole crate for one line of one test.
    let shrunk = unsafe { libc::listen(blocker.as_raw_fd(), 0) };
    assert_eq!(
        shrunk,
        0,
        "shrink the backlog: {}",
        std::io::Error::last_os_error()
    );
    // A backlog of zero still takes one connection — the kernel refuses at *more*
    // than the backlog, not at it — so the queue is filled here, and every `connect`
    // after this one waits for an `accept` that is never coming.
    let _queued = UnixStream::connect(session.socket()).expect("fill the backlog");

    let _daemon = Spawned::spawn(
        nomux_with_shell(&session.root, &["daemon", &session.id])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );

    wait_until_flock(
        Flock::Granted,
        lock.dev(),
        lock.ino(),
        "the daemon took the spawn lock before it went near the socket",
    );
}

/// The lock a `kill` creates is one the *next* process must be able to open, so it
/// is created at exactly `0600` however lax or strict the caller's umask is.
///
/// Left to the umask, a single `umask 0200` login publishes `<id>.lock` at `0400`
/// — and from then on nothing can open it `O_RDWR`, so no attach can serialise
/// against another and neither `list` nor `kill` can collect the session. A dead
/// session becomes uncollectable for good, which is the one outcome § 6.6 exists
/// to rule out.
#[test]
fn an_unopenable_spawn_lock_does_not_take_the_control_surface_with_it() {
    let session = StaleSession::create("lk4");
    fs::write(session.lock_path(), b"").expect("plant a lock file");
    fs::set_permissions(session.lock_path(), fs::Permissions::from_mode(0o400))
        .expect("make it unopenable");

    succeeded(&session.run(&["list"]), "list failed");
    assert!(
        !session.socket().exists(),
        "a dead session must still be collected when its lock cannot be opened: \
         {:?}",
        entries(&session.dir)
    );

    // And the fresh one a later session creates is openable by whoever comes next.
    let session = StaleSession::create("lk5");
    succeeded(&session.run(&["kill", "lk5"]), "kill failed");
}

/// Regression: `kill` waits out a pidfile that exists but is still empty.
///
/// The daemon publishes its pid in two steps — `File::create`, which leaves a
/// zero-length file, and then the write that fills it — so there is a moment when
/// the path exists and holds nothing. `attach` does not cover it: it releases the
/// spawn lock as soon as the path *exists*, which the empty file already satisfies,
/// so an ordinary spawn reaches this state and not only a hand-started daemon.
///
/// A missing pidfile was already waited out as the daemon's bind-to-publish window.
/// An empty one is the same window one syscall later, but it read as a *corrupt*
/// pidfile and was reported at once — so `kill` refused a session that was in
/// perfect health and a few microseconds from finishing its startup, and the caller
/// got a non-zero exit for no fault of anyone's.
///
/// The file is emptied and refilled by hand here because the real window is too
/// narrow to lose a race into deliberately; what is under test is what `kill` does
/// while it is open, not how it is arrived at.
#[test]
fn kill_waits_out_a_pidfile_that_has_been_created_but_not_yet_written() {
    let session = LiveSession::create("lk9");
    let body = fs::read_to_string(session.pid_path()).expect("read the pidfile");
    fs::write(session.pid_path(), b"").expect("empty the pidfile");
    // Stat'ed before `kill` runs, so the file the wait below watches is the one this
    // session already has rather than whatever is at the path by then.
    let lock = fs::metadata(session.run.lock_path()).expect("stat the spawn lock");

    let mut killing = Spawned::spawn(
        nomux(&session.run.root, &["kill", "lk9"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    // The window is closed on a condition rather than after a guess at how long `kill`
    // takes to reach it. `kill` takes `<id>.lock` and holds it to the end (§ 6.6)
    // strictly *before* it goes looking for a pid, so a granted `FLOCK` on that inode
    // is the fence: past it, `kill` is one `connect` and one `open` away from the
    // empty pidfile, where before it is a whole `fork`, `exec` and run-directory
    // check away — which is what a fixed sleep was really racing, and what a loaded
    // machine wins. A `kill` that never reached the empty file would pass this test
    // having tested nothing at all, and say so nowhere.
    wait_until_flock(
        Flock::Granted,
        lock.dev(),
        lock.ino(),
        "`kill` took the spawn lock",
    );
    fs::write(session.pid_path(), body.as_bytes()).expect("republish the pid");

    assert!(
        poll_until(Duration::from_secs(20), || !killing.is_running()),
        "`nomux kill` never returned from the publish grace it was waiting out"
    );
    let killed = killing
        .into_exited()
        .wait_with_output()
        .expect("collect what kill said");

    succeeded(
        &killed,
        "kill refused a session whose pidfile was merely still being written",
    );
    // The daemon, not its socket. `kill` spins until the socket stops answering and
    // only *then* unlinks it, so a `connect` to a path that is no longer there is
    // false on every exit `succeeded` above lets through — [`LiveSession::is_alive`]
    // cannot fail here, and an assertion that cannot fail is not one. The pid `kill`
    // was told to signal is what had to go, and `/proc` is where that is visible.
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(session.pid)),
        "kill reported success with the daemon it was asked to stop still running \
         as pid {}",
        session.pid
    );
}

/// `kill` never unlinks a live session's files, whatever the pidfile says.
///
/// The socket has just answered, so there is a daemon holding the user's shell.
/// Unlinking there — which is what an unreadable pidfile used to mean — takes that
/// daemon's socket away without stopping it: the session answers nothing, appears
/// in no listing, and the id is free for a second daemon to bind over. So this is
/// an error, and the files stay exactly as they were until somebody can say which
/// process to signal.
#[test]
fn kill_leaves_a_live_session_alone_when_its_pidfile_cannot_be_read() {
    let session = LiveSession::create("lk6");
    let before = entries(&session.run.dir);
    fs::set_permissions(session.pid_path(), fs::Permissions::from_mode(0o000))
        .expect("hide the pidfile");

    let killed = session.run.run(&["kill", "lk6"]);
    assert!(
        !killed.status.success(),
        "kill claimed to have removed a session it left running"
    );
    assert!(
        stderr(&killed).contains("is running"),
        "the refusal must say the session is still there: {:?}",
        stderr(&killed)
    );
    assert!(session.is_alive(), "the daemon must still be reachable");
    assert_eq!(
        entries(&session.run.dir),
        before,
        "not one of the five files was kill's to remove"
    );

    // Repaired, the same command works: the refusal is about the pidfile, not
    // about the session.
    fs::set_permissions(session.pid_path(), fs::Permissions::from_mode(0o600))
        .expect("restore the pidfile");
    succeeded(
        &session.run.run(&["kill", "lk6"]),
        "kill failed once the pidfile was readable again",
    );
    assert!(
        entries(&session.run.dir).is_empty(),
        "kill must unlink all five files"
    );
}

/// Every mode that touches the run directory establishes that it is this user's
/// alone *before* it trusts a name in it — including the two that only read.
///
/// The directory here is a symlink into one anybody can write to, with a socket, a
/// pidfile and a label planted in it. That is the whole attack: `attach` connecting
/// first and checking afterwards relays the user's keystrokes into a socket
/// somebody else is listening on, `list` prints their label to the user's terminal,
/// and `kill` reads their number out of the pidfile and signals it.
#[test]
fn the_control_surface_refuses_a_run_directory_that_is_not_ours() {
    let planted = PlantedRunDir::create("lk7");

    let attached = planted.run(&["attach", "imp"]);
    assert!(!attached.status.success(), "attach used a planted socket");
    assert!(
        stderr(&attached).contains("it is a symlink"),
        "attach must say what it refused: {:?}",
        stderr(&attached)
    );
    assert!(
        planted.nothing_connected(),
        "the relay handed the session over to a socket somebody else planted"
    );

    for mode in [vec!["list"], vec!["kill", "imp"]] {
        let out = planted.run(&mode);
        assert!(
            !out.status.success(),
            "{mode:?} used a planted run directory"
        );
        assert!(
            stderr(&out).contains("it is a symlink"),
            "{mode:?} must say what it refused: {:?}",
            stderr(&out)
        );
        assert!(
            out.stdout.is_empty(),
            "{mode:?} printed a planted entry: {:?}",
            stdout(&out)
        );
    }
}

/// Being asked what sessions exist must not be what creates the place they would
/// live.
///
/// `list` checks the run directory rather than ensuring it, so on a host that has
/// never run a session it stays silent, exits 0 and leaves the filesystem as it
/// found it. `kill` answers the same way: no run directory is "no such session",
/// which is the postcondition already holding.
#[test]
fn the_control_surface_neither_creates_nor_complains_about_a_missing_run_directory() {
    let session = StaleSession::empty("lk8");
    fs::remove_dir(&session.dir).expect("take the run directory away again");

    for mode in [vec!["list"], vec!["kill", "lk8"]] {
        let out = session.run(&mode);
        succeeded(
            &out,
            &format!("{mode:?} failed on a host with no run directory"),
        );
        assert!(
            out.stdout.is_empty(),
            "{mode:?} printed something: {:?}",
            stdout(&out)
        );
        assert!(
            !session.dir.exists(),
            "{mode:?} created the run directory it was only asked about"
        );
    }
}

/// The three answers a client gets out of this binary before it has a session: the
/// bootstrap line, the protocol revision, and 64 for a command line that makes no
/// sense.
///
/// `main.rs` has no other end-to-end coverage, and each of these is parsed by
/// somebody. The bootstrap line is the one § 5.1 says the client reads to decide
/// which artifact to upload, and its whole point is that it is the *second* probe
/// with that prefix: the shell probe that runs before any binary exists speaks
/// `uname`'s vocabulary — `Linux`, `x86_64`, `armv7l` — and this one speaks the
/// vocabulary of the binary that was installed, which is Rust's. So `linux` is
/// spelled out here rather than taken from `env::consts::OS`, which would agree with
/// whatever the binary printed and pin nothing. The architecture has to come from
/// `env::consts::ARCH`, since the suite is built for more than one — and on the ones
/// it is built for today the two vocabularies agree anyway, which leaves the `Linux`
/// that is not `linux` as the whole of what can be pinned here. The install
/// directory is the field the client actually uses, and `XDG_DATA_HOME` is set
/// because the default is the developer's own `~/.local/share`.
///
/// `--version` carries the protocol revision the client keys off, taken from
/// `nomux_proto` rather than written out: pinning the number would make bumping the
/// protocol a two-file change and say nothing about whether the binary reports the
/// one it speaks.
///
/// 64 is `EX_USAGE` (§ 10), and both ways of reaching it are here because they are
/// different code: an argument a mode that takes none was given, and a mode that does
/// not exist. Neither may put anything on stdout, which is where the bootstrap line
/// lives — a client that parses stdout must not find usage text in it.
///
/// The other two codes are left alone. 126 and 127 are `attach`'s, and § 10 defines
/// them by what `attach` met — a session that exists but will not have us, and one
/// that is absent and could not be spawned — so reaching either honestly means a real
/// relay against a sabotaged session, which is a mode that goes on to serve and so
/// cannot come through [`control`]. What is reachable from here is only the mapping
/// from an `io::ErrorKind` onto a number, and asserting on that would be asserting
/// which kind a refusal happens to carry.
#[test]
fn probe_and_version_report_what_a_client_bootstraps_from() {
    let root = run_root("lk10");
    let data_home = root.join("xdg-data");
    fs::create_dir_all(&data_home).expect("create the install directory's parent");

    let probed = collect(
        nomux(&root, &["probe"])
            .env("XDG_DATA_HOME", &data_home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    succeeded(&probed, "probe failed");
    assert_eq!(
        stdout(&probed),
        format!(
            "NOMUX-BOOTSTRAP linux {} {}\n",
            env::consts::ARCH,
            data_home.join("nomux").display()
        ),
        "probe must print the line § 5.1 has the client parse, in the installed \
         binary's own vocabulary and against its own install directory"
    );

    let versioned = control(&root, &["--version"]);
    succeeded(&versioned, "--version failed");
    assert!(
        stdout(&versioned).contains(&format!("protocol {PROTOCOL_VERSION}")),
        "--version must carry the protocol revision the client keys off: {:?}",
        stdout(&versioned)
    );

    for (mode, what) in [
        (vec!["probe", "extra"], "an argument `probe` does not take"),
        (vec!["frobnicate"], "a mode that does not exist"),
    ] {
        let refused = control(&root, &mode);
        assert_eq!(
            refused.status.code(),
            Some(64),
            "{what} must be EX_USAGE: {:?}",
            stderr(&refused)
        );
        assert!(
            refused.stdout.is_empty(),
            "{what} put {:?} on stdout, where the client looks for the bootstrap line",
            stdout(&refused)
        );
    }
}

/// A run directory holding one session, with nothing listening on its socket.
struct StaleSession {
    root: PathBuf,
    dir: PathBuf,
    id: String,
}

impl StaleSession {
    /// A directory with no session in it at all.
    fn empty(id: &str) -> Self {
        let root = run_root(id);
        let dir = root.join("nomux");
        fs::create_dir_all(&dir).expect("create run directory");
        Self {
            root,
            dir,
            id: id.to_owned(),
        }
    }

    /// The four files a daemon killed with `SIGKILL` leaves behind: a socket
    /// nobody is listening on, a pidfile naming a process that is gone, and a
    /// label. `connect` on that socket is refused, which is the definition of
    /// stale in § 6.6.
    fn create(id: &str) -> Self {
        let session = Self::empty(id);
        abandon_socket(&session.socket());
        fs::write(session.pid_path(), "999999999\n").expect("write pidfile");
        fs::write(session.dir.join(format!("{id}.label")), "stale").expect("write label");
        session
    }

    fn socket(&self) -> PathBuf {
        self.dir.join(format!("{}.sock", self.id))
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(format!("{}.lock", self.id))
    }

    fn pid_path(&self) -> PathBuf {
        self.dir.join(format!("{}.pid", self.id))
    }

    /// Takes the spawn lock the way `attach` does, and keeps it until the
    /// returned guard is dropped.
    fn hold_lock(&self) -> HeldLock {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())
            .expect("open the spawn lock");
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("take the spawn lock");
        HeldLock(file)
    }

    fn run(&self, args: &[&str]) -> Output {
        control(&self.root, args)
    }
}

/// The spawn lock, released as a property of the open file description rather than
/// by closing a descriptor.
///
/// `fork` duplicates the descriptor into every other test's children, and `flock(2)`
/// holds the lock until *all* of those duplicates are closed — but releases it on an
/// explicit `LOCK_UN` through any one of them, because they share one open file
/// description. So this is the answer `PLAN.md` § P2 prefers, the same shape as
/// `abandon_socket`'s `shutdown`: no stray copy can undo it.
struct HeldLock(File);

impl HeldLock {
    fn metadata(&self) -> std::io::Result<fs::Metadata> {
        self.0.metadata()
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

/// A session with a daemon actually running in it.
///
/// `attach` with stdin closed is all it takes: the relay connects, the daemon
/// binds, publishes its pid and then waits for a `Hello` that never comes, which
/// leaves it alive on its first-attach timeout — long enough to be the subject of a
/// `kill` that must not destroy it. No PTY is involved, which keeps these tests out
/// of the business of driving a shell.
struct LiveSession {
    run: StaleSession,
    /// What the pidfile said when the session came up, for the one test that has to
    /// be able to ask whether that process is still there after somebody else has
    /// taken the pidfile away.
    pid: u32,
    /// Whatever the test decided, this daemon is not the next run's business.
    _reaper: Reaper,
}

impl LiveSession {
    fn create(id: &str) -> Self {
        let run = StaleSession::empty(id);
        let started = collect(
            nomux_with_shell(&run.root, &["attach", id])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped()),
        );
        succeeded(&started, "attach failed");
        wait_for(&run.pid_path());
        let pid = fs::read_to_string(run.pid_path())
            .expect("read the pidfile")
            .trim()
            .parse()
            .expect("the pidfile holds a pid");
        Self {
            run,
            pid,
            _reaper: Reaper(pid),
        }
    }

    fn pid_path(&self) -> PathBuf {
        self.run.pid_path()
    }

    /// Whether a daemon is still answering. The same probe `list` and `kill` make,
    /// and the same authority: the socket outlives the process that bound it, so
    /// only a `connect` can tell.
    fn is_alive(&self) -> bool {
        UnixStream::connect(self.run.socket()).is_ok()
    }
}

/// A run directory that is a symlink into one anybody can write to, with a
/// session's files already planted in it.
///
/// The socket is bound by this process and stays bound, so anything that connects
/// to it reaches the test rather than a refused connection — which is the whole
/// point: a refusal would look like the same "stale socket" every other test uses.
struct PlantedRunDir {
    root: PathBuf,
    listener: UnixListener,
}

impl PlantedRunDir {
    fn create(name: &str) -> Self {
        let root = run_root(name);
        let theirs = root.join("theirs");
        fs::create_dir_all(&theirs).expect("create the planted directory");
        fs::set_permissions(&theirs, fs::Permissions::from_mode(0o777))
            .expect("make it world-writable");
        fs::create_dir_all(root.join("xdg")).expect("create the runtime directory");
        std::os::unix::fs::symlink(&theirs, root.join("xdg/nomux")).expect("plant the symlink");

        let listener = UnixListener::bind(theirs.join("imp.sock")).expect("plant a socket");
        listener
            .set_nonblocking(true)
            .expect("planted socket must not block the test");
        fs::write(theirs.join("imp.pid"), "999999999\n").expect("plant a pidfile");
        fs::write(theirs.join("imp.label"), "planted").expect("plant a label");
        Self { root, listener }
    }

    /// Runs one mode against the planted directory, giving up on one that will not
    /// come back.
    ///
    /// A relay that has been handed the planted socket does not exit: it has a peer
    /// that never closes and nothing to make it stop waiting. The bound is what
    /// turns the defect this test is about into a failed assertion rather than a
    /// test run that never ends.
    fn run(&self, args: &[&str]) -> Output {
        let mut child = Spawned::spawn(
            // With a shell even for `list` and `kill`, because the `attach` they
            // share this with is the one that must not reach one — and if it ever
            // does, it should find a predictable `/bin/sh` rather than whatever the
            // developer logs in with.
            nomux_with_shell(&self.root.join("xdg"), args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
        assert!(
            poll_until(Duration::from_secs(10), || !child.is_running()),
            "`nomux {args:?}` never returned, so it is still relaying to a \
             socket somebody else planted"
        );
        child
            .into_exited()
            .wait_with_output()
            .expect("collect nomux output")
    }

    /// Whether the planted socket was left entirely alone. Asked only after the
    /// process under test has exited, so a pending connection would already be in
    /// the listener's backlog.
    fn nothing_connected(&self) -> bool {
        matches!(self.listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
    }
}

/// Binds `path` and leaves it answering nothing, which is what stale means in
/// § 6.6: the socket a daemon killed with `SIGKILL` leaves in the run directory,
/// where only a refused `connect` distinguishes it from a session still in use.
///
/// The `shutdown` is the whole of the difference, and it is not belt and braces: a
/// listening socket goes on accepting for as long as *any* descriptor onto it
/// survives, and another test's `fork` in flight is holding one. `shutdown` belongs
/// to the socket rather than to the descriptor, so no duplicate can undo it
/// (`PLAN.md` § P2).
fn abandon_socket(path: &Path) {
    let listener = UnixListener::bind(path).expect("bind a socket to abandon");
    // SAFETY: `shutdown` is passed a descriptor the borrow above keeps open across
    // the call, and a flag it defines. `UnixListener` has no safe spelling of this —
    // `shutdown` is on `UnixStream` alone — and rustix's would mean adding its `net`
    // feature to the whole crate for one line of one test.
    let stopped = unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RD) };
    assert_eq!(
        stopped,
        0,
        "stop the abandoned socket accepting: {}",
        std::io::Error::last_os_error()
    );
    drop(listener);
}

fn inode(path: &Path) -> u64 {
    fs::metadata(path)
        .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
        .ino()
}

/// What is left in a run directory, sorted, for assertions about what was removed.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort_unstable();
    names
}

/// Which of the two states `/proc/locks` reports an `flock` request in.
#[derive(Clone, Copy)]
enum Flock {
    /// Still queued behind somebody else's lock on the same file.
    Queued,
    /// Granted, and held until whoever took it lets go.
    Granted,
}

/// Waits until an `flock` on `dev:ino` is in `state`, or says what never happened.
///
/// Both callers are trying to catch another process mid-operation, and without this
/// each would race the very thing it means to observe: the attach test would collect
/// the lock before anything was waiting on it, and the `kill` test would refill the
/// pidfile before `kill` had opened it. Neither asserts anything then, and neither
/// says so — which is what makes a fixed sleep the wrong tool for either. `/proc/locks`
/// lists queued requests alongside granted ones, so both are conditions to wait on.
fn wait_until_flock(state: Flock, dev: u64, ino: u64, what: &str) {
    let reached = poll_until(Duration::from_secs(20), || {
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

/// Whether `pid` is still a process rather than gone or a zombie nobody has
/// collected.
///
/// A zombie counts as gone because it has already run its `exit`, which is the whole
/// of what a `kill` has to establish — and it is a state this cannot rule out by
/// waiting: the daemon asked about here `setsid`ed away, so whoever reaps it is init
/// rather than anything in this process, and inside a container that may be a pid 1
/// that never calls `wait`.
fn process_alive(pid: u32) -> bool {
    // Read from after the parenthesised command name, because counting fields from
    // the front stops working the moment a command name contains a space or a
    // bracket. A process that is gone has no `stat` to read, which is the answer.
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let (_, tail) = stat.rsplit_once(')')?;
            tail.trim_start().chars().next()
        })
        .is_some_and(|state| state != 'Z')
}

/// Whether a `/proc/locks` field is the `MAJOR:MINOR:INODE` of one file.
///
/// The kernel prints it as `%02x:%02x:%llu` — the device in hex, the inode in
/// decimal — and all three are checked. Inode numbers are unique only within a
/// filesystem, and `CARGO_TARGET_TMPDIR` need not be on the same one as anything
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
