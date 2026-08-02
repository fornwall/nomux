//! Garbage collection against the spawn lock.
//!
//! `<id>.lock` is both the mutex an attach holds across creating a session
//! (`IMPLEMENTATION.md` § 6.3) and one of the five files `list` and `kill` remove
//! (§ 6.6). These tests drive the real binary against a run directory whose lock
//! is held by this process, which is the same position an attaching client is in.
//!
//! Run directory names are kept short on purpose: they carry unix sockets, and
//! `sockaddr_un` truncates the path at 108 bytes.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "the allow-*-in-tests settings in clippy.toml reach `#[test]` bodies \
              and `#[cfg(test)]` modules, not the helpers an integration test \
              crate shares between them"
)]

mod harness;

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use harness::wait_for;

/// A `list` that finds the spawn lock held leaves the whole entry alone, and
/// collects it on the next pass once the lock is free.
#[test]
fn a_held_spawn_lock_survives_a_concurrent_list() {
    let session = StaleSession::create("lk1");
    let lock = session.hold_lock();

    let listed = session.run(&["list"]);
    assert!(listed.status.success(), "list failed: {listed:?}");
    assert!(
        !String::from_utf8_lossy(&listed.stdout).contains(&session.id),
        "nothing is listening, so the session is not live: {:?}",
        String::from_utf8_lossy(&listed.stdout)
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
    let listed = session.run(&["list"]);
    assert!(listed.status.success(), "list failed: {listed:?}");
    assert!(
        !session.socket().exists() && !session.lock_path().exists(),
        "the same entry must be collected once the lock is free"
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
        String::from_utf8_lossy(&killed.stderr)
    );
    assert!(
        session.socket().exists() && session.lock_path().exists(),
        "kill removed files while the spawn lock was held"
    );

    drop(lock);
    let killed = session.run(&["kill", "lk2"]);
    assert!(
        killed.status.success(),
        "kill failed with the lock free: {:?}",
        String::from_utf8_lossy(&killed.stderr)
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
    let orphan = lock.metadata().expect("stat the held lock").ino();

    let mut child = Command::new(env!("CARGO_BIN_EXE_nomux"))
        .args(["attach", &session.id])
        .env("XDG_RUNTIME_DIR", &session.root)
        .env("SHELL", "/bin/sh")
        .env("NOMUX_RING_BYTES", "65536")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn attach");

    wait_until_blocked_on(orphan);

    // Exactly what collection used to do to a lock in use.
    fs::remove_file(session.lock_path()).expect("unlink the lock");
    drop(lock);

    wait_for(&session.socket());
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

    drop(child.kill());
    drop(child.wait());
    drop(session.run(&["kill", &session.id]));
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
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("run-{id}"));
        drop(fs::remove_dir_all(&root));
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
        drop(UnixListener::bind(session.socket()).expect("bind a socket to abandon"));
        fs::write(session.dir.join(format!("{id}.pid")), "999999999\n").expect("write pidfile");
        fs::write(session.dir.join(format!("{id}.label")), "stale").expect("write label");
        session
    }

    fn socket(&self) -> PathBuf {
        self.dir.join(format!("{}.sock", self.id))
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(format!("{}.lock", self.id))
    }

    /// Takes the spawn lock the way `attach` does, and keeps it until the
    /// returned file is dropped.
    fn hold_lock(&self) -> File {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())
            .expect("open the spawn lock");
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("take the spawn lock");
        file
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(args)
            .env("XDG_RUNTIME_DIR", &self.root)
            .output()
            .expect("run nomux")
    }
}

fn inode(path: &Path) -> u64 {
    fs::metadata(path)
        .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
        .ino()
}

/// Waits until some process is blocked on an `flock` for `ino`.
///
/// Without this the test would race the attach it is trying to catch mid-wait,
/// and would usually collect the lock before anything was waiting on it — which
/// asserts nothing. `/proc/locks` lists blocked requests alongside granted ones,
/// marked with `->`, so the wait is on the condition rather than on a guess.
fn wait_until_blocked_on(ino: u64) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let Ok(locks) = fs::read_to_string("/proc/locks") else {
            // A kernel without `/proc/locks` leaves the assertions below intact;
            // they just stop being guaranteed to exercise the window.
            thread::sleep(Duration::from_millis(250));
            return;
        };
        if locks.lines().any(|line| is_flock_waiter(line, ino)) {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("nothing ever blocked on the spawn lock, inode {ino}");
}

/// Whether one `/proc/locks` line is a request waiting for an `flock` on `ino`:
///
/// ```text
/// 2: -> FLOCK  ADVISORY  WRITE 3390 08:01:7746 0 EOF
/// ```
///
/// The device is `MAJOR:MINOR` in hex and the inode is decimal, so the field is
/// recognised by its shape rather than by position.
fn is_flock_waiter(line: &str, ino: u64) -> bool {
    line.contains("->")
        && line.contains("FLOCK")
        && line.split_whitespace().any(|field| {
            field.matches(':').count() == 2
                && field.rsplit(':').next().and_then(|n| n.parse().ok()) == Some(ino)
        })
}
