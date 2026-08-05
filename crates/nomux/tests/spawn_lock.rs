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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use nomux_proto::PROTOCOL_VERSION;

use harness::{
    Reaper, Session, Spawned, collect, control, daemon_reaper, entries, leads_a_process_group,
    nomux, nomux_with_shell, poll_by, poll_until, process_alive, run_root, stderr, stdout,
    succeeded, wait_for, wedge_socket, while_nothing_forks,
};

/// How long any one test here may spend waiting, across every wait it makes.
///
/// One deadline per test rather than one bound per wait, which is what
/// `.config/nextest.toml` asks for and says why: a test that waits for three things
/// one after another with a bound each is bounded by their *sum*, so several here
/// allowed themselves fifty and sixty seconds against a runner that kills at forty —
/// and a run that reached one of those bounds was killed from outside with nothing to
/// point at, which is the exact failure the bounds exist to replace. Thirty seconds
/// against tests that finish in under one leaves the margin where it belongs.
const PATIENCE: Duration = Duration::from_secs(30);

/// A `list` that finds the spawn lock held leaves the whole entry alone, and
/// collects it on the next pass once the lock is free.
///
/// The two planted names are a later version's sixth file (`rundir::session_id_of`),
/// one on this session and one that is the whole of an id: the sweep has to reach both
/// through a name this build never wrote, and [`collected_within`] asks for an empty
/// directory rather than for the five.
#[test]
fn a_held_spawn_lock_survives_a_concurrent_list() {
    let session = StaleSession::create("lk1");
    fs::write(session.dir.join("lk1.journal"), b"").expect("plant a later version's file");
    fs::write(session.dir.join("lk2.journal"), b"").expect("plant an id that is nothing else");
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
    assert_eq!(
        killed.status.code(),
        Some(1),
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

/// A spawn whose lock is collected while it waits goes back for the file that is now
/// at the path.
///
/// This is the half of the fix that is not "take the lock first": `flock` attaches
/// to the inode, so a spawn that was blocked on a lock file somebody unlinked
/// wakes up holding a lock nobody else can see. The next spawn creates a fresh
/// file at the same path, locks that, and both start a daemon for one session.
///
/// `spawn` rather than `attach` because creating is what takes this lock at all
/// (§ 6.3): `attach` connects to a session that is already there and never reaches
/// the region under test.
///
/// The interleaving is forced rather than hoped for: the collection happens only
/// once `/proc/locks` shows something blocked on this test's lock.
#[test]
fn a_spawn_re_takes_a_spawn_lock_that_was_collected() {
    let deadline = Instant::now() + PATIENCE;
    let session = StaleSession::empty("lk3");
    let lock = session.hold_lock();
    let held = lock.metadata().expect("stat the held lock");
    let orphan = held.ino();
    // A second descriptor on the same file, carrying no lock of its own: an inode
    // number is reusable the moment its last reference goes, and the spawn closes
    // the orphan before reopening the path. ext4 then hands the same number
    // straight back to the file created there, and the assertion below compares a
    // genuinely fresh file against a number it inherited — which is why this test
    // passes on tmpfs, where numbers are allocated monotonically, and fails on
    // ext4. Holding the inode open keeps its number out of circulation, so what
    // the assertion reports is the identity of the file rather than the
    // allocation policy of whichever filesystem the target directory sits on.
    let pinned = File::open(session.lock_path()).expect("pin the orphan inode");

    let _relay = Spawned::spawn(
        nomux_with_shell(&session.root, &["spawn", &session.id])
            .env("NOMUX_RING_BYTES", "65536")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );

    wait_until_flock(
        Flock::Queued,
        held.dev(),
        orphan,
        "the spawn waited for the spawn lock",
        deadline,
    );

    // Exactly what collection used to do to a lock in use.
    fs::remove_file(session.lock_path()).expect("unlink the lock");
    drop(lock);

    assert!(
        poll_by(deadline, || session.socket().exists()),
        "the spawn never brought up a socket for the session"
    );
    // Every other test here that brings a session up collects it with an explicit
    // `nomux kill`; this one is the exception, and the guard covers a failing
    // assertion below as well as a passing one. See [`daemon_reaper`] for what a
    // daemon left running costs the next run.
    let (_pid, _reaper) = daemon_reaper(&session.root, &session.id);

    assert!(
        session.lock_path().exists(),
        "the session came up without the spawn lock the layout promises, so the \
         spawn started it holding an unlinked inode"
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
/// `spawn` holds that lock from before the fork until `<id>.pid` exists (§ 6.3), and
/// `list` and `kill` take it before they unlink anything (§ 6.6) — so the mutual
/// exclusion the frozen control surface rests on existed only where a `spawn`
/// happened to be the creator. A `nomux daemon <id>` started by hand, which the usage
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
    let deadline = Instant::now() + PATIENCE;
    let session = StaleSession::empty("lka");
    // Created here so the wait below has an inode to name; the daemon opens this same
    // path, and `SpawnLock` checks that what it locked is still the file at it.
    let lock = File::create(session.lock_path()).expect("create the spawn lock");
    let lock = lock.metadata().expect("stat the spawn lock");

    let _wedged = wedge_socket(&session.socket());

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
        deadline,
    );
}

/// Regression: a session socket whose backlog is full does not park the escape hatch.
///
/// An `AF_UNIX` `connect` to a listener that has stopped calling `accept` *blocks*
/// rather than being refused (§ 6.3), and every mode here connects — so with no
/// deadline on that call, one session in that state parked `list` and `kill` inside
/// the kernel with nothing to end the wait. Measured as `timeout` killing each of them
/// after the fact, on the two modes § 6.6 promises will work against a daemon of any
/// version and on any host, and which are the only two that work standing alone.
///
/// A daemon that reaches this state is not hypothetical: § 6.3 states it as the
/// consequence of the backlog being the host's ceiling, and `PLAN.md` § P1 records it.
/// [`wedge_socket`] reproduces it in two syscalls.
///
/// What each mode does *after* the deadline is the second half of the assertion and is
/// not the same answer: a probe that timed out is not evidence of death (§ 6.3), so
/// `list` reports the session as live with no pid to print, and `kill` refuses and
/// leaves every file where it is. Collecting on a probe that never reached the socket
/// would be the escape hatch unlinking a session whose daemon is merely busy.
#[test]
fn the_control_surface_does_not_park_on_a_socket_whose_backlog_is_full() {
    let deadline = Instant::now() + PATIENCE;
    let session = StaleSession::empty("lk24");
    let _wedged = wedge_socket(&session.socket());

    let listed = ran_by(&session.root, &["list"], deadline)
        .expect("`nomux list` parked on a session socket whose backlog is full");
    let killed = ran_by(&session.root, &["kill", "lk24"], deadline)
        .expect("`nomux kill` parked on a session socket whose backlog is full");

    succeeded(&listed, "list failed");
    assert_eq!(
        stdout(&listed),
        "lk24\t?\t\n",
        "a session that would not answer is still a session, and nothing named a pid \
         for it"
    );
    assert_eq!(
        killed.status.code(),
        Some(1),
        "kill claimed to have removed a session it never established the state of"
    );
    assert!(
        stderr(&killed).contains("is running"),
        "the refusal must say the session is still there: {:?}",
        stderr(&killed)
    );
    assert!(
        session.socket().exists(),
        "a probe that timed out is not evidence of death, so nothing was kill's to \
         remove: {:?}",
        entries(&session.dir)
    );
}

/// Regression: a `nomux daemon <id>` that never bound its socket exits non-zero,
/// including on the path where § 6.2 has to fork.
///
/// The refusal an id already in use earns is not the only one that has to survive the
/// fork. Everything else the bind can answer — a read-only run directory, no space
/// for the node, a path component that stopped resolving, a name that appeared
/// between the probe and the bind — reaches the caller through the same exit status,
/// and past the fork there is no caller left to reach: the process somebody waited on
/// has already gone through `_exit(0)`. `ssh -t host 'nomux daemon <id>'` is exactly
/// the shape that forks, per § 6.2, so this is not a corner.
///
/// A dangling symlink is the deterministic way in. `connect` follows it, finds
/// nothing and answers `ENOENT`, which the probe reads as an id nobody is serving;
/// `bind` does not follow it, finds the name taken and answers `EADDRINUSE`. No race,
/// no timing, and the errno arrives strictly between the two.
///
/// [`leads_a_process_group`] is what forces the fork, the same device
/// `a_daemon_that_leads_a_process_group_detaches_by_forking` uses.
#[test]
fn a_daemon_that_cannot_bind_says_so_even_when_it_has_to_fork() {
    let session = StaleSession::empty("lkc");
    std::os::unix::fs::symlink(session.dir.join("nowhere"), session.socket())
        .expect("plant a dangling symlink at the socket");

    let mut command = nomux_with_shell(&session.root, &["daemon", "lkc"]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    leads_a_process_group(&mut command);
    let started = collect(&mut command);

    assert_eq!(
        started.status.code(),
        Some(1),
        "a daemon that never bound its socket reported success: {:?}",
        stderr(&started)
    );
    assert!(
        stderr(&started).contains("Address already in use"),
        "and it must say what stopped it: {:?}",
        stderr(&started)
    );
    assert!(
        !session.pid_path().exists(),
        "nothing may be published for a session that does not exist"
    );
}

/// A spawn lock nobody can open does not take the control surface with it: the dead
/// session behind it is still collected.
///
/// The mode a lock is *created* at is
/// [`the_lock_and_the_pidfile_are_created_at_0600_whatever_the_umask`]'s business.
/// This is what one already at `0400` costs — a file left by an older release, or by
/// a login under `umask 0200`. `list` opens `<id>.lock` `O_RDWR` to serialise against
/// a spawn, and a caller that skipped every entry whose lock it could not open
/// would leave that session on disk for good, which is the one outcome § 6.6 exists
/// to rule out. So the entry is collected anyway: what the lock stands between is a
/// spawn and a collection, and there is no spawn here to lose a race with.
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
}

/// The lock and the pidfile are created at exactly `0600`, however lax or strict the
/// umask of whoever created them was (`rundir::with_umask`).
///
/// `open(2)` subtracts the caller's umask from the mode it is given, which makes that
/// argument an upper bound rather than a request — and every mode in `rundir` is
/// exact. Left to the umask, a single `umask 0200` login publishes `<id>.lock` at
/// `0400`, and from then on nothing can open it `O_RDWR`: no spawn can serialise
/// against another, and neither `list` nor `kill` can take the lock they must hold
/// before they unlink anything (§ 6.6), so a dead session becomes uncollectable for
/// good. `<id>.pid` at `0400` is the milder version of the same fault — it is
/// rewritten rather than only read, and a mode a file keeps is one `write_private`
/// removes it to be rid of.
///
/// `0377` is the umask because it is the strictest one that still leaves a mode to
/// observe: it takes `0600` down to `0400`, which is precisely the login above, and a
/// suppression that did nothing would be visible as that number rather than as an
/// absence. The spawn takes the lock and the daemon it forks publishes the pidfile,
/// so one hostile umask reaches both files through both processes.
#[test]
fn the_lock_and_the_pidfile_are_created_at_0600_whatever_the_umask() {
    let session = StaleSession::empty("lk5");
    let mut command = nomux_with_shell(&session.root, &["spawn", "lk5"]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: the closure runs in the forked child before exec, so it must be
    // async-signal-safe. `umask` is, and nothing here allocates or takes a lock.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o377);
            Ok(())
        });
    }
    let started = collect(&mut command);
    succeeded(&started, "spawn failed under a hostile umask");
    let (_pid, _reaper) = daemon_reaper(&session.root, "lk5");

    for path in [session.lock_path(), session.pid_path()] {
        let mode = fs::metadata(&path)
            .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{} was created at {mode:o} rather than the 600 the layout fixes, so it \
             was the caller's umask that decided",
            path.display()
        );
    }

    // And what that mode is for: the next process can still take the lock and read
    // the pid, which is the whole of what `kill` needs to establish (§ 6.6).
    succeeded(&session.run(&["kill", "lk5"]), "kill failed");
}

/// Regression: `kill` waits out a pidfile that exists but is still empty.
///
/// The daemon publishes its pid in two steps — `File::create`, which leaves a
/// zero-length file, and then the write that fills it — so there is a moment when
/// the path exists and holds nothing. `spawn` does not cover it: it releases the
/// spawn lock as soon as the path *exists*, which the empty file already satisfies,
/// so an ordinary session creation reaches this state and not only a hand-started
/// daemon.
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
    let deadline = Instant::now() + PATIENCE;
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
    // The window is closed on two conditions rather than on a guess at how long `kill`
    // takes to reach it, and the first of them is the property itself: while the
    // pidfile says nothing, `kill` must still be *running*. That is what a fixed sleep
    // and the fence below cannot assert between them — a `kill` that answered the empty
    // file at once would let the fence miss it and fail this test somewhere else, or
    // win the race and pass it having tested nothing. Half a second against a grace of
    // two, so the margin is the wait rather than the scheduler.
    assert!(
        !poll_until(Duration::from_millis(500), || !killing.is_running()),
        "`kill` returned while the pidfile was still empty, so it is answering the \
         publish window rather than waiting it out"
    );
    // And the fence, which says *where* it is waiting. `kill` takes `<id>.lock` and
    // holds it to the end (§ 6.6) strictly before it goes looking for a pid, so a
    // granted `FLOCK` on that inode puts it past the whole `fork`, `exec` and
    // run-directory check and one `connect` and one `open` from the empty file.
    wait_until_flock(
        Flock::Granted,
        lock.dev(),
        lock.ino(),
        "`kill` took the spawn lock",
        deadline,
    );
    fs::write(session.pid_path(), body.as_bytes()).expect("republish the pid");

    assert!(
        poll_by(deadline, || !killing.is_running()),
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
        poll_by(deadline, || !process_alive(session.pid)),
        "kill reported success with the daemon it was asked to stop still running \
         as pid {}",
        session.pid
    );
}

/// Whether this run is root, where a test that shuts a run file with a mode would assert
/// nothing: a mode keeps nobody out of their own socket or their own pidfile there, so the
/// file opens exactly as it always did and the refusal under test never happens.
///
/// `why` is what the run gives up, said on stderr rather than swallowed — a skip
/// nobody can see is a pass, which is how CI came to run whole checks it never
/// exercised.
fn skip_as_root(why: &str) -> bool {
    let root = rustix::process::getuid().is_root();
    if root {
        eprintln!("skipped as root: {why}");
    }
    root
}

/// One way `<id>.pid` stops naming the daemon, and what that earns. See
/// [`a_live_session_its_pidfile_cannot_identify_is_refused_and_left_alone`].
struct Unidentified {
    id: &'static str,
    /// Whether the row needs a live process of this test's own for the file to
    /// appear to name.
    stranger: bool,
    /// Makes the file useless, handing back whatever must stay open for it to stay
    /// that way.
    plant: fn(&LiveSession, u32) -> Vec<File>,
    /// What the refusal must say of what it read.
    says: fn(u32) -> String,
    /// What it must not say.
    never: fn(u32) -> Option<String>,
    /// Puts a writable regular file back at the path.
    repair: fn(&LiveSession),
    /// Stands down as root, where a mode keeps nobody out of their own file.
    needs_modes: bool,
}

/// The five states `<id>.pid` can be in that never resolve themselves. An *absent*
/// pidfile is the daemon's bind-to-publish window and is waited out, and an empty one
/// is that window a syscall later; a file the caller may not open, one that is not a
/// file at all, one that runs past the bytes a pidfile may be, one naming a live
/// process that is positively not the daemon, and one naming a process that is gone
/// are none of the three, now or ever.
fn unidentified_pidfiles() -> [Unidentified; 5] {
    [
        Unidentified {
            id: "lk6",
            stranger: false,
            plant: |session, _| {
                fs::set_permissions(session.pid_path(), fs::Permissions::from_mode(0o000))
                    .expect("hide the pidfile");
                Vec::new()
            },
            says: |_| "Permission denied".to_owned(),
            never: |_| None,
            repair: |session| {
                fs::set_permissions(session.pid_path(), fs::Permissions::from_mode(0o600))
                    .expect("restore the pidfile");
            },
            needs_modes: true,
        },
        // `read_prefix` opens `O_NONBLOCK` so a FIFO cannot park the escape hatch, and
        // then took the one read it got — but only a regular file answers a read with
        // "this is all of it", so a writer that has delivered `12345` of `1234567`
        // hands back a whole, plausible, live pid. The reader is what lets the
        // writer's `open` return, so the bytes are in the pipe before `kill` opens it.
        Unidentified {
            id: "lk31",
            stranger: true,
            plant: |session, stranger| {
                fs::remove_file(session.pid_path()).expect("take the real pidfile away");
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    session.pid_path(),
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_bits_truncate(0o600),
                    0,
                )
                .expect("plant a FIFO where the pidfile should be");
                let reading = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(session.pid_path())
                    .expect("hold the FIFO open for reading");
                let mut writing = OpenOptions::new()
                    .write(true)
                    .open(session.pid_path())
                    .expect("open the FIFO for writing");
                writing
                    .write_all(stranger.to_string().as_bytes())
                    .expect("deliver a prefix of the number");
                vec![reading, writing]
            },
            says: |_| "is not a regular file".to_owned(),
            never: |stranger| Some(format!("names pid {stranger}")),
            repair: |session| {
                fs::remove_file(session.pid_path()).expect("take the FIFO away");
            },
            needs_modes: false,
        },
        // The check that a number is a `nomux daemon <id>` ran only where a *second*
        // witness named a live process too, so a file standing alone went straight to
        // `SIGTERM`: `nomux kill` inside a container sharing a run directory with a
        // daemon outside it terminated whichever process inside wore the number.
        Unidentified {
            id: "lk21",
            stranger: true,
            plant: |session, stranger| {
                fs::write(session.pid_path(), format!("{stranger}\n"))
                    .expect("plant a stranger's pid");
                Vec::new()
            },
            says: |stranger| {
                format!("it names pid {stranger}, which is not a `nomux daemon lk21` process")
            },
            // Nobody asks who is on the other end of a `connect`, so no number may be
            // offered as though the socket had named one.
            never: |_| Some("socket names".to_owned()),
            repair: |_| {},
            needs_modes: false,
        },
        // `read_prefix` takes the 32 bytes § 6.6 allows and no more, so a number padded
        // to straddle that bound comes back as a smaller, plausible, live pid — here
        // the stranger's own. A body that reached the bound is refused as one whose end
        // was never seen, rather than parsed or quoted back as a pid.
        Unidentified {
            id: "lk17",
            stranger: true,
            plant: |session, stranger| {
                let digits = stranger.to_string();
                fs::write(
                    session.pid_path(),
                    format!("{}{digits}0\n", " ".repeat(32 - digits.len())),
                )
                .expect("plant a pidfile the read cannot see the end of");
                Vec::new()
            },
            says: |_| "is cut off rather than read".to_owned(),
            never: |stranger| Some(format!("names pid {stranger}")),
            repair: |_| {},
            needs_modes: false,
        },
        // `999999999\n` is exactly the pidfile § 6.6 describes, and past any `pid_max`
        // a kernel hands out. The refusal used to quote the body back — sending the
        // reader to repair a file that is already correct, where what has happened is
        // a daemon that died without unlinking.
        Unidentified {
            id: "lk22",
            stranger: false,
            plant: |session, _| {
                fs::write(session.pid_path(), "999999999\n")
                    .expect("plant a number that names nothing");
                Vec::new()
            },
            says: |_| "999999999 names no process".to_owned(),
            never: |_| Some("it holds".to_owned()),
            repair: |_| {},
            needs_modes: false,
        },
    ]
}

/// A live session whose `<id>.pid` will not identify it keeps every one of its files,
/// and the refusal says which way the file failed.
///
/// [`unidentified_pidfiles`]'s five causes against one postcondition (§ 6.6). The
/// socket answers throughout, so there is a daemon holding the user's shell: unlinking
/// takes its socket away without stopping it, the session then appears in no listing,
/// and the id is free for a second daemon to bind over. A probe that failed as well is
/// [`kill_reports_a_socket_it_could_not_probe_rather_than_a_session_that_outlived_sigkill`]'s
/// subject.
///
/// The postcondition is the same every row: `kill` exits 1, whatever number the file
/// appeared to name is not signalled, `list` prints `?` rather than handing a user the
/// pid `kill` has just declined to act on, and not one of the files moves. Each row
/// then republishes the real pid, which is the other direction and what keeps this from
/// being a refusal of every file witness — a file that *does* name this session's
/// daemon must still be taken, or § 6.2's fork leaves a healthy session unidentifiable.
#[test]
fn a_live_session_its_pidfile_cannot_identify_is_refused_and_left_alone() {
    for case in unidentified_pidfiles() {
        if case.needs_modes
            && skip_as_root(
                "a mode keeps nobody out of their own pidfile, so it is read and acted on",
            )
        {
            continue;
        }
        let session = LiveSession::create(case.id);
        let before = entries(&session.run.dir);
        let mut bystander = case.stranger.then(sleeper);
        let stranger = bystander.as_ref().map_or(0, |sleeping| sleeping.id());
        let held = (case.plant)(&session, stranger);

        let killed = session.run.run(&["kill", case.id]);
        let listed = stdout(&session.run.run(&["list"]));
        let left = entries(&session.run.dir);
        let survived = bystander.as_mut().is_none_or(Spawned::is_running);
        drop(bystander);
        drop(held);

        // Repaired before the assertions, since the file is the only witness there is
        // and this session has to go.
        (case.repair)(&session);
        fs::write(session.pid_path(), format!("{}\n", session.pid)).expect("republish the pid");
        let identified = stdout(&session.run.run(&["list"]));
        let collected = session.run.run(&["kill", case.id]);

        let id = case.id;
        let said = stderr(&killed);
        assert!(
            survived,
            "{id}: the one candidate there was got signalled without being asked what \
             it is: {said:?}"
        );
        assert_eq!(
            killed.status.code(),
            Some(1),
            "{id}: a live session its one witness cannot identify is not one to unlink"
        );
        assert!(
            said.contains(&(case.says)(stranger)),
            "{id}: the refusal must say of the file what was actually established, \
             since that is the whole of what anyone can repair: {said:?}"
        );
        if let Some(never) = (case.never)(stranger) {
            assert!(
                !said.contains(&never),
                "{id}: the refusal claimed {never:?}, which is not what was read: \
                 {said:?}"
            );
        }
        assert_eq!(
            listed.trim_end().split('\t').nth(1),
            Some("?"),
            "{id}: list must not hand back the number kill has just declined to act \
             on: {listed:?}"
        );
        assert_eq!(
            left, before,
            "{id}: not one of the files was kill's to remove"
        );
        assert_eq!(
            identified.trim_end().split('\t').nth(1),
            Some(session.pid.to_string().as_str()),
            "{id}: a lone file witness that *is* this session's daemon must still be \
             taken, or § 6.2's fork leaves a healthy session unidentifiable: \
             {identified:?}"
        );
        succeeded(
            &collected,
            &format!("{id}: kill failed once the session could be identified again"),
        );
        assert!(
            entries(&session.run.dir).is_empty(),
            "{id}: kill must unlink every one of the session's files"
        );
    }
}

/// A live process of this test's own that nothing may signal, for the pidfiles made to
/// appear to name one.
fn sleeper() -> Spawned {
    Spawned::spawn(
        Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

/// Regression: a socket `kill` could not probe is reported as one, rather than as a
/// session that survived both signals.
///
/// A `connect` refused with `EACCES` is not evidence of death (§ 6.3), and reading it
/// as "alive" is right for the one decision that matters most — nothing is unlinked on
/// it. It was read that way for the two *other* decisions as well, and there it is
/// wrong in both directions. A socket at mode `0400` takes `SIGTERM` exactly as any
/// other session does and the daemon exits; the probe goes on answering `EACCES`,
/// because a mode does not change when a process does. So `kill` waited the whole term
/// grace out, sent `SIGKILL` to a number the kernel had already reaped and was free to
/// hand to somebody else, waited again, and then reported that the session was "still
/// answering after SIGTERM and SIGKILL to pid N, so that pid is not the process serving
/// it" — of which every clause was false. Five files stayed behind and the id was
/// wedged for good, the next spawn meeting the same `EACCES` in its own bind.
///
/// So the two readings are kept apart: only a connection that was *accepted* may
/// escalate or be called an answer, and a `connect` that failed for a reason which is
/// not death says the errno and refuses to unlink. That the daemon really did stop is
/// the other half of the assertion — the signal was never the broken part.
///
/// Stands down as root, where a mode keeps nobody out of their own socket: the probe
/// would be answered and there would be no unprobeable socket to report.
#[test]
fn kill_reports_a_socket_it_could_not_probe_rather_than_a_session_that_outlived_sigkill() {
    if skip_as_root("a socket at mode 0400 still answers its own user, so nothing is unprobeable") {
        return;
    }
    let deadline = Instant::now() + PATIENCE;
    let session = LiveSession::create("lk25");
    // Readable, so this is not the "nothing will say which process it is" case beside
    // it: `<id>.pid` names the daemon perfectly well and `kill` signals it. What 0400
    // takes away is only the `connect`, which needs write permission.
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o400))
        .expect("shut the socket to connect");

    let killed = session.run.run(&["kill", "lk25"]);
    // Whatever the daemon left behind, and it may already have collected itself: the
    // lock goes with `kill`, and its own shutdown then unlinks the five (§ 6.5).
    drop(fs::set_permissions(
        session.run.socket(),
        fs::Permissions::from_mode(0o600),
    ));

    assert_eq!(
        killed.status.code(),
        Some(1),
        "kill claimed a postcondition it could not see: {:?}",
        stdout(&killed)
    );
    assert!(
        stderr(&killed).contains("could not be probed")
            && stderr(&killed).contains("Permission denied"),
        "the refusal must name the errno that stopped it, since that is the whole of \
         what is known and the only thing anyone can repair: {:?}",
        stderr(&killed)
    );
    assert!(
        !stderr(&killed).contains("still answering after"),
        "nothing answered, so nothing may be reported as answering — that sentence \
         also claims the pid was wrong, and it was the right one: {:?}",
        stderr(&killed)
    );
    assert!(
        poll_by(deadline, || !process_alive(session.pid)),
        "the SIGTERM was never the broken part: the daemon must still have gone"
    );
    drop(session.run.run(&["kill", "lk25"]));
}

/// Regression: a daemon is still recognised when its command line is long *behind*
/// the id.
///
/// `argv[0]` is bounded — the kernel resolves it and will not hand back more than
/// `PATH_MAX`, which is what `MAX_CMDLINE_LEN` is sized from — but `--label` is not:
/// `spawn` passes what it was given straight through (`attach::spawn_daemon`), and the
/// 256-byte cap in `sanitize_label` applies to the file the daemon *writes*, not to its
/// own `argv`. So a command line has no length a buffer can be sized against, and a
/// rule that needed to see the end of one would strand a session over a label.
///
/// Nothing behind the id is read as anything but padding: the pair is looked for among
/// the arguments the read saw the end of, and finding it is an answer whether or not
/// the rest arrived. The label here is an order of magnitude past what the layout
/// stores and past the whole buffer. What both modes then have to do is the same
/// thing — `list` must print the pid the file names rather than `?`, and `kill` must
/// signal it and say so.
#[test]
fn a_daemon_started_with_an_over_long_label_is_still_recognised_as_one() {
    let root = run_root("lk20");
    let label = "L".repeat(8192);
    let started = collect(
        nomux_with_shell(&root, &["spawn", "lk20", "--label", &label])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    succeeded(&started, "a session with a very long label failed to start");
    let (daemon, _reaper) = daemon_reaper(&root, "lk20");

    let listed = stdout(&control(&root, &["list"]));
    succeeded(
        &control(&root, &["kill", "lk20"]),
        "a daemon started with a label past the command-line buffer was not recognised \
         as one",
    );
    assert_eq!(
        listed.trim_end().split('\t').nth(1),
        Some(daemon.to_string().as_str()),
        "list gave up on a daemon whose label ran past the buffer: {listed:?}"
    );
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(daemon)),
        "kill reported success with the daemon still running as pid {daemon}"
    );
}

/// The shape § 6.2's fork leaves behind, and what one witness makes of it: a live
/// process that is *not* this session's daemon is answering on `<id>.sock`, and
/// `<id>.pid` names the one that is.
///
/// A daemon built before the bind moved after that fork has exactly this shape — the
/// half that called `listen` left, and the id went on being served by something the run
/// directory never named. What the socket's own end of it is worth is nothing now: the
/// pid is read out of `<id>.pid` and asked what it is, and nobody asks who is on the
/// other end of a `connect`. So the stranger goes unsignalled however much it looks like
/// a daemon, which is what this pins — a rule that read the socket for a number would
/// signal it here, and the repair that suggests itself, removing the pidfile, would only
/// make that certain.
///
/// The socket is still what says whether the session *stopped*, and that is the end of
/// the story: it is somebody else's and goes on answering after both signals, so `kill`
/// leaves every file where it is rather than unlink a live session's on a postcondition
/// it never saw hold. This is the one path in § 6.6 that reaches "still
/// answering after SIGTERM and SIGKILL", and every clause of that sentence is true here —
/// the pid named was signalled, and it is not what serves the socket.
///
/// The shape is built rather than provoked. The creator that survives its own fork
/// holding nothing cannot be produced by this tree — the real one `_exit`s — so a second
/// daemon's socket is moved over this session's, which leaves a live, unrelated `nomux
/// daemon` process answering at the path and the real daemon in the file.
#[test]
fn kill_signals_what_the_pidfile_names_even_when_another_daemon_answers_on_the_socket() {
    let session = LiveSession::create("lk18");
    // A daemon of its own, in the same run directory and under a different id, whose
    // socket stands in for one an exited creator left behind.
    let other = collect(
        nomux_with_shell(&session.run.root, &["spawn", "lk18b"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    succeeded(&other, "the second daemon failed to start");
    let (creator, _reaper) = daemon_reaper(&session.run.root, "lk18b");

    // One syscall, so the id is served throughout and no probe ever finds the name
    // absent: from here on a `connect` to this path reaches the other daemon.
    fs::rename(session.run.dir.join("lk18b.sock"), session.run.socket())
        .expect("move the second daemon's socket over this session's");
    let before = entries(&session.run.dir);

    let killed = session.run.run(&["kill", "lk18"]);
    // Read before the `kill lk18b` below: that is this test's own cleanup, and it takes
    // the second daemon's files out of this same directory.
    let left = entries(&session.run.dir);
    let chosen_died = poll_until(Duration::from_secs(10), || !process_alive(session.pid));
    let creator_survived = process_alive(creator);
    drop(control(&session.run.root, &["kill", "lk18b"]));

    assert!(
        chosen_died,
        "kill did not signal the daemon the pidfile names: {:?}",
        stderr(&killed)
    );
    assert!(
        creator_survived,
        "kill signalled the process answering on the socket, which is another session's \
         daemon and no witness to this one: {:?}",
        stderr(&killed)
    );
    assert_eq!(
        killed.status.code(),
        Some(1),
        "the socket went on answering, so kill never established that the session had \
         stopped: {:?}",
        stdout(&killed)
    );
    assert!(
        stderr(&killed).contains(&format!(
            "still answering after SIGTERM and SIGKILL to pid {}",
            session.pid
        )),
        "and it must name the number it signalled and say the session outlived it, which \
         is the whole of what was established: {:?}",
        stderr(&killed)
    );
    assert_eq!(
        left,
        before,
        "a postcondition that was never seen to hold licenses no unlink: {:?}",
        stderr(&killed)
    );
}

/// A session that claims the id while `kill` is inside its locked region keeps all
/// five of its files.
///
/// `kill` takes `<id>.lock` first and holds it to the end so that nothing can spawn
/// into the id it is removing (§ 6.6), and that is not the whole of the guarantee:
/// § 6.3 has a daemon somebody started by hand *proceed without* the spawn lock where
/// it cannot take one, on the argument that doing so is no worse than the nothing it
/// held before. True of its bind, and not true of this unlink — the daemon can claim
/// the id inside the locked region, and every decision `kill` reached before it did is
/// then about a session that is no longer the one on disk. Removing the five on that
/// earlier evidence takes the new daemon's socket away without stopping it: no listing
/// shows it, no `kill` reaches it, and it holds a PTY until the reap.
///
/// The claim is made here by moving a listening socket of this test's over the
/// session's — atomically, so the id is served without ever being absent for a probe
/// to read as collectable — and strictly after `/proc/locks` shows `kill` holding the
/// lock. What that pins is the invariant across the whole locked region.
///
/// It does not pin the instant, and nothing outside the process can: the probe `kill`
/// decides on and the unlink it licenses are a few microseconds of userspace apart,
/// with no syscall in between for another process to be scheduled against. So the
/// microsecond interleaving is answered by construction — `control::kill` probes again
/// under the lock immediately before unlinking, which is where `control::collect` has
/// always decided — and this test is what says the invariant those two agree on still
/// holds end to end.
#[test]
fn kill_leaves_the_files_of_a_session_that_claimed_the_id_inside_its_locked_region() {
    let deadline = Instant::now() + PATIENCE;
    let session = LiveSession::create("lk26");
    let before = entries(&session.run.dir);
    // Stat'ed before `kill` runs, so the inode the wait below watches is this
    // session's own rather than whatever is at the path by then.
    let lock = fs::metadata(session.run.lock_path()).expect("stat the spawn lock");
    // Emptied for the reason [`kill_waits_out_a_pidfile_that_has_been_created_but_not_yet_written`]
    // relies on: `resolve` waits two seconds inside the locked region for a pid to be
    // published, where stopping a healthy daemon takes fifty milliseconds. The region
    // is what this has to interleave with, and a window that short is missed outright
    // under a full-core run — the failure is then a wait that never saw the state, on
    // a `kill` that had already been and gone.
    let body = fs::read_to_string(session.pid_path()).expect("read the pidfile");
    fs::write(session.pid_path(), b"").expect("empty the pidfile");
    // Bound now and moved into place later: `rename` is one syscall and `bind` is two,
    // and the gap between the second pair is a window in which the id is nobody's.
    let claiming = session.run.dir.join("claiming");
    let claimed = UnixListener::bind(&claiming).expect("bind the socket that claims it");

    let mut killing = Spawned::spawn(
        nomux(&session.run.root, &["kill", "lk26"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    wait_until_flock(
        Flock::Granted,
        lock.dev(),
        lock.ino(),
        "`kill` took the spawn lock and is inside its locked region",
        deadline,
    );
    fs::rename(&claiming, session.run.socket()).expect("claim the id under kill's lock");
    fs::write(session.pid_path(), body.as_bytes()).expect("republish the pid");

    assert!(
        poll_by(deadline, || !killing.is_running()),
        "`nomux kill` never returned"
    );
    let killed = killing
        .into_exited()
        .wait_with_output()
        .expect("collect what kill said");
    let left = entries(&session.run.dir);
    // Before the assertions, so a failure cannot leave the id claimed: nothing else
    // collects a socket this process bound.
    drop(claimed);
    drop(fs::remove_file(session.run.socket()));
    drop(session.run.run(&["kill", "lk26"]));

    assert_eq!(
        killed.status.code(),
        Some(1),
        "kill claimed to have removed a session that was answering: {:?}",
        stdout(&killed)
    );
    // Which refusal it is, so the publish window above cannot be what decided this: a
    // `kill` that gave up waiting for the pid also exits 1 and also unlinks nothing,
    // and would pass the two assertions either side of this having never reached the
    // interleaving.
    assert!(
        stderr(&killed).contains("still answering after SIGTERM and SIGKILL"),
        "kill never got as far as establishing what the id it was holding the lock \
         over had become: {:?}",
        stderr(&killed)
    );
    assert_eq!(
        left,
        before,
        "the id was claimed inside the locked region, so not one of the five files was \
         kill's to remove: {:?}",
        stderr(&killed)
    );
}

/// Regression: no run file can park the control surface in a syscall.
///
/// A FIFO opened `O_RDONLY` without `O_NONBLOCK` blocks in `open(2)` until somebody
/// opens it for writing, which for a file nobody is writing is for ever — so a FIFO
/// at `<id>.pid` or `<id>.label` stopped the escape hatch dead. The 0700 directory
/// bounds that to the session's own user, so it is the robustness of the surface
/// rather than a way in, but so was the bound on the label's length.
///
/// Both files and both modes, because they do not read the same set: `list` opens
/// `<id>.label` as well as `<id>.pid`, and `kill` opens the pidfile alone. One FIFO,
/// or one mode, would leave a reader untested; all four leave nothing.
#[test]
fn the_control_surface_does_not_park_on_a_run_file_that_is_a_fifo() {
    let deadline = Instant::now() + PATIENCE;
    let session = LiveSession::create("lk13");
    for path in [session.pid_path(), session.run.dir.join("lk13.label")] {
        drop(fs::remove_file(&path));
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
            0,
        )
        .expect("plant a FIFO where a run file should be");
    }

    // Backgrounded against a deadline: the defect is a wait with no end, and a test
    // that waits for it is one that never fails. Both share it, since a bound each is
    // a bound on their sum ([`PATIENCE`]).
    let listed = ran_by(&session.run.root, &["list"], deadline);
    let killed = ran_by(&session.run.root, &["kill", "lk13"], deadline);

    // Before the assertions, so a failure cannot leave a session behind. The pid goes
    // back where the daemon published it, since a FIFO is no pidfile and the pidfile
    // is the only thing that says what to signal.
    for path in [session.pid_path(), session.run.dir.join("lk13.label")] {
        drop(fs::remove_file(path));
    }
    fs::write(session.pid_path(), format!("{}\n", session.pid)).expect("republish the pid");
    let collected = session.run.run(&["kill", "lk13"]);

    let listed = listed.expect("`nomux list` parked on a FIFO in the run directory");
    succeeded(&listed, "list failed");
    assert_eq!(
        stdout(&listed),
        "lk13\t?\t\n",
        "a FIFO holds no label, and it is no pidfile either"
    );
    let killed = killed.expect("`nomux kill` parked on a FIFO in the run directory");
    assert_eq!(
        killed.status.code(),
        Some(1),
        "nothing was left to say which process serves the session, so there was \
         nothing to unlink: {:?}",
        stdout(&killed)
    );
    succeeded(
        &collected,
        "the session outlived the kill that was given a pidfile again",
    );
}

/// Runs one mode against a deadline, and hands back `None` if it never came back.
///
/// For the defects that are a wait with no end: a test that simply waits for the
/// process is one that hangs instead of failing, and nextest's own timeout kills the
/// runner without saying which call never returned. The deadline is the caller's
/// rather than a bound per run, for [`PATIENCE`]'s reason — both callers make two of
/// these one after another.
fn ran_by(root: &Path, args: &[&str], deadline: Instant) -> Option<Output> {
    let mut running = Spawned::spawn(
        nomux(root, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    poll_by(deadline, || !running.is_running()).then(|| {
        running
            .into_exited()
            .wait_with_output()
            .expect("collect what it said")
    })
}

/// The frozen control surface reaches a live session through the files on disk
/// alone (`IMPLEMENTATION.md` § 6.6) — `list` finds it and `kill` stops it.
///
/// "Stops it" was the half nobody checked. The assertion was that the socket had
/// gone, which is a statement about `unlink` and not about the session: a `kill`
/// that removed the five files and left the daemon running would pass it unchanged,
/// and § 10's whole contract for `kill` is that a zero status means "there is no
/// such session". What such a daemon leaves behind is the worst of both — a shell
/// still holding the user's work, with nothing on disk to attach to it by and
/// nothing for `list` to report, until the seven-day idle deadline collects it.
#[test]
fn list_and_kill_operate_without_the_protocol() {
    let (mut session, _client, _) = Session::attached("control");

    let listed = stdout(&control(&session.root, &["list"]));
    assert!(
        listed.contains(&session.id),
        "list should report the live session, got {listed:?}"
    );
    // One line per session and not per run file: `list` walks a directory holding
    // several names that lead to this one id, and it is the only thing that folds
    // them back together.
    assert_eq!(
        listed
            .lines()
            .filter(|line| line.starts_with(&format!("{}\t", session.id)))
            .count(),
        1,
        "list reported the same session more than once, got {listed:?}"
    );

    succeeded(
        &control(&session.root, &["kill", &session.id]),
        "kill failed",
    );

    assert!(!session.socket.exists(), "kill must unlink the run files");
    // `kill` returns once the daemon has stopped answering, so the process is either
    // already gone or on its way; the wait is for the reaping rather than for the
    // signal. Collected here as well as asserted, since the harness would otherwise
    // `SIGKILL` a corpse and learn nothing.
    assert!(
        poll_until(Duration::from_secs(10), || session
            .child
            .try_wait()
            .expect("wait for the daemon")
            .is_some()),
        "kill removed the session's five files and left the daemon running, so the \
         user's shell is still there with nothing left on disk to reach it by"
    );
}

/// Connecting is not attaching.
///
/// The frozen control surface decides whether a daemon is alive by connecting to
/// its socket (§ 6.6), and so does the spawn race in § 6.3. If the daemon counted
/// that as a takeover, `nomux list` would evict the user from every session on the
/// host — and the client is told never to auto-reconnect after `TAKEOVER`, so the
/// damage would be permanent.
#[test]
fn a_liveness_probe_does_not_evict_the_attached_client() {
    let (session, mut client, ok) = Session::attached("probe");

    // The bare probe, then the real thing.
    for _ in 0..3 {
        drop(UnixStream::connect(&session.socket).expect("probe connect"));
    }
    assert!(stdout(&control(&session.root, &["list"])).contains(&session.id));

    // `read_until` refuses anything that is not output, so an `Error{TAKEOVER}`
    // fails this rather than being skipped over.
    client.input(0, b"echo NOMUX-STILL-ATTACHED\n");
    client.read_until("NOMUX-STILL-ATTACHED", ok.resume_from);
}

/// Ids are opaque per-tab identifiers, so the label is the only thing that makes a
/// session recognisable to a human after the client loses its state.
///
/// Through `spawn` because the label belongs to the session rather than to the
/// connection (§ 6.6): it is recorded when the session is created, so the two modes
/// that create one take it and `attach` refuses it outright
/// ([`version_and_usage_report_what_a_client_keys_off`]).
#[test]
fn a_label_survives_into_list() {
    let root = run_root("label");
    let relay = Spawned::spawn(
        nomux_with_shell(
            &root,
            &["spawn", "labelled", "--label", "  release build\tx  "],
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    );
    // The label, not the socket. The daemon publishes in the order bind, pidfile,
    // label (§ 6.2), and the assertion below reads the last two — so waiting on the
    // first would let `list` run against a session that is answering and has not
    // said what it is called, which prints `labelled\t?\t` and fails on the label.
    wait_for(&root.join("nomux").join("labelled.label"));
    // And the pidfile is already there, being one step earlier in that same order.
    let (_pid, _reaper) = daemon_reaper(&root, "labelled");

    let listed = stdout(&control(&root, &["list"]));

    // Both collected before the assertions below, so a failure about the label does
    // not also leave a session behind.
    drop(relay);
    drop(control(&root, &["kill", "labelled"]));

    let line = listed
        .lines()
        .find(|line| line.starts_with("labelled\t"))
        .unwrap_or_else(|| panic!("session missing from list: {listed:?}"));
    let label = line.split('\t').nth(2).expect("label column");
    assert_eq!(
        label, "release buildx",
        "label should be trimmed and stripped of control characters"
    );
}

/// An id that could never have named a session is a malformed command line rather
/// than a session that would not have us.
///
/// Through `spawn`, which is the mode with something to lose by getting the order
/// wrong: it is the one that goes on to `ensure_dir`, so a refusal that came after
/// the directory was created would be a bad id bringing a run directory into
/// existence — and `../escape` would bring it into existence somewhere the caller
/// did not name. `attach` reaches the same refusal through the same
/// `SessionPaths::new` and creates nothing either way, so it is the weaker of the two
/// spellings.
#[test]
fn invalid_session_ids_are_refused() {
    // A run directory of its own even though nothing should ever be created in it:
    // the refusal is what is under test, and a regression that got as far as the
    // filesystem would otherwise leave its mess where every other test lives.
    let root = run_root("bad_ids");
    for id in ["../escape", "with/slash", "with space"] {
        let output = control(&root, &["spawn", id]);
        // The exit status, not merely a non-zero one: § 10 gives a malformed
        // invocation `EX_USAGE`, and the distinction is the whole behaviour. A client
        // caches "unattachable" per host on 126, so an id that could never have named
        // a session must not come back wearing that number.
        assert_eq!(
            output.status.code(),
            Some(64),
            "id {id:?} should be refused as EX_USAGE, got {:?}",
            output.status
        );
        assert!(
            stderr(&output).contains("invalid session id"),
            "id {id:?} should be rejected by name"
        );
    }
    assert!(
        !root.join("nomux").exists(),
        "an id that could never have named a session brought the run directory it \
         would have lived in into existence"
    );
}
/// One line per session, however many of its files are on disk.
///
/// `list` discovers sessions by every run-file name rather than by the socket alone
/// (`rundir::session_id_of`), so a live session reaches the loop as several ids and
/// has to be folded back to one. Nothing else in the suite would notice if it were
/// not: every other assertion about a listing looks for a line rather than counting
/// them, and a session printed five times satisfies all of them.
#[test]
fn a_session_is_listed_once_however_many_files_it_has() {
    let session = LiveSession::create("lk16");
    // The two the daemon does not publish unless it is asked to, so all five names
    // are present and the fold has the most it will ever have to do.
    fs::write(session.run.dir.join("lk16.label"), "five files").expect("plant a label");
    fs::write(session.run.dir.join("lk16.agent"), "").expect("plant an agent socket's name");
    assert_eq!(entries(&session.run.dir).len(), 5, "all five names on disk");

    let listed = session.run.run(&["list"]);
    succeeded(&listed, "list failed");
    let lines = stdout(&listed);
    succeeded(&session.run.run(&["kill", "lk16"]), "kill failed");

    assert_eq!(
        lines.lines().collect::<Vec<_>>(),
        vec![format!("lk16\t{}\tfive files", session.pid)],
        "five names are one session"
    );
}

/// Regression: `nomux list | head` is a listing that ended, not a failure.
///
/// The Rust runtime ignores `SIGPIPE` — § 6.2 depends on that — so the write to a
/// stdout whose reader has gone comes back `EPIPE` rather than ending the process.
/// Reported, that is `nomux: Broken pipe (os error 32)` and exit 1 for something the
/// user did on purpose, and § 10 already reads a closed stdout as a clean end for
/// `attach`. It also cut the sweep short, so the stale entries after the one being
/// printed were left for a `list` nobody may run again.
///
/// The pipe here has no reader at all rather than one that walks away, so the first
/// write fails and nothing depends on beating a reader to the buffer. The exit status
/// is what pins the defect either way: `list` visits the run directory in the order
/// the directory gives it, so whether the stale entry is reached before the failing
/// write or after it is the filesystem's business, and only the second of those two
/// orders also makes the collection below an assertion about the fix.
#[test]
fn a_listing_whose_reader_has_gone_ends_cleanly_and_still_collects() {
    let session = LiveSession::create("lk14");
    let stale = session.run.dir.join("lk14x.sock");
    abandon_socket(&stale);
    fs::write(session.run.dir.join("lk14x.pid"), "999999999\n").expect("write a stale pidfile");

    // The read end is closed where no `fork` can be carrying a copy of it: a
    // duplicate in another test's child would leave the pipe with a reader, and the
    // write below would succeed rather than testing anything.
    let broken = while_nothing_forks(|| {
        let (read_end, write_end) = rustix::pipe::pipe().expect("a pipe to break");
        drop(read_end);
        write_end
    });
    let listed = collect(
        nomux(&session.run.root, &["list"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(broken))
            .stderr(Stdio::piped()),
    );

    let left = entries(&session.run.dir);
    succeeded(&session.run.run(&["kill", "lk14"]), "kill failed");

    succeeded(&listed, "a reader that closed early is not a failure");
    assert!(
        stderr(&listed).is_empty(),
        "nothing is wrong, so nothing should be said: {:?}",
        stderr(&listed)
    );
    assert!(
        !left.iter().any(|name| name.starts_with("lk14x")),
        "the stale session after the broken write was left behind: {left:?}"
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
    assert_eq!(
        attached.status.code(),
        Some(126),
        "attach used a planted socket"
    );
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
        assert_eq!(
            out.status.code(),
            Some(1),
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

/// The two answers a client gets out of this binary before it has a session: the
/// protocol revision, and 64 for a command line that makes no sense.
///
/// `main.rs` has no other end-to-end coverage. `--version` carries the protocol
/// revision the client keys off, taken from `nomux_proto` rather than written out:
/// pinning the number would make bumping the protocol a two-file change and say
/// nothing about whether the binary reports the one it speaks.
///
/// 64 is `EX_USAGE` (§ 10), and all four ways of reaching it are here because they are
/// different code: an argument a mode that takes none was given, a mode that does not
/// exist, a `--label` offered to the one session mode that does not create a session,
/// and an id that begins with `-`, which `main` reads as an option before any mode sees
/// it — `rundir::is_valid_session_id` refuses that leading `-` for the same reason, so
/// a conforming client can never mint an id it could create and then never kill. None
/// may put anything on stdout — a client that parses stdout must not find usage text in
/// it — and each must name what it objected to, since the usage text behind it
/// describes five modes and says nothing about which one the caller got wrong.
///
/// The `--label` row is the whole of what `main` does about the split beyond
/// dispatching it, and dropping the option on the floor was the alternative. A
/// `--label` on `attach` is a caller that still believes `attach` might create the
/// session — the confusion the split exists to end — so silence there would leave it
/// believing that and lose the label besides. `kill` goes on parsing and ignoring
/// one, because what the frozen escape hatch accepts is not this change's to narrow,
/// and `daemon` and `spawn` both honour it.
///
/// The other two codes are left alone. 126 and 127 belong to the relay modes, and
/// § 10 defines them by what those modes met — an id that is taken or a session that
/// will not have us, against one that is absent and could not be started — so
/// reaching either honestly means a real relay against a real run directory, which is
/// a mode that may go on to serve and so cannot come through [`control`].
/// `attach.rs` is where they are pinned.
#[test]
fn version_and_usage_report_what_a_client_keys_off() {
    let root = run_root("lk10");

    let versioned = control(&root, &["--version"]);
    succeeded(&versioned, "--version failed");
    assert!(
        stdout(&versioned).contains(&format!("protocol {PROTOCOL_VERSION}")),
        "--version must carry the protocol revision the client keys off: {:?}",
        stdout(&versioned)
    );

    for (mode, what, must_name) in [
        (
            vec!["list", "extra"],
            "an argument `list` does not take",
            "takes no arguments",
        ),
        (
            vec!["frobnicate"],
            "a mode that does not exist",
            "unknown mode",
        ),
        (
            vec!["attach", "lk10", "--label", "a tab title"],
            "a label offered to the mode that creates nothing",
            "--label",
        ),
        (
            vec!["kill", "-abc123"],
            "an id no command line can carry",
            "unknown option",
        ),
    ] {
        let refused = control(&root, &mode);
        assert_eq!(
            refused.status.code(),
            Some(64),
            "{what} must be EX_USAGE: {:?}",
            stderr(&refused)
        );
        assert!(
            stderr(&refused).contains(must_name),
            "{what} must be refused by name rather than by usage text alone, and \
             {must_name:?} is not in {:?}",
            stderr(&refused)
        );
        assert!(
            refused.stdout.is_empty(),
            "{what} put {:?} on stdout, where a client parses output",
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

    /// Takes the spawn lock the way `spawn` does, and keeps it until the
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
/// `spawn` with stdin closed is all it takes: the relay starts a daemon, which
/// binds, publishes its pid and then waits for a `Hello` that never comes — which
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
            nomux_with_shell(&run.root, &["spawn", id])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped()),
        );
        succeeded(&started, "spawn failed");
        let (pid, reaper) = daemon_reaper(&run.root, id);
        Self {
            run,
            pid,
            _reaper: reaper,
        }
    }

    fn pid_path(&self) -> PathBuf {
        self.run.pid_path()
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
/// Every caller is trying to catch another process mid-operation, and without this each
/// would race the very thing it means to observe: the spawn test would collect the
/// lock before anything was waiting on it, and the `kill` tests would move the ground
/// under `kill` before it had reached the region they are about. None asserts anything
/// then, and none says so — which is what makes a fixed sleep the wrong tool for any of
/// them. `/proc/locks` lists queued requests alongside granted ones, so both are
/// conditions to wait on.
///
/// The deadline is the caller's, per [`PATIENCE`]: this is one of several waits every
/// caller makes, and a bound of its own would only add to their sum.
fn wait_until_flock(state: Flock, dev: u64, ino: u64, what: &str, deadline: Instant) {
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
