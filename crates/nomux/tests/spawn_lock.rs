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
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use nomux_proto::PROTOCOL_VERSION;

use harness::{
    Reaper, Spawned, collect, control, daemon_reaper, nomux, nomux_with_shell, poll_until,
    process_alive, run_root, stderr, stdout, succeeded, wait_for, while_nothing_forks,
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
    // Every other test here that brings a session up collects it with an explicit
    // `nomux kill`; this one is the exception, and the guard covers a failing
    // assertion below as well as a passing one. See [`daemon_reaper`] for what a
    // daemon left running costs the next run.
    let (_pid, _reaper) = daemon_reaper(&session.root, &session.id);

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
/// `setpgid` in the child is what forces the fork, and it is the same device
/// `a_daemon_that_leads_a_process_group_detaches_by_forking` uses: `Command` never
/// makes a process group leader, so without it `setsid` succeeds outright and this
/// test would pass against the ordering it exists to catch.
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
    let started = collect(&mut command);

    assert!(
        !started.status.success(),
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
/// an attach, and a caller that skipped every entry whose lock it could not open
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
/// `0400`, and from then on nothing can open it `O_RDWR`: no attach can serialise
/// against another, and neither `list` nor `kill` can take the lock they must hold
/// before they unlink anything (§ 6.6), so a dead session becomes uncollectable for
/// good. `<id>.pid` at `0400` is the milder version of the same fault — it is
/// rewritten rather than only read, and a mode a file keeps is one `write_private`
/// removes it to be rid of.
///
/// `0377` is the umask because it is the strictest one that still leaves a mode to
/// observe: it takes `0600` down to `0400`, which is precisely the login above, and a
/// suppression that did nothing would be visible as that number rather than as an
/// absence. The attach takes the lock and the daemon it forks publishes the pidfile,
/// so one hostile umask reaches both files through both processes.
#[test]
fn the_lock_and_the_pidfile_are_created_at_0600_whatever_the_umask() {
    let session = StaleSession::empty("lk5");
    let mut command = nomux_with_shell(&session.root, &["attach", "lk5"]);
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
    succeeded(&started, "attach failed under a hostile umask");
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

/// `kill` never unlinks a live session's files when nothing will say which process
/// is serving it.
///
/// The socket is unmistakably there, so there is a daemon holding the user's shell.
/// Unlinking there takes that daemon's socket away without stopping it: the session
/// answers nothing, appears in no listing, and the id is free for a second daemon to
/// bind over. So this is an error, and the files stay exactly as they were until
/// somebody can say which process to signal.
///
/// Both sources have to be shut for that, and the pidfile is now the lesser of them:
/// the socket names the daemon wherever it will answer at all (`control::daemon_of`),
/// so a hidden pidfile alone no longer leaves `kill` without an answer. A `connect`
/// refused with `EACCES` is not evidence of death either (§ 6.6), which is what
/// leaves this session both certainly alive and unidentifiable.
#[test]
fn kill_leaves_a_live_session_alone_when_nothing_will_say_which_process_it_is() {
    if rustix::process::getuid().is_root() {
        // A mode keeps nobody out of their own socket as root, so the daemon would
        // name itself on the connection and `kill` would rightly stop it.
        return;
    }
    let session = LiveSession::create("lk6");
    let before = entries(&session.run.dir);
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o000))
        .expect("shut the socket");
    fs::set_permissions(session.pid_path(), fs::Permissions::from_mode(0o000))
        .expect("hide the pidfile");

    let killed = session.run.run(&["kill", "lk6"]);
    // Both repaired before the assertions, since `is_alive` below has to be able to
    // reach the socket and the collection at the end has to be able to identify it.
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o600))
        .expect("restore the socket");
    fs::set_permissions(session.pid_path(), fs::Permissions::from_mode(0o600))
        .expect("restore the pidfile");

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

    // Repaired, the same command works: the refusal is about what could be read, not
    // about the session.
    succeeded(
        &session.run.run(&["kill", "lk6"]),
        "kill failed once the session could be identified again",
    );
    assert!(
        entries(&session.run.dir).is_empty(),
        "kill must unlink all five files"
    );
}

/// Regression: `kill` signals the process the socket names, not the number in the
/// pidfile.
///
/// `<id>.pid` is a name in a directory. Nothing tied it to the socket, so a number
/// that has been reissued since — a daemon killed before `clear_pid` existed, an
/// older version, a file repaired by hand — sent `SIGTERM` and then `SIGKILL` to an
/// unrelated process of the user's, and only the "still answering after `SIGKILL`"
/// branch noticed, by which time that process was already dead. `SO_PEERCRED` on the
/// connection `kill` already makes is the tie: the kernel takes it at `listen(2)`
/// from the process performing it, and no file can forge it.
///
/// The first assertion is that claim about `SO_PEERCRED` itself, checked against a
/// daemon in another process rather than assumed from the manual page.
///
/// The two live numbers do not cancel out: where they disagree, the tie is broken by
/// asking each candidate what it *is*, since only one of them runs `nomux daemon
/// <id>`. The stranger [`assert_told_from_a_stranger`] plants is live and is a
/// `sleep`, so the socket wins and the session is stopped — which is the whole point
/// of the change, and what refusing instead would have thrown away.
#[test]
fn kill_signals_the_process_the_socket_names_rather_than_the_pidfile() {
    let session = LiveSession::create("lk11");

    let answered = UnixStream::connect(session.run.socket()).expect("connect to the session");
    let named = peer_pid(&answered);
    drop(answered);
    assert_eq!(
        named.cast_unsigned(),
        session.pid,
        "a connection must name the process that called `listen` on the socket"
    );

    assert_told_from_a_stranger(
        &session.run.root,
        "lk11",
        session.pid,
        "answering on its own socket",
    );
}

/// Plants a live stranger's pid in `<id>.pid` and asserts that both modes still see
/// through it to `daemon`.
///
/// Every test about a daemon that is hard to identify ends in the same four
/// assertions, because the tie the socket and the file are in is broken the same way
/// each time — by asking each candidate what it is (`control::daemon_of`). So the
/// stranger must survive, `kill` must report success, `list` must print the pid it
/// would act on rather than the one in the file, and the daemon must be the process
/// that actually went. `describing` says which session this was: it is all that
/// distinguishes one of these failures from another.
///
/// A `sleep 300` is the stranger because it is unmistakably not a `nomux daemon`, and
/// its fate is read before anything is asserted — a failing assertion would otherwise
/// leave it behind as well, though [`Spawned`] collects it either way.
fn assert_told_from_a_stranger(root: &Path, id: &str, daemon: u32, describing: &str) {
    let pid_path = root.join("nomux").join(format!("{id}.pid"));
    let mut bystander = Spawned::spawn(
        Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
    fs::write(&pid_path, format!("{}\n", bystander.id())).expect("plant a stranger's pid");

    let listed = stdout(&control(root, &["list"]));
    let killed = control(root, &["kill", id]);
    let survived = bystander.is_running();
    drop(bystander);

    assert!(
        survived,
        "a `sleep` was taken for the daemon of a session {describing}: {:?}",
        stderr(&killed)
    );
    succeeded(
        &killed,
        &format!("a daemon {describing} was not recognised as one"),
    );
    assert_eq!(
        listed.trim_end().split('\t').nth(1),
        Some(daemon.to_string().as_str()),
        "list must name the daemon {describing}, not the pid planted in its file: \
         {listed:?}"
    );
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(daemon)),
        "kill reported success with the daemon {describing} still running as pid \
         {daemon}"
    );
}

/// Regression: a daemon is still recognised when the path it was started from is long.
///
/// The tie above is broken by reading `/proc/<pid>/cmdline`, and that read is bounded
/// like every other one here. Bounded at the wrong size it answers "not this daemon"
/// for a daemon whose `argv[0]` runs past the buffer — `attach` starts it from
/// `env::current_exe()` resolved, and § 5.2 installs under a directory the *client*
/// names — which is not a harmless answer: it is the one that leaves a healthy session
/// refused for as long as it runs, since neither candidate can then be identified.
///
/// So the buffer is sized past any path the kernel will resolve, and a read that fills
/// it says "cannot tell" rather than "no". The binary here is copied somewhere that
/// puts the whole command line past 512 bytes — a deep install rather than an absurd
/// one, and a twelfth of what the kernel allows: the daemon must still be picked out,
/// and the `sleep` planted in the pidfile must still not be.
#[test]
fn a_daemon_started_from_a_long_path_is_still_told_from_a_stranger() {
    let root = run_root("lk19");
    let mut deep = root.clone();
    for _ in 0..6 {
        deep.push("d".repeat(100));
    }
    fs::create_dir_all(&deep).expect("create the deep install directory");
    let exe = deep.join("nomux");
    // Under the fork gate, and not for tidiness: this is `ETXTBSY` waiting to
    // happen. Another test's `Command::spawn` forking between the `open` inside
    // `fs::copy` and the `close` that ends it leaves the forked child holding a
    // *writable* descriptor onto this file until it `exec`s, and the kernel refuses
    // to execute a file anybody has open for writing — so the `Command::new(&exe)`
    // a few lines down fails with `ExecutableFileBusy`. Measured at one run in
    // fifteen under `cargo test --test spawn_lock`, and invisible under nextest,
    // which gives each test a process of its own and so has never shown it in CI.
    // `PLAN.md` § P2 records the same hazard for `flock`; [`while_nothing_forks`]
    // is the seam that already exists for it.
    while_nothing_forks(|| {
        fs::copy(env!("CARGO_BIN_EXE_nomux"), &exe).expect("install the binary deep");
    });
    // What the daemon's `/proc/<pid>/cmdline` will hold: the three arguments and the
    // NUL after each. Asserted rather than assumed, since the whole test is about
    // where that length falls — this is the lower bound `MAX_CMDLINE_LEN` has to clear
    // for a deep install to be identified at all, and 512 is the size it once was.
    let cmdline = exe.as_os_str().len() + 1 + "daemon".len() + 1 + "lk19".len() + 1;
    assert!(
        cmdline > 512,
        "the command line must be longer than the buffer once was to test anything: \
         {cmdline} bytes"
    );

    let started = collect(
        Command::new(&exe)
            .args(["attach", "lk19"])
            .env("XDG_RUNTIME_DIR", &root)
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    succeeded(
        &started,
        "the deeply installed binary failed to start a session",
    );
    let (daemon, _reaper) = daemon_reaper(&root, "lk19");

    assert_told_from_a_stranger(&root, "lk19", daemon, "started from a long path");
}

/// Regression: a daemon is still recognised when its command line is long *behind*
/// the id.
///
/// The path in the test above is bounded — the kernel resolves `argv[0]` and will not
/// hand back more than `PATH_MAX` — but `--label` is not: `attach` passes what it was
/// given straight through (`attach::spawn_daemon`), and the 256-byte cap in
/// `sanitize_label` applies to the file the daemon *writes*, not to its own `argv`. So
/// a command line has no length a buffer can be sized against, and a rule that needed
/// to see the end of one would strand a session over a label.
///
/// Nothing behind the id is read as anything but padding: the pair is looked for among
/// the arguments the read saw the end of, and finding it is an answer whether or not
/// the rest arrived. The label here is an order of magnitude past what the layout
/// stores and past the whole buffer.
#[test]
fn a_daemon_started_with_an_over_long_label_is_still_told_from_a_stranger() {
    let root = run_root("lk20");
    let label = "L".repeat(8192);
    let started = collect(
        nomux_with_shell(&root, &["attach", "lk20", "--label", &label])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    succeeded(&started, "a session with a very long label failed to start");
    let (daemon, _reaper) = daemon_reaper(&root, "lk20");

    assert_told_from_a_stranger(
        &root,
        "lk20",
        daemon,
        "started with a label past the command-line buffer",
    );
}

/// The other half of that tie, and the one the fork of § 6.2 produces: the socket
/// names a live process that is *not* this session's daemon, and `<id>.pid` names the
/// one that is.
///
/// A daemon built before the bind moved after that fork has exactly this shape — the
/// half that called `listen` left, and if the kernel has since handed its number to
/// somebody else, the socket names a stranger while the file names the heir that
/// serves. Preferring the socket there signals the stranger and leaves the session
/// running, and the repair that suggests itself, removing the pidfile, makes it
/// certain; preferring the file blindly is the defect this whole change removed. So
/// the candidates are asked what they are, and `nomux daemon <id>` is the answer.
///
/// The shape is built rather than provoked. The creator that survives its own fork
/// holding nothing cannot be produced by this tree — the real one `_exit`s — so a
/// second daemon's socket is moved over this session's, which leaves a live, unrelated
/// `nomux daemon` process wearing the socket's credentials and the real daemon in the
/// file. What that costs is the end of the story: killing the pid the file names does
/// not close a socket the other daemon holds, so `kill` goes on to report a session it
/// could not establish had stopped. Which process was chosen is the assertion.
#[test]
fn kill_prefers_the_pidfile_when_the_socket_names_a_process_that_is_not_the_daemon() {
    let session = LiveSession::create("lk18");
    // A daemon of its own, in the same run directory and under a different id, whose
    // socket stands in for one an exited creator left behind.
    let other = collect(
        nomux_with_shell(&session.run.root, &["attach", "lk18b"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    succeeded(&other, "the second daemon failed to start");
    let (creator, _reaper) = daemon_reaper(&session.run.root, "lk18b");

    fs::rename(session.run.dir.join("lk18b.sock"), session.run.socket())
        .expect("move the second daemon's socket over this session's");
    let answered = UnixStream::connect(session.run.socket()).expect("connect to the session");
    assert_eq!(
        peer_pid(&answered).cast_unsigned(),
        creator,
        "the socket must now carry the other daemon's credentials"
    );
    drop(answered);

    let killed = session.run.run(&["kill", "lk18"]);
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
        "kill signalled the process the socket names, which is another session's \
         daemon and not this one's: {:?}",
        stderr(&killed)
    );
}

/// Regression: a pidfile whose number ran past the end of the read is not a pid.
///
/// The bounded read that keeps `list` off a planted gigabyte hands back a prefix, and
/// a prefix that ends mid-number parses as a smaller one: `" "*25 + "32770419\n"` came
/// back as 3277041, which was a real process of this test's. That is the harm the
/// socket-first change exists to remove, re-entering through the fix for the one
/// beside it, and the input is exactly what `MAX_PID_LEN`'s own reasoning invites — a
/// file somebody padded by hand.
///
/// The socket is shut so that it cannot answer, since a witness that works would make
/// the pidfile irrelevant and this is a test about the pidfile.
#[test]
fn a_pidfile_whose_number_is_cut_off_by_the_read_is_refused_rather_than_signalled() {
    if rustix::process::getuid().is_root() {
        // A mode keeps nobody out of their own socket as root, so the daemon would
        // name itself on the connection and the pidfile would never be consulted.
        return;
    }
    let session = LiveSession::create("lk17");
    let mut bystander = Spawned::spawn(
        Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
    // Padded so that the number straddles the end of any bounded read: a reader that
    // stops inside it comes back with a different, plausible, live pid.
    let padded = format!("{}{}\n", " ".repeat(25), 10 * bystander.id() + 7);
    fs::write(session.pid_path(), &padded).expect("plant a padded pidfile");
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o000))
        .expect("shut the socket");

    let killed = session.run.run(&["kill", "lk17"]);
    let listed = stdout(&session.run.run(&["list"]));
    let survived = bystander.is_running();
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o600))
        .expect("restore the socket");
    drop(bystander);
    fs::remove_file(session.pid_path()).expect("take the planted pidfile away");
    succeeded(&session.run.run(&["kill", "lk17"]), "kill failed");

    assert!(
        survived,
        "a truncated pidfile was parsed into somebody else's pid and signalled: {:?}",
        stderr(&killed)
    );
    assert!(
        !killed.status.success(),
        "a pidfile that does not end inside the read is no pidfile, and a live \
         session it cannot identify is not one to unlink"
    );
    assert_eq!(
        listed.trim_end().split('\t').nth(1),
        Some("?"),
        "list must not print half a number as a pid: {listed:?}"
    );
}

/// Regression: `<id>.pid` alone is not a number to signal until it has been asked what
/// it is.
///
/// The tie-break in `control::serving` ran only where *both* witnesses named a live
/// process, so a lone file witness went straight to `SIGTERM` and then `SIGKILL` with
/// nobody having asked whether it was a `nomux daemon <id>`. `control::peer_pid` states
/// the opposite as the contract: the kernel writes 0 into `SO_PEERCRED`'s pid field for
/// a peer whose pid does not map into the reader's namespace, and the pidfile the
/// daemon wrote in *its* namespace means nothing in this one either, so it is left "to
/// `resolve` to refuse". It was not refused. `nomux kill` run inside a container that
/// shares a run directory with a daemon started outside it terminated whichever process
/// inside happened to wear the outside number.
///
/// A socket at mode 0 stands in for the namespace and reaches the same state through
/// the same branch — a `connect` that failed for a reason which is not death, so the
/// session is unmistakably alive and the socket names nobody — without an `unshare`.
/// That is also why this stands down as root, where a mode keeps nobody out of their
/// own socket.
///
/// `list` is asserted beside it because the two weigh the same witnesses the same way
/// (§ 6.6): a column that still printed the stranger would be the escape hatch handing
/// a user the pid to signal by hand, at the moment `kill` has just declined to.
#[test]
fn a_lone_pidfile_naming_a_live_stranger_is_refused_rather_than_signalled() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let session = LiveSession::create("lk21");
    let before = entries(&session.run.dir);
    let mut bystander = Spawned::spawn(
        Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
    let stranger = bystander.id();
    fs::write(session.pid_path(), format!("{stranger}\n")).expect("plant a stranger's pid");
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o000))
        .expect("shut the socket");

    let killed = session.run.run(&["kill", "lk21"]);
    let listed = stdout(&session.run.run(&["list"]));
    let survived = bystander.is_running();
    let left = entries(&session.run.dir);
    // The other direction, and what keeps the check from being a refusal of every lone
    // file witness: § 6.2's fork leaves the socket naming an exited creator and the
    // file naming the daemon that serves, and such a session must still resolve to it.
    // `list` is what can say so while the socket is shut, since `kill` cannot watch a
    // socket it may not connect to stop answering.
    fs::write(session.pid_path(), format!("{}\n", session.pid)).expect("republish the pid");
    let identified = stdout(&session.run.run(&["list"]));
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o600))
        .expect("restore the socket");
    drop(bystander);
    fs::remove_file(session.pid_path()).expect("take the planted pidfile away");
    succeeded(&session.run.run(&["kill", "lk21"]), "kill failed");

    assert!(
        survived,
        "the only witness there was got signalled without being asked what it is: \
         {:?}",
        stderr(&killed)
    );
    assert!(
        !killed.status.success(),
        "a live session whose one witness is positively not its daemon is not one to \
         unlink"
    );
    assert!(
        stderr(&killed).contains(&format!(
            "it names pid {stranger}, which is not a `nomux daemon lk21` process"
        )),
        "the refusal must say which number it would not signal and what is wrong with \
         it, rather than blaming a file that holds exactly what it should: {:?}",
        stderr(&killed)
    );
    assert_eq!(
        listed.trim_end().split('\t').nth(1),
        Some("?"),
        "list must not hand back the number kill has just declined to act on: \
         {listed:?}"
    );
    assert_eq!(
        identified.trim_end().split('\t').nth(1),
        Some(session.pid.to_string().as_str()),
        "a lone file witness that *is* this session's daemon must still be taken, or \
         § 6.2's fork leaves a healthy session unidentifiable: {identified:?}"
    );
    assert_eq!(left, before, "not one of the files was kill's to remove");
}

/// Regression: a well-formed pidfile whose process is gone is reported as a stale
/// number, not as a corrupt file.
///
/// The refusal is built from the *bytes* of the body, and `control::unusable` had a
/// branch for a body running past the bound and one for everything else — so
/// `999999999\n`, which is exactly the pidfile § 6.6 describes, came back as `it holds
/// "999999999\n"`. That sends the reader to repair a file that is already correct, when
/// what has happened is the ordinary one: a daemon died without unlinking, and the
/// number it published names nothing this user can signal. There is no file to mend and
/// a session to collect, and only one of those two sentences says so.
///
/// The socket is shut for the truncated pidfile's reason — a witness that answers makes
/// the file irrelevant, and this is a test about what the file's own refusal says.
#[test]
fn a_pidfile_whose_process_is_gone_is_not_reported_as_a_corrupt_file() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let session = LiveSession::create("lk22");
    fs::write(session.pid_path(), "999999999\n").expect("plant a number that names nothing");
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o000))
        .expect("shut the socket");

    let killed = session.run.run(&["kill", "lk22"]);
    fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o600))
        .expect("restore the socket");
    fs::remove_file(session.pid_path()).expect("take the planted pidfile away");
    succeeded(&session.run.run(&["kill", "lk22"]), "kill failed");

    assert!(
        !killed.status.success(),
        "a live session with no witness left is not one to unlink"
    );
    assert!(
        stderr(&killed).contains("999999999 names no process"),
        "the refusal must say the number is stale rather than that the file is: {:?}",
        stderr(&killed)
    );
    assert!(
        !stderr(&killed).contains("it holds"),
        "a pidfile holding exactly what the layout says must not be called corrupt: \
         {:?}",
        stderr(&killed)
    );
}

/// Regression: `list` answers from a bounded prefix of `<id>.pid`.
///
/// The escape hatch has to keep working on any host, which it would not if a file
/// somebody left in the run directory decided how much memory it faulted in — and
/// under `-Cpanic=immediate-abort` (§ 8) an allocation that fails is an abort rather
/// than an error. `rundir::read_prefix` makes the argument; `<id>.label` has always
/// been read that way and `<id>.pid` was read whole.
///
/// The file here holds a usable pid in its first bytes and then runs on for sixty-four
/// megabytes, so a reader that stops where the layout stops prints that pid and one
/// that faults in the rest prints `?` — the difference lands in a column, rather than
/// in a measurement of the memory the process touched. The magnitude is only what
/// makes it obviously the wrong amount to read; the assertion is about the bound.
#[test]
fn list_reads_the_pidfile_as_far_as_the_layout_goes_and_no_further() {
    let session = LiveSession::create("lk12");
    let mut body = format!("{}\n", session.pid).into_bytes();
    // Whitespace to the end of what any bounded reader would take, so the prefix is
    // exactly a pidfile and everything past it is not.
    body.resize(32, b' ');
    let mut padded = File::create(session.pid_path()).expect("rewrite the pidfile");
    padded.write_all(&body).expect("write the pid");
    padded
        .set_len(1 << 26)
        .expect("run the file on past anything worth reading");
    drop(padded);

    let listed = session.run.run(&["list"]);
    succeeded(&listed, "list failed");
    let line = stdout(&listed);
    let column = line.split('\t').nth(1).map(str::to_owned);
    succeeded(&session.run.run(&["kill", "lk12"]), "kill failed");

    assert_eq!(
        column,
        Some(session.pid.to_string()),
        "list must answer from the prefix the layout describes: {line:?}"
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
/// Both modes, because they no longer read the same files: `list` opens `<id>.label`
/// on every live session and reaches `<id>.pid` only when the socket will not name a
/// pid, while `kill` reads `<id>.pid` on every session alive or not, since a second
/// witness is what its cross-check is made of. One FIFO each would leave the other
/// reader untested; both files and both modes leave nothing.
#[test]
fn the_control_surface_does_not_park_on_a_run_file_that_is_a_fifo() {
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

    // Backgrounded with a deadline of its own: the defect is a wait with no end, and
    // a test that waits for it is one that never fails. `kill` is given longer
    // because a pidfile that never says anything is the publish grace, waited out in
    // full before the socket's word is taken instead.
    let listed = ran_within(&session.run.root, &["list"], Duration::from_secs(10));
    let killed = ran_within(
        &session.run.root,
        &["kill", "lk13"],
        Duration::from_secs(20),
    );

    // Before the assertions, so a failure cannot leave a session behind — and a
    // second `kill` is what collects it if the first was the thing that broke.
    for path in [session.pid_path(), session.run.dir.join("lk13.label")] {
        drop(fs::remove_file(path));
    }
    let collected = session.run.run(&["kill", "lk13"]);

    let listed = listed.expect("`nomux list` parked on a FIFO in the run directory");
    succeeded(&listed, "list failed");
    assert_eq!(
        stdout(&listed),
        format!("lk13\t{}\t\n", session.pid),
        "a FIFO holds no label, and the pid comes off the socket"
    );
    let killed = killed.expect("`nomux kill` parked on a FIFO in the run directory");
    succeeded(
        &killed,
        "kill failed with a FIFO where the pidfile should be",
    );
    succeeded(
        &collected,
        "the session outlived the kill that reported success",
    );
}

/// Runs one mode with a deadline, and hands back `None` if it never came back.
///
/// For the defects that are a wait with no end: a test that simply waits for the
/// process is one that hangs instead of failing, and nextest's own timeout kills the
/// runner without saying which call never returned.
fn ran_within(root: &Path, args: &[&str], within: Duration) -> Option<Output> {
    let mut running = Spawned::spawn(
        nomux(root, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    poll_until(within, || !running.is_running()).then(|| {
        running
            .into_exited()
            .wait_with_output()
            .expect("collect what it said")
    })
}

/// One line per session, however many of its five files are on disk.
///
/// `list` discovers sessions by every run-file name rather than by the socket alone
/// (`control::session_id_of`), so a live session reaches the loop as several ids and
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

/// Regression: the install directory `probe` reports is absolute or there is none.
///
/// § 5.1 has the client read that path off one line of stdout, upload a binary to it
/// and `exec` what it uploaded (§ 5.2), over an exec channel whose working directory
/// is nobody's to predict — so a relative answer names a different place on every
/// connection, and `./nomux` from an unset `HOME` names one under whatever the login
/// shell happened to start in. `rundir::run_dir` has refused a non-absolute value
/// since it was written, for its own version of the same reason; this is the other
/// path out of the environment.
///
/// A missing answer is a failure and not a line, because a bootstrap line naming a
/// path that cannot work is worse than none at all: the client parses stdout, and
/// there is nothing in the format for "this is not usable".
#[test]
fn probe_refuses_an_install_directory_that_is_not_absolute() {
    let root = run_root("lk15");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create the home the fallback resolves against");

    // A relative `XDG_DATA_HOME` is not an install directory, and `HOME` is what § 5
    // falls back to when the first source says nothing usable.
    let fell_back = collect(
        nomux(&root, &["probe"])
            .env("XDG_DATA_HOME", "relative/share")
            .env("HOME", &home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    succeeded(&fell_back, "probe failed with a usable HOME");
    assert_eq!(
        stdout(&fell_back),
        format!(
            "NOMUX-BOOTSTRAP linux {} {}\n",
            env::consts::ARCH,
            home.join(".local/share/nomux").display()
        ),
        "a relative XDG_DATA_HOME is no install directory, and HOME is the fallback"
    );

    let nowhere = collect(
        nomux(&root, &["probe"])
            .env("XDG_DATA_HOME", "relative/share")
            .env_remove("HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert!(
        !nowhere.status.success(),
        "probe reported an install directory it had no way to resolve: {:?}",
        stdout(&nowhere)
    );
    assert!(
        nowhere.stdout.is_empty(),
        "a line the client cannot use must not be on the stream it parses: {:?}",
        stdout(&nowhere)
    );
    assert!(
        stderr(&nowhere).contains("absolute"),
        "the failure must say what was wrong with the environment: {:?}",
        stderr(&nowhere)
    );
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

/// The pid `SO_PEERCRED` reports for whoever called `listen` on `socket`, read the
/// way `control::peer_pid` reads it.
///
/// Through `libc` for the reason that function gives: rustix's `socket_peercred`
/// hands back a `UCred` whose `pid` is a `NonZeroI32`, and the kernel answers zero
/// for a peer in a pid namespace the caller cannot see.
fn peer_pid(socket: &UnixStream) -> i32 {
    use std::os::fd::AsRawFd;

    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(size_of::<libc::ucred>()).expect("the size of a ucred");
    // SAFETY: `getsockopt` is given the address and length of a `ucred` that outlives
    // the call, on a descriptor the borrow keeps open for it.
    let got = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut peer).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    assert_eq!(
        got,
        0,
        "read SO_PEERCRED: {}",
        std::io::Error::last_os_error()
    );
    peer.pid
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
