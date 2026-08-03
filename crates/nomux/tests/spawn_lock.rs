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
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use nomux_proto::PROTOCOL_VERSION;

use harness::{
    Reaper, Spawned, collect, control, nomux, nomux_with_shell, poll_until, run_root, stderr,
    stdout, succeeded, wait_for, while_nothing_forks,
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
#[test]
fn kill_signals_the_process_the_socket_names_rather_than_the_pidfile() {
    let session = LiveSession::create("lk11");

    let answered = UnixStream::connect(session.run.socket()).expect("connect to the session");
    let named = rustix::net::sockopt::socket_peercred(&answered)
        .expect("the credentials of whoever is listening")
        .pid;
    drop(answered);
    assert_eq!(
        named.as_raw_nonzero().get().cast_unsigned(),
        session.pid,
        "a connection must name the process that called `listen` on the socket"
    );

    // A process of the user's with nothing to do with the session, and a pidfile that
    // names it.
    let mut bystander = Spawned::spawn(
        Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
    fs::write(session.pid_path(), format!("{}\n", bystander.id()))
        .expect("plant a reissued pid in the pidfile");

    let killed = session.run.run(&["kill", "lk11"]);
    // Read before anything is asserted, so a failure cannot also leave the bystander
    // behind — and `Spawned` collects it either way.
    let survived = bystander.is_running();
    drop(bystander);

    assert!(
        survived,
        "kill signalled an unrelated process of the user's: {:?}",
        stderr(&killed)
    );
    succeeded(&killed, "kill could not stop the session");
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(session.pid)),
        "kill reported success with the daemon it was asked to stop still running \
         as pid {}",
        session.pid
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

/// Regression: neither run file `list` reads can park it in a syscall.
///
/// A FIFO opened `O_RDONLY` without `O_NONBLOCK` blocks in `open(2)` until somebody
/// opens it for writing, which for a file nobody is writing is for ever — so a FIFO
/// at `<id>.pid` or `<id>.label` stopped the escape hatch dead. The 0700 directory
/// bounds that to the session's own user, so it is the robustness of `list` rather
/// than a way in, but so was the bound on the label's length.
///
/// Both files at once, since one open is as far as the old reader ever got. `kill`
/// reads the pidfile through the same call, so it is fixed by the same flag.
#[test]
fn list_does_not_park_on_a_run_file_that_is_a_fifo() {
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
    // a test that waits for it is one that never fails.
    let mut listing = Spawned::spawn(
        nomux(&session.run.root, &["list"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let returned = poll_until(Duration::from_secs(10), || !listing.is_running());
    let listed = if returned {
        Some(
            listing
                .into_exited()
                .wait_with_output()
                .expect("collect what list said"),
        )
    } else {
        None
    };

    // The FIFOs go before the assertions, so a `kill` that has to fall back to the
    // pidfile is not itself parked on one.
    for path in [session.pid_path(), session.run.dir.join("lk13.label")] {
        drop(fs::remove_file(path));
    }
    succeeded(&session.run.run(&["kill", "lk13"]), "kill failed");

    assert!(
        returned,
        "`nomux list` parked on a FIFO in the run directory"
    );
    let listed = listed.expect("the output of a list that returned");
    succeeded(&listed, "list failed");
    assert_eq!(
        stdout(&listed),
        "lk13\t?\t\n",
        "a FIFO holds no pid and no label, and says so in the columns"
    );
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
