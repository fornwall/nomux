//! The frozen control surface against the run directory.
//!
//! `list` and `kill` reach a session only through the five files on disk
//! (`IMPLEMENTATION.md` § 6.6), so everything they can get wrong is here: the spawn
//! lock they must take before removing anything (§ 6.3), the order they remove it
//! in, what they do with a session that is alive — including one that has not said
//! what to signal yet — and the directory those files live in. These tests drive
//! the real binary, because most of that is only wrong across process boundaries.
//!
//! Session ids are kept short on purpose: they carry unix sockets, and
//! `sockaddr_un` truncates the path at 108 bytes. The directory they sit in is
//! [`run_root`]'s business.
//!
//! The last section is the other thing that runs before any session exists:
//! `main.rs`'s own argv dispatch, which has no end-to-end coverage anywhere else.

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

use nomux_protocol::{PROTOCOL_VERSION, RESUME_FROM_START};

use harness::{
    Flock, HeldLock, Reaper, Session, Spawned, collect, collect_by, control, control_with_shell,
    daemon_reaper, entries, leads_a_process_group, nomux, nomux_with_shell, poll_by, poll_until,
    process_alive, run_root, stderr, stdout, still_serving, succeeded, wait_for, wait_until_flock,
    wedge_socket, while_nothing_forks,
};

/// Asserts the one versioned relay record without parsing the human diagnostic beside it.
fn has_relay_class(out: &Output, class: &str, what: &str) {
    let said = stderr(out);
    let records = said
        .lines()
        .filter(|line| line.starts_with("NOMUX-RELAY-ERROR "))
        .collect::<Vec<_>>();
    assert_eq!(
        records,
        [format!("NOMUX-RELAY-ERROR 1 {class}")],
        "{what} carried the wrong machine-readable relay outcome: {said:?}"
    );
}

/// How long any one test here may spend waiting, across every wait it makes.
///
/// One figure per test rather than one per wait, for `harness::poll_by`'s reason.
const PATIENCE: Duration = Duration::from_secs(30);

/// A `list` that finds the spawn lock held leaves the whole entry alone, and
/// collects it on the next pass once the lock is free.
///
/// The two planted names are a later version's sixth file (`rundir::session_id_of`),
/// one on this session and one that is the whole of an id: the sweep has to reach both
/// through a name this build never wrote, which is why the collection below asks for
/// an empty directory rather than for the five.
#[test]
fn a_held_spawn_lock_survives_a_concurrent_list() {
    let session = StaleSession::create("lk1");
    fs::write(session.dir.join("lk1.journal"), b"").expect("plant a later version's file");
    fs::write(session.dir.join("lk2.journal"), b"").expect("plant an id that is nothing else");
    let lock = HeldLock::take(&session.lock_path());

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
    // Over a window rather than on one pass, and not because collection is unreliable:
    // `list` gives the spawn lock up rather than waiting for it (§ 6.6), so anything
    // still holding it leaves the entry correctly alone for that pass. What § 6.6
    // promises is that an entry which stays dead stays collectable, not that any
    // particular pass collects it.
    let collected = poll_until(Duration::from_secs(10), || {
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
    let lock = HeldLock::take(&session.lock_path());

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
    // Success is the whole of the postcondition, here and at every other `succeeded`
    // over a `kill` in this file: the one exit from the locked region that unlinks
    // anything is `rundir::unlink_all_locked`, which answers `Ok` only where every
    // path in its removal order is gone. A `!exists` beside this would restate the
    // status rather than check it, and an assertion that cannot fail is not one.
    succeeded(
        &session.run(&["kill", "lk2"]),
        "kill failed with the lock free",
    );
}

/// Regression: a session socket whose backlog is full parks no mode that connects.
///
/// An `AF_UNIX` `connect` to a listener that has stopped calling `accept` *blocks*
/// rather than being refused (§ 6.3), and all three modes here connect — so with no
/// deadline on that call, one session in that state parked `list`, `kill` and every
/// `attach` on that id inside the kernel with nothing to end the wait. § 6.3 states
/// this as the consequence of the backlog being the host's ceiling, and
/// [`wedge_socket`] reproduces it in two syscalls.
///
/// What each mode does *after* the deadline is the second half of the assertion and is
/// not the same answer: a probe that timed out is not evidence of death (§ 6.3), so
/// `list` reports the session as live with no pid to print, `kill` refuses and leaves
/// every file where it is, and `attach` gives § 10's 126 — found and not this mode's to
/// have — rather than the 127 that would tell `DESIGN.md` § 7's client its own id named
/// nothing here. Collecting on a probe that never reached the socket would be the escape
/// hatch unlinking a session whose daemon is merely busy: all that is known is § 6.6's
/// `unprobeable`, and an entry `list` cannot collect is one it must still print.
#[test]
fn nothing_parks_on_a_socket_whose_backlog_is_full() {
    let deadline = Instant::now() + PATIENCE;
    let session = StaleSession::empty("lk24");
    let _wedged = wedge_socket(&session.socket());
    let ran = |args: &[&str]| {
        collect_by(&mut nomux(&session.root, args), deadline).unwrap_or_else(|| {
            panic!("`nomux {args:?}` parked on a session socket whose backlog is full")
        })
    };

    let listed = ran(&["list"]);
    let killed = ran(&["kill", "lk24"]);
    let attached = ran(&["attach", "lk24"]);

    succeeded(&listed, "list failed");
    assert_eq!(
        stdout(&listed).trim_end().split('\t').nth(1),
        Some("?"),
        "a session that would not answer is still a session, and nothing named a pid \
         for it: {:?}",
        stdout(&listed)
    );
    assert_eq!(
        killed.status.code(),
        Some(1),
        "kill claimed to have removed a session it never established the state of"
    );
    assert!(
        stderr(&killed).contains("could not be probed") && stderr(&killed).contains("backlog"),
        "the refusal must name the state it gave up on, which is the whole of what was \
         established and the only thing anyone can repair: {:?}",
        stderr(&killed)
    );
    assert_eq!(
        attached.status.code(),
        Some(126),
        "a session that would not answer is still a session, so the id was found and \
         merely could not be joined; 127 here is `attach` telling a client that the \
         session it is watching does not exist, which § 7 has it act on as its own \
         mistake: {:?}",
        stderr(&attached)
    );
    assert!(
        stderr(&attached).contains("backlog is full"),
        "and the refusal must name the state it gave up on, since nothing else on \
         this host will say so: {:?}",
        stderr(&attached)
    );
    has_relay_class(&attached, "retryable", "attach on a full session backlog");
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
/// Everything the bind can answer reaches the caller through the exit status, and past
/// the fork there is no caller left to reach: the process somebody waited on has
/// already gone through `_exit(0)`. `ssh -t host 'nomux daemon <id>'` is exactly the
/// shape that forks, per § 6.2, so this is not a corner.
///
/// A dangling symlink is the deterministic way in. `connect` follows it, finds nothing
/// and answers `ENOENT`, which the probe reads as an id nobody is serving; `bind` does
/// not follow it, finds the name taken and answers `EADDRINUSE`. No race, no timing,
/// and the errno arrives strictly between the two. [`leads_a_process_group`] is what
/// forces the fork.
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

/// A spawn lock at a mode no later process would have chosen is still a lock, and the
/// dead session behind it is still collected.
///
/// The mode a lock is *created* at is
/// [`the_lock_and_the_pidfile_are_created_at_0600_whatever_the_umask`]'s business.
/// This is what one already at `0400` costs — a file left by an older release, by a
/// login under `umask 0200`, or by the second implementation of `list` and `kill` that
/// § 6.6 invites. It costs nothing, and deliberately: `rundir::SessionPaths::acquire`
/// opens `<id>.lock` `O_RDONLY`, `flock(2)` needing no particular access mode, so a
/// read-only file is locked exactly as any other. Asking for write would make this the
/// one thing § 6.6 exists to rule out — a session on disk for good, its lock refused
/// and so its entry never collectable.
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
/// `0400`, and from then on nothing can open it `O_RDWR`: neither `list` nor `kill`
/// can take the lock they must hold before they unlink anything (§ 6.6), so a dead
/// session becomes uncollectable for good.
///
/// `0377` is the strictest umask that still leaves a mode to observe: it takes `0600`
/// down to exactly that `0400`, so a suppression that did nothing is visible as a
/// number rather than as an absence. The spawn takes the lock and the daemon it forks
/// publishes the pidfile, so one hostile umask reaches both files through both
/// processes.
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

/// Regression: `kill` waits out an `<id>.pid` the daemon has not published yet.
///
/// § 6.2's bind-to-publish window, in both states it can be caught in. The daemon
/// publishes in two steps — `File::create`, which leaves a zero-length file, and the
/// write that fills it — so the path is first absent and then present and empty, and
/// answering either rather than waiting it out reports a *corrupt* pidfile over a
/// session microseconds from finishing. Neither state needs a hand-started daemon to
/// reach: `spawn` releases the spawn lock as soon as the path *exists*, which the empty
/// file already satisfies, and what reaches the absent one is what
/// `attach::await_publication` does not cover — a publish that outlived the spawn's
/// deadline, and § 6.3's daemon that could not take the lock at all. Absence is also how
/// a collected session reads, so both wrong answers leave the id unkillable through the
/// one surface meant to reach any version of it.
///
/// The pidfile is emptied or removed and put back by hand because the real window is too
/// narrow to lose a race into deliberately; what is under test is what `kill` does while
/// it is open, not how it is arrived at. `<id>.lock` is a different file either way, so
/// one arrangement serves both rows.
#[test]
fn kill_waits_out_a_pidfile_the_daemon_has_not_published_yet() {
    /// An id, what its `<id>.pid` is doing — which is also what says which row fired —
    /// and how to take the published pid back out, leaving the file in that state.
    type Row = (&'static str, &'static str, fn(&Path));

    /// One of those states, held open with its `kill` in flight.
    struct Unpublished {
        says: &'static str,
        session: LiveSession,
        published: String,
        lock: fs::Metadata,
        killing: Spawned,
    }

    let deadline = Instant::now() + PATIENCE;
    // Both rows are put in flight before either is waited on, so the negative below is
    // one 500 ms of wall clock rather than one per row.
    let rows: [Row; 2] = [
        ("lk9", "the pidfile was still empty", |path| {
            fs::write(path, b"").expect("empty the pidfile");
        }),
        ("lk32", "nothing named a pid", |path| {
            fs::remove_file(path).expect("take the pidfile away");
        }),
    ];
    let mut waiting: Vec<Unpublished> = rows
        .into_iter()
        .map(|(id, says, withhold)| {
            let session = LiveSession::create(id);
            let published = fs::read_to_string(session.pid_path()).expect("read the pidfile");
            withhold(&session.pid_path());
            // Stat'ed before `kill` runs, so the file the fence below watches is the one this
            // session already has rather than whatever is at the path by then.
            let lock = fs::metadata(session.run.lock_path()).expect("stat the spawn lock");
            let killing = Spawned::spawn(
                nomux(&session.run.root, &["kill", id])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
            );
            Unpublished {
                says,
                session,
                published,
                lock,
                killing,
            }
        })
        .collect();

    // The window is closed on two conditions rather than on a guess at how long `kill`
    // takes to reach it, and the first of them is the property itself: while the
    // pidfile says nothing, `kill` must still be *running*. That is what a fixed sleep
    // and the fence below cannot assert between them — a `kill` that answered the
    // unpublished file at once would let the fence miss it and fail this test somewhere
    // else, or win the race and pass it having tested nothing. Half a second against a
    // grace of two, so the margin is the wait rather than the scheduler.
    assert!(
        !poll_until(Duration::from_millis(500), || waiting
            .iter_mut()
            .any(|row| !row.killing.is_running())),
        "`kill` returned while {}, so it is answering the publish window rather than \
         waiting it out",
        waiting
            .iter_mut()
            .find_map(|row| (!row.killing.is_running()).then_some(row.says))
            .unwrap_or("the pidfile said nothing")
    );

    for mut row in waiting {
        // And the fence, which says *where* it is waiting. `kill` takes `<id>.lock` and
        // holds it to the end (§ 6.6) strictly before it goes looking for a pid, so a
        // granted `FLOCK` on that inode puts it past the whole `fork`, `exec` and
        // run-directory check and one `connect` and one `open` from the pidfile.
        wait_until_flock(
            Flock::Granted,
            row.lock.dev(),
            row.lock.ino(),
            "`kill` took the spawn lock",
            deadline,
        );
        fs::write(row.session.pid_path(), row.published.as_bytes()).expect("publish the pid");

        assert!(
            poll_by(deadline, || !row.killing.is_running()),
            "`nomux kill` never returned from the publish grace it was waiting out, \
             where {}",
            row.says
        );
        let killed = row
            .killing
            .into_exited()
            .wait_with_output()
            .expect("collect what kill said");

        succeeded(
            &killed,
            &format!("kill refused a session where {}", row.says),
        );
        // The daemon, not its socket. `kill` spins until the socket stops answering and
        // only *then* unlinks it, so a `connect` to a path that is no longer there is
        // false on every exit `succeeded` above lets through — [`LiveSession::is_alive`]
        // cannot fail here, and an assertion that cannot fail is not one. The pid `kill`
        // was told to signal is what had to go, and `/proc` is where that is visible.
        assert!(
            poll_by(deadline, || !process_alive(row.session.pid)),
            "kill reported success with the daemon it was asked to stop still running \
             as pid {}",
            row.session.pid
        );
    }
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
    /// What the refusal must say of what it read, which is also what says which of
    /// the five fired.
    says: fn(u32) -> String,
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
                plant_fifo(&session.pid_path());
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
            repair: |_| {},
            needs_modes: false,
        },
        // `999999999\n` is exactly the pidfile § 6.6 describes, and past any `pid_max`
        // a kernel hands out: a well-formed file naming a daemon that died without
        // unlinking.
        Unidentified {
            id: "lk22",
            stranger: false,
            plant: |session, _| {
                fs::write(session.pid_path(), "999999999\n")
                    .expect("plant a number that names nothing");
                Vec::new()
            },
            says: |_| "999999999 names no process".to_owned(),
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
    // Five rows, each spawning a session and running `kill` twice and `list` twice, and
    // every one of those waits on a `kill` that may sit out two graces. One figure for the
    // table rather than none at all, per [`PATIENCE`]: the rows are independent, so a table
    // that runs past the runner's kill reports nothing about which row was slow.
    let deadline = Instant::now() + PATIENCE;
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
            Instant::now() < deadline,
            "{id} left the table past its deadline, so the rest of it would be decided by \
             nextest's kill rather than by an assertion"
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

/// A socket `kill` could not probe is reported as one, rather than as a session that
/// survived both signals.
///
/// A `connect` refused with `EACCES` is not evidence of death (§ 6.3), so nothing is
/// unlinked on it — but a mode does not change when a process does, so the same
/// `EACCES` also answers the probe *after* a `SIGTERM` the daemon took perfectly well.
/// Reading that as "alive" makes every clause of "still answering after SIGTERM and
/// SIGKILL to pid N, so that pid is not the process serving it" false, sends a
/// `SIGKILL` to a number the kernel may already have handed to somebody else, and
/// wedges the id for good. So only a connection that was *accepted* may escalate or be
/// called an answer; anything else says the errno and refuses to unlink. That the
/// daemon really did stop is the other half of the assertion — the signal was never
/// the broken part.
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
        poll_by(deadline, || !process_alive(session.pid)),
        "the SIGTERM was never the broken part: the daemon must still have gone"
    );
    drop(session.run.run(&["kill", "lk25"]));
}

/// The same unprobeable socket, over a pidfile that names no daemon: what could not be
/// probed is still reported as that, rather than as a session established to be running.
///
/// Every refusal `control::resolve` reaches is worded "session `<id>` is running, but
/// `<id>.pid`: …", and the only thing that ever establishes the opening clause is a
/// connection a daemon accepted. Under an unprobeable socket nothing did (§ 6.3), so the
/// refusal named a state nobody had seen and blamed the file that was not the problem.
///
/// The two rows are what `<id>.pid` can be doing while the probe fails: absent, which is
/// § 6.2's publish window and is waited out, and naming a live process that is positively
/// not this daemon, which is settled on the first pass. They enter `resolve`'s two
/// refusals from opposite ends and must come back with the same account, that account
/// being about the socket rather than about either file.
///
/// Nothing is signalled on either row, which is the difference from
/// [`kill_reports_a_socket_it_could_not_probe_rather_than_a_session_that_outlived_sigkill`]
/// beside it: there `<id>.pid` identifies the daemon, and identifying it through `/proc`
/// owes the probe nothing, so the `SIGTERM` still goes out. Here there is nothing to
/// identify, so both the daemon and the stranger have to still be running afterwards.
///
/// Stands down as root for that test's reason: a mode keeps nobody out of their own
/// socket, so there is no unprobeable socket to report.
#[test]
fn kill_reports_an_unprobeable_socket_over_a_pidfile_that_names_no_daemon() {
    if skip_as_root("a socket at mode 0400 still answers its own user, so nothing is unprobeable") {
        return;
    }
    // One live process for the row whose pidfile has to appear to name something, held
    // across both so the last assertion can ask whether anything was signalled at all.
    let mut bystander = sleeper();
    let stranger = bystander.id();
    let strangers = format!("{stranger}\n");
    for (id, planted) in [("lk27", None), ("lk33", Some(strangers.as_str()))] {
        let session = LiveSession::create(id);
        match planted {
            None => fs::remove_file(session.pid_path()).expect("take the pidfile away"),
            Some(body) => fs::write(session.pid_path(), body).expect("plant a stranger's pid"),
        }
        let before = entries(&session.run.dir);
        // Readable still, so this is the `connect` and nothing else: 0400 takes away the
        // write permission that a `connect` to a unix socket needs, and leaves every
        // other file of the session exactly as the daemon left it.
        fs::set_permissions(session.run.socket(), fs::Permissions::from_mode(0o400))
            .expect("shut the socket to connect");

        let killed = session.run.run(&["kill", id]);
        let left = entries(&session.run.dir);
        // Asked outright rather than waited for: no signal was sent, so there is nothing
        // for the daemon to be on its way out of, and a wait here could only turn the
        // assertion into one that passes for having been quick.
        let serving = process_alive(session.pid);
        drop(fs::set_permissions(
            session.run.socket(),
            fs::Permissions::from_mode(0o600),
        ));

        let said = stderr(&killed);
        assert_eq!(
            killed.status.code(),
            Some(1),
            "{id}: kill claimed a postcondition no probe ever saw: {:?}",
            stdout(&killed)
        );
        assert!(
            said.contains("could not be probed") && said.contains("Permission denied"),
            "{id}: the refusal must name the errno that stopped it, that being the whole \
             of what is known and the only thing anyone can repair: {said:?}"
        );
        assert!(
            serving,
            "{id}: nothing here identified a process, so nothing was this call's to \
             signal: {said:?}"
        );
        assert_eq!(
            left, before,
            "{id}: a session that may be live keeps every one of its files"
        );
        drop(session.run.run(&["kill", id]));
    }
    assert!(
        bystander.is_running(),
        "the one number in a pidfile got signalled over a socket that was never probed"
    );
}

/// A `kill` that cannot pin the process it would signal refuses and leaves the whole
/// session standing — the postcondition on a host whose kernel has no `pidfd_open`.
///
/// `control::pin` has no fallback by design (§ 6.6). The number in `<id>.pid` is reusable,
/// so the only thing `kill` may signal is a descriptor that follows the process it was
/// opened on; where the kernel will not hand one over there is nothing it may signal at
/// all, and the honest answer is a non-zero exit with every file left where it is. The
/// alternative — falling back to `kill(2)` on the bare number — is how the escape hatch
/// terminates an unrelated process of the user's, which is the whole reason the descriptor
/// is taken before `/proc` is even consulted.
///
/// The unit test beside `pin` reaches the same state by building a `Chosen` with a
/// `reach: Err(Errno::MFILE)` of its own, which pins the *sentence* the refusal is worded
/// in. What a fabricated struct cannot say is what the mode around it then does with the
/// run directory, and that is the half this test is here for: the files are still on disk
/// afterwards and the daemon is still serving the shell that was already running behind
/// them. A `kill` that signalled nothing and unlinked anyway would take a live session's
/// socket away without stopping it — the user's work still running, behind an id that
/// appears in no listing and that a second daemon is free to bind over (§ 6.6).
///
/// The injection is a seccomp filter ([`without_pidfd_open`]) rather than a shortage of
/// descriptors. `RLIMIT_NOFILE` cannot reach this path: `pin` needs exactly one free
/// descriptor and so does the liveness probe two statements ahead of it, so every limit low
/// enough to fail the pin fails that `socket` call first — measured, and what comes back
/// then is § 6.6's `unprobeable` about a socket, which says nothing about pinning at all.
/// `ENOSYS` is the truer errno besides: this is the old-kernel case rather than a busy one.
#[test]
fn kill_refuses_and_keeps_the_session_when_the_kernel_will_not_pin_its_process() {
    // One figure for the test, per [`PATIENCE`]: the `kill` below sits out both of § 6.6's
    // graces — the socket answers throughout and neither signal ever lands — and the two
    // clients after it each wait on a shell.
    let deadline = Instant::now() + PATIENCE;
    let (session, mut client, _) = Session::attached("nopidfd");
    // Before anything is killed, so "still serving" below is a claim about the same daemon
    // driving the same shell rather than about one that never had either.
    still_serving(&mut client, "NOMUX-BEFORE-KILL");
    let dir = session.root.join("nomux/run");
    let before = entries(&dir);
    // The number `kill` will actually act on, read the way `kill` reads it — asserting on
    // the child's pid instead would pass a refusal that named some other process.
    let pid = fs::read_to_string(session.pid_file()).expect("read the published pid");
    let pid = pid.trim().to_owned();

    let mut command = nomux(&session.root, &["kill", &session.id]);
    without_pidfd_open(&mut command);
    // Bounded rather than waited on ([`collect_by`], [`PATIENCE`]): a refusal that
    // regressed into a wait for a process that will never be signalled would otherwise
    // hang the run instead of failing it.
    let killed = collect_by(&mut command, deadline)
        .expect("`nomux kill` never came back on a host with no pidfds");
    let said = stderr(&killed);

    assert_eq!(
        killed.status.code(),
        Some(1),
        "a kill that sent no signal at all must not report the session gone: {said:?}"
    );
    // Every clause, because each is a separate claim: which session, that it is answering
    // still, that *neither* signal was sent, which pid went unsignalled, and the errno that
    // says why. The errno is also the evidence that the filter reached `pin` rather than
    // something failing ahead of it — an unprobeable socket or a pidfile that named no
    // daemon are refusals of their own, and neither says any of this.
    for clause in [
        format!("session {} is still answering", session.id),
        format!("neither SIGTERM nor SIGKILL was sent to pid {pid}"),
        "(os error 38)".to_owned(),
    ] {
        assert!(
            said.contains(&clause),
            "the refusal must say that nothing was signalled and why, missing {clause:?}: \
             {said:?}"
        );
    }

    assert_eq!(
        entries(&dir),
        before,
        "not one of the files was a kill that signalled nothing to remove"
    );
    // The files are not the whole of it: a daemon torn halfway down would leave all five
    // names in place and still be gone. So the session is driven again through the client
    // that was already attached, and then through one that attaches from scratch — a
    // daemon that survived but no longer accepts is no more use to the user than one that
    // exited. The first is let go of before the second greets, `Hello` being an
    // unconditional takeover.
    still_serving(&mut client, "NOMUX-AFTER-REFUSED-KILL");
    drop(client);
    let mut reattached = session.connect();
    reattached.hello(RESUME_FROM_START);
    still_serving(&mut reattached, "NOMUX-AFTER-REATTACH");

    // And the other mode still finds it by the same files, which is what a user looking for
    // the session they were told could not be killed would do next.
    let listed = stdout(&control(&session.root, &["list"]));
    assert!(
        listed.contains(&session.id) && listed.contains(&pid),
        "list must still report the session kill declined to collect: {listed:?}"
    );
    assert!(
        Instant::now() < deadline,
        "the test ran past its own deadline, so what it asserted last was decided by \
         nextest's kill rather than by an assertion"
    );
    // The daemon is a child of this process and `Session`'s drop kills it, so refusing to
    // collect it here leaks nothing into the next run.
}

/// Makes `pidfd_open` fail with `ENOSYS` in whatever `command` starts: the whole of what a
/// kernel from before pidfds looks like to `control::pin`.
///
/// A seccomp filter rather than any of the resource shortages the rest of this suite
/// injects, because it is the only one that reaches `pin` *alone*. Every other syscall the
/// mode makes — the `connect` that probes the socket, the `open` that reads the pidfile,
/// the `flock` that holds the id — is left working, so the refusal that comes back is the
/// failure to pin rather than something the mode met earlier and reported instead.
///
/// `PR_SET_NO_NEW_PRIVS` first, which an unprivileged `PR_SET_SECCOMP` requires; both
/// survive the `execve` into `nomux`, and the filter is inherited by anything the child
/// starts — which `kill` never does.
fn without_pidfd_open(command: &mut Command) {
    /// Offset of `seccomp_data.nr`, the syscall number, which is the first word of it.
    const NR_OFFSET: u32 = 0;

    // Assembled here rather than inside the closure: everything between `fork` and `exec`
    // has to be async-signal-safe, and a `try_from` that reports its own failure is a panic
    // path. The array is moved into the closure, so the program the child registers points
    // at the child's own copy of it.
    let load = u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS).expect("a BPF opcode");
    let jump = u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K).expect("a BPF opcode");
    let ret = u16::try_from(libc::BPF_RET | libc::BPF_K).expect("a BPF opcode");
    let call = u32::try_from(libc::SYS_pidfd_open).expect("a syscall number fits a BPF constant");
    let refused = libc::SECCOMP_RET_ERRNO | u32::try_from(libc::ENOSYS).expect("ENOSYS is 38");
    let filter = [
        libc::sock_filter {
            code: load,
            jt: 0,
            jf: 0,
            k: NR_OFFSET,
        },
        // On a match, fall through to the refusal; otherwise skip it for the `allow`.
        libc::sock_filter {
            code: jump,
            jt: 0,
            jf: 1,
            k: call,
        },
        libc::sock_filter {
            code: ret,
            jt: 0,
            jf: 0,
            k: refused,
        },
        libc::sock_filter {
            code: ret,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let len = u16::try_from(filter.len()).expect("four instructions fit a filter length");

    // SAFETY: the closure runs in the forked child before `exec`, so it must be
    // async-signal-safe. `prctl` is, and nothing here allocates or takes a lock. Both calls
    // read only through pointers this frame and the closure own: `program` lives on the
    // child's stack across the call that registers it, and the array it points at is the
    // closure's own capture, which outlives every `pre_exec` invocation.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let program = libc::sock_fprog {
                len,
                filter: filter.as_ptr().cast_mut(),
            };
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const program,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Direct and older daemons can still carry arguments past `MAX_CMDLINE_LEN`. Once the
/// complete `daemon <id>` prefix is present, trailing bytes must not prevent `list` or
/// `kill` from identifying the process.
#[test]
fn a_daemon_started_with_an_over_long_label_is_still_recognised_as_one() {
    let root = run_root("lk20");
    let label = "L".repeat(8192);
    let _started = Spawned::spawn(
        nomux_with_shell(&root, &["daemon", "lk20", "--label", &label])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
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

/// The shape § 6.2's fork can leave behind: a live process that is *not* this
/// session's daemon is answering on `<id>.sock`, and `<id>.pid` names the one that is.
///
/// Nobody asks who is on the other end of a `connect`, so the pid is read out of
/// `<id>.pid` and the stranger goes unsignalled however much it looks like a daemon —
/// a rule that read the socket for a number would signal it here. The socket is still
/// what says whether the session *stopped*, and it is somebody else's and goes on
/// answering after the target has gone, so `kill` unlinks nothing. The refusal must say
/// that `SIGTERM` reached the pinned target and that the later `SIGKILL` found it gone;
/// the socket cannot turn either observation into a claim about the stranger serving it.
///
/// The shape is built rather than provoked: the real creator `_exit`s, so a second
/// daemon's socket is moved over this session's instead.
#[test]
fn kill_signals_what_the_pidfile_names_even_when_another_daemon_answers_on_the_socket() {
    let session = LiveSession::create("lk18");
    // A daemon of its own, in the same run directory and under a different id, whose
    // socket stands in for one an exited creator left behind.
    let other = control_with_shell(&session.run.root, &["spawn", "lk18b"]);
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
            "still answering after SIGTERM to pid {}; SIGKILL could not be sent \
             (No such process",
            session.pid
        )),
        "and it must name the signal that reached the pinned target without claiming the \
         failed escalation was sent: {:?}",
        stderr(&killed)
    );
    assert_eq!(
        left,
        before,
        "a postcondition that was never seen to hold licenses no unlink: {:?}",
        stderr(&killed)
    );
}

/// Regression: no run file can park the control surface in a syscall — and the spawn
/// lock's repair does not buy that at the price of the refusal it replaced.
///
/// **The park** is the oldest half and the one this test is named for. The spawn lock is
/// opened on every creation and collection path, and `open(O_RDONLY)` on a FIFO waits for
/// a writer for ever — before `flock` is even attempted, so outside every lock deadline
/// there is. A FIFO at `<id>.lock` therefore stopped `kill` and `spawn` dead where no
/// timeout could reach them, which is why that open carries `O_NONBLOCK` and why every
/// run below is bounded rather than waited on ([`collect_by`], [`PATIENCE`]).
///
/// **The repair** is what those two modes do with the FIFO now, and it is a deliberate
/// change of contract from the refusal this test used to assert. Nothing § 6.6's layout
/// writes at `<id>.lock` is anything but a regular file, so what is there is nobody's
/// mutex — and every unlink path in `rundir` demands a `&SpawnLock`, which made this the
/// one run name a planted node stranded for good: `kill` failing on the id at every
/// attempt, both collections skipping it in silence and `spawn` calling the host unsafe,
/// until the user noticed and ran `rm`. So the node is cleared, a real lock is created at
/// § 6.3's frozen `0600` in its place, and the session comes up.
///
/// **The refusal** has to survive that, or the reporting path loses its only test. A node
/// the repair *cannot* clear is still named rather than proceeded past, and a non-empty
/// directory is the durable way to be one: `rundir::remove_node` promotes the failed
/// `remove_file` to a `remove_dir`, which refuses a directory with anything in it. No
/// budget and no race is involved, unlike the other survivor — a name replanted faster
/// than one acquirer clears it — so this is the shape that can be asserted exactly.
///
/// `list` is the third mode and owes less than the other two in either half: it may
/// conservatively leave an entry it cannot serialise (§ 6.6), so all that is pinned for it
/// is that it comes back and exits 0.
#[test]
fn no_mode_parks_on_a_planted_spawn_lock_which_is_cleared_where_it_can_be_and_reported_where_it_cannot()
 {
    let deadline = Instant::now() + PATIENCE;
    let root = run_root("lock_plant");
    let dir = root.join("nomux/run");
    fs::create_dir_all(&dir).expect("create the run directory");
    let lock = dir.join("lk_plant.lock");

    // With a shell throughout, because `spawn` below now reaches one: while the FIFO was
    // refused it never could. `list` and `kill` are handed the same command so that no
    // mode here is told something another is not.
    let run = |args: &[&str]| {
        collect_by(&mut nomux_with_shell(&root, args), deadline)
            .unwrap_or_else(|| panic!("`nomux {args:?}` parked on a planted spawn lock"))
    };
    // Re-planted in front of each mode rather than once: `list`'s sweep takes the lock
    // too, so it may clear the FIFO on its way past — the same repair, but not the one the
    // mode after it is supposed to be making. Each has to meet the node itself.
    let replant = || {
        drop(fs::remove_file(&lock));
        plant_fifo(&lock);
    };

    replant();
    succeeded(
        &run(&["list"]),
        "list failed instead of collecting the entry or conservatively skipping it",
    );

    // `kill` against nothing but the FIFO: it clears the name, finds no socket and no pid,
    // and so already has its postcondition — a session that is gone is not an error
    // (§ 10). The zero *is* the repair; the old answer was exit 1 with the id stranded.
    replant();
    let killed = run(&["kill", "lk_plant"]);
    succeeded(&killed, "kill did not clear a FIFO at the spawn lock");
    assert!(
        entries(&dir).is_empty(),
        "kill held the lock, so every name under the id was its to remove: {:?}",
        entries(&dir)
    );

    // The half `kill` cannot show: a startup that goes through the planted node. What the
    // daemon ends up holding has to be a regular file this acquirer created, not whatever
    // was at the name — a FIFO adopted as the mutex would serialise nothing.
    replant();
    succeeded(
        &run(&["spawn", "lk_plant"]),
        "spawn did not clear a FIFO at the spawn lock",
    );
    // Taken before the assertions, so a failure in any of them still collects the daemon:
    // `spawn` leaves it `setsid`ed away where no `Spawned` covers it, and the version of
    // this test that asserted a refusal instead leaked one on every full-suite run.
    let (_pid, _reaper) = daemon_reaper(&root, "lk_plant");
    assert!(
        fs::symlink_metadata(&lock)
            .expect("stat what stands at the spawn lock")
            .file_type()
            .is_file(),
        "the FIFO is gone and a regular file stands where it was: {:?}",
        entries(&dir)
    );
    assert_eq!(
        fs::metadata(&lock)
            .expect("stat the lock")
            .permissions()
            .mode()
            & 0o7777,
        0o600,
        "the replacement carries § 6.3's frozen mode rather than the planted node's"
    );

    // Stopped here rather than left to the reaper, because the refusal half below reuses
    // the id: a daemon still holding it would answer the probe and change what `kill` and
    // `spawn` are being asked.
    succeeded(
        &run(&["kill", "lk_plant"]),
        "kill failed on the session spawn brought up over the cleared lock",
    );
    assert!(
        entries(&dir).is_empty(),
        "and it took the session's files with it: {:?}",
        entries(&dir)
    );

    // What the repair cannot clear is still reported, in the same terms it always was.
    fs::create_dir(&lock).expect("plant a directory at the spawn lock");
    let occupant = lock.join("occupied");
    fs::write(&occupant, b"").expect("make it one `remove_dir` will not take");

    succeeded(
        &run(&["list"]),
        "list failed instead of conservatively skipping the entry",
    );
    let killed = run(&["kill", "lk_plant"]);
    let spawned = run(&["spawn", "lk_plant"]);
    for (mode, expected, output) in [("kill", 1, killed), ("spawn", 126, spawned)] {
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{mode} accepted a spawn lock it could neither hold nor clear: {:?}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("not a regular file"),
            "{mode} did not identify the malformed lock: {:?}",
            stderr(&output)
        );
        if mode == "spawn" {
            has_relay_class(&output, "unsafe-host", "spawn with an unclearable lock");
        }
    }
    assert!(
        occupant.exists(),
        "no mode may empty out a node it never took the lock on: {:?}",
        entries(&lock)
    );
}

/// Regression: no ordinary run file can park the control surface in a syscall.
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
        plant_fifo(&path);
    }

    // Backgrounded against a deadline: the defect is a wait with no end, and a test
    // that waits for it is one that never fails. Both share it ([`PATIENCE`]).
    let listed = collect_by(&mut nomux(&session.run.root, &["list"]), deadline);
    let killed = collect_by(&mut nomux(&session.run.root, &["kill", "lk13"]), deadline);

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
        stdout(&listed)
            .trim_end_matches('\n')
            .split('\t')
            .skip(1)
            .collect::<Vec<_>>(),
        ["?", ""],
        "a FIFO holds no label, and it is no pidfile either: {:?}",
        stdout(&listed)
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

/// Runtime diagnostics cross the same terminal boundary as argv diagnostics.
///
/// The run-directory path comes from the environment and is repeated in refusals. A
/// newline could forge a second diagnostic and an escape sequence could drive the
/// terminal unless the final reporting boundary escapes the complete error, not just
/// command-line parsing errors.
#[test]
fn a_runtime_error_cannot_drive_the_terminal_it_is_printed_to() {
    let root = run_root("runtime_escape").join("line\n\u{1b}]0;forged-title\u{7}");
    fs::create_dir_all(&root).expect("create the hostile runtime root");
    fs::write(root.join("nomux"), b"not a directory").expect("plant a bad run directory");

    let listed = control(&root, &["list"]);
    assert_eq!(
        listed.status.code(),
        Some(1),
        "a bad run directory was accepted"
    );
    let complaint = stderr(&listed);
    let body = complaint
        .strip_suffix('\n')
        .expect("a diagnostic ends in exactly its own line break");
    assert!(
        !body.contains('\n') && !body.contains('\u{1b}') && !body.contains('\u{7}'),
        "a runtime-controlled path emitted terminal controls verbatim: {complaint:?}"
    );
    assert!(
        complaint.contains("line\\n\\u{1b}]0;forged-title\\u{7}"),
        "the escaped refusal no longer identifies the failing path: {complaint:?}"
    );
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
    // The two files the daemon does not publish unless it is asked to, so all five
    // names are on disk and the fold below has the most it will ever have to do.
    let dir = session.root.join("nomux/run");
    fs::write(dir.join(format!("{}.label", session.id)), "five files").expect("plant a label");
    fs::write(dir.join(format!("{}.agent", session.id)), "").expect("plant an agent name");
    assert_eq!(entries(&dir).len(), 5, "all five names on disk");

    let listing = control(&session.root, &["list"]);
    succeeded(&listing, "list failed");
    let listed = stdout(&listing);
    assert!(
        listed.contains(&session.id),
        "list should report the live session, got {listed:?}"
    );
    // One line per session and not per run file: `list` discovers sessions by every
    // run-file name (`rundir::session_id_of`), so this one reaches the loop five
    // times and the fold is the only thing that puts it back together.
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

/// The one session neither mode can act on: an id whose run files this directory cannot
/// form a socket address for (§ 6.3). `list` used to skip it in silence, leaving files
/// nothing would ever name again.
///
/// The directory is deepened here rather than taken as it comes, because what refuses an
/// id is the length of the directory plus the id against `sun_path`'s 107 — so a checkout
/// near the root would otherwise pass this test without ever reaching the case.
#[test]
fn list_reports_an_id_this_run_directory_cannot_address() {
    // The longest id § 6.3 accepts, so what refuses it below is the directory rather
    // than anything about the id itself.
    let id = "a".repeat(64);
    // This path is repeated in the per-entry diagnostic. It crosses a terminal boundary
    // inside `list`, before `main` gets a final error to escape, so make the fixture hostile.
    let root = run_root("unaddressable").join("line\n\u{1b}]0;forged-title\u{7}");
    let deep = deepened_past_sun_path(&root, &id);
    let dir = deep.join("nomux/run");
    fs::create_dir_all(&dir).expect("create a deep run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("owner-only");
    let planted = dir.join(format!("{id}.pid"));
    fs::write(&planted, b"1\n").expect("plant a run file at an unaddressable id");

    let listing = control(&deep, &["list"]);
    succeeded(&listing, "one id it cannot address is not a failed list");
    assert!(
        stdout(&listing).is_empty(),
        "an id nothing can attach to must stay out of § 6.6's three columns, got {:?}",
        stdout(&listing)
    );
    let said = stderr(&listing);
    assert!(
        said.contains(&id),
        "the id has to be named, being the only thing a user can act on: {said:?}"
    );
    assert!(
        !said.contains('\u{1b}') && said.lines().count() == 1,
        "a runtime-controlled path emitted terminal controls verbatim: {said:?}"
    );
    assert!(
        said.contains("\\n") && said.contains("\\u{1b}"),
        "the escaped refusal no longer identifies the failing path: {said:?}"
    );
    assert!(
        planted.exists(),
        "and its files are left where they are: a path that cannot be probed is not \
         evidence that nothing is listening"
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
    wait_for(&root.join("nomux/run").join("labelled.label"));
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

/// Every mode that resolves a run directory establishes that it is this user's alone
/// *before* it trusts a name in it — including the two that only read.
///
/// The directory holds a socket, a pidfile and a label somebody else planted, and it is
/// one this user does not have to itself in each of the two ways § 6.3 rules out
/// ([`Planted`]). That is the whole attack: `attach` connecting first and checking
/// afterwards relays the user's keystrokes into a socket somebody else is listening on,
/// `list` prints their label to the user's terminal, `kill` reads their number out of the
/// pidfile and signals it, and `spawn` and `daemon` `chmod` the directory and bind inside
/// it. `rundir`'s unit tests own the decision; this is the consequence, which is the half
/// a user sees — and it is the same consequence whether the way in took an attacker or a
/// umask.
///
/// The owed code is § 10's, and the tables differ: `spawn` and `attach` report 126,
/// which `DESIGN.md` § 7 has the client cache the whole host as unattachable on, so
/// 127 would have it retry a host that can never work and 1 would have it give up on
/// none. On the other table everything that is not a malformed command line is 1. Both
/// rows owe the same numbers, the refusal happening before any mode has done anything
/// that could tell them apart.
#[test]
fn a_run_directory_this_user_does_not_own_is_refused_by_every_mode_that_resolves_one() {
    // One deadline for the whole table, per [`PATIENCE`]: ten runs of a binary that must
    // refuse before it starts anything, and a bound per run would be ten times it.
    let deadline = Instant::now() + PATIENCE;
    for (name, how) in [("lk7", Planted::Symlink), ("lk34", Planted::WorldWritable)] {
        let planted = PlantedRunDir::create(name, how);
        let before = entries(&planted.dir);

        for (mode, owed) in [
            (vec!["spawn", "imp"], 126),
            (vec!["attach", "imp"], 126),
            (vec!["daemon", "imp"], 1),
            (vec!["list"], 1),
            (vec!["kill", "imp"], 1),
        ] {
            let out = planted.run(&mode, deadline);
            assert_eq!(
                out.status.code(),
                Some(owed),
                "{name}: {mode:?} must refuse this run directory with {owed}: {:?}",
                stderr(&out)
            );
            assert!(
                stderr(&out).contains("run directory") && stderr(&out).contains(how.says()),
                "{name}: {mode:?} must say what it refused and why, naming {:?}: {:?}",
                how.says(),
                stderr(&out)
            );
            assert!(
                out.stdout.is_empty(),
                "{name}: {mode:?} printed a planted entry: {:?}",
                stdout(&out)
            );
            if matches!(mode[0], "spawn" | "attach") {
                has_relay_class(
                    &out,
                    "unsafe-host",
                    &format!("{name}: {mode:?} on an untrusted run directory"),
                );
            }
        }

        assert!(
            planted.nothing_connected(),
            "{name}: the relay handed the session over to a socket somebody else planted"
        );
        assert_eq!(
            entries(&planted.dir),
            before,
            "{name}: nothing may be created in a directory this refused"
        );
        assert_eq!(
            fs::symlink_metadata(&planted.dir)
                .expect("stat the planted directory")
                .permissions()
                .mode()
                & 0o7777,
            0o777,
            "{name}: a mode nomux refused is not a mode nomux may repair — tightening it \
             now would leave whatever is already planted inside exactly where it is"
        );
        assert!(
            Instant::now() < deadline,
            "{name} left the table past its deadline, so the rest of it would be decided \
             by nextest's kill rather than by an assertion"
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

// ---- `main.rs`'s argv dispatch, which reaches no run directory and no session ----

/// An id that could never have named a session is a malformed command line rather
/// than a session that would not have us.
///
/// Both of § 10's sources of 64, which are not the same claim: an id no run directory
/// could ever hold, and one *this* run directory has no room for — a property of the
/// directory rather than of the id, a 64-byte id being § 6.3's longest legal one. A
/// client caches "unattachable" per host on 126 and retries on 127, so either of them
/// arriving as one of those numbers would be wrong and uncaught.
///
/// Through `spawn`, which is the mode with something to lose by getting the order
/// wrong: it is the one that goes on to `ensure_run_dir`, so a refusal that came after
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
    // Deepened for the last row, per [`deepened_past_sun_path`]. Nothing is created
    // along the way — the refusal precedes every syscall that would.
    let long = "a".repeat(64);
    let deep = deepened_past_sun_path(&root, &long);

    for (root, id, says) in [
        (&root, "../escape", "invalid session id"),
        (&root, "with/slash", "invalid session id"),
        (&root, "with space", "invalid session id"),
        (&deep, long.as_str(), "is too long for"),
    ] {
        let output = control(root, &["spawn", id]);
        // The exit status, not merely a non-zero one: § 10 gives a malformed
        // invocation `EX_USAGE`, and the distinction is the whole behaviour.
        assert_eq!(
            output.status.code(),
            Some(64),
            "id {id:?} should be refused as EX_USAGE, got {:?}: {:?}",
            output.status,
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(says),
            "id {id:?} should be rejected by name, saying {says:?}: {:?}",
            stderr(&output)
        );
        assert!(
            stderr(&output)
                .lines()
                .all(|line| !line.starts_with("NOMUX-RELAY-ERROR ")),
            "command usage is outside the runtime relay-error set: {:?}",
            stderr(&output)
        );
        assert!(
            !root.join("nomux").exists(),
            "id {id:?} brought the run directory it would have lived in into existence"
        );
    }
}

/// The private startup descriptor is still argv and therefore hostile input on a direct
/// invocation. Claiming a closed number as an `OwnedFd` makes Rust abort when it drops the
/// value; it must instead be rejected as the ordinary bad descriptor that it is.
#[test]
fn a_closed_inherited_lock_descriptor_is_reported_without_aborting() {
    let root = run_root("lk-invalid-fd");
    let refused = control(
        &root,
        &["daemon", "lk-invalid-fd", "--lock-fd", "2147483647"],
    );

    assert_eq!(
        refused.status.code(),
        Some(1),
        "an invalid inherited descriptor must be a reported runtime failure, not a signal or an \
         I/O-safety abort: {:?}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("Bad file descriptor"),
        "the refusal should preserve the kernel's actionable diagnosis: {:?}",
        stderr(&refused)
    );
}

/// The two answers a client gets out of this binary before it has a session: the
/// protocol revision, and 64 for a command line that makes no sense.
///
/// `--version` carries the revision taken from `nomux` rather than written out
/// here: pinning the number would make bumping the protocol a two-file change and say
/// nothing about whether the binary reports the one it speaks.
///
/// These ways of reaching `EX_USAGE` (§ 10) are here because they are different
/// code: an argument a mode that takes none was given, a mode that does not exist, a
/// `--label` offered to either session mode that cannot record one — an attaching caller
/// may still believe it creates the session, while a killing caller is otherwise silently
/// ignored — and an id beginning with `-`, which
/// `main` reads as an option before any mode sees it. None may put anything on stdout,
/// where a client parses the bootstrap line, and each must name what it objected to,
/// since the usage text behind it describes five modes and says nothing about which
/// one the caller got wrong.
///
/// 126 and 127 are `attach.rs`'s: § 10 defines them by what a real relay met, so
/// reaching either honestly means a mode that may go on to serve and so cannot come
/// through [`control`].
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
            vec!["kill", "lk10", "--label", "ignored intent"],
            "a label offered to the mode that cannot record it",
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

    // Output is an I/O boundary too. Rust's print macros panic on these writes; the release
    // profile turns that into an abort, obscuring the mode's stable status with signal death.
    for mode in ["--version", "--help"] {
        let full = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open a sink that refuses writes");
        let mut command = nomux(&root, &[mode]);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(full))
            .stderr(Stdio::null());
        let failed = collect(&mut command);
        assert_eq!(
            failed.status.code(),
            Some(1),
            "{mode} must report its failed stdout without panicking"
        );
    }

    // Each stderr reporter keeps the status its caller acts on when the diagnostic itself
    // cannot be delivered: argv usage, a classified relay refusal, and a runtime usage error.
    for (args, expected) in [
        (["frobnicate"].as_slice(), 64),
        (["attach", "missing"].as_slice(), 127),
        (["kill", "bad.id"].as_slice(), 64),
    ] {
        let full = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open a sink that refuses writes");
        let mut command = nomux(&root, args);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(full));
        let failed = collect(&mut command);
        assert_eq!(
            failed.status.code(),
            Some(expected),
            "{args:?} lost its stable status when stderr failed"
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
        let dir = root.join("nomux/run");
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

    fn run(&self, args: &[&str]) -> Output {
        control(&self.root, args)
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
        let started = control_with_shell(&run.root, &["spawn", id]);
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

/// How a run directory comes to be one this user does not have to itself.
///
/// Two ways in, and `rundir::check_run_dir` answers them from opposite ends — the
/// `open` that will not resolve the name, and the `fstat` of the directory it did
/// open. The consequence is one thing either way, which is why they share the table
/// below: a stranger's label printed to the user's terminal, a stranger's number
/// signalled out of the pidfile, and a stranger's socket handed the user's keystrokes.
#[derive(Clone, Copy)]
enum Planted {
    /// A symlink into a directory anybody can write to. The pointed-at mode is
    /// nothing `nomux` may repair, and following the link would `chmod` and bind
    /// inside somebody else's directory.
    Symlink,
    /// The run directory itself, world-writable. No attacker and no symlink needed:
    /// one login under a lax umask leaves `~/.local/state/nomux/run` at `0777`, after
    /// which anybody on the host can create names in it. Tightening it now would not
    /// un-plant what is already there, so § 6.3 refuses rather than repairs.
    WorldWritable,
}

impl Planted {
    /// What the refusal has to say, which is also what says which row fired.
    const fn says(self) -> &'static str {
        match self {
            Self::Symlink => "it is a symlink",
            Self::WorldWritable => "lets other users create files in it",
        }
    }
}

/// A run directory that is not this user's alone ([`Planted`]), with a session's files
/// already planted in it.
///
/// The socket is bound by this process and stays bound, so anything that connects
/// to it reaches the test rather than a refused connection — which is the whole
/// point: a refusal would look like the same "stale socket" every other test uses.
struct PlantedRunDir {
    root: PathBuf,
    /// The directory the planted files are in — what the link points at, or the run
    /// directory itself — so a test can ask what was done to it.
    dir: PathBuf,
    listener: UnixListener,
}

impl PlantedRunDir {
    fn create(name: &str, how: Planted) -> Self {
        let root = run_root(name);
        fs::create_dir_all(root.join("xdg")).expect("create the runtime directory");
        // `XDG_RUNTIME_DIR` is `<root>/xdg`, so `<root>/xdg/nomux` is the name every
        // mode resolves. What is at it is the whole of the difference between the rows.
        let dir = match how {
            Planted::Symlink => {
                let theirs = root.join("theirs");
                fs::create_dir_all(&theirs).expect("create the planted directory");
                std::os::unix::fs::symlink(&theirs, root.join("xdg/nomux"))
                    .expect("plant the symlink");
                theirs
            }
            Planted::WorldWritable => root.join("xdg/nomux"),
        };
        fs::create_dir_all(&dir).expect("create the planted directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))
            .expect("make it world-writable");

        let listener = UnixListener::bind(dir.join("imp.sock")).expect("plant a socket");
        listener
            .set_nonblocking(true)
            .expect("planted socket must not block the test");
        fs::write(dir.join("imp.pid"), "999999999\n").expect("plant a pidfile");
        fs::write(dir.join("imp.label"), "planted").expect("plant a label");
        Self {
            root,
            dir,
            listener,
        }
    }

    /// Runs one mode against the planted directory, giving up on one that will not
    /// come back.
    ///
    /// A relay that has been handed the planted socket does not exit: it has a peer
    /// that never closes and nothing to make it stop waiting. The bound is what
    /// turns the defect this test is about into a failed assertion rather than a
    /// test run that never ends.
    ///
    /// With a shell even for `list` and `kill`, because the three modes they share
    /// this with are the ones that must not reach one — and if any ever does, it
    /// should find a predictable `/bin/sh` rather than whatever the developer logs in
    /// with.
    ///
    /// The deadline is the caller's, per [`collect_by`] and [`PATIENCE`]: the caller below
    /// makes five of these calls, and a fresh bound each would let one test spend five
    /// times it — past the runner's own kill, which reports no assertion at all.
    fn run(&self, args: &[&str], deadline: Instant) -> Output {
        let mut command = nomux_with_shell(&self.root.join("xdg"), args);
        // This fixture specifically tests the runtime fallback; the general harness
        // pins persistent XDG state so a later HOME for the child cannot move it.
        command.env_remove("XDG_STATE_HOME").env_remove("HOME");
        collect_by(&mut command, deadline).unwrap_or_else(|| {
            panic!(
                "`nomux {args:?}` never returned, so it is still relaying to a \
                     socket somebody else planted"
            )
        })
    }

    /// Whether the planted socket was left entirely alone. Asked only after the
    /// process under test has exited, so a pending connection would already be in
    /// the listener's backlog.
    fn nothing_connected(&self) -> bool {
        matches!(self.listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
    }
}

/// Plants a FIFO at `path`, where the control surface expects a regular file — the
/// shape that used to park a mode in `open(2)` until somebody wrote to it.
fn plant_fifo(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
        0,
    )
    .expect("plant a FIFO where a run file should be");
}

/// Deepens `root` until `<root>/nomux/run/<id>.label` runs past `sun_path`'s 107
/// bytes: what refuses an id is the length of the directory plus the id against that
/// limit, so a checkout near the root would otherwise pass the tests about an
/// unaddressable id without ever reaching the case.
fn deepened_past_sun_path(root: &Path, id: &str) -> PathBuf {
    let mut deep = root.to_path_buf();
    while deep.as_os_str().len() + "/nomux/run/".len() + id.len() + ".label".len() <= 107 {
        deep.push("pad");
    }
    deep
}

/// Binds `path` and leaves it answering nothing, which is what stale means in
/// § 6.6: the socket a daemon killed with `SIGKILL` leaves in the run directory,
/// where only a refused `connect` distinguishes it from a session still in use.
///
/// The `shutdown` is the whole of the difference, and it is not belt and braces: a
/// listening socket goes on accepting for as long as *any* descriptor onto it
/// survives, and another test's `fork` in flight is holding one. `shutdown` belongs
/// to the socket rather than to the descriptor, so no duplicate can undo it.
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
