//! End-to-end tests against `nomux spawn` and `nomux attach`: the bootstrap each of
//! them does, and the relay they share.
//!
//! One relay and two answers to an id nothing is serving (`DESIGN.md` § 5.1), so the
//! bootstrap half is per mode and is mostly a table of refusals: an id `spawn` finds
//! taken, an id `attach` finds empty, and the exit status `IMPLEMENTATION.md` § 10
//! owes each of them. The refusals these two share with `list` and `kill` — a run
//! directory nobody may use, a socket whose backlog is full — are `control.rs`'s,
//! where the whole table is in one place. What is left is the one creation this suite
//! performs over the relay rather than by running `nomux daemon` directly — a daemon
//! under the flock, and the conversation behind it.
//!
//! The relay half is § 7 and belongs to neither mode: the byte pipe between the
//! client's stdio and the session socket, and every way it has to leave. Those tests
//! start no daemon at all. The relay parses nothing, so a socket the test binds itself
//! is a complete peer, the assertions are about bytes rather than about the protocol,
//! and `attach` is what they run — a session is already there, which is exactly what
//! that mode asks for.

#![allow(
    clippy::expect_used,
    reason = "the allow-expect-in-tests setting in clippy.toml reaches `#[test]` \
              bodies and `#[cfg(test)]` modules, not the helpers an integration \
              test crate keeps beside them"
)]

mod harness;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux::{Frame, RESUME_FROM_START};

use harness::{
    Rng, SETTLE, Session, Spawned, accept_within, collect, control, daemon_reaper, entries,
    has_unread_bytes, hello_frame, join_before, nomux, nomux_with_shell, poll_by, poll_until,
    process_state, read_uninterrupted, run_root, shrink_send_buffer, stderr, stdout, still_serving,
    succeeded, wedge_socket, while_nothing_forks, write_frame,
};

/// A daemon that cannot publish `<id>.pid` refuses to start rather than serving a
/// session nothing can find.
///
/// The pidfile is what `nomux kill` reads to know what to signal (§ 6.6), so a
/// daemon that carried on without one would hold the user's shell behind a socket
/// `list` reports as live and `kill` cannot stop — the worst of the states § 6.6
/// exists to make impossible. Nothing exercised that `?`: every other way of
/// refusing to start is on the *bind*, which happens first, so the whole window
/// between binding a socket and publishing the pid was untested.
///
/// What it leaves behind is asserted too, because that is the half a refusal cannot
/// tidy up itself: the socket is already bound when the failure happens, and it is
/// the one file whose presence is how everything else decides a session exists. A
/// `connect` to it is refused, which § 6.6 defines as stale, so the next `list` is
/// what collects it — and does not report a session in the meantime.
#[test]
fn a_daemon_that_cannot_publish_its_pidfile_refuses_to_start() {
    let root = run_root("nopid");
    let run_dir = root.join("nomux");
    fs::create_dir_all(run_dir.join("nopid.pid"))
        .expect("plant a directory where the pidfile goes");

    // Waited out rather than backgrounded, which is safe only because the refusal is
    // what this asserts: a regression that got past it would hang here rather than
    // fail, and `SHELL` is set so that what it started would at least be predictable.
    let refused = collect(
        nomux_with_shell(&root, &["daemon", "nopid"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    // No phrase to look for: `write_pid` propagates the bare `io::Error` from
    // `fs::write`, so the line names no path.
    refuses(&refused, 1, "", "a daemon that cannot publish its pidfile");

    let listed = control(&root, &["list"]);
    succeeded(
        &listed,
        "list over the wreckage of a daemon that never started",
    );
    assert!(
        !stdout(&listed).contains("nopid"),
        "a session that never started must not be listed as one: {:?}",
        stdout(&listed)
    );
    assert!(
        !run_dir.join("nopid.sock").exists(),
        "the socket the refusal left bound is stale by § 6.6's own test — a refused \
         connect — so `list` must have collected it"
    );
}

/// The other half of the relay's exit table: a session that is not there and could
/// not be started is 127, the shell's "not found" (`IMPLEMENTATION.md` § 10).
///
/// The set matters more than any one number. `DESIGN.md` § 7 has the client cache a
/// host as *unattachable* on 126, go on trying on 127, and read 1 as this attempt alone
/// having failed — "stop", "try again", and "nothing follows about the session" — so
/// the three arms of `main::report_relay`'s match are three different things a client
/// does next. Until these tests, nothing in the suite would have noticed any two of
/// them swapped, or all three collapsed into whichever arm that match reached first.
/// The third is
/// [`a_relay_that_fails_mid_stream_is_not_a_host_the_client_gives_up_on`].
///
/// `spawn`'s now that `attach` starts nothing, and the row it exercises is the one
/// only `spawn` can reach: `TimedOut`, a daemon that never came up. § 10 puts that on
/// the same number as the session `attach` refuses to invent, which is the whole of
/// what the two have in common — one "not found" about a session and one about
/// bringing a session into being, and a client that has to try again either way.
///
/// A directory where the socket goes is a daemon that cannot start rather than one
/// that is slow: `connect` to a non-socket is refused, which `spawn` reads as an id
/// nobody is serving and answers by spawning, and the daemon's own `bind_socket` then
/// finds something at the path it cannot remove. So the timeout below is reached with
/// the daemon's complaint in hand rather than by waiting out a race.
#[test]
fn spawn_reports_a_session_it_could_not_start_as_no_such_session() {
    let root = run_root("spawn_nostart");
    fs::create_dir_all(root.join("nomux").join("nostart.sock"))
        .expect("plant a directory where the session socket goes");

    let refused = collect(
        nomux_with_shell(&root, &["spawn", "nostart"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    // No phrase: the number is the row under test, the wording being the failure's own.
    refuses(
        &refused,
        127,
        "",
        "spawn on a session that could not be started",
    );
}

/// `spawn` refuses an id something is already serving, rather than putting a second
/// shell behind the same name.
///
/// The whole of what the split buys, seen from the creating side. Attach-or-create
/// was one mode with two answers and no way to tell which it had given, and both
/// answers were wrong somewhere: a client racing itself produced two daemons fighting
/// over one socket path, and a client whose session had been reaped got a brand-new
/// shell it had no way to distinguish from the old one. 126 rather than 127 because
/// the id was *found* and is simply not this invocation's to have — the number
/// `DESIGN.md` § 7 has the client stop on rather than retry, since retrying meets the
/// same live session.
///
/// The incumbent is asked to prove it is unharmed afterwards, because a refusal that
/// took it down with it would be worse than the creation it prevented: `create`
/// connects before it refuses, and § 6.4 is what makes that probe free — a connection
/// is promoted on its `Hello` and never on the `connect`, so a client already
/// attached cannot be evicted by somebody else's mistyped command.
#[test]
fn spawn_refuses_an_id_something_is_already_serving() {
    let session = Session::start("spawn_taken");

    let refused = collect(
        nomux_with_shell(&session.root, &["spawn", &session.id])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );

    refuses(
        &refused,
        126,
        "already exists",
        "spawn on an id something already answers for",
    );

    let mut client = session.connect();
    client.hello(RESUME_FROM_START);
    still_serving(&mut client, "NOMUX-SURVIVED");
}

/// Regression: a session whose backlog is full is a session, so `spawn` must report it
/// as one and must not take its `<id>.lock` away.
///
/// A daemon that has stopped calling `accept` is alive in every sense the layout cares
/// about: it holds the socket, it holds the user's shell, and a client already attached
/// is still being served. What it does not do is answer a probe — an `AF_UNIX` `connect`
/// to a full backlog blocks rather than being refused, so `usock::connect_within` gives
/// up after two seconds and reports `TimedOut`, which is evidence that somebody bound
/// this socket and is therefore evidence of *life*.
///
/// `spawn` read it as neither and got both halves of the answer wrong. The refusal came
/// back as 127, which `DESIGN.md` § 7 has the client cache as "nothing here" and come
/// back for, over a session that is merely busy; and the one release point keyed on
/// `AlreadyExists` alone, so a probe that had established nothing was treated as one
/// that had established death and `<id>.lock` was unlinked — a run file of a live
/// session, which § 6.6 forbids outright. Mutual exclusion survived it, `SpawnLock`
/// re-checking the file at the path, so nothing louder than this would ever have said
/// so.
///
/// Both halves are asserted because they fail apart: renaming the refusal without moving
/// the unlink still destroys the file, and moving the unlink without renaming the
/// refusal still sends the client away. The whole directory is compared rather than the
/// one name, which is also what says no second daemon was started behind an id that
/// already has one, and the refusal is made to name the backlog because nothing else on
/// this host says what it gave up on. `attach`'s row against the same wedge is
/// `control.rs`'s, that being where the refusals the relay modes share with `list` and
/// `kill` live.
#[test]
fn spawn_refuses_a_wedged_session_without_unlinking_the_lock_it_took() {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root("spawn_wedged");
    let dir = root.join("nomux");
    fs::create_dir_all(&dir).expect("create the run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .expect("tighten the run directory");
    // Both ends held to the end of the test: `wedge_socket` says why letting either go
    // turns the block this is about back into an ordinary refusal.
    let _wedged = wedge_socket(&dir.join("wedged.sock"));

    let refused = collect(
        nomux_with_shell(&root, &["spawn", "wedged"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let left = entries(&dir);

    refuses(
        &refused,
        126,
        "backlog is full",
        "spawn on an id something is holding but will not answer",
    );
    assert_eq!(
        left,
        ["wedged.lock", "wedged.sock"],
        "a probe that established nothing is licence for no unlink (§ 6.6) and for no \
         second daemon, so a wedged session must be left exactly as it was found, plus \
         the lock this spawn took"
    );
}

/// `attach` refuses an id nothing answers for instead of inventing a session behind
/// it — and starts nothing on the way to saying so.
///
/// The refusal is the point and the silence is what makes it one: attach-or-create
/// answered an id whose session had been reaped with a fresh shell under the same name
/// and nothing to say so. 127 is the shell's "not found", which `DESIGN.md` § 7 has the
/// client read as "try again" rather than as a host to give up on.
///
/// Both spellings of "nothing answers", because they reach the refusal through
/// different code and only one of them was ever a refusal: a run directory this host
/// has never made, where `check_run_dir` answers `false`, and one that exists and
/// holds no such session, where the `connect` does. The first is why `attach` had to
/// stop calling `ensure_run_dir` — being asked to join a session must not be what brings
/// the directory it would have lived in into existence, which is `list` and `kill`'s
/// rule (§ 6.3) and is now this mode's too.
#[test]
fn attach_refuses_an_id_nothing_answers_for_rather_than_inventing_a_session() {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root("attach_ghost");
    let dir = root.join("nomux");

    for expect_dir in [false, true] {
        if expect_dir {
            fs::create_dir_all(&dir).expect("create the run directory");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("tighten the run directory");
        }
        let describing = if expect_dir {
            "a run directory holding no such session"
        } else {
            "a host that has never held a session"
        };

        let refused = collect(
            nomux_with_shell(&root, &["attach", "ghost"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
        // Read before anything is collected below, since what these say is the whole
        // assertion: whether the refusal created the directory, and what it left in
        // one that was already there.
        let made_a_directory = dir.exists();
        let left = entries(&dir);
        // And collected before the assertions, because a failure here means a daemon
        // *was* started — `setsid`ed away, where nothing in this file reaches it.
        drop(control(&root, &["kill", "ghost"]));

        refuses(
            &refused,
            127,
            "no session",
            &format!("attach on {describing}"),
        );
        assert_eq!(
            made_a_directory, expect_dir,
            "attach on {describing} created the run directory it was only asked to \
             look in"
        );
        assert!(
            left.is_empty(),
            "attach on {describing} published something for a session it refused to \
             start: {left:?}"
        );
    }
}

/// The refusal § 10 owes an invocation, whole: the exit code, a stderr line naming
/// which refusal this is, and a stdout nothing has been written to.
///
/// One property in three clauses, each read by somebody different. The code is what
/// `DESIGN.md` § 7 has the client branch on — 126 "stop", 127 "try again" — and the user
/// never sees it; `must_say` is what the *user* gets, and it has to name which of the
/// refusals sharing that number this was, since that and not the number is what says
/// whether the repair is `nomux attach`, a different id, or a retry; and stdout is where
/// § 5.1 has the client read its bootstrap line, so a refusal must leave it alone rather
/// than put a byte there for a client to read as the session it was just denied.
///
/// `what` names the invocation, so a failure inside a loop over cases says which case it
/// was. An empty `must_say` asks only that it said something, which is all a refusal
/// carrying a bare `io::Error` can promise.
fn refuses(out: &Output, code: i32, must_say: &str, what: &str) {
    let (said, wrote) = (stderr(out), stdout(out));
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what} must be refused with exit {code}: {said:?}"
    );
    assert!(
        !said.is_empty() && said.contains(must_say),
        "{what} must say so, naming {must_say:?}: {said:?}"
    );
    assert!(
        wrote.is_empty(),
        "{what} must leave stdout alone: {wrote:?}"
    );
}

/// Exercises the path a real bootstrap takes: `nomux spawn` on an id nothing is
/// serving, which must start a daemon under the flock and then carry the
/// conversation.
///
/// The only end-to-end coverage of a session created over the relay. `Session::start`
/// everywhere else in this suite runs `nomux daemon` directly, which is a fork this
/// process performs and waits on — so the fork, the `setsid`, the flock and the
/// wait-for-the-socket that `spawn` does on the user's behalf are exercised here and
/// nowhere else.
///
/// Named for what it asserts. It used to say "relays transparently", and what it
/// looks for is a substring in a byte stream — which says the frames got through in
/// *some* form and nothing about transparency. That property has a test of its own
/// and it is byte-exact; this one is about the spawn, and the round trip through the
/// child is how it establishes that the daemon it started is really serving.
#[test]
fn spawn_starts_a_daemon_for_a_session_that_does_not_exist_yet() {
    use std::sync::mpsc;

    let root = run_root("relay");
    let mut child = Spawned::spawn(
        nomux_with_shell(&root, &["spawn", "relay_probe"])
            .env("NOMUX_RING_BYTES", "65536")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );

    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    // ChildStdout has no read timeout, so pump it on a thread and let the test
    // bound its own patience.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let pump = thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk) {
                // The rule `harness::read_uninterrupted` states, one layer out: a
                // signal ending this read would close the channel and fail the test
                // for something that happened to the process rather than to the relay.
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(chunk[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    write_frame(&mut stdin, &hello_frame(false, false, RESUME_FROM_START));
    write_frame(
        &mut stdin,
        &Frame::Input {
            offset: 0,
            data: b"echo NOMUX-$((6*7))-RELAY\n",
        },
    );
    stdin.flush().expect("flush");

    let deadline = Instant::now() + RELAY_PATIENCE;
    // The relay connected before it wrote anything, and `spawn` returns from `create`
    // only once the daemon is answering — which § 6.2 puts one step before the
    // pidfile — so this wait is over before it starts unless no daemon was started at
    // all. That case is the one the assertion at the foot of this test is about, and
    // it is reported here instead: a leak is not possible where there is nothing to
    // leak, and "the daemon never created relay_probe.pid" says the same thing.
    let (_pid, _reaper) = daemon_reaper(&root, "relay_probe");

    let mut seen = Vec::new();
    // A byte pipe, so the marker arrives inside the Output frames unparsed; the
    // arithmetic is what keeps the echoed command line from satisfying it.
    let found = poll_by(deadline, || {
        while let Ok(bytes) = rx.try_recv() {
            seen.extend_from_slice(&bytes);
        }
        String::from_utf8_lossy(&seen).contains("NOMUX-42-RELAY")
    });

    drop(stdin);
    drop(child);
    drop(pump.join());

    drop(control(&root, &["kill", "relay_probe"]));

    assert!(
        found,
        "spawn did not start a daemon and relay its output; saw {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// `spawn` starts the binary it is running, not whatever is at the path it was
/// started under.
///
/// The `exec` resolves the install path a second time, so between this process's load
/// and its daemon's whatever is in that directory decides what the daemon *is* —
/// `DESIGN.md` § 8's reason for keeping another uid in scope, and a window
/// `IMPLEMENTATION.md` § 5.2's own `mv -f` reaches with nobody hostile in it. Only that
/// second exec is closed here; the first ran out of the directory already.
///
/// Nothing is raced. `create` blocks on `<id>.lock` before it forks (§ 6.3), so the
/// swap goes in while the spawn is parked there, and it goes in after `Spawned::spawn`
/// has returned — which is to say after the relay's own `exec`, so the binary being
/// replaced is no longer the one the relay would run.
///
/// Two ways to fail and the marker is what separates them, which is why it is asserted
/// on rather than merely waited for. A `rename` leaves the replaced inode reachable
/// through no name, so this kernel answers the relay's own `/proc/self/exe` with
/// `… (deleted)` and a path re-read there resolves to nothing at all: what that costs
/// is a daemon that never starts, and only a path that still resolved would cost the
/// plant *running*. Which of the two a host gives is the kernel's to decide and not
/// this code's to promise, so neither is left unnamed.
///
/// The `kill` at the end is the other half. `argv[0]` is what the exec'd program is no
/// longer spelled as, and § 6.6 identifies a daemon from `/proc/<pid>/cmdline`, so a
/// session that could not be collected here would be one this fix had made
/// unreachable.
#[test]
fn spawn_starts_the_binary_it_is_running_not_the_one_now_at_its_path() {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root("spawn_swapped_exe");
    let dir = root.join("nomux");
    fs::create_dir_all(&dir).expect("create the run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .expect("tighten the run directory");

    // The file `create` takes before it goes anywhere near the fork, held until the
    // swap below is in place.
    let lock = fs::File::create(dir.join("swapped.lock")).expect("create the spawn lock");
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .expect("hold the spawn lock");

    // A copy under a path this test owns: the swap is `mv` over the installed binary,
    // which is § 5.2's own install step and not something to do to `target/`.
    //
    // Under the gate, because the very next thing done to this path is an `exec` of it:
    // a `fork` elsewhere in the process while the copy holds it open for writing carries
    // a duplicate of that descriptor until it `exec`s, and a file with a writer is one
    // `execve` answers `ETXTBSY`. Measured as one failure in eleven `cargo test` runs,
    // where a test binary is threads rather than processes and there is something else
    // to fork.
    let installed = root.join("nomux-installed");
    while_nothing_forks(|| {
        fs::copy(env!("CARGO_BIN_EXE_nomux"), &installed).expect("install a binary of our own")
    });

    let relay = Spawned::spawn(
        Command::new(&installed)
            .args(["spawn", "swapped"])
            .env("XDG_RUNTIME_DIR", &root)
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    // Waited for rather than read once. `Command::spawn` resumes this thread from
    // inside the child's `execve`, and the kernel completes that wakeup before it
    // installs the new `exe_file` — so a single read here loses a race about once in a
    // dozen `cargo test` runs and reports a relay that was still being loaded as one
    // that had loaded the wrong thing.
    let loaded = fs::canonicalize(&installed).ok();
    let exe = || fs::read_link(format!("/proc/{}/exe", relay.id())).ok();
    assert!(
        poll_until(SETTLE, || exe() == loaded),
        "the swap is only about the daemon's exec once the relay has done its own, so \
         a relay still to be loaded fails here rather than as the planting below: \
         /proc says {:?}",
        exe()
    );

    let marker = root.join("planted-ran");
    let plant = root.join("planted");
    fs::write(&plant, format!("#!/bin/sh\n: > '{}'\n", marker.display())).expect("write the plant");
    fs::set_permissions(&plant, fs::Permissions::from_mode(0o755)).expect("make the plant run");
    fs::rename(&plant, &installed).expect("swap the binary at the install path");
    // Released under the gate, so no `fork` this suite has in flight is carrying a
    // duplicate of the descriptor the lock is attached to.
    while_nothing_forks(|| drop(lock));

    let pid_file = dir.join("swapped.pid");
    let settled = poll_until(SETTLE, || pid_file.exists() || marker.exists());
    // Bound before the assertions rather than after them: the passing path leaves a
    // daemon to collect, and the failing one leaves nothing that could leak.
    let _reaper = pid_file.exists().then(|| daemon_reaper(&root, "swapped"));

    assert!(
        !marker.exists(),
        "the file now at the install path ran, so the exec resolved that name a second \
         time instead of the inode this process was already loaded from"
    );
    assert!(
        settled,
        "the daemon never came up, and nothing was planted either — so the name was \
         resolved again and this time answered with nothing, which is the same re-read \
         costing a session instead of giving one away"
    );
    drop(relay);
    succeeded(
        &control(&root, &["kill", "swapped"]),
        "the daemon was not identified as one, so what it is exec'd as has reached \
         `argv[0]` after all",
    );
}

/// Bulk traffic through the attach relay, both ways at once.
///
/// The relay copies every byte through a per-direction buffer of one `RELAY_CHUNK`, so
/// bulk is what makes this interesting: enough to fill and refill the pipe and the
/// socket, so both directions hit short reads and full destinations. A chunk dropped,
/// replayed or reordered at a buffer boundary then shows up as a first-difference index
/// instead of as output that still looks plausible.
///
/// No daemon here on purpose. The relay never parses a frame, so a bare socket is
/// a complete peer, and the assertions can be about bytes rather than about the
/// protocol.
#[test]
fn the_relay_moves_bulk_traffic_both_ways_without_losing_a_byte() {
    // Eight pipes and two and a half socket buffers per direction, which is what
    // "fill and refill" above asks for. It was two megabytes, on no argument beyond
    // being a round number: what a mis-slice or a swallowed short read does at one
    // buffer boundary it does at every one of them, so the extra megabytes buy only
    // seconds.
    const BULK: usize = 512 * 1024;

    let (mut child, peer, _listener) = relay_onto_a_socket("relay_bulk", Stdio::piped());
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    assert_relay_moves_bulk(
        child,
        peer,
        BULK,
        (0x5eed_1234, 0xfeed_9876),
        move |data| {
            stdin.write_all(data).expect("write to relay stdin");
            // Half-close, which the relay must turn into shutdown(SHUT_WR) on the
            // socket while still draining the other direction.
            drop(stdin);
        },
        move || {
            let mut got = Vec::new();
            stdout.read_to_end(&mut got).expect("read relay stdout");
            got
        },
    );
}

/// The budget a relay test gives the relay, as a whole rather than per wait.
///
/// Far above the second or so the transfers really take, and far below the
/// termination in `.config/nextest.toml`, so a stalled relay fails here — naming the
/// direction that stopped — rather than being killed there with nothing to point at.
/// Spent once per *test*, for `harness::poll_by`'s reason.
///
/// The read timeout in [`relay_onto_a_socket_over`] is the one place it is a per-call
/// figure, and it is not a deadline: it is what stops a `read_to_end` on a socket
/// with no timeout of its own from parking a test thread for ever, so the wait that
/// *is* bounded — the join around that thread — can report it.
const RELAY_PATIENCE: Duration = Duration::from_secs(25);

/// Moves `bulk` bytes each way through a relay and compares both directions.
///
/// `feed` writes the upstream bytes and then half-closes; `drain` reads the
/// downstream ones to end of file. Both own their descriptor, so the choice of pipe
/// or `socketpair` stays with the caller that made it.
fn assert_relay_moves_bulk(
    mut child: Spawned,
    peer: UnixStream,
    bulk: usize,
    seeds: (u64, u64),
    feed: impl FnOnce(&[u8]) + Send + 'static,
    drain: impl FnOnce() -> Vec<u8> + Send + 'static,
) {
    use std::net::Shutdown;
    use std::sync::Arc;

    let peer = Arc::new(peer);
    let mut stderr = child.stderr.take().expect("stderr");

    let upstream = Rng::new(seeds.0).bytes(bulk);
    let downstream = Rng::new(seeds.1).bytes(bulk);

    // Four threads because all four flows must run at once: with any one of them
    // parked the relay's back pressure would deadlock the other three. Sharply so,
    // the relay writing to a *blocking* stdout: a reader that stops reading stops the
    // relay rather than filling a buffer.
    let feeder = {
        let data = upstream.clone();
        thread::spawn(move || feed(&data))
    };
    let push = {
        let data = downstream.clone();
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            let mut peer = &*peer;
            peer.write_all(&data).expect("write to relay socket");
        })
    };
    let uplink = {
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            let mut peer = &*peer;
            let mut got = Vec::new();
            peer.read_to_end(&mut got).expect("read from relay socket");
            got
        })
    };
    let downlink = thread::spawn(drain);

    let deadline = Instant::now() + RELAY_PATIENCE;
    join_before(feeder, deadline, "feeder");
    let uplink = join_before(uplink, deadline, "socket reader");
    join_before(push, deadline, "pusher");
    // Only now: the relay ends the moment the socket reports EOF, so closing this
    // any earlier would truncate the direction under test rather than test it.
    peer.shutdown(Shutdown::Write)
        .expect("half-close the socket");
    let downlink = join_before(downlink, deadline, "stdout reader");

    // Killed before its stderr is read to the end. Every wait above goes through
    // `join_before` so that a stalled relay fails rather than hangs, and this read
    // has no deadline of its own: a relay that had closed both data directions but
    // not exited would park the run here until nextest's own kill, with nothing to
    // point at. By this line the three joins have established that both directions
    // reached EOF, so there is nothing left for it to say that this could cut off.
    drop(child.kill());
    let mut complaints = String::new();
    drop(stderr.read_to_string(&mut complaints));
    drop(child);

    assert_same(&upstream, &uplink, "stdin -> socket", &complaints);
    assert_same(&downstream, &downlink, "socket -> stdout", &complaints);
}

/// Regression: the relay must leave when its stdout dies while nothing is owed to it,
/// which is the state it is in almost all of the time. It used to answer the `EPIPE`
/// by dropping the buffer and carrying on, discarding every byte the session produced
/// over a dead pipe while holding its one client slot.
///
/// An idle direction is out of the poll set altogether — an empty buffer wants nothing
/// — so nothing is noticed until the session produces something, and that first chunk
/// is buffered rather than written, the relay writing only to a descriptor `poll` has
/// just called writable. Buffering it is what puts stdout into the set. A pipe whose
/// read end is gone then answers `POLLOUT | POLLERR` and the `ERR` branch wins, so the
/// relay leaves without attempting the write at all. A socket that has shut down its
/// read half answers `POLLOUT` alone and the `EPIPE` from the write is the only report
/// there is, which is
/// [`the_relay_exits_when_a_stdout_that_still_reports_itself_writable_stops_reading`].
///
/// Asserted as the relay exiting rather than as bytes not moving, because that is the
/// only thing that tells the two apart: a discard loop accepts everything it is handed
/// and from the socket end looks exactly like a relay doing its job.
///
/// The pipe is half-closed inside [`while_nothing_forks`], because a pipe is broken
/// only when the *last* descriptor onto its read end goes and another test's `fork` in
/// flight holds a copy of everything open here.
#[test]
fn the_relay_exits_when_its_stdout_dies_with_nothing_owed_to_it() {
    // Before a single byte has crossed, so the direction is idle: nothing buffered,
    // and so stdout not in the poll set at all.
    let broken = while_nothing_forks(|| {
        let (reader, writer) = std::io::pipe().expect("a pipe for the relay's stdout");
        drop(reader);
        writer
    });
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_idle",
        Stdio::piped(),
        Stdio::from(broken),
        Stdio::null(),
    );
    // Stdin stays open and idle, so the only thing that can end this relay is the
    // stdout it can no longer reach: the socket is held by the test, and a stdin
    // closed here would only half-close that.
    let _stdin = child.stdin.take().expect("stdin");

    // One chunk is the whole provocation. The relay wakes on the readable socket,
    // buffers it, and finds on the next pass that there is nobody left to hand it to.
    peer.write_all(&vec![b'x'; 8 * 1024])
        .expect("write to the relay's socket");

    assert_relay_left(child, "with its stdout gone and its buffer idle");
}

/// The same ending reached the other way: through the write rather than through `poll`.
///
/// The test above takes a *pipe* for its stdout, and a pipe with no reader answers
/// `POLLOUT | POLLERR`, so the relay leaves on the `ERR` branch without ever attempting
/// the write. A `socketpair` whose peer has shut down its read half reports `POLLOUT`
/// alone and takes the write, and `nbio::drain_to`'s `writev` answering `EPIPE` is then
/// the only report there is — which is the shape a socket-backed stdout gives, and sshd
/// hands the client one on some builds.
///
/// Cheap enough to be worth having: one chunk, one process, and no timing to get
/// right, since the reader stops reading before the relay has anything to hand it.
#[test]
fn the_relay_exits_when_a_stdout_that_still_reports_itself_writable_stops_reading() {
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;

    // Held open and idle, as in the test above: the socket is the test's own, so a
    // stdin closed here would half-close the one direction that could otherwise end
    // this relay for a reason that is not the one under test.
    let (_stdin, relay_stdin) = UnixStream::pair().expect("a socketpair for the relay's stdin");
    let (reader, relay_stdout) = UnixStream::pair().expect("a socketpair for the relay's stdout");
    let (child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_copy_epipe",
        Stdio::from(OwnedFd::from(relay_stdin)),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::null(),
    );

    // Shut down rather than closed, and left open afterwards to make that the point:
    // `SHUT_RD` is a property of the socket rather than of any descriptor onto it, so
    // the copy another test's `fork` in flight is holding cannot undo it where a close
    // could.
    //
    // Before a byte has crossed, so nothing is owed to it: the relay is not watching
    // this descriptor and cannot be told about it.
    reader
        .shutdown(Shutdown::Read)
        .expect("stop reading the relay's stdout");

    peer.write_all(&vec![b'x'; 8 * 1024])
        .expect("write to the relay's socket");

    assert_relay_left(child, "with a stdout that had stopped reading");
}

/// The ending the two tests above share: the relay leaves, and § 10 gives exit 0 to
/// one whose own stdout was closed by its reader — whichever of the two ways it
/// finds that out. Nothing asserted the status, so the only part of § 10's row that
/// was ever under test was that the process stopped.
fn assert_relay_left(mut child: Spawned, still_running: &str) {
    assert!(
        poll_until(Duration::from_secs(10), || !child.is_running()),
        "the relay was still running {still_running}"
    );
    let finished = child
        .into_exited()
        .wait_with_output()
        .expect("collect the relay");
    assert!(
        finished.status.success(),
        "a relay whose stdout its reader closed is exit 0 (§ 10), got {}: {:?}",
        finished.status,
        stderr(&finished)
    );
}

/// The third number in § 10's relay table: a relay that had the session and then broke
/// is 1, and says nothing about the session.
///
/// Everything else out of `attach::run` answers § 10's question — whether this mode can
/// have this session — and every kind that table does not name is 126, which
/// `DESIGN.md` § 7 has the client cache *per host*. A write that fails an hour in has
/// already answered that question, and answered it yes: scored 126, `nomux attach work >
/// /var/log/big` on a filesystem that fills takes a working host out of the client's
/// rotation over a full disk, and nothing but the disk has to be repaired to bring it
/// back. So this row is the one the client must not act on, which is why it is worth a
/// test of its own rather than an eyeball over `attach::relay_failed`.
///
/// A stdout opened read-only, which is the shape `ENOSPC` has and the only one a test
/// can produce on demand: a descriptor `poll` calls writable — `/dev/null` and a
/// regular file are both always ready — that the kernel then refuses on the write, for
/// a reason that is not `EPIPE`. `EPIPE` is the one errno `Pump::drain_to` reads as an
/// ending rather than a failure, so it is exactly the neighbouring case, and it is the
/// two tests above.
///
/// Both halves are asserted because they fail apart: the number is what the client
/// branches on and the line is the whole of what the user gets, and a relay that
/// scored 1 for having failed to *connect* would pass on the number alone.
#[test]
fn a_relay_that_fails_mid_stream_is_not_a_host_the_client_gives_up_on() {
    let deadline = Instant::now() + RELAY_PATIENCE;
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_wr",
        Stdio::piped(),
        Stdio::from(fs::File::open("/dev/null").expect("a stdout opened for reading")),
        Stdio::piped(),
    );
    // Held open and idle, as in the two tests above: the socket is the test's own, so
    // the only thing that can end this relay is the stdout it cannot write to.
    let _stdin = child.stdin.take().expect("stdin");

    // One chunk is the whole provocation, and it takes two passes: the pass that reads
    // it only buffers it, which is what puts stdout in the poll set for the next one.
    peer.write_all(&vec![b'x'; 8 * 1024])
        .expect("write to the relay's socket");

    assert!(
        poll_by(deadline, || !child.is_running()),
        "the relay was still running with a stdout it could not write a byte to"
    );
    let finished = child
        .into_exited()
        .wait_with_output()
        .expect("collect the relay");
    assert_eq!(
        finished.status.code(),
        Some(1),
        "a relay that had the session and then failed is exit 1 (§ 10), not the 126 \
         that would cache this host as unattachable: {:?}",
        stderr(&finished)
    );
    assert!(
        stderr(&finished).contains("relaying to the session failed"),
        "the line has to say the relay failed rather than name a session that was \
         never in doubt: {:?}",
        stderr(&finished)
    );
}

/// Regression: a session that ends with the relay's own input still unread is a
/// clean exit, and what is buffered for stdout still gets there.
///
/// The ordinary way a session ends rather than an exotic one: § 4.1 stops the daemon
/// draining a client it is holding back, `write_client` drops a peer that has stopped
/// reading, and `shutdown` closes straight after `flush_final`. Each closes with bytes
/// of the relay's still in the socket's receive queue, and a unix socket closed in
/// that state hands the peer the last of the data and then `ECONNRESET` where an
/// orderly close gives it a zero.
///
/// `copy_in` mapped only `EIO` to an ending, so that reset came back out of `relay` as
/// `nomux: Connection reset by peer` and a refusal, where § 10 gives 0 to "the session
/// ended and the `Exit` frame was delivered". The last of the session's output went
/// with it — a `relay` that returns `Err` never goes back for what stdout is owed, and
/// the buffer holds it precisely here, a direction with nothing queued when `poll` was
/// called not yet asking for `POLLOUT`.
#[test]
fn a_session_that_ends_with_the_relays_input_unread_still_exits_clean() {
    use std::os::fd::OwnedFd;

    /// Written in the same breath as the close, so it is still in the relay's
    /// buffer when the reset arrives.
    const LAST: &[u8] = b"NOMUX-LAST-OUTPUT";

    let (mut feed, relay_stdin) = UnixStream::pair().expect("a socketpair for the relay's stdin");
    let (mut drain, relay_stdout) =
        UnixStream::pair().expect("a socketpair for the relay's stdout");
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_reset",
        Stdio::from(OwnedFd::from(relay_stdin)),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::piped(),
    );

    // One deadline across both waits below rather than one each ([`RELAY_PATIENCE`]):
    // two of them in sequence is fifty seconds against a runner that kills at forty.
    let deadline = Instant::now() + RELAY_PATIENCE;

    // Never read from this end, which is the whole provocation: the reset is the
    // kernel's answer to a close over a receive queue that still has something in it.
    feed.write_all(b"a keystroke this session never drains")
        .expect("write to the relay's stdin");
    // Waited for rather than assumed. A close that beats the relay's delivery of
    // those bytes is an orderly FIN, and this test would then pass having provoked
    // nothing at all.
    assert!(
        poll_by(deadline, || has_unread_bytes(&peer)),
        "the relay never delivered the input this test leaves unread"
    );

    peer.write_all(LAST)
        .expect("write the session's last words");
    drop(peer);

    assert!(
        poll_by(deadline, || !child.is_running()),
        "the relay never left after its session ended"
    );
    // After the exit, so nothing here can park: the relay's own end of this
    // socketpair went with it, and what it wrote is waiting in the buffer.
    let mut got = Vec::new();
    drop(drain.read_to_end(&mut got));
    let finished = child
        .into_exited()
        .wait_with_output()
        .expect("collect the relay");
    let complaints = String::from_utf8_lossy(&finished.stderr).into_owned();

    assert_eq!(
        got, LAST,
        "the relay dropped the output it was still holding; it said {complaints:?}"
    );
    assert!(
        finished.status.success(),
        "a session that ended is exit 0 (§ 10), got {}; the relay said {complaints:?}",
        finished.status
    );
}

/// Regression: a write to stdout that a signal cut short must not send the relay
/// straight back into the kernel for the rest of it.
///
/// `nbio::drain_to` used to write until the descriptor refused. That is safe against
/// the daemon's non-blocking descriptors, but the relay points it at *stdout*, which
/// is left blocking because it may be a terminal whose open file description the
/// user's shell shares. There the second `writev` is a second block, and the relay
/// sits inside it with the other direction unserved: `POLLOUT` promises only that
/// *some* write will succeed, which is exactly what the loop read as more.
///
/// What makes it observable is a *short* write, and on Linux a blocking descriptor
/// short-writes only when a signal ends the call after it has already transferred
/// something. `SIGSTOP` cannot be caught, blocked or ignored, so it always reaches a
/// task parked in a write; `SIGCONT` then puts the relay back exactly where the fix
/// has to matter — one `drain_to` call, mid-queue, against a destination still full.
///
/// The destination is a socketpair with a shrunken send buffer, which is what makes
/// that exact rather than probable: a unix socket blocks only once its buffer is at
/// the limit, so the write made on `POLLOUT` always transfers at least one segment
/// before it stops. Shrinking the buffer is what makes 16 KiB more than one segment;
/// at the default 208 KiB the whole write is a single one, which either fits or is
/// refused outright.
#[test]
fn a_write_to_stdout_a_signal_cut_short_does_not_park_the_relay_again() {
    use std::os::fd::OwnedFd;

    /// Small enough that one of the relay's 16 KiB writes is several segments, so it
    /// can stop partway rather than only at a boundary of its own.
    const STDOUT_BUFFER: libc::c_int = 4096;
    /// More than the shrunken socket and the relay's own 16 KiB buffer hold between
    /// them, so the write it parks in cannot end by running out of bytes.
    const PUSH: usize = 64 * 1024;
    /// Sent the other way, and nothing to do with the write above: this is the
    /// traffic the parked relay is failing to serve.
    const MARKER: &[u8] = b"NOMUX-OTHER-DIRECTION";
    /// How long the marker is given to *not* arrive. A wall-clock negative, and safe
    /// as one only because [`parked_in_a_write`] has already been observed true
    /// below: what this has to outlast is a relay going round its loop, which takes
    /// microseconds, and never a relay that has not reached the write yet.
    const PARKED: Duration = Duration::from_millis(250);

    // Never read from, which is what keeps the relay's stdout full; held to the end
    // of the test, since a closed one would be an `EPIPE` rather than a block.
    let (_unread, relay_stdout) = UnixStream::pair().expect("a socketpair for the relay's stdout");
    shrink_send_buffer(&relay_stdout, STDOUT_BUFFER);
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_short_write",
        Stdio::piped(),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::null(),
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let relay = child.id();

    peer.write_all(&vec![b'x'; PUSH])
        .expect("write to the relay's socket");
    // Short, because every look for the marker below reads through this and a relay
    // that is parked has nothing to say.
    peer.set_read_timeout(Some(Duration::from_millis(20)))
        .expect("a peer the polls below must not wait on");

    assert!(
        poll_until(Duration::from_secs(10), || parked_in_a_write(relay)),
        "the relay never parked inside a write to its stdout, so there is no \
         interrupted write below for either version of `drain_to` to answer"
    );

    // Written only now, so that it cannot have been served before the relay stopped.
    stdin.write_all(MARKER).expect("write to the relay's stdin");
    stdin.flush().expect("flush the relay's stdin");
    let mut seen = Vec::new();
    assert!(
        !poll_until(PARKED, || marker_arrived(&mut peer, &mut seen, MARKER)),
        "the relay served its stdin while it was supposed to be parked in a write, \
         so the wait below would be satisfied by a marker that had already arrived"
    );

    // The stop is what ends the write; the continue is what makes what happens next
    // the relay's own decision. Waited out rather than sent back to back: a `SIGCONT`
    // generated before the stop has been taken discards it, and the write would then
    // be restarted rather than cut short.
    let pid = rustix::process::Pid::from_raw(relay.cast_signed()).expect("the relay's pid");
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stop the relay");
    assert!(
        poll_until(Duration::from_secs(10), || process_state(relay)
            == Some('T')),
        "the relay never took the stop, so the write it is in was never interrupted"
    );
    rustix::process::kill_process(pid, rustix::process::Signal::CONT).expect("continue the relay");

    assert!(
        poll_until(Duration::from_secs(10), || marker_arrived(
            &mut peer, &mut seen, MARKER
        )),
        "the relay went back into the kernel for the rest of a write the signal had \
         already ended, leaving the other direction unserved"
    );
}

/// Whether `pid` is inside a `writev(2)` at this moment, as `/proc` reports it.
///
/// The relay makes exactly one kind of write — `nbio::drain_to`'s `writev` across the
/// two halves of its queue — so the syscall number is the most direct statement of
/// the state the test needs, and far cheaper than inferring it from what the relay
/// has stopped doing. `/proc/<pid>/syscall` gives a number and its arguments, or
/// `running`; anything that does not parse, including a kernel that does not offer
/// the file, reads as "not parked" and fails the wait that asks for it rather than
/// letting some other state pass for it.
fn parked_in_a_write(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/syscall"))
        .ok()
        .and_then(|reported| {
            reported
                .split_whitespace()
                .next()?
                .parse::<libc::c_long>()
                .ok()
        })
        .is_some_and(|syscall| syscall == libc::SYS_writev)
}

/// Whether `marker` has reached `peer` yet, keeping whatever else arrives on the way.
///
/// Everything read is kept and the answer is about the whole of it, so a marker split
/// across two reads is still found — and so a look that comes back empty cannot
/// discard what an earlier one collected.
fn marker_arrived(peer: &mut UnixStream, seen: &mut Vec<u8>, marker: &[u8]) -> bool {
    let mut chunk = [0u8; 8192];
    while let Ok(read) = read_uninterrupted(peer, &mut chunk) {
        if read == 0 {
            break;
        }
        seen.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
    }
    seen.windows(marker.len()).any(|window| window == marker)
}

/// A `nomux attach` relaying onto a socket the test holds the other end of, with
/// its first connection already accepted.
///
/// The scaffolding every relay test needs and none of them is about: a run directory
/// of the mode the binary insists on, a session socket bound by the test rather than
/// by a daemon, and the relay started against it. What they do differ in is where the
/// relay's complaints go, so that is the argument — the bulk test reads them into its
/// failure messages, and the ones about the relay leaving have nobody left to read
/// them.
///
/// The listener comes back with the rest because it has to outlive the relay: a
/// connection arriving at a closed one is refused, and a refusal would look like the
/// relay giving up rather than like the test having tidied away too early.
fn relay_onto_a_socket(id: &str, complaints: Stdio) -> (Spawned, UnixStream, UnixListener) {
    relay_onto_a_socket_over(id, Stdio::piped(), Stdio::piped(), complaints)
}

/// [`relay_onto_a_socket`] with the relay's stdin and stdout chosen by the caller.
///
/// What is on the far end of those two is not a detail of the scaffolding wherever a
/// test is about how a stdout reports its death: a pipe answers `POLLERR` and a
/// `socketpair` answers `EPIPE` on the write. Kept apart from the common form so that
/// the tests which only want a relay do not have to say which of the two they are
/// getting — the answer is the pipes everybody assumes.
fn relay_onto_a_socket_over(
    id: &str,
    input: Stdio,
    output: Stdio,
    complaints: Stdio,
) -> (Spawned, UnixStream, UnixListener) {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root(id);
    let dir = root.join("nomux");
    fs::create_dir_all(&dir).expect("create run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("tighten run dir");
    let listener = UnixListener::bind(dir.join(format!("{id}.sock"))).expect("bind session socket");

    // The `Command` is a temporary and dies with the statement, which is what closes
    // this process's copies of anything the caller passed in: a `socketpair` end
    // still held here would be a stdout that never reaches EOF.
    let child = Spawned::spawn(
        nomux(&root, &["attach", id])
            .stdin(input)
            .stdout(output)
            .stderr(complaints),
    );

    let peer = accept_within(
        &listener,
        Duration::from_secs(10),
        "`nomux attach` to connect to the session socket",
    );
    // `accept` hands back a socket with no deadline of its own, and the bulk tests
    // read it to end of file — so a relay that stalled would park a test thread for
    // ever. The timeout turns that into the named failure `join_before` reports.
    peer.set_read_timeout(Some(RELAY_PATIENCE))
        .expect("a peer the test must not park on");
    (child, peer, listener)
}

/// Compares by first difference rather than by value: a failure here is megabytes
/// wide, and the only useful part of it is where the two streams parted company.
fn assert_same(want: &[u8], got: &[u8], direction: &str, stderr: &str) {
    let at = want.iter().zip(got).position(|(a, b)| a != b);
    assert!(
        at.is_none(),
        "{direction} diverged at byte {at:?} of {}; relay stderr: {stderr:?}",
        want.len()
    );
    assert_eq!(
        got.len(),
        want.len(),
        "{direction} moved the wrong number of bytes; relay stderr: {stderr:?}"
    );
}
