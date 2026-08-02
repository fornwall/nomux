//! End-to-end tests against the real binary.
//!
//! These drive `nomux daemon` over its unix socket, speaking the wire protocol
//! directly, so they exercise the PTY, the ring buffer and the resume path rather
//! than a mock of them.
//!
//! The two invariants that matter (`IMPLEMENTATION.md` § 9): input is never
//! duplicated, and output is never lost unless a `Gap` was reported.

mod harness;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{
    ErrorCode, Frame, FrameType, HELLO_AGENT_FORWARD, HELLO_REPAINT_CTRL_L, Hello,
    MAX_AGENT_CHANNELS, PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
};

use harness::{
    Rng, Session, Spawned, accept_within, control, hello_frame, poll_until, push_until_refused,
    reconnect_until_gap, run_root, wait_for, write_frame,
};

#[test]
fn runs_a_shell_and_streams_its_output() {
    let (_session, mut client, ok) = Session::attached("basic");
    assert_eq!(ok.protocol, PROTOCOL_VERSION);
    assert!(!ok.gap);

    let script = b"echo NOMUX-ALPHA\n";
    client.send(&Frame::Input {
        offset: 0,
        data: script,
    });
    let (seen, _) = client.read_until("NOMUX-ALPHA", ok.resume_from);
    assert!(seen.contains("NOMUX-ALPHA"), "shell output: {seen:?}");
}

#[test]
fn output_resumes_contiguously_after_a_reconnect() {
    let (session, mut client, ok) = Session::attached("resume");

    let first = b"echo NOMUX-BEFORE\n";
    client.send(&Frame::Input {
        offset: 0,
        data: first,
    });
    let (_, offset) = client.read_until("NOMUX-BEFORE", ok.resume_from);

    // Sever the connection the way a network drop would.
    drop(client);
    let mut client = session.connect();
    let ok = client.hello(offset, first.len() as u64);
    assert_eq!(
        ok.resume_from, offset,
        "resume must continue from exactly where the client left off"
    );
    assert_eq!(
        ok.in_applied,
        first.len() as u64,
        "daemon reports authoritative input position"
    );
    assert!(!ok.gap, "nothing should have been dropped in this window");

    client.send(&Frame::Input {
        offset: ok.in_applied,
        data: b"echo NOMUX-AFTER\n",
    });
    let (seen, _) = client.read_until("NOMUX-AFTER", ok.resume_from);
    assert!(seen.contains("NOMUX-AFTER"), "post-resume output: {seen:?}");
}

/// A client claiming output the session never produced is clamped down to the end of
/// the stream rather than believed (`IMPLEMENTATION.md` § 4.2).
///
/// `resume_from` is clamped at *both* ends, and only the lower clamp is otherwise
/// exercised — the test above it resumes from where it left off, and the gap tests
/// resume from below `base_offset`. Without the upper one the daemon sets
/// `sent_through` past everything it holds, and the documented consequence is that
/// the session looks dead: no output at all until the child happens to write enough
/// to catch up. Nothing is reported as a gap either, because nothing was dropped —
/// there was never anything there.
#[test]
fn an_out_offset_past_the_end_of_the_stream_is_clamped_rather_than_believed() {
    /// Comfortably past anything a shell echoing one line has ever written.
    const FAR: u64 = 1 << 20;

    let (session, mut client, ok) = Session::attached("clamp_high");

    let first = b"echo NOMUX-BEFORE-CLAMP\n";
    client.send(&Frame::Input {
        offset: 0,
        data: first,
    });
    let (_, end) = client.read_until("NOMUX-BEFORE-CLAMP", ok.resume_from);
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(end + FAR, first.len() as u64);
    assert!(
        !resumed.gap,
        "nothing was dropped, so nothing may be reported as a gap"
    );
    assert!(
        resumed.resume_from < end + FAR,
        "an out_offset past the end of the stream must be clamped to it: \
         resumed from {} against the {} claimed",
        resumed.resume_from,
        end + FAR
    );
    assert_eq!(
        resumed.in_applied,
        first.len() as u64,
        "the session's input position must survive a client claiming output it \
         never received"
    );

    // And it is a live session rather than one that has gone quiet behind a resume
    // point past its own stream, which is the whole shape of the fault.
    client.send(&Frame::Input {
        offset: resumed.in_applied,
        data: b"echo NOMUX-AFTER-CLAMP\n",
    });
    let (seen, _) = client.read_until("NOMUX-AFTER-CLAMP", resumed.resume_from);
    assert!(seen.contains("NOMUX-AFTER-CLAMP"), "transcript: {seen:?}");
}

/// The invariant that matters most: a client replaying input it already sent —
/// because the `InputAck` was lost with the connection — must not run it twice.
#[test]
fn replayed_input_is_applied_exactly_once() {
    let (session, mut client, ok) = Session::attached("dedup");

    // `printf` with a counter would need shell state; instead emit a unique marker
    // and assert it appears exactly once in the transcript.
    let command = b"echo NOMUX-ONCE-MARKER\n";
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });
    let (_, offset) = client.read_until("NOMUX-ONCE-MARKER", ok.resume_from);

    drop(client);
    let mut client = session.connect();

    // Resume claiming we never got the ack, then replay the identical bytes.
    let ok = client.hello(offset, 0);
    assert_eq!(
        ok.in_applied,
        command.len() as u64,
        "daemon must report input already applied"
    );
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });

    // Force a round trip so any duplicate would have been echoed by now.
    client.send(&Frame::Input {
        offset: ok.in_applied,
        data: b"echo NOMUX-FENCE\n",
    });
    let (seen, _) = client.read_until("NOMUX-FENCE", ok.resume_from);

    let echoes = seen.matches("NOMUX-ONCE-MARKER").count();
    assert_eq!(
        echoes, 0,
        "replayed input was applied a second time; transcript: {seen:?}"
    );
}

/// Input above `in_applied` is a hole in the input stream, and the daemon refuses it
/// and closes rather than guessing at what is missing (`IMPLEMENTATION.md` § 3).
///
/// The one error code with nothing else exercising it end to end. Refusing is the
/// only answer available: applying the frame would run keystrokes with a gap in the
/// middle, and the client is the side that is wrong — `in_applied` is authoritative,
/// so a client that skipped ahead has lost track of its own stream and has to start
/// again from what the daemon reports.
#[test]
fn input_that_skips_ahead_is_refused_and_the_connection_closed() {
    let (_session, mut client, _) = Session::attached("input_gap");

    // Nothing has been sent yet, so `in_applied` is zero and this claims a keystroke
    // the daemon never saw.
    client.send(&Frame::Input {
        offset: 1,
        data: b"echo NOMUX-NEVER-RUN\n",
    });

    let payload = client.next_of(FrameType::Error);
    let refusal = Frame::decode(FrameType::Error, &payload).expect("decode the refusal");
    assert!(
        matches!(
            refusal,
            Frame::Error {
                code: ErrorCode::InputGap,
                ..
            }
        ),
        "input above in_applied must be refused as an input gap, got {refusal:?}"
    );
    client.expect_eof("an Error{InputGap}");
}

#[test]
fn overflow_is_reported_as_a_gap_rather_than_silently_truncated() {
    let (session, mut client, ok) = Session::attached("gap");

    // Detach, then generate far more output than the ring can hold.
    // Comfortably more than the 64 KiB ring configured for these tests.
    let filler = format!(
        "for i in $(seq 1 4000); do echo {}; done\n",
        "x".repeat(200)
    );
    client.send(&Frame::Input {
        offset: 0,
        data: filler.as_bytes(),
    });
    drop(client);

    // The daemon must keep draining the PTY while detached, so the ring overflows
    // even with nobody listening. Waited for rather than slept through.
    let (_client, resumed) = reconnect_until_gap(&session, 0, ok.resume_from, filler.len() as u64);
    assert!(
        resumed.resume_from > ok.resume_from,
        "resume point must advance past the discarded bytes"
    );
}

/// A `NOMUX_RING_BYTES` the daemon cannot use falls back to the default rather than
/// refusing to start (`IMPLEMENTATION.md` § 4).
///
/// `Ring::new` asserts its capacity is non-zero, so this does not degrade if the
/// filter that rejects a zero is ever lost: the daemon aborts before it binds
/// anything, and every session on a host with that variable exported stops starting
/// at once. A mistyped tuning variable should never cost somebody their session, so
/// the value is dropped and the default used.
#[test]
fn a_ring_capacity_the_daemon_cannot_use_falls_back_to_the_default() {
    for (name, value) in [("ring_zero", "0"), ("ring_garbage", "not-a-number")] {
        let session = Session::start_with_raw_ring(name, value);
        let mut client = session.connect();
        let ok = client.hello(RESUME_FROM_START, 0);

        // Serving, rather than merely having bound a socket. The socket is bound
        // before the ring is built, so a daemon that aborted on the assertion leaves
        // the file behind and `wait_for` is satisfied by a corpse.
        client.send(&Frame::Input {
            offset: 0,
            data: b"echo NOMUX-DEFAULT-RING\n",
        });
        let (seen, _) = client.read_until("NOMUX-DEFAULT-RING", ok.resume_from);
        assert!(
            seen.contains("NOMUX-DEFAULT-RING"),
            "NOMUX_RING_BYTES={value:?} left the session unable to serve: {seen:?}"
        );
    }
}

#[test]
fn a_second_client_takes_over_and_the_first_is_told_why() {
    let (session, mut first, _) = Session::attached("takeover");

    let mut second = session.connect();
    second.hello(RESUME_FROM_START, 0);

    let (ty, payload) = first.next_frame();
    let frame = Frame::decode(ty, &payload).expect("decode");
    assert!(
        matches!(
            frame,
            Frame::Error {
                code: ErrorCode::Takeover,
                ..
            }
        ),
        "evicted client must learn it was a takeover, not a network fault: {frame:?}"
    );
}

#[test]
fn list_and_kill_operate_without_the_protocol() {
    let (session, _client, _) = Session::attached("control");

    let listed = control(&session.root, &["list"]);
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.contains(&session.id),
        "list should report the live session, got {listed:?}"
    );

    let killed = control(&session.root, &["kill", &session.id]);
    assert!(killed.status.success());

    assert!(!session.socket.exists(), "kill must unlink the run files");
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
    let listed = control(&session.root, &["list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains(&session.id));

    // `read_until` refuses anything that is not output, so an `Error{TAKEOVER}`
    // fails this rather than being skipped over.
    client.send(&Frame::Input {
        offset: 0,
        data: b"echo NOMUX-STILL-ATTACHED\n",
    });
    let (seen, _) = client.read_until("NOMUX-STILL-ATTACHED", ok.resume_from);
    assert!(
        seen.contains("NOMUX-STILL-ATTACHED"),
        "transcript: {seen:?}"
    );
}

/// A connection that speaks out of turn is refused on its own terms, without
/// costing the session its client.
#[test]
fn a_connection_that_does_not_greet_first_is_refused_alone() {
    let (session, mut client, ok) = Session::attached("no_greeting");

    let mut rude = session.connect();
    rude.send(&Frame::Ping { nonce: 1 });
    let (ty, payload) = rude.next_frame();
    assert!(
        matches!(
            Frame::decode(ty, &payload).expect("decode"),
            Frame::Error {
                code: ErrorCode::Protocol,
                ..
            }
        ),
        "expected a protocol error, got {ty:?}"
    );
    drop(rude);

    client.send(&Frame::Input {
        offset: 0,
        data: b"echo NOMUX-UNDISTURBED\n",
    });
    let (seen, _) = client.read_until("NOMUX-UNDISTURBED", ok.resume_from);
    assert!(seen.contains("NOMUX-UNDISTURBED"), "transcript: {seen:?}");
}

/// `Resize` reaches the child's terminal, and every attach restates the geometry
/// (`IMPLEMENTATION.md` § 2.2).
///
/// Nothing else in the suite sends a `0x07`, and nothing looks at the winsize
/// `HelloOk` carries back. Both halves matter to the same user: the window is
/// resized while attached, and the session is then picked up from a terminal of a
/// different size — which is the ordinary case for this project, since the whole
/// point is reattaching from somewhere else. The daemon takes the arriving `Hello`'s
/// winsize as authoritative and says so in its reply, so a client never has to guess
/// whether its size was applied.
#[test]
fn a_resize_reaches_the_child_and_every_attach_restates_the_geometry() {
    let (session, mut client, ok) = Session::attached("resize");
    assert_eq!(
        ok.win,
        harness::WIN,
        "the greeting must confirm the geometry the client asked for"
    );

    let wider = WinSize {
        cols: 132,
        rows: 43,
        xpixel: 0,
        ypixel: 0,
    };
    client.send(&Frame::Resize(wider));
    // `stty size` reports rows then columns, and the line discipline's echo of the
    // command carries neither number — so seeing them is the child's own answer.
    let command = b"stty size\n";
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });
    let (seen, _) = client.read_until("43 132", ok.resume_from);
    assert!(
        seen.contains("43 132"),
        "the child's terminal kept its old size across a Resize: {seen:?}"
    );
    drop(client);

    // A client arriving from a terminal of the original size gets it back, in the
    // greeting and in the child.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START, command.len() as u64);
    assert_eq!(
        resumed.win,
        harness::WIN,
        "the reply must carry the geometry of the client it is answering"
    );
    client.send(&Frame::Input {
        offset: resumed.in_applied,
        data: b"stty size\n",
    });
    let (seen, _) = client.read_until("24 80", resumed.resume_from);
    assert!(
        seen.contains("24 80"),
        "the child kept the previous client's geometry across an attach: {seen:?}"
    );
}

/// `Detach` gives the connection up without giving up the session
/// (`IMPLEMENTATION.md` § 2.2).
///
/// Never sent by anything else here — every other departure in the suite is a socket
/// being dropped, which is the *unclean* case. This is the deliberate one, and what
/// separates them is that nothing may be lost: the daemon closes the connection and
/// keeps the input position, so the client that comes back is told where it was
/// rather than starting the stream again.
#[test]
fn a_detach_ends_the_connection_but_not_the_session() {
    let (session, mut client, ok) = Session::attached("detach_frame");

    let command = b"echo NOMUX-BEFORE-DETACH\n";
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });
    client.read_until("NOMUX-BEFORE-DETACH", ok.resume_from);

    client.send(&Frame::Detach);
    client.expect_eof("a Detach");
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START, command.len() as u64);
    assert_eq!(
        resumed.in_applied,
        command.len() as u64,
        "a detach must leave the session's input position where it was"
    );
    client.send(&Frame::Input {
        offset: resumed.in_applied,
        data: b"echo NOMUX-AFTER-DETACH\n",
    });
    let (seen, _) = client.read_until("NOMUX-AFTER-DETACH", resumed.resume_from);
    assert!(seen.contains("NOMUX-AFTER-DETACH"), "transcript: {seen:?}");
}

/// The child's last words come before its status.
///
/// The linger window (§ 6.5) exists so a client reconnecting into the race still
/// collects both — in that order. A client that closes the tab on `Exit` and is
/// handed it first loses the entire transcript.
#[test]
fn the_exit_status_arrives_after_the_final_output() {
    let (session, mut client, _) = Session::attached("exit_order");

    let command = b"printf NOMUX-LAST-WORD; exit 3\n";
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });
    // The daemon must own the command before the connection goes away, or RST
    // takes it with them.
    client.wait_for_input_ack(command.len() as u64);
    drop(client);
    thread::sleep(Duration::from_millis(500));

    // Reattach inside the linger window, exactly the race the window is for.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START, command.len() as u64);
    let mut seen = Vec::new();
    loop {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode") {
            Frame::Output { data, .. } => seen.extend_from_slice(data),
            Frame::Exit { status, kind } => {
                assert_eq!(status, 3, "the child's own status must survive");
                assert_eq!(kind, nomux_proto::ExitKind::Exited);
                break;
            }
            Frame::InputAck { .. } | Frame::Gap { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let seen = String::from_utf8_lossy(&seen);
    assert!(
        seen.contains("NOMUX-LAST-WORD"),
        "output arrived after the exit status, or not at all: {seen:?} \
         (resumed from {})",
        resumed.resume_from
    );
}

/// The child must not inherit a handle to its own PTY master.
///
/// Everything the user runs in the session would otherwise hold a writable
/// descriptor onto the master: anything that walks `/proc/self/fd`, or writes to a
/// descriptor it did not open, could inject output into the stream or read the
/// user's keystrokes.
#[test]
fn the_child_inherits_only_its_stdio() {
    let (session, mut client, ok) = Session::attached("fds");
    // Wait for the shell to be up before looking for it.
    client.send(&Frame::Input {
        offset: 0,
        data: b"echo NOMUX-SPAWNED\n",
    });
    client.read_until("NOMUX-SPAWNED", ok.resume_from);

    let shell = child_of(session.child.id()).expect("find the session shell");
    let mut terminals = Vec::new();
    for entry in fs::read_dir(format!("/proc/{shell}/fd")).expect("read the shell's fds") {
        let entry = entry.expect("fd entry");
        let target = fs::read_link(entry.path()).unwrap_or_default();
        let target = target.to_string_lossy().into_owned();
        assert!(
            !target.contains("ptmx"),
            "the child inherited the PTY master as fd {:?}",
            entry.file_name()
        );
        if target.starts_with("/dev/pts/") {
            terminals.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    terminals.sort();
    assert_eq!(
        terminals,
        ["0", "1", "2"],
        "the child should hold the slave exactly three times, as its stdio"
    );
}

/// The pid of `parent`'s first child, from `/proc`.
fn child_of(parent: u32) -> Option<u32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let parent_of_pid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.trim().parse::<u32>().ok());
        if parent_of_pid == Some(parent) {
            return Some(pid);
        }
    }
    None
}

/// Ids are opaque per-tab identifiers, so the label is the only thing that makes a
/// session recognisable to a human after the client loses its state.
#[test]
fn a_label_survives_into_list() {
    let root = run_root("label");
    let attach = Spawned::spawn(
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["attach", "labelled", "--label", "  release build\tx  "])
            .env("XDG_RUNTIME_DIR", &root)
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    wait_for(&root.join("nomux").join("labelled.sock"));

    let listed = control(&root, &["list"]);
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();

    // Both collected before the assertions below, so a failure about the label does
    // not also leave a session behind.
    drop(attach);
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

#[test]
fn invalid_session_ids_are_refused() {
    // A run directory of its own even though nothing should ever be created in it:
    // the refusal is what is under test, and a regression that got as far as the
    // filesystem would otherwise leave its mess where every other test lives.
    let root = run_root("bad_ids");
    for id in ["../escape", "with/slash", "with space"] {
        let output = control(&root, &["attach", id]);
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
            String::from_utf8_lossy(&output.stderr).contains("invalid session id"),
            "id {id:?} should be rejected by name"
        );
    }
}

/// A run directory that is a symlink is refused, out loud, by both modes that
/// create one.
///
/// The unit tests in `rundir` cover the decision; this covers the consequence,
/// which is the half a user sees. Everything else in this daemon degrades rather
/// than aborts, so a session that must not start has to say so with a message and
/// an exit status rather than by quietly doing something else — and what it must
/// not do is what the code before it did, which was to `chmod` whatever the link
/// points at and bind a session's sockets inside it.
#[test]
fn a_symlinked_run_directory_is_refused_by_attach_and_daemon() {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root("symdir");
    let target = root.join("elsewhere");
    fs::create_dir_all(&target).expect("create the directory the link points at");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).expect("loosen the target");
    std::os::unix::fs::symlink(&target, root.join("nomux")).expect("plant the symlink");

    let refusals: Vec<(&str, bool, String)> = ["attach", "daemon"]
        .into_iter()
        .map(|mode| {
            let output = Command::new(env!("CARGO_BIN_EXE_nomux"))
                .args([mode, "symdir"])
                .env("XDG_RUNTIME_DIR", &root)
                .env("SHELL", "/bin/sh")
                .stdin(Stdio::null())
                .output()
                .expect("run nomux");
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            (mode, output.status.success(), stderr)
        })
        .collect();

    // Before the assertions, because the thing being asserted is that no session was
    // started — and a failure here means one *was*, in nobody's process group, with a
    // seven-day idle limit rather than the thirty seconds of a session no client ever
    // reached. Nothing else in this test would collect it.
    drop(control(&root, &["kill", "symdir"]));

    for (mode, started, stderr) in &refusals {
        assert!(
            !started,
            "{mode} started a session in a symlinked run directory"
        );
        assert!(
            stderr.contains("run directory") && stderr.contains("symlink"),
            "{mode} must say what it refused and why, got {stderr:?}"
        );
    }

    assert_eq!(
        fs::symlink_metadata(&target)
            .expect("stat the target")
            .permissions()
            .mode()
            & 0o7777,
        0o777,
        "the mode of a directory nomux does not own is not nomux's to change"
    );
    assert!(
        fs::read_dir(&target)
            .expect("read the target")
            .next()
            .is_none(),
        "nothing may be created through the link"
    );
}

/// Exercises the path a real bootstrap takes: `nomux attach` with no daemon
/// running, which must spawn one under the flock and then relay transparently.
#[test]
fn attach_spawns_the_daemon_and_relays_transparently() {
    use std::sync::mpsc;

    let root = run_root("relay");
    let mut child = Spawned::spawn(
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["attach", "relay_probe"])
            .env("XDG_RUNTIME_DIR", &root)
            .env("SHELL", "/bin/sh")
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
        while let Ok(n) = stdout.read(&mut chunk) {
            if n == 0 || tx.send(chunk[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    write_frame(&mut stdin, &hello_frame(0, RESUME_FROM_START, 0));
    write_frame(
        &mut stdin,
        &Frame::Input {
            offset: 0,
            data: b"echo NOMUX-RELAY\n",
        },
    );
    stdin.flush().expect("flush");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    let found = loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break false;
        };
        match rx.recv_timeout(remaining) {
            Ok(bytes) => seen.extend_from_slice(&bytes),
            Err(_) => break false,
        }
        // The relay is a byte pipe, so the marker appears verbatim inside the
        // Output frames without needing to parse them here.
        if String::from_utf8_lossy(&seen).contains("NOMUX-RELAY") {
            break true;
        }
    };

    drop(stdin);
    drop(child);
    drop(pump.join());

    drop(control(&root, &["kill", "relay_probe"]));

    assert!(
        found,
        "attach did not spawn a daemon and relay its output; saw {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// The PTY master is non-blocking, so a child that has stopped reading cannot
/// wedge the daemon.
///
/// A PTY's input buffer is a few kilobytes. With a blocking master, pushing more
/// than that at a child which is not reading parked the whole event loop inside
/// `write(2)` — one session's stuck child froze that session's output entirely,
/// including frames that had nothing to do with the PTY.
#[test]
fn a_child_that_stops_reading_input_does_not_wedge_the_daemon() {
    let (_session, mut client, ok) = Session::attached("wedge");

    // Raw mode is what makes the line discipline apply back pressure instead of
    // quietly dropping the overflow: in canonical mode a line longer than the
    // buffer is discarded, and the master write never blocks at all. `sleep` then
    // holds the terminal without reading it, so everything below piles up.
    let ready = client.make_ready("raw -echo", Some("sleep 30"), ok.resume_from);

    let chunk = vec![b'x'; 16 * 1024];
    let mut offset = ready.in_offset;
    for _ in 0..16 {
        client.send(&Frame::Input {
            offset,
            data: &chunk,
        });
        offset += chunk.len() as u64;
    }

    // Long enough for the daemon to have tried the write and, with a blocking
    // master, to still be parked inside it. Sending the ping in the same batch as
    // the input would prove nothing: it would be answered from the same read,
    // before the write was ever attempted.
    thread::sleep(Duration::from_millis(500));

    // The daemon must still be answering: with a blocking master this does not
    // return until the sleep does.
    let began = Instant::now();
    client.send(&Frame::Ping { nonce: 0xF00D });
    let payload = client.next_of(FrameType::Pong);
    assert_eq!(
        Frame::decode(FrameType::Pong, &payload).expect("decode pong"),
        Frame::Pong { nonce: 0xF00D }
    );
    assert!(
        began.elapsed() < Duration::from_secs(10),
        "daemon took {:?} to answer a ping behind a full PTY buffer",
        began.elapsed()
    );
}

/// A client writing faster than the child reads is back-pressured, not buffered
/// without limit.
///
/// `Conn::rx` and `pending_input` had no cap, so a client could grow the daemon by
/// however much it cared to send — and the two cheaper answers are both closed off,
/// since `in_applied` is authoritative and exactly-once (§ 3): a byte cannot be
/// dropped once acknowledged, and refusing one with an `InputGap` would accuse a
/// client that had done nothing wrong. So the daemon stops reading the socket
/// instead, exactly as the output direction always has.
///
/// Measured as bytes the daemon would take, which bounds what it can be holding:
/// everything it has is a subset of what crossed the socket.
#[test]
fn input_the_child_never_reads_is_back_pressured_rather_than_buffered() {
    /// Comfortably more than every buffer between the two processes put together.
    const BLAST: usize = 32 << 20;
    /// Room for a megabyte of queued input, a megabyte of undecoded receive buffer
    /// and the kernel's socket buffers, and nothing like room for [`BLAST`].
    const TOLERATED: usize = 8 << 20;

    let (session, mut client, ok) = Session::attached("input_cap");

    // Raw mode is what makes the line discipline apply back pressure instead of
    // quietly dropping the overflow: in canonical mode a line longer than the buffer
    // is discarded and the master never stops accepting. `sleep` then holds the
    // terminal without reading a byte of it. No settling sleep is needed once the
    // marker is back: the whole line is parsed before any of it runs, so the shell
    // reads nothing more until `sleep 30` returns.
    let ready = client.make_ready("raw -echo", Some("sleep 30"), ok.resume_from);
    drop(client);

    // A raw socket rather than the harness client, because the question is how much
    // the daemon will take before it stops taking.
    let mut blaster = UnixStream::connect(&session.socket).expect("connect");
    write_frame(
        &mut blaster,
        &hello_frame(0, RESUME_FROM_START, ready.in_offset),
    );
    blaster.set_nonblocking(true).expect("stop blocking");

    let chunk = vec![b'x'; 60 * 1024];
    let mut frames = Vec::with_capacity(BLAST + chunk.len());
    let mut offset = ready.in_offset;
    while frames.len() < BLAST {
        Frame::Input {
            offset,
            data: &chunk,
        }
        .encode(&mut frames)
        .expect("encode input");
        offset += chunk.len() as u64;
    }

    // Three seconds of refusal, which is long enough that a daemon merely busy with
    // the megabytes it already took would have come back for more.
    let sent = push_until_refused(&mut blaster, &frames, Duration::from_secs(3));
    assert!(
        sent < TOLERATED,
        "the daemon took {sent} bytes of input for a child that read none of them"
    );

    // And it is still serving. A fresh connection is never held back — that is what
    // keeps `list` and the spawn race working (§ 6.6) — so the handshake it gets
    // back is both proof the loop is alive and a statement about the input the
    // daemon really did accept.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START, offset);
    let applied = resumed.in_applied.saturating_sub(ready.in_offset);
    assert!(applied > 0, "the daemon applied none of the input it took");
    assert!(
        applied <= sent as u64,
        "the daemon applied {applied} bytes of input from {sent} bytes of frames"
    );
}

/// Reconnecting must not raise the ceiling.
///
/// Holding the client out of the poll set throttles only the reads the poll set
/// drives, and that is not where the queue grows. The takeover path of § 6.4.1 reaches
/// the decode loop twice without passing through the poll set at all — once to drain
/// the outgoing connection, once for the input pipelined behind the arriving `Hello` —
/// and a connection promoted with a megabyte already buffered decoded every byte of
/// it. Each reconnect injected another queue's worth and nothing bounds reconnects:
/// measured, 60 takeovers carried `in_applied` from 1.3 MB to 20.8 MB and the daemon's
/// resident set from 4.6 MB to 23.8 MB, linearly. So the cap is enforced between
/// frames in the decode loop, and this is the test that says so.
///
/// `in_applied` is what is asserted on because it is exactly what the daemon has taken
/// ownership of (§ 3): every byte queued for the PTY is below it, so a ceiling on it is
/// a ceiling on the queue. The test above measures one connection and would keep
/// passing with the cap in either place.
#[test]
fn reconnecting_does_not_raise_the_input_ceiling() {
    /// Enough per round that the old growth — a third of a megabyte a takeover —
    /// would be plain in the total, and enough to refill whatever the queue took.
    const BLAST: usize = 4 << 20;
    /// Linear growth over this many would be several megabytes; a ceiling is a
    /// ceiling after the first.
    const ROUNDS: usize = 8;

    let (session, mut client, ok) = Session::attached("input_ceiling");

    // The `sleep` holds the terminal without reading a byte for far longer than this
    // test runs — a child that woke up and drained the queue would make the ceiling
    // look like it moved.
    let ready = client.make_ready("raw -echo", Some("sleep 120"), ok.resume_from);
    drop(client);

    let chunk = vec![b'x'; 60 * 1024];
    let mut ceiling = None;
    let mut resume = ready.in_offset;

    for round in 0..ROUNDS {
        // Every round starts where the daemon says it has got to, which is what makes
        // the measurement mean anything: input below `in_applied` is trimmed rather
        // than queued (§ 3), so a round replaying from a fixed offset would be
        // discarded on arrival and would look like a ceiling holding.
        let mut frames = Vec::with_capacity(BLAST + chunk.len());
        let mut offset = resume;
        while frames.len() < BLAST {
            Frame::Input {
                offset,
                data: &chunk,
            }
            .encode(&mut frames)
            .expect("encode input");
            offset += chunk.len() as u64;
        }

        // A fresh connection each time, which is the takeover this is about.
        let mut blaster = UnixStream::connect(&session.socket).expect("connect");
        write_frame(&mut blaster, &hello_frame(0, RESUME_FROM_START, resume));
        blaster.set_nonblocking(true).expect("stop blocking");

        // The socket having refused everything for a quarter of a second is the daemon
        // having stopped taking input, so the ceiling is reached rather than merely
        // approached — which is what makes the first round a fair baseline. Eight
        // rounds of the three seconds the test above spends would be a minute of
        // waiting for a queue that is already full.
        let _pushed = push_until_refused(&mut blaster, &frames, Duration::from_millis(250));

        let mut probe = session.connect();
        let applied = probe.hello(RESUME_FROM_START, 0).in_applied;
        drop(probe);
        drop(blaster);
        resume = applied;

        let first = *ceiling.get_or_insert(applied);
        assert_eq!(
            applied, first,
            "round {round} took the input queue past the ceiling the first round \
             established: {applied} against {first}"
        );
    }

    // And the ceiling is the cap rather than an accident of how much fitted in a
    // socket buffer: one frame of overshoot is allowed, since the cap is tested
    // between frames.
    let ceiling = ceiling.expect("at least one round");
    assert!(
        ceiling >= (1 << 20),
        "the daemon stopped far short of the megabyte it is allowed to queue: {ceiling}"
    );
}

/// The daemon must not hold the directory it was started in — that pins a mount
/// for the life of the session — while the shell must still start where sshd
/// would have started it.
#[test]
fn the_daemon_releases_its_working_directory_but_the_shell_does_not() {
    let (session, mut client, ok) = Session::attached("cwd");

    let cwd = fs::read_link(format!("/proc/{}/cwd", session.child.id())).expect("read daemon cwd");
    assert_eq!(
        cwd,
        Path::new("/"),
        "daemon still holds a working directory"
    );

    client.send(&Frame::Input {
        offset: 0,
        data: b"pwd\n",
    });
    let home = session.root.to_str().expect("utf-8 root");
    let (seen, _) = client.read_until(home, ok.resume_from);
    assert!(
        seen.contains(home),
        "shell did not start in $HOME: {seen:?}"
    );
}

/// The `daemon` mode detaches itself, rather than trusting whoever started it.
///
/// § 6.2 claims the property for the mode, but `setsid` and the `/dev/null` stdio
/// lived in `attach::spawn_daemon` alone — so a daemon started any other way kept
/// the process group and the descriptors it inherited, which for a session meant
/// dying with the connection that started it. Started here with pipes on purpose,
/// so what those descriptors point at afterwards is the daemon's own doing.
///
/// The pidfile is the other half. The interactive case cannot detach without a
/// fork, and `nomux kill` reads that file, so the pid in it has to be the one that
/// survived rather than the one that started.
#[test]
fn the_daemon_mode_detaches_itself() {
    let root = run_root("detach");
    let child = Spawned::spawn(
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["daemon", "detached"])
            .env("XDG_RUNTIME_DIR", &root)
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let pid = child.id();
    wait_for(&root.join("nomux").join("detached.sock"));

    // The socket is bound before any of the detaching happens — deliberately, so a
    // session that already exists is still reported with an exit status — so
    // waiting for it is not barrier enough.
    // No assertion on the outcome: the reads below are what judge the daemon, and
    // this only keeps them from judging it before it has finished detaching.
    poll_until(Duration::from_secs(10), || {
        stat_field(pid, StatField::Session) == Some(pid) && stdio_is_silenced(&stdio_targets(pid))
    });

    // Everything read before the child is killed, so a failing assertion cannot
    // leave the daemon behind.
    let leads_session = stat_field(pid, StatField::Session);
    let stdio = stdio_targets(pid);
    let recorded = fs::read_to_string(root.join("nomux").join("detached.pid"))
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok());
    drop(child);

    assert_eq!(
        leads_session,
        Some(pid),
        "the daemon stayed in the session it was started in, so a hangup reaches it"
    );
    assert!(
        stdio_is_silenced(&stdio),
        "the daemon still holds the descriptors it was handed: {stdio:?}"
    );
    assert_eq!(
        recorded,
        Some(pid),
        "the pidfile must name the process that is actually serving"
    );
}

/// The other half of § 6.2, which the test above never reaches.
///
/// `Command` never calls `setpgid`, so a daemon it starts is not a process-group
/// leader, `setsid` succeeds outright, and the fork is unreachable from there — which
/// makes `recorded == pid` true by construction rather than by the pidfile being
/// written in the right order. Moving `detach_from_login_session` to after
/// `write_pidfile` leaves that test passing, so it guards nothing. Making the child a
/// group leader first is what forces the `EPERM` only a fork can answer, and it is
/// the shape a shell with job control produces.
///
/// The daemon that survives is in nobody's process group and is nobody's child, so
/// `wait` collects the process that started and nothing else — it has to be reaped
/// through `nomux kill`, before the assertions rather than after them.
#[test]
fn a_daemon_that_leads_a_process_group_detaches_by_forking() {
    let root = run_root("fork");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nomux"));
    command
        .args(["daemon", "grouped"])
        .env("XDG_RUNTIME_DIR", &root)
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::piped())
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
    let mut starter = Spawned::spawn(&mut command);
    let original_pid = starter.id();

    let pid_file = root.join("nomux").join("grouped.pid");
    wait_for(&root.join("nomux").join("grouped.sock"));
    wait_for(&pid_file);

    // Bounded rather than a bare `wait`: if the fork never happened then the process
    // started here *is* the daemon, and waiting on it would hang the suite instead of
    // failing an assertion.
    let starter_exited = poll_until(Duration::from_secs(10), || !starter.is_running());

    // `recorded` outlives the wait because the assertions below are about the pid the
    // last look found, whether or not it ever satisfied the condition.
    let mut recorded = None;
    poll_until(Duration::from_secs(10), || {
        recorded = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        recorded.is_some_and(|pid| {
            stat_field(pid, StatField::Session) == Some(pid)
                && stdio_is_silenced(&stdio_targets(pid))
        })
    });

    // Everything read before anything is collected, so a failing assertion cannot
    // leave a session behind.
    let leads_session = recorded.and_then(|pid| stat_field(pid, StatField::Session));
    let stdio = recorded.map(stdio_targets).unwrap_or_default();
    let alive = recorded.is_some_and(process_alive);
    drop(control(&root, &["kill", "grouped"]));
    drop(starter);

    assert!(
        starter_exited,
        "the process that started never left, so nothing forked"
    );
    assert_ne!(
        recorded,
        Some(original_pid),
        "the pidfile names the process that started, which has since exited — \
         `nomux kill` would signal nobody"
    );
    assert!(
        alive,
        "no live daemon behind the pidfile: it names {recorded:?}"
    );
    assert_eq!(
        leads_session, recorded,
        "the forked child must lead a session of its own"
    );
    assert!(
        stdio_is_silenced(&stdio),
        "the forked child still holds the descriptors it was handed: {stdio:?}"
    );
}

/// What the three standard descriptors of `pid` point at.
fn stdio_targets(pid: u32) -> Vec<PathBuf> {
    (0..3)
        .map(|fd| fs::read_link(format!("/proc/{pid}/fd/{fd}")).unwrap_or_default())
        .collect()
}

/// Whether all three point at `/dev/null`, which is where detaching puts them.
///
/// Takes what was read rather than a pid, so an assertion can report the targets it
/// judged: they have to be collected before the daemon is, and `/proc` has nothing
/// to say about it afterwards.
fn stdio_is_silenced(targets: &[PathBuf]) -> bool {
    targets.iter().all(|path| path == Path::new("/dev/null"))
}

/// A session created without the flag serves no socket at all: forwarding bypasses
/// the user's `ForwardAgent` decision, so it must never be on by default.
#[test]
fn agent_forwarding_is_off_unless_asked_for() {
    let (session, _client, ok) = Session::attached("agent_off");
    assert!(!ok.agent);
    assert!(
        !session.agent_socket().exists(),
        "no agent socket should exist for a session that did not ask for one"
    );
}

/// Agent forwarding, end to end: the child gets a socket, a connection to it
/// becomes a channel, and bytes cross in both directions untouched.
#[test]
fn agent_forwarding_proxies_a_connection_in_both_directions() {
    let (session, mut client, ok) = Session::attached_with("agent", HELLO_AGENT_FORWARD);
    assert!(ok.agent, "daemon should report the agent socket as served");

    // The child must be able to find it, which is the whole point.
    client.send(&Frame::Input {
        offset: 0,
        data: b"echo \"sock=$SSH_AUTH_SOCK\"\n",
    });
    let (seen, _) = client.read_until(".agent", ok.resume_from);
    let expected = format!("sock={}", session.agent_socket().display());
    assert!(seen.contains(&expected), "child environment: {seen:?}");

    let mut agent = session.connect_agent();
    let chan = client.next_chan(FrameType::AgentOpen);

    // Child to client.
    agent.write_all(b"\0\0\0\x01\x0b").expect("write request");
    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            chan,
            data: b"\0\0\0\x01\x0b",
        },
        "agent bytes must arrive verbatim"
    );

    // Client to child.
    client.send(&Frame::AgentData {
        chan,
        data: b"\0\0\0\x05\x0c-reply",
    });
    let mut reply = [0u8; 11];
    agent.read_exact(&mut reply).expect("read response");
    assert_eq!(&reply, b"\0\0\0\x05\x0c-reply");

    // And the close travels too.
    drop(agent);
    assert_eq!(client.next_chan(FrameType::AgentClose), chan);
}

/// With no client attached there is nothing to answer a signature request, so a
/// connection is accepted and closed at once: `git push` fails with the same error
/// as a missing agent instead of hanging until the user reattaches.
///
/// § 6.7 says it of both halves — the connection that arrives while detached, and
/// the channel that was already open the moment the client went. The second is the
/// one with somebody actually waiting on it: a `git push` mid-signature when the
/// network drops learns now, rather than at whatever hour the user reattaches, and
/// the daemon cannot hold the channel for a client that will come back with no idea
/// the channel exists (ids are never reissued).
#[test]
fn agent_connections_fail_fast_while_detached() {
    let (session, mut client, _) = Session::attached_with("agent_detached", HELLO_AGENT_FORWARD);

    // Open before the client leaves, and confirmed open — otherwise the read below
    // could be answered by a socket the daemon had not yet accepted.
    let mut mid_flight = session.connect_agent();
    let _chan = client.next_chan(FrameType::AgentOpen);
    drop(client);

    let mut buf = [0u8; 1];
    assert_eq!(
        mid_flight
            .read(&mut buf)
            .expect("read from the open channel"),
        0,
        "a channel that was open when the client left must be closed, not held"
    );

    let mut arriving = session.connect_agent();
    assert_eq!(
        arriving.read(&mut buf).expect("read from agent socket"),
        0,
        "a detached session must close agent connections immediately"
    );
}

/// The channel table is capped, and beyond the cap the daemon closes rather than
/// queueing — a child that leaks agent connections must not be able to make the
/// daemon track them.
#[test]
fn agent_channels_are_capped() {
    let (session, mut client, _) = Session::attached_with("agent_cap", HELLO_AGENT_FORWARD);

    let cap = MAX_AGENT_CHANNELS as usize;
    let held: Vec<UnixStream> = (0..cap).map(|_| session.connect_agent()).collect();
    let mut ids: Vec<u32> = (0..cap)
        .map(|_| client.next_chan(FrameType::AgentOpen))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), cap, "channel ids must never repeat");

    let mut extra = session.connect_agent();
    let mut buf = [0u8; 1];
    assert_eq!(
        extra.read(&mut buf).expect("read from agent socket"),
        0,
        "the connection past the cap must be closed, not queued"
    );
    drop(held);
}

/// Ids come from a counter that never rewinds, so a channel closing and another
/// opening cannot be confused for one another.
#[test]
fn agent_channel_ids_are_never_reused() {
    let (session, mut client, _) = Session::attached_with("agent_ids", HELLO_AGENT_FORWARD);

    let mut previous = 0;
    for round in 0..4 {
        let agent = session.connect_agent();
        let chan = client.next_chan(FrameType::AgentOpen);
        assert!(chan > previous, "round {round}: id {chan} did not advance");
        previous = chan;
        drop(agent);
        assert_eq!(client.next_chan(FrameType::AgentClose), chan);
    }
}

/// Drives a session to an overflow gap and returns what the child saw afterwards.
///
/// `cat` is the child because it hands back whatever reaches the PTY's input side,
/// which is the only way to observe a repaint that is delivered as a keystroke.
/// The ring is tiny so a few kilobytes echoed while detached is enough to overflow
/// it.
fn repaint_transcript(name: &str, flags: u16) -> String {
    let session = Session::start_with_ring(name, 1024);
    let mut client = session.connect();
    let ok = client.hello_with(flags, RESUME_FROM_START, 0);

    let ready = client.make_ready("-echo -onlcr", Some("cat"), ok.resume_from);
    let offset = ready.offset;

    // Echoed back by `cat` with nobody reading, which is what overflows the ring.
    // In lines, because the line discipline is still canonical: `cat` would see
    // nothing at all until a newline arrived, and the overflow would never happen.
    let filler = format!("{}\n", "x".repeat(63)).repeat(512);
    let filler = filler.as_bytes();
    let mut in_offset = ready.in_offset;
    client.send(&Frame::Input {
        offset: in_offset,
        data: filler,
    });
    in_offset += filler.len() as u64;
    client.wait_for_input_ack(in_offset);
    drop(client);

    // The repaint is the daemon's answer to a gap, so the gap has to have happened
    // before there is anything to look at. Waited for rather than slept through:
    // whether the ring has overflowed yet is a question about the scheduler.
    let (mut client, resumed) = reconnect_until_gap(&session, flags, offset, in_offset);

    // A fence bounds the wait: whatever the repaint was going to be has been
    // echoed by the time this comes back.
    client.send(&Frame::Input {
        offset: in_offset,
        data: b"FENCE\n",
    });
    read_past_gaps(&mut client, "FENCE", resumed.resume_from)
}

/// Collects the child's output until `needle` appears, following the ring over any
/// overflow it hits on the way.
///
/// `Client::read_until` refuses a `Gap`, which is right everywhere else in this
/// suite: an unannounced discontinuity is most of what these tests exist to catch.
/// It is wrong here. The ring is a kilobyte on purpose and the child is still
/// echoing tens of kilobytes of filler when the client comes back, so overflow
/// *while attached* is the ordinary case rather than a surprise — and waiting for
/// the child to fall quiet first is exactly the sleep this was written to be rid of.
/// What the caller is looking for survives it either way: the repaint keystroke and
/// the fence behind it are the last few bytes the child writes, and the newest
/// kilobyte is the one thing the ring never discards.
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "the allow-*-in-tests settings in clippy.toml reach `#[test]` bodies, \
              not a helper an integration test crate keeps beside them"
)]
fn read_past_gaps(client: &mut harness::Client, needle: &str, from: u64) -> String {
    let mut seen = Vec::new();
    let mut offset = from;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode frame") {
            Frame::Output { offset: at, data } => {
                assert_eq!(
                    at, offset,
                    "output must be contiguous unless a gap said otherwise"
                );
                offset += data.len() as u64;
                seen.extend_from_slice(data);
                if String::from_utf8_lossy(&seen).contains(needle) {
                    return String::from_utf8_lossy(&seen).into_owned();
                }
            }
            Frame::Gap { new_base_offset } => offset = new_base_offset,
            Frame::InputAck { .. } | Frame::Pong { .. } => {}
            other => panic!("unexpected {other:?} while awaiting {needle:?}"),
        }
    }
    panic!(
        "timed out waiting for {needle:?}; saw: {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// The post-gap repaint is the client's choice, and `ctrl_l` reaches the child as
/// an actual keystroke — the one thing a bare shell prompt responds to, since it
/// ignores `SIGWINCH` entirely.
#[test]
fn a_gap_repaints_with_ctrl_l_only_when_the_client_asks() {
    let asked = repaint_transcript("repaint_ctrl_l", HELLO_REPAINT_CTRL_L);
    assert!(
        asked.contains('\u{c}'),
        "no Ctrl-L reached the child: {asked:?}"
    );

    let default = repaint_transcript("repaint_winch", 0);
    assert!(
        !default.contains('\u{c}'),
        "the default policy must not write to the PTY: {default:?}"
    );
}

/// A daemon spawned by a connection that died mid-handshake must reap itself.
///
/// Every reaping rule is only checked when `poll` returns, so this is really a test
/// that a wakeup is armed for the 30-second first-attach deadline rather than only
/// for the hour-long backstop. Waiting out that deadline is the only way to observe
/// it from outside, which is why this is `#[ignore]`d: 30 seconds is unreasonable
/// in a suite that otherwise finishes in two, and CI runs it with
/// `--run-ignored all`.
#[test]
#[ignore = "waits out the 30-second first-attach timeout; run in CI, not on every commit"]
fn a_daemon_nobody_ever_attaches_to_reaps_itself() {
    let session = Session::start("unattached");
    assert!(session.socket.exists());

    assert!(
        poll_until(Duration::from_secs(45), || !session.socket.exists()),
        "daemon outlived its first-attach timeout"
    );
}

/// A daemon that reaps itself runs its shutdown to completion.
///
/// `Pty::terminate` signals the child's process group, and `kill_process_group`
/// negates the pid itself — so passing an already-negative one both defeated the
/// group kill and, because `Pid::from_raw` asserts its argument is non-negative,
/// aborted the daemon partway through `shutdown` in any debug build. The visible
/// symptom is this one: the run files outlive the session, and `list` then reports
/// a session nobody can attach to until something else garbage-collects it.
#[test]
fn a_daemon_that_reaps_itself_removes_its_run_files() {
    let (session, mut client, _) = Session::attached("shutdown_cleanup");

    let pid_file = session.pid_file();
    assert!(
        pid_file.exists(),
        "the daemon should have written its pidfile"
    );

    // The child exits and the client leaves. The linger window is deliberately *not*
    // collapsed by the departure — `on_detached` leaves `linger_until` alone, because
    // the client the window exists for is the one that has not arrived yet (§ 6.5) —
    // so what ends the daemon here is the five-second `EXIT_LINGER` expiring, and
    // `shutdown` then unlinks the run files. Hence the generous deadline below.
    client.send(&Frame::Input {
        offset: 0,
        data: b"exit 3\n",
    });
    client.drain_available();
    drop(client);

    assert!(
        poll_until(Duration::from_secs(15), || !pid_file.exists()
            && !session.socket.exists()),
        "run files outlived the daemon: socket={} pid={}",
        session.socket.exists(),
        pid_file.exists()
    );
}

/// `SIGTERM` must leave through the shutdown path, not the default disposition.
///
/// `nomux kill` signals the daemon and gives it two seconds. Without a handler it
/// died where it stood, so `Pty::terminate` never ran — and closing the PTY master
/// hides that for the ordinary case, because the kernel delivers `SIGHUP` to the
/// foreground process group on the way out. What it does not cover is a
/// backgrounded process that ignores the hangup, which is what this starts: `trap
/// '' HUP` before the fork, since an *ignored* disposition is inherited through
/// `exec` where a trapped one is reset.
///
/// `set +m` is what puts that process where reaping can see it. An interactive
/// shell gives every job a process group of its own, and nothing in the session
/// ever signals those — a real gap, but a different one, and one no `SIGTERM`
/// handler would close. With job control off the job stays in the shell's group,
/// which is what `Pty::terminate` signals and what a script's background processes
/// do anyway.
#[test]
fn a_signalled_daemon_collects_a_process_that_ignores_sighup() {
    let (session, mut client, ok) = Session::attached("sigterm");

    // The marker trails the pid so that seeing it proves the digits already
    // arrived, and the arithmetic keeps it out of the line discipline's echo of the
    // command itself — which would otherwise match first, carrying `$!` unexpanded.
    let script = b"set +m; trap '' HUP; sleep 300 & echo \"$!-NOMUX-ORPHAN-$((6*7))\"\n";
    client.send(&Frame::Input {
        offset: 0,
        data: script,
    });
    let (seen, _) = client.read_until("-NOMUX-ORPHAN-42", ok.resume_from);
    let orphan = trailing_pid(&seen, "-NOMUX-ORPHAN-42")
        .unwrap_or_else(|| panic!("no background pid in the transcript: {seen:?}"));
    // Everything below is an assertion about a process that is deliberately in
    // nobody's reach: if one of them fires, `sleep 300` outlives the whole suite.
    let _collected = Reaper(orphan);
    assert!(
        process_alive(orphan),
        "the backgrounded process was gone before the session ended"
    );
    let shell = child_of(session.child.id()).expect("find the session shell");
    assert_eq!(
        stat_field(orphan, StatField::ProcessGroup),
        Some(shell),
        "this shell kept job control on, so nothing here is testing reaping"
    );

    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    let pid_file = session.pid_file();
    // Signalled directly rather than through `nomux kill`, which unlinks the run
    // files itself and would answer the question for the daemon.
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");

    // Inside the two seconds `nomux kill` allows before `SIGKILL`, with room for a
    // loaded machine: an overrun there is this same bug wearing a hat.
    assert!(
        poll_until(Duration::from_secs(10), || !pid_file.exists()
            && !session.socket.exists()),
        "run files outlived the signalled daemon: socket={} pid={}",
        session.socket.exists(),
        pid_file.exists()
    );

    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(orphan)),
        "pid {orphan} outlived the session it was backgrounded in"
    );
}

/// A session with nothing left running is torn down at once, rather than waiting
/// out the grace period that only the stubborn case needs.
///
/// The grace period is 500 ms, and it used to be spent on *every* shutdown. The
/// loop's exit condition asks the process group first and only then walks `/proc`,
/// and an unreaped zombie is still a member of its own group — so the group probe
/// answered "still alive" for the very child the daemon was about to collect, and
/// the `&&` short-circuited before the `/proc` walk, which filters zombies, could
/// disagree. On the path that matters the child *is* unreaped: `reap` runs only
/// once the PTY has reported end of file, which on the `nomux kill` path it has
/// not.
///
/// Hence the bound below sits under the grace period rather than under § 6.6's
/// two-second budget: the regression this guards has a hard floor of 500 ms, so
/// anything that reintroduces it lands strictly above the bound however lightly
/// loaded the machine is. What is left is the honest work — two `/proc` walks and
/// a poll interval or two — which measures in tens of milliseconds.
#[test]
fn a_signalled_daemon_with_a_quiet_child_does_not_wait_out_the_grace_period() {
    let (mut session, mut client, ok) = Session::attached("fastkill");
    // So the measurement covers a session with a live shell in it, rather than the
    // window before the child exists at all.
    client.send(&Frame::Input {
        offset: 0,
        data: b"echo NOMUX-READY\n",
    });
    client.read_until("NOMUX-READY", ok.resume_from);

    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    let began = Instant::now();
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");

    let exited = poll_until(Duration::from_secs(10), || {
        session
            .child
            .try_wait()
            .expect("wait for the daemon")
            .is_some()
    });
    // Read before the assertions, since the first of them is about how long the
    // second one took to become true.
    let elapsed = began.elapsed();
    assert!(exited, "the signalled daemon never exited");
    assert!(
        elapsed < Duration::from_millis(400),
        "shutdown took {elapsed:?}, at or over the 500 ms grace period it \
         should only pay when something is still running"
    );
}

/// Kills a pid when it goes out of scope.
///
/// The processes these tests background are backgrounded *on purpose*, so nothing
/// else reaps them: a `sleep 300` left behind by a failing assertion is still there
/// when the next run starts, and the failure it caused is now accompanied by one it
/// did not. Read-then-kill-then-assert says the same thing where the ordering is
/// simple enough to arrange; this covers the case where it is not, and it fires on a
/// panic from anywhere in between.
struct Reaper(u32);

impl Drop for Reaper {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.cast_signed()) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
}

/// The run of digits immediately before `marker`, as a pid.
fn trailing_pid(transcript: &str, marker: &str) -> Option<u32> {
    let (head, _) = transcript.rsplit_once(marker)?;
    let reversed: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    reversed.chars().rev().collect::<String>().parse().ok()
}

/// A numeric field of `/proc/<pid>/stat`, by what it means.
#[derive(Clone, Copy)]
enum StatField {
    /// The process group the process belongs to.
    ProcessGroup = 2,
    /// The session it belongs to, which is its own pid exactly when it leads one.
    Session = 3,
}

/// Reads one field of `/proc/<pid>/stat`.
///
/// Counted from the state letter that follows the parenthesised command name,
/// because counting from the front stops working the moment a command name
/// contains a space or a bracket — and `sh` starting `a b )` is enough.
fn stat_field(pid: u32, field: StatField) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, tail) = stat.rsplit_once(')')?;
    tail.split_whitespace().nth(field as usize)?.parse().ok()
}

/// Whether `pid` is still a process rather than gone or a zombie awaiting its
/// parent. A collected process group reaches one of the latter two promptly.
fn process_alive(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, tail)) = stat.rsplit_once(')') else {
        return false;
    };
    !tail.trim_start().starts_with('Z')
}

/// Regression: a reconnect racing with in-flight input must not discard it.
///
/// One `poll` can report a readable client and a `Hello` from its replacement
/// together. The daemon originally took over on the *connect* and dropped the
/// outgoing connection there and then — and with it any frame still unread in its
/// socket buffer — so keystrokes vanished whenever a reconnect landed in the same
/// iteration as input the user had already sent.
///
/// Each round sets that interleaving up on purpose rather than hoping for it: the
/// replacement connects and is left un-greeted until the daemon has certainly
/// accepted it, and only then does the outgoing client send input, immediately
/// followed by the `Hello` that evicts it. Both land in one wakeup, and the
/// outgoing connection is not closed until after the assertion — so nothing here
/// depends on how the kernel treats a socket closed with data still queued.
#[test]
fn a_takeover_never_discards_input_already_delivered() {
    let (session, mut client, _) = Session::attached("takeover_input");

    let command = b"true NOMUX-KEEP\n";
    let mut expected = 0u64;

    for round in 0..15 {
        let mut next = session.connect();
        thread::sleep(Duration::from_millis(60));

        client.send(&Frame::Input {
            offset: expected,
            data: command,
        });
        expected += command.len() as u64;
        let ok = next.hello(RESUME_FROM_START, expected);
        assert_eq!(
            ok.in_applied, expected,
            "round {round}: input delivered before the takeover was lost"
        );
        client = next;
    }
}

/// Regression: a `Hello` the daemon cannot answer must not cost the session the
/// client it already has.
///
/// Version skew is the one compatibility case that exists (`DESIGN.md` § 6.4), and
/// its shape is a *newer* client reaching a session an older daemon is still
/// holding. The refusal used to happen after the takeover rather than before it, so
/// the failed handshake evicted the working client with `Error{TAKEOVER}` and then
/// dropped the newcomer too, leaving the session running with nobody attached. § 6.4
/// tells a client never to auto-reconnect after a takeover — so the user's shell
/// went quiet and stayed quiet, over a connection attempt that was refused.
#[test]
fn a_version_mismatch_refuses_the_newcomer_without_evicting_the_client() {
    let (session, mut client, ok) = Session::attached("skew");

    // The incumbent is serving before the newcomer knocks, or the assertion below
    // that it still is would be about nothing.
    let first = b"echo NOMUX-FIRST\n";
    client.send(&Frame::Input {
        offset: 0,
        data: first,
    });
    let (_, from) = client.read_until("NOMUX-FIRST", ok.resume_from);

    let mut newcomer = session.connect();
    newcomer.send(&Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION + 1,
        flags: 0,
        out_offset: RESUME_FROM_START,
        in_offset: 0,
        win: harness::WIN,
        term: "xterm-256color",
    }));
    let payload = newcomer.next_of(FrameType::Error);
    let refusal = Frame::decode(FrameType::Error, &payload).expect("decode the refusal");
    assert!(
        matches!(
            refusal,
            Frame::Error {
                code: ErrorCode::Version,
                ..
            }
        ),
        "a mismatched Hello must be refused as a version error, got {refusal:?}"
    );

    // The incumbent kept the session: it never saw a takeover, and its input stream
    // carries on from where it was rather than restarting.
    let second = b"echo NOMUX-STILL-HERE\n";
    client.send(&Frame::Input {
        offset: first.len() as u64,
        data: second,
    });
    let (seen, _) = client.read_until("NOMUX-STILL-HERE", from);
    assert!(seen.contains("NOMUX-STILL-HERE"), "transcript: {seen:?}");
}

/// Regression: a client vanishing must never take the session with it.
///
/// Closing a socket that still has unread data queued makes the kernel send RST
/// rather than FIN, so the daemon's next read fails with `ECONNRESET`. That error
/// was originally propagated out of the event loop and terminated the daemon —
/// killing the shell over exactly the kind of unclean disconnect this project
/// exists to survive.
#[test]
fn an_abrupt_client_disconnect_does_not_kill_the_session() {
    let (session, mut client, _) = Session::attached("reset");

    let command = b"echo NOMUX-SURVIVED\n";
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });

    // The daemon owns the command before the connection goes, so the assertion below
    // is about what the session kept rather than about what it managed to read in
    // the time somebody guessed at.
    client.wait_for_input_ack(command.len() as u64);
    // And it has written something nobody read, which is what makes the close an RST
    // rather than an orderly FIN — that reset is the whole fault under test.
    client.wait_for_unread_bytes();
    drop(client);

    // Straight into the reconnect: the handshake is itself the wait for the daemon to
    // have dealt with the disconnect, since `in_applied` in the reply is authoritative
    // and the takeover path runs before it is answered.
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);
    assert_eq!(
        ok.in_applied,
        command.len() as u64,
        "session lost its input state after an abrupt disconnect"
    );

    client.send(&Frame::Input {
        offset: ok.in_applied,
        data: b"echo NOMUX-STILL-HERE\n",
    });
    let (seen, _) = client.read_until("NOMUX-STILL-HERE", ok.resume_from);
    assert!(seen.contains("NOMUX-STILL-HERE"), "transcript: {seen:?}");
}

/// Bulk traffic through the attach relay, both ways at once.
///
/// The relay moves bytes with `splice(2)` where the kernel allows it and by
/// copying where it does not, decided per direction at runtime — two paths through
/// the one component that must never break. Megabytes are what makes that
/// interesting: enough to fill and refill the pipe and the socket, so both paths
/// hit short transfers and full destinations. A chunk dropped, replayed or
/// reordered at a path boundary then shows up as a first-difference index instead
/// of as output that still looks plausible.
///
/// No daemon here on purpose. The relay never parses a frame, so a bare socket is
/// a complete peer, and the assertions can be about bytes rather than about the
/// protocol.
#[test]
fn the_relay_moves_bulk_traffic_both_ways_without_losing_a_byte() {
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;

    const BULK: usize = 2 * 1024 * 1024;

    let root = run_root("bulk");
    let dir = root.join("nomux");
    fs::create_dir_all(&dir).expect("create run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("tighten run dir");
    let listener = UnixListener::bind(dir.join("relay_bulk.sock")).expect("bind session socket");

    let mut child = Spawned::spawn(
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["attach", "relay_bulk"])
            .env("XDG_RUNTIME_DIR", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );

    let peer = Arc::new(accept_within(
        &listener,
        Duration::from_secs(10),
        "`nomux attach` to connect to the session socket",
    ));
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");

    let upstream = Rng::new(0x5eed_1234).bytes(BULK);
    let downstream = Rng::new(0xfeed_9876).bytes(BULK);

    // Four threads because all four flows must run at once: with any one of them
    // parked the relay's back pressure would deadlock the other three.
    let feed = {
        let data = upstream.clone();
        thread::spawn(move || {
            stdin.write_all(&data).expect("write to relay stdin");
            // Half-close, which the relay must turn into shutdown(SHUT_WR) on the
            // socket while still draining the other direction.
            drop(stdin);
        })
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
    let downlink = thread::spawn(move || {
        let mut got = Vec::new();
        stdout.read_to_end(&mut got).expect("read relay stdout");
        got
    });

    feed.join().expect("feeder thread");
    let uplink = uplink.join().expect("socket reader thread");
    push.join().expect("pusher thread");
    // Only now: the relay ends the moment the socket reports EOF, so closing this
    // any earlier would truncate the direction under test rather than test it.
    peer.shutdown(Shutdown::Write)
        .expect("half-close the socket");
    let downlink = downlink.join().expect("stdout reader thread");

    let mut complaints = String::new();
    drop(stderr.read_to_string(&mut complaints));
    drop(child);

    assert_same(&upstream, &uplink, "stdin -> socket", &complaints);
    assert_same(&downstream, &downlink, "socket -> stdout", &complaints);
}

/// Regression: the relay must leave when its output has nowhere left to go.
///
/// `splice` into a full destination reports `EAGAIN`, which the relay records as
/// `dest_full` and answers by polling that destination for `POLLOUT` and holding
/// off on reading the source. If the destination's peer then dies, `poll` reports
/// `POLLERR` — never `POLLOUT`, because a pipe nobody is reading never becomes
/// writable — and the drain that would clear the latch was guarded on `POLLOUT`
/// alone. Nothing in the iteration could act, nothing could change, and the loop
/// went round at the speed of the scheduler: a `nomux attach` pinned at 100% CPU
/// on somebody's server for as long as the socket stayed open.
///
/// The shape is the ordinary one for this project rather than a corner: output
/// backed up in the pipe is exactly the state a connection is in when the network
/// drops under load.
///
/// A bare socket for a peer, as in the bulk test above — the relay parses nothing,
/// so a daemon here would only add a protocol conversation the bug does not need.
#[test]
fn the_relay_exits_when_its_stdout_dies_with_the_destination_latched_full() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let root = run_root("spin");
    let dir = root.join("nomux");
    fs::create_dir_all(&dir).expect("create run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("tighten run dir");
    let listener = UnixListener::bind(dir.join("relay_spin.sock")).expect("bind session socket");

    let mut child = Spawned::spawn(
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["attach", "relay_spin"])
            .env("XDG_RUNTIME_DIR", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
    );

    let mut peer = accept_within(
        &listener,
        Duration::from_secs(10),
        "`nomux attach` to connect to the session socket",
    );
    // Stdin stays open and idle throughout. It is in the poll set the whole time,
    // which is the point: the wakeups being spun on come from stdout, so a relay
    // that blocked on stdin instead would hide the bug.
    let _stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    // Push until the kernel stops taking it: that is the socket buffer *and* the
    // stdout pipe both full, which is what leaves the relay's last `splice` sitting
    // on `EAGAIN` with `dest_full` latched and its buffer empty.
    peer.set_nonblocking(true).expect("nonblocking peer");
    let chunk = vec![b'x'; 64 * 1024];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match peer.write(&chunk) {
            Ok(0) => break,
            Ok(_) => thread::sleep(Duration::from_millis(5)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => panic!("writing to the relay's socket failed: {err}"),
        }
    }
    // Nothing has read a byte of stdout, so the pipe is full and the relay is
    // waiting for it to become writable. Now take away the reader.
    drop(stdout);

    assert!(
        poll_until(Duration::from_secs(10), || !child.is_running()),
        "the relay was still running with its stdout gone and its buffer empty"
    );
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
