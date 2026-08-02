//! End-to-end tests against the real binary.
//!
//! These drive `nomux daemon` over its unix socket, speaking the wire protocol
//! directly, so they exercise the PTY, the ring buffer and the resume path rather
//! than a mock of them.
//!
//! The two invariants that matter (`IMPLEMENTATION.md` § 9): input is never
//! duplicated, and output is never lost unless a `Gap` was reported.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the allow-*-in-tests settings in clippy.toml only apply to #[cfg(test)] \
              modules, not to integration test crates; a failed assertion here should \
              panic, which is the whole point"
)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use nomux_proto::{
    Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
    decode_header,
};

const WIN: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

/// A daemon running in an isolated run directory, killed on drop.
struct Session {
    child: Child,
    socket: PathBuf,
    id: String,
}

impl Session {
    fn start(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("run-{name}"));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).expect("create run root");

        let id = format!("test_{name}");
        let child = Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["daemon", &id])
            .env("XDG_RUNTIME_DIR", &root)
            // A predictable shell keeps assertions independent of the developer's
            // login environment.
            .env("SHELL", "/bin/sh")
            .env("PS1", "")
            // A small ring makes overflow reachable in milliseconds instead of
            // requiring megabytes of output.
            .env("NOMUX_RING_BYTES", "65536")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");

        let socket = root.join("nomux").join(format!("{id}.sock"));
        wait_for(&socket);
        Self { child, socket, id }
    }

    fn connect(&self) -> Client {
        let stream = UnixStream::connect(&self.socket).expect("connect to session");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("set read timeout");
        Client {
            stream,
            pending: Vec::new(),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("daemon never bound {}", path.display());
}

/// A protocol client: enough of one to assert on daemon behaviour.
struct Client {
    stream: UnixStream,
    pending: Vec<u8>,
}

impl Client {
    fn send(&mut self, frame: &Frame<'_>) {
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        self.stream.write_all(&buf).expect("write frame");
    }

    fn hello(&mut self, out_offset: u64, in_offset: u64) -> nomux_proto::HelloOk {
        self.send(&Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset,
            in_offset,
            win: WIN,
            term: "xterm-256color",
        }));
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

    fn next_frame(&mut self) -> (FrameType, Vec<u8>) {
        loop {
            if self.pending.len() >= HEADER_LEN {
                let head: [u8; HEADER_LEN] = self.pending[..HEADER_LEN].try_into().unwrap();
                let header = decode_header(&head).expect("decode header");
                let total = HEADER_LEN + header.len as usize;
                if self.pending.len() >= total {
                    let payload = self.pending[HEADER_LEN..total].to_vec();
                    self.pending.drain(..total);
                    return (header.ty, payload);
                }
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).expect("read from daemon");
            assert!(n > 0, "daemon closed the connection unexpectedly");
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }

    /// Collects output until `needle` appears, returning everything consumed and
    /// the offset one past the last output byte.
    fn read_until(&mut self, needle: &str, from: u64) -> (String, u64) {
        let mut seen = Vec::new();
        let mut offset = from;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let (ty, payload) = self.next_frame();
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(at, offset, "output offsets must be contiguous");
                    offset += data.len() as u64;
                    seen.extend_from_slice(data);
                    if String::from_utf8_lossy(&seen).contains(needle) {
                        return (String::from_utf8_lossy(&seen).into_owned(), offset);
                    }
                }
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

#[test]
fn runs_a_shell_and_streams_its_output() {
    let session = Session::start("basic");
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);
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
    let session = Session::start("resume");
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);

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

/// The invariant that matters most: a client replaying input it already sent —
/// because the `InputAck` was lost with the connection — must not run it twice.
#[test]
fn replayed_input_is_applied_exactly_once() {
    let session = Session::start("dedup");
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);

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

#[test]
fn overflow_is_reported_as_a_gap_rather_than_silently_truncated() {
    let session = Session::start("gap");
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);

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
    // even with nobody listening. Poll rather than guessing at a fixed delay.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut client = session.connect();
        let resumed = client.hello(ok.resume_from, filler.len() as u64);
        if resumed.gap {
            assert!(
                resumed.resume_from > ok.resume_from,
                "resume point must advance past the discarded bytes"
            );
            return;
        }
        drop(client);
        assert!(
            Instant::now() < deadline,
            "ring never overflowed: base={} in_applied={} (sent {} input bytes)",
            resumed.resume_from,
            resumed.in_applied,
            filler.len()
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_second_client_takes_over_and_the_first_is_told_why() {
    let session = Session::start("takeover");
    let mut first = session.connect();
    first.hello(RESUME_FROM_START, 0);

    let mut second = session.connect();
    second.hello(RESUME_FROM_START, 0);

    let (ty, payload) = first.next_frame();
    let frame = Frame::decode(ty, &payload).expect("decode");
    assert!(
        matches!(
            frame,
            Frame::Error {
                code: nomux_proto::ErrorCode::Takeover,
                ..
            }
        ),
        "evicted client must learn it was a takeover, not a network fault: {frame:?}"
    );
}

#[test]
fn list_and_kill_operate_without_the_protocol() {
    let session = Session::start("control");
    let mut client = session.connect();
    client.hello(RESUME_FROM_START, 0);

    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("run-control");
    let listed = Command::new(env!("CARGO_BIN_EXE_nomux"))
        .arg("list")
        .env("XDG_RUNTIME_DIR", &root)
        .output()
        .expect("run list");
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.contains(&session.id),
        "list should report the live session, got {listed:?}"
    );

    let status = Command::new(env!("CARGO_BIN_EXE_nomux"))
        .args(["kill", &session.id])
        .env("XDG_RUNTIME_DIR", &root)
        .status()
        .expect("run kill");
    assert!(status.success());

    let socket = root.join("nomux").join(format!("{}.sock", session.id));
    assert!(!socket.exists(), "kill must unlink the run files");
}

#[test]
fn invalid_session_ids_are_refused() {
    for id in ["../escape", "with/slash", "with space"] {
        let output = Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["attach", id])
            .env("XDG_RUNTIME_DIR", env!("CARGO_TARGET_TMPDIR"))
            .output()
            .expect("run attach");
        assert!(!output.status.success(), "id {id:?} should be rejected");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("invalid session id"),
            "id {id:?} should be rejected by name"
        );
    }
}

/// Exercises the path a real bootstrap takes: `nomux attach` with no daemon
/// running, which must spawn one under the flock and then relay transparently.
#[test]
fn attach_spawns_the_daemon_and_relays_transparently() {
    use std::sync::mpsc;

    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("run-relay");
    drop(fs::remove_dir_all(&root));
    fs::create_dir_all(&root).expect("create run root");

    let mut child = Command::new(env!("CARGO_BIN_EXE_nomux"))
        .args(["attach", "relay_probe"])
        .env("XDG_RUNTIME_DIR", &root)
        .env("SHELL", "/bin/sh")
        .env("NOMUX_RING_BYTES", "65536")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn attach");

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

    let mut frame = Vec::new();
    Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        flags: 0,
        out_offset: RESUME_FROM_START,
        in_offset: 0,
        win: WIN,
        term: "xterm-256color",
    })
    .encode(&mut frame)
    .expect("encode hello");
    stdin.write_all(&frame).expect("write hello");

    frame.clear();
    Frame::Input {
        offset: 0,
        data: b"echo NOMUX-RELAY\n",
    }
    .encode(&mut frame)
    .expect("encode input");
    stdin.write_all(&frame).expect("write input");
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
    drop(child.kill());
    drop(child.wait());
    drop(pump.join());

    drop(
        Command::new(env!("CARGO_BIN_EXE_nomux"))
            .args(["kill", "relay_probe"])
            .env("XDG_RUNTIME_DIR", &root)
            .status(),
    );

    assert!(
        found,
        "attach did not spawn a daemon and relay its output; saw {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// Regression: a reconnect racing with in-flight input must not discard it.
///
/// One `poll` can report a readable client and a pending connection together. The
/// daemon originally accepted first, dropping the outgoing connection — and with
/// it any frame still unread in its socket buffer — so keystrokes vanished
/// whenever a reconnect landed in the same iteration as input the user had
/// already sent. Repeated here because the interleaving is timing-dependent.
#[test]
fn a_takeover_never_discards_input_already_delivered() {
    let session = Session::start("takeover_input");
    let mut client = session.connect();
    client.hello(RESUME_FROM_START, 0);

    let command = b"true NOMUX-KEEP\n";
    let mut expected = 0u64;

    for round in 0..25 {
        client.send(&Frame::Input {
            offset: expected,
            data: command,
        });
        expected += command.len() as u64;

        // Reconnect immediately, giving the daemon no chance to drain the input in
        // a poll iteration of its own.
        drop(client);
        client = session.connect();
        let ok = client.hello(RESUME_FROM_START, expected);
        assert_eq!(
            ok.in_applied, expected,
            "round {round}: input delivered before the takeover was lost"
        );
    }
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
    let session = Session::start("reset");
    let mut client = session.connect();
    client.hello(RESUME_FROM_START, 0);

    let command = b"echo NOMUX-SURVIVED\n";
    client.send(&Frame::Input {
        offset: 0,
        data: command,
    });

    // Let output pile up unread, then drop: unread data at close forces RST.
    thread::sleep(Duration::from_millis(250));
    drop(client);
    thread::sleep(Duration::from_millis(250));

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
