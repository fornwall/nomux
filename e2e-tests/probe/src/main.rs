//! The smallest client that can create a session and prove one survived.
//!
//! `nomux spawn` and `nomux attach` speak a binary frame protocol over stdio rather than
//! driving a terminal, and the daemon reaps itself after `FIRST_ATTACH_TIMEOUT` if no
//! `Hello` ever arrives. So a logout matrix cannot be driven with shell alone: something
//! has to greet the session, or there is no session to ask about afterwards.
//!
//! Two modes, one SSH connection each:
//!
//! - `create <id>` greets a session into being, types a marker into it, and detaches.
//! - `check <id>` re-attaches and looks for that marker in the replayed output.
//!
//! The marker is what makes `check` a test of *survival* rather than of `attach`: a
//! session that was killed and somehow recreated has an empty ring, and `attach` refuses
//! an absent one outright, so only the original daemon's retained output can answer.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use nomux_protocol::{
    Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, RESUME_FROM_START, SERVER_PREAMBLE,
    WinSize, decode_header,
};

/// Longest to wait for any one frame. Generous: the far side may be a container whose
/// login shell is still starting.
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);

/// Exit status meaning "the session is not there". Distinct from 1, so the matrix runner
/// can tell a session that died from a probe that broke.
const EXIT_ABSENT: i32 = 20;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, id) = match args.as_slice() {
        [mode, id] => (mode.as_str(), id.as_str()),
        _ => {
            eprintln!("usage: nomux-probe <create|check> <session-id>");
            std::process::exit(64);
        }
    };

    let outcome = match mode {
        "create" => create(id),
        "check" => check(id),
        other => Err(format!("unknown mode `{other}`")),
    };
    match outcome {
        Ok(report) => {
            println!("{report}");
        }
        Err(err) => {
            eprintln!("nomux-probe: {err}");
            // "Absent" is a verdict the matrix records, not a failure of the probe.
            std::process::exit(if err.contains("MISSING-SESSION") {
                EXIT_ABSENT
            } else {
                1
            });
        }
    }
}

/// The marker typed into the session, and looked for on the way back.
fn marker(id: &str) -> String {
    format!("NOMUX-MARK-{id}-OK")
}

/// The nomux binary to drive. Resolved through `PATH` on purpose: `image/cell-entrypoint.sh`
/// installs the build under test to `/usr/local/bin/nomux` before PID 1 starts, so there is
/// exactly one `nomux` a cell can reach and naming another would be naming one that is not
/// under test. An environment variable used to override this and nothing ever set it.
const NOMUX_BIN: &str = "nomux";

/// Greets a session into being and leaves it running with a marker in its ring.
fn create(id: &str) -> Result<String, String> {
    let mut relay = Relay::start(&["spawn", id])?;
    let ok = relay.greet(id)?;

    // Typed rather than executed-and-checked: terminal echo puts these bytes in the
    // output ring the moment the shell reads them, so the marker is retained whether or
    // not the shell ever runs the line. What is under test is the daemon outliving a
    // logout, not the shell.
    let typed = format!("# {}\n", marker(id));
    relay.send(&Frame::Input {
        offset: 0,
        data: typed.as_bytes(),
    })?;
    relay.await_frame(FrameType::InputAck)?;

    // Detach rather than close: the session goes on without a client, which is the state
    // the logout is about to test.
    relay.send(&Frame::Detach)?;
    let daemon = relay.finish();

    Ok(format!(
        "CREATED id={id} agent={} in_applied={} daemon_relay_exit={daemon}",
        ok.agent, ok.in_applied
    ))
}

/// Re-attaches and reports whether the original session is still there.
fn check(id: &str) -> Result<String, String> {
    let mut relay = Relay::start(&["attach", id])?;
    let ok = relay.greet(id)?;

    // Everything retained, so the marker is in it wherever the ring has rolled to.
    let wanted = marker(id);
    let deadline = Instant::now() + REPLY_TIMEOUT;
    let mut replayed = String::new();
    while Instant::now() < deadline {
        match relay.next_frame() {
            Ok((FrameType::Output, payload)) => {
                // Payload is an 8-byte offset then the bytes themselves.
                let bytes = payload.get(8..).unwrap_or_default();
                replayed.push_str(&String::from_utf8_lossy(bytes));
                if replayed.contains(&wanted) {
                    relay.send(&Frame::Detach).ok();
                    let exit = relay.finish();
                    return Ok(format!(
                        "SURVIVED id={id} resume_from={} replayed_bytes={} relay_exit={exit}",
                        ok.resume_from,
                        replayed.len()
                    ));
                }
            }
            // The session is there but its transcript ended — the child was killed while
            // the daemon lived. Worth telling apart from both other answers.
            Ok((FrameType::Exit, _)) => {
                relay.finish();
                return Err(format!(
                    "SHELL-GONE id={id}: the daemon answered but its terminal stream had \
                     already ended, so the session outlived the logout and the child did not"
                ));
            }
            Ok(_) => {}
            Err(err) => {
                relay.finish();
                return Err(format!("id={id}: {err}"));
            }
        }
    }
    relay.finish();
    Err(format!(
        "NO-MARKER id={id}: attached, but {wanted:?} was not in the {} replayed bytes — \
         the id answers and is not the session this matrix created",
        replayed.len()
    ))
}

/// A running `nomux spawn`/`nomux attach` and the framed conversation with it.
struct Relay {
    child: Child,
    stdin: std::process::ChildStdin,
    /// Bytes off the relay's stdout, delivered by a reader thread so every wait here can
    /// carry a deadline — a relay that says nothing must not park the matrix.
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    /// Whether [`SERVER_PREAMBLE`] has been found and discarded.
    synchronized: bool,
    stderr: Receiver<String>,
}

impl Relay {
    fn start(args: &[&str]) -> Result<Self, String> {
        let mut child = Command::new(NOMUX_BIN)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("could not run `{NOMUX_BIN} {}`: {err}", args.join(" ")))?;

        let stdin = child.stdin.take().ok_or("no stdin on the relay")?;
        let mut out = child.stdout.take().ok_or("no stdout on the relay")?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 64 * 1024];
            while let Ok(n) = out.read(&mut chunk) {
                if n == 0 || tx.send(chunk[..n].to_vec()).is_err() {
                    break;
                }
            }
        });

        // Drained on a thread of its own: the relay's machine-readable failure record
        // goes here, and a full pipe would otherwise block it before it could exit.
        let mut errs = child.stderr.take().ok_or("no stderr on the relay")?;
        let (etx, stderr) = channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            errs.read_to_string(&mut text).ok();
            etx.send(text).ok();
        });

        Ok(Self {
            child,
            stdin,
            rx,
            buf: Vec::new(),
            synchronized: false,
            stderr,
        })
    }

    /// Sends `Hello` and settles the handshake.
    fn greet(&mut self, id: &str) -> Result<nomux_protocol::HelloOk, String> {
        self.send(&Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            agent_forward: false,
            repaint_ctrl_l: false,
            if_detached: false,
            out_offset: RESUME_FROM_START,
            win: WinSize {
                cols: 80,
                rows: 24,
                xpixel: 0,
                ypixel: 0,
            },
            term: "dumb",
        }))?;
        let payload = self.await_frame(FrameType::HelloOk).map_err(|err| {
            // A relay that never reached a session says so on stderr, in the record
            // `main::report_relay` writes. That is the answer, not a probe failure.
            let said = self.complaint();
            if said.contains("missing-session") {
                format!("MISSING-SESSION id={id}: {}", said.trim())
            } else {
                format!("{err}; relay said: {}", said.trim())
            }
        })?;
        match Frame::decode(FrameType::HelloOk, &payload) {
            Ok(Frame::HelloOk(ok)) => Ok(ok),
            other => Err(format!("HelloOk did not decode: {other:?}")),
        }
    }

    fn send(&mut self, frame: &Frame<'_>) -> Result<(), String> {
        let mut wire = Vec::new();
        frame
            .encode(&mut wire)
            .map_err(|err| format!("could not encode {frame:?}: {err}"))?;
        self.stdin
            .write_all(&wire)
            .and_then(|()| self.stdin.flush())
            .map_err(|err| format!("could not write {frame:?}: {err}"))
    }

    /// Reads frames until one of `want` arrives, returning its payload.
    fn await_frame(&mut self, want: FrameType) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while Instant::now() < deadline {
            let (ty, payload) = self.next_frame()?;
            if ty == want {
                return Ok(payload);
            }
            if ty == FrameType::Error {
                return Err(format!(
                    "the daemon refused this connection: {}",
                    String::from_utf8_lossy(payload.get(2..).unwrap_or_default())
                ));
            }
        }
        Err(format!("timed out waiting for {want:?}"))
    }

    /// One frame off the relay, waiting for bytes as needed.
    fn next_frame(&mut self) -> Result<(FrameType, Vec<u8>), String> {
        loop {
            if !self.synchronized {
                // Scan rather than assume: an attach relay is transparent, so a remote
                // login shell's own startup output can precede the daemon's first frame.
                if let Some(at) = find(&self.buf, SERVER_PREAMBLE) {
                    self.buf.drain(..at + SERVER_PREAMBLE.len());
                    self.synchronized = true;
                } else {
                    // Keep only what could still be a partial preamble.
                    let keep = SERVER_PREAMBLE.len().saturating_sub(1);
                    if self.buf.len() > keep {
                        let cut = self.buf.len() - keep;
                        self.buf.drain(..cut);
                    }
                    self.fill()?;
                    continue;
                }
            }
            if let Some(head) = self.buf.first_chunk::<HEADER_LEN>() {
                let header = decode_header(head).map_err(|err| format!("bad header: {err}"))?;
                let len = header.len as usize;
                if self.buf.len() >= HEADER_LEN + len {
                    let payload = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
                    self.buf.drain(..HEADER_LEN + len);
                    return Ok((header.ty, payload));
                }
            }
            self.fill()?;
        }
    }

    fn fill(&mut self) -> Result<(), String> {
        match self.rx.recv_timeout(REPLY_TIMEOUT) {
            Ok(chunk) => {
                self.buf.extend_from_slice(&chunk);
                Ok(())
            }
            Err(RecvTimeoutError::Timeout) => Err("the relay went quiet".to_owned()),
            Err(RecvTimeoutError::Disconnected) => Err("the relay closed its output".to_owned()),
        }
    }

    /// Whatever the relay wrote to stderr, which is where its `NOMUX-RELAY-ERROR` record
    /// and human diagnostic go.
    fn complaint(&mut self) -> String {
        self.stderr
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default()
    }

    /// Closes the conversation and reports how the relay exited.
    fn finish(mut self) -> String {
        drop(self.stdin);
        match self.child.wait() {
            Ok(status) => status
                .code()
                .map_or_else(|| "signalled".to_owned(), |code| code.to_string()),
            Err(err) => format!("unwaitable: {err}"),
        }
    }
}

/// First index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}
