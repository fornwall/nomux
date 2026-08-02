//! Shared scaffolding for the end-to-end test binaries.
//!
//! Each integration test crate compiles its own copy of this module and uses a
//! subset of it, so unused items here are expected rather than a smell.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "shared by several test binaries, each using a subset; and the \
              allow-*-in-tests settings in clippy.toml cover only #[cfg(test)] \
              modules, not integration test crates"
)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use nomux_proto::{Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, WinSize, decode_header};

pub(crate) const WIN: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

/// A daemon running in an isolated run directory, killed on drop.
pub(crate) struct Session {
    pub(crate) child: Child,
    pub(crate) root: PathBuf,
    pub(crate) socket: PathBuf,
    pub(crate) id: String,
}

/// Ring capacity for tests that are not about overflow. Small enough that a
/// runaway child cannot eat memory, large enough that nothing is dropped.
pub(crate) const DEFAULT_TEST_RING: usize = 64 * 1024;

impl Session {
    /// Starts a daemon with a ring small enough that overflow is reachable in
    /// milliseconds instead of requiring megabytes of output.
    pub(crate) fn start(name: &str) -> Self {
        Self::start_with_ring(name, DEFAULT_TEST_RING)
    }

    pub(crate) fn start_with_ring(name: &str, ring_bytes: usize) -> Self {
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
            // The child's working directory, so `pwd` is assertable.
            .env("HOME", &root)
            .env("NOMUX_RING_BYTES", ring_bytes.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");

        let socket = root.join("nomux").join(format!("{id}.sock"));
        wait_for(&socket);
        Self {
            child,
            root,
            socket,
            id,
        }
    }

    pub(crate) fn connect(&self) -> Client {
        let stream = UnixStream::connect(&self.socket).expect("connect to session");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("set read timeout");
        Client {
            stream,
            pending: Vec::new(),
        }
    }

    /// The session's `ssh-agent` socket, which exists only once a client has
    /// created the session with agent forwarding on.
    pub(crate) fn agent_socket(&self) -> PathBuf {
        self.root.join("nomux").join(format!("{}.agent", self.id))
    }

    /// Opens a connection to the agent socket, the way a child process would.
    pub(crate) fn connect_agent(&self) -> UnixStream {
        let stream = UnixStream::connect(self.agent_socket()).expect("connect to agent socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("set read timeout");
        stream
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

pub(crate) fn wait_for(path: &Path) {
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
pub(crate) struct Client {
    stream: UnixStream,
    pending: Vec<u8>,
}

impl Client {
    pub(crate) fn send(&mut self, frame: &Frame<'_>) {
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        self.stream.write_all(&buf).expect("write frame");
    }

    pub(crate) fn hello(&mut self, out_offset: u64, in_offset: u64) -> nomux_proto::HelloOk {
        self.hello_with(0, out_offset, in_offset)
    }

    pub(crate) fn hello_with(
        &mut self,
        flags: u16,
        out_offset: u64,
        in_offset: u64,
    ) -> nomux_proto::HelloOk {
        self.send(&Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags,
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

    pub(crate) fn next_frame(&mut self) -> (FrameType, Vec<u8>) {
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

    /// Reads frames until one of type `want` arrives, returning its payload and
    /// ignoring the session's own chatter. Anything else is a bug in the daemon's
    /// frame ordering.
    pub(crate) fn next_of(&mut self, want: FrameType) -> Vec<u8> {
        loop {
            let (ty, payload) = self.next_frame();
            if ty == want {
                return payload;
            }
            assert!(
                matches!(
                    ty,
                    FrameType::Output | FrameType::InputAck | FrameType::Pong
                ),
                "unexpected {ty:?} while waiting for {want:?}"
            );
        }
    }

    /// The channel id carried by the next frame of type `want`.
    pub(crate) fn next_chan(&mut self, want: FrameType) -> u32 {
        let payload = self.next_of(want);
        match Frame::decode(want, &payload).expect("decode channel frame") {
            Frame::AgentOpen { chan } | Frame::AgentClose { chan } => chan,
            other => panic!("expected a channel frame, got {other:?}"),
        }
    }

    /// Consumes whatever the daemon has already sent, without waiting for more.
    ///
    /// For tests that are about to close on purpose: a socket closed with data
    /// still unread makes the kernel send RST, which discards *both* directions —
    /// including bytes this client wrote and the daemon had not yet read. Draining
    /// first turns the close into an orderly FIN, so what happens to that input is
    /// the daemon's behaviour rather than the kernel's timing.
    pub(crate) fn drain_available(&mut self) {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("shorten read timeout");
        let mut chunk = [0u8; 8192];
        while let Ok(n) = self.stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
        self.stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("restore read timeout");
    }

    /// Reads until the daemon has acknowledged input through `through`, tolerating
    /// whatever else arrives on the way.
    ///
    /// For tests that are about to disconnect on purpose: an `Input` frame that was
    /// written but not yet read is lost when the socket closes with output still
    /// queued, so waiting for the ack is what makes "the daemon has this" true.
    pub(crate) fn wait_for_input_ack(&mut self, through: u64) {
        loop {
            let (ty, payload) = self.next_frame();
            if ty == FrameType::InputAck
                && let Frame::InputAck { applied_through } =
                    Frame::decode(ty, &payload).expect("decode ack")
                && applied_through >= through
            {
                return;
            }
        }
    }

    /// Collects output until `needle` appears, returning everything consumed and
    /// the offset one past the last output byte.
    pub(crate) fn read_until(&mut self, needle: &str, from: u64) -> (String, u64) {
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
