//! Non-blocking framed connection to a client.
//!
//! Reads accumulate until a whole frame is available; writes accumulate until the socket
//! accepts them. Decoding copies each payload into caller-owned scratch so the borrow of
//! the receive buffer ends before the frame is handled — cheap, that direction carrying
//! only keystrokes and control frames.
//!
//! What the two buffers are *allowed* to reach is not decided here: § 4.1's caps live
//! together in `daemon.rs`, measured through [`Conn::queued`] and [`Conn::buffered`].

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use nomux_protocol::{
    Frame, FrameType, HEADER_LEN, Header, MAX_AGENT_DATA, MAX_OUTPUT_DATA, MAX_PAYLOAD,
    SERVER_PREAMBLE, decode_header,
};

use crate::daemon::{MAX_PENDING_READ, MAX_PENDING_WRITE};

const _: () = assert!(
    MAX_PENDING_READ > HEADER_LEN + MAX_PAYLOAD as usize,
    "MAX_PENDING_READ must have room for a whole frame, or take_frame never completes one"
);

/// Capacity an emptied *send* queue keeps rather than hold one paste's peak for a week.
/// Above one PTY read and its framing — `daemon.rs` reads 64 KiB a pass — or a busy
/// session reallocates the queue down and back up on every pass.
const RETAINED_CAPACITY: usize = 128 * 1024;

/// The same for the receive buffer, three orders of magnitude smaller: this direction
/// carries keystrokes and control frames, and only a paste takes it past a page.
const RETAINED_INPUT: usize = 4096;

/// Reclaims the consumed prefix of a cursor-and-`Vec` buffer, keeping `floor` bytes of
/// capacity where it empties one. The surviving case moves on a *ratio* rather than a
/// fixed threshold, which is what makes it O(1) amortised however the writes fall.
fn compact(buf: &mut Vec<u8>, pos: &mut usize, floor: usize) {
    if *pos == buf.len() {
        buf.clear();
        buf.shrink_to(floor);
        *pos = 0;
    } else if *pos * 2 >= buf.len() {
        buf.drain(..*pos);
        *pos = 0;
    }
}

/// Longest to spend delivering a connection's last frames before abandoning them.
/// Reachable from `daemon.rs` because the departures that must *not* spend it are
/// tested against it there.
pub(crate) const FINAL_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// A client connection carrying partially read and partially written frames.
pub(crate) struct Conn {
    stream: UnixStream,
    rx: Vec<u8>,
    rx_pos: usize,
    tx: Vec<u8>,
    tx_pos: usize,
    /// Whether this connection has ever queued its server-to-client synchronization
    /// sequence. Once true it stays true, so no later frame can put magic in the middle
    /// of the stream.
    preamble_queued: bool,
    eof: bool,
}

impl std::fmt::Debug for Conn {
    /// Sizes and flags, never bytes: `rx` and `tx` are deliberately left out. Derived,
    /// this would hand both buffers to whatever printed a `Conn` — the megabyte § 4.1
    /// lets each of them reach, of session output and of whatever the peer last typed —
    /// and the only place this binary prints to is syslog.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("buffered", &self.buffered())
            .field("queued", &self.queued())
            .field("preamble_queued", &self.preamble_queued)
            .field("eof", &self.eof)
            .finish_non_exhaustive()
    }
}

impl Conn {
    /// Wraps an accepted stream, switching it to non-blocking.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be made non-blocking.
    pub(crate) fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            rx: Vec::new(),
            rx_pos: 0,
            tx: Vec::new(),
            tx_pos: 0,
            preamble_queued: false,
            eof: false,
        })
    }

    /// The underlying socket, for registering in a poll set.
    #[must_use]
    pub(crate) const fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Whether the peer has closed its sending half.
    #[must_use]
    pub(crate) const fn is_eof(&self) -> bool {
        self.eof
    }

    /// Output queued for the socket and not yet accepted by it: zero is "nothing to
    /// write", and § 4.1's `MAX_PENDING_WRITE` and `ABANDON_PENDING_WRITE` are what the
    /// daemon reads it against.
    #[must_use]
    pub(crate) const fn queued(&self) -> usize {
        self.tx.len() - self.tx_pos
    }

    /// Input read off the socket and not yet decoded, against § 4.1's `MAX_PENDING_READ`.
    ///
    /// Non-zero is also what sends the event loop back for frames no second `POLLIN` will
    /// ever announce: the daemon stops decoding while the PTY queue is full (§ 4.1), which
    /// can leave whole frames sitting here.
    #[must_use]
    pub(crate) const fn buffered(&self) -> usize {
        self.rx.len() - self.rx_pos
    }

    /// Queues a frame, answering whether it was encoded — false for one too large for
    /// the protocol, which drops it and leaves the queue as it was. Unreachable, every
    /// caller here chunking to at most [`MAX_PAYLOAD`] or queueing a control frame whose
    /// size it fixed itself.
    ///
    /// The answer is only news to a caller that advances a stream position on it, which
    /// is why [`Conn::send_output`] reads it and the control-frame callers do not: a
    /// frame that vanished from under an advancing offset leaves the client contiguous
    /// offsets with a hole inside them, § 3's one loss no client can detect.
    pub(crate) fn send(&mut self, frame: &Frame<'_>) -> bool {
        if !self.preamble_queued {
            self.tx.extend_from_slice(SERVER_PREAMBLE);
            self.preamble_queued = true;
        }
        frame.encode(&mut self.tx).is_ok()
    }

    /// Queues raw output bytes as one or more `Output` frames, splitting at
    /// [`MAX_OUTPUT_DATA`].
    ///
    /// Returns the offset one past the last byte queued, which is short of
    /// `offset + data.len()` when the queue filled partway through. The cap is re-checked
    /// per chunk rather than once on entry, which is what makes a short return *final*
    /// within a pass — `pump_output` walks the ring's two halves on that.
    pub(crate) fn send_output(&mut self, mut offset: u64, data: &[u8]) -> u64 {
        for part in data.chunks(MAX_OUTPUT_DATA) {
            // The ring can be far larger than the queue budget, so a single pump would
            // otherwise queue the whole of it for a client that has stopped reading. The
            // caller resumes from the returned offset.
            if self.queued() >= MAX_PENDING_WRITE {
                break;
            }
            // The chunking above is what makes this unreachable. Were it ever to move,
            // advancing here would carry `pump_output`'s `sent_through` past bytes no
            // frame carried — and a client cannot tell that from output it has already
            // been given, there being no `Gap` in it and nothing left to resend from.
            if !self.send(&Frame::Output { offset, data: part }) {
                break;
            }
            offset += part.len() as u64;
        }
        offset
    }

    /// Queues agent bytes as one or more `AgentData` frames for `generation`, splitting
    /// at [`MAX_AGENT_DATA`]: a chunk past it is one `send` drops — a silent hole in a
    /// stream nothing here can resend.
    pub(crate) fn send_agent_data(&mut self, generation: u32, data: &[u8]) {
        for part in data.chunks(MAX_AGENT_DATA) {
            self.send(&Frame::AgentData {
                generation,
                data: part,
            });
        }
    }

    /// Reads one fair share from the socket into the receive buffer, up to
    /// [`MAX_PENDING_READ`] still undecoded.
    ///
    /// `chunk` is the caller's, and is only ever written to: a buffer of its own would be
    /// zeroed on every call, and the daemon already carries one. An empty one reads
    /// nothing rather than ending the connection; both callers hand over the daemon's
    /// whole 64 KiB read buffer.
    ///
    /// # Errors
    ///
    /// Propagates read failures other than `EWOULDBLOCK` and `EINTR`.
    pub(crate) fn fill(&mut self, chunk: &mut [u8]) -> io::Result<()> {
        if chunk.is_empty() {
            // `read` into a zero-length slice answers `Ok(0)`, which below is the peer
            // having closed — a session declared over with its child still alive, and
            // nothing that reports it afterwards. Guarded here for the same reason
            // `nbio::read_or_eof` guards it rather than requiring it of its callers.
            return Ok(());
        }
        if self.buffered() >= MAX_PENDING_READ {
            return Ok(());
        }
        let room = MAX_PENDING_READ - self.buffered();
        let read_len = chunk.len().min(room);
        let read_buf = chunk.get_mut(..read_len).unwrap_or_default();
        loop {
            match self.stream.read(read_buf) {
                Ok(0) => self.eof = true,
                Ok(n) => self.rx.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
            // A continuously readable peer gets one successful read per service call.
            // Otherwise a stream of four-byte control frames can consume the whole 1 MiB
            // receive allowance and delay PTY draining behind hundreds of thousands of
            // decodes, despite every other source receiving a bounded share of the pass.
            return Ok(());
        }
    }

    /// Writes as much of the send buffer as the socket accepts.
    ///
    /// # Errors
    ///
    /// Propagates write failures other than `EWOULDBLOCK` and `EINTR`.
    pub(crate) fn flush_some(&mut self) -> io::Result<()> {
        while self.tx_pos < self.tx.len() {
            let pending = self.tx.get(self.tx_pos..).unwrap_or(&[]);
            match self.stream.write(pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.tx_pos += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        compact(&mut self.tx, &mut self.tx_pos, RETAINED_CAPACITY);
        Ok(())
    }

    /// Pushes out whatever is queued, giving up [`FINAL_FLUSH_TIMEOUT`] after it started.
    ///
    /// Private, and reached only by [`Conn::close_with`]: it goes *blocking*, so for as long
    /// as it runs the caller's event loop is not — no PTY drained, no reaping — and its
    /// timeout path hands back a socket still in that mode.
    ///
    /// # Errors
    ///
    /// Propagates write failures, including the deadline expiring.
    fn flush_final(&mut self) -> io::Result<()> {
        // Bounded because the peer being flushed has frequently stopped reading (§ 6.4),
        // and against the whole call rather than each `write` (§ 6.5): `SO_SNDTIMEO`
        // restarts per syscall, so a peer reading a trickle keeps resetting it.
        self.stream.set_nonblocking(false)?;
        let deadline = std::time::Instant::now() + FINAL_FLUSH_TIMEOUT;
        while self.tx_pos < self.tx.len() {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.stream.set_write_timeout(Some(remaining))?;
            let pending = self.tx.get(self.tx_pos..).unwrap_or(&[]);
            match self.stream.write(pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.tx_pos += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        self.tx.clear();
        self.tx_pos = 0;
        self.stream.flush()
    }

    /// Closes, delivering `frame` as the last thing this connection will ever carry — or,
    /// with `None`, whatever is already queued (§ 6.5's shutdown). Waits up to
    /// [`FINAL_FLUSH_TIMEOUT`] for a peer that is not taking it.
    ///
    /// Consumed rather than borrowed because [`Conn::flush_final`]'s timeout path leaves
    /// the socket blocking, which no event loop may be handed.
    pub(crate) fn close_with(mut self, frame: Option<&Frame<'_>>) {
        if let Some(frame) = frame {
            // Replacing queued bytes can splice this frame into a partially written one.
            self.send(frame);
        }
        drop(self.flush_final());
    }

    /// Removes one complete frame from the receive buffer, copying its payload into
    /// `scratch`, or `None` where no complete frame is buffered yet.
    ///
    /// # Errors
    ///
    /// [`nomux_protocol::ProtoError`] for an unparseable header.
    pub(crate) fn take_frame(
        &mut self,
        scratch: &mut Vec<u8>,
    ) -> Result<Option<FrameType>, nomux_protocol::ProtoError> {
        let available = self.rx.get(self.rx_pos..).unwrap_or(&[]);
        let Some(head) = available.first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        let Header { ty, len } = decode_header(head)?;

        let len = len as usize;
        let Some(payload) = available.get(HEADER_LEN..HEADER_LEN + len) else {
            return Ok(None);
        };
        scratch.clear();
        scratch.extend_from_slice(payload);
        self.rx_pos += HEADER_LEN + len;

        compact(&mut self.rx, &mut self.rx_pos, RETAINED_INPUT);
        Ok(Some(ty))
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::Instant;

    use nomux_protocol::{
        ErrorCode, Hello, HelloOk, PROTOCOL_VERSION, ProtoError, RESUME_FROM_START, WinSize,
    };

    use super::*;

    const WIN: WinSize = WinSize {
        cols: 80,
        rows: 24,
        xpixel: 640,
        ypixel: 480,
    };

    /// A connection and the far end of its socket, both non-blocking so that neither
    /// side of a test can park inside the kernel waiting for the other.
    fn pair() -> (UnixStream, Conn) {
        let (peer, ours) = UnixStream::pair().expect("a socketpair");
        peer.set_nonblocking(true).expect("a non-blocking peer");
        (peer, Conn::new(ours).expect("a connection"))
    }

    /// The rendering pinned exactly, so a `#[derive(Debug)]` cannot come back silently:
    /// derived, both buffers go wherever a `Conn` is printed, and in this binary that is
    /// syslog. Frames on both sides, so a derive would have contents to leak.
    #[test]
    fn the_debug_rendering_carries_no_buffer_contents() {
        let (mut peer, mut conn) = pair();
        conn.send(&Frame::Output {
            offset: 0,
            data: b"queued output",
        });
        let typed = encoded(&Frame::Input {
            offset: 0,
            data: b"typed input",
        });
        feed(&mut peer, &mut conn, &typed);

        assert_eq!(
            format!("{conn:?}"),
            "Conn { buffered: 23, queued: 37, preamble_queued: true, eof: false, .. }"
        );
    }

    /// One ready socket gets one share per service call. In particular, a stream of
    /// four-byte `Ping`s must not fill the whole megabyte receive allowance and spend
    /// hundreds of thousands of decodes before the PTY is serviced again.
    #[test]
    fn one_fill_takes_one_read_bufferful() {
        let (mut peer, mut conn) = pair();
        peer.write_all(&[b'x'; 64]).expect("fill the socket");

        let mut chunk = [0; 16];
        conn.fill(&mut chunk).expect("take one fair share");
        assert_eq!(conn.buffered(), chunk.len());

        conn.fill(&mut chunk).expect("take the next fair share");
        assert_eq!(conn.buffered(), 2 * chunk.len());
    }

    /// An empty read buffer must not end the connection: `read` answers `Ok(0)` for one,
    /// which is the peer's close everywhere else in `fill`. The same hazard, and the same
    /// guard, as `nbio::read_or_eof`'s.
    #[test]
    fn an_empty_chunk_is_not_reported_as_end_of_file() {
        let (mut peer, mut conn) = pair();
        peer.write_all(b"still here").expect("write to the socket");

        conn.fill(&mut []).expect("a fill with nowhere to put it");
        assert!(!conn.is_eof(), "the peer has not closed");
        assert_eq!(conn.buffered(), 0, "an empty chunk can take nothing");
    }

    /// A frame too large to encode is dropped, and `send` has to say so: `send_output`
    /// advances its offset on that answer, and an offset past bytes no frame carried is
    /// a hole the client reads as contiguous output.
    #[test]
    fn a_frame_too_large_to_encode_is_reported_as_unsent() {
        let (_peer, mut conn) = pair();
        let payload = bulk(MAX_OUTPUT_DATA + 1);

        assert!(
            !conn.send(&Frame::Output {
                offset: 0,
                data: &payload,
            }),
            "a payload past the protocol maximum cannot be queued"
        );
        assert_eq!(
            conn.queued(),
            SERVER_PREAMBLE.len(),
            "a frame that could not be encoded must leave the queue alone"
        );
        assert!(
            conn.send(&Frame::Output {
                offset: 0,
                data: payload.get(..MAX_OUTPUT_DATA).unwrap_or_default(),
            }),
            "one byte less is the largest frame the protocol allows"
        );
    }

    /// A payload whose every byte is a function of its position, so a compaction that
    /// moved the wrong bytes shows up as a mismatch rather than as zeros.
    fn bulk(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    /// One frame of each shape the reassembler has to handle: empty, fixed-size, and
    /// both variable-length forms.
    fn samples(payload: &[u8]) -> [Frame<'_>; 6] {
        [
            Frame::Detach,
            Frame::Resize(WIN),
            Frame::HelloOk(HelloOk {
                resume_from: 9,
                in_applied: 4,
                agent: true,
            }),
            Frame::Hello(Hello {
                protocol: PROTOCOL_VERSION,
                agent_forward: true,
                repaint_ctrl_l: false,
                if_detached: false,
                out_offset: RESUME_FROM_START,
                win: WIN,
                term: "xterm-256color",
            }),
            Frame::Input {
                offset: 1 << 33,
                data: payload,
            },
            Frame::AgentData {
                generation: 3,
                data: &payload[..7],
            },
        ]
    }

    fn encoded(frame: &Frame<'_>) -> Vec<u8> {
        let mut wire = Vec::new();
        frame.encode(&mut wire).expect("a valid frame");
        wire
    }

    /// What the daemon's event loop carries for the whole pass.
    const READ_CHUNK: usize = 64 * 1024;

    /// Fills through a buffer of the caller's, as the daemon's event loop does with the
    /// one it carries for the whole pass.
    fn fill(conn: &mut Conn) -> io::Result<()> {
        let mut chunk = vec![0u8; READ_CHUNK];
        conn.fill(&mut chunk)
    }

    /// Hands every byte of `bytes` to `conn`, filling whenever the kernel's buffer
    /// fills — a frame at [`MAX_PAYLOAD`] does not fit in one, so the alternative is
    /// a blocking write with nobody left to unblock it.
    fn feed(peer: &mut UnixStream, conn: &mut Conn, bytes: &[u8]) {
        let mut sent = 0;
        while sent < bytes.len() {
            match peer.write(&bytes[sent..]) {
                Ok(0) => panic!("the peer accepted nothing"),
                Ok(n) => sent += n,
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    let before = conn.rx.len();
                    fill(conn).expect("a fill");
                    assert!(
                        conn.rx.len() > before,
                        "neither side can move: {} bytes buffered, {} of {} sent",
                        conn.buffered(),
                        sent,
                        bytes.len()
                    );
                }
                Err(err) => panic!("the peer could not write: {err}"),
            }
        }
        fill(conn).expect("a fill");
    }

    /// Takes one frame and decodes it out of the scratch buffer, as the daemon's
    /// decode loop does.
    fn take<'a>(conn: &mut Conn, scratch: &'a mut Vec<u8>) -> Option<Frame<'a>> {
        let ty = conn.take_frame(scratch).expect("a well-formed header")?;
        Some(Frame::decode(ty, scratch).expect("a well-formed payload"))
    }

    /// Takes a frame from the server side of a test pair, consuming and checking the
    /// one response-stream preamble before the first one.
    fn take_server<'a>(
        conn: &mut Conn,
        scratch: &'a mut Vec<u8>,
        synchronized: &mut bool,
    ) -> Option<Frame<'a>> {
        if !*synchronized {
            let available = conn.rx.get(conn.rx_pos..).unwrap_or(&[]);
            let preamble = available.get(..SERVER_PREAMBLE.len())?;
            assert_eq!(preamble, SERVER_PREAMBLE);
            conn.rx_pos += SERVER_PREAMBLE.len();
            *synchronized = true;
        }
        take(conn, scratch)
    }

    /// Reads one bufferful from the peer, treating "nothing there" as zero bytes.
    fn sip(peer: &mut UnixStream, into: &mut Vec<u8>) -> usize {
        // On the heap: bigger than a socket buffer, so the slow-peer test empties one
        // per round, and too big for the stack.
        let mut buf = vec![0u8; 64 * 1024];
        match peer.read(&mut buf) {
            Ok(n) => {
                into.extend_from_slice(&buf[..n]);
                n
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => 0,
            Err(err) => panic!("the peer could not read: {err}"),
        }
    }

    /// Reads everything the peer's buffer currently holds.
    fn drain(peer: &mut UnixStream, into: &mut Vec<u8>) -> usize {
        let mut total = 0;
        loop {
            let n = sip(peer, into);
            if n == 0 {
                return total;
            }
            total += n;
        }
    }

    /// Post-condition of [`compact`]: whatever is dead is smaller than what is live,
    /// so no buffer carries a prefix bigger than the remainder it is paying to move.
    fn compacted(len: usize, pos: usize) -> bool {
        pos == 0 || pos * 2 < len
    }

    /// Every frame split at every possible point into two writes: reassembly must not
    /// depend on where the read boundary landed, header or payload — the split-read
    /// path every real socket takes and no integration test reaches.
    #[test]
    fn every_split_point_reassembles_the_same_frame() {
        let payload = bulk(300);
        let mut scratch = Vec::new();
        for frame in samples(&payload) {
            let wire = encoded(&frame);
            for split in 1..wire.len() {
                let (mut peer, mut conn) = pair();
                feed(&mut peer, &mut conn, &wire[..split]);
                assert!(
                    matches!(conn.take_frame(&mut scratch), Ok(None)),
                    "{frame:?} completed on {split} of {} bytes",
                    wire.len()
                );
                assert_eq!(conn.buffered(), split, "every byte given must be kept");

                feed(&mut peer, &mut conn, &wire[split..]);
                assert_eq!(
                    take(&mut conn, &mut scratch),
                    Some(frame),
                    "{frame:?} split at {split}"
                );
                assert_eq!(&scratch[..], &wire[HEADER_LEN..], "payload at {split}");
            }
        }
    }

    /// A peer that keeps writing is stopped exactly at [`MAX_PENDING_READ`]. Staged
    /// excess proves the cap, rather than `EAGAIN`, stopped the read.
    #[test]
    fn a_peer_that_keeps_writing_is_stopped_at_the_read_cap() {
        // One byte short of the cap, so the next read must take exactly one byte.
        let preload = MAX_PENDING_READ - 1;
        // 60 KiB payloads, as `flow.rs` blasts and well inside `MAX_PAYLOAD`. Whole
        // frames, so the release at the end has something to decode.
        let payload = bulk(60 * 1024);
        let mut wire = Vec::new();
        let mut offset = 0;
        while wire.len() < preload + 8 * READ_CHUNK {
            Frame::Input {
                offset,
                data: &payload,
            }
            .encode(&mut wire)
            .expect("a valid frame");
            offset += payload.len() as u64;
        }

        let (mut peer, mut conn) = pair();
        feed(&mut peer, &mut conn, &wire[..preload]);
        while conn.buffered() < preload {
            let before = conn.buffered();
            fill(&mut conn).expect("finish the preload one fair share at a time");
            assert!(
                conn.buffered() > before,
                "the staged preload stopped moving"
            );
        }
        assert_eq!(conn.buffered(), preload, "every byte given must be kept");
        assert!(
            conn.buffered() < MAX_PENDING_READ,
            "a byte short of the cap is not the cap"
        );

        // Written at the socket with nothing draining it, which is the peer that has
        // gone on writing while this side was busy. It ends refused, that being what the
        // cap leaves a peer doing.
        let mut staged = 0;
        while let Some(rest) = wire.get(preload + staged..) {
            match peer.write(rest) {
                Ok(0) => break,
                Ok(n) => staged += n,
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => panic!("the peer could not write: {err}"),
            }
        }
        assert!(
            staged > READ_CHUNK,
            "the socket took {staged} bytes, which one read empties — so a `fill` with no \
             cap in it would stop here too and the bound below would prove nothing"
        );

        fill(&mut conn).expect("a fill");
        let taken = conn.buffered() - preload;
        assert_eq!(conn.buffered(), MAX_PENDING_READ);
        assert_eq!(taken, 1, "the read cap was exceeded");

        // And goes on declining. Nothing empties this buffer while the caller has stopped
        // decoding, so every later pass finds the same wall.
        fill(&mut conn).expect("a fill");
        assert_eq!(
            conn.buffered() - preload,
            taken,
            "a fill that starts at the cap must take nothing"
        );

        let mut scratch = Vec::new();
        while conn.buffered() >= MAX_PENDING_READ {
            assert!(
                take(&mut conn, &mut scratch).is_some(),
                "the cap must leave room for a whole frame, or nothing here ever completes"
            );
        }
        let under_cap = conn.buffered();
        fill(&mut conn).expect("a fill");
        assert!(
            conn.buffered() > under_cap,
            "nothing was left for this fill to take, so the two above stopped on an empty \
             socket rather than on the cap"
        );
    }

    /// `send_output` chunks at exactly [`MAX_OUTPUT_DATA`], so the production path emits
    /// the largest frame the protocol allows; read back through a second `Conn` it
    /// has to reassemble into the bytes that went in, contiguously.
    #[test]
    fn send_output_chunks_at_exactly_the_maximum_payload() {
        let chunk = MAX_OUTPUT_DATA;
        let data = bulk(2 * chunk + 1000);
        let (peer, ours) = UnixStream::pair().expect("a socketpair");
        let mut sender = Conn::new(ours).expect("a sender");
        let mut reader = Conn::new(peer).expect("a reader");

        let end = sender.send_output(7, &data);
        assert_eq!(end, 7 + data.len() as u64, "the whole slice fits the queue");

        let mut scratch = Vec::new();
        let mut lens = Vec::new();
        let mut got = Vec::new();
        let mut next = 7;
        let mut synchronized = false;
        while sender.queued() > 0 || reader.buffered() > 0 {
            let before = (sender.queued(), reader.buffered());
            sender.flush_some().expect("a flush");
            fill(&mut reader).expect("a fill");
            while let Some(frame) = take_server(&mut reader, &mut scratch, &mut synchronized) {
                let Frame::Output { offset, data } = frame else {
                    panic!("expected Output, got {frame:?}");
                };
                assert_eq!(offset, next, "output offsets must be contiguous");
                next += data.len() as u64;
                lens.push(data.len());
                got.extend_from_slice(data);
            }
            assert_ne!(
                before,
                (sender.queued(), reader.buffered()),
                "neither side moved"
            );
        }

        assert_eq!(lens, vec![MAX_OUTPUT_DATA, chunk, 1000]);
        assert!(got == data, "the reassembled stream must be what went in");
        assert!(synchronized, "the stream preamble was not consumed");
    }

    /// Several whole frames and a partial one in a single read: the trailing bytes
    /// must be kept for the rest of their frame rather than decoded or dropped.
    #[test]
    fn one_read_carrying_several_frames_ends_on_a_partial_one() {
        let payload = bulk(300);
        let frames = samples(&payload);
        let mut wire = Vec::new();
        for frame in &frames {
            frame.encode(&mut wire).expect("a valid frame");
        }
        let tail_at = wire.len();
        let tail = Frame::Error {
            code: ErrorCode::Takeover,
            message: "another client attached",
        };
        tail.encode(&mut wire).expect("a valid frame");

        let (mut peer, mut conn) = pair();
        let mut scratch = Vec::new();
        // Three bytes short of even a header, so the cut is inside the fixed part.
        feed(&mut peer, &mut conn, &wire[..tail_at + 3]);
        for frame in &frames {
            assert_eq!(take(&mut conn, &mut scratch).as_ref(), Some(frame));
        }
        assert!(
            matches!(conn.take_frame(&mut scratch), Ok(None)),
            "three bytes of a header are not a frame"
        );
        assert!(conn.buffered() > 0, "the stump must be kept");

        feed(&mut peer, &mut conn, &wire[tail_at + 3..]);
        assert_eq!(take(&mut conn, &mut scratch), Some(tail));
        assert_eq!(conn.buffered(), 0);
    }

    /// A header this build cannot parse is reported without being consumed, so the
    /// caller sees the bytes it is refusing rather than a buffer already advanced
    /// past them.
    #[test]
    fn an_unparseable_header_is_reported_without_consuming_it() {
        let (mut peer, mut conn) = pair();
        let mut scratch = Vec::new();
        feed(&mut peer, &mut conn, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            conn.take_frame(&mut scratch),
            Err(ProtoError::UnknownFrameType(0x00))
        );
        assert_eq!(conn.buffered(), HEADER_LEN, "the bad header must stay put");
    }

    /// A stream of frames read in chunks that never end on a frame boundary: the
    /// receive buffer must be compacted back down rather than grow with the session.
    #[test]
    fn the_receive_buffer_is_compacted_rather_than_grown() {
        let payload = bulk(64);
        let one = encoded(&Frame::Input {
            offset: 0,
            data: &payload,
        });
        let rounds = 400;
        let stream: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(rounds * one.len())
            .collect();

        let (mut peer, mut conn) = pair();
        let mut scratch = Vec::new();
        let (mut frames, mut halvings, mut high_water) = (0usize, 0usize, 0usize);
        for chunk in stream.chunks(1000) {
            feed(&mut peer, &mut conn, chunk);
            while take(&mut conn, &mut scratch).is_some() {
                frames += 1;
                assert!(
                    compacted(conn.rx.len(), conn.rx_pos),
                    "{} dead bytes under {} live ones",
                    conn.rx_pos,
                    conn.buffered()
                );
                if conn.rx_pos == 0 && !conn.rx.is_empty() {
                    halvings += 1;
                }
                high_water = high_water.max(conn.rx.len());
            }
        }

        assert_eq!(frames, rounds, "every frame must come back out");
        assert!(halvings > 0, "the halving branch never ran");
        assert!(
            high_water <= 1000 + 2 * one.len(),
            "the buffer reached {high_water} bytes over {} read",
            stream.len()
        );
    }

    /// A peer that reads slower than the daemon queues: `flush_some` makes partial
    /// progress and hands the rest back, the queue is compacted instead of growing
    /// with the session, and every byte still arrives in order.
    #[test]
    fn a_slow_peer_gets_every_byte_and_the_send_queue_stays_bounded() {
        let payload = bulk(4096);
        let frame_len = HEADER_LEN + 8 + payload.len();
        let (mut peer, mut conn) = pair();
        let (mut expected, mut got) = (SERVER_PREAMBLE.to_vec(), Vec::new());
        let (mut offset, mut short_writes, mut halvings, mut high_water) = (0u64, 0usize, 0, 0);

        let rounds = 128;
        for _ in 0..rounds {
            // Topped back up after every write, which is what the replay path does
            // and what makes the dead prefix a cost rather than a curiosity.
            while conn.queued() < MAX_PENDING_WRITE {
                let frame = Frame::Output {
                    offset,
                    data: &payload,
                };
                conn.send(&frame);
                frame.encode(&mut expected).expect("a valid frame");
                offset += payload.len() as u64;
            }
            conn.flush_some().expect("a flush");
            assert!(
                compacted(conn.tx.len(), conn.tx_pos),
                "{} dead bytes under {} live ones",
                conn.tx_pos,
                conn.queued()
            );
            if conn.tx_pos == 0 && !conn.tx.is_empty() {
                halvings += 1;
            }
            if conn.queued() > 0 {
                short_writes += 1;
            }
            high_water = high_water.max(conn.tx.len());

            // One bufferful per round, so the socket stays full and the writes stay
            // short.
            assert!(sip(&mut peer, &mut got) > 0, "the peer read nothing");
        }

        while conn.queued() > 0 {
            conn.flush_some().expect("a flush");
            assert!(
                drain(&mut peer, &mut got) > 0 || conn.queued() == 0,
                "nothing moved"
            );
        }
        drain(&mut peer, &mut got);

        assert_eq!(
            short_writes, rounds,
            "every write here should be a short one"
        );
        assert!(halvings > 0, "the halving branch never ran");
        assert!(
            high_water < 2 * (MAX_PENDING_WRITE + frame_len),
            "the queue reached {high_water} bytes over {} written",
            expected.len()
        );
        assert!(got == expected, "every byte must arrive, once and in order");
        assert!(conn.tx.is_empty(), "a drained queue must be given back");
    }

    /// Regression: [`RETAINED_CAPACITY`] below one PTY read reallocated the send queue
    /// down and straight back up on every pass of a session that was merely busy.
    #[test]
    fn a_queue_that_drains_every_pass_is_never_reallocated() {
        let payload = bulk(64 * 1024);
        let (mut peer, mut conn) = pair();
        let mut got = Vec::new();
        let mut settled = 0;
        for round in 0..8u64 {
            conn.send(&Frame::Output {
                offset: round * payload.len() as u64,
                data: &payload,
            });
            while conn.queued() > 0 {
                conn.flush_some().expect("a flush");
                drain(&mut peer, &mut got);
            }
            if round == 0 {
                settled = conn.tx.capacity();
                assert!(settled > 0, "a queue that carried a frame has a capacity");
            }
            assert_eq!(conn.tx.capacity(), settled, "reallocated on pass {round}");
        }
    }

    /// A peer that closes mid-frame: the header arrived, the payload never will.
    /// The half-frame must never be handed over, and the end of file must be
    /// reported so the daemon lets the connection go instead of waiting for bytes
    /// nobody will send.
    #[test]
    fn an_end_of_file_mid_frame_never_yields_the_frame() {
        let payload = bulk(100);
        let wire = encoded(&Frame::Input {
            offset: 5,
            data: &payload,
        });
        let mut scratch = Vec::new();

        // Once cut inside the payload, once inside the header itself.
        for split in [HEADER_LEN + 10, HEADER_LEN - 2] {
            let (mut peer, mut conn) = pair();
            feed(&mut peer, &mut conn, &wire[..split]);
            assert!(!conn.is_eof(), "the peer is still there");
            drop(peer);

            // Another unit test may be between `fork` and `exec` while this peer is
            // dropped. That child briefly inherited the descriptor and keeps EOF from
            // becoming observable until CLOEXEC takes effect, so wait for the kernel's
            // report instead of requiring it in the next two syscalls.
            let deadline = Instant::now() + std::time::Duration::from_secs(1);
            while !conn.is_eof() && Instant::now() < deadline {
                fill(&mut conn).expect("a fill after the peer closed");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(conn.is_eof(), "the close must be reported");
            for _ in 0..2 {
                assert!(
                    matches!(conn.take_frame(&mut scratch), Ok(None)),
                    "a frame whose payload never arrived must not be handed over"
                );
                assert_eq!(conn.buffered(), split, "the stump is neither used nor lost");
            }
        }
    }

    #[test]
    fn a_closing_frame_does_not_splice_into_a_partial_frame() {
        let (mut peer, mut conn) = pair();
        let output = Frame::Output {
            offset: 7,
            data: b"abcdefghijklmnop",
        };
        conn.send(&output);

        // Model a short write ending three bytes into the payload. Tests can move the
        // cursor directly, avoiding assumptions about the host's socket buffer size.
        let cut = SERVER_PREAMBLE.len() + HEADER_LEN + 8 + 3;
        let mut got = conn.tx[..cut].to_vec();
        conn.tx_pos = cut;

        let last = Frame::Error {
            code: ErrorCode::Takeover,
            message: "another client attached",
        };
        conn.close_with(Some(&last));

        drain(&mut peer, &mut got);
        let mut expected = SERVER_PREAMBLE.to_vec();
        expected.extend_from_slice(&encoded(&output));
        expected.extend_from_slice(&encoded(&last));
        assert_eq!(got, expected, "both frames must remain decodable");
    }

    /// The magic is a stream prefix, not a frame prefix: later frames follow each other
    /// directly and a client cannot encounter a false resynchronization point midstream.
    #[test]
    fn the_server_preamble_precedes_only_the_first_frame() {
        let (mut peer, mut conn) = pair();
        let first = Frame::Pong;
        let second = Frame::Detach;
        conn.send(&first);
        conn.send(&second);
        conn.flush_some().expect("flush both frames");

        let mut got = Vec::new();
        drain(&mut peer, &mut got);
        let mut expected = SERVER_PREAMBLE.to_vec();
        expected.extend_from_slice(&encoded(&first));
        expected.extend_from_slice(&encoded(&second));
        assert_eq!(got, expected);
    }

    /// `flush_final` against a peer that has stopped reading gives up on its
    /// deadline. Unbounded, it would park the whole daemon — no PTY drained, no
    /// reaping — inside a blocking write for as long as that peer likes.
    #[test]
    fn flush_final_gives_up_on_a_peer_that_has_stopped_reading() {
        let payload = bulk(4096);
        let (_peer, mut conn) = pair();
        while conn.queued() < MAX_PENDING_WRITE {
            conn.send(&Frame::Output {
                offset: 0,
                data: &payload,
            });
        }
        // Fill the kernel's buffer first, so it is the deadline that ends the call.
        conn.flush_some().expect("a flush");
        assert!(
            conn.queued() > 0,
            "the socket must be full to test anything"
        );

        let started = Instant::now();
        let err = conn
            .flush_final()
            .expect_err("a peer that never reads must not be waited on for ever");
        let elapsed = started.elapsed();

        assert!(
            matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock),
            "unexpected {err:?}"
        );
        assert!(
            elapsed >= FINAL_FLUSH_TIMEOUT / 2 && elapsed < FINAL_FLUSH_TIMEOUT * 8,
            "the deadline is what should have ended this, after {elapsed:?}"
        );
        assert!(
            conn.queued() > 0,
            "the queue is left for the caller to drop"
        );
    }
}
