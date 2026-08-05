//! Non-blocking framed connection to a client.
//!
//! Reads accumulate until a whole frame is available; writes accumulate until the
//! socket accepts them. Decoding copies each payload into caller-owned scratch so the
//! borrow of the receive buffer ends before the frame is handled — cheap, because that
//! direction only ever carries keystrokes and control frames. The output direction,
//! where volume lives, is encoded straight from the ring.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use nomux_proto::{Frame, FrameType, HEADER_LEN, Header, MAX_PAYLOAD, decode_header};

/// Stop queueing output once this much is already waiting for a slow client; the
/// ring absorbs the PTY regardless, so a stalled client costs a gap and never a
/// blocked child (`IMPLEMENTATION.md` § 4.1).
const MAX_PENDING_WRITE: usize = 1 << 20;

/// Queue size at which a client is treated as gone rather than slow: the frames that
/// *answer* a client are queued regardless of [`MAX_PENDING_WRITE`], so a peer that
/// writes without ever reading grows this queue without bound (§ 4.1).
const ABANDON_PENDING_WRITE: usize = 8 << 20;

/// Stop reading from the socket once this much undecoded input is already buffered.
///
/// [`Conn::fill`] loops until `EAGAIN`, and against a peer that keeps writing that
/// loop has no natural end: every chunk it takes frees exactly that much room in the
/// kernel's buffer for the peer to refill. The cap is what leaves the bytes where the
/// peer blocks on them instead — load-bearing rather than defensive, because nothing
/// empties this buffer while the daemon has stopped *decoding* (§ 4.1).
const MAX_PENDING_READ: usize = 1 << 20;

const _: () = assert!(
    MAX_PENDING_READ > HEADER_LEN + MAX_PAYLOAD as usize,
    "MAX_PENDING_READ must have room for a whole frame, or take_frame never completes one"
);

/// Capacity an emptied buffer keeps rather than hold one paste's peak for a week.
///
/// Above one PTY read and its framing — `daemon.rs` reads 64 KiB a pass — because a
/// floor below that reallocates the send queue down and back up on every pass of a
/// busy session, which is the one path this must cost nothing on.
const RETAINED_CAPACITY: usize = 128 * 1024;

/// Reclaims the consumed prefix of a cursor-and-`Vec` buffer.
///
/// Both directions carry one, and both would otherwise grow without bound across a
/// long session: neither cursor ever moves backwards, so the bytes below it are dead
/// the moment they are passed. The empty case is separated because clearing is free
/// where draining is not, and the surviving case moves on a *ratio* rather than at a
/// fixed number of bytes: draining a queue of `n` bytes in `c`-byte writes at a fixed
/// threshold moves about `n²/2c`, so the cost per byte delivered rises with the queue.
/// Halving instead moves at most as many bytes as the compaction retires, which is
/// O(1) amortised however the writes fall.
fn compact(buf: &mut Vec<u8>, pos: &mut usize) {
    if *pos == buf.len() {
        buf.clear();
        buf.shrink_to(RETAINED_CAPACITY);
        *pos = 0;
    } else if *pos * 2 >= buf.len() {
        buf.drain(..*pos);
        *pos = 0;
    }
}

/// Longest to spend delivering a connection's last frames before abandoning them.
const FINAL_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// A client connection carrying partially read and partially written frames.
#[derive(Debug)]
pub(crate) struct Conn {
    stream: UnixStream,
    rx: Vec<u8>,
    rx_pos: usize,
    tx: Vec<u8>,
    tx_pos: usize,
    eof: bool,
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

    /// Whether there is buffered output waiting for the socket.
    #[must_use]
    pub(crate) const fn wants_write(&self) -> bool {
        self.tx_pos < self.tx.len()
    }

    /// Whether enough output is already queued that more should not be added.
    #[must_use]
    pub(crate) const fn is_write_saturated(&self) -> bool {
        self.tx.len() - self.tx_pos >= MAX_PENDING_WRITE
    }

    /// Whether this peer has stopped reading altogether: past
    /// [`ABANDON_PENDING_WRITE`] it is not slow but gone, which that constant has.
    #[must_use]
    pub(crate) const fn is_write_hopeless(&self) -> bool {
        self.tx.len() - self.tx_pos >= ABANDON_PENDING_WRITE
    }

    /// Queues a frame, and reports whether anything was queued.
    ///
    /// The encode failures — an oversized payload, a `TERM` this side would not
    /// accept back — are both unreachable: every caller here chunks to at most
    /// [`MAX_PAYLOAD`], and every caller in the daemon queues a control frame whose
    /// size it fixed itself. Reported rather than discarded for
    /// [`Conn::send_output`], the one caller that has something to get wrong about it.
    pub(crate) fn send(&mut self, frame: &Frame<'_>) -> bool {
        frame.encode(&mut self.tx).is_ok()
    }

    /// Queues raw output bytes as one or more `Output` frames, splitting at
    /// [`MAX_PAYLOAD`].
    ///
    /// Returns the offset one past the last byte queued, which is short of
    /// `offset + data.len()` when the queue filled partway through.
    pub(crate) fn send_output(&mut self, mut offset: u64, data: &[u8]) -> u64 {
        // Leave room for the 8-byte offset that shares the payload.
        let chunk = MAX_PAYLOAD as usize - 8;
        for part in data.chunks(chunk) {
            // Re-checked per chunk, not just before the call: the ring can be far
            // larger than the queue budget, and a single pump would otherwise queue
            // the whole of it for a client that has stopped reading. The caller
            // resumes from the returned offset.
            if self.is_write_saturated() {
                break;
            }
            // Ahead of the offset rather than beside it. A frame that was not queued
            // is one the client never sees, and an offset moved over it is the daemon
            // certain it delivered bytes that are now unreachable in the ring.
            if !self.send(&Frame::Output { offset, data: part }) {
                break;
            }
            offset += part.len() as u64;
        }
        offset
    }

    /// Queues agent bytes as one or more `AgentData` frames, splitting at
    /// [`MAX_PAYLOAD`].
    pub(crate) fn send_agent_data(&mut self, chan: u32, data: &[u8]) {
        // Leave room for the 4-byte channel id that shares the payload.
        for part in data.chunks(MAX_PAYLOAD as usize - 4) {
            self.send(&Frame::AgentData { chan, data: part });
        }
    }

    /// Whether enough undecoded input is buffered that no more should be read.
    const fn is_read_saturated(&self) -> bool {
        self.rx.len() - self.rx_pos >= MAX_PENDING_READ
    }

    /// Whether undecoded bytes are still sitting in the receive buffer.
    ///
    /// The daemon stops decoding while the PTY queue is full (`IMPLEMENTATION.md`
    /// § 4.1), which can leave whole frames here that no second `POLLIN` will ever
    /// announce: this is what sends the event loop back for them.
    #[must_use]
    pub(crate) const fn has_buffered_input(&self) -> bool {
        self.rx_pos < self.rx.len()
    }

    /// Reads whatever the socket has available into the receive buffer, up to
    /// [`MAX_PENDING_READ`] still undecoded.
    ///
    /// # Errors
    ///
    /// Propagates read failures other than `EWOULDBLOCK` and `EINTR`.
    pub(crate) fn fill(&mut self) -> io::Result<()> {
        let mut chunk = [0u8; 16 * 1024];
        while !self.is_read_saturated() {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(n) => self.rx.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
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
        compact(&mut self.tx, &mut self.tx_pos);
        Ok(())
    }

    /// Pushes out whatever is queued, giving up [`FINAL_FLUSH_TIMEOUT`] after it
    /// started.
    ///
    /// # Errors
    ///
    /// Propagates write failures, including the deadline expiring.
    pub(crate) fn flush_final(&mut self) -> io::Result<()> {
        // Bounded because the peer being flushed has frequently stopped reading
        // (§ 6.4), and against the whole call rather than each `write` (§ 6.5):
        // `SO_SNDTIMEO` restarts per syscall, so a peer reading a trickle keeps
        // resetting it.
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

    /// Sends `frame` as the last thing this connection will ever carry, discarding
    /// anything still queued — a reattaching client replays it from the ring anyway
    /// (§ 6.4) — then flushes.
    ///
    /// Consumed rather than borrowed because [`Conn::flush_final`] returns on its
    /// timeout path with the queue untouched and the socket back in blocking mode,
    /// which no event loop may be handed.
    pub(crate) fn send_last(mut self, frame: &Frame<'_>) {
        self.tx.clear();
        self.tx_pos = 0;
        self.send(frame);
        drop(self.flush_final());
    }

    /// Removes one complete frame from the receive buffer, copying its payload into
    /// `scratch`, or `None` where no complete frame is buffered yet.
    ///
    /// # Errors
    ///
    /// [`nomux_proto::ProtoError`] for an unparseable header.
    pub(crate) fn take_frame(
        &mut self,
        scratch: &mut Vec<u8>,
    ) -> Result<Option<FrameType>, nomux_proto::ProtoError> {
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

        compact(&mut self.rx, &mut self.rx_pos);
        Ok(Some(ty))
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::Instant;

    use nomux_proto::{
        ErrorCode, Hello, HelloOk, Linger, PROTOCOL_VERSION, ProtoError, RESUME_FROM_START, WinSize,
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
                linger: Linger::Enabled,
                agent: true,
            }),
            Frame::Hello(Hello {
                protocol: PROTOCOL_VERSION,
                agent_forward: true,
                repaint_ctrl_l: false,
                out_offset: RESUME_FROM_START,
                win: WIN,
                term: "xterm-256color",
            }),
            Frame::Input {
                offset: 1 << 33,
                data: payload,
            },
            Frame::AgentData {
                chan: 3,
                data: &payload[..7],
            },
        ]
    }

    fn encoded(frame: &Frame<'_>) -> Vec<u8> {
        let mut wire = Vec::new();
        frame.encode(&mut wire).expect("a valid frame");
        wire
    }

    /// Undecoded bytes waiting in the receive buffer.
    fn buffered(conn: &Conn) -> usize {
        conn.rx.len() - conn.rx_pos
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
                    conn.fill().expect("a fill");
                    assert!(
                        conn.rx.len() > before,
                        "neither side can move: {} bytes buffered, {} of {} sent",
                        buffered(conn),
                        sent,
                        bytes.len()
                    );
                }
                Err(err) => panic!("the peer could not write: {err}"),
            }
        }
        conn.fill().expect("a fill");
    }

    /// Takes one frame and decodes it out of the scratch buffer, as the daemon's
    /// decode loop does.
    fn take<'a>(conn: &mut Conn, scratch: &'a mut Vec<u8>) -> Option<Frame<'a>> {
        let ty = conn.take_frame(scratch).expect("a well-formed header")?;
        Some(Frame::decode(ty, scratch).expect("a well-formed payload"))
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
                assert_eq!(buffered(&conn), split, "every byte given must be kept");

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

    /// A frame at exactly [`MAX_PAYLOAD`] clears [`MAX_PENDING_READ`] — the case the
    /// const assert at the top of this module protects, since a read cap below a whole
    /// frame is a frame `take_frame` never completes and a connection stuck for good.
    #[test]
    fn a_maximum_payload_frame_fits_under_the_read_cap() {
        // The 8-byte offset shares the payload, so this is the largest `Output` there
        // is — and exactly what `send_output` chunks to.
        let data = bulk(MAX_PAYLOAD as usize - 8);
        let frame = Frame::Output {
            offset: 1 << 40,
            data: &data,
        };
        let wire = encoded(&frame);
        assert_eq!(
            wire.len(),
            HEADER_LEN + MAX_PAYLOAD as usize,
            "the payload must be exactly the maximum for this to test anything"
        );
        assert!(
            MAX_PENDING_READ > wire.len(),
            "the read cap must have room for a whole frame"
        );

        let mut scratch = Vec::new();
        let (mut peer, mut conn) = pair();
        feed(&mut peer, &mut conn, &wire);
        assert_eq!(buffered(&conn), wire.len());
        assert!(!conn.is_read_saturated(), "a whole frame must not saturate");
        assert_eq!(take(&mut conn, &mut scratch), Some(frame));
        assert_eq!(&scratch[..], &wire[HEADER_LEN..]);
    }

    /// `send_output` chunks at exactly [`MAX_PAYLOAD`], so the production path emits
    /// the largest frame the protocol allows; read back through a second `Conn` it
    /// has to reassemble into the bytes that went in, contiguously.
    #[test]
    fn send_output_chunks_at_exactly_the_maximum_payload() {
        let chunk = MAX_PAYLOAD as usize - 8;
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
        while sender.wants_write() || reader.has_buffered_input() {
            let before = (sender.tx.len() - sender.tx_pos, buffered(&reader));
            sender.flush_some().expect("a flush");
            reader.fill().expect("a fill");
            while let Some(frame) = take(&mut reader, &mut scratch) {
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
                (sender.tx.len() - sender.tx_pos, buffered(&reader)),
                "neither side moved"
            );
        }

        assert_eq!(lens, vec![MAX_PAYLOAD as usize - 8, chunk, 1000]);
        assert!(got == data, "the reassembled stream must be what went in");
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
        assert!(conn.has_buffered_input(), "the stump must be kept");

        feed(&mut peer, &mut conn, &wire[tail_at + 3..]);
        assert_eq!(take(&mut conn, &mut scratch), Some(tail));
        assert!(!conn.has_buffered_input());
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
        assert_eq!(buffered(&conn), HEADER_LEN, "the bad header must stay put");
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
                    buffered(&conn)
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
        let (mut expected, mut got) = (Vec::new(), Vec::new());
        let (mut offset, mut short_writes, mut halvings, mut high_water) = (0u64, 0usize, 0, 0);

        let rounds = 128;
        for _ in 0..rounds {
            // Topped back up after every write, which is what the replay path does
            // and what makes the dead prefix a cost rather than a curiosity.
            while !conn.is_write_saturated() {
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
                conn.tx.len() - conn.tx_pos
            );
            if conn.tx_pos == 0 && !conn.tx.is_empty() {
                halvings += 1;
            }
            if conn.wants_write() {
                short_writes += 1;
            }
            high_water = high_water.max(conn.tx.len());

            // One bufferful per round, so the socket stays full and the writes stay
            // short.
            assert!(sip(&mut peer, &mut got) > 0, "the peer read nothing");
        }

        while conn.wants_write() {
            conn.flush_some().expect("a flush");
            assert!(
                drain(&mut peer, &mut got) > 0 || !conn.wants_write(),
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
            while conn.wants_write() {
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

            for _ in 0..2 {
                conn.fill().expect("a fill after the peer closed");
                assert!(conn.is_eof(), "the close must be reported");
                assert!(
                    matches!(conn.take_frame(&mut scratch), Ok(None)),
                    "a frame whose payload never arrived must not be handed over"
                );
                assert_eq!(buffered(&conn), split, "the stump is neither used nor lost");
            }
        }
    }

    /// `send_last` throws the queue away: a client being closed replays from the
    /// ring anyway, and a small final write is what lets it complete against a peer
    /// that is barely reading.
    #[test]
    fn send_last_replaces_whatever_was_queued() {
        let payload = bulk(4096);
        let (mut peer, mut conn) = pair();
        for i in 0..64u64 {
            conn.send(&Frame::Output {
                offset: i * 4096,
                data: &payload,
            });
        }
        assert!(conn.wants_write(), "there is something to throw away");

        let last = Frame::Error {
            code: ErrorCode::Takeover,
            message: "another client attached",
        };
        conn.send_last(&last);

        let mut got = Vec::new();
        drain(&mut peer, &mut got);
        assert!(
            got == encoded(&last),
            "only the last frame may be delivered"
        );
    }

    /// `flush_final` against a peer that has stopped reading gives up on its
    /// deadline. Unbounded, it would park the whole daemon — no PTY drained, no
    /// reaping — inside a blocking write for as long as that peer likes.
    #[test]
    fn flush_final_gives_up_on_a_peer_that_has_stopped_reading() {
        let payload = bulk(4096);
        let (_peer, mut conn) = pair();
        while !conn.is_write_saturated() {
            conn.send(&Frame::Output {
                offset: 0,
                data: &payload,
            });
        }
        // Fill the kernel's buffer first, so it is the deadline that ends the call.
        conn.flush_some().expect("a flush");
        assert!(
            conn.wants_write(),
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
            conn.wants_write(),
            "the queue is left for the caller to drop"
        );
    }
}
