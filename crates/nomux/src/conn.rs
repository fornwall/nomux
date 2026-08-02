//! Non-blocking framed connection to a client.
//!
//! Reads accumulate until a whole frame is available; writes accumulate until the
//! socket accepts them. Decoding copies each payload into caller-owned scratch so
//! the borrow of the receive buffer ends before the frame is handled — cheap,
//! because the decode direction only ever carries keystrokes and control frames.
//! The output direction, where volume actually lives, is encoded straight from the
//! ring.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use nomux_proto::{Frame, FrameType, HEADER_LEN, Header, MAX_PAYLOAD, decode_header};

/// Stop queueing output once this much is already waiting for a slow client. The
/// ring keeps absorbing PTY output regardless, so the effect of a stalled client is
/// a gap, never a blocked child.
const MAX_PENDING_WRITE: usize = 1 << 20;

/// Queue size at which a client is treated as gone rather than slow. Well clear of
/// [`MAX_PENDING_WRITE`] plus one output chunk, so only unanswered control frames
/// can reach it.
const ABANDON_PENDING_WRITE: usize = 8 << 20;

/// Stop reading from the socket once this much undecoded input is already buffered.
///
/// [`Conn::fill`] loops until `EAGAIN`, and against a peer that keeps writing that
/// loop has no natural end: every chunk it takes frees exactly that much room in the
/// kernel's buffer for the peer to refill. The cap turns it back into back pressure,
/// leaving the bytes where the peer blocks on them.
///
/// Load-bearing rather than defensive, because the daemon stops *decoding* once the
/// PTY queue is full (`IMPLEMENTATION.md` § 4.1). Nothing empties this buffer while
/// that holds, so without a ceiling on what goes into it the queue would simply have
/// moved from one `Vec` to another.
///
/// It has to stay clear of `HEADER_LEN + MAX_PAYLOAD`, which is the one thing it may
/// not be: a frame that cannot be buffered whole is a frame [`Conn::take_frame`]
/// never completes, and the connection would then refuse to read the rest of the
/// frame it is waiting for.
const MAX_PENDING_READ: usize = 1 << 20;

// That last relationship, as a compile error rather than a paragraph. The two sides
// live in different crates, so raising `MAX_PAYLOAD` is a change nobody editing it
// would think to check here — and the failure it buys is a connection that wedges on
// the one frame it can never finish reading.
const _: () = assert!(
    MAX_PENDING_READ > HEADER_LEN + MAX_PAYLOAD as usize,
    "MAX_PENDING_READ must have room for a whole frame, or take_frame never completes one"
);

/// Compact the receive buffer once this many consumed bytes have accumulated.
const COMPACT_THRESHOLD: usize = 64 * 1024;

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

    /// Whether this peer has stopped reading altogether.
    ///
    /// [`Conn::is_write_saturated`] holds back output, but the control frames that
    /// answer a client — an `InputAck` per `Input`, a `Pong` per `Ping` — are not
    /// optional and are queued regardless. A peer that writes without ever reading
    /// therefore grows this queue without bound, and past this point it is not slow,
    /// it is gone: dropping it costs a working client nothing, since reattaching
    /// replays from the ring.
    #[must_use]
    pub(crate) const fn is_write_hopeless(&self) -> bool {
        self.tx.len() - self.tx_pos >= ABANDON_PENDING_WRITE
    }

    /// Queues a frame, discarding the encode result.
    ///
    /// Every caller here chunks to at most [`MAX_PAYLOAD`] and passes flags this
    /// crate defines, so the two encode failures — an oversized payload and an
    /// undefined flag bit — are both unreachable. Threading a `Result` out to every
    /// call site would obscure the real error paths for an impossible case.
    fn send(&mut self, frame: &Frame<'_>) {
        let _ = frame.encode(&mut self.tx);
    }

    /// Queues a control frame, whose size is fixed and small.
    pub(crate) fn send_control(&mut self, frame: &Frame<'_>) {
        self.send(frame);
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
            // larger than the queue budget, and a single pump would otherwise
            // queue the whole of it for a client that has stopped reading. The
            // caller resumes from the returned offset.
            if self.is_write_saturated() {
                break;
            }
            self.send(&Frame::Output { offset, data: part });
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
    /// announce — the socket reported them once and has nothing new to say. This is
    /// what tells the event loop to come back for them once the queue has room,
    /// instead of waiting for a wakeup that is not coming.
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
        if self.tx_pos == self.tx.len() {
            self.tx.clear();
            self.tx_pos = 0;
        } else if self.tx_pos >= COMPACT_THRESHOLD {
            self.tx.drain(..self.tx_pos);
            self.tx_pos = 0;
        }
        Ok(())
    }

    /// Pushes out whatever is queued, giving up [`FINAL_FLUSH_TIMEOUT`] after it
    /// started.
    ///
    /// # Errors
    ///
    /// Propagates write failures, including the deadline expiring.
    pub(crate) fn flush_final(&mut self) -> io::Result<()> {
        // Bounded, because the connection being flushed is frequently one that has
        // stopped reading — that is what a takeover is usually recovering from. An
        // unbounded blocking write here parks the entire daemon inside the kernel:
        // no PTY drained, no client served, no reaping, until a peer that may never
        // read again decides to.
        //
        // Against the whole call, not against each `write`. `SO_SNDTIMEO` restarts
        // per syscall, so a peer reading a trickle keeps resetting it and eight
        // megabytes — the queue this tolerates before giving up on a client — take
        // as long as that peer likes. `nomux kill` allows the daemon two seconds to
        // shut down before `SIGKILL`, and this runs inside them, so an overrun here
        // is a process group left behind and run files that outlive the session.
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
    /// anything still queued, then flushes.
    ///
    /// Queued output is worthless to a connection that is being closed — a
    /// reattaching client replays it from the ring anyway — and dropping it keeps
    /// the final write small enough to complete promptly even against a peer that
    /// has stopped reading.
    pub(crate) fn send_last(&mut self, frame: &Frame<'_>) {
        self.tx.clear();
        self.tx_pos = 0;
        self.send_control(frame);
        drop(self.flush_final());
    }

    /// Removes one complete frame from the receive buffer, copying its payload into
    /// `scratch`.
    ///
    /// Returns `None` when no complete frame is buffered yet.
    ///
    /// # Errors
    ///
    /// [`nomux_proto::ProtoError`] for an unparseable header.
    pub(crate) fn take_frame(
        &mut self,
        scratch: &mut Vec<u8>,
    ) -> Result<Option<FrameType>, nomux_proto::ProtoError> {
        let available = self.rx.get(self.rx_pos..).unwrap_or(&[]);
        let Some(head) = available.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let head: [u8; HEADER_LEN] = head.try_into().unwrap_or([0; HEADER_LEN]);
        let Header { ty, len } = decode_header(&head)?;

        let len = len as usize;
        let Some(payload) = available.get(HEADER_LEN..HEADER_LEN + len) else {
            return Ok(None);
        };
        scratch.clear();
        scratch.extend_from_slice(payload);
        self.rx_pos += HEADER_LEN + len;

        if self.rx_pos == self.rx.len() {
            self.rx.clear();
            self.rx_pos = 0;
        } else if self.rx_pos >= COMPACT_THRESHOLD {
            self.rx.drain(..self.rx_pos);
            self.rx_pos = 0;
        }
        Ok(Some(ty))
    }
}
