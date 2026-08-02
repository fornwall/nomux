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
pub(crate) const MAX_PENDING_WRITE: usize = 1 << 20;

/// Compact the receive buffer once this many consumed bytes have accumulated.
const COMPACT_THRESHOLD: usize = 64 * 1024;

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

    /// Queues a frame.
    ///
    /// # Errors
    ///
    /// [`nomux_proto::ProtoError`] if the frame's payload exceeds
    /// [`MAX_PAYLOAD`]; the buffer is left unchanged in that case.
    pub(crate) fn send(&mut self, frame: &Frame<'_>) -> Result<(), nomux_proto::ProtoError> {
        frame.encode(&mut self.tx)
    }

    /// Queues a frame whose size is fixed and small, ignoring the encode result.
    ///
    /// The only encode failure is an oversized payload, which is unreachable for
    /// the control frames this is used with. Threading a `Result` through every
    /// such call site would obscure the real error paths for an impossible case.
    pub(crate) fn send_control(&mut self, frame: &Frame<'_>) {
        let _ = self.send(frame);
    }

    /// Queues raw output bytes as one or more `Output` frames, splitting at
    /// [`MAX_PAYLOAD`].
    ///
    /// Returns the offset one past the last byte queued.
    ///
    /// # Errors
    ///
    /// Propagates encoding failures, which cannot occur for correctly chunked input.
    pub(crate) fn send_output(
        &mut self,
        mut offset: u64,
        data: &[u8],
    ) -> Result<u64, nomux_proto::ProtoError> {
        // Leave room for the 8-byte offset that shares the payload.
        let chunk = MAX_PAYLOAD as usize - 8;
        for part in data.chunks(chunk) {
            self.send(&Frame::Output { offset, data: part })?;
            offset += part.len() as u64;
        }
        Ok(offset)
    }

    /// Reads whatever the socket has available into the receive buffer.
    ///
    /// # Errors
    ///
    /// Propagates read failures other than `EWOULDBLOCK` and `EINTR`.
    pub(crate) fn fill(&mut self) -> io::Result<()> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
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

    /// Blocks until the send buffer is drained, for the final frames before exit.
    ///
    /// # Errors
    ///
    /// Propagates write failures.
    pub(crate) fn flush_blocking(&mut self) -> io::Result<()> {
        self.stream.set_nonblocking(false)?;
        let pending = self.tx.get(self.tx_pos..).unwrap_or(&[]);
        self.stream.write_all(pending)?;
        self.tx.clear();
        self.tx_pos = 0;
        self.stream.flush()
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
