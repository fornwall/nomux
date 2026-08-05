//! Frame payloads and their codec.
//!
//! Decoding borrows from the input buffer, so relaying PTY bytes costs no
//! allocation and no copy beyond the eventual write.

use crate::{FrameType, HEADER_LEN, ProtoError, encode_header, wire_enum};

/// Terminal dimensions, applied to the PTY master via `TIOCSWINSZ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WinSize {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// Width in pixels, 0 when unknown.
    pub xpixel: u16,
    /// Height in pixels, 0 when unknown.
    pub ypixel: u16,
}

wire_enum! {
    /// How the child process terminated.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    ExitKind: u8, as_byte / from_byte,
    /// Returned a status from `main` or `exit`.
    Exited = 0,
    /// Killed by a signal.
    Signalled = 1,
}

wire_enum! {
    /// Reason the daemon is closing a connection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    ErrorCode: u16, as_u16 / from_u16,
    /// Malformed or out-of-sequence frame.
    Protocol = 1,
    /// Another client attached and took the session over.
    Takeover = 2,
    /// `Hello.protocol` does not match this daemon's.
    Version = 3,
    /// Client skipped ahead in the input stream; input must not have holes.
    InputGap = 4,
    /// Daemon-side failure.
    Internal = 5,
}

/// Sentinel for [`Hello::out_offset`] meaning "I have no state; send everything
/// retained". Used on a fresh client launch to recover scrollback.
pub const RESUME_FROM_START: u64 = u64::MAX;

/// [`Hello::flags`] bit: serve an `ssh-agent` socket for this session.
///
/// Honoured only by the `Hello` that *creates* the session (`IMPLEMENTATION.md`
/// § 2.3), and never set silently: it bypasses the user's `ForwardAgent` decision
/// (`DESIGN.md` § 5.4).
pub const HELLO_AGENT_FORWARD: u8 = 1 << 0;

/// [`Hello::flags`] bit: repaint after a gap by writing `Ctrl-L` to the PTY
/// instead of the `TIOCSWINSZ` dance.
///
/// Honoured on every attach (`IMPLEMENTATION.md` § 2.3), and chosen by the client
/// because only the client knows whether a bare shell prompt or an editor is on the
/// screen.
pub const HELLO_REPAINT_CTRL_L: u8 = 1 << 1;

/// Bits defined in [`Hello::flags`]. Anything else set is a protocol error.
const HELLO_FLAG_BITS: u8 = HELLO_AGENT_FORWARD | HELLO_REPAINT_CTRL_L;

/// Refuses a [`Hello::flags`] word carrying a bit this revision does not define.
///
/// Undefined bits are a protocol error rather than a forward-compatibility case
/// (`IMPLEMENTATION.md` § 2.3), and are refused on the way *out* as well as on the
/// way in: without the encode-side call a caller could build a `Hello` that encodes
/// cleanly and earns an `Error{Protocol}` from the peer, a bug reported at the wrong
/// end of the connection, by the process that did nothing wrong.
const fn checked_hello_flags(flags: u8) -> Result<(), ProtoError> {
    if flags & !HELLO_FLAG_BITS != 0 {
        return Err(ProtoError::Malformed("undefined Hello flag bits"));
    }
    Ok(())
}

/// Refuses a [`Hello::term`] carrying an interior NUL.
///
/// U+0000 is valid UTF-8, so the `from_utf8` on the decode side lets it through —
/// and the daemon puts `term` straight into the child's environment
/// (`IMPLEMENTATION.md` § 6.1.1), where `execve` takes NUL-terminated strings and
/// refuses it. That makes a NUL the one field value this crate can call
/// well-formed and the daemon then cannot use: the spawn fails, the client is told
/// `Error{Internal}`, and a failure that belongs to the frame is reported as one
/// belonging to the host. Refused at the boundary instead, on the way *out* as
/// well as in, for the reason [`checked_hello_flags`] gives.
fn checked_term(term: &str) -> Result<(), ProtoError> {
    if term.as_bytes().contains(&0) {
        return Err(ProtoError::Malformed("TERM contains a NUL byte"));
    }
    Ok(())
}

/// Opening frame: what the client already has, and how big its terminal is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello<'a> {
    /// Must equal [`crate::PROTOCOL_VERSION`] or the daemon rejects the connection.
    ///
    /// The only field on this wire that survives a revision bump unchanged, and the
    /// whole of the compatibility story: there is no negotiation, so a mismatch is a
    /// refusal (`DESIGN.md` § 6.4). [`HelloOk`] carries no answering copy — the
    /// daemon has already checked this one by the time it replies, so a revision in
    /// the answer could only ever repeat what the client just said.
    pub protocol: u16,
    /// [`HELLO_AGENT_FORWARD`] and [`HELLO_REPAINT_CTRL_L`].
    pub flags: u8,
    /// Next output byte the client wants, or [`RESUME_FROM_START`].
    pub out_offset: u64,
    /// Terminal dimensions.
    pub win: WinSize,
    /// Value for the child's `TERM`. Ignored when resuming an existing session.
    pub term: &'a str,
}

impl Hello<'_> {
    /// Whether the client asked for an `ssh-agent` socket.
    #[must_use]
    pub const fn agent_forward(&self) -> bool {
        self.flags & HELLO_AGENT_FORWARD != 0
    }

    /// Whether the client wants `Ctrl-L` rather than a `SIGWINCH` pair as the
    /// post-gap repaint.
    #[must_use]
    pub const fn repaint_ctrl_l(&self) -> bool {
        self.flags & HELLO_REPAINT_CTRL_L != 0
    }
}

wire_enum! {
    /// Whether the daemon's session outlives the user's last logout.
    ///
    /// The daemon cannot stop `logind` from killing it at logout, so it reports the
    /// state and the client warns (`IMPLEMENTATION.md` § 6.2).
    ///
    /// A byte of [`HelloOk`] in its own right, like every other closed set here, so
    /// [`Linger::as_byte`] and [`Linger::from_byte`] are the wire form rather than an
    /// unshifted half of it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    Linger: u8, as_byte / from_byte,
    /// Not determined: no `systemd`, or its state is unreadable. Do not warn —
    /// on a host without `logind` there is nothing to warn about.
    #[default]
    Unknown = 0,
    /// `logind` is running and lingering is off for this user. The session dies at
    /// logout if the host also sets `KillUserProcesses=yes`.
    Disabled = 1,
    /// Lingering is on; the session survives logout.
    Enabled = 2,
}

/// [`HelloOk`] flags bit: this session is serving an agent socket.
const HELLOOK_AGENT: u8 = 1 << 0;
/// Bits defined in [`HelloOk`]'s flags byte. Anything else set is a protocol error.
const HELLOOK_FLAG_BITS: u8 = HELLOOK_AGENT;

/// Daemon's answer to [`Hello`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloOk {
    /// Offset the daemon will start streaming output from.
    pub resume_from: u64,
    /// Authoritative input offset; the client fast-forwards to this.
    pub in_applied: u64,
    /// The session's current dimensions.
    pub win: WinSize,
    /// Whether this session survives the user's logout.
    pub linger: Linger,
    /// Whether an agent socket is being served, so the client knows to expect
    /// [`Frame::AgentOpen`]. False when the session was created without
    /// [`HELLO_AGENT_FORWARD`], or when the socket could not be bound.
    pub agent: bool,
}

impl HelloOk {
    /// Whether output was dropped before [`HelloOk::resume_from`], leaving the stream
    /// discontinuous for a client that asked to resume at `out_offset`.
    ///
    /// Derived rather than carried, because `resume_from` already decides it and the
    /// client already holds the `out_offset` it sent. The daemon's three branches
    /// (`IMPLEMENTATION.md` § 4.2) each satisfy `gap ⟺ resume_from > out_offset`,
    /// with `b` the ring's base and `e` its end, `b <= e` by construction:
    ///
    /// - `out_offset == u64::MAX`, the "send me whatever you have" sentinel: no gap,
    ///   and `resume_from = b`, which cannot exceed `u64::MAX`.
    /// - `out_offset < b`: a gap, and `min(out_offset, e).max(b) = b > out_offset`.
    /// - `b <= out_offset <= e`: no gap, and `resume_from` is `out_offset` itself.
    /// - `out_offset > e`: output the session never produced, clamped down to `e`
    ///   and not a gap, since nothing was dropped — and `e < out_offset`.
    ///
    /// An empty ring is the third and fourth cases at `b == e` and needs nothing of
    /// its own.
    #[must_use]
    pub const fn gap(&self, out_offset: u64) -> bool {
        self.resume_from > out_offset
    }

    /// Packs the boolean fields into the wire flags byte.
    const fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.agent {
            flags |= HELLOOK_AGENT;
        }
        flags
    }
}

/// A decoded protocol frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// See [`Hello`].
    Hello(Hello<'a>),
    /// See [`HelloOk`].
    HelloOk(HelloOk),
    /// Keystrokes at an absolute offset in the input stream.
    Input {
        /// Offset of the first byte of `data`.
        offset: u64,
        /// Raw bytes for the PTY master.
        data: &'a [u8],
    },
    /// Input the daemon has taken ownership of and will never re-apply.
    ///
    /// Sent once the bytes are queued for the PTY master, not once `write(2)` for
    /// them returns: what the client needs in order to stop replaying them is
    /// ownership rather than durability (`IMPLEMENTATION.md` § 3).
    InputAck {
        /// Exclusive upper bound of applied input.
        applied_through: u64,
    },
    /// PTY output at an absolute offset in the output stream.
    Output {
        /// Offset of the first byte of `data`.
        offset: u64,
        /// Raw bytes from the PTY master.
        data: &'a [u8],
    },
    /// Advisory acknowledgement of consumed output.
    ///
    /// Payload-free: the daemon tracks what it has sent by itself and never trims the
    /// ring on an ack (`IMPLEMENTATION.md` § 3, § 4), so what this frame does is
    /// *arrive* — it wakes the loop and lets a replay that stopped on a full socket
    /// resume. An offset here would be a number with no reader.
    OutputAck,
    /// New terminal dimensions.
    Resize(WinSize),
    /// Output was discarded by ring overflow.
    Gap {
        /// New oldest retained offset.
        new_base_offset: u64,
    },
    /// The child terminated.
    Exit {
        /// Exit status, or signal number when `kind` is [`ExitKind::Signalled`].
        status: i32,
        /// How it terminated.
        kind: ExitKind,
        /// Whole seconds since the child let go of the terminal.
        ///
        /// Zero for a client watching the exit happen and days for one that arrives
        /// afterwards, the daemon now outliving its child
        /// (`IMPLEMENTATION.md` § 6.5). Elapsed rather than a wall-clock stamp: the
        /// daemon reads a monotonic clock it can trust and never one it cannot, and
        /// the client converts against its own. Saturates rather than wrapping, at a
        /// width no session reaches — 136 years.
        since_exit_secs: u32,
    },
    /// Client is leaving without ending the session.
    Detach,
    /// Liveness probe.
    Ping {
        /// Echoed back in [`Frame::Pong`].
        nonce: u64,
    },
    /// Liveness response.
    Pong {
        /// Nonce from the corresponding [`Frame::Ping`].
        nonce: u64,
    },
    /// Daemon-side failure; the connection closes after this.
    Error {
        /// Machine-readable reason.
        code: ErrorCode,
        /// Human-readable detail.
        message: &'a str,
    },
    /// A process connected to the session's agent socket.
    AgentOpen {
        /// Daemon-allocated channel id.
        chan: u32,
    },
    /// Opaque `ssh-agent` bytes for one channel.
    AgentData {
        /// Channel id.
        chan: u32,
        /// Bytes, never parsed by the daemon.
        data: &'a [u8],
    },
    /// One agent channel is finished.
    AgentClose {
        /// Channel id.
        chan: u32,
    },
}

impl<'a> Frame<'a> {
    /// Returns this frame's discriminant.
    #[must_use]
    pub const fn frame_type(&self) -> FrameType {
        match *self {
            Self::Hello(_) => FrameType::Hello,
            Self::HelloOk(_) => FrameType::HelloOk,
            Self::Input { .. } => FrameType::Input,
            Self::InputAck { .. } => FrameType::InputAck,
            Self::Output { .. } => FrameType::Output,
            Self::OutputAck => FrameType::OutputAck,
            Self::Resize(_) => FrameType::Resize,
            Self::Gap { .. } => FrameType::Gap,
            Self::Exit { .. } => FrameType::Exit,
            Self::Detach => FrameType::Detach,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
            Self::Error { .. } => FrameType::Error,
            Self::AgentOpen { .. } => FrameType::AgentOpen,
            Self::AgentData { .. } => FrameType::AgentData,
            Self::AgentClose { .. } => FrameType::AgentClose,
        }
    }

    /// Appends this frame, header included, to `out`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::PayloadTooLarge`] if the encoded payload exceeds
    /// [`crate::MAX_PAYLOAD`], or [`ProtoError::Malformed`] for a field too long
    /// for its own length prefix — or for the header slot going missing, which the
    /// line that reserves it rules out and which is an error here rather than a
    /// silence for the reason given below. `out` is rewound to its original length
    /// in every case.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        // The payload goes straight into the caller's buffer and the header is
        // patched in behind it, so every error path rewinds to `start`: a refused
        // frame leaves the buffer exactly as long as it was found, and a caller
        // appending frames back to back never ships half of one. Each field's check
        // is then free to live beside the field in `encode_payload`.
        let start = out.len();
        out.extend_from_slice(&[0; HEADER_LEN]);
        self.encode_payload(out)
            .inspect_err(|_| out.truncate(start))?;

        let header = u32::try_from(out.len() - start - HEADER_LEN)
            .map_err(|_| ProtoError::PayloadTooLarge(u32::MAX))
            .and_then(|len| encode_header(self.frame_type(), len))
            .inspect_err(|_| out.truncate(start))?;
        // A patch that does not land must not pass for one that did: the frame would
        // go out under the zero header reserved above, which the peer decodes as
        // `UnknownFrameType(0x00)` and answers with `Error{Protocol}` — a bug
        // reported at the far end of the connection, about a frame that end never
        // had a say in. Unreachable behind the `extend_from_slice`, and so written
        // as the one thing an unreachable case may be.
        let Some(slot) = out
            .get_mut(start..)
            .and_then(<[u8]>::first_chunk_mut::<HEADER_LEN>)
        else {
            out.truncate(start);
            return Err(ProtoError::Malformed("the header slot went missing"));
        };
        *slot = header;
        Ok(())
    }

    fn encode_payload(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        match *self {
            Self::Hello(hello) => {
                // Refused rather than truncated: silently shortening a `TERM` too
                // long for its own length prefix would open the session under a
                // terminal type nobody chose, and the caller has no way to notice.
                // Ahead of the flag check, so a `Hello` that is wrong in both ways
                // names this one — `a_hello_wrong_in_two_ways_reports_the_term`
                // pins that, since the choice should not change by accident.
                let term_len = u16::try_from(hello.term.len())
                    .map_err(|_| ProtoError::Malformed("TERM exceeds 65535 bytes"))?;
                checked_term(hello.term)?;
                checked_hello_flags(hello.flags)?;

                out.extend_from_slice(&hello.protocol.to_be_bytes());
                out.push(hello.flags);
                out.extend_from_slice(&hello.out_offset.to_be_bytes());
                put_win(out, hello.win);
                out.extend_from_slice(&term_len.to_be_bytes());
                out.extend_from_slice(hello.term.as_bytes());
            }
            Self::HelloOk(ok) => {
                out.extend_from_slice(&ok.resume_from.to_be_bytes());
                out.extend_from_slice(&ok.in_applied.to_be_bytes());
                put_win(out, ok.win);
                out.push(ok.linger.as_byte());
                out.push(ok.flags());
            }
            Self::Input { offset, data } | Self::Output { offset, data } => {
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::InputAck {
                applied_through: value,
            }
            | Self::Gap {
                new_base_offset: value,
            }
            | Self::Ping { nonce: value }
            | Self::Pong { nonce: value } => out.extend_from_slice(&value.to_be_bytes()),
            Self::Resize(win) => put_win(out, win),
            Self::Exit {
                status,
                kind,
                since_exit_secs,
            } => {
                out.extend_from_slice(&status.to_be_bytes());
                out.push(kind.as_byte());
                out.extend_from_slice(&since_exit_secs.to_be_bytes());
            }
            Self::Detach | Self::OutputAck => {}
            Self::Error { code, message } => {
                out.extend_from_slice(&code.as_u16().to_be_bytes());
                out.extend_from_slice(message.as_bytes());
            }
            Self::AgentOpen { chan } | Self::AgentClose { chan } => {
                out.extend_from_slice(&chan.to_be_bytes());
            }
            Self::AgentData { chan, data } => {
                out.extend_from_slice(&chan.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }

    /// Decodes a frame payload, borrowing byte and string fields from it.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] if the payload ends early,
    /// [`ProtoError::TrailingBytes`] if it is longer than the frame requires,
    /// [`ProtoError::PayloadTooLarge`] if it is longer than [`crate::MAX_PAYLOAD`],
    /// and [`ProtoError::Malformed`] for invalid enum discriminants or non-UTF-8
    /// text.
    pub fn decode(ty: FrameType, payload: &'a [u8]) -> Result<Self, ProtoError> {
        // The in-tree caller reaches this only through `decode_header`, which has
        // already applied the bound. Restated here because `decode` is public and
        // meant to be usable on its own (`IMPLEMENTATION.md` § 1): without it a
        // frame could decode that this crate would then refuse to encode, and the
        // two halves would not be inverses.
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        if len > crate::MAX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge(len));
        }

        let mut r = Reader::new(payload);
        let frame = match ty {
            FrameType::Hello => {
                let protocol = r.u16()?;
                let flags = r.u8()?;
                checked_hello_flags(flags)?;
                let out_offset = r.u64()?;
                let win = r.win()?;
                let term_len = usize::from(r.u16()?);
                let term = core::str::from_utf8(r.take(term_len)?)
                    .map_err(|_| ProtoError::Malformed("TERM is not UTF-8"))?;
                checked_term(term)?;
                Self::Hello(Hello {
                    protocol,
                    flags,
                    out_offset,
                    win,
                    term,
                })
            }
            FrameType::HelloOk => {
                let resume_from = r.u64()?;
                let in_applied = r.u64()?;
                let win = r.win()?;
                let linger = Linger::from_byte(r.u8()?)
                    .ok_or(ProtoError::Malformed("unknown linger state"))?;
                let flags = r.u8()?;
                if flags & !HELLOOK_FLAG_BITS != 0 {
                    return Err(ProtoError::Malformed("undefined HelloOk flag bits"));
                }
                Self::HelloOk(HelloOk {
                    resume_from,
                    in_applied,
                    win,
                    linger,
                    agent: flags & HELLOOK_AGENT != 0,
                })
            }
            FrameType::Input => Self::Input {
                offset: r.u64()?,
                data: r.rest(),
            },
            FrameType::Output => Self::Output {
                offset: r.u64()?,
                data: r.rest(),
            },
            FrameType::InputAck => Self::InputAck {
                applied_through: r.u64()?,
            },
            FrameType::OutputAck => Self::OutputAck,
            FrameType::Resize => Self::Resize(r.win()?),
            FrameType::Gap => Self::Gap {
                new_base_offset: r.u64()?,
            },
            FrameType::Exit => Self::Exit {
                status: r.i32()?,
                kind: ExitKind::from_byte(r.u8()?)
                    .ok_or(ProtoError::Malformed("unknown exit kind"))?,
                since_exit_secs: r.u32()?,
            },
            FrameType::Detach => Self::Detach,
            FrameType::Ping => Self::Ping { nonce: r.u64()? },
            FrameType::Pong => Self::Pong { nonce: r.u64()? },
            FrameType::Error => Self::Error {
                code: ErrorCode::from_u16(r.u16()?)
                    .ok_or(ProtoError::Malformed("unknown error code"))?,
                message: core::str::from_utf8(r.rest())
                    .map_err(|_| ProtoError::Malformed("error message is not UTF-8"))?,
            },
            FrameType::AgentOpen => Self::AgentOpen { chan: r.u32()? },
            FrameType::AgentClose => Self::AgentClose { chan: r.u32()? },
            FrameType::AgentData => Self::AgentData {
                chan: r.u32()?,
                data: r.rest(),
            },
        };

        // Every fixed-size frame must have consumed its payload exactly; the
        // variable-length ones end in `rest()`, which empties the reader, so this
        // is vacuously true for them rather than a case to exclude.
        r.finish().map(|()| frame)
    }
}

fn put_win(out: &mut Vec<u8>, win: WinSize) {
    out.extend_from_slice(&win.cols.to_be_bytes());
    out.extend_from_slice(&win.rows.to_be_bytes());
    out.extend_from_slice(&win.xpixel.to_be_bytes());
    out.extend_from_slice(&win.ypixel.to_be_bytes());
}

/// Big-endian cursor over a frame payload.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { rest: buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(ProtoError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(ProtoError::Truncated)?;
        self.rest = tail;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn i32(&mut self) -> Result<i32, ProtoError> {
        Ok(i32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn win(&mut self) -> Result<WinSize, ProtoError> {
        Ok(WinSize {
            cols: self.u16()?,
            rows: self.u16()?,
            xpixel: self.u16()?,
            ypixel: self.u16()?,
        })
    }

    const fn rest(&mut self) -> &'a [u8] {
        let all = self.rest;
        self.rest = &[];
        all
    }

    const fn finish(self) -> Result<(), ProtoError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_PAYLOAD, PROTOCOL_VERSION, decode_header};

    fn round_trip(frame: Frame<'_>) {
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let header: [u8; HEADER_LEN] = buf[..HEADER_LEN].try_into().unwrap();
        let header = decode_header(&header).unwrap();
        assert_eq!(header.ty, frame.frame_type());
        assert_eq!(header.len as usize, buf.len() - HEADER_LEN);

        let decoded = Frame::decode(header.ty, &buf[HEADER_LEN..]).unwrap();
        assert_eq!(decoded, frame, "round trip mismatch");
    }

    const WIN: WinSize = WinSize {
        cols: 120,
        rows: 40,
        xpixel: 960,
        ypixel: 640,
    };

    #[test]
    fn empty_payloads_round_trip() {
        round_trip(Frame::Input {
            offset: 0,
            data: b"",
        });
        round_trip(Frame::Output {
            offset: 0,
            data: b"",
        });
        round_trip(Frame::Error {
            code: ErrorCode::Internal,
            message: "",
        });
    }

    #[test]
    fn truncated_payload_is_rejected() {
        assert_eq!(
            Frame::decode(FrameType::Ping, &[0, 0, 0]),
            Err(ProtoError::Truncated)
        );
        assert_eq!(
            Frame::decode(FrameType::Hello, &[]),
            Err(ProtoError::Truncated)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            Frame::decode(FrameType::Ping, &[0, 0, 0, 0, 0, 0, 0, 0, 9]),
            Err(ProtoError::TrailingBytes)
        );
    }

    #[test]
    fn invalid_discriminants_are_rejected() {
        assert_eq!(
            Frame::decode(FrameType::Exit, &[0, 0, 0, 0, 7]),
            Err(ProtoError::Malformed("unknown exit kind"))
        );
        assert_eq!(
            Frame::decode(FrameType::Error, &[0xff, 0xff]),
            Err(ProtoError::Malformed("unknown error code"))
        );
    }

    /// Each reserved encoding earns its own diagnosis, so the two are not
    /// interchangeable: an undefined bit is one bug, a reserved linger value another.
    ///
    /// The two now sit in adjacent bytes rather than in one, so this also pins that
    /// the decoder reads them apart: a byte offset off by one turns each complaint
    /// into the other's.
    #[test]
    fn undefined_flag_bits_are_rejected() {
        let mut hello = Vec::new();
        Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            win: WIN,
            term: "",
        })
        .encode(&mut hello)
        .unwrap();
        // `flags` is the single byte after the u16 protocol.
        hello[HEADER_LEN + 2] = 0x80;
        assert_eq!(
            Frame::decode(FrameType::Hello, &hello[HEADER_LEN..]),
            Err(ProtoError::Malformed("undefined Hello flag bits"))
        );

        let mut ok = Vec::new();
        Frame::HelloOk(HelloOk {
            resume_from: 0,
            in_applied: 0,
            win: WIN,
            linger: Linger::Unknown,
            agent: false,
        })
        .encode(&mut ok)
        .unwrap();
        // The payload ends `.., u8 linger, u8 flags`: reserved bit 1 of the flags
        // byte, then the reserved linger encoding 3 in the byte before it.
        let flags = ok.len() - 1;
        for (at, byte, complaint) in [
            (flags, 0b10, "undefined HelloOk flag bits"),
            (flags - 1, 3, "unknown linger state"),
        ] {
            let mut mutated = ok.clone();
            mutated[at] = byte;
            assert_eq!(
                Frame::decode(FrameType::HelloOk, &mutated[HEADER_LEN..]),
                Err(ProtoError::Malformed(complaint)),
                "byte {byte:#b} at payload offset {} should be refused",
                at - HEADER_LEN
            );
        }
    }

    /// [`HelloOk::gap`] answers what the flag it replaced carried, on every case
    /// `IMPLEMENTATION.md` § 4.2 distinguishes.
    ///
    /// The flag was computed by the daemon from the client's `out_offset` and the
    /// ring's base; this derives it from `resume_from`, which the same three branches
    /// had just set. That they agree is an argument, and this is the argument run
    /// rather than written down: § 4.2 is transcribed once below, and both answers are
    /// compared for every ring shape that matters — empty, ordinary, and pressed
    /// against the top of the offset space — against offsets on both sides of each
    /// edge, plus the `RESUME_FROM_START` sentinel that is the one `out_offset` value
    /// meaning something other than an offset.
    #[test]
    fn the_derived_gap_agrees_with_the_flowchart_it_replaces() {
        /// § 4.2's flowchart, for a ring retaining `base..end`.
        fn flowchart(out_offset: u64, base: u64, end: u64) -> (u64, bool) {
            if out_offset == RESUME_FROM_START {
                (base, false)
            } else if out_offset < base {
                (base, true)
            } else {
                // Clamped at both ends, exactly as `Daemon::on_hello` does it.
                (out_offset.min(end).max(base), false)
            }
        }

        for (base, end) in [
            // A session nobody has written to, and one that has not overflowed.
            (0, 0),
            (0, 16),
            // A ring that has dropped its head, full and empty.
            (8, 8),
            (8, 24),
            // The top of the offset space, where the sentinel and a real offset are
            // the closest they can be.
            (u64::MAX - 4, u64::MAX),
            (u64::MAX, u64::MAX),
        ] {
            for out_offset in [
                0,
                base.saturating_sub(1),
                base,
                base.saturating_add(1),
                end.saturating_sub(1),
                end,
                end.saturating_add(1),
                u64::MAX - 1,
                RESUME_FROM_START,
            ] {
                let (resume_from, gap) = flowchart(out_offset, base, end);
                let ok = HelloOk {
                    resume_from,
                    in_applied: 0,
                    win: WIN,
                    linger: Linger::Unknown,
                    agent: false,
                };
                assert_eq!(
                    ok.gap(out_offset),
                    gap,
                    "a client resuming at {out_offset} against a ring holding \
                     {base}..{end} is told to resume at {resume_from}, which § 4.2 \
                     calls gap={gap}"
                );
            }
        }
    }

    #[test]
    fn non_utf8_text_is_rejected() {
        // Hello with term_len 1 and a lone continuation byte: protocol, flags,
        // `out_offset` and the winsize ahead of it.
        let mut payload = vec![0; 2 + 1 + 8 + 8];
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(0x80);
        assert_eq!(
            Frame::decode(FrameType::Hello, &payload),
            Err(ProtoError::Malformed("TERM is not UTF-8"))
        );

        // The other text field, which earns its own diagnosis for the same reason
        // the reserved encodings above do: `Error` with a valid code and a lone
        // continuation byte for a message.
        assert_eq!(
            Frame::decode(FrameType::Error, &[0x00, 0x01, 0x80]),
            Err(ProtoError::Malformed("error message is not UTF-8"))
        );
    }

    #[test]
    fn oversized_frame_is_refused_and_buffer_restored() {
        let data = vec![0u8; MAX_PAYLOAD as usize];
        let mut buf = b"previous frame".to_vec();
        let before = buf.len();
        let err = Frame::Output {
            offset: 0,
            data: &data,
        }
        .encode(&mut buf);
        assert!(matches!(err, Err(ProtoError::PayloadTooLarge(_))));
        assert_eq!(
            buf.len(),
            before,
            "failed encode must not leave partial data"
        );
    }

    /// `term` is length-prefixed by a `u16`, so a longer one cannot be represented.
    #[test]
    fn an_unrepresentable_term_is_refused_rather_than_truncated() {
        let long = "x".repeat(usize::from(u16::MAX) + 1);
        let mut buf = b"previous frame".to_vec();
        let before = buf.len();
        let err = Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            win: WIN,
            term: &long,
        })
        .encode(&mut buf);

        assert_eq!(err, Err(ProtoError::Malformed("TERM exceeds 65535 bytes")));
        assert_eq!(buf.len(), before, "the buffer must be left untouched");

        // The longest that still fits is accepted, so the boundary is exact.
        let exact = "x".repeat(usize::from(u16::MAX));
        round_trip(Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            win: WIN,
            term: &exact,
        }));
    }

    /// Encode and decode agree about which flag bits exist.
    #[test]
    fn undefined_flag_bits_are_refused_by_encode_too() {
        let mut buf = b"previous frame".to_vec();
        let before = buf.len();
        let err = Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: HELLO_AGENT_FORWARD | 0x80,
            out_offset: 0,
            win: WIN,
            term: "xterm",
        })
        .encode(&mut buf);

        assert_eq!(err, Err(ProtoError::Malformed("undefined Hello flag bits")));
        assert_eq!(buf.len(), before, "the buffer must be left untouched");
    }

    /// A `Hello` wrong in two ways at once names the `TERM`, not the flags.
    ///
    /// A `Hello` wrong in both ways is two caller bugs at once, and which of them
    /// gets named is decided by nothing more than the order of the two checks in
    /// `encode_payload` — an order an unrelated edit could reverse without noticing.
    /// `TERM` has always been the one reported, and this is what keeps it so.
    #[test]
    fn a_hello_wrong_in_two_ways_reports_the_term() {
        let long = "x".repeat(usize::from(u16::MAX) + 1);
        let err = Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: HELLO_AGENT_FORWARD | 0x80,
            out_offset: 0,
            win: WIN,
            term: &long,
        })
        .encode(&mut Vec::new());

        assert_eq!(err, Err(ProtoError::Malformed("TERM exceeds 65535 bytes")));
    }

    /// A NUL in `TERM` is valid UTF-8, and refused anyway at both ends.
    ///
    /// The decode direction is the one that matters: the daemon hands `term`
    /// straight to the child's environment, where `execve` refuses it, so a frame
    /// this crate called well-formed would take the daemon down at `spawn` rather
    /// than be answered as the protocol error it is.
    #[test]
    fn a_nul_in_term_is_refused_at_both_ends() {
        let mut buf = b"previous frame".to_vec();
        let before = buf.len();
        let err = Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            win: WIN,
            term: "xt\0rm",
        })
        .encode(&mut buf);

        assert_eq!(err, Err(ProtoError::Malformed("TERM contains a NUL byte")));
        assert_eq!(buf.len(), before, "the buffer must be left untouched");

        // Built by encoding a well-formed `Hello` and overwriting one byte of its
        // `TERM`, so this does not restate the field layout it is not testing —
        // `wire.rs` is where that is pinned.
        let mut wire = Vec::new();
        Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            win: WIN,
            term: "xt_rm",
        })
        .encode(&mut wire)
        .unwrap();
        let marker = wire.iter().position(|&b| b == b'_').unwrap();
        wire[marker] = 0;

        assert_eq!(
            Frame::decode(FrameType::Hello, &wire[HEADER_LEN..]),
            Err(ProtoError::Malformed("TERM contains a NUL byte")),
            "a NUL that arrived on the socket is a protocol error, not a spawn failure"
        );
    }

    /// `decode` is public and usable without `decode_header`, so it applies the
    /// same bound rather than trusting a caller to have done it.
    #[test]
    fn a_payload_over_the_maximum_is_refused_by_decode() {
        let oversized = vec![0u8; MAX_PAYLOAD as usize + 1];
        assert_eq!(
            Frame::decode(FrameType::Output, &oversized),
            Err(ProtoError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
        // One byte under the limit still decodes, so the bound is inclusive.
        let largest = vec![0u8; MAX_PAYLOAD as usize];
        assert!(Frame::decode(FrameType::Output, &largest).is_ok());
    }
}
