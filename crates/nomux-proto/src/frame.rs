//! Frame payloads and their codec.
//!
//! Decoding borrows from the input buffer, so relaying PTY bytes costs no
//! allocation and no copy beyond the eventual write.

use crate::{FrameType, HEADER_LEN, ProtoError, encode_header};

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

/// How the child process terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// Returned a status from `main` or `exit`.
    Exited,
    /// Killed by a signal.
    Signalled,
}

impl ExitKind {
    /// Returns the wire discriminant.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Exited => 0,
            Self::Signalled => 1,
        }
    }

    /// Parses a wire discriminant.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Exited),
            1 => Some(Self::Signalled),
            _ => None,
        }
    }
}

/// Reason the daemon is closing a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
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

impl ErrorCode {
    /// Returns the wire discriminant.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Parses a wire discriminant.
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Protocol),
            2 => Some(Self::Takeover),
            3 => Some(Self::Version),
            4 => Some(Self::InputGap),
            5 => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Sentinel for [`Hello::out_offset`] meaning "I have no state; send everything
/// retained". Used on a fresh client launch to recover scrollback.
pub const RESUME_FROM_START: u64 = u64::MAX;

/// [`Hello::flags`] bit: serve an `ssh-agent` socket for this session.
///
/// Honoured only by the `Hello` that *creates* the session, because the child's
/// environment is frozen at spawn. Opt-in per host and never set silently: it
/// bypasses the user's `ForwardAgent` decision (`DESIGN.md` § 5.4).
pub const HELLO_AGENT_FORWARD: u16 = 1 << 0;

/// [`Hello::flags`] bit: repaint after a gap by writing `Ctrl-L` to the PTY
/// instead of the `TIOCSWINSZ` dance.
///
/// Honoured on every attach, since it costs nothing to restate. Better for a bare
/// shell prompt, destructive inside an editor — the client picks, because only the
/// client knows what it is showing.
pub const HELLO_REPAINT_CTRL_L: u16 = 1 << 1;

/// Bits defined in [`Hello::flags`]. Anything else set is a protocol error.
const HELLO_FLAG_BITS: u16 = HELLO_AGENT_FORWARD | HELLO_REPAINT_CTRL_L;

/// Opening frame: what the client already has, and how big its terminal is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello<'a> {
    /// Must equal [`crate::PROTOCOL_VERSION`] or the daemon rejects the connection.
    pub protocol: u16,
    /// [`HELLO_AGENT_FORWARD`] and [`HELLO_REPAINT_CTRL_L`].
    pub flags: u16,
    /// Next output byte the client wants, or [`RESUME_FROM_START`].
    pub out_offset: u64,
    /// Next input byte the client intends to send.
    pub in_offset: u64,
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

/// Whether the daemon's session outlives the user's last logout.
///
/// `systemd-logind` with `KillUserProcesses=yes` kills the daemon at logout unless
/// the user has lingering enabled, and no amount of double-forking avoids it
/// (`IMPLEMENTATION.md` § 6.2). The daemon cannot fix this, so it reports it and
/// the client warns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Linger {
    /// Not determined: no `systemd`, or its state is unreadable. Do not warn —
    /// on a host without `logind` there is nothing to warn about.
    #[default]
    Unknown,
    /// `logind` is running and lingering is off for this user. The session dies at
    /// logout if the host also sets `KillUserProcesses=yes`.
    Disabled,
    /// Lingering is on; the session survives logout.
    Enabled,
}

impl Linger {
    /// Returns the two-bit wire encoding, already shifted into place.
    #[must_use]
    const fn as_bits(self) -> u8 {
        let value: u8 = match self {
            Self::Unknown => 0,
            Self::Disabled => 1,
            Self::Enabled => 2,
        };
        value << HELLOOK_LINGER_SHIFT
    }

    /// Parses the two-bit wire encoding out of a flags byte.
    const fn from_flags(flags: u8) -> Option<Self> {
        match (flags & HELLOOK_LINGER_MASK) >> HELLOOK_LINGER_SHIFT {
            0 => Some(Self::Unknown),
            1 => Some(Self::Disabled),
            2 => Some(Self::Enabled),
            _ => None,
        }
    }
}

/// [`HelloOk`] flags bit: output was dropped before `resume_from`.
const HELLOOK_GAP: u8 = 1 << 0;
/// Offset of the two-bit [`Linger`] field in [`HelloOk`]'s flags byte.
const HELLOOK_LINGER_SHIFT: u32 = 1;
/// Mask of that field.
const HELLOOK_LINGER_MASK: u8 = 0b11 << HELLOOK_LINGER_SHIFT;
/// [`HelloOk`] flags bit: this session is serving an agent socket.
const HELLOOK_AGENT: u8 = 1 << 3;
/// Bits defined in [`HelloOk`]'s flags byte. Anything else set is a protocol error.
const HELLOOK_FLAG_BITS: u8 = HELLOOK_GAP | HELLOOK_LINGER_MASK | HELLOOK_AGENT;

/// Daemon's answer to [`Hello`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloOk {
    /// This daemon's protocol revision.
    pub protocol: u16,
    /// Offset the daemon will start streaming output from.
    pub resume_from: u64,
    /// Authoritative input offset; the client fast-forwards to this.
    pub in_applied: u64,
    /// The session's current dimensions.
    pub win: WinSize,
    /// Output was dropped before `resume_from`; the stream is discontinuous.
    pub gap: bool,
    /// Whether this session survives the user's logout.
    pub linger: Linger,
    /// Whether an agent socket is being served, so the client knows to expect
    /// [`Frame::AgentOpen`]. False when the session was created without
    /// [`HELLO_AGENT_FORWARD`], or when the socket could not be bound.
    pub agent: bool,
}

impl HelloOk {
    /// Packs the boolean and enum fields into the wire flags byte.
    const fn flags(&self) -> u8 {
        let mut flags = self.linger.as_bits();
        if self.gap {
            flags |= HELLOOK_GAP;
        }
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
    /// them returns — see `IMPLEMENTATION.md` § 3. Ownership is what the client
    /// needs to stop replaying them; the write cannot be lost afterwards, because
    /// the queue outlives the connection.
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
    OutputAck {
        /// Exclusive upper bound of consumed output.
        consumed_through: u64,
    },
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

impl Frame<'_> {
    /// Returns this frame's discriminant.
    #[must_use]
    pub const fn frame_type(&self) -> FrameType {
        match *self {
            Self::Hello(_) => FrameType::Hello,
            Self::HelloOk(_) => FrameType::HelloOk,
            Self::Input { .. } => FrameType::Input,
            Self::InputAck { .. } => FrameType::InputAck,
            Self::Output { .. } => FrameType::Output,
            Self::OutputAck { .. } => FrameType::OutputAck,
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
    /// for its own length prefix. `out` is left unchanged in either case.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        // Checked before anything is appended, so the caller's buffer is untouched
        // on the error path. Refused rather than truncated: this returns a
        // `Result`, so reporting success while putting something other than what
        // the caller passed on the wire is never the right trade. A `TERM` this
        // long is a broken caller, and silently shortening it would open the
        // session under a terminal type nobody chose.
        if let Self::Hello(hello) = *self
            && u16::try_from(hello.term.len()).is_err()
        {
            return Err(ProtoError::Malformed("TERM exceeds 65535 bytes"));
        }

        let start = out.len();
        out.extend_from_slice(&[0; HEADER_LEN]);
        self.encode_payload(out);

        let header = u32::try_from(out.len() - start - HEADER_LEN)
            .map_err(|_| ProtoError::PayloadTooLarge(u32::MAX))
            .and_then(|len| encode_header(self.frame_type(), len))
            .inspect_err(|_| out.truncate(start))?;
        if let Some(slot) = out.get_mut(start..start + HEADER_LEN) {
            slot.copy_from_slice(&header);
        }
        Ok(())
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Hello(hello) => {
                out.extend_from_slice(&hello.protocol.to_be_bytes());
                out.extend_from_slice(&hello.flags.to_be_bytes());
                out.extend_from_slice(&hello.out_offset.to_be_bytes());
                out.extend_from_slice(&hello.in_offset.to_be_bytes());
                put_win(out, hello.win);
                // `encode` refused anything longer, so this never truncates.
                let term_len = u16::try_from(hello.term.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&term_len.to_be_bytes());
                out.extend_from_slice(hello.term.as_bytes());
            }
            Self::HelloOk(ok) => {
                out.extend_from_slice(&ok.protocol.to_be_bytes());
                out.extend_from_slice(&ok.resume_from.to_be_bytes());
                out.extend_from_slice(&ok.in_applied.to_be_bytes());
                put_win(out, ok.win);
                out.push(ok.flags());
            }
            Self::Input { offset, data } | Self::Output { offset, data } => {
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::InputAck {
                applied_through: value,
            }
            | Self::OutputAck {
                consumed_through: value,
            }
            | Self::Gap {
                new_base_offset: value,
            }
            | Self::Ping { nonce: value }
            | Self::Pong { nonce: value } => out.extend_from_slice(&value.to_be_bytes()),
            Self::Resize(win) => put_win(out, win),
            Self::Exit { status, kind } => {
                out.extend_from_slice(&status.to_be_bytes());
                out.push(kind.as_byte());
            }
            Self::Detach => {}
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
    }
}

impl<'a> Frame<'a> {
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
                let flags = r.u16()?;
                if flags & !HELLO_FLAG_BITS != 0 {
                    return Err(ProtoError::Malformed("undefined Hello flag bits"));
                }
                let out_offset = r.u64()?;
                let in_offset = r.u64()?;
                let win = r.win()?;
                let term_len = usize::from(r.u16()?);
                let term = core::str::from_utf8(r.take(term_len)?)
                    .map_err(|_| ProtoError::Malformed("TERM is not UTF-8"))?;
                Self::Hello(Hello {
                    protocol,
                    flags,
                    out_offset,
                    in_offset,
                    win,
                    term,
                })
            }
            FrameType::HelloOk => {
                let protocol = r.u16()?;
                let resume_from = r.u64()?;
                let in_applied = r.u64()?;
                let win = r.win()?;
                let flags = r.u8()?;
                if flags & !HELLOOK_FLAG_BITS != 0 {
                    return Err(ProtoError::Malformed("undefined HelloOk flag bits"));
                }
                Self::HelloOk(HelloOk {
                    protocol,
                    resume_from,
                    in_applied,
                    win,
                    gap: flags & HELLOOK_GAP != 0,
                    linger: Linger::from_flags(flags)
                        .ok_or(ProtoError::Malformed("unknown linger state"))?,
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
            FrameType::OutputAck => Self::OutputAck {
                consumed_through: r.u64()?,
            },
            FrameType::Resize => Self::Resize(r.win()?),
            FrameType::Gap => Self::Gap {
                new_base_offset: r.u64()?,
            },
            FrameType::Exit => Self::Exit {
                status: r.i32()?,
                kind: ExitKind::from_byte(r.u8()?)
                    .ok_or(ProtoError::Malformed("unknown exit kind"))?,
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
        self.take(N)?.try_into().map_err(|_| ProtoError::Truncated)
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
    fn every_variant_round_trips() {
        round_trip(Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: HELLO_AGENT_FORWARD | HELLO_REPAINT_CTRL_L,
            out_offset: RESUME_FROM_START,
            in_offset: 0,
            win: WIN,
            term: "xterm-256color",
        }));
        round_trip(Frame::HelloOk(HelloOk {
            protocol: PROTOCOL_VERSION,
            resume_from: 4096,
            in_applied: 17,
            win: WIN,
            gap: true,
            linger: Linger::Enabled,
            agent: true,
        }));
        round_trip(Frame::Input {
            offset: 9,
            data: b"ls -l\r",
        });
        round_trip(Frame::InputAck {
            applied_through: 15,
        });
        round_trip(Frame::Output {
            offset: u64::MAX / 2,
            data: b"\x1b[2Jhello",
        });
        round_trip(Frame::OutputAck {
            consumed_through: 1,
        });
        round_trip(Frame::Resize(WIN));
        round_trip(Frame::Gap {
            new_base_offset: 8192,
        });
        round_trip(Frame::Exit {
            status: 130,
            kind: ExitKind::Signalled,
        });
        round_trip(Frame::Exit {
            status: 0,
            kind: ExitKind::Exited,
        });
        round_trip(Frame::Detach);
        round_trip(Frame::Ping { nonce: 42 });
        round_trip(Frame::Pong { nonce: 42 });
        round_trip(Frame::Error {
            code: ErrorCode::Takeover,
            message: "session taken over",
        });
        round_trip(Frame::AgentOpen { chan: 3 });
        round_trip(Frame::AgentData {
            chan: 3,
            data: b"\0\0\0\x01\x0b",
        });
        round_trip(Frame::AgentClose { chan: 3 });
    }

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
        assert!(matches!(
            Frame::decode(FrameType::Exit, &[0, 0, 0, 0, 7]),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Frame::decode(FrameType::Error, &[0xff, 0xff]),
            Err(ProtoError::Malformed(_))
        ));
    }

    /// Every flag combination survives, including the ones the daemon never sends
    /// together — the packing shares one byte, so a bit that leaks between fields
    /// would show up here rather than as a mysterious linger warning in the client.
    #[test]
    fn hello_ok_flags_are_independent() {
        for gap in [false, true] {
            for agent in [false, true] {
                for linger in [Linger::Unknown, Linger::Disabled, Linger::Enabled] {
                    round_trip(Frame::HelloOk(HelloOk {
                        protocol: PROTOCOL_VERSION,
                        resume_from: 1,
                        in_applied: 2,
                        win: WIN,
                        gap,
                        linger,
                        agent,
                    }));
                }
            }
        }
    }

    /// Undefined bits are a bug in a peer built from this repository, not a
    /// forward-compatibility case (`DESIGN.md` § 2), so they are refused rather
    /// than masked off.
    #[test]
    fn undefined_flag_bits_are_rejected() {
        let mut hello = Vec::new();
        Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            in_offset: 0,
            win: WIN,
            term: "",
        })
        .encode(&mut hello)
        .unwrap();
        // `flags` is the second u16 of the payload.
        hello[HEADER_LEN + 3] = 0x80;
        assert!(matches!(
            Frame::decode(FrameType::Hello, &hello[HEADER_LEN..]),
            Err(ProtoError::Malformed(_))
        ));

        let mut ok = Vec::new();
        Frame::HelloOk(HelloOk {
            protocol: PROTOCOL_VERSION,
            resume_from: 0,
            in_applied: 0,
            win: WIN,
            gap: false,
            linger: Linger::Unknown,
            agent: false,
        })
        .encode(&mut ok)
        .unwrap();
        let flags = ok.len() - 1;
        // Reserved bit 4, then the reserved linger encoding 0b11.
        for byte in [0b1_0000, 0b110] {
            ok[flags] = byte;
            assert!(
                matches!(
                    Frame::decode(FrameType::HelloOk, &ok[HEADER_LEN..]),
                    Err(ProtoError::Malformed(_))
                ),
                "flags byte {byte:#b} should be refused"
            );
        }
    }

    #[test]
    fn non_utf8_text_is_rejected() {
        // Hello with term_len 1 and a lone continuation byte.
        let mut payload = vec![0; 2 + 2 + 8 + 8 + 8];
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(0x80);
        assert!(matches!(
            Frame::decode(FrameType::Hello, &payload),
            Err(ProtoError::Malformed(_))
        ));
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
    /// Refused rather than truncated: `encode` reporting success while sending a
    /// different `TERM` than it was handed would open the session under a terminal
    /// type nobody chose, and the caller has no way to notice.
    #[test]
    fn an_unrepresentable_term_is_refused_rather_than_truncated() {
        let long = "x".repeat(usize::from(u16::MAX) + 1);
        let mut buf = b"previous frame".to_vec();
        let before = buf.len();
        let err = Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            in_offset: 0,
            win: WIN,
            term: &long,
        })
        .encode(&mut buf);

        assert!(matches!(err, Err(ProtoError::Malformed(_))), "got {err:?}");
        assert_eq!(buf.len(), before, "the buffer must be left untouched");

        // The longest that still fits is accepted, so the boundary is exact.
        let exact = "x".repeat(usize::from(u16::MAX));
        round_trip(Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            flags: 0,
            out_offset: 0,
            in_offset: 0,
            win: WIN,
            term: &exact,
        }));
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
