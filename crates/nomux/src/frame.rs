//! Frame payloads and their codec.
//!
//! Decoding borrows byte and string fields from the payload it is handed, so nothing
//! here allocates. It is not copy-free, and the PTY path is the copying one: `encode`
//! appends the payload to the caller's buffer, every output byte copied once, which is
//! what lets a queued `Frame::Output` outlive the ring slot it was read from. `conn.rs`
//! has the copy the other direction makes.

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
/// retained" (`IMPLEMENTATION.md` § 2.2).
pub const RESUME_FROM_START: u64 = u64::MAX;

/// Wire bit for [`Hello::agent_forward`] (`IMPLEMENTATION.md` § 2.3).
///
/// Never set silently: it bypasses the user's `ForwardAgent` decision
/// (`DESIGN.md` § 5.4).
pub const HELLO_AGENT_FORWARD: u8 = 1 << 0;

/// Wire bit for [`Hello::repaint_ctrl_l`] (`IMPLEMENTATION.md` § 2.3).
pub const HELLO_REPAINT_CTRL_L: u8 = 1 << 1;

/// Bits defined in `Hello`'s flags byte. Anything else set is a protocol error.
const HELLO_FLAG_BITS: u8 = HELLO_AGENT_FORWARD | HELLO_REPAINT_CTRL_L;

/// Refuses a [`Hello::term`] carrying an interior NUL, on the way *out* as well as in,
/// for the reason `IMPLEMENTATION.md` § 2.2 gives.
fn checked_term(term: &str) -> Result<(), ProtoError> {
    if term.as_bytes().contains(&0) {
        return Err(ProtoError::Malformed("TERM contains a NUL byte"));
    }
    Ok(())
}

/// Opening frame: what the client already has, and how big its terminal is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello<'a> {
    /// Must equal [`crate::PROTOCOL_VERSION`] or the daemon rejects the connection,
    /// there being no negotiation (`DESIGN.md` § 6.4). The only revision on the wire,
    /// for the reason `IMPLEMENTATION.md` § 2 gives.
    pub protocol: u16,
    /// Whether to serve an `ssh-agent` socket ([`HELLO_AGENT_FORWARD`]). Honoured only
    /// on the `Hello` that creates the session; ignored when resuming one.
    pub agent_forward: bool,
    /// Whether to repaint after a gap with `Ctrl-L` rather than a `SIGWINCH` pair
    /// ([`HELLO_REPAINT_CTRL_L`]).
    pub repaint_ctrl_l: bool,
    /// Next output byte the client wants, or [`RESUME_FROM_START`].
    pub out_offset: u64,
    /// Terminal dimensions.
    pub win: WinSize,
    /// Value for the child's `TERM`. Ignored when resuming an existing session.
    pub term: &'a str,
}

impl Hello<'_> {
    /// Packs the boolean fields into the wire flags byte.
    const fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.agent_forward {
            flags |= HELLO_AGENT_FORWARD;
        }
        if self.repaint_ctrl_l {
            flags |= HELLO_REPAINT_CTRL_L;
        }
        flags
    }
}

wire_enum! {
    /// Whether the daemon's session outlives the user's last logout.
    ///
    /// Reported rather than worked around, and a byte of [`HelloOk`] in its own right
    /// rather than bits inside its flags (`IMPLEMENTATION.md` § 6.2, § 2.3).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    Linger: u8, as_byte / from_byte,
    /// Not determined: no `systemd`, or its state is unreadable. Do not warn —
    /// on a host without `logind` there is nothing to warn about.
    Unknown = 0,
    /// `logind` is running and lingering is off for this user. The session dies at
    /// logout if the host also sets `KillUserProcesses=yes`.
    Disabled = 1,
    /// Lingering is on; the session survives logout.
    Enabled = 2,
}

/// The only bit defined in [`HelloOk`]'s flags byte: this session is serving an agent
/// socket. Anything else set is a protocol error.
const HELLOOK_AGENT: u8 = 1 << 0;

/// Daemon's answer to [`Hello`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloOk {
    /// Offset the daemon will start streaming output from.
    pub resume_from: u64,
    /// Authoritative input offset; the client fast-forwards to this.
    pub in_applied: u64,
    /// Whether this session survives the user's logout.
    pub linger: Linger,
    /// Whether an agent socket is being served, so the client knows to expect
    /// [`Frame::AgentOpen`]. False when it was not asked for, and equally when the
    /// socket could not be bound.
    pub agent: bool,
}

impl HelloOk {
    /// Whether output was dropped before [`HelloOk::resume_from`], leaving the stream
    /// discontinuous for a client that asked to resume at `out_offset`.
    ///
    /// Derived rather than carried on the wire, for the reason `IMPLEMENTATION.md`
    /// § 4.2 gives.
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
    /// Sent once the bytes are queued for the PTY master rather than once `write(2)`
    /// returns: what stops the client replaying them is ownership rather than
    /// durability (`IMPLEMENTATION.md` § 3).
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
        /// Whole seconds since the child let go of the terminal, saturating
        /// (`IMPLEMENTATION.md` § 2.2). Elapsed against a monotonic clock rather than
        /// a wall-clock stamp the two ends would have to agree on, and carried here
        /// rather than on [`HelloOk`], which goes out on every attach of every session
        /// while this means anything only once the child has gone.
        since_exit_secs: u32,
    },
    /// Client is leaving without ending the session.
    Detach,
    /// Liveness probe.
    Ping,
    /// Liveness response. Carries nothing: the stream is ordered, so the *n*th `Pong`
    /// can only answer the *n*th [`Frame::Ping`].
    Pong,
    /// Daemon-side failure; the connection closes after this.
    Error {
        /// Machine-readable reason.
        code: ErrorCode,
        /// Human-readable detail.
        message: &'a str,
    },
    /// A process connected to the session's agent socket, and the client is to open one
    /// of its own to the real agent.
    AgentOpen {
        /// Names this incarnation of the one slot. Local peers are accepted out of band
        /// from the client's stream, so the connections that hold it in turn are
        /// otherwise indistinguishable — one at a time in *space* only
        /// (`IMPLEMENTATION.md` § 6.7).
        generation: u32,
    },
    /// Opaque `ssh-agent` bytes for the connection being served.
    AgentData {
        /// The channel these are for. The daemon drops what names one it no longer
        /// holds, rather than writing a dead peer's bytes into its successor.
        generation: u32,
        /// Bytes, never parsed by the daemon.
        data: &'a [u8],
    },
    /// The served connection is finished.
    AgentClose {
        /// The channel being closed, on the same terms as [`Frame::AgentData`]: a
        /// client's close for a peer that has already gone must not take the next one.
        generation: u32,
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
            Self::Resize(_) => FrameType::Resize,
            Self::Gap { .. } => FrameType::Gap,
            Self::Exit { .. } => FrameType::Exit,
            Self::Detach => FrameType::Detach,
            Self::Ping => FrameType::Ping,
            Self::Pong => FrameType::Pong,
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
    /// [`crate::MAX_PAYLOAD`], or [`ProtoError::Malformed`] for a field too long for
    /// its own length prefix. `out` is rewound to its original length in every case.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        // The payload goes straight into the caller's buffer and the header is patched
        // in behind it, so the rewind lives here, once, rather than on each error path
        // inside: a caller appending frames back to back never ships half of one,
        // whatever `encode_from` grows a new way to fail on.
        let start = out.len();
        self.encode_from(start, out)
            .inspect_err(|_| out.truncate(start))
    }

    /// Appends the frame, `start` being `out`'s length on entry. Free to leave a partial
    /// frame behind on failure: [`Frame::encode`] rewinds to `start`.
    fn encode_from(&self, start: usize, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        out.extend_from_slice(&[0; HEADER_LEN]);
        self.encode_payload(out)?;

        let header = u32::try_from(out.len() - start - HEADER_LEN)
            .map_err(|_| ProtoError::PayloadTooLarge(u32::MAX))
            .and_then(|len| encode_header(self.frame_type(), len))?;
        // Unreachable after the `extend_from_slice`; fallible for `indexing_slicing`.
        let Some(slot) = out
            .get_mut(start..)
            .and_then(<[u8]>::first_chunk_mut::<HEADER_LEN>)
        else {
            return Err(ProtoError::Malformed("the header slot went missing"));
        };
        *slot = header;
        Ok(())
    }

    fn encode_payload(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        match *self {
            Self::Hello(hello) => {
                // Refused rather than truncated, per `IMPLEMENTATION.md` § 2.2.
                let term_len = u16::try_from(hello.term.len())
                    .map_err(|_| ProtoError::Malformed("TERM exceeds 65535 bytes"))?;
                checked_term(hello.term)?;

                out.extend_from_slice(&hello.protocol.to_be_bytes());
                out.push(hello.flags());
                out.extend_from_slice(&hello.out_offset.to_be_bytes());
                put_win(out, hello.win);
                out.extend_from_slice(&term_len.to_be_bytes());
                out.extend_from_slice(hello.term.as_bytes());
            }
            Self::HelloOk(ok) => {
                out.extend_from_slice(&ok.resume_from.to_be_bytes());
                out.extend_from_slice(&ok.in_applied.to_be_bytes());
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
            } => out.extend_from_slice(&value.to_be_bytes()),
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
            Self::Detach | Self::Ping | Self::Pong => {}
            Self::Error { code, message } => {
                out.extend_from_slice(&code.as_u16().to_be_bytes());
                out.extend_from_slice(message.as_bytes());
            }
            Self::AgentOpen { generation } | Self::AgentClose { generation } => {
                out.extend_from_slice(&generation.to_be_bytes());
            }
            Self::AgentData { generation, data } => {
                out.extend_from_slice(&generation.to_be_bytes());
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
        // The daemon reaches this only through `decode_header`, which has already
        // applied the bound. Restated because `decode` is public and the suite calls
        // it on its own: without it a frame could decode that `encode` would refuse.
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        if len > crate::MAX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge(len));
        }

        let mut r = Reader::new(payload);
        let frame = match ty {
            FrameType::Hello => {
                let protocol = r.u16()?;
                let flags = r.u8()?;
                if flags & !HELLO_FLAG_BITS != 0 {
                    return Err(ProtoError::Malformed("undefined Hello flag bits"));
                }
                let out_offset = r.u64()?;
                let win = r.win()?;
                let term_len = usize::from(r.u16()?);
                let term = core::str::from_utf8(r.take(term_len)?)
                    .map_err(|_| ProtoError::Malformed("TERM is not UTF-8"))?;
                checked_term(term)?;
                Self::Hello(Hello {
                    protocol,
                    agent_forward: flags & HELLO_AGENT_FORWARD != 0,
                    repaint_ctrl_l: flags & HELLO_REPAINT_CTRL_L != 0,
                    out_offset,
                    win,
                    term,
                })
            }
            FrameType::HelloOk => {
                let resume_from = r.u64()?;
                let in_applied = r.u64()?;
                let linger = Linger::from_byte(r.u8()?)
                    .ok_or(ProtoError::Malformed("unknown linger state"))?;
                let flags = r.u8()?;
                if flags & !HELLOOK_AGENT != 0 {
                    return Err(ProtoError::Malformed("undefined HelloOk flag bits"));
                }
                Self::HelloOk(HelloOk {
                    resume_from,
                    in_applied,
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
            FrameType::Ping => Self::Ping,
            FrameType::Pong => Self::Pong,
            FrameType::Error => Self::Error {
                code: ErrorCode::from_u16(r.u16()?)
                    .ok_or(ProtoError::Malformed("unknown error code"))?,
                message: core::str::from_utf8(r.rest())
                    .map_err(|_| ProtoError::Malformed("error message is not UTF-8"))?,
            },
            FrameType::AgentOpen => Self::AgentOpen {
                generation: r.u32()?,
            },
            FrameType::AgentClose => Self::AgentClose {
                generation: r.u32()?,
            },
            FrameType::AgentData => Self::AgentData {
                generation: r.u32()?,
                data: r.rest(),
            },
        };

        // Every fixed-size frame must have consumed its payload exactly; the
        // variable-length ones end in `rest()`, which empties the reader.
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
            Frame::decode(FrameType::InputAck, &[0, 0, 0]),
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
            Frame::decode(FrameType::InputAck, &[0, 0, 0, 0, 0, 0, 0, 0, 9]),
            Err(ProtoError::TrailingBytes)
        );
        // `Ping` carries nothing, so any payload at all is trailing.
        assert_eq!(
            Frame::decode(FrameType::Ping, &[0]),
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

    #[test]
    fn undefined_flag_bits_are_rejected() {
        let mut hello = Vec::new();
        Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            agent_forward: false,
            repaint_ctrl_l: false,
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

    /// § 4.2's `gap = resume_from > out_offset`, at the one offset where the sentinel
    /// and a real position collide, and either side of an ordinary edge.
    #[test]
    fn the_derived_gap_is_the_comparison_section_4_2_makes() {
        let gap = |resume_from, out_offset| {
            HelloOk {
                resume_from,
                in_applied: 0,
                linger: Linger::Unknown,
                agent: false,
            }
            .gap(out_offset)
        };
        // `RESUME_FROM_START` *is* `u64::MAX`, so a ring based at the top of the offset
        // space answers the sentinel and a client genuinely there with one number.
        // § 4.2 calls both no-gap, which is what makes the collision harmless.
        assert!(!gap(u64::MAX, RESUME_FROM_START), "the sentinel is no gap");
        assert!(gap(16, 8), "output dropped before the client is a gap");
        assert!(!gap(8, 16), "a resume_from clamped down is no gap");
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

        // The other text field, which earns a diagnosis of its own: `Error` with a
        // valid code and a lone continuation byte for a message.
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
            agent_forward: false,
            repaint_ctrl_l: false,
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
            agent_forward: false,
            repaint_ctrl_l: false,
            out_offset: 0,
            win: WIN,
            term: &exact,
        }));
    }

    /// The decode direction is the one that matters: the daemon hands `term`
    /// straight to the child's environment, where `execve` refuses it.
    #[test]
    fn a_nul_in_term_is_refused_at_both_ends() {
        let mut buf = b"previous frame".to_vec();
        let before = buf.len();
        let err = Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            agent_forward: false,
            repaint_ctrl_l: false,
            out_offset: 0,
            win: WIN,
            term: "xt\0rm",
        })
        .encode(&mut buf);

        assert_eq!(err, Err(ProtoError::Malformed("TERM contains a NUL byte")));
        assert_eq!(buf.len(), before, "the buffer must be left untouched");

        // Built by encoding a well-formed `Hello` and overwriting one byte of its
        // `TERM`, so this does not restate the layout `wire.rs` pins.
        let mut wire = Vec::new();
        Frame::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            agent_forward: false,
            repaint_ctrl_l: false,
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
