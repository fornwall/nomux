//! Byte-exact conformance to the frame table in `IMPLEMENTATION.md` § 2.2.
//!
//! Everything else in this crate's suite tests the codec against *itself*: encode
//! then decode, and assert you got back what you put in. That proves the two halves
//! agree, which is not the same as either being right. Swap `Hello`'s `out_offset`
//! and `in_offset` in both directions and every round-trip test still passes — the
//! two fields are the same width, so the frames stay symmetric while the bytes on
//! the wire are wrong. The property tests in `codec.rs` inherit the same blind spot,
//! because they generate frames and compare frames.
//!
//! So these vectors are written out by hand from the § 2.2 table rather than
//! produced by the encoder, and are checked in *both* directions. They are the only
//! thing in the repository that would notice a field order, field width or
//! endianness change, and the only reason the client — a separate codebase reading
//! the same table — can be built against the document instead of against this code.
//!
//! A failure here is either a deliberate wire change, which is a
//! `PROTOCOL_VERSION` bump and an edit to § 2.2, or a bug. It is never a test that
//! needs relaxing.

use nomux_proto::{
    ErrorCode, ExitKind, Frame, FrameType, HEADER_LEN, HELLO_AGENT_FORWARD, HELLO_REPAINT_CTRL_L,
    Hello, HelloOk, Linger, WinSize,
};

/// Distinct in all four fields on purpose: `cols`, `rows`, `xpixel` and `ypixel`
/// share a layout and a width, so equal values would hide a transposition.
const WIN: WinSize = WinSize {
    cols: 120,
    rows: 40,
    xpixel: 960,
    ypixel: 640,
};

/// One frame and the exact bytes § 2.2 says it is.
struct Vector {
    frame: Frame<'static>,
    bytes: &'static [u8],
}

/// Every vector, in discriminant order.
///
/// Split into groups only to keep each list readable; the tests below and
/// [`every_frame_type_has_a_vector`] treat them as one table.
fn vectors() -> Vec<Vector> {
    let mut all = handshake_vectors();
    all.extend(stream_vectors());
    all.extend(control_vectors());
    all.extend(agent_vectors());
    all
}

/// Byte patterns are ascending and distinct per field so that a swap between two
/// same-width neighbours — the failure a round-trip test cannot see — changes the
/// expected bytes.
fn handshake_vectors() -> Vec<Vector> {
    vec![
        // 0x01 Hello: u16 proto, u16 flags, u64 out_offset, u64 in_offset,
        // winsize, u16 term_len, term bytes.
        Vector {
            frame: Frame::Hello(Hello {
                protocol: 2,
                flags: HELLO_AGENT_FORWARD | HELLO_REPAINT_CTRL_L,
                out_offset: 0x0102_0304_0506_0708,
                in_offset: 0x1112_1314_1516_1718,
                win: WIN,
                term: "xterm-256color",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x2c, // header: type, u24 len = 44
                0x00, 0x02, // protocol
                0x00, 0x03, // flags: bit 0 agent forward, bit 1 repaint ctrl-l
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // out_offset
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // in_offset
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x00, 0x0e, // term_len = 14
                b'x', b't', b'e', b'r', b'm', b'-', b'2', b'5', b'6', b'c', b'o', b'l', b'o', b'r',
            ],
        },
        // 0x02 HelloOk: u16 proto, u64 resume_from, u64 in_applied, winsize,
        // u8 flags. Note the flags field is a u8 here and a u16 in Hello — the
        // two handshake frames are deliberately not the same shape. Its 0x0d is
        // bit 0 gap, bits 1-2 linger = 2 (enabled), bit 3 agent (§ 2.3).
        Vector {
            frame: Frame::HelloOk(HelloOk {
                protocol: 2,
                resume_from: 0x2122_2324_2526_2728,
                in_applied: 0x3132_3334_3536_3738,
                win: WIN,
                gap: true,
                linger: Linger::Enabled,
                agent: true,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x1b, // header: type, u24 len = 27
                0x00, 0x02, // protocol
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // resume_from
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // in_applied
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x0d, // flags
            ],
        },
    ]
}

/// The two byte streams and their acknowledgements, plus the frames that describe
/// the shape of the terminal carrying them.
fn stream_vectors() -> Vec<Vector> {
    vec![
        // 0x03 Input: u64 offset, bytes.
        Vector {
            frame: Frame::Input {
                offset: 9,
                data: b"ls -l\r",
            },
            bytes: &[
                0x03, 0x00, 0x00, 0x0e, // header: len = 8 + 6
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, // offset
                b'l', b's', b' ', b'-', b'l', b'\r',
            ],
        },
        // 0x04 InputAck: u64 applied_through.
        Vector {
            frame: Frame::InputAck {
                applied_through: 15,
            },
            bytes: &[
                0x04, 0x00, 0x00, 0x08, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
            ],
        },
        // 0x05 Output: u64 offset, bytes. Same shape as Input, different type byte.
        Vector {
            frame: Frame::Output {
                offset: 0x4142_4344_4546_4748,
                data: b"\x1b[2J",
            },
            bytes: &[
                0x05, 0x00, 0x00, 0x0c, // header: len = 8 + 4
                0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // offset
                0x1b, 0x5b, 0x32, 0x4a,
            ],
        },
        // 0x06 OutputAck: u64 consumed_through.
        Vector {
            frame: Frame::OutputAck {
                consumed_through: 1,
            },
            bytes: &[
                0x06, 0x00, 0x00, 0x08, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ],
        },
        // 0x07 Resize: winsize, bare.
        Vector {
            frame: Frame::Resize(WIN),
            bytes: &[
                0x07, 0x00, 0x00, 0x08, //
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80,
            ],
        },
        // 0x08 Gap: u64 new_base_offset.
        Vector {
            frame: Frame::Gap {
                new_base_offset: 8192,
            },
            bytes: &[
                0x08, 0x00, 0x00, 0x08, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
            ],
        },
    ]
}

/// Session lifecycle and liveness.
fn control_vectors() -> Vec<Vector> {
    vec![
        // 0x09 Exit: i32 status, u8 kind (0 exited, 1 signalled).
        Vector {
            frame: Frame::Exit {
                status: 130,
                kind: ExitKind::Signalled,
            },
            bytes: &[
                0x09, 0x00, 0x00, 0x05, //
                0x00, 0x00, 0x00, 0x82, // status
                0x01, // signalled
            ],
        },
        // The only signed field on the wire, so its two's-complement encoding is
        // pinned rather than inferred from the positive case above.
        Vector {
            frame: Frame::Exit {
                status: -1,
                kind: ExitKind::Exited,
            },
            bytes: &[
                0x09, 0x00, 0x00, 0x05, //
                0xff, 0xff, 0xff, 0xff, // status
                0x00, // exited
            ],
        },
        // 0x0a Detach: no payload at all, so the frame is its header.
        Vector {
            frame: Frame::Detach,
            bytes: &[0x0a, 0x00, 0x00, 0x00],
        },
        // 0x0b Ping / 0x0c Pong: u64 nonce, echoed back unchanged.
        Vector {
            frame: Frame::Ping { nonce: 42 },
            bytes: &[
                0x0b, 0x00, 0x00, 0x08, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a,
            ],
        },
        Vector {
            frame: Frame::Pong { nonce: 42 },
            bytes: &[
                0x0c, 0x00, 0x00, 0x08, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a,
            ],
        },
        // 0x0d Error: u16 code, UTF-8 message with no length prefix — it runs to
        // the end of the payload.
        Vector {
            frame: Frame::Error {
                code: ErrorCode::Takeover,
                message: "taken over",
            },
            bytes: &[
                0x0d, 0x00, 0x00, 0x0c, // header: len = 2 + 10
                0x00, 0x02, // Takeover
                b't', b'a', b'k', b'e', b'n', b' ', b'o', b'v', b'e', b'r',
            ],
        },
    ]
}

/// The agent sub-channels of § 6.7, the one place this protocol multiplexes.
fn agent_vectors() -> Vec<Vector> {
    vec![
        // 0x0e AgentOpen: u32 chan. Four bytes, not eight — the one place an id
        // on this wire is not a u64.
        Vector {
            frame: Frame::AgentOpen { chan: 3 },
            bytes: &[0x0e, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03],
        },
        // 0x0f AgentData: u32 chan, opaque bytes. The payload here is a real
        // `ssh-agent` request — length 1, type 11 (REQUEST_IDENTITIES) — to make
        // the point that the daemon never parses it.
        Vector {
            frame: Frame::AgentData {
                chan: 3,
                data: b"\x00\x00\x00\x01\x0b",
            },
            bytes: &[
                0x0f, 0x00, 0x00, 0x09, // header: len = 4 + 5
                0x00, 0x00, 0x00, 0x03, // chan
                0x00, 0x00, 0x00, 0x01, 0x0b,
            ],
        },
        // 0x10 AgentClose: u32 chan.
        Vector {
            frame: Frame::AgentClose { chan: 3 },
            bytes: &[0x10, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03],
        },
    ]
}

/// The encoder emits exactly the bytes § 2.2 specifies.
#[test]
fn frames_encode_to_their_documented_bytes() {
    for Vector { frame, bytes } in vectors() {
        let mut encoded = Vec::new();
        frame.encode(&mut encoded).unwrap();
        assert_eq!(
            encoded,
            bytes,
            "{:?} does not encode to the bytes IMPLEMENTATION.md § 2.2 specifies",
            frame.frame_type()
        );
    }
}

/// And the decoder reads those same bytes back as the frame they describe.
///
/// Separate from the encode direction rather than folded into it: a single
/// assertion that `decode(encode(f)) == f` is exactly the self-consistency check
/// this file exists to supplement.
#[test]
fn documented_bytes_decode_to_their_frames() {
    for Vector { frame, bytes } in vectors() {
        let (header, payload) = bytes.split_at(HEADER_LEN);
        let header: [u8; HEADER_LEN] = header.try_into().unwrap();
        let header = nomux_proto::decode_header(&header).unwrap();

        assert_eq!(header.ty, frame.frame_type(), "type byte");
        assert_eq!(
            header.len as usize,
            payload.len(),
            "declared length disagrees with the payload that follows it"
        );
        assert_eq!(Frame::decode(header.ty, payload).unwrap(), frame);
    }
}

/// Every frame type has a vector, so a new one cannot be added without writing
/// down what it looks like on the wire.
#[test]
fn every_frame_type_has_a_vector() {
    let covered: Vec<FrameType> = vectors().iter().map(|v| v.frame.frame_type()).collect();
    for byte in 0x01..=0x10 {
        let ty = FrameType::from_byte(byte).expect("0x01..=0x10 are the defined discriminants");
        assert!(covered.contains(&ty), "{ty:?} has no wire vector");
    }
}
