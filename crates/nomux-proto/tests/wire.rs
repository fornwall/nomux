//! Byte-exact conformance to the frame table in `IMPLEMENTATION.md` § 2.2.
//!
//! Everything else in this crate's suite tests the codec against *itself*: encode
//! then decode, and assert you got back what you put in. That proves the two halves
//! agree, which is not the same as either being right. Swap `HelloOk`'s
//! `resume_from` and `in_applied` in both directions and every round-trip test still
//! passes — the two fields are the same width, so the frames stay symmetric while
//! the bytes on the wire are wrong. The property tests in `codec.rs` inherit the
//! same blind spot, because they generate frames and compare frames.
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
    ErrorCode, ExitKind, Frame, FrameType, HEADER_LEN, Hello, HelloOk, Linger, MAX_PAYLOAD,
    PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
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
///
/// Byte patterns are ascending and distinct per field so that a swap between two
/// same-width neighbours — the failure a round-trip test cannot see — changes the
/// expected bytes.
///
/// Both handshake frames appear more than once, because distinct values catch a swap
/// between two fields and do nothing about a swap *inside* one. A flag bit or an
/// enumerator exercised at a single value is pinned only against being renumbered
/// wholesale: give `Hello` both of its flags at once and their two bits can trade
/// places without moving a byte. So each repeat is chosen to disagree with the
/// ones before it on every bit and every enumerator that has one — which is what
/// makes § 2.3 a table this file actually checks, rather than one the codec merely
/// agrees with itself about. Each of the two takes three: [`Linger`] has three values
/// and [`every_linger_state_has_a_vector`] insists on all of them, and two `Hello`
/// vectors cannot both show the bits set together and show each of them clear, which
/// [`every_hello_flag_bit_is_pinned_in_both_states`] insists on.
fn vectors() -> Vec<Vector> {
    let mut all = hello_vectors();
    all.extend(hello_ok_vectors());
    all.extend(stream_vectors());
    all.extend(control_vectors());
    all.extend(agent_vectors());
    all
}

/// The client's opening frame, at three different flag words.
fn hello_vectors() -> Vec<Vector> {
    vec![
        // 0x01 Hello: u16 proto, u8 flags, u64 out_offset, winsize, u16 term_len,
        // term bytes. The revision is two bytes and the flags one, so no swap between
        // them is even representable — §2.3's "no reserved space", made in bytes.
        Vector {
            frame: Frame::Hello(Hello {
                protocol: 5,
                agent_forward: true,
                repaint_ctrl_l: true,
                out_offset: 0x0102_0304_0506_0708,
                win: WIN,
                term: "xterm-256color",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x23, // header: type, u24 len = 35
                0x00, 0x05, // protocol
                0x03, // flags: bit 0 agent forward, bit 1 repaint ctrl-l
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // out_offset
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x00, 0x0e, // term_len = 14
                b'x', b't', b'e', b'r', b'm', b'-', b'2', b'5', b'6', b'c', b'o', b'l', b'o', b'r',
            ],
        },
        // 0x01 Hello again, with bit 0 alone, which is what pins *which* bit is
        // which: above, both are set, so exchanging the two leaves 0x03 unchanged.
        // Carries `RESUME_FROM_START` as well, which no other vector shows.
        Vector {
            frame: Frame::Hello(Hello {
                protocol: 5,
                agent_forward: true,
                repaint_ctrl_l: false,
                out_offset: RESUME_FROM_START,
                win: WIN,
                term: "vt100",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                0x00, 0x05, // protocol
                0x01, // flags: bit 0 agent forward, bit 1 clear
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // RESUME_FROM_START
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x00, 0x05, // term_len = 5
                b'v', b't', b'1', b'0', b'0',
            ],
        },
        // 0x01 Hello a third time, with both bits clear. Bit 0 is set in both of the
        // vectors above, so this is the only one that pins it clear.
        Vector {
            frame: Frame::Hello(Hello {
                protocol: 5,
                agent_forward: false,
                repaint_ctrl_l: false,
                out_offset: 0x8182_8384_8586_8788,
                win: WIN,
                term: "dumb",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x19, // header: type, u24 len = 25
                0x00, 0x05, // protocol
                0x00, // flags: both bits clear
                0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, // out_offset
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x00, 0x04, // term_len = 4
                b'd', b'u', b'm', b'b',
            ],
        },
    ]
}

/// The daemon's answer, at all three linger states and both agent states.
fn hello_ok_vectors() -> Vec<Vector> {
    vec![
        // 0x02 HelloOk: u64 resume_from, u64 in_applied, winsize, u8 linger, u8
        // flags. It carries no revision (§ 2.2), and the last two bytes are one byte
        // each, `linger` being a field of its own rather than two bits inside the
        // flags (§ 2.3).
        Vector {
            frame: Frame::HelloOk(HelloOk {
                resume_from: 0x2122_2324_2526_2728,
                in_applied: 0x3132_3334_3536_3738,
                win: WIN,
                linger: Linger::Enabled,
                agent: true,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // resume_from
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // in_applied
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x02, // linger = 2 (enabled)
                0x01, // flags: bit 0 agent
            ],
        },
        // 0x02 HelloOk again, at linger unknown with the agent still served. The two
        // trailing bytes differ from each other in every vector here, which is what
        // pins their order: exchange the pair and each of the three moves.
        Vector {
            frame: Frame::HelloOk(HelloOk {
                resume_from: 0x4142_4344_4546_4748,
                in_applied: 0x5152_5354_5556_5758,
                win: WIN,
                linger: Linger::Unknown,
                agent: true,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // resume_from
                0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, // in_applied
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x00, // linger = 0 (unknown)
                0x01, // flags: bit 0 agent
            ],
        },
        // 0x02 HelloOk a third time, for the one linger value the other two leave
        // out: reading `Disabled` off them as the number left over is a deduction
        // rather than a test. Also the only vector with the agent bit clear.
        Vector {
            frame: Frame::HelloOk(HelloOk {
                resume_from: 0x6162_6364_6566_6768,
                in_applied: 0x7172_7374_7576_7778,
                win: WIN,
                linger: Linger::Disabled,
                agent: false,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, // resume_from
                0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, // in_applied
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                0x01, // linger = 1 (disabled)
                0x00, // flags: agent clear
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
        // 0x06 OutputAck: no payload. What the frame does is arrive (§ 3), so like
        // `Detach` below it is nothing but its header.
        Vector {
            frame: Frame::OutputAck,
            bytes: &[0x06, 0x00, 0x00, 0x00],
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
        // 0x09 Exit: i32 status, u8 kind (0 exited, 1 signalled), u32
        // since_exit_secs. The kind byte sits *between* the two four-byte fields and
        // does not stop them being exchanged, so the pair are given values that
        // disagree in every byte here and are all-ones against all-zeros below —
        // which is the transposition this file exists to catch, at the one place on
        // this wire where two same-width fields are adjacent but for a byte.
        Vector {
            frame: Frame::Exit {
                status: 130,
                kind: ExitKind::Signalled,
                since_exit_secs: 0x0a0b_0c0d,
            },
            bytes: &[
                0x09, 0x00, 0x00, 0x09, //
                0x00, 0x00, 0x00, 0x82, // status
                0x01, // signalled
                0x0a, 0x0b, 0x0c, 0x0d, // since_exit_secs
            ],
        },
        // The only signed field on the wire, so its two's-complement encoding is
        // pinned rather than inferred from the positive case above. Zero seconds is
        // the other value worth writing down: it is what a client watching the exit
        // happen is handed, and the one number that has to mean "now" rather than a
        // session that ended while nobody was there (§ 6.5).
        Vector {
            frame: Frame::Exit {
                status: -1,
                kind: ExitKind::Exited,
                since_exit_secs: 0,
            },
            bytes: &[
                0x09, 0x00, 0x00, 0x09, //
                0xff, 0xff, 0xff, 0xff, // status
                0x00, // exited
                0x00, 0x00, 0x00, 0x00, // since_exit_secs
            ],
        },
        // 0x0a Detach: no payload at all either, so the frame is its header.
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
///
/// Driven from [`FrameType::ALL`], which the discriminant list generates, rather
/// than from a range of bytes written out here: a hand-written `0x01..=0x10` stops
/// covering the protocol the moment the protocol grows, and does it quietly, which
/// is the failure this test exists to prevent.
#[test]
fn every_frame_type_has_a_vector() {
    let covered: Vec<FrameType> = vectors().iter().map(|v| v.frame.frame_type()).collect();
    for ty in FrameType::ALL {
        assert!(covered.contains(&ty), "{ty:?} has no wire vector");
    }
}

/// Every `Exit.kind` has a vector, so both are pinned on bytes rather than one
/// being inferred from the other.
///
/// Swept from [`ExitKind::ALL`] for the reason [`every_frame_type_has_a_vector`]
/// gives: a hand-written list of the kinds to check is a list that stops covering
/// the set the moment the set grows, and does it in silence.
#[test]
fn every_exit_kind_has_a_vector() {
    let covered: Vec<ExitKind> = vectors()
        .iter()
        .filter_map(|v| match v.frame {
            Frame::Exit { kind, .. } => Some(kind),
            _ => None,
        })
        .collect();
    for kind in ExitKind::ALL {
        assert!(covered.contains(&kind), "{kind:?} has no wire vector");
    }
}

/// Every `HelloOk.linger` state has a vector.
///
/// Swept from [`Linger::ALL`], so all three values are written down in bytes: taking
/// one of them on faith as the number the other two leave over is an argument about
/// those vectors rather than a check on this one.
#[test]
fn every_linger_state_has_a_vector() {
    let covered: Vec<Linger> = vectors()
        .iter()
        .filter_map(|v| match v.frame {
            Frame::HelloOk(ok) => Some(ok.linger),
            _ => None,
        })
        .collect();
    for linger in Linger::ALL {
        assert!(covered.contains(&linger), "{linger:?} has no wire vector");
    }
}

/// Every `Hello` flag appears both set and clear across the vectors.
///
/// The sweep the `ALL`-driven ones have, for a closed set with no `ALL` to drive it:
/// a flag exercised at a single value is pinned only against being renumbered
/// wholesale, so an encoder that always asserted its bit would move no byte any
/// other test here compares.
#[test]
fn every_hello_flag_bit_is_pinned_in_both_states() {
    let mut flags = Vec::new();

    for vector in vectors() {
        // Destructured exhaustively for the reason
        // [`every_hello_ok_flag_is_pinned_in_both_states`] gives.
        if let Frame::Hello(Hello {
            protocol: _,
            agent_forward,
            repaint_ctrl_l,
            out_offset: _,
            win: _,
            term: _,
        }) = vector.frame
        {
            flags.push([agent_forward, repaint_ctrl_l]);
        }
    }

    for (bit, name) in [(0, "agent_forward"), (1, "repaint_ctrl_l")] {
        assert!(
            flags.iter().any(|set| set[bit]),
            "no Hello vector sets {name}"
        );
        assert!(
            flags.iter().any(|set| !set[bit]),
            "no Hello vector clears {name}"
        );
    }
}

/// Every `HelloOk` flag appears set and clear across the vectors.
///
/// [`every_hello_flag_bit_is_pinned_in_both_states`] for the other flags byte. The
/// three vectors above do cover both states today and say so in their comments, but
/// prose is not what fails when an edit drops that vector.
///
/// `Linger` is a byte of its own and is covered by
/// [`every_linger_state_has_a_vector`].
#[test]
fn every_hello_ok_flag_is_pinned_in_both_states() {
    let mut agent = Vec::new();

    for vector in vectors() {
        // Destructured exhaustively rather than read field by field, which is what
        // gives this sweep the property the `ALL`-driven ones have for free: a
        // second bool added to the flags byte stops this file compiling until it is
        // swept here too, instead of going quietly unpinned.
        if let Frame::HelloOk(HelloOk {
            resume_from: _,
            in_applied: _,
            win: _,
            linger: _,
            agent: this_agent,
        }) = vector.frame
        {
            agent.push(this_agent);
        }
    }

    assert!(
        agent.iter().any(|set| *set),
        "no HelloOk vector sets the agent flag"
    );
    assert!(
        agent.iter().any(|set| !*set),
        "no HelloOk vector clears the agent flag"
    );
}

/// The revision the `Hello` vectors are written at is the one this build speaks.
///
/// The three of them write it out as a literal, the way everything else in them is
/// written out from § 2.2 — which is what makes them a check on the document rather
/// than on the encoder, and equally what would let them go on passing at a revision
/// the daemon refuses. That refusal is the failure the daemon is built to make loud:
/// it turns away a `Hello` whose `protocol` is not [`PROTOCOL_VERSION`], so a client
/// built from a § 2.2 written at one number, against a daemon speaking another, is
/// stopped at the handshake with every vector here still green.
///
/// `HelloOk` is not swept because it no longer carries a revision: the daemon has
/// already accepted the client's by the time it answers (§ 2.2).
///
/// [`the_frozen_numbers_are_the_ones_the_document_gives`] holds the constant against
/// the document; this holds the literals against the constant. Between them the
/// vectors carry the number the code will accept rather than merely a number.
#[test]
fn the_handshake_vectors_are_written_at_the_revision_this_build_speaks() {
    let mut seen = 0;
    for vector in vectors() {
        let Frame::Hello(hello) = vector.frame else {
            continue;
        };
        seen += 1;
        assert_eq!(
            hello.protocol, PROTOCOL_VERSION,
            "a handshake vector is written at a revision the daemon would refuse: \
             {:?}",
            vector.frame
        );
    }
    assert!(seen > 0, "no Hello vector carries a revision to check");
}

/// The `Error` codes are the numbers § 2.2 gives them.
///
/// A frame carries one code at a time, so the vector above can pin exactly one of
/// the five and a table is the only way to reach the rest. Without it, the daemon
/// and the suite would both name them symbolically and so agree on any renumbering,
/// while only the client — built from § 2.2 — disagreed.
///
/// The numbers are written out by hand because they have to come from the document
/// rather than from the code under test. *Which* codes the table has to carry does
/// not: that is swept from [`ErrorCode::ALL`], so a code added to the protocol and
/// not to this table fails here instead of going quietly unchecked. The two
/// directions are checked separately for the reason the module doc gives:
/// `from_u16(as_u16(c)) == c` holds under any renumbering consistent with itself.
#[test]
fn error_codes_are_the_numbers_the_table_gives_them() {
    let documented: [(ErrorCode, u16); 5] = [
        (ErrorCode::Protocol, 1),
        (ErrorCode::Takeover, 2),
        (ErrorCode::Version, 3),
        (ErrorCode::InputGap, 4),
        (ErrorCode::Internal, 5),
    ];

    for (code, number) in documented {
        assert_eq!(
            code.as_u16(),
            number,
            "{code:?} does not encode to the number IMPLEMENTATION.md § 2.2 gives it"
        );
        assert_eq!(
            ErrorCode::from_u16(number),
            Some(code),
            "{number} does not decode to the code IMPLEMENTATION.md § 2.2 gives it"
        );
    }

    for code in ErrorCode::ALL {
        assert!(
            documented.iter().any(|&(listed, _)| listed == code),
            "{code:?} is on no line of the table IMPLEMENTATION.md § 2.2 gives"
        );
    }
}

/// The `len` field is a big-endian `u24`, checked past its low byte and at the cap.
///
/// Every vector above carries a payload shorter than 256 bytes, so the top two
/// bytes of its length are always zero — and an encoder that computed `len`
/// correctly and then wrote only its low byte would satisfy all sixteen of them.
/// The § 2.1 cap is the other half of the same gap: only a payload at the cap
/// produces a length that reaches the top byte at all, so the largest legal frame is
/// the one case that can show the field is three bytes wide rather than two.
/// [`the_frozen_numbers_are_the_ones_the_document_gives`] is where `MAX_PAYLOAD`
/// itself is held against § 2.1; this is where its encoding is.
///
/// These payloads are built rather than written out, which is why they sit here
/// instead of in the table above. The bytes being asserted are still only the
/// header, and still hand-written from the document.
#[test]
fn the_length_field_is_a_u24_past_its_low_byte() {
    // `Output` is a u64 offset followed by the bytes, so the payload runs 8 longer
    // than the data: 308 == 0x00_01_34 reaches the middle byte, and the largest
    // legal payload is 0x04_00_00, which is the only value that reaches the top one.
    for (data_len, header) in [
        (300_usize, [0x05, 0x00, 0x01, 0x34]),
        (MAX_PAYLOAD as usize - 8, [0x05, 0x04, 0x00, 0x00]),
    ] {
        let data = vec![0xa5; data_len];
        let frame = Frame::Output {
            offset: 0,
            data: &data,
        };

        let mut buf = Vec::new();
        frame
            .encode(&mut buf)
            .expect("a payload at the cap encodes");
        assert_eq!(
            buf[..HEADER_LEN],
            header,
            "a {}-byte payload does not encode the length § 2.1 gives it",
            data_len + 8
        );

        assert_eq!(
            Frame::decode(FrameType::Output, &buf[HEADER_LEN..]),
            Ok(frame),
            "a {}-byte payload does not decode back",
            data_len + 8
        );
    }
}

/// Every frozen number, held against the document rather than against itself.
///
/// One table, because these are the numbers a second implementation reads out of the
/// document rather than out of this crate. Both are already held against a hand-written
/// literal somewhere, and are here for the citation rather than for the arithmetic. The
/// `Hello` vectors write `PROTOCOL_VERSION` out as `5` and
/// [`the_handshake_vectors_are_written_at_the_revision_this_build_speaks`] compares
/// them; the largest legal frame in
/// [`the_length_field_is_a_u24_past_its_low_byte`] encodes its length as the literal
/// `0x04_00_00`. So moving either constant alone already fails. What those two cannot
/// see is the edit that moves the constant *and* the literals together, which is
/// exactly what a revision bump looks like — and which is a change to the wire that
/// § 2.1 and § 2.2 have not been told about.
///
/// It matters because the far end is a separate codebase built from the document. A
/// client whose § 2.2 disagrees is turned away at the handshake; one built from § 2.1
/// sending a legal 256 KiB frame collects `Error{Protocol}`.
///
/// Two rows, because only these two are on the wire. The id length § 6.3 fixes and
/// the channel cap § 6.7 fixes are pinned this same way beside the code that enforces
/// them, by `rundir::tests::the_session_id_bound_is_the_one_the_document_gives` and
/// `agent::tests::the_channel_cap_is_the_one_the_document_gives`.
///
/// The numbers are written out by hand, since they have to come from the document
/// rather than from the code under test, and every row carries the section it was
/// read from — that citation is the whole difference between a failure here and one
/// answered by editing the expectation.
#[test]
fn the_frozen_numbers_are_the_ones_the_document_gives() {
    let documented: [(&str, u64, u64, &str); 2] = [
        (
            "PROTOCOL_VERSION",
            u64::from(PROTOCOL_VERSION),
            5,
            "§ 2.2 puts the current revision at 5",
        ),
        (
            "MAX_PAYLOAD",
            u64::from(MAX_PAYLOAD),
            262_144,
            "§ 2.1 caps a payload at 256 KiB",
        ),
    ];

    for (name, held, expected, section) in documented {
        assert_eq!(
            held, expected,
            "{name} is {held}, and IMPLEMENTATION.md {section}"
        );
    }
}
