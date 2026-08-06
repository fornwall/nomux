//! Byte-exact conformance to the frame table in `IMPLEMENTATION.md` § 2.2.
//!
//! Everything else in this crate's suite tests the codec against *itself*: encode then
//! decode, and assert you got back what you put in. That proves the two halves agree,
//! not that either is right. Swap `HelloOk`'s `resume_from` and `in_applied` in both
//! directions and every round-trip test still passes — same width, so the frames stay
//! symmetric while the bytes on the wire are wrong. `codec.rs` inherits that blind
//! spot, because it generates frames and compares frames.
//!
//! So these vectors are written out by hand from the § 2.2 table rather than produced
//! by the encoder, and are checked in *both* directions. They are the only thing in the
//! repository that would notice a field order, field width or endianness change, and
//! the only reason the client — a separate codebase reading the same table — can be
//! built against the document instead of against this code.
//!
//! A failure here is either a deliberate wire change, which is a
//! `PROTOCOL_VERSION` bump and an edit to § 2.2, or a bug. It is never a test that
//! needs relaxing.
//!
//! The same table is written out beside this file as `wire-vectors.txt`, in a form an
//! implementation in another language reads without parsing Rust;
//! [`the_hex_fixture_carries_the_same_table`] renders these vectors and holds that file
//! to the rendering, so neither can move alone.

use nomux_proto::{
    ErrorCode, ExitKind, Frame, FrameType, HEADER_LEN, Hello, HelloOk, Linger, MAX_PAYLOAD,
    PROTOCOL_VERSION, RESUME_FROM_START, WinSize,
};

/// The language-neutral copy of the table below, compiled in rather than read: a test
/// holding a file it cannot open is a test that cannot quietly rewrite it.
const FIXTURE: &str = include_str!("wire-vectors.txt");

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

/// Every vector, in discriminant order. Split into groups only to keep each list
/// readable; the tests below treat them as one table.
///
/// Byte patterns are ascending and distinct per field, so that a swap between two
/// same-width neighbours — the failure a round-trip test cannot see — changes the
/// expected bytes.
///
/// Both handshake frames appear three times, because distinct values catch a swap
/// between two fields and do nothing about a swap *inside* one: each repeat disagrees
/// with the ones before it on every bit and every enumerator that has one. Three is
/// what [`the_vectors_pin_every_value_of_every_closed_set`] insists on — [`Linger`] has
/// three values, and two `Hello` vectors cannot both show the flag bits set together
/// and show each of them clear.
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
                protocol: 7,
                agent_forward: true,
                repaint_ctrl_l: true,
                out_offset: 0x0102_0304_0506_0708,
                win: WIN,
                term: "xterm-256color",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x23, // header: type, u24 len = 35
                0x00, 0x07, // protocol
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
                protocol: 7,
                agent_forward: true,
                repaint_ctrl_l: false,
                out_offset: RESUME_FROM_START,
                win: WIN,
                term: "vt100",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                0x00, 0x07, // protocol
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
                protocol: 7,
                agent_forward: false,
                repaint_ctrl_l: false,
                out_offset: 0x8182_8384_8586_8788,
                win: WIN,
                term: "dumb",
            }),
            bytes: &[
                0x01, 0x00, 0x00, 0x19, // header: type, u24 len = 25
                0x00, 0x07, // protocol
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
        // 0x02 HelloOk: u64 resume_from, u64 in_applied, u8 linger, u8 flags. It
        // carries neither a revision nor a winsize (§ 2.2) — both would only repeat
        // what the client just sent — and the last two bytes are one byte each,
        // `linger` being a field of its own rather than two bits inside the flags
        // (§ 2.3).
        Vector {
            frame: Frame::HelloOk(HelloOk {
                resume_from: 0x2122_2324_2526_2728,
                in_applied: 0x3132_3334_3536_3738,
                linger: Linger::Enabled,
                agent: true,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x12, // header: type, u24 len = 18
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // resume_from
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // in_applied
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
                linger: Linger::Unknown,
                agent: true,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x12, // header: type, u24 len = 18
                0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // resume_from
                0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, // in_applied
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
                linger: Linger::Disabled,
                agent: false,
            }),
            bytes: &[
                0x02, 0x00, 0x00, 0x12, // header: type, u24 len = 18
                0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, // resume_from
                0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, // in_applied
                0x01, // linger = 1 (disabled)
                0x00, // flags: agent clear
            ],
        },
    ]
}

/// The two byte streams and the acknowledgement one of them carries, plus the frames
/// that describe the shape of the terminal carrying them.
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
        // 0x06 Resize: winsize, bare.
        Vector {
            frame: Frame::Resize(WIN),
            bytes: &[
                0x06, 0x00, 0x00, 0x08, //
                0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80,
            ],
        },
        // 0x07 Gap: u64 new_base_offset.
        Vector {
            frame: Frame::Gap {
                new_base_offset: 8192,
            },
            bytes: &[
                0x07, 0x00, 0x00, 0x08, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
            ],
        },
    ]
}

/// Session lifecycle and liveness.
fn control_vectors() -> Vec<Vector> {
    vec![
        // 0x08 Exit: i32 status, u8 kind (0 exited, 1 signalled), u32
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
                0x08, 0x00, 0x00, 0x09, //
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
                0x08, 0x00, 0x00, 0x09, //
                0xff, 0xff, 0xff, 0xff, // status
                0x00, // exited
                0x00, 0x00, 0x00, 0x00, // since_exit_secs
            ],
        },
        // 0x09 Detach: no payload at all, so the frame is nothing but its header.
        Vector {
            frame: Frame::Detach,
            bytes: &[0x09, 0x00, 0x00, 0x00],
        },
        // 0x0a Ping / 0x0b Pong: header only. The stream is ordered, so the nth Pong
        // answers the nth Ping and there is nothing to correlate them with.
        Vector {
            frame: Frame::Ping,
            bytes: &[0x0a, 0x00, 0x00, 0x00],
        },
        Vector {
            frame: Frame::Pong,
            bytes: &[0x0b, 0x00, 0x00, 0x00],
        },
        // 0x0c Error: u16 code, UTF-8 message with no length prefix — it runs to
        // the end of the payload.
        Vector {
            frame: Frame::Error {
                code: ErrorCode::Takeover,
                message: "taken over",
            },
            bytes: &[
                0x0c, 0x00, 0x00, 0x0c, // header: len = 2 + 10
                0x00, 0x02, // Takeover
                b't', b'a', b'k', b'e', b'n', b' ', b'o', b'v', b'e', b'r',
            ],
        },
    ]
}

/// The single serialized agent pipe of § 6.7.
fn agent_vectors() -> Vec<Vector> {
    vec![
        // 0x0d AgentOpen: header only. One connection is served at a time, so there is
        // nothing to name, and the frame is the boundary rather than an address.
        Vector {
            frame: Frame::AgentOpen,
            bytes: &[0x0d, 0x00, 0x00, 0x00],
        },
        // 0x0e AgentData: opaque bytes, the whole payload. What is written here is a
        // real `ssh-agent` request — length 1, type 11 (REQUEST_IDENTITIES) — to make
        // the point that the daemon never parses it.
        Vector {
            frame: Frame::AgentData {
                data: b"\x00\x00\x00\x01\x0b",
            },
            bytes: &[
                0x0e, 0x00, 0x00, 0x05, // header: len = 5
                0x00, 0x00, 0x00, 0x01, 0x0b,
            ],
        },
        // 0x0f AgentClose: header only, like the open it answers.
        Vector {
            frame: Frame::AgentClose,
            bytes: &[0x0f, 0x00, 0x00, 0x00],
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

/// A byte string as the fixture writes one.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    // `'?'` is unreachable, a nibble being a base-16 digit by construction; it stands in
    // for an `unwrap` the lint wall refuses outside a `#[test]`.
    out.extend(
        bytes
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('?')),
    );
    out
}

/// The four fields of a winsize, destructured so that a fifth would not be dropped
/// silently from the fixture.
fn win_lines(win: WinSize) -> [String; 4] {
    let WinSize {
        cols,
        rows,
        xpixel,
        ypixel,
    } = win;
    [
        format!("cols {cols:#06x}"),
        format!("rows {rows:#06x}"),
        format!("xpixel {xpixel:#06x}"),
        format!("ypixel {ypixel:#06x}"),
    ]
}

/// One vector as `wire-vectors.txt` writes it.
///
/// The values are the frame's, not the wire's: booleans where § 2.3 has flag bits, a
/// name where the wire has a discriminant, no `term_len` an encoder can count for
/// itself. Rendering the wire form instead would make each record a restatement of its
/// own `bytes`, which is the one thing a reader must not be handed.
fn record(vector: &Vector) -> String {
    let &Vector { frame, bytes } = vector;
    let mut lines = vec![format!("frame {:?}", frame.frame_type())];
    match frame {
        Frame::Hello(Hello {
            protocol,
            agent_forward,
            repaint_ctrl_l,
            out_offset,
            win,
            term,
        }) => {
            lines.push(format!("protocol {protocol:#06x}"));
            lines.push(format!("agent_forward {agent_forward}"));
            lines.push(format!("repaint_ctrl_l {repaint_ctrl_l}"));
            lines.push(format!("out_offset {out_offset:#018x}"));
            lines.extend(win_lines(win));
            lines.push(format!("term {}", hex(term.as_bytes())));
        }
        Frame::HelloOk(HelloOk {
            resume_from,
            in_applied,
            linger,
            agent,
        }) => {
            lines.push(format!("resume_from {resume_from:#018x}"));
            lines.push(format!("in_applied {in_applied:#018x}"));
            lines.push(format!("linger {linger:?}"));
            lines.push(format!("agent {agent}"));
        }
        Frame::Input { offset, data } | Frame::Output { offset, data } => {
            lines.push(format!("offset {offset:#018x}"));
            lines.push(format!("data {}", hex(data)));
        }
        Frame::InputAck { applied_through } => {
            lines.push(format!("applied_through {applied_through:#018x}"));
        }
        Frame::Resize(win) => lines.extend(win_lines(win)),
        Frame::Gap { new_base_offset } => {
            lines.push(format!("new_base_offset {new_base_offset:#018x}"));
        }
        Frame::Exit {
            status,
            kind,
            since_exit_secs,
        } => {
            lines.push(format!("status {status}"));
            lines.push(format!("kind {kind:?}"));
            lines.push(format!("since_exit_secs {since_exit_secs:#010x}"));
        }
        Frame::Error { code, message } => {
            lines.push(format!("code {code:?}"));
            lines.push(format!("message {}", hex(message.as_bytes())));
        }
        Frame::AgentData { data } => lines.push(format!("data {}", hex(data))),
        Frame::Detach | Frame::Ping | Frame::Pong | Frame::AgentOpen | Frame::AgentClose => {}
    }
    lines.push(format!("bytes {}", hex(bytes)));
    lines.join("\n")
}

/// The whole table as the fixture writes it.
fn rendered_fixture() -> String {
    let records: Vec<String> = vectors().iter().map(record).collect();
    format!("{}\n", records.join("\n\n"))
}

/// The lines of a fixture that say something, numbered from one — the reader its own
/// grammar promises, which is the one thing here that has to be naive.
fn content(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            (
                index + 1,
                line.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// `wire-vectors.txt` says what this table says, so a second implementation can be
/// built against these bytes without reading Rust.
///
/// The table is the original and the fixture is rendered from it rather than the other
/// way round: what the two tests above are worth rests on the vectors being literals
/// read out of § 2.2 by hand and reviewed as a diff, and the fixture's `bytes` come from
/// those literals rather than from `encode`, so what it offers another implementation is
/// the document and not this codec's opinion of it. Both sides are read through the
/// ignorable-line rule the fixture states, so a re-commented or hand-aligned file still
/// passes and only the data is pinned.
///
/// A stale fixture fails here and is never rewritten: [`FIXTURE`] is `include_str!`, so
/// this test has no handle to write through, and the rendering rides on the failure
/// instead — which is what a maintainer pastes, a vector added or dropped having moved
/// every line after it.
#[test]
fn the_hex_fixture_carries_the_same_table() {
    let rendered = rendered_fixture();
    let table = content(&rendered);
    let carried = content(FIXTURE);

    let complaint = table
        .iter()
        .enumerate()
        .find_map(|(index, (_, want))| match carried.get(index) {
            Some((_, found)) if found == want => None,
            Some((number, found)) => Some(format!(
                "wire-vectors.txt:{number} carries `{found}`, and this table renders `{want}`"
            )),
            None => Some(format!(
                "wire-vectors.txt ends before this table does, at `{want}`"
            )),
        })
        .or_else(|| {
            carried.get(table.len()).map(|(number, extra)| {
                format!("wire-vectors.txt:{number} carries `{extra}`, which no vector renders")
            })
        });

    if let Some(complaint) = complaint {
        panic!("{complaint}\n\nthe table renders:\n\n{rendered}");
    }
}

/// Every closed set on this wire is written down in bytes above, at every value it has,
/// and the handshake vectors are written at the revision this build speaks.
///
/// Swept from each set's `ALL` rather than from a list written out here, which would
/// stop covering the protocol the moment the protocol grew, and quietly. The two flags
/// bytes have no `ALL` and are destructured exhaustively instead, for the same property
/// reached the other way round: a bool added to either stops this file compiling. Both
/// states of each, because a bit exercised at one value is pinned only against being
/// renumbered wholesale — give `Hello` both of its flags at once and the two can trade
/// places without moving a byte. The revision rides along because the `Hello` vectors
/// write it out as a literal, which is what makes them a check on the document and
/// equally what would let them pass at one the daemon refuses; `HelloOk` carries none
/// (§ 2.2).
#[test]
fn the_vectors_pin_every_value_of_every_closed_set() {
    let mut types = Vec::new();
    let mut kinds = Vec::new();
    let mut lingers = Vec::new();
    let mut hello_flags = Vec::new();
    let mut agent_flags = Vec::new();

    for Vector { frame, .. } in vectors() {
        types.push(frame.frame_type());
        match frame {
            Frame::Hello(Hello {
                protocol,
                agent_forward,
                repaint_ctrl_l,
                out_offset: _,
                win: _,
                term: _,
            }) => {
                assert_eq!(
                    protocol, PROTOCOL_VERSION,
                    "a handshake vector is written at a revision the daemon would \
                     refuse: {frame:?}"
                );
                hello_flags.push([agent_forward, repaint_ctrl_l]);
            }
            Frame::HelloOk(HelloOk {
                resume_from: _,
                in_applied: _,
                linger,
                agent,
            }) => {
                lingers.push(linger);
                agent_flags.push(agent);
            }
            Frame::Exit { kind, .. } => kinds.push(kind),
            _ => {}
        }
    }

    for ty in FrameType::ALL {
        assert!(types.contains(&ty), "{ty:?} has no wire vector");
    }
    for kind in ExitKind::ALL {
        assert!(kinds.contains(&kind), "{kind:?} has no wire vector");
    }
    for linger in Linger::ALL {
        assert!(lingers.contains(&linger), "{linger:?} has no wire vector");
    }
    for (state, verb) in [(true, "sets"), (false, "clears")] {
        for (bit, name) in [(0, "agent_forward"), (1, "repaint_ctrl_l")] {
            let pinned = hello_flags.iter().any(|flags| flags[bit] == state);
            assert!(pinned, "no Hello vector {verb} {name}");
        }
        let pinned = agent_flags.contains(&state);
        assert!(pinned, "no HelloOk vector {verb} the agent flag");
    }
}

/// The `len` field is a big-endian `u24`, checked past its low byte and at the cap.
///
/// Every vector above carries a payload shorter than 256 bytes, so the top two bytes of
/// its length are always zero — an encoder that computed `len` correctly and then wrote
/// only its low byte would satisfy every one of them. The § 2.1 cap is the other half
/// of the same gap: only a payload at the cap produces a length that reaches the top
/// byte, so the largest legal frame is the one case that shows the field is three bytes
/// wide rather than two. [`the_frozen_numbers_are_the_ones_the_document_gives`] holds
/// `MAX_PAYLOAD` itself against § 2.1; this holds its encoding.
///
/// These payloads are built rather than written out, which is why they sit here rather
/// than in the table. The bytes asserted are still only the header, still hand-written
/// from the document.
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

/// Every number this wire freezes, written out by hand with the section it was read
/// from, so a failure here is the code moving away from the document.
///
/// A frame carries one enumerator at a time, so the vectors above pin one value of each
/// set and a table is the only way to reach the rest; *which* values it must carry is
/// swept from each set's `ALL`, so one added to the protocol and not to this table fails
/// here. The two scalars are already pinned by the vectors' literals, but only alongside
/// them: the edit that moves the constant *and* the literals together is a revision bump
/// § 2.1 and § 2.2 have not been told about.
#[test]
fn the_frozen_numbers_are_the_ones_the_document_gives() {
    /// One closed set, written the way § 2.2 writes it.
    macro_rules! frozen {
        ($ty:ty, $to:ident / $from:ident, $($name:ident = $number:literal),+) => {
            for (value, number) in [$((<$ty>::$name, $number)),+] {
                assert_eq!(value.$to(), number, "{value:?} is not the § 2.2 number");
                assert_eq!(<$ty>::$from(number), Some(value), "{number} is not {value:?}");
            }
            for value in <$ty>::ALL {
                let listed = [$(<$ty>::$name),+].contains(&value);
                assert!(listed, "{value:?} is on no line of § 2.2's table");
            }
        };
    }

    for (name, held, expected, section) in [
        (
            "PROTOCOL_VERSION",
            u64::from(PROTOCOL_VERSION),
            7,
            "§ 2.2 puts the current revision at 7",
        ),
        (
            "MAX_PAYLOAD",
            u64::from(MAX_PAYLOAD),
            262_144,
            "§ 2.1 caps a payload at 256 KiB",
        ),
    ] {
        assert_eq!(
            held, expected,
            "{name} is {held}, and IMPLEMENTATION.md {section}"
        );
    }

    frozen!(
        ErrorCode,
        as_u16 / from_u16,
        Protocol = 1,
        Takeover = 2,
        Version = 3,
        InputGap = 4,
        Internal = 5
    );
    frozen!(
        Linger,
        as_byte / from_byte,
        Unknown = 0,
        Disabled = 1,
        Enabled = 2
    );
    frozen!(ExitKind, as_byte / from_byte, Exited = 0, Signalled = 1);
}
