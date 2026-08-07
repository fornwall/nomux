//! The codec (`IMPLEMENTATION.md` § 9), from the two directions it can be got wrong in.
//!
//! [`generated`] drives the codec against *itself* over a generated input space: encode,
//! decode, and assert that nothing panicked and nothing changed. That proves the two
//! halves agree, not that either is right — swap `HelloOk`'s `resume_from` and
//! `in_applied` in both directions and every case still passes, the two being the same
//! width, while the bytes on the wire are wrong.
//!
//! [`vectors`] is the half that closes it: byte literals read out of the § 2.2 table by
//! hand rather than produced by the encoder, checked in both directions. They are the only
//! thing in the repository that would notice a field order, field width or endianness
//! change, and the only reason the client — a separate codebase reading the same table —
//! can be built against the document instead of against this code.
//!
//! One binary because they are one subject: a deliberate wire change is a
//! [`nomux::PROTOCOL_VERSION`] bump, an edit to § 2.2 and a new set of vectors, and it
//! should not be possible to move any one of the three alone.

/// Generated coverage: every field at its extremes, every frame type pointed at every
/// payload, and payloads one flipped bit away from valid.
///
/// The codec reads bytes the peer chose, so the bar is not "rejects bad input" but "never
/// panics on any input" — `indexing_slicing` is denied crate-wide, which makes an
/// out-of-bounds panic unlikely rather than impossible.
///
/// This is the fuzzing story for the parser, run on stable as part of the normal suite
/// rather than as a `cargo-fuzz` target: the input space that matters is a 4-byte header
/// and a length-prefixed payload, which a generator reaches by construction.
///
/// The generator is a seeded [`generated::Rng`] rather than a property-testing crate. The
/// cases here are already small — a payload is at most 40 bytes and a text field at most
/// 24 characters — so shrinking would have nothing left to take away, and what it buys is
/// not worth fifteen transitive dependencies and three proc-macro compiles in a tree that
/// otherwise has two. What replaces it is determinism: every case is derived from
/// [`generated::SEED`], a failure prints the `u64` its own case came from, and
/// `Rng::new(that)` replays it alone.
mod generated {
    use std::collections::HashSet;

    use nomux::{
        ErrorCode, ExitKind, Frame, FrameType, HEADER_LEN, Hello, HelloOk, Linger, MAX_PAYLOAD,
        ProtoError, WinSize, decode_header,
    };

    /// Base seed for every generated case in this module. Fixed, so a run either always
    /// fails or never does; changing it is how the suite is pointed at fresh cases.
    pub(super) const SEED: u64 = 0x6e6f_6d75_785f_3038;

    /// Cases per property.
    ///
    /// High for a property count, and affordable: the codec is a few hundred branches over
    /// tiny buffers, so the whole file still runs in well under a second, and finding a
    /// valid `ErrorCode` in two random bytes needs the cases more than it needs the time
    /// back.
    const CASES: u32 = 2048;

    /// Cap on generated `data` and `term` lengths.
    ///
    /// The codec treats those fields as opaque tails, so the interesting behaviour is all
    /// at 0, 1 and "more than the fixed prefix"; anything near [`MAX_PAYLOAD`] would only
    /// slow the suite down.
    const MAX_GENERATED_LEN: usize = 24;

    /// `SplitMix64`'s increment, chosen for the same reason it was there: successive states
    /// differ in every bit of the mixed output.
    const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

    /// `SplitMix64`'s finalizer — a bijection on `u64` with full avalanche.
    const fn mix(mut z: u64) -> u64 {
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The seed for case `case` of the property salted `salt`.
    ///
    /// Per case rather than one stream per property, so a failure names a number that
    /// reproduces that one case: seed an [`Rng`] with it and run the body once. Mixed
    /// rather than added, because adding would hand consecutive cases the same stream
    /// shifted by a draw.
    const fn case_seed(salt: u16, case: u32) -> u64 {
        mix(SEED ^ ((salt as u64) << 48) ^ case as u64)
    }

    /// `SplitMix64`: 30 lines of arithmetic with no state but a counter, which is all a
    /// generator that has to be reproducible from a `u64` needs to be.
    pub(super) struct Rng {
        state: u64,
    }

    impl Rng {
        /// A stream from `seed`. Two seeds far apart give streams that do not overlap
        /// within the few dozen draws a case makes.
        pub(super) const fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        /// The next 64 bits.
        const fn u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(GOLDEN);
            mix(self.state)
        }

        /// The next 32 bits.
        const fn u32(&mut self) -> u32 {
            let [a, b, c, d, ..] = self.u64().to_be_bytes();
            u32::from_be_bytes([a, b, c, d])
        }

        /// The next 32 bits, read as a signed value, so exit statuses lose their sign as
        /// often as they keep it.
        const fn i32(&mut self) -> i32 {
            i32::from_be_bytes(self.u32().to_be_bytes())
        }

        /// The next 16 bits.
        const fn u16(&mut self) -> u16 {
            let [a, b, ..] = self.u64().to_be_bytes();
            u16::from_be_bytes([a, b])
        }

        /// The next byte.
        const fn u8(&mut self) -> u8 {
            let [a, ..] = self.u64().to_be_bytes();
            a
        }

        /// The next bit.
        const fn bool(&mut self) -> bool {
            self.u64() & 1 == 1
        }

        /// A number below `n`, and 0 when `n` is. The modulo bias is under one part in
        /// 2^58 for every `n` used here.
        fn below(&mut self, n: usize) -> usize {
            let n = u64::try_from(n).unwrap_or(u64::MAX);
            if n == 0 {
                return 0;
            }
            usize::try_from(self.u64() % n).unwrap_or(0)
        }

        /// One of `values`, uniformly, and `if_empty` when there are none — which no
        /// caller's `ALL` is. The fallback stands in for an index `indexing_slicing`
        /// refuses outside a `#[test]`.
        fn pick<T: Copy>(&mut self, values: &[T], if_empty: T) -> T {
            let at = self.below(values.len());
            values.get(at).copied().unwrap_or(if_empty)
        }

        /// One Unicode scalar, weighted by encoded width rather than drawn uniformly over
        /// the scalar space — which is 96% four-byte, and would put ASCII and U+0000 in
        /// front of the codec about once a suite.
        fn char(&mut self) -> char {
            let value = match self.below(4) {
                0 => self.u32() % 0x80,
                1 => 0x80 + self.u32() % (0x800 - 0x80),
                2 => 0x800 + self.u32() % (0x1_0000 - 0x800),
                _ => 0x1_0000 + self.u32() % (0x11_0000 - 0x1_0000),
            };
            // The surrogates are the values in the three-byte range that are not scalars.
            char::from_u32(value).unwrap_or('\u{fffd}')
        }

        /// Bounded UTF-8 text.
        ///
        /// Built from characters rather than from a pattern, so the bound is in the
        /// characters the generator emits and multi-byte scalars turn up rather than
        /// being filtered out.
        fn text(&mut self, max: usize) -> String {
            let len = self.below(max + 1);
            (0..len).map(|_| self.char()).collect()
        }

        /// [`Rng::text`] minus U+0000, which the codec refuses in `Hello.term` by design
        /// — valid UTF-8 that `execve` will not take, so not a well-formed frame. This
        /// generator's job is the frames that encode; the refusal is covered by the
        /// mutation property below and by a unit test beside the check.
        ///
        /// Rewritten rather than redrawn, so the ASCII draw keeps its whole range.
        fn term(&mut self, max: usize) -> String {
            self.text(max).replace('\0', "\u{fffd}")
        }

        /// A bounded opaque payload.
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let len = self.below(max + 1);
            (0..len).map(|_| self.u8()).collect()
        }

        /// Terminal dimensions, unconstrained: the codec is not the layer that decides a
        /// 0x0 terminal is nonsense, and a size it silently clamped would be a bug this
        /// must catch.
        const fn win(&mut self) -> WinSize {
            WinSize {
                cols: self.u16(),
                rows: self.u16(),
                xpixel: self.u16(),
                ypixel: self.u16(),
            }
        }
    }

    /// Unwraps a checked step, naming the seed that replays the case it failed on.
    ///
    /// A macro rather than a function so the panic lands inside the `#[test]` body, which
    /// is where `clippy.toml`'s `allow-panic-in-tests` reaches.
    macro_rules! checked {
        ($outcome:expr) => {
            match $outcome {
                Ok(value) => value,
                Err(complaint) => panic!("{complaint}"),
            }
        };
        ($outcome:expr, $seed:expr) => {
            match $outcome {
                Ok(value) => value,
                Err(complaint) => {
                    panic!("{complaint}\n\nreplay with Rng::new({:#018x})", $seed)
                }
            }
        };
    }

    /// Owned mirror of [`Frame`], whose `data`, `term` and `message` fields borrow.
    ///
    /// A generated value is owned, so the generated bytes must outlive the frame pointing
    /// at them. No frame borrows both text and bytes, so one slot of each covers all five
    /// borrowed fields: the frame travels with an empty placeholder and
    /// [`OwnedFrame::frame`] hands back a copy pointing at the owned value.
    #[derive(Debug, Clone)]
    struct OwnedFrame {
        /// The frame, with a placeholder wherever it borrows.
        frame: Frame<'static>,
        /// Backing store for a borrowed `term` or `message`.
        text: String,
        /// Backing store for a borrowed `data`.
        bytes: Vec<u8>,
    }

    impl OwnedFrame {
        /// Wraps a frame that borrows nothing.
        const fn copied(frame: Frame<'static>) -> Self {
            Self::with_text(frame, String::new())
        }

        /// Wraps a frame whose text field [`OwnedFrame::frame`] will point at `text`.
        const fn with_text(frame: Frame<'static>, text: String) -> Self {
            Self {
                frame,
                text,
                bytes: Vec::new(),
            }
        }

        /// Wraps a frame whose byte field [`OwnedFrame::frame`] will point at `bytes`.
        const fn with_bytes(frame: Frame<'static>, bytes: Vec<u8>) -> Self {
            Self {
                frame,
                text: String::new(),
                bytes,
            }
        }

        /// Lends a [`Frame`] borrowing from `self`.
        fn frame(&self) -> Frame<'_> {
            match self.frame {
                Frame::Hello(hello) => Frame::Hello(Hello {
                    term: &self.text,
                    ..hello
                }),
                Frame::Error { code, .. } => Frame::Error {
                    code,
                    message: &self.text,
                },
                Frame::Input { offset, .. } => Frame::Input {
                    offset,
                    data: &self.bytes,
                },
                Frame::Output { offset, .. } => Frame::Output {
                    offset,
                    data: &self.bytes,
                },
                Frame::AgentData { generation, .. } => Frame::AgentData {
                    generation,
                    data: &self.bytes,
                },
                borrows_nothing => borrows_nothing,
            }
        }
    }

    /// One frame, with every field drawn over its whole domain.
    ///
    /// One arm per [`FrameType`], picked uniformly. The arm list is the one list here
    /// still written by hand, and a variant missing from it is never round-tripped; the
    /// modulus is [`FrameType::ALL`]'s length, so a variant added to the protocol falls
    /// into the last arm and [`every_frame_type_is_generated`] says so.
    ///
    /// The closed sets are drawn from their own `ALL`, so a value added to one of those is
    /// generated without anyone remembering to come here.
    fn frame(rng: &mut Rng) -> OwnedFrame {
        match rng.below(FrameType::ALL.len()) {
            0 => OwnedFrame::with_text(
                Frame::Hello(Hello {
                    protocol: rng.u16(),
                    agent_forward: rng.bool(),
                    repaint_ctrl_l: rng.bool(),
                    out_offset: rng.u64(),
                    win: rng.win(),
                    term: "",
                }),
                rng.term(MAX_GENERATED_LEN),
            ),
            1 => OwnedFrame::copied(Frame::HelloOk(HelloOk {
                resume_from: rng.u64(),
                in_applied: rng.u64(),
                linger: rng.pick(&Linger::ALL, Linger::Unknown),
                agent: rng.bool(),
            })),
            2 => OwnedFrame::with_bytes(
                Frame::Input {
                    offset: rng.u64(),
                    data: b"",
                },
                rng.bytes(MAX_GENERATED_LEN),
            ),
            3 => OwnedFrame::copied(Frame::InputAck {
                applied_through: rng.u64(),
            }),
            4 => OwnedFrame::with_bytes(
                Frame::Output {
                    offset: rng.u64(),
                    data: b"",
                },
                rng.bytes(MAX_GENERATED_LEN),
            ),
            5 => OwnedFrame::copied(Frame::Resize(rng.win())),
            6 => OwnedFrame::copied(Frame::Gap {
                new_base_offset: rng.u64(),
            }),
            7 => OwnedFrame::copied(Frame::Exit {
                status: rng.i32(),
                kind: rng.pick(&ExitKind::ALL, ExitKind::Exited),
                since_exit_secs: rng.u32(),
            }),
            8 => OwnedFrame::copied(Frame::Detach),
            9 => OwnedFrame::copied(Frame::Ping),
            10 => OwnedFrame::copied(Frame::Pong),
            11 => OwnedFrame::with_text(
                Frame::Error {
                    code: rng.pick(&ErrorCode::ALL, ErrorCode::Internal),
                    message: "",
                },
                rng.text(MAX_GENERATED_LEN),
            ),
            12 => OwnedFrame::copied(Frame::AgentOpen {
                generation: rng.u32(),
            }),
            13 => OwnedFrame::with_bytes(
                Frame::AgentData {
                    generation: rng.u32(),
                    data: b"",
                },
                rng.bytes(MAX_GENERATED_LEN),
            ),
            _ => OwnedFrame::copied(Frame::AgentClose {
                generation: rng.u32(),
            }),
        }
    }

    /// Encodes `frame` and returns the bytes after the header, having checked that the
    /// header describes what follows it.
    ///
    /// Reports failures instead of panicking: `clippy.toml`'s `allow-*-in-tests` covers
    /// `#[test]` bodies, not helpers beside them, and the caller is the one holding the
    /// seed a failure has to be reported with.
    fn encode_and_split(frame: Frame<'_>) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        frame
            .encode(&mut buf)
            .map_err(|err| format!("encode refused {frame:?}: {err}"))?;

        let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
            return Err("encode emitted no header".to_owned());
        };
        let header = decode_header(header).map_err(|err| format!("own header rejected: {err}"))?;
        let payload = buf.split_off(HEADER_LEN);

        if header.ty != frame.frame_type() {
            return Err(format!(
                "header says {:?} and the frame behind it is {:?}",
                header.ty,
                frame.frame_type()
            ));
        }
        if header.len as usize != payload.len() {
            return Err(format!(
                "declared length {} disagrees with the {} bytes written",
                header.len,
                payload.len()
            ));
        }
        Ok(payload)
    }

    /// Offers `payload` to every frame type and checks what must hold for bytes from a
    /// hostile peer: not panicking, and — when accepted — being the *only* encoding of
    /// what they decoded to. A decoder that takes two spellings of one frame lets a peer
    /// smuggle bytes past anything downstream that compares encodings.
    fn decode_as_every_type(payload: &[u8]) -> Result<(), String> {
        // Every type rather than a sampled few: a decode apiece is far cheaper than the
        // cases it would otherwise take to find the one type that mishandles a payload.
        // [`FrameType::ALL`] comes from the discriminant list, so a new type joins by
        // itself.
        for ty in FrameType::ALL {
            let Ok(frame) = Frame::decode(ty, payload) else {
                continue;
            };
            if frame.frame_type() != ty {
                return Err(format!(
                    "{payload:?} decoded as {:?} when it was asked for {ty:?}",
                    frame.frame_type()
                ));
            }
            let re_encoded = encode_and_split(frame)?;
            if re_encoded != payload {
                return Err(format!(
                    "accepted a non-canonical encoding of {frame:?}: {payload:?} decodes, \
                     and re-encodes as {re_encoded:?}"
                ));
            }
        }
        Ok(())
    }

    /// The whole of `decode_header`'s contract, for one four-byte header.
    ///
    /// It reads four bytes off the wire before anything has been validated, so there is no
    /// input it may refuse to return from. It must also promise what the rest of the
    /// daemon relies on — a known type, and a length that bounds the next allocation —
    /// and, when it refuses, must report the bytes it actually read.
    fn check_header(bytes: [u8; HEADER_LEN]) -> Result<(), String> {
        let [ty, a, b, c] = bytes;
        let len = u32::from_be_bytes([0, a, b, c]);
        match decode_header(&bytes) {
            Ok(header) => {
                if FrameType::from_wire(ty) != Some(header.ty) {
                    return Err(format!("{bytes:02x?}: invented the type {:?}", header.ty));
                }
                if header.len != len {
                    return Err(format!(
                        "{bytes:02x?}: length {} is not the low 24 bits, {len}",
                        header.len
                    ));
                }
                if header.len > MAX_PAYLOAD {
                    return Err(format!(
                        "{bytes:02x?}: accepted an unbounded allocation of {}",
                        header.len
                    ));
                }
            }
            Err(ProtoError::UnknownFrameType(reported)) => {
                if reported != ty {
                    return Err(format!("{bytes:02x?}: reported a byte it did not read"));
                }
                if FrameType::from_wire(ty).is_some() {
                    return Err(format!("{bytes:02x?}: refused a known type"));
                }
            }
            Err(ProtoError::PayloadTooLarge(reported)) => {
                if reported != len {
                    return Err(format!(
                        "{bytes:02x?}: reported the length {reported}, which it did not read"
                    ));
                }
                if len <= MAX_PAYLOAD {
                    return Err(format!("{bytes:02x?}: refused a length within the cap"));
                }
            }
            Err(other) => {
                return Err(format!(
                    "{bytes:02x?}: header decode cannot produce {other:?}"
                ));
            }
        }
        Ok(())
    }

    /// [`frame`] generates every frame type.
    ///
    /// Its arms are the one list here still written by hand, and a variant missing from
    /// them is never round-tripped. The sweeps below take arbitrary payloads to every type
    /// and so reach a new variant's decoder, but never its field domain.
    ///
    /// This asserts coverage of the generator rather than a property of the codec, and
    /// coverage that passes by luck is worse than none — hence the one stream, long enough
    /// that a variant reachable at all is reached.
    #[test]
    fn every_frame_type_is_generated() {
        let mut rng = Rng::new(case_seed(0x0001, 0));
        let mut seen = HashSet::new();
        for _ in 0..4096 {
            seen.insert(frame(&mut rng).frame().frame_type());
        }

        for ty in FrameType::ALL {
            assert!(seen.contains(&ty), "the generator never produces {ty:?}");
        }
    }

    /// Encoding then decoding is the identity, for every variant over its whole field
    /// domain — including the extremes a fixed value per field cannot reach, such as a
    /// `u64` offset truncated to 32 bits or a signed exit status losing its sign.
    #[test]
    fn every_frame_round_trips() {
        for case in 0..CASES {
            let seed = case_seed(0x0002, case);
            let owned = frame(&mut Rng::new(seed));
            let frame = owned.frame();
            let payload = checked!(encode_and_split(frame), seed);
            let decoded = checked!(
                Frame::decode(frame.frame_type(), &payload)
                    .map_err(|err| format!("own encoding rejected: {err}")),
                seed
            );
            assert_eq!(
                decoded, frame,
                "round trip changed the frame (seed {seed:#018x})"
            );
        }
    }

    /// `decode_header` is total over its input, and reports only what it read.
    ///
    /// Exhaustive in the type byte and deliberate in the length before it is random in
    /// either: the field is 2^24 wide and what matters is the cap and the values on both
    /// sides of it, which uniform draws land on with probability 2^-24. The random cases
    /// afterwards are what would catch a rule neither sweep thought of.
    #[test]
    fn header_decode_is_total() {
        for ty in 0..=u8::MAX {
            for len in [
                0,
                1,
                MAX_PAYLOAD - 1,
                MAX_PAYLOAD,
                MAX_PAYLOAD + 1,
                0x00ff_ffff,
            ] {
                let [_, a, b, c] = len.to_be_bytes();
                checked!(check_header([ty, a, b, c]));
            }
        }

        for case in 0..CASES {
            let seed = case_seed(0x0003, case);
            let mut rng = Rng::new(seed);
            checked!(check_header([rng.u8(), rng.u8(), rng.u8(), rng.u8()]), seed);
        }
    }

    /// `Frame::decode` is total over arbitrary payloads for every frame type.
    ///
    /// The type byte and the payload arrive from the same untrusted stream and are not
    /// checked against each other, so a peer can point any type at any bytes.
    #[test]
    fn payload_decode_is_total() {
        for case in 0..CASES {
            let seed = case_seed(0x0004, case);
            let payload = Rng::new(seed).bytes(40);
            checked!(decode_as_every_type(&payload), seed);
        }
    }

    /// A `Hello` whose declared `term_len` runs past the bytes behind it.
    ///
    /// The one length prefix on this wire. The sweeps above reach its boundary only on the
    /// rare payload already shaped like a `Hello`, and accept any refusal there; this
    /// reaches it every time and pins which refusal.
    #[test]
    fn a_hello_that_overstates_its_term_length_is_truncated() {
        for case in 0..CASES {
            let seed = case_seed(0x0005, case);
            let mut rng = Rng::new(seed);
            let term = rng.bytes(MAX_GENERATED_LEN);
            // At least one byte past what follows, which is the whole point of the case.
            let beyond = rng.u16().max(1);

            // The fixed prefix § 2.2 gives `Hello` — protocol, flags, out_offset,
            // winsize — all zero, which is a shape the decoder accepts.
            let mut payload = vec![0u8; 19];
            let declared = u16::try_from(term.len())
                .unwrap_or(u16::MAX)
                .saturating_add(beyond);
            payload.extend_from_slice(&declared.to_be_bytes());
            payload.extend_from_slice(&term);
            assert_eq!(
                Frame::decode(FrameType::Hello, &payload),
                Err(ProtoError::Truncated),
                "declared {declared} with {} bytes behind it (seed {seed:#018x})",
                term.len()
            );
            checked!(decode_as_every_type(&payload), seed);
        }
    }

    /// The same, on payloads one byte away from valid.
    ///
    /// Uniform random bytes almost never reach the code past a length prefix or an enum
    /// discriminant; a real encoding with one byte flipped or amputated does, and lands on
    /// the boundaries — a `term_len` larger than what follows, a reserved flag bit, a
    /// truncated final field.
    #[test]
    fn mutated_encodings_decode_without_panicking() {
        for case in 0..CASES {
            let seed = case_seed(0x0006, case);
            let mut rng = Rng::new(seed);
            let owned = frame(&mut rng);
            let position = rng.u16();
            // Never zero: a flip of no bits is a case this test already has 2048 of.
            let flip = rng.u8().max(1);
            let truncate = rng.bool();

            let mut payload = checked!(encode_and_split(owned.frame()), seed);
            let position = usize::from(position)
                .checked_rem(payload.len())
                .unwrap_or(0);
            if let Some(byte) = payload.get_mut(position) {
                *byte ^= flip;
            }
            if truncate {
                payload.pop();
            }
            checked!(decode_as_every_type(&payload), seed);
        }
    }
}

/// Byte-exact conformance to the frame table in `IMPLEMENTATION.md` § 2.2.
///
/// A failure here is either a deliberate wire change, which is a [`nomux::PROTOCOL_VERSION`]
/// bump and an edit to § 2.2, or a bug. It is never a test that needs relaxing.
///
/// The same table is written out beside this file as `wire-vectors.txt`, in a form an
/// implementation in another language reads without parsing Rust;
/// [`vectors::the_hex_fixture_carries_the_same_table`] renders these vectors and holds that
/// file to the rendering, so neither can move alone.
mod vectors {
    use nomux::{
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
                    protocol: 8,
                    agent_forward: true,
                    repaint_ctrl_l: true,
                    out_offset: 0x0102_0304_0506_0708,
                    win: WIN,
                    term: "xterm-256color",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x23, // header: type, u24 len = 35
                    0x00, 0x08, // protocol
                    0x03, // flags: bit 0 agent forward, bit 1 repaint ctrl-l
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // out_offset
                    0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                    0x00, 0x0e, // term_len = 14
                    b'x', b't', b'e', b'r', b'm', b'-', b'2', b'5', b'6', b'c', b'o', b'l', b'o',
                    b'r',
                ],
            },
            // 0x01 Hello again, with bit 0 alone, which is what pins *which* bit is
            // which: above, both are set, so exchanging the two leaves 0x03 unchanged.
            // Carries `RESUME_FROM_START` as well, which no other vector shows.
            Vector {
                frame: Frame::Hello(Hello {
                    protocol: 8,
                    agent_forward: true,
                    repaint_ctrl_l: false,
                    out_offset: RESUME_FROM_START,
                    win: WIN,
                    term: "vt100",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                    0x00, 0x08, // protocol
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
                    protocol: 8,
                    agent_forward: false,
                    repaint_ctrl_l: false,
                    out_offset: 0x8182_8384_8586_8788,
                    win: WIN,
                    term: "dumb",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x19, // header: type, u24 len = 25
                    0x00, 0x08, // protocol
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
            // 0x0d AgentOpen: u32 generation, which the daemon mints and the other two
            // frames echo. One connection is served at a time, so it addresses nothing —
            // it separates the peers that hold the one slot in turn.
            Vector {
                frame: Frame::AgentOpen {
                    generation: 0x1112_1314,
                },
                bytes: &[
                    0x0d, 0x00, 0x00, 0x04, //
                    0x11, 0x12, 0x13, 0x14, // generation
                ],
            },
            // 0x0e AgentData: u32 generation, then opaque bytes to the end of the payload.
            // What is written here is a real `ssh-agent` request — length 1, type 11
            // (REQUEST_IDENTITIES) — to make the point that the daemon never parses it.
            // The generation has its top bit set, which no other vector shows: it is
            // unsigned, and a session that mints four billion of them wraps rather than
            // going negative.
            Vector {
                frame: Frame::AgentData {
                    generation: 0x9192_9394,
                    data: b"\x00\x00\x00\x01\x0b",
                },
                bytes: &[
                    0x0e, 0x00, 0x00, 0x09, // header: len = 4 + 5
                    0x91, 0x92, 0x93, 0x94, // generation
                    0x00, 0x00, 0x00, 0x01, 0x0b,
                ],
            },
            // 0x0f AgentClose: u32 generation, like the open it answers. Written at the
            // first generation a session mints, which is a channel like any other and not
            // a sentinel — nothing on this wire spells "no channel".
            Vector {
                frame: Frame::AgentClose { generation: 0 },
                bytes: &[
                    0x0f, 0x00, 0x00, 0x04, //
                    0x00, 0x00, 0x00, 0x00, // generation
                ],
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
    /// these vectors exist to supplement.
    #[test]
    fn documented_bytes_decode_to_their_frames() {
        for Vector { frame, bytes } in vectors() {
            let (header, payload) = bytes.split_at(HEADER_LEN);
            let header: [u8; HEADER_LEN] = header.try_into().unwrap();
            let header = nomux::decode_header(&header).unwrap();

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
            Frame::AgentOpen { generation } | Frame::AgentClose { generation } => {
                lines.push(format!("generation {generation:#010x}"));
            }
            Frame::AgentData { generation, data } => {
                lines.push(format!("generation {generation:#010x}"));
                lines.push(format!("data {}", hex(data)));
            }
            Frame::Detach | Frame::Ping | Frame::Pong => {}
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
            ($ty:ty, $($name:ident = $number:literal),+) => {
                for (value, number) in [$((<$ty>::$name, $number)),+] {
                    assert_eq!(value.as_wire(), number, "{value:?} is not the § 2.2 number");
                    assert_eq!(<$ty>::from_wire(number), Some(value), "{number} is not {value:?}");
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
                8,
                "§ 2.2 puts the current revision at 8",
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
            Protocol = 1,
            Takeover = 2,
            Version = 3,
            InputGap = 4,
            Internal = 5
        );
        frozen!(Linger, Unknown = 0, Disabled = 1, Enabled = 2);
        frozen!(ExitKind, Exited = 0, Signalled = 1);
    }
}
