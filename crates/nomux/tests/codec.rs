//! Protocol codec coverage (`IMPLEMENTATION.md` § 9).
//!
//! [`generated`] checks round trips and parser totality. [`vectors`] independently
//! transcribes § 2.2, catching matching encoder/decoder mistakes. A wire change updates
//! the protocol revision, the table, and its vectors together.

/// Deterministic generated coverage of field extremes, cross-type payloads and mutations.
/// Committed fuzz seeds are replayed here so sanitizer findings remain release gates.
mod generated {
    use std::path::Path;
    use std::{fs, io};

    use nomux_protocol::{
        ErrorCode, ExitKind, Frame, FrameType, HEADER_LEN, Hello, HelloOk, MAX_PAYLOAD, ProtoError,
        WinSize, decode_header,
    };

    /// Base seed for every generated case in this module. Fixed, so a run either always
    /// fails or never does; changing it is how the suite is pointed at fresh cases.
    pub(super) const SEED: u64 = 0x6e6f_6d75_785f_3038;

    /// Cases per property.
    ///
    /// High for a property count, and affordable: the codec is a few hundred branches over
    /// tiny buffers, so the whole file still runs in well under a second, and a mutation
    /// that has to pick both a frame and the byte of it to flip needs the cases more than
    /// it needs the time back.
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
    /// into the last arm and is never round-tripped over its own fields, which is what
    /// [`every_frame_round_trips`] closes by sweeping [`FrameType::ALL`] against what it
    /// generated.
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
                    if_detached: rng.bool(),
                    out_offset: rng.u64(),
                    win: rng.win(),
                    term: "",
                }),
                rng.text(MAX_GENERATED_LEN),
            ),
            1 => OwnedFrame::copied(Frame::HelloOk(HelloOk {
                resume_from: rng.u64(),
                in_applied: rng.u64(),
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
                since_terminal_closed_secs: rng.u32(),
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

    /// What the encoder refuses `frame` for, where it has to refuse it at all.
    ///
    /// The one shape [`frame`] generates that has no encoding: a `Hello` whose `term`
    /// carries a NUL. It is valid UTF-8 that `execve` will not take, and the daemon hands
    /// `term` straight to the child's environment — so § 2.2 has both ends refuse it, and
    /// a codec that quietly encoded one would put a `TERM` on the wire that only fails
    /// much later, inside somebody's session.
    ///
    /// The generator draws it rather than stepping around it, which is what puts the
    /// refusal under the same sweep as everything else: reaching it by mutation means
    /// flipping a byte of a term to exactly zero, which is a few draws in ten thousand.
    /// The message is compared rather than merely the variant, `Malformed` being what
    /// every other complaint in this encoder is spelled as too.
    fn refused_by_design(frame: Frame<'_>) -> Option<&'static str> {
        match frame {
            Frame::Hello(hello) if hello.term.contains('\0') => Some("TERM contains a NUL byte"),
            _ => None,
        }
    }

    /// Encodes `frame` and returns the bytes after the header, having checked that the
    /// encoder's own decoder will take the header it wrote.
    ///
    /// Reports failures instead of panicking: `clippy.toml`'s `allow-*-in-tests` covers
    /// `#[test]` bodies, not helpers beside them, and the caller is the one holding the
    /// seed a failure has to be reported with.
    ///
    /// What that header *says* is not re-derived per case: `encode` patches it in from
    /// `frame_type()` and the payload length it has just written, and that `decode_header`
    /// inverts `encode_header` is asserted by `lib.rs`'s `header_round_trips` over every
    /// type and pinned in literal bytes by every vector in [`super::vectors`].
    fn encode_and_split(frame: Frame<'_>) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        frame
            .encode(&mut buf)
            .map_err(|err| format!("encode refused {frame:?}: {err}"))?;

        let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
            return Err("encode emitted no header".to_owned());
        };
        decode_header(header).map_err(|err| format!("own header rejected: {err}"))?;
        Ok(buf.split_off(HEADER_LEN))
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
                // Through `as_wire`, not `from_wire`: `decode_header` is built out of the
                // latter, so comparing against it asserts that a function agrees with
                // itself. The byte it was handed is the only independent witness there is.
                if header.ty.as_wire() != ty {
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
                if FrameType::ALL.iter().any(|known| known.as_wire() == ty) {
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

    /// Encoding then decoding is the identity, for every variant over its whole field
    /// domain — including the extremes a fixed value per field cannot reach, such as a
    /// `u64` offset truncated to 32 bits or a signed exit status losing its sign.
    ///
    /// Except for the frames [`refused_by_design`] names, which have no encoding to come
    /// back from: those are asserted to be refused, and refused for the stated reason
    /// rather than by some other check the frame also happens to trip.
    ///
    /// What the cases *reached* is stated at the foot, both for the refusal and for the
    /// variants, because coverage that passes by luck is worse than none and this sweep is
    /// the only thing that takes a frame type over its own field domain. [`frame`]'s arms
    /// are the one list in this file still written by hand, so a variant added to the
    /// protocol falls into the last of them and is generated by nothing — and every
    /// property here would go on passing over the fourteen that were already covered.
    #[test]
    fn every_frame_round_trips() {
        let mut refused = 0u32;
        let mut generated = Vec::new();
        for case in 0..CASES {
            let seed = case_seed(0x0002, case);
            let owned = frame(&mut Rng::new(seed));
            let frame = owned.frame();
            generated.push(frame.frame_type());
            if let Some(saying) = refused_by_design(frame) {
                refused += 1;
                let mut buf = b"previous frame".to_vec();
                let before = buf.len();
                assert_eq!(
                    frame.encode(&mut buf),
                    Err(ProtoError::Malformed(saying)),
                    "the encoder took {frame:?} (seed {seed:#018x})"
                );
                assert_eq!(
                    buf.len(),
                    before,
                    "a refused frame left bytes behind it in the stream (seed \
                     {seed:#018x})"
                );
                continue;
            }
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
        // The refusals above are reached by a NUL turning up in a generated `term`, which
        // is a property of [`Rng::text`] rather than of anything asserted — three of the
        // 2048 cases at this seed, deterministically. Stated here because a generator that
        // stopped producing one would leave the arm above green and never entered, which
        // is how the refusal came to be untested in the first place.
        assert!(
            refused > 0,
            "no case reached the encoder's refusal of a NUL in `term`, so the generator \
             no longer draws one and the arm above asserts nothing"
        );
        for ty in FrameType::ALL {
            assert!(
                generated.contains(&ty),
                "no case above was a {ty:?}, so nothing here round-trips one — it has an \
                 arm missing from `frame`, and the sweeps in this file reach its decoder \
                 with arbitrary payloads but never its fields"
            );
        }
    }

    /// `decode_header` is total over its input, and reports only what it read.
    ///
    /// Exhaustive in the type byte and deliberate in the length: the field is 2^24 wide and
    /// what matters is the cap and the values either side of it, which uniform draws land on
    /// with probability 2^-24.
    ///
    /// Nothing random rides on top, there being nothing left to reach: `decode_header` asks
    /// exactly two questions — is this type byte a [`FrameType`], is this length over
    /// [`MAX_PAYLOAD`] — and 256 type bytes crossed with lengths either side of the cap
    /// answers both at every combination they have. That closes this function's domain on
    /// stable and in a gate, which is why `fuzz/` is pointed at `Frame::decode` alone.
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
    }

    /// A `Hello` whose declared `term_len` runs past the bytes behind it.
    ///
    /// The one length prefix on this wire. The sweep below reaches its boundary only on the
    /// rare payload already shaped like a `Hello`, and accepts any refusal there; this
    /// reaches it every time and pins which refusal.
    ///
    /// Three cases rather than a generated sweep, because every overstatement is the same
    /// case: `decode` reads the fixed prefix, reads `term_len`, and asks the reader for that
    /// many bytes, which fails before a byte of the term is looked at. So neither the term's
    /// contents nor the size of the overshoot can change the answer, and what is left worth
    /// writing down is the ends of the comparison — nothing at all declared as one byte, a
    /// term declared one byte longer than it is, and the widest value the prefix can hold.
    #[test]
    fn a_hello_that_overstates_its_term_length_is_truncated() {
        for (term, declared) in [
            (b"".as_slice(), 1_u16),
            (b"vt100".as_slice(), 6),
            (b"vt100".as_slice(), u16::MAX),
        ] {
            // The fixed prefix § 2.2 gives `Hello` — protocol, flags, out_offset,
            // winsize — all zero, which is a shape the decoder accepts.
            let mut payload = vec![0u8; 19];
            payload.extend_from_slice(&declared.to_be_bytes());
            payload.extend_from_slice(term);
            assert_eq!(
                Frame::decode(FrameType::Hello, &payload),
                Err(ProtoError::Truncated),
                "declared {declared} with {} bytes behind it",
                term.len()
            );
            checked!(decode_as_every_type(&payload));
        }
    }

    /// `Frame::decode` is total over the payloads a peer can choose, for every frame type.
    ///
    /// The type byte and the payload arrive from the same untrusted stream and are never
    /// checked against each other, so a peer can point any type at any bytes; every case
    /// here sweeps all fifteen.
    ///
    /// Payloads one byte away from valid rather than uniform bytes, which this file used to
    /// draw 2048 of beside them. Uniform bytes reach the code past a length prefix or an
    /// enum discriminant essentially never — a draw is a `HelloOk` only if it came out 18
    /// bytes long and its last two landed in three values of 256 and two of 256 — so the
    /// branches they can reach are the shallow refusals a mutated encoding reaches too, and
    /// reaches far more often. What only the mutation reaches is the far side: a `term_len`
    /// larger than what follows, a reserved flag bit set, a truncated final field. So the
    /// uniform draw bought cases rather than coverage, and the search that does buy coverage
    /// here is `fuzz/frame`, which keeps whatever got further and builds on it.
    #[test]
    fn mutated_encodings_decode_without_panicking() {
        for case in 0..CASES {
            let seed = case_seed(0x0006, case);
            let mut rng = Rng::new(seed);
            let owned = frame(&mut rng);
            // Nothing to mutate where nothing encodes; the round-trip sweep is where
            // those cases are spent.
            if refused_by_design(owned.frame()).is_some() {
                continue;
            }
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

    /// Replays the durable part of fuzzing under the ordinary test gate.
    ///
    /// The sanitizer job is intentionally time-boxed and is not a publish dependency;
    /// committed regression inputs must not inherit that exemption. Reading the target's seed directory here
    /// makes every checked-in payload a deterministic, stable test without duplicating the
    /// target's invariants or its corpus in a second location.
    #[test]
    fn every_committed_fuzz_seed_is_a_stable_regression() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/frame");
        let mut paths = fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()
            .unwrap_or_else(|err| panic!("enumerate {}: {err}", dir.display()));
        paths.sort();
        assert!(
            !paths.is_empty(),
            "{} has no committed seeds",
            dir.display()
        );

        for path in paths {
            let payload = fs::read(&path)
                .unwrap_or_else(|err| panic!("read fuzz seed {}: {err}", path.display()));
            if let Err(complaint) = decode_as_every_type(&payload) {
                panic!("fuzz seed {}: {complaint}", path.display());
            }
        }
    }
}

/// Byte-exact conformance to `IMPLEMENTATION.md` § 2.2 and the language-neutral fixture.
mod vectors {
    use std::{cell::Cell, fmt::Debug};

    use nomux_protocol::{
        ErrorCode, ExitKind, Frame, FrameType, HEADER_LEN, Hello, HelloOk, MAX_PAYLOAD,
        PROTOCOL_VERSION, RESUME_FROM_START, SERVER_PREAMBLE, WinSize,
    };

    const FIXTURE: &str = include_str!("wire-vectors.txt");

    /// Distinct in all four fields on purpose: `cols`, `rows`, `xpixel` and `ypixel`
    /// share a layout and a width, so equal values would hide a transposition.
    const WIN: WinSize = WinSize {
        cols: 120,
        rows: 40,
        xpixel: 960,
        ypixel: 640,
    };

    /// This marker belongs to the response stream rather than to any frame, so it has
    /// its own byte-exact pin beside the frame vectors.
    #[test]
    fn the_server_preamble_is_pinned() {
        assert_eq!(
            SERVER_PREAMBLE,
            &[
                0x00, 0x6e, 0x6f, 0x6d, 0x75, 0x78, 0x2d, 0x73, 0x79, 0x6e, 0x63, 0xff
            ]
        );
    }

    /// One frame and the exact bytes § 2.2 says it is.
    struct Vector {
        frame: Frame<'static>,
        bytes: &'static [u8],
    }

    /// Every vector in discriminant order, with distinct values for adjacent fields.
    fn vectors() -> Vec<Vector> {
        let mut all = hello_vectors();
        all.extend(hello_ok_vectors());
        all.extend(stream_vectors());
        all.extend(control_vectors());
        all.extend(error_vectors());
        all.extend(agent_vectors());
        all
    }

    /// The client's opening frame, at four flag words that pin all three bits.
    fn hello_vectors() -> Vec<Vector> {
        vec![
            // 0x01 Hello: u16 proto, u8 flags, u64 out_offset, winsize, u16 term_len,
            // term bytes. The revision is two bytes and the flags one, so no swap between
            // them is even representable — §2.3's "no reserved space", made in bytes.
            Vector {
                frame: Frame::Hello(Hello {
                    protocol: 11,
                    agent_forward: true,
                    repaint_ctrl_l: true,
                    if_detached: true,
                    out_offset: 0x0102_0304_0506_0708,
                    win: WIN,
                    term: "xterm-256color",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x23, // header: type, u24 len = 35
                    0x00, 0x0b, // protocol
                    0x07, // flags: agent forward, repaint ctrl-l, if detached
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // out_offset
                    0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                    0x00, 0x0e, // term_len = 14
                    b'x', b't', b'e', b'r', b'm', b'-', b'2', b'5', b'6', b'c', b'o', b'l', b'o',
                    b'r',
                ],
            },
            // 0x01 Hello again, with bit 0 alone, which starts pinning *which* bit is
            // which: above, all are set, so exchanging them leaves 0x07 unchanged.
            // Carries `RESUME_FROM_START` as well, which no other vector shows.
            Vector {
                frame: Frame::Hello(Hello {
                    protocol: 11,
                    agent_forward: true,
                    repaint_ctrl_l: false,
                    if_detached: false,
                    out_offset: RESUME_FROM_START,
                    win: WIN,
                    term: "vt100",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x1a, // header: type, u24 len = 26
                    0x00, 0x0b, // protocol
                    0x01, // flags: bit 0 agent forward, bit 1 clear
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // RESUME_FROM_START
                    0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                    0x00, 0x05, // term_len = 5
                    b'v', b't', b'1', b'0', b'0',
                ],
            },
            // 0x01 Hello a third time, with all bits clear. Bit 0 is set in both of the
            // vectors above, so this is the only one that pins it clear.
            Vector {
                frame: Frame::Hello(Hello {
                    protocol: 11,
                    agent_forward: false,
                    repaint_ctrl_l: false,
                    if_detached: false,
                    out_offset: 0x8182_8384_8586_8788,
                    win: WIN,
                    term: "dumb",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x19, // header: type, u24 len = 25
                    0x00, 0x0b, // protocol
                    0x00, // flags: all bits clear
                    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, // out_offset
                    0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                    0x00, 0x04, // term_len = 4
                    b'd', b'u', b'm', b'b',
                ],
            },
            // 0x01 Hello a fourth time, for the empty `term` — the first of the three
            // zero-length variable fields § 2.2 permits and this table used to show none
            // of. An implementation that reads `term_len` and then insists on at least one
            // byte behind it passes every vector above and is still wrong, and the client
            // is the end that would have to be rewritten to find out.
            //
            // Carries bit 1 alone, the one flag word the three above leave out, and
            // `out_offset` 0, which is the client asking for the stream from its first byte
            // rather than for whatever is retained — a distinction `RESUME_FROM_START`
            // above exists to make.
            Vector {
                frame: Frame::Hello(Hello {
                    protocol: 11,
                    agent_forward: false,
                    repaint_ctrl_l: true,
                    if_detached: false,
                    out_offset: 0,
                    win: WIN,
                    term: "",
                }),
                bytes: &[
                    0x01, 0x00, 0x00, 0x15, // header: type, u24 len = 21
                    0x00, 0x0b, // protocol
                    0x02, // flags: bit 0 clear, bit 1 repaint ctrl-l
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // out_offset
                    0x00, 0x78, 0x00, 0x28, 0x03, 0xc0, 0x02, 0x80, // winsize
                    0x00, 0x00, // term_len = 0, and nothing behind it
                ],
            },
        ]
    }

    /// The daemon's answer, at both agent states.
    fn hello_ok_vectors() -> Vec<Vector> {
        vec![
            // 0x02 HelloOk: u64 resume_from, u64 in_applied, u8 flags. It carries
            // neither a revision nor a winsize (§ 2.2) — both would only repeat what
            // the client just sent.
            Vector {
                frame: Frame::HelloOk(HelloOk {
                    resume_from: 0x2122_2324_2526_2728,
                    in_applied: 0x3132_3334_3536_3738,
                    agent: true,
                }),
                bytes: &[
                    0x02, 0x00, 0x00, 0x11, // header: type, u24 len = 17
                    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // resume_from
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // in_applied
                    0x01, // flags: bit 0 agent
                ],
            },
            // 0x02 HelloOk again, with the agent bit clear.
            Vector {
                frame: Frame::HelloOk(HelloOk {
                    resume_from: 0x4142_4344_4546_4748,
                    in_applied: 0x5152_5354_5556_5758,
                    agent: false,
                }),
                bytes: &[
                    0x02, 0x00, 0x00, 0x11, // header: type, u24 len = 17
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // resume_from
                    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, // in_applied
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
            // 0x05 Output again, carrying nothing: the second of the three empty fields, and
            // a different way to be empty from the `Hello` above — `data` runs to the end of
            // the payload where `term` sits behind a count, so this one is a payload that is
            // exactly its fixed prefix, which is the length a decoder demanding "an offset
            // *and* some bytes" refuses. An implementation can get either right alone.
            Vector {
                frame: Frame::Output {
                    offset: 0xa1a2_a3a4_a5a6_a7a8,
                    data: b"",
                },
                bytes: &[
                    0x05, 0x00, 0x00, 0x08, // header: len = 8 + 0
                    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, // offset
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
            // 0x08 Exit: i32 status, u8 kind (0 exited, 1 signalled, 2 unknown), u32
            // since_terminal_closed_secs. The kind byte sits *between* the two four-byte fields and
            // does not stop them being exchanged, so the pair are given values that
            // disagree in every byte here and are all-ones against all-zeros below —
            // which is the transposition this file exists to catch, at the one place on
            // this wire where two same-width fields are adjacent but for a byte.
            Vector {
                frame: Frame::Exit {
                    status: 130,
                    kind: ExitKind::Signalled,
                    since_terminal_closed_secs: 0x0a0b_0c0d,
                },
                bytes: &[
                    0x08, 0x00, 0x00, 0x09, //
                    0x00, 0x00, 0x00, 0x82, // status
                    0x01, // signalled
                    0x0a, 0x0b, 0x0c, 0x0d, // since_terminal_closed_secs
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
                    since_terminal_closed_secs: 0,
                },
                bytes: &[
                    0x08, 0x00, 0x00, 0x09, //
                    0xff, 0xff, 0xff, 0xff, // status
                    0x00, // exited
                    0x00, 0x00, 0x00, 0x00, // since_terminal_closed_secs
                ],
            },
            // A closed terminal does not prove the child chose status zero. `Unknown`
            // carries the sentinel status 0 the daemon sends, and the elapsed time.
            Vector {
                frame: Frame::Exit {
                    status: 0,
                    kind: ExitKind::Unknown,
                    since_terminal_closed_secs: 0x1020_3040,
                },
                bytes: &[
                    0x08, 0x00, 0x00, 0x09, //
                    0x00, 0x00, 0x00, 0x00, // sentinel unknown status
                    0x02, // unknown
                    0x10, 0x20, 0x30, 0x40, // since_terminal_closed_secs
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
        ]
    }

    /// 0x0c `Error`: u16 code, UTF-8 message with no length prefix — it runs to the end of
    /// the payload. All six codes, one vector each.
    ///
    /// A group of its own because it is the one most easily left half-written. `Error` is
    /// the last frame a connection ever carries (§ 6.4), so it is what a client mishandles
    /// exactly when the session is being torn down and the user is watching: a code read as
    /// the wrong number is a takeover reported as an internal fault, or a version mismatch
    /// retried forever. The set is closed (§ 2.3), so a code the peer does not know is a
    /// protocol error rather than something to skip past, and deducing five of the six from
    /// `Takeover` is arithmetic rather than a test.
    ///
    /// The messages differ in length on purpose — the field has no count in front of it and
    /// runs to the end of the payload, so a decoder that took a fixed width would agree with
    /// one vector and no more — and `Internal` carries none at all, which § 2.2 permits and
    /// nothing else in this table shows for `message`.
    fn error_vectors() -> Vec<Vector> {
        vec![
            Vector {
                frame: Frame::Error {
                    code: ErrorCode::Protocol,
                    message: "bad frame",
                },
                bytes: &[
                    0x0c, 0x00, 0x00, 0x0b, // header: len = 2 + 9
                    0x00, 0x01, // Protocol
                    b'b', b'a', b'd', b' ', b'f', b'r', b'a', b'm', b'e',
                ],
            },
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
            Vector {
                frame: Frame::Error {
                    code: ErrorCode::Version,
                    message: "wrong version",
                },
                bytes: &[
                    0x0c, 0x00, 0x00, 0x0f, // header: len = 2 + 13
                    0x00, 0x03, // Version
                    b'w', b'r', b'o', b'n', b'g', b' ', b'v', b'e', b'r', b's', b'i', b'o', b'n',
                ],
            },
            Vector {
                frame: Frame::Error {
                    code: ErrorCode::InputGap,
                    message: "input gap",
                },
                bytes: &[
                    0x0c, 0x00, 0x00, 0x0b, // header: len = 2 + 9
                    0x00, 0x04, // InputGap
                    b'i', b'n', b'p', b'u', b't', b' ', b'g', b'a', b'p',
                ],
            },
            Vector {
                frame: Frame::Error {
                    code: ErrorCode::Internal,
                    message: "",
                },
                bytes: &[
                    0x0c, 0x00, 0x00, 0x02, // header: len = 2 + 0
                    0x00, 0x05, // Internal, and nothing behind it
                ],
            },
            Vector {
                frame: Frame::Error {
                    code: ErrorCode::AlreadyAttached,
                    message: "already attached",
                },
                bytes: &[
                    0x0c, 0x00, 0x00, 0x12, // header: len = 2 + 16
                    0x00, 0x06, // AlreadyAttached
                    b'a', b'l', b'r', b'e', b'a', b'd', b'y', b' ', b'a', b't', b't', b'a', b'c',
                    b'h', b'e', b'd',
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

    /// The encoder emits exactly the bytes § 2.2 specifies, and the decoder reads those same
    /// bytes back as the frame they describe.
    ///
    /// Both directions off the same literal, and neither off the other's output: the decode
    /// is handed `bytes`, never the buffer `encode` has just filled, so what is asserted is
    /// never `decode(encode(f)) == f` — the self-consistency check these vectors exist to
    /// supplement.
    ///
    /// The header is not decoded separately on the way back in. Comparing the whole encoding
    /// against `bytes` has already pinned all four of its literal bytes, discriminant and
    /// u24 length included, so re-reading them through `decode_header` and asserting they
    /// describe the frame they precede would only ask whether `decode_header` inverts
    /// `encode_header` — which is `lib.rs`'s `header_round_trips`, in its own file.
    #[test]
    fn frames_encode_to_their_documented_bytes_and_decode_back() {
        for Vector { frame, bytes } in vectors() {
            let mut encoded = Vec::new();
            frame.encode(&mut encoded).unwrap();
            assert_eq!(
                encoded,
                bytes,
                "{:?} does not encode to the bytes IMPLEMENTATION.md § 2.2 specifies",
                frame.frame_type()
            );
            assert_eq!(
                Frame::decode(frame.frame_type(), &bytes[HEADER_LEN..]),
                Ok(frame),
                "the bytes IMPLEMENTATION.md § 2.2 specifies for {:?} do not decode back",
                frame.frame_type()
            );
        }
    }

    /// A value as the fixture's grammar writes one.
    ///
    /// Hex is decoded at the line that carries it rather than where it is read, so a value
    /// that is not hex names its own line. What the bytes then mean — a number as wide as its
    /// field, or the field's own bytes — is the frame type's business, and is read below.
    enum Value<'a> {
        /// Lowercase hex behind an `0x`. An empty `term` is this, carrying nothing.
        Hex(Vec<u8>),
        /// A bare word: `true`, `false`, an enumerator, or the decimal `status` is written in.
        Word(&'a str),
    }

    /// One `key value` line under a `frame`.
    struct Field<'a> {
        /// Where it was written, so a complaint can name it.
        line: usize,
        /// The key, spelled as § 2.2 names that field.
        key: &'a str,
        /// The value under it.
        value: Value<'a>,
        /// Whether the frame this record describes asked for it.
        ///
        /// The one risk a parser runs and a renderer does not: a reader that stepped over what
        /// it did not recognise would turn a mistyped key into a field this file quietly stops
        /// pinning, and the fixture into a no-op one line at a time.
        read: Cell<bool>,
    }

    /// A `frame` line, the fields under it, and the `bytes` that close it.
    struct Record<'a> {
        /// The line the `frame` sits on.
        line: usize,
        /// The message it names, spelled as the [`FrameType`] variant.
        name: &'a str,
        /// The fields under it, read below by name — so a file whose lines were reordered
        /// still passes, and what is pinned is the value under each key.
        fields: Vec<Field<'a>>,
        /// The whole frame, four-byte header included, once `closed`.
        bytes: Vec<u8>,
        /// Whether a `bytes` line has closed it. Tracked rather than read off `bytes`, the
        /// grammar letting `0x` stand for no bytes at all.
        closed: bool,
    }

    /// One lowercase hex digit. Uppercase is refused rather than folded: the grammar writes
    /// one spelling, and a file written in two is one whose diffs stop reading cleanly.
    fn nibble(digit: char) -> Option<u8> {
        if digit.is_ascii_uppercase() {
            return None;
        }
        u8::try_from(digit.to_digit(16)?).ok()
    }

    /// The bytes behind an `0x`, or what is wrong with the value.
    fn hex(line: usize, value: &str) -> Result<Vec<u8>, String> {
        let complaint =
            || format!("wire-vectors.txt:{line}: `{value}` is not lowercase hex behind an `0x`");
        let mut digits = value.strip_prefix("0x").ok_or_else(complaint)?.chars();
        let mut bytes = Vec::new();
        while let Some(high) = digits.next() {
            let low = digits.next().ok_or_else(complaint)?;
            let (Some(high), Some(low)) = (nibble(high), nibble(low)) else {
                return Err(complaint());
            };
            bytes.push((high << 4) | low);
        }
        Ok(bytes)
    }

    /// The value of a closed set that `Debug` spells `word`, swept from the set's own `ALL` so
    /// that a value added to the protocol is spelled here without this being edited.
    fn by_name<T: Copy + Debug>(all: &[T], word: &str) -> Option<T> {
        all.iter()
            .copied()
            .find(|value| format!("{value:?}") == word)
    }

    impl Record<'_> {
        /// A complaint about one of this record's fields.
        fn wrong(&self, key: &str, detail: &str) -> String {
            format!(
                "wire-vectors.txt:{}: `{key}` under this `frame {}` {detail}",
                self.line, self.name
            )
        }

        /// The value under `key`, marked read.
        fn value(&self, key: &str) -> Result<&Value<'_>, String> {
            let field = self
                .fields
                .iter()
                .find(|field| field.key == key)
                .ok_or_else(|| self.wrong(key, "is missing"))?;
            field.read.set(true);
            Ok(&field.value)
        }

        /// A field the grammar writes in hex.
        fn bytes(&self, key: &str) -> Result<&[u8], String> {
            match self.value(key)? {
                Value::Hex(bytes) => Ok(bytes),
                Value::Word(_) => Err(self.wrong(key, "is not `0x` hex")),
            }
        }

        /// A field the grammar writes as a bare word.
        fn word(&self, key: &str) -> Result<&str, String> {
            match self.value(key)? {
                Value::Word(word) => Ok(word),
                Value::Hex(_) => Err(self.wrong(key, "is hex where a word belongs")),
            }
        }

        /// A number as wide as § 2.2 gives it, big-endian.
        ///
        /// The width is the array's, so a value written short — which the grammar's
        /// zero-padding rules out and a hand-edit does not — fails here rather than reading
        /// back as a number that happens to be equal.
        fn fixed<const N: usize>(&self, key: &str) -> Result<[u8; N], String> {
            let bytes = self.bytes(key)?;
            let width = bytes.len();
            <[u8; N]>::try_from(bytes)
                .map_err(|_| self.wrong(key, &format!("is {width} bytes, not § 2.2's {N}")))
        }

        /// A `u16` field.
        fn u16(&self, key: &str) -> Result<u16, String> {
            Ok(u16::from_be_bytes(self.fixed(key)?))
        }

        /// A `u32` field.
        fn u32(&self, key: &str) -> Result<u32, String> {
            Ok(u32::from_be_bytes(self.fixed(key)?))
        }

        /// A `u64` field.
        fn u64(&self, key: &str) -> Result<u64, String> {
            Ok(u64::from_be_bytes(self.fixed(key)?))
        }

        /// The one signed field on this wire, and so the one value written in decimal: a
        /// two's-complement pattern is a reinterpretation the fixture does not ask for.
        fn decimal(&self, key: &str) -> Result<i32, String> {
            let word = self.word(key)?;
            word.parse()
                .map_err(|_| self.wrong(key, "is no decimal `i32`"))
        }

        /// A flag, where § 2.3 has a bit.
        fn flag(&self, key: &str) -> Result<bool, String> {
            match self.word(key)? {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(self.wrong(key, "is neither `true` nor `false`")),
            }
        }

        /// A text field: bytes here, UTF-8 on the wire (§ 2.2).
        fn text(&self, key: &str) -> Result<&str, String> {
            str::from_utf8(self.bytes(key)?).map_err(|_| self.wrong(key, "is not UTF-8"))
        }

        /// An enumerator of a closed set, by the name it is written under.
        fn enumerator<T: Copy + Debug>(&self, key: &str, all: &[T]) -> Result<T, String> {
            let word = self.word(key)?;
            by_name(all, word).ok_or_else(|| self.wrong(key, "names no value § 2.2 gives it"))
        }

        /// The four fields of a winsize, wherever one is written out.
        fn win(&self) -> Result<WinSize, String> {
            Ok(WinSize {
                cols: self.u16("cols")?,
                rows: self.u16("rows")?,
                xpixel: self.u16("xpixel")?,
                ypixel: self.u16("ypixel")?,
            })
        }

        /// The frame this record describes, built from its field lines.
        ///
        /// From the fields and never from `bytes`, which are what the frame is then held
        /// against: a record decoded from its own bytes would agree with itself while every
        /// field line above them went unread. The match is exhaustive on [`FrameType`], so a
        /// frame added to the protocol is one this has to learn to read rather than one the
        /// fixture silently never carries.
        fn frame(&self) -> Result<Frame<'_>, String> {
            let Some(frame_type) = by_name(&FrameType::ALL, self.name) else {
                return Err(format!(
                    "wire-vectors.txt:{}: `{}` names no frame in § 2.2's table",
                    self.line, self.name
                ));
            };
            let frame = match frame_type {
                FrameType::Hello => Frame::Hello(Hello {
                    protocol: self.u16("protocol")?,
                    agent_forward: self.flag("agent_forward")?,
                    repaint_ctrl_l: self.flag("repaint_ctrl_l")?,
                    if_detached: self.flag("if_detached")?,
                    out_offset: self.u64("out_offset")?,
                    win: self.win()?,
                    term: self.text("term")?,
                }),
                FrameType::HelloOk => Frame::HelloOk(HelloOk {
                    resume_from: self.u64("resume_from")?,
                    in_applied: self.u64("in_applied")?,
                    agent: self.flag("agent")?,
                }),
                FrameType::Input => Frame::Input {
                    offset: self.u64("offset")?,
                    data: self.bytes("data")?,
                },
                FrameType::InputAck => Frame::InputAck {
                    applied_through: self.u64("applied_through")?,
                },
                FrameType::Output => Frame::Output {
                    offset: self.u64("offset")?,
                    data: self.bytes("data")?,
                },
                FrameType::Resize => Frame::Resize(self.win()?),
                FrameType::Gap => Frame::Gap {
                    new_base_offset: self.u64("new_base_offset")?,
                },
                FrameType::Exit => Frame::Exit {
                    status: self.decimal("status")?,
                    kind: self.enumerator("kind", &ExitKind::ALL)?,
                    since_terminal_closed_secs: self.u32("since_terminal_closed_secs")?,
                },
                FrameType::Detach => Frame::Detach,
                FrameType::Ping => Frame::Ping,
                FrameType::Pong => Frame::Pong,
                FrameType::Error => Frame::Error {
                    code: self.enumerator("code", &ErrorCode::ALL)?,
                    message: self.text("message")?,
                },
                FrameType::AgentOpen => Frame::AgentOpen {
                    generation: self.u32("generation")?,
                },
                FrameType::AgentData => Frame::AgentData {
                    generation: self.u32("generation")?,
                    data: self.bytes("data")?,
                },
                FrameType::AgentClose => Frame::AgentClose {
                    generation: self.u32("generation")?,
                },
            };

            if let Some(field) = self.fields.iter().find(|field| !field.read.get()) {
                return Err(format!(
                    "wire-vectors.txt:{}: `{}` is a line no {frame_type:?} reads — a key that \
                     frame does not have, or a second value under one it does",
                    field.line, field.key
                ));
            }
            Ok(frame)
        }
    }

    /// The fixture's records in file order, or the first thing about it that is not the
    /// grammar its own header states.
    ///
    /// Every line opens a record, closes one, or lands in the open one; a key with nowhere to
    /// go fails rather than being stepped over. Blank lines, `#` comments and the alignment
    /// are all that is thrown away, so a re-commented or hand-aligned file still passes and
    /// only the data is pinned.
    fn records(text: &str) -> Result<Vec<Record<'_>>, String> {
        let mut records: Vec<Record<'_>> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let (line, raw) = (index + 1, raw.trim());
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let complaint = |detail| format!("wire-vectors.txt:{line}: `{raw}` {detail}");
            let Some((key, value)) = raw.split_once(char::is_whitespace) else {
                return Err(complaint("is a key with no value"));
            };
            let value = value.trim();
            if key == "frame" {
                records.push(Record {
                    line,
                    name: value,
                    fields: Vec::new(),
                    bytes: Vec::new(),
                    closed: false,
                });
            } else if let Some(record) = records.last_mut().filter(|record| !record.closed) {
                if key == "bytes" {
                    record.bytes = hex(line, value)?;
                    record.closed = true;
                } else {
                    let value = match value.strip_prefix("0x") {
                        Some(_) => Value::Hex(hex(line, value)?),
                        None => Value::Word(value),
                    };
                    let field = Field {
                        line,
                        key,
                        value,
                        read: Cell::new(false),
                    };
                    record.fields.push(field);
                }
            } else {
                return Err(complaint(
                    "is under no open record, preceding the first `frame` or following the \
                     `bytes` that closed one",
                ));
            }
        }
        if let Some(open) = records.iter().find(|record| !record.closed) {
            return Err(format!(
                "wire-vectors.txt:{}: this `frame {}` reaches the end of the file with no \
                 `bytes` line to close it",
                open.line, open.name
            ));
        }
        Ok(records)
    }

    /// The independently transcribed fixture must describe the same frames and bytes.
    #[test]
    fn the_hex_fixture_carries_the_same_table() {
        let records = records(FIXTURE).unwrap_or_else(|complaint| panic!("{complaint}"));
        let table = vectors();

        for (index, record) in records.iter().enumerate() {
            let Some(&Vector { frame, bytes }) = table.get(index) else {
                panic!(
                    "wire-vectors.txt:{} carries a `frame {}` no vector in this table answers",
                    record.line, record.name
                );
            };
            let carried = record
                .frame()
                .unwrap_or_else(|complaint| panic!("{complaint}"));
            assert_eq!(
                carried, frame,
                "wire-vectors.txt:{} describes a frame this table writes otherwise",
                record.line
            );
            assert_eq!(
                record.bytes,
                bytes,
                "wire-vectors.txt:{} gives {:?} bytes this table does not",
                record.line,
                frame.frame_type()
            );
        }

        if let Some(Vector { frame, .. }) = table.get(records.len()) {
            panic!(
                "this table holds a {:?} vector that wire-vectors.txt has no record for",
                frame.frame_type()
            );
        }
    }

    /// Every value of each closed wire set and both states of every flag are covered.
    #[test]
    fn the_vectors_pin_every_value_of_every_closed_set() {
        let mut types = Vec::new();
        let mut kinds = Vec::new();
        let mut codes = Vec::new();
        let mut hello_flags = Vec::new();
        let mut agent_flags = Vec::new();

        for Vector { frame, .. } in vectors() {
            types.push(frame.frame_type());
            match frame {
                Frame::Hello(Hello {
                    protocol,
                    agent_forward,
                    repaint_ctrl_l,
                    if_detached,
                    out_offset: _,
                    win: _,
                    term: _,
                }) => {
                    assert_eq!(
                        protocol, PROTOCOL_VERSION,
                        "a handshake vector is written at a revision the daemon would \
                         refuse: {frame:?}"
                    );
                    hello_flags.push([agent_forward, repaint_ctrl_l, if_detached]);
                }
                Frame::HelloOk(HelloOk {
                    resume_from: _,
                    in_applied: _,
                    agent,
                }) => agent_flags.push(agent),
                Frame::Exit { kind, .. } => kinds.push(kind),
                Frame::Error { code, .. } => codes.push(code),
                _ => {}
            }
        }

        for ty in FrameType::ALL {
            assert!(types.contains(&ty), "{ty:?} has no wire vector");
        }
        for kind in ExitKind::ALL {
            assert!(kinds.contains(&kind), "{kind:?} has no wire vector");
        }
        for code in ErrorCode::ALL {
            assert!(codes.contains(&code), "{code:?} has no wire vector");
        }
        for (state, verb) in [(true, "sets"), (false, "clears")] {
            for (bit, name) in [
                (0, "agent_forward"),
                (1, "repaint_ctrl_l"),
                (2, "if_detached"),
            ] {
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
        ///
        /// One direction only. `wire_enum!` writes `as_wire` and `from_wire` from the same
        /// literal — the former reads the `#[repr]` discriminant that literal declares, the
        /// latter matches on the literal itself — and two variants cannot share one, a
        /// duplicate discriminant being a compile error. So `from_wire(n) == Some(v)`
        /// follows from `v.as_wire() == n` with nothing left to falsify.
        macro_rules! frozen {
            ($ty:ty, $($name:ident = $number:literal),+) => {
                for (value, number) in [$((<$ty>::$name, $number)),+] {
                    assert_eq!(value.as_wire(), number, "{value:?} is not the § 2.2 number");
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
                11,
                "§ 2.2 puts the current revision at 11",
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
            Internal = 5,
            AlreadyAttached = 6
        );
        frozen!(ExitKind, Exited = 0, Signalled = 1, Unknown = 2);
    }
}
