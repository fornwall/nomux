//! `Frame::decode` over arbitrary payloads, pointed at every frame type
//! (`IMPLEMENTATION.md` § 2.2).
//!
//! The two properties are `crates/nomux/tests/codec.rs`'s `decode_as_every_type`, verbatim
//! in what they assert:
//!
//! * a frame decodes as the type it was asked for, so no payload can arrive as one message
//!   and leave as another;
//! * an accepted payload is the *only* encoding of what it decoded to. A decoder taking two
//!   spellings of one frame lets a peer smuggle bytes past anything downstream that
//!   compares encodings.
//!
//! What differs is the generator, and here that is the whole point — unlike `header`, whose
//! domain that suite closes. `payload_decode_is_total` draws 2048 payloads of up to 40
//! uniform bytes, which reach the code past a length prefix or an enum discriminant
//! essentially never; `mutated_encodings_decode_without_panicking` buys that back by XORing
//! one byte of a real encoding and sometimes dropping the last, which lands on the
//! boundaries but never more than that one edit from valid. Coverage feedback needs neither
//! arrangement: it keeps whatever got further and builds on it, and it gets tens of millions
//! of tries rather than four thousand.
//!
//! The input is a payload rather than a whole frame. The type byte and the bytes behind it
//! arrive from the same untrusted stream and are never checked against each other, so a
//! peer can point any type at any payload; sweeping all fifteen per case reaches every
//! decoder from one input and takes the type byte out of the mutator's search space, where
//! it would otherwise spend most of its draws on the 241 discriminants that return before
//! reading anything. `header` is the target that owns those.
//!
//! The seeds in `fuzz/seeds/frame` are § 2.2's frame table with each four-byte header cut
//! off — one payload per frame type, taken from `crates/nomux/tests/wire-vectors.txt`,
//! which is the document's bytes rather than this codec's. `Detach`, `Ping` and `Pong` are
//! left out: their payload is the empty input, which libFuzzer tries first regardless.
//!
//! Note the bound this does not reach: `MAX_PAYLOAD` is 256 KiB and libFuzzer's default
//! `-max_len` is 4096, so the oversize refusal at the top of `decode` stays covered by
//! `a_payload_over_the_maximum_is_refused_by_decode` alone. Raising `-max_len` to 262145
//! would buy that one branch at the cost of every exec, which is the wrong trade for a
//! search.
//!
//! The lint wall in `../Cargo.toml` — `unwrap_used`, `panic`, `indexing_slicing` — does not
//! reach this workspace, and would be backwards here if it did. It stands because a daemon
//! that panics loses the user's session; a fuzz target that panics is a fuzz target
//! reporting its finding, and the assertions below are the whole point of the binary.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nomux::{Frame, FrameType, HEADER_LEN};

fuzz_target!(|payload: &[u8]| {
    // One buffer for the whole sweep: `encode` appends, so clearing is the rewind.
    let mut buf = Vec::new();

    // `FrameType::ALL` comes from the discriminant list in lib.rs, so a type added to the
    // protocol is fuzzed without anyone remembering to add it here.
    for ty in FrameType::ALL {
        let Ok(frame) = Frame::decode(ty, payload) else {
            continue;
        };
        assert_eq!(
            frame.frame_type(),
            ty,
            "{payload:02x?} was decoded as {ty:?} and came back a different type"
        );

        buf.clear();
        if let Err(err) = frame.encode(&mut buf) {
            panic!("decode accepted {frame:?}, which encode then refused: {err}");
        }
        assert_eq!(
            buf.get(HEADER_LEN..),
            Some(payload),
            "accepted a non-canonical encoding of {frame:?}"
        );
    }
});
