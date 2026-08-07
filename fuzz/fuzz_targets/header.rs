//! `decode_header` over the four bytes a peer sends before anything has been checked
//! (`IMPLEMENTATION.md` § 2.1).
//!
//! Worth being plain about what this adds, which is not coverage of the domain.
//! `crates/nomux/tests/codec.rs`'s `header_decode_is_total` already sweeps all 256 type
//! bytes against both sides of the `MAX_PAYLOAD` cap, and `decode_header` has no third
//! thing it does — so the input space is closed there, on stable, in well under a second.
//! What is left here is the one assertion that suite cannot make about itself, plus a
//! sanitiser under the whole thing and an entry point somebody fuzzing this protocol will
//! look for.
//!
//! The assertion: `check_header` compares the decode against `FrameType::from_wire`, which
//! is the function `decode_header` is built out of, so that arm asserts only that a
//! function agrees with itself. Both type checks below go the other way instead — through
//! `as_wire` and through `FrameType::ALL` — and would survive `from_wire` being wrong.
//!
//! No seed corpus, alone among the targets here. The domain is four bytes and the live
//! discriminants are 0x01 through 0x0f, contiguous and low, which a byte mutator reaches
//! from the empty input before a corpus would have finished loading. Coverage guidance has
//! little to work with for the same reason those are easy — contiguous values compile to a
//! range check rather than fifteen arms — so a run plateaus at a few dozen edges within
//! seconds and everything after that is a blind sweep.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nomux::{FrameType, HEADER_LEN, MAX_PAYLOAD, ProtoError, decode_header};

fuzz_target!(|data: &[u8]| {
    let Some(header) = data.first_chunk::<HEADER_LEN>() else {
        return;
    };
    let [ty, a, b, c] = *header;
    let len = u32::from_be_bytes([0, a, b, c]);

    match decode_header(header) {
        Ok(decoded) => {
            // Asking the type that came back which byte it is on the wire, and getting
            // the byte that went in.
            assert_eq!(
                decoded.ty.as_wire(),
                ty,
                "{ty:#04x} came back as {:?}",
                decoded.ty
            );
            assert_eq!(decoded.len, len, "length is not the low 24 bits");
            // The one promise the rest of the daemon builds on: `conn.rs` sizes the read
            // that follows from this number.
            assert!(
                decoded.len <= MAX_PAYLOAD,
                "accepted an unbounded allocation of {len}"
            );
        }
        Err(ProtoError::UnknownFrameType(reported)) => {
            assert_eq!(reported, ty, "reported a byte it did not read");
            // Against the discriminant list, for the reason the module note gives.
            assert!(
                !FrameType::ALL.iter().any(|known| known.as_wire() == ty),
                "refused {ty:#04x}, which FrameType::ALL has"
            );
        }
        Err(ProtoError::PayloadTooLarge(reported)) => {
            assert_eq!(reported, len, "reported a length it did not read");
            assert!(len > MAX_PAYLOAD, "refused {len}, which is within the cap");
        }
        // Truncated, TrailingBytes and Malformed all describe a payload, and this
        // function has never seen one.
        Err(other) => panic!("header decode cannot produce {other:?}"),
    }
});
