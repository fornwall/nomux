//! Fuzzes arbitrary payloads against every frame decoder. Any accepted payload must
//! round-trip canonically with the same type and an accurate header. Seed payloads come
//! from `crates/nomux/tests/wire-vectors.txt`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nomux_protocol::{Frame, FrameType, HEADER_LEN, decode_header};

fuzz_target!(|payload: &[u8]| {
    let mut buf = Vec::new();

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

        let header = match buf.first_chunk::<HEADER_LEN>().map(decode_header) {
            Some(Ok(header)) => header,
            Some(Err(err)) => panic!("{frame:?}: own header rejected: {err}"),
            None => panic!("encode emitted no header for {frame:?}"),
        };
        assert_eq!(
            header.ty,
            frame.frame_type(),
            "the header says one type and the frame behind it is {frame:?}"
        );
        assert_eq!(
            header.len as usize,
            payload.len(),
            "the declared length disagrees with the bytes written for {frame:?}"
        );
        assert_eq!(
            buf.get(HEADER_LEN..),
            Some(payload),
            "accepted a non-canonical encoding of {frame:?}"
        );
    }
});
