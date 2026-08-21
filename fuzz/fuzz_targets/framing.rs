//! Fuzzes the *stream framing* layer: the same byte stream cut into chunks two
//! different ways must yield the same frames.
//!
//! `crates/nomux/src/conn.rs`'s `fill`/`take_frame` pair is what a peer's bytes actually
//! arrive through, and it lives in the binary — a fuzz target cannot import from one,
//! which is why `lib.rs` and `frame.rs` are the `nomux_protocol` library target at all.
//! So this drives the equivalent loop over the two library entry points that `take_frame`
//! is built from, [`decode_header`] and [`Frame::decode`], and asserts the one property
//! that separates a framing bug from a decoding one: **where the reads fall must not
//! change what comes out**.
//!
//! Two readers over one stream. One is handed the whole buffer at once and pops frames
//! until it runs out or the framing is lost. The other is handed the same bytes in chunks
//! whose sizes come from the input's first byte, appending each to a pending buffer and
//! popping every whole frame it can before asking for more — which is `Conn::fill` and
//! `Conn::take_frame` in miniature. A header split across two reads, a length prefix split
//! from the payload it declares, a chunk carrying the tail of one frame and the head of
//! the next: all of them are ordinary draws here, and each is a state a reader that kept
//! its parse across reads incorrectly gets wrong. The two sequences, the reason each
//! stopped and the number of bytes each consumed are compared in full.
//!
//! What this does *not* reach, and cannot from outside the binary: `Conn`'s own buffer
//! management — `MAX_PENDING_READ`, its growth and compaction, and the refusal of a peer
//! that declares more than the reader will hold. Closing that needs the framing reader
//! moved into the library, which is a change to `conn.rs` rather than to this directory.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nomux_protocol::{Frame, FrameType, HEADER_LEN, decode_header};

/// Why a reader stopped, which is as much a part of the answer as the frames are: a
/// stream whose framing is lost must be given up at the same byte either way.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    /// Every byte was accounted for by whole frames.
    Drained,
    /// Fewer than a header's worth left, or a header whose payload has not all arrived.
    /// A live reader waits here for more bytes; both readers are out of stream.
    Partial,
    /// A header the protocol does not allow: an unknown type byte, or a length past
    /// `MAX_PAYLOAD`. The daemon closes the connection on this, so nothing may be read
    /// past it — and *where* it is found must not depend on how the bytes arrived.
    Lost,
}

/// What one reader made of the stream: the frames it handed on, in order, as the
/// boundaries it drew them at; why it stopped; and how far into the stream it got.
#[derive(Debug, PartialEq, Eq)]
struct Read {
    frames: Vec<(FrameType, Vec<u8>)>,
    stop: Stop,
    consumed: usize,
}

/// Pops one frame off the front of `pending`, or says why it could not.
///
/// The whole of `take_frame`'s arithmetic: a header, the length it declares, and the
/// payload behind it — with the payload copied out rather than borrowed, so the caller
/// may go on filling the buffer it came from.
fn take_frame(pending: &[u8]) -> Result<Option<(FrameType, Vec<u8>)>, Stop> {
    let Some(head) = pending.first_chunk::<HEADER_LEN>() else {
        return Ok(None);
    };
    let Ok(header) = decode_header(head) else {
        return Err(Stop::Lost);
    };
    let total = HEADER_LEN + header.len as usize;
    let Some(payload) = pending.get(HEADER_LEN..total) else {
        return Ok(None);
    };
    Ok(Some((header.ty, payload.to_vec())))
}

/// The reader that is handed the whole stream at once: the answer the chunked one below
/// has to agree with.
fn read_whole(stream: &[u8]) -> Read {
    let mut frames = Vec::new();
    let mut consumed = 0;
    loop {
        match take_frame(&stream[consumed..]) {
            Ok(Some((ty, payload))) => {
                consumed += HEADER_LEN + payload.len();
                frames.push((ty, payload));
            }
            Ok(None) => {
                let stop = if consumed == stream.len() {
                    Stop::Drained
                } else {
                    Stop::Partial
                };
                return Read {
                    frames,
                    stop,
                    consumed,
                };
            }
            Err(stop) => {
                return Read {
                    frames,
                    stop,
                    consumed,
                };
            }
        }
    }
}

/// The same stream through a reader that only ever sees a chunk at a time, keeping what
/// it could not use yet — `Conn::fill` followed by `Conn::take_frame` until it says no.
///
/// Chunk sizes come from `seed` rather than from a second input, so a finding is one file
/// and replays exactly. Never zero: a read of no bytes is not a read.
fn read_chunked(stream: &[u8], seed: u8) -> Read {
    let mut rng = u64::from(seed).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next_chunk = move || {
        // SplitMix64's finalizer, which is all a chunk size needs to be well spread.
        rng = rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        // One to nine bytes at a time: small against a four-byte header, so a header
        // split across reads is the common case rather than a rare one.
        1 + ((z ^ (z >> 31)) % 9) as usize
    };

    let mut frames = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut consumed = 0;
    let mut filled = 0;
    loop {
        loop {
            match take_frame(&pending) {
                Ok(Some((ty, payload))) => {
                    let total = HEADER_LEN + payload.len();
                    pending.drain(..total);
                    consumed += total;
                    frames.push((ty, payload));
                }
                Ok(None) => break,
                Err(stop) => {
                    return Read {
                        frames,
                        stop,
                        consumed,
                    };
                }
            }
        }
        if filled == stream.len() {
            let stop = if pending.is_empty() {
                Stop::Drained
            } else {
                Stop::Partial
            };
            return Read {
                frames,
                stop,
                consumed,
            };
        }
        let end = stream.len().min(filled + next_chunk());
        pending.extend_from_slice(&stream[filled..end]);
        filled = end;
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte chooses the chunking and the rest is the stream, so one input file
    // carries both and a crash replays with no state beside it.
    let Some((&seed, stream)) = data.split_first() else {
        return;
    };

    let whole = read_whole(stream);
    let chunked = read_chunked(stream, seed);
    assert_eq!(
        whole, chunked,
        "the same stream framed differently depending on where the reads fell \
         (chunk seed {seed})"
    );

    // And every boundary the framing drew is one the codec can be handed: a payload the
    // decoder refuses is a frame the daemon answers with `Error{PROTOCOL}`, which is a
    // decision about content and not about where the frame ended — but it must reach that
    // decision rather than a panic, at every split this target produced.
    for (ty, payload) in &whole.frames {
        if let Ok(frame) = Frame::decode(*ty, payload) {
            assert_eq!(
                frame.frame_type(),
                *ty,
                "{payload:02x?} was framed as {ty:?} and decoded as a different type"
            );
        }
    }
});
