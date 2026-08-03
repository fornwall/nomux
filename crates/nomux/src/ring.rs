//! Bounded output buffer addressed by absolute stream offset.
//!
//! The daemon must keep draining the PTY whether or not a client is attached —
//! otherwise the child blocks on write and the session looks frozen on reattach.
//! So when the buffer fills, the oldest bytes are discarded and a gap is recorded.
//! Losing scrollback is recoverable; a wedged shell is not.

use std::collections::VecDeque;

/// A rolling window over the tail of the output stream.
#[derive(Debug)]
pub(crate) struct Ring {
    buf: VecDeque<u8>,
    capacity: usize,
    base: u64,
}

impl Ring {
    /// Creates a ring retaining at most `capacity` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero, which would make every write a gap.
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "ring capacity must be non-zero");
        Self {
            buf: VecDeque::with_capacity(capacity),
            capacity,
            base: 0,
        }
    }

    /// Offset of the oldest retained byte.
    #[must_use]
    pub(crate) const fn base(&self) -> u64 {
        self.base
    }

    /// Offset one past the newest byte, i.e. the total ever written.
    #[must_use]
    pub(crate) fn end(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    /// Appends output, discarding from the front if it no longer fits.
    ///
    /// Discarding is not reported here. Whether a *reader* lost anything depends on
    /// where that reader had got to, so it is derived per client by comparing its
    /// position against [`Ring::base`] — which stays correct across any number of
    /// overflows, including ones that happened while the client was away.
    pub(crate) fn push(&mut self, data: &[u8]) {
        // One number for both sides of the eviction. What must fall out of the
        // window is `retained + new - capacity` however it is split, and `base` —
        // the offset of the oldest surviving byte — advances by the whole of it,
        // never by what came off one side. That is what a write larger than the
        // ring turns on: it keeps only its own tail, because everything before it
        // is unreachable anyway, so *both* everything already retained and the head
        // of this very write are gone. Counting only one of the two leaves `base`
        // too low.
        let overflow = (self.buf.len() + data.len()).saturating_sub(self.capacity);
        let from_buf = overflow.min(self.buf.len());
        self.base += overflow as u64;
        self.buf.drain(..from_buf);
        self.buf
            .extend(data.get(overflow - from_buf..).unwrap_or_default());
    }

    /// Returns the retained bytes at and after `from`, as the two halves of the
    /// underlying deque.
    ///
    /// `from` is clamped to [`Ring::base`], so a caller that has fallen behind
    /// silently resumes at the oldest retained byte — check [`Ring::base`] first if
    /// that needs reporting as a gap.
    ///
    /// The two stay in stream order and in place: either may be empty, the *first*
    /// one included once `from` is past the front half, so a caller walking them
    /// must skip an empty part rather than stop at one.
    #[must_use]
    pub(crate) fn slices_from(&self, from: u64) -> [&[u8]; 2] {
        let skip = usize::try_from(from.saturating_sub(self.base)).unwrap_or(usize::MAX);
        let (front, back) = self.buf.as_slices();
        [
            front.get(skip..).unwrap_or_default(),
            back.get(skip.saturating_sub(front.len())..)
                .unwrap_or_default(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concatenates what the ring would serve from `offset`.
    fn read_from(ring: &Ring, offset: u64) -> Vec<u8> {
        ring.slices_from(offset).concat()
    }

    #[test]
    fn offsets_track_total_written_not_retained() {
        let mut ring = Ring::new(4);
        ring.push(b"ab");
        assert_eq!((ring.base(), ring.end()), (0, 2));
        ring.push(b"cd");
        assert_eq!((ring.base(), ring.end()), (0, 4));
        ring.push(b"ef");
        assert_eq!(
            (ring.base(), ring.end()),
            (2, 6),
            "base advances by exactly what was dropped"
        );
    }

    /// An oversized write discards what was retained *as well as* its own head.
    ///
    /// Counting only its own head leaves `base` too low, and a caught-up client
    /// then sits above it — so the overflow is invisible, no `Gap` is sent, and the
    /// client splices a stream with a hole in it onto its scrollback believing it
    /// contiguous. That is the one failure this whole design exists to make
    /// impossible, so it is pinned at the arithmetic rather than end to end.
    #[test]
    fn an_oversized_write_accounts_for_what_it_evicts() {
        let mut ring = Ring::new(4);
        ring.push(b"abc");
        let caught_up = ring.end();

        ring.push(b"vwxyz");
        assert_eq!(
            (ring.base(), ring.end()),
            (4, 8),
            "offsets must still count every byte ever written"
        );
        assert!(
            caught_up < ring.base(),
            "a client that was caught up must now be below base, i.e. see a gap"
        );
        assert_eq!(read_from(&ring, ring.base()), b"wxyz");
    }

    #[test]
    fn serves_exact_ranges() {
        let mut ring = Ring::new(8);
        ring.push(b"abcdef");
        assert_eq!(read_from(&ring, 0), b"abcdef");
        assert_eq!(read_from(&ring, 3), b"def");
        assert_eq!(read_from(&ring, 6), b"");
    }

    #[test]
    fn reads_below_base_are_clamped() {
        let mut ring = Ring::new(4);
        ring.push(b"abcdefgh");
        assert_eq!(ring.base(), 4);
        assert_eq!(
            read_from(&ring, 0),
            b"efgh",
            "clamped to base, not panicking"
        );
        assert_eq!(read_from(&ring, 4), b"efgh");
    }

    #[test]
    fn write_larger_than_capacity_keeps_its_own_tail() {
        let mut ring = Ring::new(4);
        ring.push(b"abcdefghij");
        assert_eq!(read_from(&ring, ring.base()), b"ghij");
        assert_eq!(ring.end(), 10, "offsets still count every byte written");
        assert_eq!(ring.base(), 6);
    }

    #[test]
    fn wrapped_deque_is_served_in_order() {
        let mut ring = Ring::new(6);
        ring.push(b"abcdef");
        ring.push(b"ghi");
        let (front, back) = ring.buf.as_slices();
        assert!(
            !front.is_empty() && !back.is_empty(),
            "test needs a wrapped deque to be meaningful"
        );
        assert_eq!(read_from(&ring, ring.base()), b"defghi");
        assert_eq!(read_from(&ring, 5), b"fghi");
    }

    /// Chunks run past the ring's own capacity, so the oversized-write branch is
    /// exercised against the model rather than only by the case above.
    #[test]
    fn matches_a_reference_model() {
        let capacity = 16;
        let mut ring = Ring::new(capacity);
        let mut model: Vec<u8> = Vec::new();

        for round in 0u32..200 {
            let len = usize::try_from(round % 37).unwrap_or(0);
            let chunk: Vec<u8> = (0..len)
                .map(|i| u8::try_from((u64::from(round) + i as u64) % 251).unwrap_or(0))
                .collect();
            ring.push(&chunk);
            model.extend_from_slice(&chunk);

            let total = model.len() as u64;
            assert_eq!(ring.end(), total);
            let retained = model.len().min(capacity);
            assert_eq!(ring.base(), total - retained as u64);

            let expected = model.get(model.len() - retained..).unwrap_or(&[]);
            assert_eq!(read_from(&ring, ring.base()), expected, "round {round}");
        }
    }
}
