//! Bounded output buffer addressed by absolute stream offset.
//!
//! Precedence when it fills: keep draining the PTY, drop the oldest bytes
//! (`IMPLEMENTATION.md` § 4.1). Losing scrollback is recoverable; a wedged shell
//! is not.

use std::collections::{TryReserveError, VecDeque};

/// A rolling window over the tail of the output stream.
#[derive(Debug)]
pub(crate) struct Ring {
    buf: VecDeque<u8>,
    /// Not `buf.capacity()`: the allocation may hold more than was asked for, so reading
    /// the window back off it would silently enlarge the protocol-visible retention.
    capacity: usize,
    base: u64,
}

impl Ring {
    /// Tries to create a ring retaining at most `capacity` bytes, and never fewer than one.
    ///
    /// The clamp is unreachable — `daemon::ring_capacity` filters zero — but clamping
    /// rather than asserting keeps an abort site out of a `panic = "abort"` binary.
    pub(crate) fn try_new(capacity: usize) -> Result<Self, TryReserveError> {
        let capacity = capacity.max(1);
        let mut buf = VecDeque::new();
        // Unlike `with_capacity`, this reports allocator refusal. The daemon performs
        // this reservation before publishing a socket or pidfile, so an aggressive
        // `NOMUX_RING_BYTES` under a tight address-space limit is a normal startup error
        // rather than an abort that strands run files.
        buf.try_reserve_exact(capacity)?;
        Ok(Self {
            buf,
            capacity,
            base: 0,
        })
    }

    /// Infallible spelling kept inside tests, whose tiny capacities are fixtures rather
    /// than hostile configuration.
    #[cfg(test)]
    pub(crate) fn new(capacity: usize) -> Self {
        Self::try_new(capacity).expect("reserve the test ring")
    }

    /// Offset of the oldest retained byte.
    pub(crate) const fn base(&self) -> u64 {
        self.base
    }

    /// Offset one past the newest byte, i.e. the total ever written.
    pub(crate) fn end(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    /// Appends output, discarding from the front if it no longer fits.
    ///
    /// Discarding is not reported here; whether a *reader* lost anything is derived
    /// per client from [`Ring::base`], for the reason `IMPLEMENTATION.md` § 4 gives.
    pub(crate) fn push(&mut self, data: &[u8]) {
        // One number for both sides of the eviction: what falls out of the window is
        // `retained + new - capacity` however it splits between the buffer's head and
        // this write's own, and `base` advances by the whole of it.
        let overflow = self
            .buf
            .len()
            .saturating_add(data.len())
            .saturating_sub(self.capacity);
        let from_buf = overflow.min(self.buf.len());
        self.base += overflow as u64;
        self.buf.drain(..from_buf);
        self.buf
            .extend(data.get(overflow - from_buf..).unwrap_or_default());
    }

    /// Returns the retained bytes at and after `from`, as the two halves of the underlying
    /// deque.
    ///
    /// `from` is clamped to [`Ring::base`], so a caller that has fallen behind resumes at
    /// the oldest retained byte — check [`Ring::base`] first if that needs reporting as a
    /// gap. The two stay in stream order, and either may be empty — including the *first*,
    /// once `from` is past the front half — so a caller walking them must skip an empty
    /// part rather than stop at one.
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
    fn a_zero_capacity_retains_one_byte_rather_than_aborting() {
        let mut ring = Ring::new(0);
        ring.push(b"ab");
        assert_eq!((ring.base(), ring.end()), (1, 2));
        assert_eq!(read_from(&ring, ring.base()), b"b");
    }

    #[test]
    fn an_impossible_allocation_is_reported_instead_of_aborting() {
        assert!(
            Ring::try_new(usize::MAX).is_err(),
            "capacity overflow must remain a recoverable construction error"
        );
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
    /// A `base` left too low puts a caught-up client above it, so no `Gap` is sent and
    /// the client splices a stream with a hole in it onto its scrollback believing it
    /// contiguous — the one failure the whole design exists to prevent, so it is
    /// pinned at the arithmetic rather than end to end.
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
