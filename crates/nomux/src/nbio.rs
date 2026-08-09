//! The transfers the PTY master, the agent channels and the relay are moved by.
//!
//! Every descriptor here is non-blocking bar the relay's stdout. The relay cannot
//! safely change that inherited open-file description, so `attach.rs` isolates its
//! writes in a bounded worker where blocking cannot park the event loop. `EINTR` and
//! `EAGAIN` are ordinary flow rather than failures in either case.
//!
//! What an outcome *means* is mostly not here: [`drain_to`] hands `EPIPE` back rather than
//! folding it into a decision two of the three callers would get wrong; [`read_or_eof`]
//! distinguishes a real ending from a failed descriptor; the relay folds its own in
//! `attach.rs`'s `fill_from`.

use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::os::fd::BorrowedFd;

use rustix::io::Errno;

/// Outcome of one [`read_or_eof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadOutcome {
    Data(usize),
    /// Peer gone, including Linux's `EIO` spelling of PTY end of file.
    Eof,
    /// The whole reason this is an enum: this and [`ReadOutcome::Eof`] both arrive as an error
    /// return, and confusing the two would end the session on every spurious wakeup.
    WouldBlock,
    /// The descriptor failed for a reason that is not an ending.
    Failed(Errno),
}

/// Reads into `buf`, retrying a call a signal interrupted: `EINTR` says a signal
/// arrived and nothing about the descriptor, so it is never news to a caller.
pub(crate) fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, Errno> {
    loop {
        match rustix::io::read(fd, &mut *buf) {
            Err(Errno::INTR) => {}
            outcome => return outcome,
        }
    }
}

/// Reads from a PTY master or agent channel without conflating failure with EOF.
///
/// Linux fails master reads with `EIO`, rather than returning 0, once the last process holding
/// the slave exits — so that specific errno is the kernel's own EOF and is folded in here.
/// Every other errno is preserved: a failed PTY must not become a clean terminal ending and
/// an invented process outcome.
///
/// An empty `buf` answers [`ReadOutcome::WouldBlock`] rather than `read`'s `Ok(0)`, which
/// every caller reads as the peer having gone — a session declared over with its child
/// still alive. No caller passes one; this is what keeps that from having to be checked.
pub(crate) fn read_or_eof(fd: BorrowedFd<'_>, buf: &mut [u8]) -> ReadOutcome {
    if buf.is_empty() {
        return ReadOutcome::WouldBlock;
    }
    match read(fd, buf) {
        Ok(n) if n > 0 => ReadOutcome::Data(n),
        Err(Errno::AGAIN) => ReadOutcome::WouldBlock,
        Ok(_) | Err(Errno::IO) => ReadOutcome::Eof,
        Err(err) => ReadOutcome::Failed(err),
    }
}

/// Writes as much of `queue` as `fd` will take, removing what it accepted.
///
/// A non-empty queue on return is normal: come back on `POLLOUT` (`IMPLEMENTATION.md`
/// § 4.1). One write and not a loop until `EAGAIN`, so an
/// event-loop destination gets one fair share of a pass and the stdout worker makes no
/// second unpromised blocking write.
///
/// One `writev` over both halves rather than a write apiece, load-bearing rather than
/// an optimisation: a wrapped `VecDeque` served back-first delivers transposed
/// keystrokes rather than an error anybody could see, and an empty front handed to
/// `write` alone comes back `Ok(0)`, after which the queue never drains again.
pub(crate) fn drain_to(queue: &mut VecDeque<u8>, fd: BorrowedFd<'_>) -> io::Result<()> {
    if queue.is_empty() {
        return Ok(());
    }
    loop {
        let written = {
            let (front, back) = queue.as_slices();
            rustix::io::writev(fd, &[IoSlice::new(front), IoSlice::new(back)])
        };
        return match written {
            Ok(0) => Err(io::ErrorKind::WriteZero.into()),
            Err(Errno::AGAIN) => Ok(()),
            // Clamped like every returned count in this tree: `drain` past the end
            // panics, and this binary is built `panic = "abort"`.
            Ok(n) => {
                drop(queue.drain(..n.min(queue.len())));
                Ok(())
            }
            Err(Errno::INTR) => continue,
            Err(err) => Err(err.into()),
        };
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    /// The case a naive `as_slices().0` write gets wrong, which no integration test
    /// reaches deliberately.
    #[test]
    fn a_wrapped_queue_is_delivered_in_order() {
        let (read_end, write_end) = rustix::pipe::pipe().expect("pipe");

        // Fill, drain from the front, refill: the head ends up past index zero.
        let mut queue: VecDeque<u8> = VecDeque::with_capacity(8);
        queue.extend(b"abcdefgh");
        drop(queue.drain(..5));
        queue.extend(b"ijklm");
        assert!(
            queue.as_slices().0.len() < queue.len(),
            "the queue must actually be wrapped for this to test anything"
        );

        drain_to(&mut queue, write_end.as_fd()).expect("drain to the pipe");
        assert!(queue.is_empty(), "a pipe with room takes the whole queue");

        let mut got = [0u8; 8];
        let n = read(read_end.as_fd(), &mut got).expect("read it back");
        assert_eq!(&got[..n], b"fghijklm", "the two halves arrived in order");
    }

    #[test]
    fn a_read_failure_is_not_reported_as_end_of_file() {
        let dir = rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("open a descriptor read(2) refuses");
        assert_eq!(
            read_or_eof(dir.as_fd(), &mut [0]),
            ReadOutcome::Failed(Errno::ISDIR),
            "a failed descriptor was mistaken for a peer that closed cleanly"
        );
    }

    #[test]
    fn an_empty_buffer_is_not_reported_as_end_of_file() {
        let (read_end, _write_end) = rustix::pipe::pipe().expect("pipe");
        assert_eq!(
            read_or_eof(read_end.as_fd(), &mut []),
            ReadOutcome::WouldBlock
        );
    }
}
