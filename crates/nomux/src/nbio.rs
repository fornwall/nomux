//! The two transfers the PTY master, the agent channels and the relay are moved by.
//!
//! Every descriptor here is non-blocking, a single-threaded `poll` loop not being
//! able to afford to be parked inside a `read` or a `write`, so `EINTR` and `EAGAIN`
//! are part of the ordinary flow rather than failures.
//!
//! What an outcome *means* is not here: a closed peer ends the session for the PTY,
//! one channel for the agent and one direction for the relay, and `EPIPE` divides
//! them the same way. So both come back as they arrived, rather than folded into a
//! decision two of the three callers would get wrong.

use std::collections::VecDeque;
use std::io::IoSlice;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;

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

/// Writes as much of `queue` as `fd` will take, removing what it accepted.
///
/// Returning with a non-empty queue is the normal ending rather than a failure: ask
/// `poll` for `POLLOUT` and come back. Errors are the caller's to interpret.
///
/// One write, not a loop until `EAGAIN`: a short write already means the descriptor
/// is full, and on the one *blocking* descriptor this is pointed at — the relay's
/// stdout, which may be a terminal it cannot set non-blocking (`attach.rs`) —
/// `POLLOUT` promises only that *some* write will succeed, so a second one parks the
/// whole relay inside the kernel with the other direction unserved.
///
/// One `writev` over both halves in order rather than a write apiece, which is
/// load-bearing rather than an optimisation: a wrapped `VecDeque` served back-first
/// delivers transposed keystrokes rather than an error anybody could see, and an
/// empty front handed to `write` alone comes back `Ok(0)` — the break below — after
/// which the queue never drains again.
pub(crate) fn drain_to(queue: &mut VecDeque<u8>, fd: BorrowedFd<'_>) -> Result<(), Errno> {
    while !queue.is_empty() {
        let written = {
            let (front, back) = queue.as_slices();
            rustix::io::writev(fd, &[IoSlice::new(front), IoSlice::new(back)])
        };
        match written {
            Ok(0) | Err(Errno::AGAIN) => break,
            // Clamped like every returned count in this tree: `drain` past the end
            // panics, and this binary is built `panic = "abort"`.
            Ok(n) => {
                drop(queue.drain(..n.min(queue.len())));
                break;
            }
            Err(Errno::INTR) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
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

        // Wrap it: fill the ring, then take from the front and push to the back
        // so that the head is no longer at index zero.
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
}
