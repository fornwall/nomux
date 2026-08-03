//! The two transfers the PTY master, the agent channels and the relay are moved by.
//!
//! Every descriptor in this daemon is non-blocking, because a single-threaded
//! `poll` loop cannot afford to be parked inside a `read` or a `write`. That makes
//! `EINTR` and `EAGAIN` part of the ordinary flow rather than error handling, and
//! both have a wrong answer that looks right: treating `EINTR` as failure loses
//! bytes to any signal, and treating `EAGAIN` as end of file reports the session as
//! over every time the kernel has nothing to hand over yet.
//!
//! Only the client socket (`conn`) keeps a loop of its own, and on purpose: it
//! queues into a `Vec` with a cursor rather than a `VecDeque`, so there is nothing
//! for [`drain_to`] to take, and it reads a zero-length write as `WriteZero` where
//! this module reads it as "not now".
//!
//! What is *not* here is what each outcome means. A closed peer ends the session for
//! the PTY, one channel for the agent and one direction for the relay, and `EPIPE`
//! divides them the same way. Folding either decision in would make two of the three
//! callers wrong, so both come back as they arrived.

use std::collections::VecDeque;
use std::io::IoSlice;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;

/// Reads into `buf`, retrying a call a signal interrupted.
///
/// The retry is the whole of it. `EINTR` says a signal arrived and says nothing
/// about the descriptor, so it is never news to a caller. Everything else is passed
/// through untouched, including the zero that means end of file and the `EAGAIN`
/// that emphatically does not.
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
/// Returns once the descriptor stops accepting — which is the normal ending, not a
/// failure — so a non-empty queue afterwards means the caller should ask `poll` for
/// `POLLOUT` and come back. Errors are the caller's to interpret: the same `EIO`
/// that ends the session on the PTY master is one dead channel to the agent.
///
/// One write, not a loop until `EAGAIN`. A short write already means the descriptor
/// is full — a pipe, a unix socket and the PTY line discipline all return partial
/// only on hitting their limit — so the retry could answer nothing but `EAGAIN` on
/// the non-blocking descriptors, and on the one *blocking* descriptor this is
/// pointed at it is worse than useless: the relay's stdout may be a terminal it
/// cannot set non-blocking (`attach.rs`), where `POLLOUT` promises only that some
/// write will succeed, and a second one parks the whole relay inside the kernel with
/// the other direction unserved. Stopping here is what makes it safe for both.
///
/// The `writev` is load-bearing rather than an optimisation. A `VecDeque` that has
/// wrapped hands back a front and a back, and writing the back without the front
/// ahead of it would deliver the queue out of order — which for a terminal is
/// transposed keystrokes rather than an error anybody could see. One `writev` over
/// both, in that order, is what makes that unrepresentable; halving the syscalls a
/// wrapped queue costs is the side benefit.
///
/// It also disposes of the empty front. `as_slices` on a non-empty deque is not
/// documented to put anything in the front slice, and an empty one handed to `write`
/// comes back `Ok(0)` — the break below — so the queue would stop draining for good,
/// a session that quietly stops accepting keystrokes. As one of two `iovec`s an
/// empty slice contributes nothing and the call still writes what is beside it.
pub(crate) fn drain_to(queue: &mut VecDeque<u8>, fd: BorrowedFd<'_>) -> Result<(), Errno> {
    while !queue.is_empty() {
        let written = {
            let (front, back) = queue.as_slices();
            rustix::io::writev(fd, &[IoSlice::new(front), IoSlice::new(back)])
        };
        match written {
            Ok(0) | Err(Errno::AGAIN) => break,
            Ok(n) => {
                drop(queue.drain(..n));
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

    /// The wrapped case, which is the one a naive `as_slices().0` write gets
    /// wrong, and which no integration test reaches deliberately.
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
