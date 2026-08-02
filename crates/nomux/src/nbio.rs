//! The two non-blocking transfers every fd in this daemon is moved by.
//!
//! Four descriptors carry bytes here — the PTY master, the client socket, the
//! agent listener's channels and the relay's stdio — and all of them are
//! non-blocking, because a single-threaded `poll` loop cannot afford to be parked
//! inside a `read` or a `write`. That makes `EINTR` and `EAGAIN` part of the
//! ordinary flow rather than error handling, and both have a wrong answer that
//! looks right: treating `EINTR` as failure loses bytes to any signal, and
//! treating `EAGAIN` as end of file reports the session as over every time the
//! kernel has nothing to hand over yet.
//!
//! What is *not* here is what each outcome means. A closed peer ends the session
//! for the PTY and ends one channel for the agent, and folding that decision in
//! would make one of the two callers wrong.

use std::collections::VecDeque;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;

/// Reads into `buf`, retrying a call a signal interrupted.
///
/// The retry is the whole of it. `EINTR` says a signal arrived and says nothing
/// about the descriptor, so it is never news to a caller — but written out at each
/// site it costs a `loop { return match … }`, which reads like control flow and is
/// not. Everything else is passed through untouched, including the zero that means
/// end of file and the `EAGAIN` that emphatically does not.
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
/// The `as_slices` dance is load-bearing. A `VecDeque` that has wrapped hands back
/// a front and a back, and the front is what may be empty — writing the back
/// without the front ahead of it would deliver the queue out of order, which for a
/// terminal is transposed keystrokes rather than an error anybody could see.
pub(crate) fn drain_to(queue: &mut VecDeque<u8>, fd: BorrowedFd<'_>) -> Result<(), Errno> {
    while !queue.is_empty() {
        let (front, _) = queue.as_slices();
        if front.is_empty() {
            // Only reachable once per drain: after this the whole queue is the
            // front, so the branch cannot be taken again before something is
            // written.
            queue.make_contiguous();
            continue;
        }
        match rustix::io::write(fd, front) {
            Ok(0) | Err(Errno::AGAIN) => break,
            Ok(n) => drop(queue.drain(..n)),
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
