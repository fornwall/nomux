//! The transfers the PTY master, the agent channels and the relay are moved by.
//!
//! Every descriptor here is non-blocking bar one — the relay's stdout, which may be a
//! terminal it cannot take out of blocking mode (`attach.rs`) — a single-threaded
//! `poll` loop not being able to afford to be parked inside a `read` or a `write`, so
//! `EINTR` and `EAGAIN` are part of the ordinary flow rather than failures.
//!
//! What an outcome *means* is mostly not here: a closed peer ends the session for the
//! PTY, one channel for the agent and one direction for the relay, so [`drain_to`]
//! hands `EPIPE` back as it arrived rather than folded into a decision two of the three
//! callers would get wrong. [`read_or_eof`] is the one fold they do agree on.

use std::collections::VecDeque;
use std::io::IoSlice;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;

/// Outcome of one [`read_or_eof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Read {
    /// Bytes are available in the buffer.
    Data(usize),
    /// The peer is gone, or the descriptor failed. One ending: the payload is opaque,
    /// so there is nothing worth telling apart.
    Eof,
    /// Nothing buffered right now, which is the whole reason this is an enum: on a
    /// non-blocking descriptor this and [`Read::Eof`] both arrive as an error return,
    /// and confusing the two would end the session on every spurious wakeup.
    WouldBlock,
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

/// Reads from a descriptor whose only endings are bytes and gone: the PTY master and
/// an agent channel's socket.
///
/// Linux fails master reads with `EIO`, rather than returning 0, once the last process
/// holding the slave exits — so the kernel's own EOF is folded in here too. Nothing is
/// propagated, which is why there is no `Result`: one `poll` pass reports several sources
/// at once (`daemon.rs`, around `ACCEPT_BEFORE_READ`), and `daemon::Daemon::read_client`
/// states the rule this is the other half of — a failure on one descriptor ends that
/// connection and never the event loop. An errno this does not know is a descriptor nothing
/// can be read from, and both callers answer [`Read::Eof`] by dropping it out of the poll
/// set, so nothing spins on one either.
pub(crate) fn read_or_eof(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Read {
    match read(fd, buf) {
        Ok(n) if n > 0 => Read::Data(n),
        Err(Errno::AGAIN) => Read::WouldBlock,
        Ok(_) | Err(_) => Read::Eof,
    }
}

/// Writes as much of `queue` as `fd` will take, removing what it accepted.
///
/// Returning with a non-empty queue is the normal ending rather than a failure: ask
/// `poll` for `POLLOUT` and come back. Errors are the caller's to interpret.
///
/// One write, not a loop until `EAGAIN`. On the blocking stdout above `POLLOUT`
/// promises only that *some* write will succeed, so even the first one can park for up
/// to a whole 16 KiB chunk where a byte of room was reported, and a second would park
/// on no promise at all — the relay's other direction unserved throughout.
///
/// One `writev` over both halves rather than a write apiece, load-bearing rather than
/// an optimisation: a wrapped `VecDeque` served back-first delivers transposed
/// keystrokes rather than an error anybody could see, and an empty front handed to
/// `write` alone comes back `Ok(0)`, after which the queue never drains again.
///
/// `Ok(0)` on a non-empty queue is "come back on `POLLOUT`" here, and deliberately not the
/// `WriteZero` that `Conn::flush_some` makes of the same count. The difference is what is
/// being written to: `flush_some` only ever holds a `UnixStream`, which cannot answer a
/// non-empty write with zero, while every fd reaching here is a tty or a pipe. A `^S` in
/// the session arrives as the `EAGAIN` beside this arm rather than as a zero — the master
/// is `O_NONBLOCK`, and `n_tty_write` turns the driver's zero into `EAGAIN` before
/// userspace sees it — so what this arm is for is a count that says only "nothing moved",
/// which is never grounds for tearing down a queue that still owes its bytes.
pub(crate) fn drain_to(queue: &mut VecDeque<u8>, fd: BorrowedFd<'_>) -> Result<(), Errno> {
    if queue.is_empty() {
        return Ok(());
    }
    loop {
        let written = {
            let (front, back) = queue.as_slices();
            rustix::io::writev(fd, &[IoSlice::new(front), IoSlice::new(back)])
        };
        return match written {
            Ok(0) | Err(Errno::AGAIN) => Ok(()),
            // Clamped like every returned count in this tree: `drain` past the end
            // panics, and this binary is built `panic = "abort"`.
            Ok(n) => {
                drop(queue.drain(..n.min(queue.len())));
                Ok(())
            }
            Err(Errno::INTR) => continue,
            Err(err) => Err(err),
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
}
