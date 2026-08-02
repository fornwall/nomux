//! The daemon half of agent forwarding (`IMPLEMENTATION.md` § 6.7).
//!
//! The daemon owns `$RUNDIR/<id>.agent` for the session's whole life and proxies
//! every connection to it onto the protocol as a sub-channel; the client answers
//! from its own key store. Nothing here parses the `ssh-agent` protocol — a
//! channel is a byte pipe, exactly like the PTY stream — and nothing here talks to
//! the client, so the frame traffic stays in one place, in `daemon.rs`.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use nomux_proto::MAX_AGENT_CHANNELS;

use crate::rundir::SOCKET_MODE;

/// Most a single channel may hold for a local peer that has stopped reading.
///
/// Generous by two orders of magnitude for real `ssh-agent` traffic, and small
/// enough that eight channels at the limit are still nothing next to the ring.
const MAX_CHANNEL_QUEUE: usize = 256 * 1024;

/// Outcome of one attempt to drain a channel's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flush {
    /// Still in use, whether or not anything is left queued.
    Open,
    /// The client closed this channel and the last of what it sent has now
    /// reached the waiting process. Forget it *without* telling the client, which
    /// closed it and is not waiting to hear so.
    Finished,
    /// The write failed; the local peer is gone and the client needs telling.
    Failed,
    /// No such channel — it closed while a frame for it was in flight.
    Gone,
}

/// Outcome of one read from a channel's socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Read {
    /// Bytes are available in the buffer.
    Data(usize),
    /// The peer is done, or the connection failed. Either way the channel closes:
    /// there is no error path worth distinguishing when the payload is opaque.
    Closed,
    /// Nothing buffered right now.
    WouldBlock,
}

/// One proxied connection to the agent socket.
#[derive(Debug)]
struct Channel {
    id: u32,
    stream: UnixStream,
    /// Bytes from the client waiting for the local socket to accept them.
    pending: VecDeque<u8>,
    /// The client closed its end; drop once `pending` has drained.
    closing: bool,
}

/// The agent socket and its live channels.
#[derive(Debug)]
pub(crate) struct Agent {
    listener: UnixListener,
    path: PathBuf,
    channels: Vec<Channel>,
    /// Next id to hand out. Monotonic and never reused within a session, so a
    /// close and an open crossing in flight cannot be confused for each other.
    next_id: u32,
}

impl Agent {
    /// Binds the session's agent socket, replacing a stale one.
    ///
    /// # Errors
    ///
    /// Propagates bind, permission and non-blocking failures. The caller degrades
    /// to a session without forwarding rather than refusing to start.
    pub(crate) fn bind(path: &Path) -> io::Result<Self> {
        // Only ever reached while holding this session's id, and the daemon
        // unlinks its run files on exit, so anything still here is a leftover.
        drop(fs::remove_file(path));
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            channels: Vec::new(),
            next_id: 1,
        })
    }

    /// The socket path, for `SSH_AUTH_SOCK`.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The listening socket, for the poll set.
    #[must_use]
    pub(crate) fn listener(&self) -> BorrowedFd<'_> {
        self.listener.as_fd()
    }

    /// Every live channel as `(id, fd, wants_write)`, for the poll set.
    pub(crate) fn watches(&self) -> impl Iterator<Item = (u32, BorrowedFd<'_>, bool)> {
        self.channels
            .iter()
            .map(|chan| (chan.id, chan.stream.as_fd(), !chan.pending.is_empty()))
    }

    /// Accepts one connection, returning the id of the channel to announce.
    ///
    /// `serving` is whether a client is attached and greeted. When it is not, the
    /// connection is accepted and dropped on the spot: a `git push` with nobody
    /// listening must fail with the same error as a missing agent rather than hang
    /// until the user happens to reattach. The cap is enforced the same way — the
    /// daemon closes rather than queueing.
    ///
    /// Never fails. `EMFILE`, `ECONNABORTED` and friends are transient and belong
    /// to one connection; propagating them would cost the session its agent socket
    /// for good, with `SSH_AUTH_SOCK` in the child still pointing at it.
    pub(crate) fn accept(&mut self, serving: bool) -> Option<u32> {
        let Ok((stream, _)) = self.listener.accept() else {
            return None;
        };
        if !serving
            || self.channels.len() >= MAX_AGENT_CHANNELS as usize
            || self.next_id == u32::MAX
            || stream.set_nonblocking(true).is_err()
        {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.channels.push(Channel {
            id,
            stream,
            pending: VecDeque::new(),
            closing: false,
        });
        Some(id)
    }

    /// Reads from one channel's socket.
    pub(crate) fn read(&mut self, id: u32, buf: &mut [u8]) -> Read {
        let Some(chan) = self.channels.iter_mut().find(|chan| chan.id == id) else {
            return Read::Closed;
        };
        loop {
            return match rustix::io::read(chan.stream.as_fd(), &mut *buf) {
                Ok(0) => Read::Closed,
                Ok(n) => Read::Data(n),
                Err(rustix::io::Errno::AGAIN) => Read::WouldBlock,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => Read::Closed,
            };
        }
    }

    /// Queues bytes from the client for one channel's socket.
    ///
    /// Unknown ids are dropped silently: the channel closed while the frame was in
    /// flight, which is normal and not the client's fault.
    ///
    /// Returns `false` if the queue has outgrown [`MAX_CHANNEL_QUEUE`], which means
    /// the caller should close the channel. An agent exchange is a few hundred
    /// bytes; a queue this size is a local process that has stopped reading, and
    /// the daemon must not hold megabytes per channel on its behalf.
    pub(crate) fn deliver(&mut self, id: u32, data: &[u8]) -> bool {
        let Some(chan) = self.channels.iter_mut().find(|chan| chan.id == id) else {
            return true;
        };
        chan.pending.extend(data.iter().copied());
        chan.pending.len() <= MAX_CHANNEL_QUEUE
    }

    /// Writes what it can of one channel's queue.
    pub(crate) fn flush(&mut self, id: u32) -> Flush {
        let Some(chan) = self.channels.iter_mut().find(|chan| chan.id == id) else {
            return Flush::Gone;
        };
        while !chan.pending.is_empty() {
            let (front, _) = chan.pending.as_slices();
            if front.is_empty() {
                chan.pending.make_contiguous();
                continue;
            }
            match rustix::io::write(chan.stream.as_fd(), front) {
                Ok(0) | Err(rustix::io::Errno::AGAIN) => break,
                Ok(n) => drop(chan.pending.drain(..n)),
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return Flush::Failed,
            }
        }
        if chan.closing && chan.pending.is_empty() {
            Flush::Finished
        } else {
            Flush::Open
        }
    }

    /// Marks a channel closed by the client. Its queue is flushed first, so a reply
    /// the client has already sent still reaches the waiting process.
    pub(crate) fn close_from_client(&mut self, id: u32) {
        if let Some(chan) = self.channels.iter_mut().find(|chan| chan.id == id) {
            chan.closing = true;
            drop(chan.stream.shutdown(std::net::Shutdown::Read));
        }
        if self.flush(id) != Flush::Open {
            let _ = self.forget(id);
        }
    }

    /// Drops a channel, closing its socket. Returns whether it was still open —
    /// the caller uses that to decide whether the client needs telling, since a
    /// channel the client itself closed needs no answer.
    pub(crate) fn forget(&mut self, id: u32) -> bool {
        let before = self.channels.len();
        self.channels.retain(|chan| chan.id != id);
        self.channels.len() != before
    }

    /// Drops every channel, for when the client goes away.
    ///
    /// Nothing can answer an in-flight request once the client is gone, and the
    /// process waiting on it should learn that now rather than at reattach.
    pub(crate) fn forget_all(&mut self) {
        self.channels.clear();
    }
}
