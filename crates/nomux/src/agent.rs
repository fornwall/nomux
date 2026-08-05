//! The daemon half of agent forwarding (`IMPLEMENTATION.md` § 6.7).
//!
//! Nothing here parses the `ssh-agent` protocol — a channel is a byte pipe, exactly
//! like the PTY stream — and nothing here talks to the client, so the frame traffic
//! stays in one place, in `daemon.rs`.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Most concurrent agent channels one session will serve
/// (`IMPLEMENTATION.md` § 6.7).
///
/// Daemon policy rather than anything the wire imposes — no frame field is bounded by
/// it — so it is enforced here, in the `accept` that turns it down. `pub(crate)`
/// because `daemon` sizes its poll set against it.
pub(crate) const MAX_AGENT_CHANNELS: u32 = 8;

/// Most a single channel may hold for a local peer that has stopped reading
/// (`IMPLEMENTATION.md` § 6.7).
///
/// The ceiling that matters is the product: eight channels all at the limit is 2 MiB,
/// half the default ring rather than a rounding error against it.
const MAX_CHANNEL_QUEUE: usize = 256 * 1024;

/// Outcome of one attempt to take a connection off the agent socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accept {
    /// A channel was opened, and the client is owed an `AgentOpen` for it.
    Opened(u32),
    /// Nothing came of this pass: an empty backlog, or a connection closed on the
    /// spot because nothing could serve it.
    Idle,
    /// The `accept` failed for something that will still be there on the next pass,
    /// so the listener has to leave the poll set for a while — `daemon`'s
    /// `ACCEPT_BACKOFF` says why retrying at once is retrying for ever.
    Failed,
}

/// Outcome of one attempt to drain a channel's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flush {
    /// Still in use, whether or not anything is left queued.
    Open,
    /// The client closed this channel and the last of what it sent has now
    /// reached the waiting process. Forget it *without* telling the client, which
    /// closed it and is not waiting to hear so.
    Finished,
    /// The write failed on a channel the client still holds; the local peer is gone
    /// and the client needs telling.
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
    /// Where [`Agent::take_id`] starts looking for the next id to hand out. No id is
    /// ever reused while a channel holds it, so a close and an open crossing in
    /// flight cannot be confused for each other.
    next_id: u32,
    /// Whether the cap has already been reported; once is an attachment's worth.
    capped: bool,
}

impl Agent {
    /// Binds the session's agent socket, replacing a stale one.
    ///
    /// # Errors
    ///
    /// Propagates bind, permission and non-blocking failures. The caller degrades
    /// to a session without forwarding rather than refusing to start.
    pub(crate) fn bind(path: &Path) -> io::Result<Self> {
        // Only ever reached while holding this session's id, so anything still here is
        // a leftover.
        drop(fs::remove_file(path));
        // Never briefly world-connectable: this is the socket that hands out signatures.
        let listener = crate::rundir::bind_socket_private(path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            channels: Vec::new(),
            next_id: 1,
            capped: false,
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

    /// Every live channel as `(id, fd, wants_write, wants_read)`, for the poll set.
    ///
    /// A closing channel wants no reads, and asking for them would spin the loop at full
    /// tilt: `close_from_client` shuts the read half down, and a unix socket in that
    /// state reports itself readable on every pass for ever. It stays in the poll set on
    /// `POLLOUT` alone, which is the only thing that can still move it.
    pub(crate) fn watches(&self) -> impl Iterator<Item = (u32, BorrowedFd<'_>, bool, bool)> {
        self.channels.iter().map(|chan| {
            (
                chan.id,
                chan.stream.as_fd(),
                !chan.pending.is_empty(),
                !chan.closing,
            )
        })
    }

    /// The still-open channel with this id.
    ///
    /// A scan rather than a keyed lookup: the list is capped at [`MAX_AGENT_CHANNELS`],
    /// and a `BTreeMap` over eight entries measured 8 KiB of monomorphised B-tree on
    /// `x86_64` against the 400 KiB budget of `IMPLEMENTATION.md` § 8.
    fn channel(&mut self, id: u32) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|chan| chan.id == id)
    }

    /// Accepts one connection, returning the channel to announce.
    ///
    /// `serving` is whether a client is attached and greeted. When it is not, the
    /// connection is accepted and dropped on the spot, as is one past the channel cap
    /// (§ 6.7).
    ///
    /// Never fails the session. `EMFILE`, `ECONNABORTED` and friends belong to one
    /// connection; propagating them would cost the session its agent socket for good,
    /// with `SSH_AUTH_SOCK` in the child still pointing at it. They are still told apart
    /// from an empty backlog, because only one of the two leaves a connection queued
    /// behind it, and a queued connection keeps this descriptor readable.
    pub(crate) fn accept(&mut self, serving: bool) -> Accept {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            // The listener is non-blocking, so an empty backlog is an ordinary
            // answer, and a signal is a call that has not happened yet. Neither
            // queued anything, so neither is a reason to stand back from the socket.
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Accept::Idle;
            }
            Err(_) => return Accept::Failed,
        };
        if !serving || stream.set_nonblocking(true).is_err() {
            return Accept::Idle;
        }
        // Nothing but a detach frees the slot of a closed channel whose peer stopped
        // reading, and the queue dropped with it is one that peer's socket buffer had no
        // room for — bytes already in that buffer survive the close and are still read.
        if self.channels.len() >= MAX_AGENT_CHANNELS as usize
            && let Some(at) = self.channels.iter().position(|chan| chan.closing)
        {
            drop(self.channels.remove(at));
        }
        if self.channels.len() >= MAX_AGENT_CHANNELS as usize {
            if !std::mem::replace(&mut self.capped, true) {
                let id = crate::rundir::session_id_of(&self.path).unwrap_or_default();
                crate::syslog::error(id, "agent socket: every channel is in use");
            }
            return Accept::Idle;
        }
        // Unreachable past the cap above — see [`Agent::take_id`] — and answered by
        // dropping this one connection rather than by a panic if it ever is not.
        let Some(id) = self.take_id() else {
            return Accept::Idle;
        };
        self.channels.push(Channel {
            id,
            stream,
            pending: VecDeque::new(),
            closing: false,
        });
        Accept::Opened(id)
    }

    /// The next id no live channel holds, or `None` if every candidate is taken.
    ///
    /// A wrapping search rather than a bare increment: ids are handed out for the whole
    /// life of a session that may run for a week. What § 6.7 needs is that no *live*
    /// channel's id is reissued, which this keeps — at most [`MAX_AGENT_CHANNELS`] are
    /// live, so one of any nine consecutive candidates is free and `None` cannot be
    /// reached from a caller that respects the cap.
    fn take_id(&mut self) -> Option<u32> {
        for _ in 0..=MAX_AGENT_CHANNELS {
            let id = self.next_id;
            // Round to 1 rather than to 0, which no channel has ever worn: it stays
            // free to read as "no channel" wherever one of these is written down.
            self.next_id = self.next_id.checked_add(1).unwrap_or(1);
            if !self.channels.iter().any(|chan| chan.id == id) {
                return Some(id);
            }
        }
        None
    }

    /// Reads from one channel's socket.
    pub(crate) fn read(&mut self, id: u32, buf: &mut [u8]) -> Read {
        let Some(chan) = self.channel(id) else {
            return Read::Closed;
        };
        // A channel the client has closed has had its read half shut down by
        // `close_from_client`, so it answers every read with the end of file we
        // ourselves caused. Taking that at face value would drop the very reply
        // [`Flush::Finished`] exists to deliver, and would tell the client of a close
        // it made itself.
        if chan.closing {
            return Read::WouldBlock;
        }
        match crate::nbio::read(chan.stream.as_fd(), buf) {
            Ok(0) => Read::Closed,
            Ok(n) => Read::Data(n),
            Err(rustix::io::Errno::AGAIN) => Read::WouldBlock,
            // Anything else is this one socket's problem, never the session's:
            // the process on the other end is a `ssh-add` that went away.
            Err(_) => Read::Closed,
        }
    }

    /// Queues bytes from the client for one channel's socket.
    ///
    /// Unknown ids are dropped silently: the channel closed while the frame was in
    /// flight, which is normal and not the client's fault.
    ///
    /// Returns `false` if the data would take the queue past [`MAX_CHANNEL_QUEUE`],
    /// which means the caller should close the channel. An agent exchange is a few
    /// hundred bytes; a queue this size is a local process that has stopped reading.
    pub(crate) fn deliver(&mut self, id: u32, data: &[u8]) -> bool {
        let Some(chan) = self.channel(id) else {
            return true;
        };
        // Before the bytes are taken rather than after: tested afterwards, the frame
        // that crosses the cap is queued anyway, and the peak is the cap plus a whole
        // `MAX_PAYLOAD`.
        if chan.pending.len() + data.len() > MAX_CHANNEL_QUEUE {
            return false;
        }
        chan.pending.extend(data);
        true
    }

    /// Writes what it can of one channel's queue.
    pub(crate) fn flush(&mut self, id: u32) -> Flush {
        let Some(chan) = self.channel(id) else {
            return Flush::Gone;
        };
        let failed = crate::nbio::drain_to(&mut chan.pending, chan.stream.as_fd()).is_err();
        if chan.closing {
            // A write that failed ends this channel exactly as a drained queue does: the
            // rest of it has nowhere left to go either way, and the client closed this
            // channel and has already forgotten it — so [`Flush::Failed`] here would have
            // the daemon answer with an `AgentClose` for a channel it no longer has.
            if failed || chan.pending.is_empty() {
                Flush::Finished
            } else {
                Flush::Open
            }
        } else if failed {
            Flush::Failed
        } else {
            Flush::Open
        }
    }

    /// Marks a channel closed by the client. Its queue is flushed first, so a reply
    /// the client has already sent still reaches the waiting process.
    pub(crate) fn close_from_client(&mut self, id: u32) {
        if let Some(chan) = self.channel(id) {
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
        let Some(at) = self.channels.iter().position(|chan| chan.id == id) else {
            return false;
        };
        drop(self.channels.remove(at));
        true
    }

    /// Drops every channel, for when the client goes away.
    ///
    /// Nothing can answer an in-flight request once the client is gone, and the
    /// process waiting on it should learn that now rather than at reattach.
    pub(crate) fn forget_all(&mut self) {
        self.channels.clear();
        self.capped = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::scratch::Scratch;

    /// An agent socket of this test's own, bound in `root`.
    fn bind_in(root: &Scratch, name: &str) -> Agent {
        Agent::bind(&root.join(name)).expect("bind an agent socket")
    }

    /// Connects to `agent` as the child's `ssh-add` would and takes the connection,
    /// handing back the peer end — which the caller must keep, or the channel closes
    /// under it.
    fn open(agent: &mut Agent) -> (UnixStream, u32) {
        let peer = UnixStream::connect(agent.path()).expect("connect to the agent socket");
        match agent.accept(true) {
            Accept::Opened(id) => (peer, id),
            other => panic!("a connection with a client attached must open a channel: {other:?}"),
        }
    }

    /// Regression: eight channels at the old peak of `MAX_CHANNEL_QUEUE + MAX_PAYLOAD`
    /// is 4 MiB, against the 2 MiB the constant's own comment sizes the session against.
    #[test]
    fn a_channel_queue_is_bounded_before_the_bytes_are_taken() {
        let root = Scratch::new("agent-queue");
        let mut agent = bind_in(&root, "q.agent");
        let (_peer, id) = open(&mut agent);

        assert!(
            agent.deliver(id, &vec![0u8; MAX_CHANNEL_QUEUE - 1]),
            "a queue below the cap is served"
        );
        assert!(
            agent.deliver(id, &[0u8]),
            "and one that lands exactly on it still is"
        );
        assert!(
            !agent.deliver(id, &vec![0u8; 64 * 1024]),
            "the frame that would cross the cap is refused"
        );
        assert_eq!(
            agent.channels[0].pending.len(),
            MAX_CHANNEL_QUEUE,
            "and none of it is queued: the peak is the cap, not the cap plus a payload"
        );
    }

    /// Regression: ids were a bare counter that refused every connection from
    /// `u32::MAX` on, and did it silently — `SSH_AUTH_SOCK` goes on naming a socket
    /// that accepts and closes.
    #[test]
    fn channel_ids_wrap_rather_than_running_out() {
        let root = Scratch::new("agent-ids");
        let mut agent = bind_in(&root, "w.agent");
        agent.next_id = u32::MAX - 1;

        // The peer ends are held for the whole test: a channel whose peer has gone is
        // one the search may legitimately reuse the id of.
        let mut opened: Vec<(UnixStream, u32)> = Vec::new();
        for _ in 0..MAX_AGENT_CHANNELS {
            opened.push(open(&mut agent));
        }
        assert_eq!(
            opened.iter().map(|(_, id)| *id).collect::<Vec<u32>>(),
            vec![u32::MAX - 1, u32::MAX, 1, 2, 3, 4, 5, 6],
            "the cursor must carry on past the end of the range rather than stop at it"
        );

        // Pointed back at ids that are all still live, the search has to walk past
        // them: reuse is only ever of an id no channel holds.
        assert!(agent.forget(3), "free one of the eight");
        agent.next_id = 1;
        let (_peer, reused) = open(&mut agent);
        assert_eq!(
            reused, 3,
            "the search must skip every live id and take only the one that was freed"
        );
    }

    /// The cap held against the document rather than against itself: every other
    /// agent-channel test counts to `MAX_AGENT_CHANNELS` and asks for one more, so all of
    /// them pass at whatever value it happens to hold. The far end is a separate codebase
    /// built from § 6.7, so the number is written out by hand here.
    #[test]
    fn the_channel_cap_is_the_one_the_document_gives() {
        assert_eq!(
            MAX_AGENT_CHANNELS, 8,
            "MAX_AGENT_CHANNELS is {MAX_AGENT_CHANNELS}, and IMPLEMENTATION.md § 6.7 caps a \
             session at 8 concurrent agent channels"
        );
    }

    /// An empty backlog must not be reported as the failure that takes the socket out
    /// of the poll set.
    #[test]
    fn an_empty_backlog_is_not_a_failure_to_back_off_from() {
        let root = Scratch::new("agent-idle");
        let mut agent = bind_in(&root, "i.agent");
        assert_eq!(agent.accept(true), Accept::Idle);
    }
}
