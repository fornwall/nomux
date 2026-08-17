//! The daemon half of agent forwarding (`IMPLEMENTATION.md` § 6.7).
//!
//! Nothing here parses the `ssh-agent` protocol — the served connection is a byte pipe,
//! exactly like the PTY stream — and nothing here talks to the client, so the frame
//! traffic stays in one place, in `daemon.rs`.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::nbio::ReadOutcome;

/// Most the served connection may hold for a local peer that has stopped reading
/// (`IMPLEMENTATION.md` § 6.7).
///
/// An agent exchange is a few hundred bytes, so this is already three orders of
/// magnitude past anything legitimate; what it bounds is the peer that has stopped
/// reading altogether, at a sixteenth of the default ring rather than beside it.
const MAX_CHANNEL_QUEUE: usize = 256 * 1024;

/// How long the served connection may move no byte in either direction before the
/// daemon gives it up (`IMPLEMENTATION.md` § 6.7, which has why it runs from the last
/// byte rather than from the accept).
///
/// One slot makes later peers wait this long in series. A minute still leaves room for
/// a human or hardware key to answer a live signing request.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_mins is unstable on the pinned toolchain"
)]
const AGENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Outcome of one attempt to take a connection off the agent socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accept {
    /// A connection is being served, and the client is owed an `AgentOpen` naming the
    /// generation this minted for it.
    Opened(u32),
    /// Nothing came of this pass: an empty backlog, a connection closed on the spot
    /// because nothing could serve it, or a slot that was already taken.
    Idle,
    /// The `accept` failed for something that will still be there on the next pass,
    /// so the listener has to leave the poll set for a while — `daemon`'s
    /// `ACCEPT_BACKOFF` says why retrying at once is retrying for ever.
    Failed,
}

/// Outcome of one attempt to drain the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flush {
    /// Still in use, whether or not anything is left queued.
    Open,
    /// Nothing more will be written: the client closed this connection and the last of
    /// what it sent has reached the waiting process. Forget it *without* telling the
    /// client, which closed it and is not waiting to hear so.
    Finished,
    /// The write failed on a connection the client still holds; the local peer is gone
    /// and the client needs telling.
    Failed,
}

/// The one proxied connection to the agent socket.
#[derive(Debug)]
struct Channel {
    /// Which incarnation of the slot this is, echoed by the client on everything it
    /// sends for it (`IMPLEMENTATION.md` § 6.7).
    generation: u32,
    stream: UnixStream,
    /// Bytes from the client waiting for the local socket to accept them.
    pending: VecDeque<u8>,
    /// The client closed its end; drop once `pending` has drained.
    closing: bool,
    /// When this connection is given up as stalled: [`AGENT_IDLE_TIMEOUT`] past the
    /// last byte that moved in either direction.
    idle_deadline: Instant,
}

impl Channel {
    /// Pushes the idle deadline out, for a byte that has just moved either way.
    fn touch(&mut self) {
        self.idle_deadline = Instant::now() + AGENT_IDLE_TIMEOUT;
    }
}

/// The agent socket and the one connection it is serving.
#[derive(Debug)]
pub(crate) struct Agent {
    listener: UnixListener,
    path: PathBuf,
    channel: Option<Channel>,
    /// What the next accepted connection is called.
    ///
    /// A name rather than a fence the daemon sends to flush the ended peer's frames out
    /// of the wire ahead of the next accept: `Ping` is client→daemon and `Pong`
    /// daemon→client, so the daemon has nothing it can send that forces a round trip.
    next_generation: u32,
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
        // a leftover. Two syscalls on one name, where `rundir::write_private` needs
        // `O_EXCL` to survive the same window: `bind(2)` resolves through
        // `filename_create`, which refuses a trailing symlink with `EEXIST`, so a name
        // planted between the unlink and the bind cannot send this socket anywhere else.
        drop(fs::remove_file(path));
        // Never briefly world-connectable: this is the socket that hands out signatures.
        let listener = crate::rundir::bind_socket_private(path)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            channel: None,
            next_generation: 0,
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

    /// Whether a connection is being served, and so whether the listener has a slot.
    #[must_use]
    pub(crate) const fn is_serving(&self) -> bool {
        self.channel.is_some()
    }

    /// The served connection's generation, for the frames the daemon sends about it.
    #[must_use]
    pub(crate) fn generation(&self) -> Option<u32> {
        self.channel.as_ref().map(|chan| chan.generation)
    }

    /// The served connection as `(fd, wants_write, wants_read)`, for the poll set.
    ///
    /// A closing connection asks for no reads: nothing it could still send has anywhere
    /// to go, and its shut-down read half would report itself readable on every pass for
    /// ever. `POLLOUT` is all that can move it.
    pub(crate) fn watch(&self) -> Option<(BorrowedFd<'_>, bool, bool)> {
        let chan = self.channel.as_ref()?;
        Some((chan.stream.as_fd(), !chan.pending.is_empty(), !chan.closing))
    }

    /// When the served connection falls due for [`Agent::close_if_idle`] — the wakeup
    /// the poll loop has to arrange, nothing else being able to make it arrive.
    #[must_use]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        Some(self.channel.as_ref()?.idle_deadline)
    }

    /// Gives the served connection up if it has moved no byte in either direction since
    /// [`AGENT_IDLE_TIMEOUT`] before `now`, reporting whether the client is owed an
    /// `AgentClose` for it.
    ///
    /// `now` is the caller's rather than this function's, so the poll loop tests every
    /// deadline of one pass against one clock reading, and a test can put the deadline
    /// behind it without waiting out a minute.
    pub(crate) fn close_if_idle(&mut self, now: Instant) -> Option<u32> {
        if self.deadline().is_none_or(|at| now < at) {
            return None;
        }
        // A connection the client closed itself is one it has already forgotten, so
        // abandoning the undeliverable rest of its queue is not news to send back — the
        // argument [`Flush::Finished`] makes, arrived at by the clock instead. The slot
        // still has to come back, which is why the clock reaches it at all.
        let owed = self.channel.as_ref().is_some_and(|chan| !chan.closing);
        self.forget().filter(|_| owed)
    }

    /// Accepts one connection, if the slot is free.
    ///
    /// `serving` is whether a client is attached and greeted. When it is not, the
    /// connection is accepted and dropped on the spot (§ 6.7).
    ///
    /// One at a time, and a second connection is left where it is rather than turned
    /// away: `daemon`'s `watch_for` keeps the listener out of the poll set while this is
    /// serving, on the same terms and for the same reason as the session listener, so
    /// what waits in the backlog is greeted when the slot frees.
    ///
    /// Never fails the session. `EMFILE`, `ECONNABORTED` and friends belong to one
    /// connection; propagating them would cost the session its agent socket for good,
    /// with `SSH_AUTH_SOCK` in the child still pointing at it. They are still told apart
    /// from an empty backlog, because only one of the two leaves a connection queued
    /// behind it, and a queued connection keeps this descriptor readable.
    pub(crate) fn accept(&mut self, serving: bool, id: &str) -> Accept {
        if self.is_serving() {
            return Accept::Idle;
        }
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
        // Before the slot is taken and before a byte is read, and on the same terms as
        // the session listener's (§ 6.3): what a connection here reaches is the client's
        // key store, so this is the socket that check is worth most on.
        if !crate::usock::peer_is_ours(stream.as_fd(), id)
            || !serving
            || stream.set_nonblocking(true).is_err()
        {
            return Accept::Idle;
        }
        let generation = self.next_generation;
        // Wrapping rather than saturating: a generation that stuck at the top would name
        // every later connection the same thing, which is the bug this counter closes.
        self.next_generation = generation.wrapping_add(1);
        self.channel = Some(Channel {
            generation,
            stream,
            pending: VecDeque::new(),
            closing: false,
            idle_deadline: Instant::now() + AGENT_IDLE_TIMEOUT,
        });
        Accept::Opened(generation)
    }

    /// Reads from the served connection's socket.
    ///
    /// **A half-close is a close.** `nbio::read_or_eof` folds `read() == 0` into
    /// [`ReadOutcome::Eof`] and the daemon answers that by ending the channel, so a peer that
    /// shuts down its own write side and waits for a reply — the idiomatic Go
    /// `io.Copy` plus `CloseWrite` shape — is dropped rather than answered.
    /// `AgentClose` has no half-close spelling on the wire (§ 2.2), so there is nothing
    /// this could report instead; `ssh-agent` clients keep the connection open for the
    /// reply, which is why it has never cost anything.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> ReadOutcome {
        let Some(chan) = self.channel.as_mut() else {
            return ReadOutcome::Eof;
        };
        // Nothing is read from a connection the client has closed: what is left to do
        // with it is hand on the queue behind it ([`Flush::Finished`]), and reading is
        // what would end it early.
        if chan.closing {
            return ReadOutcome::WouldBlock;
        }
        let read = crate::nbio::read_or_eof(chan.stream.as_fd(), buf);
        if matches!(read, ReadOutcome::Data(_)) {
            chan.touch();
        }
        read
    }

    /// Queues bytes from the client for the served connection's socket.
    ///
    /// Bytes naming a connection this is no longer serving or is already closing are
    /// dropped silently: they were in flight when it closed. `generation` keeps them out
    /// of the connection that next takes the slot.
    ///
    /// Returns `false` if the data would take the queue past [`MAX_CHANNEL_QUEUE`],
    /// which means the caller should close the connection.
    pub(crate) fn deliver(&mut self, generation: u32, data: &[u8]) -> bool {
        let Some(chan) = self
            .channel
            .as_mut()
            .filter(|chan| chan.generation == generation && !chan.closing)
        else {
            return true;
        };
        // Before the bytes are taken rather than after: tested afterwards, the frame
        // that crosses the cap is queued anyway, and the peak is the cap plus a whole
        // `MAX_PAYLOAD`.
        if chan.pending.len() + data.len() > MAX_CHANNEL_QUEUE {
            return false;
        }
        // Queued and not touched: [`Channel::touch`] is for a byte that *moved*, and
        // [`Agent::flush`] does it whenever one did. Refreshing the deadline here would
        // have every arriving frame push it out over a peer that has stopped reading,
        // which is the one connection the clock is there to end — it would live to
        // [`MAX_CHANNEL_QUEUE`] instead.
        chan.pending.extend(data);
        true
    }

    /// Writes what it can of the queue.
    pub(crate) fn flush(&mut self) -> Flush {
        let Some(chan) = self.channel.as_mut() else {
            return Flush::Finished;
        };
        let before = chan.pending.len();
        let failed = crate::nbio::drain_to(&mut chan.pending, chan.stream.as_fd()).is_err();
        if chan.pending.len() != before {
            chan.touch();
        }
        if chan.closing {
            // A write that failed ends this connection exactly as a drained queue does:
            // the rest of it has nowhere left to go either way, and the client closed
            // this connection and has already forgotten it — so [`Flush::Failed`] here
            // would have the daemon answer with an `AgentClose` it no longer has a
            // connection for.
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

    /// Marks the served connection closed by the client. Its queue is flushed first, so
    /// a reply the client has already sent still reaches the waiting process.
    ///
    /// A close for a generation this is no longer serving does nothing at all. The
    /// client sent it for a peer that had already gone, and honouring it would kill the
    /// one that took the slot — silently, this being the close the daemon does not
    /// answer.
    pub(crate) fn close_from_client(&mut self, generation: u32) {
        let Some(chan) = self
            .channel
            .as_mut()
            .filter(|chan| chan.generation == generation)
        else {
            return;
        };
        chan.closing = true;
        // For the peer rather than for us — [`Channel::closing`] is what keeps the daemon
        // off this read side. Linux propagates `SEND_SHUTDOWN` across an `AF_UNIX` pair,
        // so the peer's next write fails with `EPIPE` instead of blocking against a
        // reader that will never come back.
        drop(chan.stream.shutdown(std::net::Shutdown::Read));
        if self.flush() != Flush::Open {
            let _ = self.forget();
        }
    }

    /// Drops the served connection, closing its socket. Returns its generation if there
    /// was one — the caller uses that both to decide whether the client needs telling,
    /// since a connection the client itself closed needs no answer, and to name what it
    /// is telling it about.
    ///
    /// Also how a departing client releases the slot: nothing can answer an in-flight
    /// request once the client is gone, and the process waiting on it should learn that
    /// now rather than at reattach.
    pub(crate) fn forget(&mut self) -> Option<u32> {
        self.channel.take().map(|chan| chan.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use crate::scratch::Scratch;

    /// The id a refusal would be reported against. Nothing here provokes one — a peer
    /// this process connects to itself with is this uid's — and `Agent` derives no path
    /// from it, the socket having been bound before it is passed.
    const ID: &str = "agent";

    /// An agent socket of this test's own, bound in `root`.
    fn bind_in(root: &Scratch, name: &str) -> Agent {
        Agent::bind(&root.join(name)).expect("bind an agent socket")
    }

    /// Connects to `agent` as the child's `ssh-add` would and takes the connection,
    /// handing back the peer end — which the caller must keep, or the connection closes
    /// under it — and the generation everything sent for it must name.
    fn open(agent: &mut Agent) -> (UnixStream, u32) {
        let peer = UnixStream::connect(agent.path()).expect("connect to the agent socket");
        let Accept::Opened(generation) = agent.accept(true, ID) else {
            panic!("a connection with a client attached and the slot free must be served");
        };
        (peer, generation)
    }

    /// Fills the peer's socket buffer, leaving data queued in `agent`.
    fn stall(agent: &mut Agent, generation: u32) {
        loop {
            assert!(agent.deliver(generation, &vec![b'q'; 64 * 1024]));
            assert_eq!(agent.flush(), Flush::Open);
            if agent
                .channel
                .as_ref()
                .is_some_and(|chan| !chan.pending.is_empty())
            {
                return;
            }
        }
    }

    /// The peak is the cap, never the cap plus a payload.
    #[test]
    fn a_channel_queue_is_bounded_before_the_bytes_are_taken() {
        let root = Scratch::new("agent-queue");
        let mut agent = bind_in(&root, "q.agent");
        let (_peer, live) = open(&mut agent);

        assert!(
            agent.deliver(live, &vec![0u8; MAX_CHANNEL_QUEUE - 1]),
            "a queue below the cap is served"
        );
        assert!(
            agent.deliver(live, &[0u8]),
            "and one that lands exactly on it still is"
        );
        assert!(
            !agent.deliver(live, &vec![0u8; 64 * 1024]),
            "the frame that would cross the cap is refused"
        );
        assert_eq!(
            agent
                .channel
                .as_ref()
                .expect("the served connection")
                .pending
                .len(),
            MAX_CHANNEL_QUEUE,
            "and none of it is queued: the peak is the cap, not the cap plus a payload"
        );
    }

    /// A second connection is not refused while one is served — it waits in the backlog
    /// and is greeted, with everything it wrote meanwhile, once the slot frees.
    ///
    /// The bytes are what make this a test of *waiting*: a connection the daemon had
    /// accepted and dropped would take them with it, and `ssh-add` would see a socket
    /// that answers and then hangs up rather than one that takes a moment.
    #[test]
    fn a_second_connection_waits_in_the_backlog_rather_than_being_refused() {
        let root = Scratch::new("agent-serialized");
        let mut agent = bind_in(&root, "s.agent");
        let (_first, first_generation) = open(&mut agent);

        let mut second =
            UnixStream::connect(agent.path()).expect("connect a second time to the agent socket");
        second
            .write_all(b"\0\0\0\x01\x0b")
            .expect("write a request");
        assert_eq!(
            agent.accept(true, ID),
            Accept::Idle,
            "a connection arriving while one is served must be left where it is"
        );

        assert_eq!(
            agent.forget(),
            Some(first_generation),
            "the first connection frees the slot"
        );
        let Accept::Opened(generation) = agent.accept(true, ID) else {
            panic!("the one that waited is taken next");
        };
        assert_ne!(
            generation, first_generation,
            "the successor must be named something else, or a frame the client sent \
             for the peer that had the slot is indistinguishable from one for this"
        );

        let mut buf = [0u8; 8];
        assert!(
            matches!(agent.read(&mut buf), ReadOutcome::Data(5) if &buf[..5] == b"\0\0\0\x01\x0b"),
            "the request written while it waited must still be there to read"
        );
    }

    /// A served connection that says nothing is given up at its deadline, so the peer
    /// behind it in the backlog is not held off for the life of the session.
    #[test]
    fn a_silent_served_connection_is_given_up_at_its_deadline() {
        let root = Scratch::new("agent-stalled");
        let mut agent = bind_in(&root, "t.agent");
        let (_peer, live) = open(&mut agent);

        let due = agent
            .deadline()
            .expect("a served connection has a deadline");
        assert!(
            agent
                .close_if_idle(
                    due.checked_sub(Duration::from_nanos(1))
                        .expect("a moment earlier")
                )
                .is_none(),
            "a connection inside its window is not stalled yet"
        );
        assert_eq!(
            agent.close_if_idle(due),
            Some(live),
            "and one that reaches it is closed, with the client owed the news"
        );
        assert!(!agent.is_serving(), "the slot is free again");
        assert!(
            agent.close_if_idle(due + AGENT_IDLE_TIMEOUT).is_none(),
            "an empty slot is nothing to announce a second close for"
        );
    }

    /// The slot comes back from a connection the client closed against a peer that
    /// stopped reading — and silently, that client having forgotten it already.
    ///
    /// The same argument `Flush::Finished` makes: an `AgentClose` here answers a close
    /// the client made itself, and it is the clock rather than a write that gives up on
    /// the queue behind it.
    #[test]
    fn a_stalled_close_frees_the_slot_without_announcing_itself() {
        let root = Scratch::new("agent-stalled-close");
        let mut agent = bind_in(&root, "c.agent");
        let (_peer, live) = open(&mut agent);

        stall(&mut agent, live);
        agent.close_from_client(live);
        assert!(
            agent.is_serving(),
            "a queue that cannot drain holds the slot"
        );

        let due = agent.deadline().expect("and so still has a deadline");
        assert!(
            agent.close_if_idle(due).is_none(),
            "the slot comes back with nothing said about it"
        );
        assert!(!agent.is_serving(), "but it does come back");
    }

    #[test]
    fn data_after_a_client_close_is_ignored() {
        let root = Scratch::new("agent-data-after-close");
        let mut agent = bind_in(&root, "c.agent");
        let (_peer, live) = open(&mut agent);
        stall(&mut agent, live);
        agent.close_from_client(live);

        let queued = agent
            .channel
            .as_ref()
            .expect("still draining")
            .pending
            .len();
        assert!(agent.deliver(live, b"late"), "late data is not a fault");
        assert_eq!(
            agent
                .channel
                .as_ref()
                .expect("still draining")
                .pending
                .len(),
            queued,
            "data received after AgentClose was queued behind the closed stream"
        );
    }

    /// The window is against the last byte, not against the accept: `ssh(1)` holds one
    /// agent connection across a whole authentication and issues several requests down
    /// it, so a first-byte deadline would cut a working exchange off partway.
    ///
    /// A byte that *moved*, which is the whole of what `Agent::flush` touches on: the
    /// daemon queues in one pass and writes on the next, so the reply below is delivered
    /// exactly as the loop delivers one.
    #[test]
    fn traffic_either_way_pushes_the_idle_deadline_out() {
        let root = Scratch::new("agent-traffic");
        let mut agent = bind_in(&root, "r.agent");
        let (mut peer, live) = open(&mut agent);

        let accepted_at = agent
            .deadline()
            .expect("a served connection has a deadline");
        assert!(
            agent.deliver(live, b"\0\0\0\x05\x0c-reply"),
            "the client answers"
        );
        assert_eq!(
            agent.flush(),
            Flush::Open,
            "and the daemon hands it to the peer"
        );
        assert!(
            agent.close_if_idle(accepted_at).is_none(),
            "a reply from the client is traffic, and the old deadline must not close it"
        );

        let moved_at = agent.deadline().expect("still served");
        peer.write_all(b"\0\0\0\x01\x0b").expect("a second request");
        let mut buf = [0u8; 8];
        assert!(
            matches!(agent.read(&mut buf), ReadOutcome::Data(5)),
            "and reaches us"
        );
        assert!(
            agent.close_if_idle(moved_at).is_none(),
            "so is a second request from the peer, which is the ssh(1) case"
        );
    }

    /// A frame that reached the queue and got no further is not traffic: refreshing the
    /// deadline for merely *queued* bytes would keep the one connection the clock exists
    /// to end — a peer that has stopped reading — alive to [`MAX_CHANNEL_QUEUE`].
    #[test]
    fn a_queue_that_cannot_be_written_does_not_push_the_deadline_out() {
        let root = Scratch::new("agent-queued");
        let mut agent = bind_in(&root, "u.agent");
        let (_peer, live) = open(&mut agent);

        stall(&mut agent, live);

        // Read after the last write that moved something, so what follows has to leave
        // it exactly where it is.
        let due = agent
            .deadline()
            .expect("a served connection has a deadline");
        assert!(
            agent.deliver(live, &vec![b'q'; 64 * 1024]),
            "the client sends another frame at a peer reading none of them"
        );
        assert_eq!(
            agent.deadline(),
            Some(due),
            "queuing is not moving: a frame the peer never reads must not buy the \
             connection another window"
        );
        assert_eq!(
            agent.flush(),
            Flush::Open,
            "and the write that cannot place it is not a failure either"
        );
        assert_eq!(
            agent.deadline(),
            Some(due),
            "nor does the attempt to write it, which moved no byte"
        );
    }

    /// An empty backlog must not be reported as the failure that takes the socket out
    /// of the poll set.
    #[test]
    fn an_empty_backlog_is_not_a_failure_to_back_off_from() {
        let root = Scratch::new("agent-idle");
        let mut agent = bind_in(&root, "i.agent");
        assert_eq!(agent.accept(true, ID), Accept::Idle);
    }
}
