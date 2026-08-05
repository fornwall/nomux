//! Agent forwarding, end to end (`IMPLEMENTATION.md` § 6.7).
//!
//! The daemon serves the session's child an `ssh-agent` socket and carries what
//! crosses it to the attached client as channels. Everything that can go wrong with
//! that lives here: the flag a client has to ask for, a socket the daemon cannot
//! bind, a client that is not there to answer, the two caps, and the one channel
//! state that used to cost a core.

mod harness;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use nomux_proto::{Frame, FrameType, HELLO_AGENT_FORWARD, RESUME_FROM_START};

use harness::{
    SPIN_WINDOW, Session, cpu_ticks, read_uninterrupted, socket_capacity, still_serving,
};

/// A session created without the flag serves no socket at all: forwarding bypasses
/// the user's `ForwardAgent` decision, so it must never be on by default.
#[test]
fn agent_forwarding_is_off_unless_asked_for() {
    let (session, _client, ok) = Session::attached("agent_off");
    assert!(!ok.agent);
    assert!(
        !session.agent_socket().exists(),
        "no agent socket should exist for a session that did not ask for one"
    );
}

/// Agent forwarding, end to end: the child gets a socket, a connection to it
/// becomes a channel, and bytes cross in both directions untouched.
#[test]
fn agent_forwarding_proxies_a_connection_in_both_directions() {
    let (session, mut client, ok) = Session::attached_with("agent", HELLO_AGENT_FORWARD);
    assert!(ok.agent, "daemon should report the agent socket as served");

    // The child must be able to find it, which is the whole point.
    client.input(0, b"echo \"sock=$SSH_AUTH_SOCK\"\n");
    let (seen, _) = client.read_until(".agent", ok.resume_from);
    let expected = format!("sock={}", session.agent_socket().display());
    assert!(seen.contains(&expected), "child environment: {seen:?}");

    let mut agent = session.connect_agent();
    let chan = client.next_chan(FrameType::AgentOpen);

    // Child to client.
    agent.write_all(b"\0\0\0\x01\x0b").expect("write request");
    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            chan,
            data: b"\0\0\0\x01\x0b",
        },
        "agent bytes must arrive verbatim"
    );

    // Client to child.
    client.send(&Frame::AgentData {
        chan,
        data: b"\0\0\0\x05\x0c-reply",
    });
    let mut reply = [0u8; 11];
    agent.read_exact(&mut reply).expect("read response");
    assert_eq!(&reply, b"\0\0\0\x05\x0c-reply");

    // And the close travels too.
    drop(agent);
    assert_eq!(client.next_chan(FrameType::AgentClose), chan);
}

/// An agent socket the daemon cannot bind costs the session its forwarding and
/// nothing else, and `HelloOk` says so.
///
/// `start_session` calls this the daemon's "one remaining silent degradation": a
/// client that asked for forwarding is answered `agent: false` with no reason
/// given. Silent to the *user* is not the same as untested, and it was both — every
/// agent test here asks for forwarding and gets it, so nothing exercised the arm
/// that logs and carries on. A daemon that instead refused the `Hello`, or started
/// the session and reported `agent: true` off the flag it was asked for rather than
/// off the socket it has, would pass the whole agent suite.
///
/// A directory in the socket's place is the cheapest real version of the failure:
/// `Agent::bind` unlinks first, which a directory survives, and then `bind` refuses
/// it. What is asserted is the honest flag, a session that still starts and serves,
/// and — the half a bare flag does not cover — that the child is not handed an
/// `SSH_AUTH_SOCK` pointing at a socket nothing is listening on, which would hang
/// `git push` rather than failing it.
#[test]
fn an_agent_socket_that_cannot_be_bound_leaves_an_honest_flag_and_a_live_session() {
    // Started before the directory is planted, because the run directory is the
    // daemon's to create — and the agent socket is not bound until the first
    // `Hello`, which is what leaves room to plant anything at all.
    let session = Session::start("agent_unbindable");
    fs::create_dir_all(session.agent_socket())
        .expect("plant a directory where the agent socket goes");

    let mut client = session.connect();
    let ok = client.hello_with(HELLO_AGENT_FORWARD, RESUME_FROM_START);
    assert!(
        !ok.agent,
        "the daemon reported an agent socket it never bound"
    );

    // The default is what makes this a wait the child has to satisfy: `sock=[` is in
    // the command line the line discipline echoes before any shell reads it, so a
    // wait for that is over before the expansion happens.
    client.input(0, b"echo \"sock=[${SSH_AUTH_SOCK:-none}]\"\n");
    let (seen, _) = client.read_until("none]", ok.resume_from);
    assert!(
        !seen.contains(&session.agent_socket().display().to_string()),
        "the child was pointed at an agent socket the daemon does not serve, so \
         everything it signs with will hang rather than fail: {seen:?}"
    );

    assert!(
        session.agent_socket().is_dir(),
        "the daemon replaced something it does not own"
    );
}

/// With no client attached there is nothing to answer a signature request, so a
/// connection is accepted and closed at once: `git push` fails with the same error
/// as a missing agent instead of hanging until the user reattaches.
///
/// § 6.7 says it of both halves — the connection that arrives while detached, and
/// the channel that was already open the moment the client went. The second is the
/// one with somebody actually waiting on it: a `git push` mid-signature when the
/// network drops learns now, rather than at whatever hour the user reattaches, and
/// the daemon cannot hold the channel for a client that will come back with no idea
/// the channel exists (ids are never reissued).
#[test]
fn agent_connections_fail_fast_while_detached() {
    let (session, mut client, _) = Session::attached_with("agent_detached", HELLO_AGENT_FORWARD);

    // Open before the client leaves, and confirmed open — otherwise the read below
    // could be answered by a socket the daemon had not yet accepted.
    let mut mid_flight = session.connect_agent();
    let _chan = client.next_chan(FrameType::AgentOpen);
    drop(client);

    // Through the harness rather than `Read::read`: these sockets carry a receive
    // timeout, so a signal ends the call with `EINTR` rather than the kernel
    // restarting it, and a raw read would report that as the channel having failed.
    let mut buf = [0u8; 1];
    assert_eq!(
        read_uninterrupted(&mut mid_flight, &mut buf).expect("read from the open channel"),
        0,
        "a channel that was open when the client left must be closed, not held"
    );

    let mut arriving = session.connect_agent();
    assert_eq!(
        read_uninterrupted(&mut arriving, &mut buf).expect("read from agent socket"),
        0,
        "a detached session must close agent connections immediately"
    );
}

/// The channel table is capped, and beyond the cap the daemon closes rather than
/// queueing — a child that leaks agent connections must not be able to make the
/// daemon track them.
#[test]
fn agent_channels_are_capped() {
    let (session, mut client, _) = Session::attached_with("agent_cap", HELLO_AGENT_FORWARD);

    // The literal because `agent::MAX_AGENT_CHANNELS` is inside the binary, which has no
    // lib target for an integration test to import from. § 6.7's 8, pinned against the
    // document by `agent::tests::the_channel_cap_is_the_one_the_document_gives`.
    let cap = 8_usize;
    let held: Vec<UnixStream> = (0..cap).map(|_| session.connect_agent()).collect();
    let mut ids: Vec<u32> = (0..cap)
        .map(|_| client.next_chan(FrameType::AgentOpen))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), cap, "channel ids must never repeat");

    let mut extra = session.connect_agent();
    let mut buf = [0u8; 1];
    assert_eq!(
        read_uninterrupted(&mut extra, &mut buf).expect("read from agent socket"),
        0,
        "the connection past the cap must be closed, not queued"
    );
    drop(held);
}

/// Regression: an id is not reissued once its own channel has closed, so an
/// `AgentClose` and an `AgentOpen` crossing in flight cannot alias (§ 6.7).
#[test]
fn an_agent_channel_id_outlives_the_channel_that_held_it() {
    let (session, mut client, _) = Session::attached_with("agent_ids", HELLO_AGENT_FORWARD);

    let peer = session.connect_agent();
    let closed = client.next_chan(FrameType::AgentOpen);
    drop(peer);
    assert_eq!(client.next_chan(FrameType::AgentClose), closed);

    let _next = session.connect_agent();
    assert_ne!(
        client.next_chan(FrameType::AgentOpen),
        closed,
        "the id of a closed channel was reissued, and a client that has not yet read \
         the AgentClose cannot tell the two apart"
    );
}

/// The *per-channel* queue is capped too, and reaching it costs that channel and
/// nothing else.
///
/// `MAX_AGENT_CHANNELS` has a test above; `MAX_CHANNEL_QUEUE` had none, and the one
/// test that comes near it sizes itself "comfortably short of" the cap on purpose —
/// so `Agent::deliver` returning `false`, and the `close_agent_channel` the daemon
/// answers that with, were both unreachable from the suite. § 6.7 makes this the
/// bound on what one stalled `ssh-add` can make the daemon hold: without it a client
/// can push a quarter of the default ring per channel, eight times over, into a
/// process that has stopped reading.
///
/// What has to be true is not just that the channel goes but that *only* it goes. A
/// daemon answering the overflow by dropping the client, or by forgetting every
/// channel the way `on_detached` does, would also stop the queue growing — and would
/// take a second, innocent agent connection and the user's shell with it. So the
/// sibling channel is opened first, left idle across the whole overflow, and then
/// used; and the session is driven through the PTY afterwards.
#[test]
fn an_agent_channel_whose_queue_outgrows_the_cap_is_closed_alone() {
    /// `agent::MAX_CHANNEL_QUEUE`, which is private to the daemon. Written down
    /// rather than derived, and the assertions do not rest on the number being
    /// exact: everything below sends *past* it by a wide margin, so a cap that moved
    /// down still closes the channel and one that moved up fails here loudly rather
    /// than passing quietly.
    const CAP: usize = 256 * 1024;
    /// One frame's worth. Comfortably under `MAX_PAYLOAD`, and large enough that the
    /// burst below is a few dozen frames rather than thousands.
    const CHUNK: usize = 32 * 1024;
    /// How far past the cap the client pushes. The daemon flushes between passes, so
    /// what it can shed is bounded by what the peer's socket will take — measured
    /// below — and everything beyond that has to sit in the queue.
    const OVERSHOOT: usize = 256 * 1024;

    let (session, mut client, ok) = Session::attached_with("agent_queue", HELLO_AGENT_FORWARD);
    client.make_ready("-echo", None, ok.resume_from);

    let capacity = socket_capacity();

    // The bystander, opened first so that it is unambiguously live before anything
    // goes wrong on the other channel.
    let mut bystander = session.connect_agent();
    let quiet = client.next_chan(FrameType::AgentOpen);
    let mut drowned_peer = session.connect_agent();
    let drowned = client.next_chan(FrameType::AgentOpen);

    // Neither peer ever reads, so past `capacity` every byte stays in the daemon's
    // own queue for that channel. No fence between the frames, which is the whole
    // difference from the spin test: it round-trips each one precisely to keep the
    // queue under the cap, and this one is about crossing it.
    let filler = vec![b'q'; CHUNK];
    let mut sent = 0usize;
    while sent < capacity + CAP + OVERSHOOT {
        client.send(&Frame::AgentData {
            chan: drowned,
            data: &filler,
        });
        sent += filler.len();
    }

    assert_eq!(
        client.next_chan(FrameType::AgentClose),
        drowned,
        "a channel whose queue passed {CAP} bytes must be closed, and it must be \
         that channel: {sent} bytes were pushed at a peer that read none of them"
    );
    // And the process on the other end learns now rather than blocking on a socket
    // nothing will ever write to again — § 6.7's argument for closing over holding,
    // reached here by the queue rather than by the client going away. Whatever the
    // daemon had already flushed comes out first; what it was still holding is
    // exactly what it refused to go on holding.
    let mut delivered = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match read_uninterrupted(&mut drowned_peer, &mut chunk) {
            Ok(0) => break,
            Ok(read) => delivered += read,
            Err(err) => panic!("reading from the channel the daemon closed: {err}"),
        }
    }
    assert!(
        delivered < sent,
        "the daemon delivered all {sent} bytes, so nothing was ever queued and the \
         close above was not the cap firing"
    );

    // The bystander is still a channel: bytes cross it in the direction the daemon
    // has to be awake to serve.
    bystander.write_all(b"\0\0\0\x01\x0b").expect("write");
    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            chan: quiet,
            data: b"\0\0\0\x01\x0b",
        },
        "the daemon took a second agent channel down with the one that overflowed"
    );

    // And the session itself, which is what a client would actually notice losing.
    still_serving(&mut client, "NOMUX-STILL-SERVING");
}

/// One agent channel the daemon is left holding a queue for, closed by the client
/// against a peer that has read none of it.
///
/// The state both regressions below are about, and the whole of what they share.
struct Overqueued {
    session: Session,
    client: harness::Client,
    /// The local `ssh-add`'s end of the channel, which has read nothing.
    peer: UnixStream,
    /// How much the client pushed at it.
    sent: usize,
    /// What a unix socket on this host took of that before it stopped taking any.
    capacity: usize,
}

/// Builds [`Overqueued`] on a session named `name`.
///
/// The queue is what the close has to find for the channel to outlive it, so it is
/// grown a frame at a time, each fenced by a round trip the daemon can only answer by
/// having read it: the daemon queues everything it decodes in one pass and writes it
/// out on the pass after, so handing it the lot at once would take the queue past
/// `MAX_CHANNEL_QUEUE` and have the channel closed for *that* instead — which looks
/// nothing like the state these tests are about.
///
/// Nothing answers an `AgentClose` — the client closed the channel and has already
/// forgotten it — so the round trip through the child behind it is what says the
/// daemon has acted on it, frames being handled in the order they arrive. It is also
/// the first half of the session still working.
fn overqueued_then_closed(name: &str) -> Overqueued {
    /// One `AgentData` frame per round, and small beside `MAX_CHANNEL_QUEUE`: the
    /// daemon closes a channel whose queue outgrows that, which would take away the
    /// very state under test.
    const CHUNK: usize = 32 * 1024;
    /// How far past what the peer's socket will hold the client sends. It is what is
    /// left over that the daemon has to keep, and it has to be enough to be certain
    /// of — but comfortably short of `MAX_CHANNEL_QUEUE`.
    const OVERSHOOT: usize = 96 * 1024;

    let (session, mut client, ok) = Session::attached_with(name, HELLO_AGENT_FORWARD);
    // `-echo` so that everything on the output stream is the child answering rather
    // than the line discipline repeating the question, which is what lets the markers
    // below be read one after the other from a stream that joins up.
    client.make_ready("-echo", None, ok.resume_from);

    let capacity = socket_capacity();
    let peer = session.connect_agent();
    let chan = client.next_chan(FrameType::AgentOpen);

    let filler = vec![b'k'; CHUNK];
    let mut sent = 0usize;
    while sent < capacity + OVERSHOOT {
        client.send(&Frame::AgentData {
            chan,
            data: &filler,
        });
        sent += filler.len();
        client.send(&Frame::Ping { nonce: 0x5EED });
        drop(client.next_of(FrameType::Pong));
    }

    client.send(&Frame::AgentClose { chan });
    still_serving(&mut client, "NOMUX-CLOSE-ACTED-ON");
    Overqueued {
        session,
        client,
        peer,
        sent,
        capacity,
    }
}

/// Regression: a write that fails on a channel the client has already closed is not
/// announced back to it.
///
/// `Agent::flush` reported a failed write as `Flush::Failed` whatever the channel's
/// state, and the daemon answers that with an `AgentClose` — for a channel the client
/// closed itself and has already forgotten, which is what `Flush::Finished` exists to
/// say instead. Ids are never reissued, so the frame names nothing the client can look
/// up, and a client that treats an unknown channel as a protocol error loses the
/// session over it.
///
/// The state is the one `close_from_client` leaves behind when its flush does not
/// finish: a queue too big for the peer's socket, the client's close on top of it, and
/// then the local `ssh-add` exiting with the reply still owed. The next `POLLOUT` on
/// that channel is an `EPIPE`.
///
/// Nothing arrives to be asserted about, so the assertion is over a window with a fence
/// at each end: the close is acted on before the peer goes, and the marker after it can
/// only be answered by a daemon that has been round its loop since. Every frame in
/// between is read, and `read_until` fails the test on any that is not the session's
/// own chatter — an `AgentClose` among them being the bug.
#[test]
fn a_failed_write_on_a_closed_agent_channel_is_never_announced() {
    let Overqueued {
        session: _session,
        mut client,
        peer,
        ..
    } = overqueued_then_closed("agent_epipe");

    // The `ssh-add` on the other end exits with the reply still queued.
    drop(peer);

    still_serving(&mut client, "NOMUX-STILL-SERVING");
}

/// Regression: a channel the client has closed against a peer that stopped reading
/// leaves the daemon asleep rather than spinning at a full core.
///
/// `close_from_client` shuts the read half of the daemon's end of the channel down,
/// and a unix socket in that state reports itself readable on every pass for ever.
/// `Agent::read` is right to decline to act on a closing channel — taking that end of
/// file at face value would drop the very queue the close exists to deliver — so
/// nothing consumes the readiness and nothing can. The daemon armed `POLLIN` on every
/// channel a saturated client was not already holding back, so `poll` returned
/// instantly for ever; with the local peer's buffer full there was no `POLLOUT` to
/// make progress against either, and the daemon burned a core until the peer read.
/// `Agent::watches` now reports read interest of its own, and the daemon arms
/// `POLLIN` only where it is set.
///
/// Measured as processor time, because that is the only thing the bug touches: every
/// frame is still answered, every byte still arrives, and the sole symptom is the
/// fan. The two answers are nowhere near each other — a spinning daemon burns a
/// hundred ticks a second and a sleeping one burns none — so the threshold sits an
/// order of magnitude below one core and cannot be reached by a loaded machine
/// scheduling a daemon that has nothing to do.
///
/// Everything [`cpu_ticks`]'s window needs to be true was established before it
/// starts: the queue is provably non-empty, the close has provably been acted on, and
/// the drain afterwards proves the channel was still there to be spun on.
#[test]
fn a_closed_agent_channel_whose_peer_stopped_reading_leaves_the_daemon_asleep() {
    /// Five ticks is 50 ms of processor time against [`SPIN_WINDOW`]: a tenth of one
    /// core, where the bug is a whole one and the fix is exactly zero.
    const TOLERATED: u64 = 5;

    let Overqueued {
        session,
        mut client,
        peer: mut agent,
        sent,
        capacity,
    } = overqueued_then_closed("agent_spin");

    let burned = cpu_ticks(session.child.id());
    assert!(
        burned <= TOLERATED,
        "the daemon burned {burned} clock ticks in {SPIN_WINDOW:?} holding one closed \
         agent channel, with a shell that is doing nothing and a client that is \
         asking for nothing"
    );

    // And the queue really was there to spin on. A channel the daemon had forgotten
    // at the close would have taken what it was holding with it, so reading the lot
    // back is what makes the measurement above a measurement of the right state —
    // and it is § 6.7's promise that a reply the client already sent still reaches
    // the process waiting on it.
    let mut received = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match read_uninterrupted(&mut agent, &mut chunk) {
            Ok(0) => break,
            Ok(read) => received += read,
            Err(err) => panic!("reading what the closed channel still owed: {err}"),
        }
    }
    assert_eq!(
        received, sent,
        "the daemon was not holding the queue this test measured it against: a \
         channel it had let go of at the close takes the rest with it, and no more \
         than the {capacity} bytes already in the kernel could have arrived"
    );

    still_serving(&mut client, "NOMUX-STILL-SERVING");
}
