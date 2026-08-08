//! Agent forwarding, end to end (`IMPLEMENTATION.md` § 6.7).
//!
//! The daemon serves the child an `ssh-agent` socket and carries what crosses it to
//! the attached client, one connection at a time. What can go wrong with that: the flag
//! a client has to ask for, a socket the daemon cannot bind, a client that is not there
//! to answer, a second peer arriving mid-exchange, the slot changing hands under frames
//! already sent for the peer that had it, the queue cap, and a connection the client
//! closed with a queue behind it.

mod harness;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use nomux_protocol::{Frame, FrameType, RESUME_FROM_START};

use harness::{
    Client, SPIN_WINDOW, Session, cpu_ticks, read_uninterrupted, socket_capacity, still_serving,
};

/// Waits for the next `AgentOpen` or `AgentClose`, ignoring the session's own chatter,
/// asserts that it is `want` — `why` saying what that would mean — and hands back the
/// generation it names, which everything the client sends for that channel has to carry.
///
/// Which of the two arrives is the question these tests keep asking, the daemon serving
/// one connection at a time being visible as nothing but the *order* of the boundaries.
fn expect_agent(client: &mut Client, want: FrameType, why: &str) -> u32 {
    let (ty, generation) = next_agent_boundary(client);
    assert_eq!(ty, want, "{why}");
    generation
}

/// The next `AgentOpen` or `AgentClose`, whichever comes first, and the channel it names.
fn next_agent_boundary(client: &mut Client) -> (FrameType, u32) {
    loop {
        let (ty, payload) = client.frame_owed("a frame from the daemon");
        let decoded = Frame::decode(ty, &payload);
        if let Ok(Frame::AgentOpen { generation } | Frame::AgentClose { generation }) = decoded {
            return (ty, generation);
        }
        assert!(
            matches!(
                ty,
                FrameType::Output | FrameType::InputAck | FrameType::Pong
            ),
            "unexpected {ty:?} while waiting for an agent frame: {decoded:?}"
        );
    }
}

/// Forwarding is opt-in: it bypasses the user's `ForwardAgent` decision, so a
/// session that did not ask for it is served no socket at all.
#[test]
fn agent_forwarding_is_off_unless_asked_for() {
    let (session, _client, ok) = Session::attached("agent_off");
    assert!(!ok.agent);
    assert!(
        !session.agent_socket().exists(),
        "no agent socket should exist for a session that did not ask for one"
    );
}

/// Agent forwarding, end to end: the child gets a socket, a connection to it is
/// announced, and bytes cross in both directions untouched.
#[test]
fn agent_forwarding_proxies_a_connection_in_both_directions() {
    let (session, mut client, ok) = Session::attached_with("agent", true, false);
    assert!(ok.agent, "daemon should report the agent socket as served");

    // The child must be able to find it.
    client.input(0, b"echo \"sock=$SSH_AUTH_SOCK\"\n");
    let (seen, _) = client.read_until(".agent", ok.resume_from);
    let expected = format!("sock={}", session.agent_socket().display());
    assert!(seen.contains(&expected), "child environment: {seen:?}");

    let mut agent = session.connect_agent();
    let generation = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "a connection to the session's agent socket is announced to the client",
    );

    // Child to client.
    agent.write_all(b"\0\0\0\x01\x0b").expect("write request");
    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            generation,
            data: b"\0\0\0\x01\x0b",
        },
        "agent bytes must arrive verbatim, under the channel they came from"
    );

    // Client to child.
    client.send(&Frame::AgentData {
        generation,
        data: b"\0\0\0\x05\x0c-reply",
    });
    let mut reply = [0u8; 11];
    agent.read_exact(&mut reply).expect("read response");
    assert_eq!(&reply, b"\0\0\0\x05\x0c-reply");

    // And the close travels too, for the channel that ended and not for some other.
    drop(agent);
    assert_eq!(
        expect_agent(
            &mut client,
            FrameType::AgentClose,
            "the peer hanging up ends the connection on the wire too",
        ),
        generation,
        "and the close names the channel that ended"
    );
}

/// An agent socket the daemon cannot bind costs the session its forwarding and
/// nothing else, and `HelloOk` says so.
///
/// A directory in the socket's place is the cheapest real version of the failure:
/// `Agent::bind` unlinks first, which a directory survives, and then `bind` refuses
/// it. `agent: false` must come off the socket the daemon has rather than the flag it
/// was asked for — and the child must not be handed an `SSH_AUTH_SOCK` pointing at a
/// socket nothing listens on, which would hang `git push` rather than fail it.
#[test]
fn an_agent_socket_that_cannot_be_bound_leaves_an_honest_flag_and_a_live_session() {
    // Started before the directory is planted: the run directory is the daemon's to
    // create, and the socket is not bound until the first `Hello`.
    let session = Session::start("agent_unbindable");
    fs::create_dir_all(session.agent_socket())
        .expect("plant a directory where the agent socket goes");

    let mut client = session.connect();
    let ok = client.hello_with(true, false, RESUME_FROM_START);
    assert!(
        !ok.agent,
        "the daemon reported an agent socket it never bound"
    );

    // The `:-none` default is what makes this a wait only the child can satisfy:
    // `sock=[` is in the command line the line discipline echoes before any shell
    // reads it, so a wait for that would be over before the expansion happens.
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

/// With no client attached nothing can answer a signature request, so § 6.7 has the
/// daemon close rather than hold: `git push` fails like it would against a missing
/// agent instead of hanging until the user reattaches.
///
/// Both halves — the connection that arrives while detached, and the one that was
/// already being served when the client went. The second cannot be held either: the
/// returning client hears no `AgentOpen` for it and would answer nothing.
#[test]
fn agent_connections_fail_fast_while_detached() {
    let (session, mut client, _) = Session::attached_with("agent_detached", true, false);

    // Confirmed open before the client leaves, otherwise the read below could be
    // answered by a socket the daemon had not yet accepted.
    let mut mid_flight = session.connect_agent();
    expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "the connection has to be established before the client leaves",
    );
    drop(client);

    // Through the harness rather than `Read::read`: these sockets carry a receive
    // timeout, so a signal ends the call with `EINTR` rather than the kernel
    // restarting it, and a raw read would report that as the connection having failed.
    let mut buf = [0u8; 1];
    assert_eq!(
        read_uninterrupted(&mut mid_flight, &mut buf).expect("read from the open connection"),
        0,
        "a connection that was being served when the client left must be closed, not held"
    );

    let mut arriving = session.connect_agent();
    assert_eq!(
        read_uninterrupted(&mut arriving, &mut buf).expect("read from agent socket"),
        0,
        "a detached session must close agent connections immediately"
    );
}

/// One connection at a time (§ 6.7), and the rest **wait**: a second peer arriving
/// mid-exchange is left in the listen backlog rather than accepted or refused, and is
/// served the moment the first ends.
///
/// Waiting rather than being turned away is the whole of what serializing buys, and the
/// two assertions that separate the two outcomes are the *order* of the boundary frames
/// — the open cannot precede the close — and the request the second peer wrote before
/// its turn arriving afterwards. A connection the daemon had accepted and dropped would
/// have taken those bytes with it, and `ssh-add` would see an agent that answers and
/// then hangs up rather than one that takes a moment.
#[test]
fn a_second_agent_connection_waits_for_the_one_being_served() {
    let (session, mut client, ok) = Session::attached_with("agent_serial", true, false);
    client.make_ready("-echo", None, ok.resume_from);

    let first = session.connect_agent();
    expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "the first peer has the slot",
    );

    let mut second = session.connect_agent();
    second
        .write_all(b"\0\0\0\x01\x0b")
        .expect("write while waiting for a turn");

    // Two round trips through the daemon, which is what makes this a fence: an
    // `AgentOpen` the daemon had already queued for `second` would be ahead of the
    // second `Pong` in the stream, and `next_of` refuses anything but this session's
    // own chatter on the way to what it was asked for.
    for _ in 0..2 {
        client.send(&Frame::Ping);
        drop(client.next_of(FrameType::Pong));
    }

    drop(first);
    expect_agent(
        &mut client,
        FrameType::AgentClose,
        "the slot has to come free before anything else can have it",
    );
    let generation = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "and the peer that waited is greeted only then",
    );

    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            generation,
            data: b"\0\0\0\x01\x0b",
        },
        "what the waiting peer wrote before its turn must still be there"
    );

    still_serving(&mut client, "NOMUX-STILL-SERVING");
}

/// Regression: frames the client sent for a peer that has ended are never answered by
/// the peer that took the slot next.
///
/// The daemon accepts local peers out of band from the client's stream, so before the
/// generation there was nothing to tell one incarnation of the one slot from the next:
/// an `AgentData` written before the client read `AgentClose` was delivered to whoever
/// held the slot when it arrived, and the client's own `AgentClose` for the peer that
/// had gone closed its successor — silently, that being the one close the daemon does
/// not report back.
///
/// The race is driven the other way round rather than waited for. The frames go out
/// *after* the turnover has been read off the wire, which is the same thing to a daemon
/// that cannot see when the client read: what reaches it is bytes naming a channel it no
/// longer holds, which is exactly what a frame overtaken by the turnover is.
#[test]
fn frames_for_a_peer_that_ended_are_not_answered_by_its_successor() {
    let (session, mut client, ok) = Session::attached_with("agent_turnover", true, false);
    client.make_ready("-echo", None, ok.resume_from);

    let ending = session.connect_agent();
    let stale = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "the peer that is about to end holds the slot",
    );
    let mut successor = session.connect_agent();

    drop(ending);
    assert_eq!(
        expect_agent(
            &mut client,
            FrameType::AgentClose,
            "the peer that ended frees the slot",
        ),
        stale,
        "the close names the channel that ended"
    );
    let live = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "and the one that waited takes it",
    );
    assert_ne!(
        live, stale,
        "a successor named what its predecessor was named is the whole bug: the daemon \
         would have no way left to tell their frames apart"
    );

    // What the client had in flight for the peer that ended, in the order it wrote them.
    client.send(&Frame::AgentData {
        generation: stale,
        data: b"STALE",
    });
    client.send(&Frame::AgentClose { generation: stale });
    // Both are decoded before this is answered, frames being handled in order, so what
    // follows cannot outrun them.
    client.send(&Frame::Ping);
    drop(client.next_of(FrameType::Pong));

    client.send(&Frame::AgentData {
        generation: live,
        data: b"FRESH",
    });
    let mut seen = [0u8; 5];
    let mut filled = 0;
    while filled < seen.len() {
        match read_uninterrupted(&mut successor, &mut seen[filled..]) {
            Ok(0) => panic!(
                "the successor was closed by an `AgentClose` the client sent for the \
                 peer that ended, and was never told"
            ),
            Ok(read) => filled += read,
            Err(err) => panic!("reading what the successor was served: {err}"),
        }
    }
    assert_eq!(
        &seen, b"FRESH",
        "the successor was handed bytes its predecessor was owed"
    );

    // And it is still the channel the daemon is serving, in the other direction too.
    successor.write_all(b"\0\0\0\x01\x0b").expect("write");
    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            generation: live,
            data: b"\0\0\0\x01\x0b",
        },
        "the successor is still served, under the channel it was opened as"
    );

    // Nothing was said about the stale close, and nothing else was disturbed:
    // `still_serving` fails on any frame that is not the session's own chatter.
    still_serving(&mut client, "NOMUX-STILL-SERVING");
}

/// The queue is capped too (§ 6.7's bound on what one stalled `ssh-add` can make the
/// daemon hold), and reaching it costs that connection and nothing else.
///
/// *Only* it goes is the harder half: a daemon answering the overflow by dropping the
/// client, or by giving the agent socket up, would also stop the queue growing. So the
/// session is driven through the PTY afterwards, and the freed slot is asked for again
/// — a listener that survived the overflow is one the next `ssh-add` can still use.
#[test]
fn an_agent_connection_whose_queue_outgrows_the_cap_is_closed_alone() {
    /// `agent::MAX_CHANNEL_QUEUE`, private to the daemon. Nothing below rests on it
    /// being exact: everything is sent *past* it by a wide margin, so a cap that moved
    /// down still closes the connection and one that moved up fails here loudly.
    const CAP: usize = 256 * 1024;
    /// One frame's worth: under `MAX_PAYLOAD`, and large enough that the burst below
    /// is a few dozen frames rather than thousands.
    const CHUNK: usize = 32 * 1024;
    /// How far past the cap to push. The daemon flushes between passes, so what it can
    /// shed is bounded by what the peer's socket takes — measured below — and the rest
    /// has to sit in the queue.
    const OVERSHOOT: usize = 256 * 1024;

    let (session, mut client, ok) = Session::attached_with("agent_queue", true, false);
    client.make_ready("-echo", None, ok.resume_from);

    let capacity = socket_capacity();

    let mut drowned_peer = session.connect_agent();
    let drowned = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "the peer that will stop reading is served first",
    );

    // The peer never reads, so past `capacity` every byte stays in the daemon's own
    // queue. No fence between frames, which is the whole difference from
    // `overqueued_then_closed`: it fences to stay under the cap, this crosses it.
    let filler = vec![b'q'; CHUNK];
    let mut sent = 0usize;
    while sent < capacity + CAP + OVERSHOOT {
        client.send(&Frame::AgentData {
            generation: drowned,
            data: &filler,
        });
        sent += filler.len();
    }

    expect_agent(
        &mut client,
        FrameType::AgentClose,
        &format!(
            "a queue that passed {CAP} bytes must cost the connection: {sent} bytes \
             were pushed at a peer that read none of them"
        ),
    );
    // And the process on the other end learns now rather than blocking on a socket
    // nothing will write to again — § 6.7's argument for closing over holding, reached
    // by the queue rather than by the client going away.
    let mut delivered = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match read_uninterrupted(&mut drowned_peer, &mut chunk) {
            Ok(0) => break,
            Ok(read) => delivered += read,
            Err(err) => panic!("reading from the connection the daemon closed: {err}"),
        }
    }
    assert!(
        delivered < sent,
        "the daemon delivered all {sent} bytes, so nothing was ever queued and the \
         close above was not the cap firing"
    );

    // The socket is still the session's to serve: the slot the overflow freed is one
    // the next connection can have, and bytes cross it in the direction the daemon has
    // to be awake for.
    let mut next = session.connect_agent();
    let generation = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "the slot the overflow freed is one the next connection can have",
    );
    next.write_all(b"\0\0\0\x01\x0b").expect("write");
    let payload = client.next_of(FrameType::AgentData);
    assert_eq!(
        Frame::decode(FrameType::AgentData, &payload).expect("decode"),
        Frame::AgentData {
            generation,
            data: b"\0\0\0\x01\x0b",
        },
        "the daemon took its agent socket down with the connection that overflowed"
    );

    // And the session itself, which is what a client would actually notice losing.
    still_serving(&mut client, "NOMUX-STILL-SERVING");
}

/// One agent connection the daemon is left holding a queue for, closed by the client
/// against a peer that has read none of it — the state both regressions below need.
struct Overqueued {
    session: Session,
    client: Client,
    /// The local `ssh-add`'s end of the connection, which has read nothing.
    peer: UnixStream,
    /// How much the client pushed at it, every byte of which the daemon owes it. What
    /// this peer's socket did not take is [`still_owed`], and the state both tests below
    /// are about is the one where that is not zero.
    sent: usize,
}

/// Builds [`Overqueued`] on a session named `name`.
///
/// The queue is grown a frame at a time, each fenced by a round trip: the daemon queues
/// everything it decodes in one pass and writes it out on the next, so handing it the
/// lot at once would take the queue past `MAX_CHANNEL_QUEUE` and close the connection
/// for *that* instead — not the state these tests are about.
///
/// Nothing answers an `AgentClose`, the client having forgotten the connection, so the
/// round trip through the child behind it is what says the daemon has acted on the
/// close, frames being handled in the order they arrive.
///
/// How much of what is sent here reaches the daemon's queue is a guess and cannot be
/// anything else: `socket_capacity` measures a fresh `UnixStream::pair` with a patience
/// of its own rather than the socket the daemon accepted. Under-measure and the daemon
/// gives the lot to the peer's kernel buffer before the close, `flush` reports
/// `Finished`, and the connection is forgotten there — leaving neither test below
/// anything to be about. [`still_owed`] is what makes a bad guess a failure instead.
fn overqueued_then_closed(name: &str) -> Overqueued {
    /// One `AgentData` frame per round, small beside `MAX_CHANNEL_QUEUE`.
    const CHUNK: usize = 32 * 1024;
    /// How far past what the peer's socket holds to send: the excess is what the daemon
    /// has to keep, and it stays comfortably short of `MAX_CHANNEL_QUEUE`.
    const OVERSHOOT: usize = 96 * 1024;

    let (session, mut client, ok) = Session::attached_with(name, true, false);
    // `-echo`, so everything on the output stream is the child answering rather than
    // the line discipline repeating the question, and the markers below can be read
    // one after another from a stream that joins up.
    client.make_ready("-echo", None, ok.resume_from);

    let capacity = socket_capacity();
    let peer = session.connect_agent();
    let generation = expect_agent(
        &mut client,
        FrameType::AgentOpen,
        "the connection this state is built on is served",
    );

    let filler = vec![b'k'; CHUNK];
    let mut sent = 0usize;
    while sent < capacity + OVERSHOOT {
        client.send(&Frame::AgentData {
            generation,
            data: &filler,
        });
        sent += filler.len();
        client.send(&Frame::Ping);
        drop(client.next_of(FrameType::Pong));
    }

    client.send(&Frame::AgentClose { generation });
    still_serving(&mut client, "NOMUX-CLOSE-ACTED-ON");
    Overqueued {
        session,
        client,
        peer,
        sent,
    }
}

/// How much of the `sent` bytes handed to the daemon for this peer it has still to hand
/// on, which is what a queue kept past the close looks like from outside.
///
/// Asked of the socket that took them and asked with `FIONREAD`, which consumes nothing.
/// Reading the queue out instead is what would end the state it is asked about: the
/// daemon flushes into whatever space frees, and a closing channel whose queue runs dry
/// is one it forgets on the spot. Nothing else is written to this socket, so what the
/// kernel is holding and what the daemon still owes account for `sent` between them.
fn still_owed(peer: &UnixStream, sent: usize) -> usize {
    let held = rustix::io::ioctl_fionread(peer);
    let taken = held.map_or(usize::MAX, |bytes| {
        usize::try_from(bytes).unwrap_or(usize::MAX)
    });
    assert!(
        taken <= sent,
        "the peer's socket answered `FIONREAD` with {taken} against the {sent} bytes \
         written at it, which is either an ask that failed ({held:?}) or a daemon \
         writing bytes nothing here gave it"
    );
    sent - taken
}

/// Regression: a write that fails on a connection the client has already closed is not
/// announced back to it.
///
/// `Agent::flush` reported a failed write as `Flush::Failed` whatever the connection's
/// state, and the daemon answers that with an `AgentClose` for a connection the client
/// closed itself and has forgotten — `Flush::Finished` is what it should say instead. A
/// client that reads that as the daemon contradicting itself loses the session over it.
///
/// The failing write is the `EPIPE` on the next `POLLOUT` after the local `ssh-add`
/// exits with the reply still queued. Nothing arrives to assert on, so the assertion is
/// the fence behind it: `still_serving` reads every frame in between and fails on any
/// that is not the session's own chatter.
#[test]
fn a_failed_write_on_a_closed_agent_channel_is_never_announced() {
    let Overqueued {
        session: _session,
        mut client,
        peer,
        sent,
    } = overqueued_then_closed("agent_epipe");

    // The reply the drop below leaves queued, asserted rather than assumed: a daemon
    // that owes this peer nothing has no write left to fail, and the negative assertion
    // at the foot of this test would pass over a run that never reached the bug. Asked
    // at this moment because this is the one it has to hold at, and asked without
    // reading a byte, which is what would empty the queue it asks about.
    assert!(
        still_owed(&peer, sent) > 0,
        "the daemon had handed this peer every one of the {sent} bytes sent to it \
         before it died, so nothing here can produce the failing write this test is \
         named for: the connection was emptied and forgotten at the close, and what \
         follows asserts nothing"
    );

    // The `ssh-add` on the other end exits with the reply still queued.
    drop(peer);

    still_serving(&mut client, "NOMUX-STILL-SERVING");
}

/// Regression: a connection the client has closed against a peer that stopped reading
/// leaves the daemon asleep rather than spinning at a full core.
///
/// `close_from_client` shuts down the read half of the daemon's end, and a unix socket
/// in that state reports itself readable for ever. `Agent::read` is right to decline to
/// act on a closing connection — taking that end of file at face value would drop the
/// very queue the close exists to deliver — so nothing consumes the readiness, and with
/// the peer's buffer full there is no `POLLOUT` to make progress against either.
/// `Agent::watch` reports read interest of its own, and the daemon arms `POLLIN` only
/// where it is set.
///
/// Processor time is the only thing the bug touches: every frame is still answered and
/// the sole symptom is the fan. A spinning daemon burns a hundred ticks a second and a
/// sleeping one none, so the threshold below sits an order of magnitude under one core.
#[test]
fn a_closed_agent_channel_whose_peer_stopped_reading_leaves_the_daemon_asleep() {
    /// Five ticks is 50 ms against [`SPIN_WINDOW`]: a tenth of one core, where the bug
    /// is a whole one and the fix is exactly zero.
    const TOLERATED: u64 = 5;

    let Overqueued {
        session,
        mut client,
        peer: mut agent,
        sent,
    } = overqueued_then_closed("agent_spin");

    // Established before the measurement rather than inferred from it: a daemon with
    // nothing left to write is a daemon with nothing to spin on, and the ticks it does
    // not burn then say only that this run never built the state.
    let owed = still_owed(&agent, sent);
    assert!(
        owed > 0,
        "the daemon had handed this peer every one of the {sent} bytes sent to it, so \
         it was holding no queue to spin on and the measurement below is one of an \
         idle daemon in a state this test is not about"
    );

    let burned = cpu_ticks(session.child.id());
    assert!(
        burned <= TOLERATED,
        "the daemon burned {burned} clock ticks in {SPIN_WINDOW:?} holding one closed \
         agent connection, with a shell that is doing nothing and a client that is \
         asking for nothing"
    );

    // And the queue the daemon was holding is handed over rather than merely held:
    // § 6.7's promise that a reply already sent still reaches the process waiting on
    // it, which is the whole reason a closing channel keeps its queue at all.
    let mut received = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match read_uninterrupted(&mut agent, &mut chunk) {
            Ok(0) => break,
            Ok(read) => received += read,
            Err(err) => panic!("reading what the closed connection still owed: {err}"),
        }
    }
    assert_eq!(
        received,
        sent,
        "the daemon was not holding the queue this test measured it against: a \
         connection it had let go of at the close takes the rest with it, and no more \
         than the {} bytes already in the kernel could have arrived",
        sent - owed
    );

    still_serving(&mut client, "NOMUX-STILL-SERVING");
}
