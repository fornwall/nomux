//! End-to-end tests against the real binary: `nomux daemon` driven over its unix
//! socket, speaking the wire protocol directly, so the PTY, the ring buffer and the
//! resume path are exercised rather than a mock of them.
//!
//! The two invariants that matter (`IMPLEMENTATION.md` § 9): input is never duplicated,
//! and output is never lost unless a `Gap` was reported. What is here is what those are
//! made of — resume, gap and ring exactness, the refusals a connection can earn, the
//! takeover rules, and the repaint a gap owes the child.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "integration test crate; clippy.toml's allow-*-in-tests reaches only #[cfg(test)]"
)]

mod harness;

use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_protocol::{
    ErrorCode, Frame, FrameType, HEADER_LEN, Hello, PROTOCOL_VERSION, RESUME_FROM_START,
    SERVER_PREAMBLE, WinSize, decode_header,
};

use harness::{
    Client, DEFAULT_TEST_RING, FRAME_PATIENCE, Rng, Session, Spawned, StreamModel, hello_frame,
    nomux_with_shell, poll_by, poll_until, position, read_uninterrupted, reconnect_until_gap,
    run_root, still_serving,
};

/// `daemon::PENDING_HELLO_TIMEOUT`: how long a connection that has not said `Hello`
/// keeps the one pending slot. Private to the daemon, mirrored here, and the two must
/// move together.
const PENDING_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// The one pending slot is taken back from a peer that connects and then says nothing.
///
/// § 6.4 has the daemon promote a connection on its `Hello`, and it holds exactly one
/// ungreeted connection at a time — the listener leaves the poll set while that slot is
/// taken, so nobody is accepted only to be dropped unheard. Without a deadline on it, a
/// peer of this uid that connects and stops there holds every later attach off for the
/// life of the session, which is the one denial of service reachable from outside the
/// daemon. Nothing else in this suite waits that deadline out.
///
/// The peer that must eventually be served connects *before* the deadline fires rather
/// than after it, which is what makes this a test about the slot rather than about a
/// socket the daemon closed: it sits in the listen backlog for as long as the silent one
/// holds the slot, and the `HelloOk` it is answered with can only come from a daemon that
/// took the slot back and accepted it. The close is also timed, because a daemon that
/// hung up on every ungreeted connection at once would satisfy the rest of this while
/// refusing the liveness probe `harness::wait_until_answering` and § 6.6's `list` are
/// built on.
#[test]
fn a_connection_that_never_greets_gives_the_pending_slot_back() {
    // One deadline for both waits (`harness::poll_by`), and above [`FRAME_PATIENCE`] by
    // the timeout this spends before either of them can begin.
    let deadline = Instant::now() + PENDING_HELLO_TIMEOUT + FRAME_PATIENCE;
    let session = Session::start("no_hello");

    // By hand rather than through a `Client`, which has no way to say nothing: what is
    // under test is a peer that never reaches the protocol at all.
    // Sampled *before* the `connect` below, and that is the whole of what makes the
    // deadline assertion at the foot of this test correct rather than a race: the
    // daemon's own five-second clock starts at its `accept`, which this `connect` is
    // what triggers, so anything read after it — the `connect_by` behind it included —
    // is time already on the daemon's clock and not on this one. Taken afterwards, every
    // microsecond the test thread was descheduled for came off the measured elapse and
    // the assertion fired on a daemon that had waited the whole five seconds.
    let connected = Instant::now();
    let mut silent = UnixStream::connect(&session.socket).expect("connect without greeting");
    silent
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set a read timeout");

    // Queued behind it from here: `connect` on a listening unix socket completes in the
    // kernel, so this is in the backlog whether or not the daemon has looked, and the
    // backlog is ordered — nothing can serve this one before the silent one is dealt with.
    let mut waiting = session.connect_by(deadline);

    let mut chunk = [0u8; 64];
    let closed = poll_by(deadline, || {
        match read_uninterrupted(&mut silent, &mut chunk) {
            Ok(0) => true,
            Ok(n) => panic!(
                "the daemon sent {n} bytes to a connection that never greeted; nothing \
                 precedes a HelloOk on this wire but the preamble behind it"
            ),
            // The read timeout expiring, which is the deadline above's to answer.
            Err(err) if err.kind() == ErrorKind::WouldBlock => false,
            Err(err) => panic!("reading the connection that never greeted: {err}"),
        }
    });
    assert!(
        closed,
        "a peer that connected and said nothing still holds the daemon's one pending \
         slot, so every attach after it — this test's own included — waits for the life \
         of the session"
    );
    // Measured from before the `connect` that provokes the daemon's `accept`, so this
    // elapse is never shorter than the one the daemon's own clock ran: a close inside
    // this is the daemon refusing ungreeted connections rather than deadlining them,
    // which would cost § 6.6 the probe it identifies a live session with.
    assert!(
        connected.elapsed() >= PENDING_HELLO_TIMEOUT,
        "the ungreeted connection was closed after {:?}, inside the {PENDING_HELLO_TIMEOUT:?} \
         § 6.4 gives a relayed Hello to arrive in",
        connected.elapsed()
    );

    // And the slot came back to the peer that had been waiting in it since before the
    // deadline fired — greeted, and driving the shell rather than merely acknowledged.
    // Through `harness::still_serving`, whose marker is arithmetic: the session is at
    // the PTY's default `ECHO|ICANON`, so the line discipline puts the command line back
    // on the master before any shell has read it, and a marker written out whole would
    // be satisfied by that echo rather than by the child.
    waiting.hello(RESUME_FROM_START);
    still_serving(&mut waiting, "NOMUX-AFTER-PENDING");
}

/// A client claiming output the session never produced is clamped down to the end of
/// the stream rather than believed (`IMPLEMENTATION.md` § 4.2).
///
/// The upper clamp is exercised nowhere else. Without it the daemon sets `sent_through`
/// past everything it holds and the session looks dead — with no gap reported, because
/// nothing was dropped.
///
/// The end of the stream is *known* here rather than bracketed, which is what makes the
/// clamp falsifiable. `-echo` keeps the line discipline's copy of the command line off
/// the stream, and `printf` without a newline against an empty `PS1` makes the marker
/// the last byte the child writes, so the offset the read returns is where it ends.
#[test]
fn an_out_offset_past_the_end_of_the_stream_is_clamped_rather_than_believed() {
    /// Comfortably past anything a shell echoing one line has ever written.
    const FAR: u64 = 1 << 20;

    let (session, mut client, ok) = Session::attached("clamp_high");
    let ready = client.make_ready("-echo", None, ok.resume_from);

    let first = b"printf NOMUX-BEFORE-CLAMP\n";
    client.input(ready.in_offset, first);
    let (_, end) = client.read_until("NOMUX-BEFORE-CLAMP", ready.offset);
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(end + FAR);
    // An equality rather than an upper bound: clamping to the ring's *base* also comes
    // in under anything claimed, also reports no gap, and also leaves the read at the
    // end of this test finding its marker.
    assert_eq!(
        resumed.resume_from,
        end,
        "an out_offset past the end of the stream must be clamped to the end of it, \
         which is the {end} bytes this client has already been handed against the {} \
         it claimed",
        end + FAR
    );
    assert_eq!(
        resumed.in_applied,
        ready.in_offset + first.len() as u64,
        "the session's input position must survive a client claiming output it \
         never received"
    );

    // And it is a live session rather than one gone quiet behind a resume point past
    // its own stream, which is the whole shape of the fault.
    client.input(resumed.in_applied, b"echo NOMUX-AFTER-CLAMP\n");
    client.read_until("NOMUX-AFTER-CLAMP", resumed.resume_from);
}

/// The invariant that matters most: a client replaying input it already sent —
/// because the `InputAck` was lost with the connection — must not run it twice.
///
/// Echo off throughout: with it on, the first frame carrying the marker is the terminal
/// repeating the *command*, so the resume point lands ahead of the one legitimate
/// occurrence rather than behind it. With `-echo` the marker can only be the shell's own
/// output, and so can the fence — reading that back proves everything queued in front of
/// it, the replay included, has been through the PTY.
///
/// Three resends, because `on_input` has two defences and the obvious replay exercises
/// neither. Sending the applied bytes *exactly* lands on `end == in_applied`, where the
/// `end > in_applied` guard is false and the trim inside it never runs. The other two
/// put a frame on each side of that line: one ending below it, which only the guard
/// stops from rewinding the session's position, and one straddling it, which only the
/// trim stops from re-running its overlap.
#[test]
fn replayed_input_is_applied_exactly_once() {
    /// How much of the command the short resend carries. Any amount ending below
    /// `in_applied` asks the same question; a whole word keeps a transcript readable.
    const PREFIX: usize = 8;

    let (session, mut client, ok) = Session::attached("dedup");
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);

    // A unique marker rather than a counter, which would need shell state.
    let command = b"echo NOMUX-ONCE-MARKER\n";
    client.input(ready.in_offset, command);
    let (_, offset) = client.read_until("NOMUX-ONCE-MARKER", ready.offset);
    let applied = ready.in_offset + command.len() as u64;

    drop(client);
    let mut client = session.connect();

    // Resume claiming we never got the ack, then replay the identical bytes.
    let ok = client.hello(offset);
    assert_eq!(
        ok.in_applied, applied,
        "daemon must report input already applied"
    );
    client.input(ready.in_offset, command);

    // The same resend cut short, which is the one shape that can move `in_applied`
    // *backwards* and the only one the `end > in_applied` guard answers alone.
    client.input(
        ready.in_offset,
        command.get(..PREFIX).expect("part of a line"),
    );
    // Frames are handled in the order they arrive, so a `Pong` for a ping behind them
    // is the daemon having decoded both — and decoded is what matters, since a socket
    // closed with output queued loses whatever `fill` had buffered.
    client.send(&Frame::Ping);
    drop(client.next_of(FrameType::Pong));
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(offset);
    assert_eq!(
        resumed.in_applied,
        applied,
        "a resend that stopped {} bytes short of where the daemon had got to moved \
         the session's input position backwards, so every offset the client sends \
         from here is one the daemon will refuse as an input gap",
        command.len() - PREFIX
    );

    // And a resend that overlaps what was applied *and* carries something new, which is
    // what a client actually sends: `offset < in_applied < end`, the frame the trim
    // exists for. The overlap is the whole command, so a daemon that stopped trimming
    // runs the marker again rather than something unrecognisable.
    let mut overlapping = command.to_vec();
    overlapping.extend_from_slice(b"echo NOMUX-FENCE\n");
    client.input(ready.in_offset, &overlapping);
    let (seen, _) = client.read_until("NOMUX-FENCE", resumed.resume_from);

    let echoes = seen.matches("NOMUX-ONCE-MARKER").count();
    assert_eq!(
        echoes, 0,
        "replayed input was applied a second time; transcript: {seen:?}"
    );
}

/// Input above `in_applied` is a hole in the input stream, and the daemon refuses it
/// and closes rather than guessing at what is missing (`IMPLEMENTATION.md` § 3).
///
/// The one error code with nothing else exercising it end to end. `in_applied` is
/// authoritative, so a client that skipped ahead has lost track of its own stream and
/// has to start again from what the daemon reports.
#[test]
fn input_that_skips_ahead_is_refused_and_the_connection_closed() {
    let (_session, mut client, _) = Session::attached("input_gap");

    // Nothing has been sent yet, so `in_applied` is zero and this claims a keystroke
    // the daemon never saw.
    client.input(1, b"echo NOMUX-NEVER-RUN\n");

    client.expect_error_among_output(
        ErrorCode::InputGap,
        "input above in_applied must be refused as an input gap",
    );
    client.expect_eof("an Error{InputGap}");
}

/// Markers bracketing the stream [`predictable_blob`] produces. Lower case, which that
/// alphabet cannot contain, so neither can occur inside the data it delimits and the
/// read that stops at the opening one stops at the byte before the stream.
const BLOB_BEGIN: &str = "nomux-blob-begin";

const BLOB_END: &str = "nomux-blob-end";

/// A byte stream a test can predict exactly and a ring cannot hold cheaply.
///
/// *Predictable*, so a byte the daemon labels with an offset can be checked against the
/// byte that offset names — the whole of what a `Gap` claims. *Aperiodic and
/// near-incompressible*, so "more than the ring holds" is a property of the data rather
/// than an assumption about the ring: `/dev/zero` fits in any ring that compresses,
/// leaving nothing dropped and nothing to report. Drawn from `0x21..=0x60`, which is
/// what lets it cross a terminal in canonical mode untouched.
fn predictable_blob(len: usize) -> Vec<u8> {
    // Any fixed seed: nothing explores a space, it just needs the same stream twice.
    let mut blob = Rng::new(0x9e37_79b9_7f4a_7c15).bytes(len);
    for byte in &mut blob {
        *byte = 0x21 + *byte % 0x40;
    }
    blob
}

/// A session whose child is writing a stream the test knows byte for byte.
struct Planted {
    /// Absolute output offset of the first byte of that stream.
    stream_start: u64,
    /// The whole of what the child writes from there — the blob and the closing marker
    /// — so an offset into the stream is an index into this.
    expected: Vec<u8>,
    /// Touched by the child once every byte above has been written: how a client that
    /// is deliberately not reading learns the child has finished.
    sentinel: PathBuf,
    /// One past the last input byte sent here.
    in_offset: u64,
}

/// Puts a blob where the session's child can read it, sets it writing, and leaves the
/// client's stream positioned at exactly the first byte of it.
///
/// The opening marker is read to completion before the line producing the blob is sent,
/// which is what makes the arithmetic exact: the shell writes nothing more until it has
/// read the next line, so the offset that read returns is one past the marker rather
/// than one past whatever else was in the frame carrying it.
fn plant_blob(
    session: &Session,
    client: &mut Client,
    from: u64,
    in_offset: u64,
    len: usize,
) -> Planted {
    let mut expected = predictable_blob(len);
    fs::write(session.root.join("blob"), &expected).expect("plant the blob the child reads");

    let begin = format!("printf '{BLOB_BEGIN}'\n");
    client.input(in_offset, begin.as_bytes());
    let (_, stream_start) = client.read_until(BLOB_BEGIN, from);

    let run = format!("cat blob; printf '{BLOB_END}'; touch produced\n");
    client.input(in_offset + begin.len() as u64, run.as_bytes());

    expected.extend_from_slice(BLOB_END.as_bytes());
    Planted {
        stream_start,
        expected,
        sentinel: session.root.join("produced"),
        in_offset: in_offset + (begin.len() + run.len()) as u64,
    }
}

/// Reads the session's output to the end of `planted.expected`, checking every byte
/// against the byte its offset names (`harness::StreamModel`, and the canonical
/// statement of why the check is by absolute offset), and returns the gaps followed
/// on the way.
fn read_against(client: &mut Client, planted: &Planted, from: u64) -> Vec<(u64, u64)> {
    let model = StreamModel {
        bytes: &planted.expected,
        stream_start: planted.stream_start,
        context: String::new(),
    };
    let end = planted.stream_start + planted.expected.len() as u64;
    // Nothing for `sits_in` to add to the offset: this model has no structure of its
    // own to place a byte in, and nothing here is drawn from a seed.
    model
        .follow(
            client,
            from,
            end,
            usize::MAX,
            Instant::now() + FRAME_PATIENCE,
            |_| String::new(),
        )
        .gaps
}

/// A gap reported at the handshake must name the byte the stream really resumes at.
///
/// The handshake half of the wiring `Ring::base` → `HelloOk.resume_from`, which
/// `src/ring.rs` pins only as arithmetic in isolation. The byte comparison catches only
/// a base reported *too low*, so `resume_from` is pinned to a value rather than a range
/// — which the setup makes exact: the child has finished before this client attaches,
/// the ring is exactly full, and a `VecDeque` of `RING` bytes retains exactly `RING`.
#[test]
fn a_gap_at_the_handshake_names_the_byte_the_stream_actually_resumes_at() {
    /// Small enough that half a megabyte overruns it many times over, and larger than
    /// the terminal setup preceding the blob — so all that is evicted is predictable.
    const RING: usize = 16 * 1024;
    /// Comfortably past [`RING`], and small enough to compare in milliseconds. The
    /// client is *away*, so there is no send queue to outrun, only the ring.
    const PRODUCED: usize = 512 * 1024;

    let session = Session::start_with_ring("gap_exact_hello", RING);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // Echo off, so the stream from the marker on is the child's own bytes.
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let planted = plant_blob(
        &session,
        &mut client,
        ready.offset,
        ready.in_offset,
        PRODUCED,
    );

    // The command that makes the gap has to be the daemon's before the connection goes:
    // a socket closed with output still queued resets, and the daemon lets the
    // connection go on `ECONNRESET` without decoding what its last `fill` had buffered.
    client.wait_for_input_ack(planted.in_offset);
    drop(client);

    assert!(
        poll_until(Duration::from_secs(10), || planted.sentinel.exists()),
        "the child never finished writing its {PRODUCED} bytes"
    );

    // Greeted once rather than through `reconnect_until_gap`, which exists for the case
    // where whether the ring has overflowed *yet* is a question about the scheduler.
    // The sentinel says the child has written every byte, so the gap is owed on the
    // first `Hello` and retrying would only make a failure take twenty seconds.
    let mut client = session.connect();
    let resumed = client.hello(planted.stream_start);
    assert!(
        resumed.gap(planted.stream_start),
        "the child wrote {PRODUCED} bytes through a {RING}-byte ring while this \
         client was away, and the daemon reported no gap"
    );

    let stream_end = planted.stream_start + planted.expected.len() as u64;
    let oldest_held = stream_end - RING as u64;
    assert_eq!(
        resumed.resume_from,
        oldest_held,
        "the daemon offered to resume at {}, where the oldest byte a full \
         {RING}-byte ring can still serve is {oldest_held}. Below it and the daemon \
         is serving bytes from somewhere other than where it says; above it and it \
         has thrown away {} bytes of the user's scrollback that it was still \
         holding",
        resumed.resume_from,
        oldest_held.abs_diff(resumed.resume_from)
    );

    let gaps = read_against(&mut client, &planted, resumed.resume_from);
    assert!(
        gaps.is_empty(),
        "the child had finished before this client attached, so nothing could \
         overflow while it read: {gaps:?}"
    );
}

/// The mid-stream half of the same invariant: a client that never left is still told
/// when the ring overran it.
///
/// A different path from the test above rather than a duplicate. There the client comes
/// back and `on_hello` answers with a flag on `HelloOk`; nothing reconnects here, so
/// what this waits for is the `Gap` *frame* `pump_output` sends down a connection that
/// has been attached the whole time — the case a slow terminal on a busy session meets.
///
/// Deterministic because the state it needs is monotone rather than timed. The client
/// reads nothing, so `sent_through` stops at whatever the send queue and the socket
/// buffers hold between them and stays there; the child writes several times that
/// through a ring keeping [`RING`], so `base` passes `sent_through` and can never come
/// back under it. From that moment the `Gap` is owed, and draining a single byte
/// collects it. The sentinel is how a client that is not reading learns the child has
/// finished, and the gap is pinned to a number: one, at exactly `stream_end - RING`.
#[test]
fn an_overflow_that_outruns_an_attached_client_is_reported_as_a_gap_mid_stream() {
    /// Larger than the 64 KiB the daemon takes off the PTY in one pass, so a client
    /// still keeping up cannot be gapped by a single read. That leaves exactly one way
    /// to reach a gap here: the client falling behind on purpose.
    const RING: usize = 128 * 1024;
    /// Comfortably past everything between the child and the client put together — the
    /// daemon's megabyte of queued output, the 256 KiB frame it may overshoot that by,
    /// the kernel's socket buffers, and [`RING`].
    const PRODUCED: usize = 8 << 20;

    let session = Session::start_with_ring("midstream_gap", RING);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // The first byte of the stream rather than `!ok.gap(RESUME_FROM_START)`, which is
    // `!(resume_from > u64::MAX)` and so is true of every answer a daemon can give.
    assert_eq!(
        ok.resume_from, 0,
        "a session nobody has attached to before is holding everything it ever \
         produced, so every gap below is one this connection was sent"
    );

    // Echo off, so everything from the opening marker on is the child's own bytes. The
    // sentinel is touched last, so its arrival means every byte before it is already in
    // the ring — or already evicted from it.
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let planted = plant_blob(
        &session,
        &mut client,
        ready.offset,
        ready.in_offset,
        PRODUCED,
    );

    // And from here to the sentinel the client reads nothing, which is the whole setup:
    // the daemon's send queue fills, `sent_through` stops with it, and the ring runs
    // away from a client that has not gone anywhere.
    assert!(
        poll_until(Duration::from_secs(10), || planted.sentinel.exists()),
        "the child never finished writing its {PRODUCED} bytes"
    );

    let stream_end = planted.stream_start + planted.expected.len() as u64;
    let oldest_held = stream_end - RING as u64;
    let gaps = read_against(&mut client, &planted, planted.stream_start);
    let (sent_through, base) = *gaps.first().expect(
        "the ring overran a client that never detached and nothing said so: the \
         whole stream arrived contiguous, which it cannot have been",
    );
    assert!(
        sent_through > planted.stream_start,
        "the gap must interrupt a stream this client was already receiving — that \
         is what makes it mid-stream rather than the handshake's"
    );
    assert_eq!(
        base,
        oldest_held,
        "the daemon resumed this client at {base}, where the oldest byte a full \
         {RING}-byte ring can still serve is {oldest_held}. Below it and the stream \
         is being served from somewhere other than where it says; above it and {} \
         bytes the ring was still holding were thrown away without a word",
        oldest_held.abs_diff(base)
    );
    assert_eq!(
        gaps.len(),
        1,
        "the child had finished before this client read a byte, so the ring was \
         static and one gap is all there was to report: {gaps:?}"
    );
}

/// § 6.4's whole sentence, rather than its first clause: "the previous connection
/// receives `Error{TAKEOVER}` **and closes**", and the session goes to the newcomer.
///
/// A daemon that sent the error and kept the old connection in its poll set would leave
/// two peers believing they hold the session, the evicted one told never to reconnect
/// (§ 6.4) and still receiving output; one that evicted the incumbent without promoting
/// the newcomer leaves the shell running with nobody attached. So all three are
/// asserted, in the order the daemon establishes them.
#[test]
fn a_second_client_takes_over_and_the_first_is_told_why() {
    let (session, mut first, _) = Session::attached("takeover");

    let mut second = session.connect();
    second.hello(RESUME_FROM_START);

    first.expect_error(
        ErrorCode::Takeover,
        "an evicted client must learn it was a takeover, not a network fault",
    );
    // The refusal was the daemon's goodbye, and nothing may follow it — `expect_eof`
    // fails on a second `Error`, which would be the daemon refusing this peer for some
    // further reason rather than having finished with it.
    first.expect_eof("an Error{TAKEOVER}");

    // And the session is the newcomer's, which is the half the eviction exists for: a
    // round trip through the *child*, so what is asserted is a client that can drive the
    // shell rather than one that merely got a `HelloOk`. That is what
    // `harness::still_serving` buys and a marker of this test's own would not: nothing
    // here ever called `make_ready`, so the PTY is at its default `ECHO|ICANON` and the
    // line discipline echoes the command line back on the master before the shell is
    // scheduled — a literal marker is found in the echo of the request for it, and the
    // takeover would read as proven by bytes that never reached the child.
    still_serving(&mut second, "NOMUX-TOOK-OVER");
}

/// The opt-in opposite of takeover: the newcomer learns that the slot is occupied,
/// while the incumbent keeps driving the shell. Once that incumbent deliberately
/// detaches, the same kind of greeting succeeds. The ordinary takeover test above keeps
/// the flag's default pinned separately.
///
/// This is also the suite's only `Detach`, every other departure here being a socket
/// dropped — the *unclean* case. What separates the deliberate one is that nothing may be
/// lost: the daemon closes the connection and keeps the input position, which is the
/// `in_applied` compared below rather than an incidental step on the way to the
/// conditional attach.
#[test]
fn a_conditional_attach_refuses_to_displace_but_succeeds_after_detach() {
    let (session, mut incumbent, _) = Session::attached("if_detached");

    let mut refused = session.connect();
    refused.send(&Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        agent_forward: false,
        repaint_ctrl_l: false,
        if_detached: true,
        out_offset: RESUME_FROM_START,
        win: harness::WIN,
        term: "xterm-256color",
    }));
    refused.expect_error(
        ErrorCode::AlreadyAttached,
        "a conditional attach must distinguish an occupied slot from a takeover",
    );
    refused.expect_eof("an Error{ALREADY_ATTACHED}");

    // The incumbent is still the one driving the shell, asked for in the arithmetic
    // `harness::still_serving` sends: this session was never made ready, so its line
    // discipline echoes whatever is written at it and a literal marker would come back
    // whether or not a shell ever ran the line. What it returns is the input position
    // the daemon must report below — the line is `still_serving`'s to compose, so a
    // length written out here would be a guess at somebody else's string.
    let sent = still_serving(&mut incumbent, "NOMUX-STILL-ATTACHED");

    incumbent.send(&Frame::Detach);
    incumbent.expect_eof("a Detach after a refused conditional attach");
    drop(incumbent);

    let mut resumed = session.connect();
    let accepted = resumed.hello_if_detached(RESUME_FROM_START);
    assert_eq!(
        accepted.in_applied, sent,
        "the refusal and detach changed the session's input position"
    );
    still_serving(&mut resumed, "NOMUX-CONDITIONALLY-ATTACHED");
}

/// The refusals a connection can earn against a session that is already serving, and
/// the session surviving each.
///
/// `handle_frame`'s "frame is not valid from a client" arm and its "already greeted"
/// one, both of `read_client`'s `reject(Protocol, …)` sites and all three of
/// `read_pending`'s have no other caller in the suite. The frame-boundary pair matters
/// most: a frame boundary the daemon has lost track of is a stream in which every
/// subsequent `Input` offset is somebody else's number.
///
/// Nine rows reaching a refusal by six routes. A `HelloOk`, an `Output` and a `Gap`
/// are well-formed frames the *daemon* sends, so they decode perfectly and fall through
/// the match. A second `Hello` decodes just as well and is refused for having arrived at
/// all, greeting being what *makes* a connection the client — honouring one would rewind
/// both streams under a session that has been running against them. A discriminant no
/// `FrameType` has never reaches the match at all. And a `Resize` whose payload is four
/// bytes rather than eight has a header that decodes and a body that does not — the one
/// case where the daemon knows how many bytes to skip and still must not.
///
/// The last three rows put an unparseable header, an unparseable `Hello` and a
/// perfectly good frame that simply is not one to a connection that has *not* greeted,
/// where `read_pending` answers rather than `read_client`: those are the sites reached
/// before a session exists for the connection, and the every-row `still_serving` that
/// opens a round is exactly what keeps them out of reach of the rows above. The `Ping`
/// among them is the shape a client speaking out of turn takes — well formed, current,
/// and refused for being spoken before the greeting that would give it a session.
///
/// Every row names the daemon's own words as well as its code, because the code does not
/// separate these sites: `Protocol` is what all seven of them answer with. For the second
/// `Hello` that is the whole question — its arm and the catch-all behind it produce the
/// same code, the same close and the same silence about the session, and differ in the
/// message and in nothing else.
///
/// Each row asserts all of what a refusal is: the code and the words, that the
/// connection then closes without a second complaint — which is what
/// `Client::expect_eof` separates from a frame quietly *honoured* — that the session's
/// input position did not move over it, and that a client can still drive the shell
/// afterwards. One session for all nine, so each row lands on one the rows before it
/// have abused.
#[test]
fn frames_a_client_may_not_send_are_refused_and_the_connection_closed() {
    let cases = refusals_a_connection_can_earn();
    let session = Session::start("refuse");
    // One deadline for the table (`harness::poll_by`): held by every connection the rows
    // make, and checked between rows so that a table which merely *finished* late says
    // which row it was. Nine rows of round trips against a daemon on this machine are a
    // small fraction of one wait's patience; what this replaces is a connection per row
    // minting a budget of its own, which bounded the table at the rows times the patience
    // rather than at the patience.
    let deadline = Instant::now() + FRAME_PATIENCE;
    let mut client = session.connect_by(deadline);
    let start = client.hello(RESUME_FROM_START).resume_from;

    for (round, case) in cases.iter().enumerate() {
        // Greeted *and* serving: the session is created by the first `Hello`, so a round
        // trip through the child is what puts the connection in the state this is about
        // rather than mid-handshake. A marker of the round's own, so a row cannot be
        // satisfied by the one before it.
        still_serving(&mut client, &format!("NOMUX-BEFORE-{round}"));

        if case.greeted {
            // What the daemon has taken ownership of, taken before the frame that is
            // going to be refused so that the reconnect below can be asked whether
            // refusing it moved the session's input position.
            let delivered = client.in_offset();
            (case.write)(&mut client);
            client.expect_error_saying(ErrorCode::Protocol, case.saying, case.what);
            client.expect_eof(case.what);
            drop(client);

            // The whole point of refusing on the connection's own terms: the shell is
            // still there, at the offsets it had, for whoever attaches next.
            client = session.connect_by(deadline);
            let resumed = client.hello(start);
            assert!(
                !resumed.gap(start),
                "{}: the session lost output while refusing one connection",
                case.what
            );
            assert_eq!(
                resumed.in_applied, delivered,
                "{}: the session's input position moved over a frame it refused, so \
                 every offset the next client sends is one the daemon will answer with \
                 an Error{{InputGap}}",
                case.what
            );
        } else {
            // Refused before it has a session to lose: `reject_pending` empties the slot
            // the newcomer is waiting in and never reaches the client, so what these
            // rows ask for is the refusal *and* an incumbent that never heard about it —
            // which is what the `still_serving` below, on the connection that was never
            // dropped, is the answer to.
            let mut ungreeted = session.connect_by(deadline);
            (case.write)(&mut ungreeted);
            ungreeted.expect_error_saying(ErrorCode::Protocol, case.saying, case.what);
            ungreeted.expect_eof(case.what);
        }

        still_serving(&mut client, &format!("NOMUX-SERVING-{round}"));
        assert!(
            Instant::now() < deadline,
            "row {round} ({}) left the table past its deadline, so the rest of it \
             would be decided by nextest's kill rather than by an assertion",
            case.what
        );
    }
}

/// One case of [`frames_a_client_may_not_send_are_refused_and_the_connection_closed`]:
/// what goes on the wire, what the daemon owes back, and what the failure says it was.
struct Refused {
    what: &'static str,
    write: fn(&mut Client),
    /// The daemon's own words for the refusal this row earns. See the test above for
    /// why the `ErrorCode` alone will not do.
    saying: &'static str,
    /// Whether the connection that sends it has greeted. A row that has not gets a
    /// connection of its own, and the session's client stays attached throughout.
    greeted: bool,
}

/// The table itself, out here so that the test reading it stays one screen long.
fn refusals_a_connection_can_earn() -> [Refused; 9] {
    [
        Refused {
            what: "a HelloOk, which is the daemon's own answer coming back at it",
            write: |client| {
                client.send(&Frame::HelloOk(nomux_protocol::HelloOk {
                    resume_from: 0,
                    in_applied: 0,
                    agent: false,
                }));
            },
            saying: "frame is not valid from a client",
            greeted: true,
        },
        Refused {
            what: "an Output, which only the session has any business producing",
            write: |client| {
                client.send(&Frame::Output {
                    offset: 0,
                    data: b"not from here",
                });
            },
            saying: "frame is not valid from a client",
            greeted: true,
        },
        Refused {
            what: "a Gap, which is a claim about a ring the client does not own",
            write: |client| {
                client.send(&Frame::Gap {
                    new_base_offset: 1 << 40,
                });
            },
            saying: "frame is not valid from a client",
            greeted: true,
        },
        Refused {
            what: "a second Hello on a connection that has already greeted",
            // Well formed and current, so nothing but *when* it arrives is wrong with
            // it: the same frame one connection earlier is how this session was made.
            write: |client| client.send(&hello_frame(false, false, RESUME_FROM_START)),
            saying: "this connection has already greeted",
            greeted: true,
        },
        Refused {
            what: "a header carrying a discriminant no FrameType has",
            // `0xff` is past every variant, and the length is zero so that a daemon
            // which skipped the frame rather than refusing it would find the stream
            // still framed — the failure has to come from the unreadable header.
            write: |client| client.send_raw(&[0xff, 0x00, 0x00, 0x00]),
            saying: "unparseable frame header",
            greeted: true,
        },
        Refused {
            what: "a Resize whose payload is half a WinSize",
            // Four bytes where the frame's four `u16`s need eight.
            write: |client| client.send_raw(&[0x06, 0x00, 0x00, 0x04, 0, 80, 0, 24]),
            saying: "unparseable frame payload",
            greeted: true,
        },
        Refused {
            what: "a header carrying a discriminant no FrameType has, before greeting",
            write: |client| client.send_raw(&[0xff, 0x00, 0x00, 0x00]),
            saying: "unparseable frame header",
            greeted: false,
        },
        Refused {
            what: "a Hello whose header declares one byte less than it delivers",
            // Encoded properly and then told to be shorter, so the header decodes and
            // says `Hello`: the daemon gets past "the first frame must be a Hello" and
            // fails on the frame itself, which is a `TERM` a byte short of its own
            // length prefix. The spare byte behind it goes with the connection.
            write: |client| {
                let mut wire = Vec::new();
                hello_frame(false, false, RESUME_FROM_START)
                    .encode(&mut wire)
                    .expect("encode a Hello");
                let short = u32::try_from(wire.len() - HEADER_LEN - 1)
                    .expect("a Hello is far shorter than a header can say");
                // § 2.1's header: the discriminant, then the length big endian in the
                // three bytes that follow — which are the low three of a `u32`.
                wire.get_mut(1..HEADER_LEN)
                    .expect("the length field of a header")
                    .copy_from_slice(
                        short
                            .to_be_bytes()
                            .get(1..)
                            .expect("the low three bytes of a u32"),
                    );
                client.send_raw(&wire);
            },
            saying: "unparseable Hello",
            greeted: false,
        },
        Refused {
            what: "a Ping from a connection that has not greeted yet",
            // Nothing is wrong with the frame: the daemon answers this exact one with a
            // `Pong` on every connection that greeted first. What it earns here is the
            // rule that a connection says `Hello` before it says anything — and the
            // incumbent, which is never told about any of it, is the other half of what
            // this row is for.
            write: |client| client.send(&Frame::Ping),
            saying: "first frame from a client must be Hello",
            greeted: false,
        },
    ]
}

/// A session whose shell cannot be started is refused with `Error{INTERNAL}`.
///
/// The one `ErrorCode` a running daemon never produced anywhere else: the answer to the
/// single failure that can happen *after* a client has been accepted and before it has a
/// session, `Pty::spawn` failing. A client that gets silence there waits out its own
/// attach deadline instead of reporting a host whose `$SHELL` is wrong, and `DESIGN.md`
/// § 6.4 has the client treat `INTERNAL` and `PROTOCOL` differently.
///
/// Getting `Pty::spawn` to fail at all takes a `$SHELL` the filesystem cannot tell from a
/// shell and the kernel can. Everything `pty::pick_shell` is able to recognise — a
/// relative path, a name that is gone, a file with no exec bit, a directory — it falls
/// back to `/bin/sh` for, which is § 6.1.1's precedence and costs the user nothing; what
/// is planted here passes all three of its probes (absolute, regular, `X_OK`) and is
/// still not a program. Its contents are neither an ELF header nor a `#!` line and no
/// `binfmt_misc` handler claims them, so the child's `execve` refuses it `ENOEXEC` and
/// that errno comes back up `crate::exec`'s failure pipe as the `io::Error` from
/// `Pty::spawn` that the daemon turns into this frame. Nothing else in the suite reaches
/// that arm.
#[test]
fn a_session_whose_shell_cannot_be_started_is_refused_as_an_internal_failure() {
    // In a run root of its own: the one `Session::start_with` is about to take is wiped
    // as it is handed out, which would take the planted shell with it.
    let planted = run_root("shell_broken_bin").join("not-a-program");
    fs::write(&planted, b"nomux: neither an ELF image nor a `#!` line\n")
        .expect("plant a shell that is not a program");
    fs::set_permissions(&planted, fs::Permissions::from_mode(0o755))
        .expect("make the planted shell pass an X_OK probe");

    let session = Session::start_with(
        "shell_broken",
        &DEFAULT_TEST_RING.to_string(),
        planted.to_str().expect("a run root that is UTF-8"),
    );
    let mut client = session.connect();

    // By hand: `Client::hello` panics on anything but a `HelloOk`, and the refusal is
    // the whole point.
    client.send(&hello_frame(false, false, RESUME_FROM_START));
    client.expect_error_among_output(
        ErrorCode::Internal,
        "a shell that cannot be started must be reported as the daemon's failure",
    );
    client.expect_eof("an Error{INTERNAL}");
}

/// `Resize` reaches the child's terminal (`IMPLEMENTATION.md` § 2.2).
///
/// Nothing else in the suite sends a `0x06`. Asserted at the child through `stty`, the
/// only witness that the geometry was *applied* rather than merely received. What an
/// arriving `Hello` does with the geometry is the next test, which asks it in the one
/// state that can tell a restatement from a skipped one.
#[test]
fn a_resize_reaches_the_child() {
    let (_session, mut client, ok) = Session::attached("resize");

    let wider = WinSize {
        cols: 132,
        rows: 43,
        xpixel: 0,
        ypixel: 0,
    };
    client.send(&Frame::Resize(wider));
    // `stty size` reports rows then columns, and the line discipline's echo of the
    // command carries neither number — so seeing them is the child's own answer.
    client.input(0, b"stty size\n");
    client.read_until("43 132", ok.resume_from);
}

/// An attach restates the geometry even when it has not changed since the last one.
///
/// The daemon is not the only thing that can move the master: `stty rows` inside the
/// session needs no permission from it, and nothing reports the change back. So a size
/// this daemon last sent is a record of what it sent, never a belief about what the
/// terminal is — and the pass that may not skip the `TIOCSWINSZ` is precisely the one
/// where the two look equal. Reattaching from an unchanged window is the only chance the
/// user has to put a child's own resize right, which is what makes § 2.2's "the arriving
/// `Hello`'s winsize is authoritative" a rule about every `Hello` rather than about the
/// ones that differ.
#[test]
fn an_attach_restates_a_geometry_the_child_moved_underneath_it() {
    let (session, mut client, ok) = Session::attached("resize-stale");

    // The child takes the terminal somewhere the daemon never sent it.
    client.input(0, b"stty rows 50 cols 100 && stty size\n");
    client.read_until("50 100", ok.resume_from);
    drop(client);

    // Same window as before, so the daemon's record of the size it last sent agrees with
    // the greeting — and the child is nonetheless owed the restatement.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    client.input(resumed.in_applied, b"stty size\n");
    client.read_until("24 80", resumed.resume_from);
}

/// What the child prints when the terminal it is on changes size. See
/// [`repaint_transcript`].
///
/// Built out of `$((6*7))` for `harness::READY_MARKER`'s reason, which the line
/// installing the trap needs because it runs before `stty -echo` takes effect. `dash`
/// evaluates a trap's body when the signal arrives, which is what makes the
/// substitution happen then rather than at definition.
const WINCHED: &str = "NOMUX-42-WINCHED";

/// Drives a session to an overflow gap and returns what the child saw afterwards.
///
/// `cat` is the child because it hands back whatever reaches the PTY's input side, the
/// only way to see a repaint delivered as a keystroke; the `SIGWINCH` trap in front of
/// it is the only way to see the other policy at all, the default repaint writing
/// nothing to the terminal. The filler is drained before the client leaves, so the
/// marker printed after the gap has only the kilobyte ring to survive.
///
/// Two things about the trap are `dash`'s doing rather than the daemon's. `set +m`,
/// because with job control on the shell puts `cat` in a foreground process group of
/// its own and `TIOCSWINSZ` signals *that* group, so the shell holding the trap never
/// hears about it. And the trap sits in a background subshell parked on `wait` rather
/// than in the shell itself, because `dash` defers a trap until the foreground job
/// finishes — `wait` is the one thing POSIX requires a trapped signal to interrupt.
/// The subshell prints its own marker rather than the line going through
/// `Client::make_ready`, whose marker arrives *before* the command behind it starts: a
/// `SIGWINCH` landing before the `trap` has run is ignored and no marker ever comes.
///
/// `owed` names the marker the fence cannot bound: `Ctrl-L` needs nothing, `cat` handing
/// the keystroke back along the same path as the fence, but the `SIGWINCH` marker comes
/// from a *second* process `TIOCSWINSZ` has merely made runnable — and § 4.3 obliges the
/// repaint to happen, not to win that race.
fn repaint_transcript(name: &str, repaint_ctrl_l: bool, owed: Option<&str>) -> String {
    /// The child echoes far more than this, so the gap is by construction.
    const RING: usize = 1024;
    /// The last line of the filler: `cat` echoes it, so seeing it means everything
    /// before it is behind us.
    const DRAINED: &str = "NOMUX-FILLER-DRAINED";
    /// Printed by the subshell once its `SIGWINCH` trap is in place, which is behind the
    /// `stty` in the same line — so arriving at it is proof of both. Arithmetic for the
    /// reason [`WINCHED`] is.
    const ARMED: &str = "NOMUX-42-TRAP-ARMED";

    let session = Session::start_with_ring(name, RING);
    let mut client = session.connect();
    let ok = client.hello_with(false, repaint_ctrl_l, RESUME_FROM_START);

    // The sleep is short so a subshell that somehow outlived its session is asleep
    // rather than looping. It does not normally have to be: everything here shares the
    // shell's process group, so closing the PTY master hangs the lot up.
    let setup = "stty -echo -onlcr; set +m; \
                 (trap 'printf NOMUX-$((6*7))-WINCHED' WINCH; \
                 printf NOMUX-$((6*7))-TRAP-ARMED; \
                 while :; do sleep 5 & wait; done) & cat\n";
    client.input(0, setup.as_bytes());
    let (_, offset) = client.read_until(ARMED, ok.resume_from);

    // Echoed back by `cat`, which is what overflows the ring. In lines, because the line
    // discipline is still canonical: `cat` would see nothing until a newline arrived.
    let filler = format!("{}{DRAINED}\n", format!("{}\n", "x".repeat(63)).repeat(512));
    let filler = filler.as_bytes();
    let mut in_offset = setup.len() as u64;
    client.input(in_offset, filler);
    in_offset += filler.len() as u64;
    // Past gaps, since overflowing the ring is the point; what this waits for is the
    // newest bytes on the stream, which are the ones a ring never discards.
    client.read_past_gaps(DRAINED, offset);
    drop(client);

    // A gap by arithmetic rather than by timing: the ring holds a kilobyte and the
    // child has just echoed thirty-two, so `base` is far above where this resumes.
    let mut client = session.connect();
    let resumed = client.hello_with(false, repaint_ctrl_l, offset);
    assert!(
        resumed.gap(offset),
        "the child echoed {} bytes through a {RING}-byte ring and the daemon \
         reported no gap to a client resuming from {offset}",
        filler.len()
    );

    // § 4.3: `ctrl_l` goes through the same queue as client input but is not client
    // input, so `in_applied` does not move for it. Counting it would put `in_applied` a
    // byte past what the client believes it delivered, after which every offset the
    // client sends is a byte low and the next keystroke earns an `Error{InputGap}` for
    // input nobody skipped. The fence below is sent at `in_offset` for the same reason.
    assert_eq!(
        resumed.in_applied, in_offset,
        "the repaint moved the session's input position, but only the client's own \
         keystrokes may"
    );

    // A fence bounds the wait for everything the repaint puts through the PTY, which
    // the child echoes back ahead of it.
    client.input(in_offset, b"FENCE\n");
    let (mut transcript, _) = client.read_past_gaps("FENCE", resumed.resume_from);

    // What the fence cannot bound is waited for on its own — see above. Offsets stop
    // mattering: all this is after is whether the marker comes at all. Collected rather
    // than asserted on, so the verdict stays with the test.
    if let Some(owed) = owed {
        let deadline = Instant::now() + FRAME_PATIENCE;
        while !transcript.contains(owed) {
            let Some((ty, payload)) = client.frame_before(deadline, "the repaint § 4.3 owes")
            else {
                break;
            };
            if let Frame::Output { data, .. } = Frame::decode(ty, &payload).expect("decode frame") {
                transcript.push_str(&String::from_utf8_lossy(data));
            }
        }
    }
    transcript
}

/// The post-gap repaint is the client's choice, and each policy does its own thing
/// and only its own thing (`IMPLEMENTATION.md` § 4.3).
///
/// Both halves are asserted positively as well as negatively. Asserting only that the
/// default policy wrote no `0x0c` is satisfied by a daemon whose `winch` branch does
/// nothing at all — and doing nothing is the shape a regression here would take, the
/// `TIOCSWINSZ` dance being the fiddly half.
#[test]
fn a_gap_repaints_with_ctrl_l_only_when_the_client_asks() {
    let asked = repaint_transcript("repaint_ctrl_l", true, None);
    assert!(
        asked.contains('\u{c}'),
        "no Ctrl-L reached the child: {asked:?}"
    );
    assert!(
        !asked.contains(WINCHED),
        "a client that asked for Ctrl-L was also sent through the winsize dance, so \
         an editor gets both a redraw it did not want and a keystroke: {asked:?}"
    );

    let default = repaint_transcript("repaint_winch", false, Some(WINCHED));
    assert!(
        default.contains(WINCHED),
        "the gap was reported and the child was never told the terminal had \
         changed, so nothing asked it to redraw: {default:?}"
    );
    assert!(
        !default.contains('\u{c}'),
        "the default policy must not write to the PTY: {default:?}"
    );
}

/// A sustained overrun owes the child one repaint after recovery, not one per gap
/// (`IMPLEMENTATION.md` § 4.3). `Ctrl-L` makes the repaint countable in the child's
/// input record. The ring exceeds the maximum client queue plus one frame, so a pass
/// reporting a gap cannot also queue the entire retained window.
#[test]
fn a_sustained_overflow_repaints_when_the_client_catches_up_rather_than_per_gap() {
    /// Above `MAX_PENDING_WRITE + MAX_PAYLOAD`.
    const RING: usize = 2 * 1024 * 1024;
    const GAPS: usize = 16;
    /// The one repaint § 4.3 owes, plus one of slack.
    ///
    /// Four left the property barely pinned: a daemon repainting once per *four* gaps
    /// would still come in under it, and the whole rule is that sixteen gaps owe one
    /// repaint rather than a fraction of one each. Measured at exactly one over fourteen
    /// runs, half of them against twenty busy cores, so the slack is for a catch-up this
    /// test did not intend rather than for a figure that moves.
    const BUDGET: usize = 2;
    /// Caps this client near 5 MB/s even on a busy test host.
    const PACE: Duration = Duration::from_millis(50);
    const OVER: &str = "NOMUX-42-FLOOD-OVER";
    const FENCE: &[u8] = b"FENCE\n";

    // One deadline for the four consecutive waits below rather than one each
    // (`harness::poll_by`).
    let deadline = Instant::now() + FRAME_PATIENCE;
    let session = Session::start_with_ring("repaint_storm", RING);
    let mut client = session.connect();
    let ok = client.hello_with(false, true, RESUME_FROM_START);

    // `cat` keeps the terminal and writes what arrives on it to a file, so nothing the
    // daemon injects is echoed back into the ring it would be lost from. The flooder is
    // a background subshell sharing the session's process group (`set +m`, as in
    // `repaint_transcript`), and it stops on a file rather than on a signal, which would
    // take `cat` with it. Non-canonical because the daemon's `0x0c` carries no newline:
    // in line mode it would sit in the line discipline until the fence flushed it.
    let flood = "set +m; L=0123456789abcdef; L=$L$L$L$L; L=$L$L$L$L; L=$L$L$L$L; \
                 (while [ ! -f stop ]; do printf '%s\\n' \"$L\"; done; \
                 printf NOMUX-$((6*7))-FLOOD-OVER) & exec cat > record";
    let ready = client.make_ready(
        "-echo -onlcr -icanon min 1 time 0",
        Some(flood),
        ok.resume_from,
    );

    // Away while the ring fills, and back only once it has overflowed, so that every
    // frame from here is a full one. A client attached while the child gets going
    // collects a megabyte of two-kilobyte frames queued before it fell behind, and has
    // to read all of them at this pace before reaching the first `Gap` behind them.
    drop(client);
    let (mut client, resumed) = reconnect_until_gap(&session, deadline, true, ready.offset);

    // Paced reads against an unpaced child: every frame taken off the socket lets the
    // daemon's queue dip below its cap, which is what lets the next pass notice the ring
    // has moved on and report a gap. That dip is the whole recurrence.
    let mut offset = resumed.resume_from;
    let mut gaps = 0;
    while gaps < GAPS {
        thread::sleep(PACE);
        let Some((ty, payload)) = client.frame_before(deadline, "output past an overflowing ring")
        else {
            break;
        };
        match Frame::decode(ty, &payload).expect("decode frame") {
            Frame::Output { offset: at, data } => {
                assert_eq!(at, offset, "output between gaps must be contiguous");
                offset += data.len() as u64;
            }
            Frame::Gap { new_base_offset } => {
                offset = new_base_offset;
                gaps += 1;
            }
            Frame::InputAck { .. } | Frame::Pong => {}
            other => panic!("unexpected frame while overflowing the ring: {other:?}"),
        }
    }
    assert_eq!(
        gaps, GAPS,
        "the child never outran this client through a {RING}-byte ring, so there was \
         no sustained overflow to measure"
    );

    fs::write(session.root.join("stop"), []).expect("ask the flooder to stop");
    client.read_past_gaps(OVER, offset);

    // Everything the repaint owes is in the child's hands by now: the pass that
    // queued the marker above is the pass that found this client caught up.
    client.input(ready.in_offset, FENCE);
    let record = session.root.join("record");
    let fenced = poll_by(deadline, || {
        fs::read(&record).is_ok_and(|seen| position(&seen, FENCE).is_some())
    });
    assert!(
        fenced,
        "the fence never reached the child, so what it was sent cannot be counted"
    );

    let seen = fs::read(&record).expect("what the child was sent");
    let fence = position(&seen, FENCE).expect("the fence the wait above returned for");
    let repaints = seen
        .iter()
        .take(fence)
        .filter(|byte| **byte == 0x0c)
        .count();
    assert!(
        repaints >= 1,
        "{gaps} gaps were reported and the child was never asked to redraw: § 4.3 \
         owes it one once the client is back in step, however many gaps it took"
    );
    assert!(
        repaints <= BUDGET,
        "{repaints} repaints for {gaps} gaps: a repaint per gap forces a full redraw \
         several times a second out of the program that is already outrunning the \
         ring, and every redraw is more output to overflow it with"
    );
}

/// Regression: a reconnect racing with in-flight input must not discard it.
///
/// One `poll` can report a readable client and a `Hello` from its replacement together.
/// The daemon originally took over on the *connect* and dropped the outgoing connection
/// there and then — with it any frame still unread in its socket buffer — so keystrokes
/// vanished whenever a reconnect landed in the same iteration as input already sent.
///
/// Each round sets that interleaving up on purpose: the replacement connects and is left
/// un-greeted until the daemon has certainly accepted it, and only then does the
/// outgoing client send input, immediately followed by the `Hello` that evicts it. Both
/// land in one wakeup, and the outgoing connection is not closed until after the
/// assertion — so nothing depends on how the kernel treats a socket closed with data
/// still queued.
#[test]
fn a_takeover_never_discards_input_already_delivered() {
    let (session, mut client, _) = Session::attached("takeover_input");
    // One deadline for all fifteen rounds rather than one per reconnect
    // (`harness::poll_by`), held by the client already attached as well as by every one
    // the loop makes. A round is a ping, a keystroke and a handshake against a daemon on
    // this machine, so the whole loop is a small fraction of one wait's patience — where a
    // budget minted per round put this test 250 seconds out, past `.config/nextest.toml`'s
    // kill by six times over, so that a slow run was reported killed rather than on the
    // frame it was still owed.
    let deadline = Instant::now() + FRAME_PATIENCE;
    client.waits_by(deadline);

    let command = b"true NOMUX-KEEP\n";
    let mut expected = 0u64;

    for round in 0..15 {
        let mut next = session.connect_by(deadline);
        // The accept, asked for rather than waited out. `connect` on a listening unix
        // socket completes in the kernel, so the connection is already in the backlog
        // and the next `poll` reports the listener; that same pass services the client,
        // then accepts, and only then writes what it queued — so a `Pong` for a ping
        // sent from here cannot have come from a pass that had not yet accepted.
        client.send(&Frame::Ping);
        drop(client.next_of(FrameType::Pong));

        client.input(expected, command);
        expected += command.len() as u64;
        let ok = next.hello(RESUME_FROM_START);
        assert_eq!(
            ok.in_applied, expected,
            "round {round}: input delivered before the takeover was lost"
        );
        client = next;
    }
}

/// Regression: a `Hello` the daemon cannot answer must not cost the session the
/// client it already has.
///
/// Version skew is the one compatibility case that exists (`DESIGN.md` § 6.4): a *newer*
/// client reaching a session an older daemon is still holding. The refusal used to
/// happen after the takeover rather than before it, so the failed handshake evicted the
/// working client with `Error{TAKEOVER}` and then dropped the newcomer too — and § 6.4
/// tells a client never to auto-reconnect after a takeover, so the user's shell went
/// quiet and stayed quiet over a connection attempt that was refused.
#[test]
fn a_version_mismatch_refuses_the_newcomer_without_evicting_the_client() {
    let (session, mut client, _) = Session::attached("skew");

    // The incumbent is serving before the newcomer knocks, or the assertion below
    // that it still is would be about nothing. Both are `harness::still_serving`, whose
    // marker is arithmetic the line discipline's echo of the command line cannot
    // produce — this session is at the PTY's default `ECHO|ICANON`, so a literal marker
    // would come back off the master before the shell had read a byte of it.
    still_serving(&mut client, "NOMUX-FIRST");

    let mut newcomer = session.connect();
    newcomer.send(&Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION + 1,
        agent_forward: false,
        repaint_ctrl_l: false,
        if_detached: true,
        out_offset: RESUME_FROM_START,
        win: harness::WIN,
        term: "xterm-256color",
    }));
    newcomer.expect_error(
        ErrorCode::Version,
        "a mismatched Hello must be refused as a version error",
    );

    // The incumbent kept the session: it never saw a takeover, and its input stream
    // carries on from where it was rather than restarting — `still_serving` sends from
    // the position this client has reached, so a session that rewound it would fail on
    // the offset before the marker was ever looked for.
    still_serving(&mut client, "NOMUX-STILL-HERE");
}

/// Regression: a client vanishing must never take the session with it.
///
/// Closing a socket that still has unread data queued makes the kernel send RST rather
/// than FIN, so the daemon's next read fails with `ECONNRESET`. That error was
/// originally propagated out of the event loop and terminated the daemon — killing the
/// shell over exactly the kind of unclean disconnect this project exists to survive.
#[test]
fn an_abrupt_client_disconnect_does_not_kill_the_session() {
    let (session, mut client, _) = Session::attached("reset");

    let command = b"echo NOMUX-SURVIVED\n";
    client.input(0, command);

    // The daemon owns the command before the connection goes, so the assertion below is
    // about what the session kept rather than what it managed to read in time.
    client.wait_for_input_ack(command.len() as u64);
    // And it has written something nobody read, which is what makes the close an RST
    // rather than an orderly FIN — that reset is the whole fault under test.
    client.wait_for_unread_bytes();
    drop(client);

    // Straight into the reconnect: the handshake is itself the wait for the daemon to
    // have dealt with the disconnect, the takeover path running before it is answered.
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    assert_eq!(
        ok.in_applied,
        command.len() as u64,
        "session lost its input state after an abrupt disconnect"
    );

    // And it is a shell that answers rather than the line discipline: this session was
    // never made ready, so `harness::still_serving`'s arithmetic marker is what
    // separates the child's reply from the echo of the request for it.
    still_serving(&mut client, "NOMUX-STILL-HERE");
}

/// A daemon started with the standard descriptors closed still serves its session.
///
/// `IMPLEMENTATION.md` § 6.2 documents `nomux daemon <id>` typed by hand as a supported
/// way to start one, and a shell hands it whatever descriptor table it likes:
///
/// ```text
/// nomux daemon x 0<&- 1>&- 2>&-
/// ```
///
/// What that risks is the daemon silencing itself. The kernel gives out the lowest free
/// number, so with those three free the session socket would take fd 1 and the stop
/// pipe's read end fd 2 — and § 6.2's detachment `dup2`s `/dev/null` over all three on
/// its way past, which leaves the worst state this program has: the id claimed by a
/// daemon nothing can reach, `poll` finding `/dev/null` ready for ever, every `accept`
/// failing behind the backoff, and the pipe that says "stop" reading as though it had.
///
/// It does not happen, because std's runtime fills those three before `main` ever runs
/// (`startup::silence_standard_descriptors` has the argument). That is a guarantee from outside
/// this tree and invisible inside it, which is exactly why the property is asserted rather
/// than reasoned about — and nothing else in this suite starts a daemon with a
/// descriptor table of its own.
///
/// The greeting is the assertion rather than a `connect`, deliberately: the socket
/// answers between the bind and the detachment, so a connection alone can be satisfied
/// by the very window this is about. A `HelloOk` needs the event loop to be polling the
/// socket the daemon actually bound.
#[test]
fn a_daemon_whose_standard_descriptors_are_closed_still_serves_its_session() {
    let root = run_root("nostdio");
    let mut command = nomux_with_shell(&root, &["daemon", "nsd"]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure runs in the forked child before exec, so it must be
    // async-signal-safe. `close` is, and nothing here allocates or takes a lock. std has
    // already put the three `Stdio::null()`s in place by this point — that ordering is
    // what leaves this the last word on them, and it is what the shell above does too.
    unsafe {
        command.pre_exec(|| {
            for fd in [0, 1, 2] {
                libc::close(fd);
            }
            Ok(())
        });
    }
    // Killed however this test ends: the daemon is this process's own child, having no
    // reason to fork — it is not a process-group leader, so `setsid` takes.
    let _daemon = Spawned::spawn(&mut command);

    let socket = root.join("nomux/run").join("nsd.sock");
    assert!(
        poll_by(Instant::now() + FRAME_PATIENCE, || greeted(&socket)),
        "the daemon never answered a Hello on {}, so it is holding the id with nothing \
         able to reach it",
        socket.display()
    );
}

/// Whether a daemon on `socket` answers a `Hello` with a `HelloOk`.
///
/// By hand rather than through a [`Client`], which only a [`Session`] hands out: what is
/// under test is a daemon started with a descriptor table of the test's own. Every
/// failure is a "no" rather than a panic, the caller asking this repeatedly of a session
/// that may not be up yet — and a daemon that answers the `connect` and then goes is
/// exactly the state being ruled out rather than an error.
fn greeted(socket: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set a read timeout");
    let mut hello = Vec::new();
    hello_frame(false, false, RESUME_FROM_START)
        .encode(&mut hello)
        .expect("encode a Hello");
    if stream.write_all(&hello).is_err() {
        return false;
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut seen = Vec::new();
    let opening_len = SERVER_PREAMBLE.len() + HEADER_LEN;
    while seen.len() < opening_len {
        if Instant::now() >= deadline {
            return false;
        }
        let mut chunk = [0u8; 64];
        match read_uninterrupted(&mut stream, &mut chunk) {
            Ok(0) => return false,
            Ok(n) => seen.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            // The read timeout expiring, which is the deadline above's to answer.
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
    if seen.get(..SERVER_PREAMBLE.len()) != Some(SERVER_PREAMBLE.as_slice()) {
        return false;
    }
    let Some(head) = seen
        .get(SERVER_PREAMBLE.len()..opening_len)
        .and_then(|head| head.try_into().ok())
    else {
        return false;
    };
    decode_header(head).is_ok_and(|header| header.ty == FrameType::HelloOk)
}
