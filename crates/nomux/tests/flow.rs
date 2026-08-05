//! Back pressure in both directions, and the one shortage the daemon must stand
//! back from rather than spin on (`IMPLEMENTATION.md` § 4.1, § 6.4.1).
//!
//! A client can write faster than the child reads, and a peer can stop reading what
//! it asked for. Neither may grow the daemon without bound, and neither may cost the
//! session its shell: the daemon stops reading the socket in the one direction and
//! lets go of the connection in the other. The `EMFILE` test is here because it is
//! the same question about a third resource — what the event loop does when it
//! cannot make progress on something it is being woken for.

#![allow(
    clippy::expect_used,
    reason = "the allow-expect-in-tests setting in clippy.toml reaches `#[test]` \
              bodies and `#[cfg(test)]` modules, not the helpers an integration \
              test crate keeps beside them"
)]

mod harness;

use std::io::{ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{Frame, FrameType, HEADER_LEN, RESUME_FROM_START, decode_header};

use harness::{
    FRAME_PATIENCE, Session, cpu_ticks, hello_frame, poll_until, push_until_refused,
    read_uninterrupted, wait_for, write_frame,
};

/// The PTY master is non-blocking, so a child that has stopped reading cannot
/// wedge the daemon.
///
/// A PTY's input buffer is a few kilobytes. With a blocking master, pushing more
/// than that at a child which is not reading parked the whole event loop inside
/// `write(2)` — one session's stuck child froze that session's output entirely,
/// including frames that had nothing to do with the PTY.
#[test]
fn a_child_that_stops_reading_input_does_not_wedge_the_daemon() {
    let (_session, mut client, ok) = Session::attached("wedge");

    // `raw` for the back pressure it keeps (see [`Client::make_ready`]); `sleep`
    // then holds the terminal without reading it, so everything below piles up.
    let ready = client.make_ready("raw -echo", Some("sleep 30"), ok.resume_from);

    let chunk = vec![b'x'; 16 * 1024];
    let mut offset = ready.in_offset;
    for _ in 0..16 {
        client.input(offset, &chunk);
        offset += chunk.len() as u64;
    }

    // The ping has to reach the daemon in a *later* read than the input, or it is
    // answered before the write to the master was ever attempted and proves nothing.
    // The ack for the last input byte is the daemon saying it has consumed all of
    // them, which is that condition rather than a guess at how long it takes — and
    // with a blocking master the daemon is parked in the write instead, so the ack
    // never comes and this fails here rather than below.
    client.wait_for_input_ack(offset);

    // The daemon must still be answering: with a blocking master this does not
    // return until the sleep does.
    let began = Instant::now();
    client.send(&Frame::Ping { nonce: 0xF00D });
    let payload = client.next_of(FrameType::Pong);
    assert_eq!(
        Frame::decode(FrameType::Pong, &payload).expect("decode pong"),
        Frame::Pong { nonce: 0xF00D }
    );
    assert!(
        began.elapsed() < Duration::from_secs(10),
        "daemon took {:?} to answer a ping behind a full PTY buffer",
        began.elapsed()
    );
}

/// A client writing faster than the child reads is back-pressured, not buffered
/// without limit.
///
/// `Conn::rx` and `pending_input` had no cap, so a client could grow the daemon by
/// however much it cared to send — and the two cheaper answers are both closed off,
/// since `in_applied` is authoritative and exactly-once (§ 3): a byte cannot be
/// dropped once acknowledged, and refusing one with an `InputGap` would accuse a
/// client that had done nothing wrong. So the daemon stops reading the socket
/// instead, exactly as the output direction always has.
///
/// Measured as bytes the daemon would take, which bounds what it can be holding:
/// everything it has is a subset of what crossed the socket.
#[test]
fn input_the_child_never_reads_is_back_pressured_rather_than_buffered() {
    /// Comfortably more than every buffer between the two processes put together.
    const BLAST: usize = 32 << 20;
    /// Room for a megabyte of queued input, a megabyte of undecoded receive buffer
    /// and the kernel's socket buffers, and nothing like room for [`BLAST`].
    const TOLERATED: usize = 8 << 20;

    let (session, mut client, ok) = Session::attached("input_cap");

    // `raw` for the back pressure it keeps (see [`Client::make_ready`]); `sleep`
    // then holds the terminal without reading a byte of it. No settling sleep is
    // needed once the marker is back: the whole line is parsed before any of it
    // runs, so the shell reads nothing more until `sleep 30` returns.
    let ready = client.make_ready("raw -echo", Some("sleep 30"), ok.resume_from);
    drop(client);

    // A raw socket rather than the harness client, because the question is how much
    // the daemon will take before it stops taking.
    let mut blaster = blaster(&session);
    let (frames, _) = input_frames(BLAST, ready.in_offset);

    // A second of refusal, which is long enough that a daemon merely busy with
    // the megabytes it already took would have come back for more. Paid in full on
    // every run, since a daemon that has stopped never comes back — so it is one
    // second rather than the three it was, which is the figure
    // [`a_client_that_never_reads_its_answers_is_dropped_rather_than_queued_for`]
    // has always used for the same measurement.
    let sent = push_until_refused(&mut blaster, &frames, Duration::from_secs(1));
    assert!(
        sent < TOLERATED,
        "the daemon took {sent} bytes of input for a child that read none of them"
    );

    // And it is still serving. A fresh connection is never held back — that is what
    // keeps `list` and the spawn race working (§ 6.6) — so the handshake it gets
    // back is both proof the loop is alive and a statement about the input the
    // daemon really did accept.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    let applied = resumed.in_applied.saturating_sub(ready.in_offset);
    assert!(applied > 0, "the daemon applied none of the input it took");
    assert!(
        applied <= sent as u64,
        "the daemon applied {applied} bytes of input from {sent} bytes of frames"
    );
}

/// Reconnecting must not raise the ceiling.
///
/// Holding the client out of the poll set throttles only the reads the poll set
/// drives, and that is not where the queue grows. The takeover path of § 6.4.1 reaches
/// the decode loop twice without passing through the poll set at all — once to drain
/// the outgoing connection, once for the input pipelined behind the arriving `Hello` —
/// and nothing bounds reconnects, so each one injected another queue's worth. The cap
/// is therefore enforced between frames in the decode loop, and this is the test that
/// says so.
///
/// `in_applied` is what is asserted on because it is exactly what the daemon has taken
/// ownership of (§ 3): every byte queued for the PTY is below it, so a ceiling on it is
/// a ceiling on the queue. The test above measures one connection and would keep
/// passing with the cap in either place.
#[test]
fn reconnecting_does_not_raise_the_input_ceiling() {
    /// Enough per round that the old growth — a third of a megabyte a takeover —
    /// would be plain in the total, and enough to refill whatever the queue took.
    const BLAST: usize = 4 << 20;
    /// Linear growth over this many would be a megabyte past the cap and plain in
    /// the total; a ceiling is a ceiling after the second.
    const ROUNDS: usize = 4;

    let (session, mut client, ok) = Session::attached("input_ceiling");

    // The `sleep` holds the terminal without reading a byte for far longer than this
    // test runs — a child that woke up and drained the queue would make the ceiling
    // look like it moved.
    let ready = client.make_ready("raw -echo", Some("sleep 120"), ok.resume_from);
    drop(client);

    let mut ceiling = None;
    let mut resume = ready.in_offset;

    for round in 0..ROUNDS {
        // Every round starts where the daemon says it has got to, which is what makes
        // the measurement mean anything: input below `in_applied` is trimmed rather
        // than queued (§ 3), so a round replaying from a fixed offset would be
        // discarded on arrival and would look like a ceiling holding.
        let (frames, _) = input_frames(BLAST, resume);

        // A fresh connection each time, which is the takeover this is about.
        let mut blaster = blaster(&session);

        // The socket having refused everything for a quarter of a second is the daemon
        // having stopped taking input, so the ceiling is reached rather than merely
        // approached — which is what makes the first round a fair baseline. Four
        // rounds of the second the test above spends would be four seconds of
        // waiting for a queue that is already full.
        let _pushed = push_until_refused(&mut blaster, &frames, Duration::from_millis(250));

        let mut probe = session.connect();
        let applied = probe.hello(RESUME_FROM_START).in_applied;
        drop(probe);
        drop(blaster);
        resume = applied;

        let first = *ceiling.get_or_insert(applied);
        assert_eq!(
            applied, first,
            "round {round} took the input queue past the ceiling the first round \
             established: {applied} against {first}"
        );
    }

    // And the ceiling is the cap rather than an accident of how much fitted in a
    // socket buffer: one frame of overshoot is allowed, since the cap is tested
    // between frames.
    let ceiling = ceiling.expect("at least one round");
    assert!(
        ceiling >= (1 << 20),
        "the daemon stopped far short of the megabyte it is allowed to queue: {ceiling}"
    );
}

/// Input already delivered survives the half-close that follows it
/// (`IMPLEMENTATION.md` § 4.1).
///
/// The decode loop stops between frames once the PTY queue is full, and its exit used
/// to fall straight into the end-of-file test beneath it — so a peer whose write half
/// had closed was let go of with up to a megabyte of *complete* `Input` frames still
/// undecoded, which is the one thing § 4.1 says is never stranded in that buffer. The
/// peer is not gone: the relay shuts its write half down on stdin EOF and goes on
/// draining output (§ 7), so `nomux attach ID < script.sh` against a child that is
/// slow to read ran the first megabyte and silently lost the rest.
///
/// Sized to the real cap rather than to a knob, there being no `NOMUX_RING_BYTES` for
/// the input direction. What the child is *given* is what is asserted on, from the far
/// side of the PTY, because that is the claim: `in_applied` behind it says the daemon
/// agrees, and is what a reattaching client would resume from.
#[test]
fn input_delivered_before_a_half_close_is_applied_rather_than_dropped() {
    use std::net::Shutdown;
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::Mode;

    /// More than the megabyte the daemon queues, the megabyte it buffers undecoded
    /// and the socket buffers between them, so what crosses is bounded by the daemon
    /// rather than by this.
    const BLAST: usize = 8 << 20;
    /// One `Input` frame's payload, well inside `MAX_PAYLOAD`.
    const CHUNK: usize = 60 * 1024;
    /// The queue cap of § 4.1. Named because the test means nothing unless more than
    /// this crossed the socket before the half-close: below it nothing was ever held
    /// back, and there would have been nothing to strand.
    const CAP: u64 = 1 << 20;

    let session = Session::start("input_halfclose");
    let cue = session.root.join("cue");
    rustix::fs::mkfifoat(rustix::fs::CWD, &cue, Mode::RUSR | Mode::WUSR)
        .expect("create the FIFO the child waits on");

    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // `raw` for the back pressure it keeps (see [`Client::make_ready`]) and `-echo` so
    // the blast is not echoed back at a peer that never reads. Past the marker the
    // child never touches its terminal until the cue arrives: the whole line is parsed
    // before any of it runs, and `read` has the FIFO. Then `cat` drains the terminal
    // into a file, which is where this side counts what the child was really given.
    let ready = client.make_ready(
        "raw -echo",
        Some("read cue < cue; exec cat > drained"),
        ok.resume_from,
    );
    drop(client);

    // Where each whole frame ends on the wire, against the input offset one past it.
    // The push below stops wherever the daemon stopped taking, routinely mid-frame,
    // and a part-frame is owed to nobody — `take_frame` never completes one — so this
    // is what turns a byte count into the offset the daemon is actually in debt for.
    let chunk = vec![b'x'; CHUNK];
    let mut frames = Vec::with_capacity(BLAST + CHUNK);
    let mut whole = Vec::new();
    let mut offset = ready.in_offset;
    while frames.len() < BLAST {
        Frame::Input {
            offset,
            data: &chunk,
        }
        .encode(&mut frames)
        .expect("encode input");
        offset += CHUNK as u64;
        whole.push((frames.len(), offset));
    }

    // A raw socket rather than the harness client, because this has to stop writing
    // exactly where the daemon stops reading and then half-close on the spot. A
    // second of a socket that will not take another byte is a daemon that has stopped
    // rather than one that is busy, which is the same measure the two cap tests above
    // are built on — and one second rather than the three this used to spend, since
    // nothing here ever gets the byte back that would end the wait early.
    //
    // Pushed again while the daemon has not yet taken more than it queues, rather
    // than judged on the first answer. The push ends on a window in which nothing was
    // accepted, and a daemon merely descheduled for the whole of one produces exactly
    // that — a short count, and then an assertion below reporting a back-pressure
    // defect that did not happen, where its two siblings would have passed. The state
    // this test needs is the daemon having *stopped*, which is something to wait for.
    // A daemon that really has stopped is past the threshold on the first push, so
    // the ordinary path pays nothing for this.
    let mut blaster = blaster(&session);
    let mut sent = 0;
    let deadline = Instant::now() + FRAME_PATIENCE;
    let applied_end = loop {
        sent += push_until_refused(
            &mut blaster,
            frames.get(sent..).unwrap_or_default(),
            Duration::from_secs(1),
        );
        // Where the last whole frame the daemon took ends, as an input offset. The
        // push stops wherever the daemon stopped taking, routinely mid-frame, and a
        // part-frame is owed to nobody — `take_frame` never completes one.
        let applied_end = whole
            .iter()
            .rev()
            .find(|(through, _)| *through <= sent)
            .map_or(ready.in_offset, |(_, end)| *end);
        if applied_end - ready.in_offset > CAP + CHUNK as u64 || Instant::now() >= deadline {
            break applied_end;
        }
    };
    let owed = applied_end - ready.in_offset;
    // The queue is tested between frames, so it stops at [`CAP`] plus the one frame
    // that crossed it and never holds more. Anything past that was waiting *outside*
    // it — in the receive buffer or the socket's — which is what the bug threw away
    // and so is what has to be there for any of this to be a test.
    assert!(
        owed > CAP + CHUNK as u64,
        "the {owed} bytes of whole frames that reached the daemon all fit in the \
         {CAP} it queues, so nothing was ever held back outside it and the \
         half-close below would prove nothing"
    );

    // The half-close § 7 has the relay make on stdin EOF, arriving while everything
    // above is still held back. The read half stays open, so this is a peer that is
    // still there and still owed.
    blaster
        .shutdown(Shutdown::Write)
        .expect("half-close the client the way the relay does");

    // And now the child starts reading, which is what drains the queue and lets the
    // decode loop through the rest. Opened without blocking so a child that never
    // reached its own `open` fails here rather than parking this: a FIFO answers
    // `ENXIO` until a reader is there, and the child counts as one from the moment it
    // enters the wait.
    let mut go = None;
    assert!(
        poll_until(FRAME_PATIENCE, || {
            go = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&cue)
                .ok();
            go.is_some()
        }),
        "the child never reached the cue it waits on"
    );
    go.expect("the FIFO the wait above opened")
        .write_all(b"go\n")
        .expect("cue the child");

    let drained = session.root.join("drained");
    let seen = || fs::metadata(&drained).map_or(0, |meta| meta.len());
    assert!(
        poll_until(FRAME_PATIENCE, || seen() >= owed),
        "the child was given {} of the {owed} bytes this client delivered before it \
         half-closed: the rest went with the connection",
        seen()
    );
    assert_eq!(
        seen(),
        owed,
        "the child was given a different amount than this client delivered"
    );

    // The daemon's own accounting, which is what a reattaching client resumes from
    // (§ 3) — and a connection that is greeted after all this is also proof the
    // session outlived the peer it stopped reading from.
    let mut probe = session.connect();
    assert_eq!(
        probe.hello(RESUME_FROM_START).in_applied,
        applied_end,
        "the daemon applied a different amount than the child was given"
    );
}

/// Regression: a session whose child exits while its input queue is full still
/// answers.
///
/// The queue only ever drains in `write_pty`, and `Daemon::watches` keeps the master in
/// the poll set only while `child_gone` is `None` — so from the exit onwards there is
/// no `write_pty` to come. A queue standing at the § 4.1 cap at that moment stayed
/// there for good, and `input_is_saturated` with it: the client is polled with an empty
/// mask and `read_client` returns before it decodes anything, so no `Ping` is answered,
/// a `Detach` is never seen, and a *fresh* attach is answered to its `HelloOk` and mute
/// after it — `read_pending` decodes the greeting, and everything behind it goes
/// through the loop that has stopped. With a client attached the session is on no
/// deadline at all (§ 6.5), so nothing but `nomux kill` ever ended it.
///
/// Composed exactly rather than hoped for, and every step a condition. The child waits
/// on a FIFO and so never touches its terminal, which is what lets the queue reach the
/// cap; `push_until_refused` returning short of the blast is the daemon having stopped
/// reading, which is saturation observed rather than assumed; and the cue is what makes
/// the exit happen after it rather than at some point during it.
///
/// The `Ping` goes down a connection opened after the exit because that is the state a
/// user is in — a session that looks alive, answers the handshake, and then says
/// nothing. `Pong` rather than `Exit`, since `pump_output` sends the exit whatever the
/// input direction is doing and so cannot tell the two daemons apart.
#[test]
fn a_child_that_exits_behind_a_full_input_queue_leaves_the_session_answering() {
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::Mode;

    /// Comfortably past the megabyte § 4.1 queues, the megabyte it buffers undecoded
    /// and the socket buffers between them, so what stops the push is the daemon.
    const BLAST: usize = 8 << 20;
    /// The queue cap of § 4.1. The test means nothing unless the daemon really reached
    /// it before the child exited: below it nothing was ever held back.
    const CAP: u64 = 1 << 20;

    let session = Session::start("exit_saturated");
    let cue = session.root.join("cue");
    rustix::fs::mkfifoat(rustix::fs::CWD, &cue, Mode::RUSR | Mode::WUSR)
        .expect("create the FIFO the child waits on");

    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // `raw` for the back pressure it keeps (see [`Client::make_ready`]) and `-echo` so
    // the blast is not echoed back at a peer that never reads. Past the marker the child
    // never touches its terminal: the whole line is parsed before any of it runs, and
    // `read` has the FIFO — so the terminal's input buffer fills, the daemon stops
    // being able to write, and everything after that piles up in `pending_input`.
    let ready = client.make_ready("raw -echo", Some("read cue < cue; exit 9"), ok.resume_from);
    drop(client);

    // A raw socket rather than the harness client, because what is wanted is the point
    // at which the daemon stops taking input at all. A second of a socket that will not
    // take another byte is a daemon that has stopped rather than one that is busy,
    // which is the same measure the three tests above are built on.
    let mut blaster = blaster(&session);
    let (frames, _) = input_frames(BLAST, ready.in_offset);
    let sent = push_until_refused(&mut blaster, &frames, Duration::from_secs(1));
    assert!(
        sent as u64 > CAP,
        "the daemon took only {sent} bytes before it stopped, which all fits in the \
         {CAP} it queues — so the queue never reached the cap and the exit below has \
         nothing to strand"
    );

    // And now the child leaves, with the queue full behind it. Opened without blocking
    // so a child that never reached its own `open` fails here rather than parking this:
    // a FIFO answers `ENXIO` until a reader is there, and the child counts as one from
    // the moment it enters the wait.
    let mut go = None;
    assert!(
        poll_until(FRAME_PATIENCE, || {
            go = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&cue)
                .ok();
            go.is_some()
        }),
        "the child never reached the cue it waits on"
    );
    go.expect("the FIFO the wait above opened")
        .write_all(b"go\n")
        .expect("cue the child");

    // A fresh attach, which is what a user reaching for a session that has gone quiet
    // does. The greeting proves the daemon is scheduling; the `Pong` behind it is the
    // whole of this test, since it can only come from the decode loop the full queue
    // used to stop.
    let mut client = session.connect();
    client.hello(RESUME_FROM_START);
    client.send(&Frame::Ping { nonce: 0x5A7 });

    // One deadline for the whole loop rather than a fresh one per frame: the replay and
    // the `Exit` arrive ahead of the `Pong` and each would renew the patience for it.
    let deadline = Instant::now() + FRAME_PATIENCE;
    let awaiting = "a Pong from a session whose child exited behind a full input queue";
    loop {
        let (ty, payload) = client.frame_before(deadline, awaiting).unwrap_or_else(|| {
            panic!(
                "the daemon never answered: {sent} bytes of input were still queued for \
                 a child that has gone, so it is holding this client out of its own \
                 decode loop for as long as the session lasts"
            )
        });
        match Frame::decode(ty, &payload).expect("decode") {
            Frame::Pong { nonce } => {
                assert_eq!(nonce, 0x5A7, "the Pong must answer the Ping this sent");
                break;
            }
            Frame::Output { .. }
            | Frame::Gap { .. }
            | Frame::InputAck { .. }
            | Frame::Exit { .. } => {}
            other => panic!("unexpected {other:?} while awaiting {awaiting}"),
        }
    }
}

/// A peer that writes without ever reading is let go of, rather than queued for
/// without bound (`IMPLEMENTATION.md` § 4.1).
///
/// The output direction is bounded twice, at two different meanings of "not keeping
/// up", and only the first has a test. Past a megabyte pending the daemon stops
/// *queueing output*, which is what
/// [`an_overflow_that_outruns_an_attached_client_is_reported_as_a_gap_mid_stream`]
/// builds its gap out of. That bound does not cover everything, because the frames
/// that *answer* a client — an `InputAck` per `Input`, a `Pong` per `Ping` — are not
/// optional and are queued whatever the output policy says. So a peer that only ever
/// writes grows the queue at exactly the rate it is fed, and `ABANDON_PENDING_WRITE`
/// is the second bound: past eight megabytes it is not slow but gone. Nothing in the
/// suite sent a daemon anything it had to answer without reading the answers, so both
/// the bound and its consequence were untested — § 9's backpressure row is the input
/// direction alone.
///
/// `Ping` is what this is written in because it is the smallest frame that must be
/// answered and the answer is the same size, so the queue tracks what was pushed at
/// it byte for byte, and the two-sided bound below can say which bound fired. That is
/// the point of the *lower* one: every cheaper way for the daemon to end up with a
/// closed connection — a write it could not make, a frame it would not accept, a peer
/// it decided was a protocol violation — happens far below eight megabytes, so a
/// figure at the bound is the bound. The transcript is checked for the same reason
/// from the other side: it must carry the pongs that filled the queue and no `Error`,
/// since a refusal reaches the same closed socket by a different route entirely.
///
/// What the daemon does about it is nothing: `drop_client`, no `Error`, no goodbye,
/// which is the connection simply ending under a peer that was not listening anyway.
/// This side sees it as the `EPIPE` that stops the push, and then as everything the
/// daemon did send followed by an end — `ECONNRESET` rather than a clean zero, since
/// it let go with bytes of ours still unread (§ 3).
#[test]
fn a_client_that_never_reads_its_answers_is_dropped_rather_than_queued_for() {
    /// Comfortably past [`QUEUE`] and the socket buffers either side of it: a daemon
    /// that lets go takes a fraction of this, and one that queues without bound takes
    /// all of it.
    const BLAST: usize = 24 << 20;
    /// The queue § 4.1 lets a client reach before it counts as gone. Every byte of it
    /// is a pong answering a ping, so it is also, near enough, how much of [`BLAST`]
    /// the daemon has to have taken to get there.
    const QUEUE: usize = 8 << 20;
    /// [`QUEUE`] over again for the kernel's buffers, the undecoded megabyte § 4.1
    /// caps the receive side at, and the pongs already on the wire — and nothing like
    /// room for [`BLAST`].
    const TOLERATED: usize = 16 << 20;

    let session = Session::start("abandon");

    // The `Hello` this sends is what starts the session, and past it this peer never
    // reads another byte until the measurement is over.
    let mut peer = blaster(&session);
    let mut ping = Vec::new();
    Frame::Ping { nonce: 0x8B_ACED }
        .encode(&mut ping)
        .expect("encode a ping");
    let pings = ping.repeat(BLAST.div_ceil(ping.len()));

    // A second of a socket that will not take another byte, which is not what ends
    // this: the daemon lets go, and the write after that is an `EPIPE`. The patience
    // is for the daemon that never does — a full second without a byte accepted is one
    // that has stopped rather than one that is busy — and it doubles as the pace of the
    // push, since [`push_until_refused`] backs off by a fiftieth of it whenever the
    // send buffer is full. That is most of this test's second: the buffer holds a
    // fraction of what has to cross, so the eight megabytes are handed over in some
    // forty rounds of filling it and waiting for the daemon to drain it.
    let sent = push_until_refused(&mut peer, &pings, Duration::from_secs(1));

    // Blocking with a timeout for the drain, so what the daemon managed to send is
    // read at the speed it wrote it rather than at a poll interval per chunk — and so
    // that a daemon which is merely slow is read from until the deadline rather than
    // declared finished by an `EAGAIN` between two of its writes.
    peer.set_nonblocking(false).expect("block for the drain");
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("bound each read");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut answered = Vec::new();
    let mut chunk = [0u8; 8192];
    let released = loop {
        match read_uninterrupted(&mut peer, &mut chunk) {
            // Both are the daemon having let go, and which one arrives is the
            // kernel's business rather than the daemon's: a close with nothing of
            // ours left unread is a plain end of file, and one with pings still
            // queued for it is the same close reported as a reset (§ 3). It is
            // always the second here, since the push ends by being refused.
            Ok(0) => break true,
            Ok(n) => answered.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == ErrorKind::ConnectionReset => break true,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => panic!("reading what the daemon sent before it let go: {err}"),
        }
        if Instant::now() >= deadline {
            break false;
        }
    };

    assert!(
        released,
        "the daemon never let go: it has written {} bytes to a peer that read none of \
         them and is still queueing more",
        answered.len()
    );
    assert!(
        sent >= QUEUE,
        "the daemon let go at {sent} bytes of pings, short of the {QUEUE} of pongs \
         they queue — so it dropped this peer for something other than a queue it \
         could not deliver"
    );
    assert!(
        sent < TOLERATED,
        "the daemon took {sent} bytes from a peer that read none of its answers"
    );

    let seen = frame_types(&answered);
    assert!(
        seen.contains(&FrameType::Pong),
        "the daemon answered none of the pings, so what filled its queue was not the \
         traffic § 4.1 says cannot be held back: {} bytes over {} frames",
        answered.len(),
        seen.len()
    );
    assert!(
        !seen.contains(&FrameType::Error),
        "the daemon refused this peer rather than letting go of it, which reaches the \
         same closed connection for an entirely different reason"
    );

    // § 4.1: dropping such a client costs a working one nothing, since reattaching
    // replays from the ring. Nothing was ever read off this session, so a fresh client
    // driving one command through the shell is the whole of that claim.
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    client.input(ok.in_applied, b"echo NOMUX-AFTER-ABANDON\n");
    client.read_until("NOMUX-AFTER-ABANDON", ok.resume_from);
}

/// At least `at_least` bytes of encoded `Input` frames starting at `from`, and one
/// past the last input offset they carry.
///
/// Built in full before any of it is sent, because the two tests above measure how
/// much of a buffer the daemon takes: encoding as they went would have them
/// measuring this process instead.
fn input_frames(at_least: usize, from: u64) -> (Vec<u8>, u64) {
    let chunk = vec![b'x'; 60 * 1024];
    let mut frames = Vec::with_capacity(at_least + chunk.len());
    let mut offset = from;
    while frames.len() < at_least {
        Frame::Input {
            offset,
            data: &chunk,
        }
        .encode(&mut frames)
        .expect("encode input");
        offset += chunk.len() as u64;
    }
    (frames, offset)
}

/// The types of the frames in `bytes`, stopping at the first one that is not all
/// there.
///
/// For the one test that reads a connection the daemon abandoned rather than closed
/// in order: its last write is however much of the queue the socket took, so the tail
/// is routinely half a frame, and a walk that decoded it would be reporting on the
/// truncation rather than on what the daemon sent. Only the header is read, because
/// the question is which frames arrived rather than what they carried.
fn frame_types(bytes: &[u8]) -> Vec<FrameType> {
    let mut types = Vec::new();
    let mut at = 0;
    while let Some(head) = bytes
        .get(at..at + HEADER_LEN)
        .and_then(|head| <[u8; HEADER_LEN]>::try_from(head).ok())
    {
        let header = decode_header(&head).expect("decode a header the daemon wrote");
        at += HEADER_LEN + header.len as usize;
        if at > bytes.len() {
            break;
        }
        types.push(header.ty);
    }
    types
}

/// A greeted socket that refuses rather than blocks once the daemon stops taking what
/// it is given.
///
/// [`push_until_refused`] reads that refusal as the daemon having stopped, which is
/// the behaviour all three of its callers are about — so the non-blocking flag is not
/// a detail of how the writing is done, it is what makes the measurement possible at
/// all. Two of them have the daemon stop by declining to read, where the refusal is
/// an `EAGAIN`; the third by letting go of the connection altogether, where it is an
/// `EPIPE`. The measurement is the same one either way: how much this peer got rid of
/// before the daemon stopped taking it.
fn blaster(session: &Session) -> UnixStream {
    let mut socket = UnixStream::connect(&session.socket).expect("connect");
    write_frame(&mut socket, &hello_frame(0, RESUME_FROM_START));
    socket.set_nonblocking(true).expect("stop blocking");
    socket
}

/// Regression: an `accept` the daemon has no descriptor for is waited out rather
/// than retried without pause.
///
/// `EMFILE` and `ENFILE` fail the call *without* consuming the queued connection, so
/// the listener goes on reporting itself readable and `poll` returns instantly on
/// every pass for as long as the shortage lasts. The peer closing does not clear it
/// either: an aborted connection sits in the backlog until something accepts it.
/// § 6.4.1 is right that such an error must not end the session, but returning to
/// retry it on the next pass is retrying it immediately and for ever — and under a
/// system-wide `ENFILE` every nomux daemon on the host burns a core, which is what
/// whoever is trying to recover the machine has to compete with.
///
/// The shortage is imposed from outside rather than provoked from within: lowering
/// another process's soft `RLIMIT_NOFILE` needs no privilege beyond sharing its uid,
/// costs the daemon none of the descriptors it already holds — `alloc_fd` refuses a
/// *number* at or above the limit and says nothing about the table below it — and is
/// exactly the state a host out of descriptors puts it in. Measured as processor
/// time for the reason
/// [`a_closed_agent_channel_whose_peer_stopped_reading_leaves_the_daemon_asleep`]
/// gives, against the same window and the same tolerance.
#[test]
fn a_daemon_that_cannot_accept_stands_back_rather_than_spinning() {
    /// Long enough that the bug shows up as tens of ticks, short enough to keep the
    /// suite where it is.
    ///
    /// Half a second rather than the 300 ms the agent-channel test above uses,
    /// because that is what separates the two answers well enough for a threshold to
    /// sit between them under load. No figure is quoted for the spin: it is whatever
    /// share of a core the scheduler hands the daemon, and three measurements of it
    /// spread from the twenties to the forties. What the threshold rests on is the
    /// other answer, which is not a share of anything — the fixed daemon sleeps
    /// 100 ms at a time and wakes five times to fail one `accept`, so it measures
    /// zero, and no amount of load moves zero.
    const WINDOW: Duration = Duration::from_millis(500);
    /// Five ticks is 50 ms of processor time against half a second of wall clock: a
    /// tenth of one core, well under the lowest spin figure seen and unreachable by a
    /// daemon that is asleep.
    const TOLERATED: u32 = 5;

    let session = Session::start("emfile");
    let daemon = session.child.id();
    // Not merely answering. `Session::start` waits for the socket, and the daemon
    // binds that before it writes its pidfile, opens `/dev/null` over its stdio and
    // asks `logind` about lingering — all of which need a descriptor, and the first
    // of which is a `?` that ends the process. Starving it there is starving a
    // *startup*, which is a different thing from the event loop this measures and
    // fails it about one run in four on a loaded machine. The pidfile is the last of
    // those that can refuse to start, so waiting for it is waiting for the state the
    // test is about.
    wait_for(&session.pid_file());
    let restore = open_file_limit(daemon);
    // Below the three the daemon cannot be without, so the next descriptor it asks
    // for is refused however few it is holding.
    set_open_file_limit(daemon, 3);

    // The knock it cannot answer. `connect` succeeds regardless — the connection is
    // queued by the listener, and the `accept` that is refused is what leaves it
    // there.
    let starved = UnixStream::connect(&session.socket).expect("knock on the door");
    let began = cpu_ticks(daemon);
    thread::sleep(WINDOW);
    let burned = cpu_ticks(daemon).saturating_sub(began);
    assert!(
        burned <= TOLERATED,
        "the daemon burned {burned} clock ticks in {WINDOW:?} failing to accept one \
         connection, with no client attached and no child running"
    );

    // And the listener came back rather than being stood down for good: a backoff
    // that never expires is the same session lost by a quieter route.
    set_open_file_limit(daemon, restore);
    drop(starved);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    client.input(0, b"echo NOMUX-AFTER-EMFILE\n");
    client.read_until("NOMUX-AFTER-EMFILE", ok.resume_from);
}

/// The soft limit on open descriptors that `pid` is running under.
fn open_file_limit(pid: u32) -> u64 {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `prlimit` is passed a pid, the resource it is being asked about, a null
    // pointer for the limit that is not being set, and a pointer to a `rlimit` this
    // frame owns for the answer. Reading a limit needs no privilege at all.
    let read = unsafe {
        libc::prlimit(
            i32::try_from(pid).expect("a pid fits a pid_t"),
            libc::RLIMIT_NOFILE,
            std::ptr::null(),
            &raw mut current,
        )
    };
    assert_eq!(
        read,
        0,
        "read the daemon's open-file limit: {}",
        std::io::Error::last_os_error()
    );
    current.rlim_cur
}

/// Puts `pid` under a soft limit of `soft` open descriptors.
///
/// The hard limit is read back and passed through untouched, which is what keeps
/// this within what one uid may do to its own processes: raising a hard limit is
/// privileged, leaving it alone is not.
fn set_open_file_limit(pid: u32, soft: u64) {
    let mut hard = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: as [`open_file_limit`], which is the same call for the same reason.
    let read = unsafe {
        libc::prlimit(
            i32::try_from(pid).expect("a pid fits a pid_t"),
            libc::RLIMIT_NOFILE,
            std::ptr::null(),
            &raw mut hard,
        )
    };
    assert_eq!(read, 0, "read the daemon's open-file limit");
    let wanted = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard.rlim_max,
    };
    // SAFETY: as above, with the two pointers the other way round: `wanted` is owned
    // by this frame and the answer is not asked for.
    let set = unsafe {
        libc::prlimit(
            i32::try_from(pid).expect("a pid fits a pid_t"),
            libc::RLIMIT_NOFILE,
            &raw const wanted,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        set,
        0,
        "hold the daemon to {soft} open descriptors: {}",
        std::io::Error::last_os_error()
    );
}
