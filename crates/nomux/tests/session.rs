//! End-to-end tests against the real binary.
//!
//! These drive `nomux daemon` over its unix socket, speaking the wire protocol
//! directly, so they exercise the PTY, the ring buffer and the resume path rather
//! than a mock of them.
//!
//! The two invariants that matter (`IMPLEMENTATION.md` § 9): input is never
//! duplicated, and output is never lost unless a `Gap` was reported.

#![allow(
    clippy::expect_used,
    reason = "the allow-expect-in-tests setting in clippy.toml reaches `#[test]` \
              bodies and `#[cfg(test)]` modules, not the helpers an integration \
              test crate keeps beside them"
)]

mod harness;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{
    ErrorCode, Frame, FrameType, HEADER_LEN, HELLO_AGENT_FORWARD, HELLO_REPAINT_CTRL_L, Hello,
    MAX_AGENT_CHANNELS, PROTOCOL_VERSION, RESUME_FROM_START, WinSize, decode_header,
};

use harness::{
    Client, Reaper, Rng, Session, Spawned, accept_within, collect, control, has_unread_bytes,
    hello_frame, join_before, nomux, nomux_with_shell, poll_until, push_until_refused,
    read_uninterrupted, reconnect_until_gap, run_root, shrink_send_buffer, stderr, stdout,
    succeeded, wait_for, while_nothing_forks, write_frame,
};

#[test]
fn runs_a_shell_and_streams_its_output() {
    let (_session, mut client, ok) = Session::attached("basic");
    assert_eq!(ok.protocol, PROTOCOL_VERSION);
    assert!(!ok.gap);

    client.input(0, b"echo NOMUX-ALPHA\n");
    client.read_until("NOMUX-ALPHA", ok.resume_from);
}

#[test]
fn output_resumes_contiguously_after_a_reconnect() {
    let (session, mut client, ok) = Session::attached("resume");

    let first = b"echo NOMUX-BEFORE\n";
    client.input(0, first);
    let (_, offset) = client.read_until("NOMUX-BEFORE", ok.resume_from);

    // Sever the connection the way a network drop would.
    drop(client);
    let mut client = session.connect();
    let ok = client.hello(offset);
    assert_eq!(
        ok.resume_from, offset,
        "resume must continue from exactly where the client left off"
    );
    assert_eq!(
        ok.in_applied,
        first.len() as u64,
        "daemon reports authoritative input position"
    );
    assert!(!ok.gap, "nothing should have been dropped in this window");

    client.input(ok.in_applied, b"echo NOMUX-AFTER\n");
    client.read_until("NOMUX-AFTER", ok.resume_from);
}

/// A client claiming output the session never produced is clamped down to the end of
/// the stream rather than believed (`IMPLEMENTATION.md` § 4.2).
///
/// `resume_from` is clamped at *both* ends, and only the lower clamp is otherwise
/// exercised — the test above it resumes from where it left off, and the gap tests
/// resume from below `base_offset`. Without the upper one the daemon sets
/// `sent_through` past everything it holds, and the documented consequence is that
/// the session looks dead: no output at all until the child happens to write enough
/// to catch up. Nothing is reported as a gap either, because nothing was dropped —
/// there was never anything there.
#[test]
fn an_out_offset_past_the_end_of_the_stream_is_clamped_rather_than_believed() {
    /// Comfortably past anything a shell echoing one line has ever written.
    const FAR: u64 = 1 << 20;

    let (session, mut client, ok) = Session::attached("clamp_high");

    let first = b"echo NOMUX-BEFORE-CLAMP\n";
    client.input(0, first);
    let (_, end) = client.read_until("NOMUX-BEFORE-CLAMP", ok.resume_from);
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(end + FAR);
    assert!(
        !resumed.gap,
        "nothing was dropped, so nothing may be reported as a gap"
    );
    // Pinned from below as well as from above. Clamping to the ring's *base* rather
    // than to its end also satisfies an upper bound, also reports no gap, and also
    // leaves the read at the end of this test finding its marker — in a stream it
    // simply receives again from the start.
    assert!(
        (end..end + FAR).contains(&resumed.resume_from),
        "an out_offset past the end of the stream must be clamped to the end of it: \
         resumed from {} against the {end} already received and the {} claimed",
        resumed.resume_from,
        end + FAR
    );
    assert_eq!(
        resumed.in_applied,
        first.len() as u64,
        "the session's input position must survive a client claiming output it \
         never received"
    );

    // And it is a live session rather than one that has gone quiet behind a resume
    // point past its own stream, which is the whole shape of the fault.
    client.input(resumed.in_applied, b"echo NOMUX-AFTER-CLAMP\n");
    client.read_until("NOMUX-AFTER-CLAMP", resumed.resume_from);
}

/// The invariant that matters most: a client replaying input it already sent —
/// because the `InputAck` was lost with the connection — must not run it twice.
///
/// Everything here happens with the line discipline's echo turned off, and that is
/// not tidiness. With echo on, the first frame carrying `NOMUX-ONCE-MARKER` is the
/// terminal repeating the *command* — measured against a hand-written client, which
/// saw `OUTPUT off=0 "echo NOMUX-ONCE-MARKER\r\n"` before `OUTPUT off=24
/// "NOMUX-ONCE-MARKER\r\n"` — so the resume point below was 24, ahead of a
/// legitimate single occurrence rather than behind it, and the transcript compared
/// at the end began before the marker the shell was about to print. What kept the
/// test green on correct code was `dash` not having got round to running the
/// command yet: warmed up, or with 300 ms between the read and the disconnect, it
/// failed on a daemon that was doing exactly the right thing.
///
/// With `-echo` the marker can only be the shell's own output, so the resume point
/// is past the one occurrence there may be, and the fence really is a fence: its
/// text also only ever arrives from the shell, so reading it back proves everything
/// queued in front of it — the replay included — has already been through the PTY.
///
/// Three resends, because `on_input` has two defences and the obvious replay
/// exercises neither. Sending the applied bytes again *exactly* — which is the § 3
/// scenario and was the whole of this test — lands on `end == in_applied`, where
/// the `end > in_applied` guard is false and the trim inside it never runs. The
/// other two put a frame on each side of that line: one ending below it, which only
/// the guard stops from rewinding the session's position, and one straddling it,
/// which only the trim stops from running its overlap a second time. Each of the
/// two, removed on its own, now fails this test; before, neither did.
#[test]
fn replayed_input_is_applied_exactly_once() {
    /// How much of the command the short resend below carries. Any amount that
    /// leaves the frame ending below `in_applied` asks the same question; this one
    /// is a whole word of it, so a transcript that does show it is readable.
    const PREFIX: usize = 8;

    let (session, mut client, ok) = Session::attached("dedup");
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);

    // `printf` with a counter would need shell state; instead emit a unique marker
    // and assert it appears exactly once in the transcript.
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
    // *backwards*. `on_input` has two defences and they answer different frames:
    // the `end > in_applied` guard is the only thing that stops a frame ending
    // below the session's position from rewinding it, and the trim is the only
    // thing that stops one ending above it re-running its overlap. Replaying the
    // command exactly reaches neither — `end == in_applied` falls through both —
    // so a test built on that alone passes with either defence removed, which is
    // what this one used to do. Measured: each of the two, taken out on its own,
    // left the whole workspace green.
    client.input(
        ready.in_offset,
        command.get(..PREFIX).expect("part of a line"),
    );
    // Frames are handled in the order they arrive, so a `Pong` for a ping behind
    // them is the daemon having decoded both — and decoded is what matters, since a
    // socket closed with output queued loses whatever `fill` had buffered.
    client.send(&Frame::Ping { nonce: 0xD00D });
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

    // And a resend that overlaps what was applied *and* carries something new,
    // which is what a client actually sends: `offset < in_applied < end`, the frame
    // the trim exists for. The overlap is the whole command, so a daemon that
    // stopped trimming runs the marker a second time rather than something
    // unrecognisable.
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
/// The one error code with nothing else exercising it end to end. Refusing is the
/// only answer available: applying the frame would run keystrokes with a gap in the
/// middle, and the client is the side that is wrong — `in_applied` is authoritative,
/// so a client that skipped ahead has lost track of its own stream and has to start
/// again from what the daemon reports.
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

#[test]
fn overflow_is_reported_as_a_gap_rather_than_silently_truncated() {
    let (session, mut client, ok) = Session::attached("gap");

    // Detach, then generate far more output than the ring can hold.
    // Comfortably more than the 64 KiB ring configured for these tests.
    let filler = format!(
        "for i in $(seq 1 4000); do echo {}; done\n",
        "x".repeat(200)
    );
    client.input(0, filler.as_bytes());
    // The command that makes the gap has to be the daemon's before the connection
    // goes: an `Input` written but not yet decoded is lost when the socket closes
    // with output queued (see `Client::drain_available`), and losing this one leaves
    // the child silent, the ring never overflowing, and the wait below spending its
    // whole twenty seconds blaming the ring for a keystroke that never arrived.
    client.wait_for_input_ack(filler.len() as u64);
    drop(client);

    // The daemon must keep draining the PTY while detached, so the ring overflows
    // even with nobody listening. Waited for rather than slept through.
    let (_client, resumed) = reconnect_until_gap(&session, 0, ok.resume_from);
    assert!(
        resumed.resume_from > ok.resume_from,
        "resume point must advance past the discarded bytes"
    );
}

/// Markers bracketing the stream [`predictable_blob`] produces.
///
/// Lower case, which that alphabet cannot contain, so neither marker can occur
/// inside the data it delimits — and the read that stops at the opening one
/// therefore stops at the byte before the stream rather than somewhere inside it.
const BLOB_BEGIN: &str = "nomux-blob-begin";
const BLOB_END: &str = "nomux-blob-end";

/// A byte stream a test can predict exactly and a ring cannot hold cheaply.
///
/// Two properties, both load-bearing, and neither available from the `/dev/zero`
/// the mid-stream gap test below used to run on. *Predictable*, so that a byte the
/// daemon labels with an offset can be checked against the byte that offset names —
/// which is the whole of what a `Gap` claims and the one thing no gap test in this
/// suite asserted. *Aperiodic and near-incompressible*, so that "more than the ring
/// holds" is a property of the data rather than an assumption about the ring: eight
/// megabytes of `/dev/zero` fit in any ring that compresses, and a test resting on
/// that would then find nothing dropped, no gap owed, and nothing to report.
///
/// Every byte carries six bits of the generator's stream, drawn from `0x21..=0x60`,
/// which is what lets it cross a terminal in canonical mode untouched: no newline,
/// no carriage return, no tab, nothing the line discipline has an opinion about. A
/// compressor could take it to three quarters of its size, against a ring that
/// holds a sixtieth of it.
fn predictable_blob(len: usize) -> Vec<u8> {
    // Any fixed seed; the generator is reproducible from it, which is the whole
    // requirement — nothing here explores a space, it just needs the same stream
    // every run so a failure can be looked at twice.
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
    /// The whole of what the child writes from there: the blob and the closing
    /// marker, so an offset into the stream is an index into this.
    expected: Vec<u8>,
    /// Touched by the child once every byte above has been written, which is how a
    /// client that is deliberately not reading learns the child has finished.
    sentinel: PathBuf,
    /// One past the last input byte sent here.
    in_offset: u64,
}

/// Puts a blob where the session's child can read it, sets it writing, and leaves
/// the client's stream positioned at exactly the first byte of it.
///
/// The opening marker goes on a line of its own and is read to completion before
/// the line that produces the blob is sent. That ordering is what makes the
/// arithmetic exact rather than nearly so: the shell writes nothing more until it
/// has read the next line, so the offset that read returns is one past the marker
/// and not one past whatever else happened to be in the frame carrying it.
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
/// against the byte its offset names, and returns the gaps followed on the way.
///
/// This is the assertion the gap tests exist for and the one none of them made.
/// Every one of them adopts `new_base_offset` or `resume_from` as ground truth and
/// then checks contiguity *relative to it* — which cannot fail, whatever the daemon
/// says. A base reported N too low replays N bytes the client already has; one
/// reported N too high drops N it never will; both produce a perfectly contiguous
/// stream and both corrupt the user's scrollback, which is the single failure
/// `IMPLEMENTATION.md` § 9's second invariant exists to prevent. Indexing a model of
/// the child's own output by absolute offset is what makes that claim falsifiable.
#[expect(
    clippy::panic,
    reason = "clippy.toml's allow-panic-in-tests reaches `#[test]` bodies, not the \
              helpers an integration test crate keeps beside them"
)]
fn read_against(client: &mut Client, planted: &Planted, from: u64) -> Vec<(u64, u64)> {
    let expected = &planted.expected;
    let end = planted.stream_start + expected.len() as u64;
    let mut offset = from;
    let mut gaps = Vec::new();
    while offset < end {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode frame") {
            Frame::Output { offset: at, data } => {
                assert_eq!(
                    at,
                    offset,
                    "output must join up unless a Gap said otherwise, and this frame \
                     opens {} bytes from where the stream stood",
                    at.abs_diff(offset)
                );
                let index = usize::try_from(at.saturating_sub(planted.stream_start))
                    .expect("an offset within a stream this test wrote");
                let want = expected.get(index..index + data.len()).unwrap_or_else(|| {
                    panic!(
                        "the daemon sent {} bytes at offset {at}, running {} past the \
                         end of everything the child ever wrote",
                        data.len(),
                        index + data.len() - expected.len()
                    )
                });
                assert_same_stream(want, data, at);
                offset += data.len() as u64;
            }
            Frame::Gap { new_base_offset } => {
                assert!(
                    new_base_offset > offset,
                    "a Gap must name a base past what the client was sent: \
                     {new_base_offset} against {offset}"
                );
                gaps.push((offset, new_base_offset));
                offset = new_base_offset;
            }
            Frame::InputAck { .. } | Frame::Pong { .. } => {}
            other => panic!("unexpected {other:?} while reading the session's output"),
        }
    }
    gaps
}

/// Fails saying which offset the stream stopped meaning what the child wrote there.
///
/// Quoted from both sides, because the number alone does not say which way the
/// error went — a stream that resumed too early repeats bytes the client has, and
/// one that resumed too late is missing bytes it never will.
#[expect(
    clippy::panic,
    reason = "clippy.toml's allow-panic-in-tests reaches `#[test]` bodies, not the \
              helpers an integration test crate keeps beside them"
)]
fn assert_same_stream(want: &[u8], got: &[u8], at: u64) {
    if want == got {
        return;
    }
    let diff = want
        .iter()
        .zip(got)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| want.len().min(got.len()));
    let window = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes.get(diff..(diff + 48).min(bytes.len())).unwrap_or(&[]))
            .into_owned()
    };
    panic!(
        "the daemon labelled a byte with an offset that is not where the child wrote \
         it: at offset {}, the session sent {:?} where the child wrote {:?}. The \
         stream is contiguous and wrong, which is what an off-by-N ring base looks \
         like from a client",
        at + diff as u64,
        window(got),
        window(want),
    );
}

/// A gap reported at the handshake must name the byte the stream really resumes at.
///
/// The handshake half of the wiring `Ring::base` → `HelloOk.resume_from`, which
/// `src/ring.rs` pins only as arithmetic in isolation. Here the client comes back
/// below the ring's base, is told where it may resume, and every byte from that
/// point on is checked against what the child actually wrote there. A daemon whose
/// base was off in either direction hands back a stream that joins up perfectly and
/// says the wrong thing, and until this test nothing in the suite could tell the
/// two apart.
///
/// The byte comparison is only half of it, and on its own it catches only half the
/// fault. A base reported *too low* serves bytes the ring no longer starts at and
/// the model comparison fires. A base reported too *high* — `resume_from + 16`, say
/// — is a daemon silently throwing away sixteen bytes of scrollback it is still
/// holding, and every byte it then sends is at the offset it claims, so nothing
/// about the stream is wrong: it is simply short. Measured, on the first version of
/// this test: that injection left the whole workspace green.
///
/// So `resume_from` is pinned to the value it must have rather than to a range. The
/// child has finished before this client attaches, the ring is exactly full, and a
/// `VecDeque` of `RING` bytes retains exactly `RING` — so the oldest byte the daemon
/// can serve is `stream_end - RING` and there is nothing approximate to allow for.
/// One equality catches both directions, and it is the only assertion here that
/// catches the second.
#[test]
fn a_gap_at_the_handshake_names_the_byte_the_stream_actually_resumes_at() {
    /// Small enough that half a megabyte overruns it many times over, and larger
    /// than the terminal setup that precedes the blob — so the only thing evicted
    /// is data this test can predict.
    const RING: usize = 16 * 1024;
    /// Comfortably past [`RING`], and small enough to be produced and compared in
    /// milliseconds. Nothing here needs the megabytes the mid-stream case does: the
    /// client is *away*, so there is no send queue to outrun, only the ring.
    const PRODUCED: usize = 512 * 1024;

    let session = Session::start_with_ring("gap_exact_hello", RING);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // Echo off, so the stream from the marker on is the child's own bytes and the
    // model below is the whole of it.
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let planted = plant_blob(
        &session,
        &mut client,
        ready.offset,
        ready.in_offset,
        PRODUCED,
    );

    // The command that makes the gap has to be the daemon's before the connection
    // goes: an `Input` written but not yet decoded is lost when the socket closes
    // with output queued (see `Client::drain_available`).
    client.wait_for_input_ack(planted.in_offset);
    drop(client);

    assert!(
        poll_until(Duration::from_secs(10), || planted.sentinel.exists()),
        "the child never finished writing its {PRODUCED} bytes"
    );

    // Connected and greeted once rather than through `reconnect_until_gap`, which
    // exists for the case where whether the ring has overflowed *yet* is a question
    // about the scheduler. It is not one here: the sentinel says the child has
    // written every byte, so the overflow is behind us and the gap is owed on the
    // first `Hello`. Retrying would only make a failure take twenty seconds to
    // arrive.
    let mut client = session.connect();
    let resumed = client.hello(planted.stream_start);
    assert!(
        resumed.gap,
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

/// The mid-stream half of the same invariant: a client that never left is still
/// told when the ring overran it.
///
/// The test above pins the *other* place a gap is reported. There the client has
/// been away and comes back, `on_hello` compares the offset it claims against the
/// ring's base, and the answer is a flag on `HelloOk`. Nothing reconnects here, so
/// that path is never entered: what this waits for is the `Gap` *frame*
/// `pump_output` sends down a connection that has been attached and greeted the
/// whole time — the case a slow terminal on a busy session actually meets. Neither
/// is a duplicate of the other, and deleting either leaves half of § 9 undefended.
///
/// Deterministic because the state it needs is monotone rather than timed. The
/// client greets and then reads nothing of the stream, so `sent_through` stops at
/// whatever the daemon's send queue and the kernel's socket buffers hold between
/// them, and stays there. The child goes on to write several times that much through
/// a ring that keeps [`RING`], so `base` passes `sent_through` and can never come
/// back under it: from that moment the `Gap` is owed, and draining a single byte is
/// what collects it. Nothing here waits on the scheduler having got round to
/// something — the sentinel file is how a client that is not reading learns the child
/// has finished, since the stream it is ignoring cannot tell it.
///
/// The child writes [`predictable_blob`] rather than the `/dev/zero` it used to,
/// and that buys two things. The premise "eight megabytes will not fit in a 128 KiB
/// ring" stops being an unstated assumption about the ring — eight megabytes of
/// zeroes fit in any ring that compresses, and the test would then pass with no gap
/// owed and nothing dropped, having proved nothing. And the `Gap` stops being taken
/// on trust: `read_against` checks every arriving byte against the byte its offset
/// names, so the base the daemon reports has to be the right one rather than merely
/// a plausible one.
///
/// And, as at the handshake, the byte comparison alone catches only a base that is
/// too *low*. One that is too high sends every byte at the offset it claims and
/// simply omits the ones in front of it, which is scrollback the ring was still
/// holding thrown away without a word. So the gap is pinned to a number rather than
/// to a property: there can be exactly one, at exactly `stream_end - RING`. Both
/// halves of that follow from the setup rather than from timing — the ring's base
/// can only pass `sent_through` once the send queue has saturated, and it stays
/// saturated until this client reads, by which time the sentinel says the child has
/// finished and the ring is static.
#[test]
fn an_overflow_that_outruns_an_attached_client_is_reported_as_a_gap_mid_stream() {
    /// Larger than the 64 KiB the daemon takes off the PTY in one pass, so a client
    /// that is still keeping up cannot be gapped by a single read. That keeps the
    /// setup below silent and leaves exactly one way to reach a gap here: the client
    /// falling behind on purpose.
    const RING: usize = 128 * 1024;
    /// What the child writes. Eight megabytes is comfortably past everything between
    /// it and the client put together — the daemon's megabyte of queued output, the
    /// 256 KiB frame it may overshoot that by, the kernel's socket buffers, and
    /// [`RING`].
    const PRODUCED: usize = 8 << 20;

    let session = Session::start_with_ring("midstream_gap", RING);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    assert!(
        !ok.gap,
        "a session nobody has attached to before has nothing to report at the \
         handshake, so every gap below is one this connection was sent"
    );

    // Echo off, so everything from the opening marker on is the child's own bytes
    // and the model is the whole of the stream. The sentinel is touched last, so its
    // arrival means every byte before it is already in the ring — or already evicted
    // from it.
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let planted = plant_blob(
        &session,
        &mut client,
        ready.offset,
        ready.in_offset,
        PRODUCED,
    );

    // And from here to the sentinel the client reads nothing, which is the whole
    // setup: the daemon's send queue fills, `sent_through` stops with it, and the
    // ring runs away from a client that has not gone anywhere.
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

/// A `NOMUX_RING_BYTES` the daemon cannot use falls back to the default rather than
/// refusing to start (`IMPLEMENTATION.md` § 4).
///
/// `Ring::new` asserts its capacity is non-zero, so this does not degrade if the
/// filter that rejects a zero is ever lost: the daemon aborts before it binds
/// anything, and every session on a host with that variable exported stops starting
/// at once. A mistyped tuning variable should never cost somebody their session, so
/// the value is dropped and the default used.
///
/// The third row is the one that is *not* a fallback, and it is here because it is
/// the same promise reached by the other of the two routes to it. A value mistyped
/// upwards parses and is positive, so nothing rejects it — `MAX_RING_CAPACITY` caps
/// it instead, which its own doc gives as the whole reason it exists: without a
/// ceiling `VecDeque::with_capacity` answers a request it cannot serve by aborting
/// the process, and the daemon dies before it binds exactly as the zero would have
/// made it. What the daemon then reserves is a gigabyte of *address space* rather
/// than of memory — nothing here fills a ring, so the pages are never touched — which
/// is what makes this row cost no more to run than the two above it.
#[test]
fn a_ring_capacity_the_daemon_cannot_use_falls_back_to_the_default() {
    for (name, value) in [
        ("ring_zero", "0"),
        ("ring_garbage", "not-a-number"),
        ("ring_huge", "99999999999999999"),
    ] {
        let session = Session::start_with_raw_ring(name, value);
        let mut client = session.connect();
        let ok = client.hello(RESUME_FROM_START);

        // Serving, rather than merely having bound a socket. The socket is bound
        // before the ring is built, so a daemon that aborted on the assertion leaves
        // the file behind and `wait_for` is satisfied by a corpse.
        //
        // The marker carries the case's own name so that the wait names it too: the
        // two rows are otherwise indistinguishable at the point they fail, and
        // `timed out waiting for "NOMUX-DEFAULT-RING"` twice over says nothing about
        // which `NOMUX_RING_BYTES` the daemon choked on.
        let marker = format!("NOMUX-DEFAULT-RING-{name}");
        client.input(0, format!("echo {marker}\n").as_bytes());
        client.read_until(&marker, ok.resume_from);
    }
}

/// An `OutputAck` is advisory: it says where a client had got to, and the ring keeps
/// everything regardless (`IMPLEMENTATION.md` § 3 and § 4's "never trimmed on ack").
///
/// The daemon's arm for it is empty on purpose, which is exactly the kind of thing a
/// later change fills in — `consumed_through` looks like a low-water mark asking to
/// be applied, and applying it would even look like an improvement, since the bytes
/// below it are ones somebody has already seen. Nothing else in the suite would
/// notice: the codec tests prove the frame survives a round trip, and every other
/// test here reads its output as it arrives, so a ring trimmed to what its reader
/// already holds serves all of them identically. What breaks is the one thing the
/// ring is for — § 4's "a full rolling window is the scrollback a fresh client gets"
/// — and it breaks for the *next* client, which never sent the ack.
///
/// So the marker is written, acked past, and then asked for by somebody who has
/// never seen it. The flag cannot be what fails here and is asserted anyway:
/// `RESUME_FROM_START` resumes at `base_offset` whatever that is, so a daemon that
/// trimmed would report no gap and simply hand back a shorter stream. The base is
/// what says so directly — a session this quiet cannot move it any other way, the
/// ring being 64 KiB against a few hundred bytes of shell — and the transcript is
/// what says what was lost.
///
/// The fence is what bounds the second read: the replay is finite and the session
/// silent after it, so looking for a marker that is gone would otherwise cost the
/// whole timeout rather than failing with the transcript in hand.
#[test]
fn an_output_ack_never_trims_the_ring() {
    let (session, mut client, ok) = Session::attached("ack_ring");

    let command = b"echo NOMUX-BEFORE-ACK\n";
    client.input(0, command);
    let (_, end) = client.read_until("NOMUX-BEFORE-ACK", ok.resume_from);

    // Everything this client has seen, which is everything the marker is in.
    client.send(&Frame::OutputAck {
        consumed_through: end,
    });
    // Frames are handled in the order they arrive, so a `Pong` for a ping sent behind
    // the ack is the daemon having already done whatever it does with one. Without it
    // the reconnect below could win the race and pass against a daemon that trims.
    client.send(&Frame::Ping { nonce: 0xACED });
    drop(client.next_of(FrameType::Pong));
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    assert!(
        !resumed.gap,
        "nothing was dropped, so nothing may be reported as a gap"
    );
    assert_eq!(
        resumed.resume_from, 0,
        "the ack moved the ring's base off the start of the stream"
    );

    client.input(resumed.in_applied, b"echo NOMUX-FENCE\n");
    let (replayed, _) = client.read_until("NOMUX-FENCE", resumed.resume_from);
    assert!(
        replayed.contains("NOMUX-BEFORE-ACK"),
        "output the previous client acknowledged was trimmed from the ring, so a \
         fresh client got a shorter scrollback than the session held: {replayed:?}"
    );
}

/// § 6.4's whole sentence, rather than its first clause: "the previous connection
/// receives `Error{TAKEOVER}` **and closes**", and the session goes to the newcomer.
///
/// The refusal alone is the cheapest third of that to satisfy and the least of what
/// the client is promised. A daemon that sent the error and then kept the old
/// connection in its poll set would leave two peers believing they hold the session,
/// with the evicted one told never to reconnect (§ 6.4) and still receiving output —
/// and a daemon that evicted the incumbent without promoting the newcomer leaves the
/// shell running with nobody attached at all, which is the exact failure
/// [`a_version_mismatch_refuses_the_newcomer_without_evicting_the_client`] guards
/// from the other side. So all three are asserted here, in the order the daemon
/// establishes them.
#[test]
fn a_second_client_takes_over_and_the_first_is_told_why() {
    let (session, mut first, _) = Session::attached("takeover");

    let mut second = session.connect();
    let ok = second.hello(RESUME_FROM_START);

    first.expect_error(
        ErrorCode::Takeover,
        "an evicted client must learn it was a takeover, not a network fault",
    );
    // The refusal was the daemon's goodbye, not a message on a connection it means to
    // go on serving. Nothing else may follow it — `expect_eof` fails on a second
    // `Error`, which would be the daemon refusing this peer for some further reason
    // rather than having finished with it.
    first.expect_eof("an Error{TAKEOVER}");

    // And the session is the newcomer's, which is the half the eviction exists for:
    // a round trip through the child, so what is asserted is a client that can drive
    // the shell rather than one that merely got a `HelloOk`.
    second.input(ok.in_applied, b"echo NOMUX-TOOK-OVER\n");
    second.read_until("NOMUX-TOOK-OVER", ok.resume_from);
}

/// The frozen control surface reaches a live session through the files on disk
/// alone (`IMPLEMENTATION.md` § 6.6) — `list` finds it and `kill` stops it.
///
/// "Stops it" was the half nobody checked. The assertion was that the socket had
/// gone, which is a statement about `unlink` and not about the session: a `kill`
/// that removed the five files and left the daemon running would pass it unchanged,
/// and § 10's whole contract for `kill` is that a zero status means "there is no
/// such session". What such a daemon leaves behind is the worst of both — a shell
/// still holding the user's work, with nothing on disk to attach to it by and
/// nothing for `list` to report, until the seven-day idle deadline collects it.
#[test]
fn list_and_kill_operate_without_the_protocol() {
    let (mut session, _client, _) = Session::attached("control");

    let listed = stdout(&control(&session.root, &["list"]));
    assert!(
        listed.contains(&session.id),
        "list should report the live session, got {listed:?}"
    );
    // One line per session and not per run file: `list` walks a directory holding
    // several names that lead to this one id, and it is the only thing that folds
    // them back together.
    assert_eq!(
        listed
            .lines()
            .filter(|line| line.starts_with(&format!("{}\t", session.id)))
            .count(),
        1,
        "list reported the same session more than once, got {listed:?}"
    );

    succeeded(
        &control(&session.root, &["kill", &session.id]),
        "kill failed",
    );

    assert!(!session.socket.exists(), "kill must unlink the run files");
    // `kill` returns once the daemon has stopped answering, so the process is either
    // already gone or on its way; the wait is for the reaping rather than for the
    // signal. Collected here as well as asserted, since the harness would otherwise
    // `SIGKILL` a corpse and learn nothing.
    assert!(
        poll_until(Duration::from_secs(10), || session
            .child
            .try_wait()
            .expect("wait for the daemon")
            .is_some()),
        "kill removed the session's five files and left the daemon running, so the \
         user's shell is still there with nothing left on disk to reach it by"
    );
}

/// Connecting is not attaching.
///
/// The frozen control surface decides whether a daemon is alive by connecting to
/// its socket (§ 6.6), and so does the spawn race in § 6.3. If the daemon counted
/// that as a takeover, `nomux list` would evict the user from every session on the
/// host — and the client is told never to auto-reconnect after `TAKEOVER`, so the
/// damage would be permanent.
#[test]
fn a_liveness_probe_does_not_evict_the_attached_client() {
    let (session, mut client, ok) = Session::attached("probe");

    // The bare probe, then the real thing.
    for _ in 0..3 {
        drop(UnixStream::connect(&session.socket).expect("probe connect"));
    }
    assert!(stdout(&control(&session.root, &["list"])).contains(&session.id));

    // `read_until` refuses anything that is not output, so an `Error{TAKEOVER}`
    // fails this rather than being skipped over.
    client.input(0, b"echo NOMUX-STILL-ATTACHED\n");
    client.read_until("NOMUX-STILL-ATTACHED", ok.resume_from);
}

/// The refusals an *attached* client can earn, and the session surviving each.
///
/// `handle_frame`'s "frame is not valid from a client" arm and both of
/// `read_client`'s `reject(Protocol, …)` sites had no caller in the suite at all:
/// every test here speaks the protocol correctly once greeted, so a daemon that
/// answered a server-only frame by acting on it, or a bad header by carrying on
/// reading the socket as though the stream were still framed, would go unnoticed.
/// The last of those is the one that matters — a frame boundary the daemon has lost
/// track of is a stream in which every subsequent `Input` offset is somebody else's
/// number.
///
/// Three shapes, and they are three because they reach the refusal by three
/// different routes. A `HelloOk`, an `Output` and a `Gap` are well-formed frames the
/// *daemon* sends, so they decode perfectly and fall through the match; the daemon
/// must not mistake its own vocabulary for the client's. A discriminant no
/// `FrameType` has never reaches the match, because the header will not decode. And
/// a `Resize` whose payload is four bytes rather than eight has a header that
/// decodes and a body that does not, which is the one case between them where the
/// daemon knows how many bytes to skip and still must not.
///
/// Each row asserts all three of what a refusal is: the code, that the connection
/// then closes without a second complaint — which is what `Client::expect_eof`
/// separates from a frame that was quietly *honoured* — and that a fresh client can
/// still drive the shell afterwards. A daemon that took the session down with the
/// misbehaving connection would satisfy the first two.
#[test]
fn frames_a_client_may_not_send_are_refused_and_the_connection_closed() {
    /// One case: what the client puts on the wire, and what the failure says it was.
    struct Refused {
        what: &'static str,
        write: fn(&mut Client),
    }

    let cases = [
        Refused {
            what: "a HelloOk, which is the daemon's own answer coming back at it",
            write: |client| {
                client.send(&Frame::HelloOk(nomux_proto::HelloOk {
                    protocol: PROTOCOL_VERSION,
                    resume_from: 0,
                    in_applied: 0,
                    win: harness::WIN,
                    gap: false,
                    linger: nomux_proto::Linger::Unknown,
                    agent: false,
                }));
            },
        },
        Refused {
            what: "an Output, which only the session has any business producing",
            write: |client| {
                client.send(&Frame::Output {
                    offset: 0,
                    data: b"not from here",
                });
            },
        },
        Refused {
            what: "a Gap, which is a claim about a ring the client does not own",
            write: |client| {
                client.send(&Frame::Gap {
                    new_base_offset: 1 << 40,
                });
            },
        },
        Refused {
            what: "a header carrying a discriminant no FrameType has",
            // `0xff` is past every variant in the table, and the length is zero so
            // that a daemon which skipped the frame rather than refusing it would
            // find the stream still framed — the failure has to come from the
            // header being unreadable, not from what followed it.
            write: |client| client.send_raw(&[0xff, 0x00, 0x00, 0x00]),
        },
        Refused {
            what: "a Resize whose payload is half a WinSize",
            // A header that decodes and a body that does not: four bytes where the
            // frame's four `u16`s need eight.
            write: |client| client.send_raw(&[0x07, 0x00, 0x00, 0x04, 0, 80, 0, 24]),
        },
    ];

    for (round, case) in cases.iter().enumerate() {
        let session = Session::start(&format!("refuse_{round}"));
        let mut client = session.connect();
        let ok = client.hello(RESUME_FROM_START);
        // Greeted *and* serving: the session is created by the first `Hello`, so a
        // round trip through the child is what puts the connection in the state this
        // is about rather than in the middle of its own handshake.
        client.input(0, b"echo NOMUX-BEFORE-REFUSAL\n");
        let (_, offset) = client.read_until("NOMUX-BEFORE-REFUSAL", ok.resume_from);

        (case.write)(&mut client);
        client.expect_error_among_output(ErrorCode::Protocol, case.what);
        client.expect_eof(case.what);
        drop(client);

        // The whole point of refusing on the connection's own terms: the shell is
        // still there, at the offsets it had, for whoever attaches next.
        let mut fresh = session.connect();
        let resumed = fresh.hello(offset);
        assert!(
            !resumed.gap,
            "{}: the session lost output while refusing one connection",
            case.what
        );
        fresh.input(resumed.in_applied, b"echo NOMUX-STILL-SERVING\n");
        fresh.read_until("NOMUX-STILL-SERVING", resumed.resume_from);
    }
}

/// A session whose shell cannot be started is refused with `Error{INTERNAL}`.
///
/// The one `ErrorCode` a running daemon never produced anywhere in the suite. It is
/// the answer to the single failure that can happen *after* a client has been
/// accepted and before it has a session — `Pty::spawn` failing — and a client that
/// gets silence there waits out its own attach deadline instead of reporting a host
/// whose `$SHELL` is wrong. `DESIGN.md` § 6.4 has the client treat `INTERNAL` and
/// `PROTOCOL` differently, so answering with the wrong one is not cosmetic either.
///
/// A directory rather than a missing file, so the failure is `execve` refusing what
/// it was handed rather than `$SHELL` naming nothing: `login_shell` falls back
/// through the password database only when the variable is *absent*, and a path that
/// resolves to something unexecutable is what a real misconfiguration looks like.
#[test]
fn a_session_whose_shell_cannot_be_started_is_refused_as_an_internal_failure() {
    let session = Session::start_with_shell("shell_broken", "/tmp");
    let mut client = session.connect();

    // Written by hand rather than through `Client::hello`, which expects a `HelloOk`
    // and would panic on the refusal that is the whole point.
    client.send(&hello_frame(0, RESUME_FROM_START));
    client.expect_error_among_output(
        ErrorCode::Internal,
        "a shell that cannot be started must be reported as the daemon's failure",
    );
    client.expect_eof("an Error{INTERNAL}");
}

/// A connection that speaks out of turn is refused on its own terms, without
/// costing the session its client.
#[test]
fn a_connection_that_does_not_greet_first_is_refused_alone() {
    let (session, mut client, ok) = Session::attached("no_greeting");

    let mut rude = session.connect();
    rude.send(&Frame::Ping { nonce: 1 });
    rude.expect_error(
        ErrorCode::Protocol,
        "a connection that speaks before it greets must be refused on its own terms",
    );
    drop(rude);

    client.input(0, b"echo NOMUX-UNDISTURBED\n");
    client.read_until("NOMUX-UNDISTURBED", ok.resume_from);
}

/// `Resize` reaches the child's terminal, and every attach restates the geometry
/// (`IMPLEMENTATION.md` § 2.2).
///
/// Nothing else in the suite sends a `0x07`, and nothing looks at the winsize
/// `HelloOk` carries back. Both halves matter to the same user: the window is
/// resized while attached, and the session is then picked up from a terminal of a
/// different size — which is the ordinary case for this project, since the whole
/// point is reattaching from somewhere else. The daemon takes the arriving `Hello`'s
/// winsize as authoritative and says so in its reply, so a client never has to guess
/// whether its size was applied.
#[test]
fn a_resize_reaches_the_child_and_every_attach_restates_the_geometry() {
    let (session, mut client, ok) = Session::attached("resize");
    assert_eq!(
        ok.win,
        harness::WIN,
        "the greeting must confirm the geometry the client asked for"
    );

    let wider = WinSize {
        cols: 132,
        rows: 43,
        xpixel: 0,
        ypixel: 0,
    };
    client.send(&Frame::Resize(wider));
    // `stty size` reports rows then columns, and the line discipline's echo of the
    // command carries neither number — so seeing them is the child's own answer.
    let command = b"stty size\n";
    client.input(0, command);
    client.read_until("43 132", ok.resume_from);
    drop(client);

    // A client arriving from a terminal of the original size gets it back, in the
    // greeting and in the child.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    assert_eq!(
        resumed.win,
        harness::WIN,
        "the reply must carry the geometry of the client it is answering"
    );
    client.input(resumed.in_applied, b"stty size\n");
    client.read_until("24 80", resumed.resume_from);
}

/// `Detach` gives the connection up without giving up the session
/// (`IMPLEMENTATION.md` § 2.2).
///
/// Never sent by anything else here — every other departure in the suite is a socket
/// being dropped, which is the *unclean* case. This is the deliberate one, and what
/// separates them is that nothing may be lost: the daemon closes the connection and
/// keeps the input position, so the client that comes back is told where it was
/// rather than starting the stream again.
#[test]
fn a_detach_ends_the_connection_but_not_the_session() {
    let (session, mut client, ok) = Session::attached("detach_frame");

    let command = b"echo NOMUX-BEFORE-DETACH\n";
    client.input(0, command);
    client.read_until("NOMUX-BEFORE-DETACH", ok.resume_from);

    client.send(&Frame::Detach);
    client.expect_eof("a Detach");
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    assert_eq!(
        resumed.in_applied,
        command.len() as u64,
        "a detach must leave the session's input position where it was"
    );
    client.input(resumed.in_applied, b"echo NOMUX-AFTER-DETACH\n");
    client.read_until("NOMUX-AFTER-DETACH", resumed.resume_from);
}

/// The child's last words come before its status.
///
/// The linger window (§ 6.5) exists so a client reconnecting into the race still
/// collects both — in that order. A client that closes the tab on `Exit` and is
/// handed it first loses the entire transcript.
#[test]
fn the_exit_status_arrives_after_the_final_output() {
    let (session, mut client, _) = Session::attached("exit_order");
    let shell = shell_of(&session);

    let command = b"printf NOMUX-LAST-WORD; exit 3\n";
    client.input(0, command);
    // The daemon must own the command before the connection goes away, or RST
    // takes it with them.
    client.wait_for_input_ack(command.len() as u64);
    drop(client);

    // The reattach has to land after the child is gone, or the ordering below is
    // satisfied by a live stream rather than by the replay this is about — which is
    // all a fixed sleep here could hope for, and silently miss on a loaded machine.
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(shell)),
        "the child never exited, so the reattach below is not the race the linger \
         window exists for"
    );

    // Reattach inside the linger window, exactly the race the window is for.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    let mut seen = Vec::new();
    loop {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode") {
            Frame::Output { data, .. } => seen.extend_from_slice(data),
            Frame::Exit { status, kind } => {
                assert_eq!(status, 3, "the child's own status must survive");
                assert_eq!(kind, nomux_proto::ExitKind::Exited);
                break;
            }
            Frame::InputAck { .. } | Frame::Gap { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let seen = String::from_utf8_lossy(&seen);
    assert!(
        seen.contains("NOMUX-LAST-WORD"),
        "output arrived after the exit status, or not at all: {seen:?} \
         (resumed from {})",
        resumed.resume_from
    );
}

/// A child that was killed is reported as `Signalled` carrying the signal, not as a
/// process that returned one (`IMPLEMENTATION.md` § 10).
///
/// The whole of the `128+n` convention rests on telling those two apart, and it is
/// the client that applies it: a shell killed by `SIGKILL` has to reach the user as
/// 137 rather than as a program that chose to exit 9, and the only thing carrying
/// that distinction across the wire is this one byte. `pty::exit_parts` produces it
/// from `ExitStatus::code()` returning `None`, which nothing end to end had ever
/// made happen — every other exit in the suite is an ordinary one, so the
/// `Signalled` arm was reachable only from the codec tests, where it is a value in a
/// round trip rather than a fate the daemon observed.
///
/// A test of its own rather than a second case on
/// [`the_exit_status_arrives_after_the_final_output`], which is about *ordering* and
/// buys that with a shape this does not want: it waits for the child to be gone and
/// then reattaches inside the linger window, so what it asserts is the replay. A
/// second case there would assert that a second time and the live path not at all;
/// this one stays attached, so what it pins is the frame the daemon builds on the
/// pass that collects the status.
///
/// `kill -9 $$` rather than a signal from outside, because `$$` is the shell the
/// daemon is watching and `kill` is a builtin of it: no second process to find, and
/// nothing to race. There is no final output to wait through, so the loop tolerates
/// whatever the echo of the command line produces and stops at the fate.
#[test]
fn a_child_killed_by_a_signal_is_reported_as_signalled_rather_than_as_a_status() {
    let (_session, mut client, _) = Session::attached("exit_signalled");

    client.input(0, b"kill -9 $$\n");

    let ended = loop {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode") {
            Frame::Exit { status, kind } => break (status, kind),
            Frame::Output { .. } | Frame::InputAck { .. } | Frame::Pong { .. } => {}
            other => panic!("unexpected {other:?} while waiting for the exit"),
        }
    };

    assert_eq!(
        ended,
        (9, nomux_proto::ExitKind::Signalled),
        "a child killed by SIGKILL must arrive as the signal that killed it, not as \
         a status a process chose"
    );
}

/// Regression: the status is turned into a frame on the pass that collects it, not
/// on whatever pass happens to wake up next.
///
/// `pump_output` is the only place the `Exit` frame is built, and `collect_status`
/// used to run at the top of `event_loop` — one whole iteration earlier.
/// `poll_timeout` clamps the sleep to `STATUS_RETRY` only while the status is still
/// outstanding, so the pass that finally collected one no longer qualified for the
/// clamp, and by then the master had already left the poll set with the child. There
/// was nothing left that could wake the daemon: it slept out the rest of `EXIT_LINGER`
/// and only then built the frame the user was waiting for.
///
/// Driven down the `STATUS_GRACE` path rather than through an ordinary `exit`, which
/// reaches the same bug only when `waitpid` is not ready at PTY end of file — about
/// one exit in three, which is a coin toss rather than a test. A child that closes
/// the terminal *without* exiting reaches it every time: the master reports end of
/// file at once, and `waitpid` has nothing to give up because the process is still
/// there. So the status can only ever come from the two-second synthesis in
/// `collect_status`, and when the frame carrying it arrives is the whole measurement
/// — 2 s where the collecting pass pumps, 5 s where it sleeps first.
///
/// `exec <command>` rather than bare redirections, because redirecting 0, 1 and 2
/// away from the slave does not take the last descriptor onto it: an interactive
/// shell keeps one more for job control — `/dev/tty` on fd 10, under the `dash` this
/// suite pins as `SHELL` — and the master goes on waiting. Replacing the process is
/// what closes that one, since it is close-on-exec, and it leaves `sleep` holding
/// nothing but `/dev/null`.
#[test]
fn a_synthesised_exit_status_is_sent_when_it_is_collected_rather_than_when_the_linger_ends() {
    /// Between `STATUS_GRACE` and `EXIT_LINGER`, and not near either: 1.5 s of slack
    /// for a shell to run one `exec` builtin on a loaded machine, against the 1.5 s
    /// that still separates it from the regression.
    const BOUND: Duration = Duration::from_millis(3500);

    let (_session, mut client, ok) = Session::attached("exit_synthesised");

    // The marker is the last thing the child writes, and the `exec` on its heels is
    // what closes the terminal — so the clock below starts within one shell statement
    // of the end of file the daemon reacts to. The process it leaves behind is alive
    // for far longer than this test runs, which is what leaves `waitpid` with nothing
    // to report and forces the synthesis.
    client.make_ready(
        "-echo",
        Some("exec sleep 300 0</dev/null 1>/dev/null 2>/dev/null"),
        ok.resume_from,
    );
    let began = Instant::now();

    let (elapsed, status, kind) = loop {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode") {
            Frame::Exit { status, kind } => break (began.elapsed(), status, kind),
            Frame::Output { .. } | Frame::InputAck { .. } | Frame::Pong { .. } => {}
            other => panic!("unexpected {other:?} while waiting for the exit"),
        }
    };

    assert_eq!(
        status, 0,
        "a child that closed the terminal without exiting has no status of its own"
    );
    assert_eq!(kind, nomux_proto::ExitKind::Exited);
    assert!(
        elapsed < BOUND,
        "the Exit frame took {elapsed:?}: the status was collected at the two-second \
         grace and then held until the five-second linger window expired, which is a \
         terminal that hangs on every exit `waitpid` is not ready for"
    );
}

/// Regression: the session's own child is collected as soon as `waitpid` will give
/// it up, whether or not the terminal has been let go of.
///
/// A shell that exits behind a job still holding the slave — `sleep 300 &` and then
/// `exit`, which is what a `nohup ... &` leaves — never brings the master to end of
/// file, so nothing stamps `child_gone` and a collection gated on it never runs.
/// Nothing else reaps: `Pty::try_wait` has no other caller until `terminate`. The
/// shell was therefore left a zombie for the whole life of the session, which is up
/// to the seven-day idle timeout.
///
/// Collecting is not reporting, and the two are asserted together: `next_of` refuses
/// anything but the session's own chatter, so an `Exit` frame arriving here would
/// fail this test. It must not, because the transcript is plainly not finished —
/// the job that outlived the shell still has the terminal.
///
/// The reap happens on an event-loop pass, and with the client idle there are none:
/// nothing wakes a daemon whose child exits behind a held slave, `SIGCHLD` being at
/// its default disposition and so discarded. The `Ping` is what supplies one, on a
/// condition rather than a sleep — the `Pong` answering it is queued by the same
/// pass that collects.
#[test]
fn a_shell_that_exits_behind_a_background_job_is_still_reaped() {
    let (session, mut client, ok) = Session::attached("zombie_shell");
    let shell = shell_of(&session);
    let ready = client.make_ready("-echo", None, ok.resume_from);

    // The job outlives the shell and keeps the slave open, so the master never
    // reports end of file and the daemon is never told the child has gone.
    client.input(ready.in_offset, b"sleep 300 & exit\n");
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(shell)),
        "the shell never exited"
    );

    client.send(&Frame::Ping { nonce: 0x2031 });
    drop(client.next_of(FrameType::Pong));

    assert_ne!(
        process_state(shell),
        Some('Z'),
        "the shell exited behind a job that still holds the slave and was left a \
         zombie as pid {shell}"
    );

    // The job still has the terminal, and `Session` drops its daemon with `SIGKILL`,
    // which runs none of § 6.5's collection — so the `sleep` would outlive this test
    // by five minutes. Asking the daemon to stop is what collects it.
    let raw = session.child.id();
    let daemon = rustix::process::Pid::from_raw(raw.cast_signed()).expect("the daemon's own pid");
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(raw)),
        "the signalled daemon never exited, so the job it was collecting is still \
         running"
    );
}

/// The child must not inherit a handle to its own PTY master.
///
/// Everything the user runs in the session would otherwise hold a writable
/// descriptor onto the master: anything that walks `/proc/self/fd`, or writes to a
/// descriptor it did not open, could inject output into the stream or read the
/// user's keystrokes.
#[test]
fn the_child_inherits_only_its_stdio() {
    let (session, mut client, ok) = Session::attached("fds");
    // Wait for the shell to be up before looking for it.
    client.input(0, b"echo NOMUX-SPAWNED\n");
    client.read_until("NOMUX-SPAWNED", ok.resume_from);

    let shell = shell_of(&session);
    let mut terminals = Vec::new();
    for entry in fs::read_dir(format!("/proc/{shell}/fd")).expect("read the shell's fds") {
        let entry = entry.expect("fd entry");
        let target = fs::read_link(entry.path()).unwrap_or_default();
        let target = target.to_string_lossy().into_owned();
        assert!(
            !target.contains("ptmx"),
            "the child inherited the PTY master as fd {:?}",
            entry.file_name()
        );
        if target.starts_with("/dev/pts/") {
            terminals.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    terminals.sort();
    assert_eq!(
        terminals,
        ["0", "1", "2"],
        "the child should hold the slave exactly three times, as its stdio"
    );
}

/// The pid of the shell `session` is running.
///
/// Waited for rather than looked up once: a session is up when its daemon answers,
/// which is one fork before the shell exists, so a single walk of `/proc` is a race
/// every caller here would lose occasionally and blame on something else.
fn shell_of(session: &Session) -> u32 {
    let daemon = session.child.id();
    let mut shell = None;
    assert!(
        poll_until(Duration::from_secs(10), || {
            shell = child_of(daemon);
            shell.is_some()
        }),
        "the daemon never started a shell"
    );
    shell.expect("the shell the wait above returned for")
}

/// The pid of `parent`'s first child, from `/proc`.
fn child_of(parent: u32) -> Option<u32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let parent_of_pid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.trim().parse::<u32>().ok());
        if parent_of_pid == Some(parent) {
            return Some(pid);
        }
    }
    None
}

/// A guard that collects the daemon `id` published a pidfile for, however this test
/// ends.
///
/// For the two tests here that bring a session up through `nomux attach` rather than
/// through [`Session`], which kills its own child on drop. The daemon such an attach
/// spawns has `setsid`ed away, so killing the relay does not reach it and no
/// [`Spawned`] covers it: it is collected by an explicit `nomux kill` further down,
/// and a panic before that line skips it. What is left behind then holds its run
/// directory for the whole 30-second first-attach timeout, and the *next* run's
/// `sweep_finished_runs` deletes that directory out from under it — the pid in its
/// name having gone with this process. `spawn_lock.rs` documents the same hazard at
/// the one place it meets it; these are the other two.
fn daemon_reaper(root: &Path, id: &str) -> Reaper {
    let pid_file = root.join("nomux").join(format!("{id}.pid"));
    wait_for(&pid_file);
    Reaper(
        fs::read_to_string(&pid_file)
            .expect("read the pidfile")
            .trim()
            .parse()
            .expect("the pidfile holds a pid"),
    )
}

/// Ids are opaque per-tab identifiers, so the label is the only thing that makes a
/// session recognisable to a human after the client loses its state.
#[test]
fn a_label_survives_into_list() {
    let root = run_root("label");
    let attach = Spawned::spawn(
        nomux_with_shell(
            &root,
            &["attach", "labelled", "--label", "  release build\tx  "],
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    );
    // The label, not the socket. The daemon publishes in the order bind, pidfile,
    // label (§ 6.2), and the assertion below reads the last two — so waiting on the
    // first would let `list` run against a session that is answering and has not
    // said what it is called, which prints `labelled\t?\t` and fails on the label.
    wait_for(&root.join("nomux").join("labelled.label"));
    // And the pidfile is already there, being one step earlier in that same order.
    let _reaper = daemon_reaper(&root, "labelled");

    let listed = stdout(&control(&root, &["list"]));

    // Both collected before the assertions below, so a failure about the label does
    // not also leave a session behind.
    drop(attach);
    drop(control(&root, &["kill", "labelled"]));

    let line = listed
        .lines()
        .find(|line| line.starts_with("labelled\t"))
        .unwrap_or_else(|| panic!("session missing from list: {listed:?}"));
    let label = line.split('\t').nth(2).expect("label column");
    assert_eq!(
        label, "release buildx",
        "label should be trimmed and stripped of control characters"
    );
}

#[test]
fn invalid_session_ids_are_refused() {
    // A run directory of its own even though nothing should ever be created in it:
    // the refusal is what is under test, and a regression that got as far as the
    // filesystem would otherwise leave its mess where every other test lives.
    let root = run_root("bad_ids");
    for id in ["../escape", "with/slash", "with space"] {
        let output = control(&root, &["attach", id]);
        // The exit status, not merely a non-zero one: § 10 gives a malformed
        // invocation `EX_USAGE`, and the distinction is the whole behaviour. A client
        // caches "unattachable" per host on 126, so an id that could never have named
        // a session must not come back wearing that number.
        assert_eq!(
            output.status.code(),
            Some(64),
            "id {id:?} should be refused as EX_USAGE, got {:?}",
            output.status
        );
        assert!(
            stderr(&output).contains("invalid session id"),
            "id {id:?} should be rejected by name"
        );
    }
}

/// A run directory that is a symlink is refused, out loud, by both modes that
/// create one.
///
/// The unit tests in `rundir` cover the decision; this covers the consequence,
/// which is the half a user sees. Everything else in this daemon degrades rather
/// than aborts, so a session that must not start has to say so with a message and
/// an exit status rather than by quietly doing something else — and what it must
/// not do is what the code before it did, which was to `chmod` whatever the link
/// points at and bind a session's sockets inside it.
#[test]
fn a_symlinked_run_directory_is_refused_by_attach_and_daemon() {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root("symdir");
    let target = root.join("elsewhere");
    fs::create_dir_all(&target).expect("create the directory the link points at");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).expect("loosen the target");
    std::os::unix::fs::symlink(&target, root.join("nomux")).expect("plant the symlink");

    // The exit code each mode owes § 10 for this refusal. `attach` reports 126 — the
    // shell's "found but not executable", applied to a session — and `DESIGN.md` § 7
    // has the client cache a host as unattachable on exactly that number, so a
    // refusal answered with 127 instead would have it retry a host that will never
    // work and one answered with 1 would have it give up on none. `daemon` is on the
    // other table, where everything that is not a malformed command line is 1.
    let refusals: Vec<(&str, i32, Option<i32>, String)> = [("attach", 126), ("daemon", 1)]
        .into_iter()
        .map(|(mode, owed)| {
            // Waited out rather than backgrounded, which is safe only because both
            // modes are refused before they serve: were that refusal ever to
            // regress, this would hang rather than fail. `SHELL` is here for the
            // same reason — a regression that got past the refusal starts one.
            let output = collect(
                nomux_with_shell(&root, &[mode, "symdir"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
            );
            (mode, owed, output.status.code(), stderr(&output))
        })
        .collect();

    // Before the assertions, because the thing being asserted is that no session was
    // started — and a failure here means one *was*, in nobody's process group, with a
    // seven-day idle limit rather than the thirty seconds of a session no client ever
    // reached. Nothing else in this test would collect it.
    drop(control(&root, &["kill", "symdir"]));

    for (mode, owed, code, stderr) in &refusals {
        assert_eq!(
            *code,
            Some(*owed),
            "{mode} must refuse a symlinked run directory with {owed}, got {code:?}: \
             {stderr:?}"
        );
        assert!(
            stderr.contains("run directory") && stderr.contains("symlink"),
            "{mode} must say what it refused and why, got {stderr:?}"
        );
    }

    assert_eq!(
        fs::symlink_metadata(&target)
            .expect("stat the target")
            .permissions()
            .mode()
            & 0o7777,
        0o777,
        "the mode of a directory nomux does not own is not nomux's to change"
    );
    assert!(
        fs::read_dir(&target)
            .expect("read the target")
            .next()
            .is_none(),
        "nothing may be created through the link"
    );
}

/// A daemon that cannot publish `<id>.pid` refuses to start rather than serving a
/// session nothing can find.
///
/// The pidfile is what `nomux kill` reads to know what to signal (§ 6.6), so a
/// daemon that carried on without one would hold the user's shell behind a socket
/// `list` reports as live and `kill` cannot stop — the worst of the states § 6.6
/// exists to make impossible. Nothing exercised that `?`: every other way of
/// refusing to start is on the *bind*, which happens first, so the whole window
/// between binding a socket and publishing the pid was untested.
///
/// What it leaves behind is asserted too, because that is the half a refusal cannot
/// tidy up itself: the socket is already bound when the failure happens, and it is
/// the one file whose presence is how everything else decides a session exists. A
/// `connect` to it is refused, which § 6.6 defines as stale, so the next `list` is
/// what collects it — and does not report a session in the meantime.
#[test]
fn a_daemon_that_cannot_publish_its_pidfile_refuses_to_start() {
    let root = run_root("nopid");
    let run_dir = root.join("nomux");
    fs::create_dir_all(run_dir.join("nopid.pid"))
        .expect("plant a directory where the pidfile goes");

    // Waited out rather than backgrounded, which is safe only because the refusal is
    // what this asserts: a regression that got past it would hang here rather than
    // fail, and `SHELL` is set so that what it started would at least be predictable.
    let refused = collect(
        nomux_with_shell(&root, &["daemon", "nopid"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a daemon that cannot publish its pidfile must refuse to start (§ 10): {:?}",
        stderr(&refused)
    );
    // Only that it said something, which is all it says. `write_pid` propagates the
    // bare `io::Error` from `fs::write`, so the line the user gets is `nomux: Is a
    // directory (os error 21)` with no path in it — every other refusal on this path
    // names what it refused, and this one is worth an errno with a filename beside
    // it. Left as a note rather than asserted, because tightening it is a change to
    // the daemon rather than to its tests.
    assert!(
        !stderr(&refused).is_empty(),
        "a daemon that refuses to start must say why"
    );

    let listed = control(&root, &["list"]);
    succeeded(
        &listed,
        "list over the wreckage of a daemon that never started",
    );
    assert!(
        !stdout(&listed).contains("nopid"),
        "a session that never started must not be listed as one: {:?}",
        stdout(&listed)
    );
    assert!(
        !run_dir.join("nopid.sock").exists(),
        "the socket the refusal left bound is stale by § 6.6's own test — a refused \
         connect — so `list` must have collected it"
    );
}

/// The other half of `attach`'s exit table: a session that is not there and could
/// not be started is 127, the shell's "not found" (`IMPLEMENTATION.md` § 10).
///
/// The pair matters more than either number. `DESIGN.md` § 7 has the client cache a
/// host as *unattachable* on 126 and go on trying on 127, so the two are read as
/// "stop" and "try again" — and until this test and the one above them, nothing in
/// the suite would have noticed them swapped, collapsed into 1, or both answered
/// with whichever branch `run_session_mode` reached first.
///
/// A directory where the socket goes is a daemon that cannot start rather than one
/// that is slow: `connect` to a non-socket is refused, which `attach` reads as
/// absent and answers by spawning, and the daemon's own `bind_socket` then finds
/// something at the path it cannot remove. So the timeout below is reached with the
/// daemon's complaint in hand rather than by waiting out a race.
#[test]
fn attach_reports_a_session_it_could_not_start_as_no_such_session() {
    let root = run_root("attach_nostart");
    fs::create_dir_all(root.join("nomux").join("nostart.sock"))
        .expect("plant a directory where the session socket goes");

    let refused = collect(
        nomux_with_shell(&root, &["attach", "nostart"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(
        refused.status.code(),
        Some(127),
        "a session that does not exist and could not be started must be reported \
         the way a shell reports a missing command: {:?}",
        stderr(&refused)
    );
    assert!(
        stdout(&refused).is_empty(),
        "stdout is where § 5.1 has the client read the bootstrap line, so a failing \
         attach must leave it alone: {:?}",
        stdout(&refused)
    );
}

/// Exercises the path a real bootstrap takes: `nomux attach` with no daemon
/// running, which must spawn one under the flock and then carry the conversation.
///
/// Named for what it asserts. It used to say "relays transparently", and what it
/// looks for is a substring in a byte stream — which says the frames got through in
/// *some* form and nothing about transparency. That property has tests of its own
/// and they are byte-exact over both the `splice` and the copying paths of § 7;
/// this one is about the spawn, and the round trip through the child is how it
/// establishes that the daemon it started is really serving.
#[test]
fn attach_spawns_a_daemon_for_a_session_that_does_not_exist_yet() {
    use std::sync::mpsc;

    let root = run_root("relay");
    let mut child = Spawned::spawn(
        nomux_with_shell(&root, &["attach", "relay_probe"])
            .env("NOMUX_RING_BYTES", "65536")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );

    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    // ChildStdout has no read timeout, so pump it on a thread and let the test
    // bound its own patience.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let pump = thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk) {
                // The rule PLAN § P2 records, one layer out: a signal ending this
                // read would close the channel and fail the test for something that
                // happened to the process rather than to the relay.
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(chunk[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    write_frame(&mut stdin, &hello_frame(0, RESUME_FROM_START));
    write_frame(
        &mut stdin,
        &Frame::Input {
            offset: 0,
            data: b"echo NOMUX-RELAY\n",
        },
    );
    stdin.flush().expect("flush");

    // The relay connected before it wrote anything, and `attach` connects only to a
    // socket a daemon is already answering on — which § 6.2 puts one step before the
    // pidfile — so this wait is over before it starts unless no daemon was spawned at
    // all. That case is the one the assertion at the foot of this test is about, and
    // it is reported here instead: a leak is not possible where there is nothing to
    // leak, and "the daemon never created relay_probe.pid" says the same thing.
    let _reaper = daemon_reaper(&root, "relay_probe");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    let found = loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break false;
        };
        match rx.recv_timeout(remaining) {
            Ok(bytes) => seen.extend_from_slice(&bytes),
            Err(_) => break false,
        }
        // The relay is a byte pipe, so the marker appears verbatim inside the
        // Output frames without needing to parse them here.
        if String::from_utf8_lossy(&seen).contains("NOMUX-RELAY") {
            break true;
        }
    };

    drop(stdin);
    drop(child);
    drop(pump.join());

    drop(control(&root, &["kill", "relay_probe"]));

    assert!(
        found,
        "attach did not spawn a daemon and relay its output; saw {:?}",
        String::from_utf8_lossy(&seen)
    );
}

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

    // Three seconds of refusal, which is long enough that a daemon merely busy with
    // the megabytes it already took would have come back for more.
    let sent = push_until_refused(&mut blaster, &frames, Duration::from_secs(3));
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
    /// Linear growth over this many would be several megabytes; a ceiling is a
    /// ceiling after the first.
    const ROUNDS: usize = 8;

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
        // approached — which is what makes the first round a fair baseline. Eight
        // rounds of the three seconds the test above spends would be a minute of
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

/// A child that exits while the daemon is still holding input it never read must not
/// take its own last words with it.
///
/// Guards the consequence rather than one line of the cause. `write_pty` used to
/// answer an `EIO` from the master by recording the exit, and recording the exit is
/// what takes the master out of the poll set, since `Daemon::watches` keeps it only
/// while `child_gone` is `None`. From that moment the master is never read again, so
/// everything the child wrote on its way out past the one read of that same pass was
/// dropped with no `Gap` to say so, which is the one thing § 9 forbids outright. The
/// exit belongs to `read_pty`, which reaches `Read::Eof` only once the master is dry.
///
/// That `EIO` cannot be provoked on Linux, and this test does not pretend otherwise:
/// writing to a master whose slave has closed *succeeds* here — measured directly,
/// and measured again for a slave that was a session leader's controlling terminal,
/// which is the shape this daemon makes. A master reports the departure on its read
/// side only, as the `EIO` `pty::read_pty` turns into end of file, and its write side
/// answers a slave that is gone exactly as it answers one that is merely full, with
/// `EAGAIN`. So the arm that was changed is unreachable from outside the process, and
/// no end-to-end test can fail on it; showing it fails needs the fault injection § 9
/// already keeps for the takeover ordering, which is a change to the daemon rather
/// than to this file.
///
/// What is left is worth having on its own account, because it is the invariant the
/// removed line broke rather than the line: the state where an early exit would cost
/// output, composed exactly rather than hoped for, and asserted byte for byte. It
/// fails on a daemon that stamps the exit while the master still holds anything —
/// confirmed by doing so at the very moment the old code would have, which lost 4 KiB
/// of the 10 below.
///
/// Composing that state is what the rest of this is. The master has to be holding
/// output nobody has read, and a daemon keeps up with a child effortlessly: writing
/// megabytes at it builds no backlog at all, since the terminal ends up empty at the
/// exit and `read_pty` reaches end of file with nothing outstanding. `pending_input`
/// has to be non-empty, since the daemon asks for `POLLOUT` only while something is
/// queued. And the master has to still be *writable*, which rules out the queue
/// [`input_the_child_never_reads_is_back_pressured_rather_than_buffered`] builds:
/// input that reached the cap got there by filling the terminal, and a full terminal
/// never reports `POLLOUT` again.
///
/// So the daemon is stopped while all three are arranged around it. That is not a
/// stand-in for a wait — it is the only way to hold a single-threaded event loop still
/// long enough to compose a state it would otherwise pass through in microseconds, and
/// every step is then a condition rather than a hope: the child has burst and exited
/// (`/proc` says so), the whole burst is in the terminal's buffer (it fits, so the
/// child never blocked on a daemon that was not running), and the keystroke is in the
/// socket waiting to be read.
#[test]
fn a_child_that_exits_with_input_still_queued_delivers_its_last_output_in_full() {
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::Mode;

    /// Bounded on both sides by the line discipline rather than by this daemon, and
    /// sitting between the two: a read of the master is handed 4095 bytes however
    /// large a buffer it offers, and a single write into an empty terminal is taken up
    /// to 11776 before the writer has to wait for a reader. So the burst is more than
    /// the couple of reads a daemon gets in before it could notice the exit — without
    /// which there would be nothing left to lose — and less than what the child can
    /// hand over in one go without ever waiting on a daemon that is not running, which
    /// it would otherwise do for ever, never reaching the exit this is about.
    const BURST: usize = 10 * 1024;
    /// Room for the burst several times over. A `Gap` here would be the ring being
    /// tight rather than the master leaving the poll set, and the assertions below
    /// have to be able to tell those apart.
    const RING: usize = 4 << 20;

    let session = Session::start_with_ring("last_words", RING);

    // Written where the child can reach it — the shell starts in this directory — and
    // compared byte for byte at the far end, so a burst that arrives short, doubled or
    // out of order fails on the byte rather than on the total.
    let burst = Rng::new(0x1a57_0207).bytes(BURST);
    fs::write(session.root.join("burst"), &burst).expect("write what the child will emit");
    let cue = session.root.join("cue");
    rustix::fs::mkfifoat(rustix::fs::CWD, &cue, Mode::RUSR | Mode::WUSR)
        .expect("create the FIFO the child waits on");

    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // `-echo` so the keystroke below is not echoed into the stream being compared, and
    // `raw` so the line discipline neither mangles it nor throws it away — which is
    // what makes it reach `pending_input` rather than the floor. Past the marker the
    // child never reads its terminal again: the whole line is parsed before any of it
    // runs, the cue comes from the FIFO, and `cat` has a file.
    let ready = client.make_ready(
        "raw -echo",
        Some("read cue < cue; cat burst; exit 9"),
        ok.resume_from,
    );
    let shell = shell_of(&session);

    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    rustix::process::kill_process(daemon, rustix::process::Signal::STOP).expect("stop the daemon");
    assert!(
        poll_until(Duration::from_secs(10), || process_state(
            session.child.id()
        ) == Some('T')),
        "the daemon never stopped, so what follows is a race rather than a setup"
    );

    // Opened without blocking, so a child that never reached its own `open` fails this
    // rather than parking it: a FIFO answers `ENXIO` until a reader is there, and the
    // child counts as one from the moment it enters the wait.
    let mut go = None;
    assert!(
        poll_until(Duration::from_secs(10), || {
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

    // The whole burst is in the terminal's buffer by the time this comes back, and
    // nothing but the master's read side can ever produce it again. A child that has
    // exited but not been collected is a zombie, which is one of the two states this
    // reads as gone — the daemon that would reap it is stopped.
    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(shell)),
        "the child never finished its burst and left"
    );

    // A keystroke the child is never going to read, waiting in the socket for a daemon
    // that has not run since the terminal it belongs to lost its far end.
    client.input(ready.in_offset, b"x");

    rustix::process::kill_process(daemon, rustix::process::Signal::CONT)
        .expect("let the daemon go");

    let mut seen: Vec<u8> = Vec::new();
    let mut offset = ready.offset;
    let ended = loop {
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode frame") {
            Frame::Output { offset: at, data } => {
                assert_eq!(
                    at,
                    offset,
                    "the child's last output must arrive unbroken: this frame opens {} \
                     bytes from where the stream stood",
                    at.abs_diff(offset)
                );
                offset += data.len() as u64;
                seen.extend_from_slice(data);
            }
            Frame::Exit { status, kind } => break (status, kind),
            Frame::InputAck { .. } | Frame::Pong { .. } => {}
            other => panic!("unexpected {other:?} while collecting the child's last output"),
        }
    };

    assert_eq!(
        ended,
        (9, nomux_proto::ExitKind::Exited),
        "the child's own status must survive the exit its queued input interrupted"
    );
    assert!(
        seen.len() >= BURST,
        "only {} bytes arrived before the Exit, out of the {BURST} the child wrote on \
         its way out",
        seen.len()
    );
    assert_eq!(
        &seen[seen.len() - BURST..],
        &burst[..],
        "the child's last {BURST} bytes are not what it wrote"
    );
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

/// The daemon must not hold the directory it was started in — that pins a mount
/// for the life of the session — while the shell must still start where sshd
/// would have started it.
#[test]
fn the_daemon_releases_its_working_directory_but_the_shell_does_not() {
    let (session, mut client, ok) = Session::attached("cwd");

    let cwd = fs::read_link(format!("/proc/{}/cwd", session.child.id())).expect("read daemon cwd");
    assert_eq!(
        cwd,
        Path::new("/"),
        "daemon still holds a working directory"
    );

    client.input(0, b"pwd\n");
    let home = session.root.to_str().expect("utf-8 root");
    client.read_until(home, ok.resume_from);
}

/// The `daemon` mode detaches itself, rather than trusting whoever started it.
///
/// § 6.2 claims the property for the mode, but `setsid` and the `/dev/null` stdio
/// lived in `attach::spawn_daemon` alone — so a daemon started any other way kept
/// the process group and the descriptors it inherited, which for a session meant
/// dying with the connection that started it. Started here with pipes on purpose,
/// so what those descriptors point at afterwards is the daemon's own doing.
///
/// The pidfile is the other half. The interactive case cannot detach without a
/// fork, and `nomux kill` reads that file, so the pid in it has to be the one that
/// survived rather than the one that started.
#[test]
fn the_daemon_mode_detaches_itself() {
    let root = run_root("detach");
    let child = Spawned::spawn(
        nomux_with_shell(&root, &["daemon", "detached"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let pid = child.id();
    wait_for(&root.join("nomux").join("detached.sock"));

    // The socket is bound before any of the detaching happens — deliberately, so a
    // session that already exists is still reported with an exit status — so
    // waiting for it is not barrier enough.
    // No assertion on the outcome: the reads below are what judge the daemon, and
    // this only keeps them from judging it before it has finished detaching.
    poll_until(Duration::from_secs(10), || has_detached(pid));

    // Everything read before the child is killed, so a failing assertion cannot
    // leave the daemon behind.
    let detachment = detachment_of(pid);
    let recorded = fs::read_to_string(root.join("nomux").join("detached.pid"))
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok());
    drop(child);

    assert_detached(&detachment, Some(pid), "the daemon");
    assert_eq!(
        recorded,
        Some(pid),
        "the pidfile must name the process that is actually serving"
    );
}

/// The other half of § 6.2, which the test above never reaches.
///
/// `Command` never calls `setpgid`, so a daemon it starts is not a process-group
/// leader, `setsid` succeeds outright, and the fork is unreachable from there — which
/// makes `recorded == pid` true by construction rather than by the pidfile being
/// written in the right order. Moving `detach_from_login_session` to after
/// `write_pidfile` leaves that test passing, so it guards nothing. Making the child a
/// group leader first is what forces the `EPERM` only a fork can answer, and it is
/// the shape a shell with job control produces.
///
/// The daemon that survives is in nobody's process group and is nobody's child, so
/// `wait` collects the process that started and nothing else — it has to be reaped
/// through `nomux kill`, before the assertions rather than after them.
#[test]
fn a_daemon_that_leads_a_process_group_detaches_by_forking() {
    let root = run_root("fork");
    let mut command = nomux_with_shell(&root, &["daemon", "grouped"]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure runs in the forked child before exec, so it must be
    // async-signal-safe. `setpgid` is, and nothing here allocates or takes a lock.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut starter = Spawned::spawn(&mut command);
    let original_pid = starter.id();

    let pid_file = root.join("nomux").join("grouped.pid");
    wait_for(&root.join("nomux").join("grouped.sock"));
    wait_for(&pid_file);

    // Bounded rather than a bare `wait`: if the fork never happened then the process
    // started here *is* the daemon, and waiting on it would hang the suite instead of
    // failing an assertion.
    let starter_exited = poll_until(Duration::from_secs(10), || !starter.is_running());

    // `recorded` outlives the wait because the assertions below are about the pid the
    // last look found, whether or not it ever satisfied the condition.
    let mut recorded = None;
    poll_until(Duration::from_secs(10), || {
        recorded = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        recorded.is_some_and(has_detached)
    });

    // Everything read before anything is collected, so a failing assertion cannot
    // leave a session behind.
    let detachment = recorded.map(detachment_of).unwrap_or_default();
    let alive = recorded.is_some_and(process_alive);
    let killed = control(&root, &["kill", "grouped"]);
    drop(starter);

    assert!(
        starter_exited,
        "the process that started never left, so nothing forked"
    );
    // The other half of what the pidfile is for, and the one case where it outranks
    // the socket: `control::daemon_of` takes the pid off the connection, and the
    // process that made this socket is the one that `_exit`ed above. A number the
    // kernel has already reclaimed is not an identity, so `kill` falls back to the
    // file the survivor wrote — without which this session could not be stopped at
    // all, which is the fault the assertion below names from the other side.
    succeeded(
        &killed,
        "kill could not stop a daemon that had to fork to detach",
    );
    assert_ne!(
        recorded,
        Some(original_pid),
        "the pidfile names the process that started, which has since exited — \
         `nomux kill` would signal nobody"
    );
    assert!(
        alive,
        "no live daemon behind the pidfile: it names {recorded:?}"
    );
    assert_detached(&detachment, recorded, "the forked child");
}

/// Whether `pid` has finished detaching itself (§ 6.2): a session of its own, and
/// nothing left of the stdio it was handed.
fn has_detached(pid: u32) -> bool {
    stat_field(pid, StatField::Session) == Some(pid) && stdio_is_silenced(&stdio_targets(pid))
}

/// What `/proc` says about `pid`'s detachment, as the session it leads and the three
/// descriptors it holds.
///
/// Read out and handed back rather than asserted on the spot, because both halves
/// have to be in hand *before* the caller collects the daemon: `/proc` has nothing to
/// say about a process that is gone, and a failing assertion must not be the thing
/// that leaves a session behind.
fn detachment_of(pid: u32) -> (Option<u32>, Vec<PathBuf>) {
    (stat_field(pid, StatField::Session), stdio_targets(pid))
}

/// The two halves of § 6.2, as [`detachment_of`] found them for `whose`.
fn assert_detached(found: &(Option<u32>, Vec<PathBuf>), pid: Option<u32>, whose: &str) {
    let (leads_session, stdio) = found;
    assert_eq!(
        *leads_session, pid,
        "{whose} stayed in the session it was started in, so a hangup reaches it"
    );
    assert!(
        stdio_is_silenced(stdio),
        "{whose} still holds the descriptors it was handed: {stdio:?}"
    );
}

/// What the three standard descriptors of `pid` point at.
fn stdio_targets(pid: u32) -> Vec<PathBuf> {
    (0..3)
        .map(|fd| fs::read_link(format!("/proc/{pid}/fd/{fd}")).unwrap_or_default())
        .collect()
}

/// Whether all three point at `/dev/null`, which is where detaching puts them.
///
/// Takes what was read rather than a pid, so an assertion can report the targets it
/// judged: they have to be collected before the daemon is, and `/proc` has nothing
/// to say about it afterwards.
fn stdio_is_silenced(targets: &[PathBuf]) -> bool {
    targets.iter().all(|path| path == Path::new("/dev/null"))
}

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

    client.input(0, b"echo \"sock=[$SSH_AUTH_SOCK]\"\n");
    let (seen, _) = client.read_until("sock=[", ok.resume_from);
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

    let cap = MAX_AGENT_CHANNELS as usize;
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
    let ready = client.make_ready("-echo", None, ok.resume_from);

    // How much a unix socket on this host takes from a peer that has stopped
    // reading, measured rather than assumed for the reason
    // `a_closed_agent_channel_whose_peer_stopped_reading_leaves_the_daemon_asleep`
    // gives: the limit is a sysctl away from any number written here.
    let capacity = {
        let (mut probe, _other_end) = UnixStream::pair().expect("a socketpair to measure");
        probe.set_nonblocking(true).expect("stop blocking");
        push_until_refused(&mut probe, &vec![0u8; 8 << 20], Duration::from_millis(100))
    };

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
    client.input(ready.in_offset, b"echo NOMUX-STILL-SERVING\n");
    client.read_until("NOMUX-STILL-SERVING", ready.offset);
}

/// Ids come from a counter that never rewinds, so a channel closing and another
/// opening cannot be confused for one another.
#[test]
fn agent_channel_ids_are_never_reused() {
    let (session, mut client, _) = Session::attached_with("agent_ids", HELLO_AGENT_FORWARD);

    let mut previous = 0;
    for round in 0..4 {
        let agent = session.connect_agent();
        let chan = client.next_chan(FrameType::AgentOpen);
        assert!(chan > previous, "round {round}: id {chan} did not advance");
        previous = chan;
        drop(agent);
        assert_eq!(client.next_chan(FrameType::AgentClose), chan);
    }
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
/// The window is a wall-clock interval rather than a wait for a condition, since it
/// *is* the measurement. Everything it needs to be true was established before it
/// started: the queue is provably non-empty, the close has provably been acted on,
/// and the drain afterwards proves the channel was still there to be spun on.
#[test]
fn a_closed_agent_channel_whose_peer_stopped_reading_leaves_the_daemon_asleep() {
    /// One `AgentData` frame per round, and small beside `MAX_CHANNEL_QUEUE`: the
    /// daemon closes a channel whose queue outgrows that, which would take away the
    /// very state under test.
    const CHUNK: usize = 32 * 1024;
    /// How far past what the socket will hold the client sends. It is what is left
    /// over that the daemon has to keep, and it has to be enough to be certain of —
    /// but comfortably short of `MAX_CHANNEL_QUEUE`, which the daemon would answer by
    /// closing the channel rather than holding it.
    const OVERSHOOT: usize = 96 * 1024;
    /// How long the daemon is watched for. Long enough that the bug would show up as
    /// tens of ticks, short enough to keep the suite where it is.
    const WINDOW: Duration = Duration::from_millis(300);
    /// Five ticks is 50 ms of processor time against 300 ms of wall clock: a sixth of
    /// one core, where the bug is a whole one and the fix is exactly zero.
    const TOLERATED: u32 = 5;

    let (session, mut client, ok) = Session::attached_with("agent_spin", HELLO_AGENT_FORWARD);
    // `-echo` so that everything on the output stream is the child answering rather
    // than the line discipline repeating the question, which is what lets the two
    // markers below be read one after the other from a stream that joins up.
    let ready = client.make_ready("-echo", None, ok.resume_from);

    // How much a unix socket on this host takes from a peer that has stopped reading.
    // Measured rather than assumed: the limit is the *sender's* send buffer, which is
    // a sysctl away from any number written down here, and everything below turns on
    // sending more than it. Asking a socketpair is asking the same kernel the same
    // question — nothing about the pair the daemon accepts is different.
    let capacity = {
        let (mut probe, _other_end) = UnixStream::pair().expect("a socketpair to measure");
        probe.set_nonblocking(true).expect("stop blocking");
        push_until_refused(&mut probe, &vec![0u8; 8 << 20], Duration::from_millis(100))
    };

    let mut agent = session.connect_agent();
    let chan = client.next_chan(FrameType::AgentOpen);

    // Bytes the test's end of the channel is deliberately never going to read. Past
    // `capacity` the kernel stops taking them and the rest stays in the daemon's own
    // queue, which is what the close below has to find for the channel to outlive it.
    //
    // A frame at a time, each fenced by a round trip the daemon can only answer by
    // having read it. The daemon queues everything it decodes in one pass and writes
    // it out on the pass after, so handing it the lot at once would take the queue
    // past `MAX_CHANNEL_QUEUE` and have the channel closed for that instead — which
    // looks nothing like the state this is about and would still leave the daemon
    // asleep.
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

    // Nothing answers an `AgentClose` — the client closed the channel and has already
    // forgotten it — so the round trip through the child behind it is what says the
    // daemon has acted on it, frames being handled in the order they arrive. It is
    // also the first half of the session still working.
    client.send(&Frame::AgentClose { chan });
    let before = b"echo NOMUX-CLOSE-ACTED-ON\n";
    client.input(ready.in_offset, before);
    let (_, offset) = client.read_until("NOMUX-CLOSE-ACTED-ON", ready.offset);

    let daemon = session.child.id();
    let began = cpu_ticks(daemon);
    thread::sleep(WINDOW);
    let burned = cpu_ticks(daemon).saturating_sub(began);
    assert!(
        burned <= TOLERATED,
        "the daemon burned {burned} clock ticks in {WINDOW:?} holding one closed \
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

    client.input(
        ready.in_offset + before.len() as u64,
        b"echo NOMUX-STILL-SERVING\n",
    );
    client.read_until("NOMUX-STILL-SERVING", offset);
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

/// What the child prints when the terminal it is on changes size. See
/// [`repaint_transcript`].
///
/// Built out of `$((6*7))` for the reason `Client::make_ready` gives: the line
/// discipline echoes the command line that installs the trap before `stty -echo`
/// takes effect, and that echo carries the arithmetic unexpanded — so the marker
/// cannot be satisfied by the request for it. `dash` evaluates a trap's body when
/// the signal arrives, which is what makes the substitution happen then rather than
/// at definition.
const WINCHED: &str = "NOMUX-42-WINCHED";

/// Drives a session to an overflow gap and returns what the child saw afterwards.
///
/// `cat` is the child because it hands back whatever reaches the PTY's input side,
/// which is the only way to observe a repaint that is delivered as a keystroke. In
/// front of it sits a `SIGWINCH` trap, which is the only way to observe the other
/// policy at all: the default repaint writes nothing to the terminal, so a test
/// that can only see the PTY's input side reads it as "nothing happened" — which is
/// also what a daemon whose default branch does nothing produces. The ring is tiny
/// so a few kilobytes echoed while detached is enough to overflow it.
///
/// Two things about the trap are `dash`'s doing rather than the daemon's, and both
/// were measured against a bare PTY before being written down here. `set +m`,
/// because with job control on the shell puts `cat` in a foreground process group
/// of its own and `TIOCSWINSZ` signals *that* group — so the shell holding the trap
/// never hears about it. And the trap sits in a background subshell parked on
/// `wait` rather than in the shell itself, because `dash` defers a trap until the
/// foreground job finishes: with `cat` in front of it the marker arrives when the
/// session ends, which is far too late, and the first version of this printed
/// nothing at all. `wait` is the one thing POSIX requires a trapped signal to
/// interrupt, which is what makes the marker prompt.
///
/// The filler is drained *before* the client leaves, which is what makes the
/// `SIGWINCH` half observable at all. The repaint fires the instant the daemon
/// answers the reconnecting `Hello`, and the marker the child prints then has to
/// survive a one-kilobyte ring: with tens of kilobytes of echo still in flight it
/// does not, and the first version of this test failed with a transcript of nothing
/// but filler. Reading to a marker of its own leaves the child idle and the ring
/// holding only what comes after — and it also turns the reconnect below into
/// arithmetic rather than a wait, since `base` is already tens of kilobytes above
/// where this client resumes from.
fn repaint_transcript(name: &str, flags: u16) -> String {
    /// The child echoes far more than this, so what the client comes back to is a
    /// gap by construction.
    const RING: usize = 1024;
    /// The last line of the filler, and how the client learns the child has caught
    /// up: `cat` echoes it, so seeing it means everything before it is behind us.
    const DRAINED: &str = "NOMUX-FILLER-DRAINED";

    let session = Session::start_with_ring(name, RING);
    let mut client = session.connect();
    let ok = client.hello_with(flags, RESUME_FROM_START);

    // The sleep is short so that a subshell which somehow outlived its session is
    // asleep rather than looping, and gone within seconds either way. It does not
    // normally have to be: everything here shares the shell's process group, so
    // closing the PTY master hangs the lot up.
    let ready = client.make_ready(
        "-echo -onlcr",
        Some(
            "set +m; (trap 'printf NOMUX-$((6*7))-WINCHED' WINCH; \
             while :; do sleep 5 & wait; done) & cat",
        ),
        ok.resume_from,
    );
    let offset = ready.offset;

    // Echoed back by `cat`, which is what overflows the ring. In lines, because the
    // line discipline is still canonical: `cat` would see nothing at all until a
    // newline arrived, and the overflow would never happen.
    let filler = format!("{}{DRAINED}\n", format!("{}\n", "x".repeat(63)).repeat(512));
    let filler = filler.as_bytes();
    let mut in_offset = ready.in_offset;
    client.input(in_offset, filler);
    in_offset += filler.len() as u64;
    // Past gaps, since overflowing the ring is the point; what this waits for is the
    // newest bytes on the stream, which are the ones a ring never discards.
    client.read_past_gaps(DRAINED, offset);
    drop(client);

    // A gap by arithmetic rather than by timing: the ring holds a kilobyte and the
    // child has just echoed thirty-two, so `base` is far above where this resumes.
    let mut client = session.connect();
    let resumed = client.hello_with(flags, offset);
    assert!(
        resumed.gap,
        "the child echoed {} bytes through a {RING}-byte ring and the daemon \
         reported no gap to a client resuming from {offset}",
        filler.len()
    );

    // § 4.3: "`ctrl_l` goes through the same queue as client input ... It is not
    // client input, so `in_applied` does not move for it." Asserted for both
    // policies because the claim is only interesting for one of them: the daemon
    // has just queued a `0x0c` this client never sent, and counting it would put
    // `in_applied` one byte past what the client believes it has delivered — after
    // which every offset the client sends is a byte low, and the daemon answers the
    // next keystroke with an `Error{InputGap}` for input nobody skipped. The fence
    // below is sent at `in_offset` for the same reason, so a daemon that moved it
    // would fail here rather than in the read that follows.
    assert_eq!(
        resumed.in_applied, in_offset,
        "the repaint moved the session's input position, but only the client's own \
         keystrokes may"
    );

    // A fence bounds the wait: whatever the repaint was going to be has been
    // echoed by the time this comes back.
    client.input(in_offset, b"FENCE\n");
    let (transcript, _) = client.read_past_gaps("FENCE", resumed.resume_from);
    transcript
}

/// The post-gap repaint is the client's choice, and each policy does its own thing
/// and only its own thing (`IMPLEMENTATION.md` § 4.3).
///
/// Both halves are asserted positively as well as negatively, which the default one
/// was not. `assert!(!default.contains('\u{c}'))` is satisfied by a daemon whose
/// `winch` branch does nothing at all — and doing nothing is the shape a regression
/// here would actually take, since the `TIOCSWINSZ` dance is the fiddly half and
/// the one that can be lost to a refactor without any client noticing. A gap with
/// no repaint behind it leaves a full-screen program showing the tail of a stream
/// with a hole in it and no reason to redraw, which is the whole of what § 4.3
/// exists to prevent.
#[test]
fn a_gap_repaints_with_ctrl_l_only_when_the_client_asks() {
    let asked = repaint_transcript("repaint_ctrl_l", HELLO_REPAINT_CTRL_L);
    assert!(
        asked.contains('\u{c}'),
        "no Ctrl-L reached the child: {asked:?}"
    );
    assert!(
        !asked.contains(WINCHED),
        "a client that asked for Ctrl-L was also sent through the winsize dance, so \
         an editor gets both a redraw it did not want and a keystroke: {asked:?}"
    );

    let default = repaint_transcript("repaint_winch", 0);
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

/// A daemon spawned by a connection that died mid-handshake must reap itself — and a
/// session somebody has actually used must not.
///
/// Every reaping rule is only checked when `poll` returns, so this is really a test
/// that a wakeup is armed for the 30-second first-attach deadline rather than only
/// for the hour-long backstop. Waiting out that deadline is the only way to observe
/// it from outside, which is why this is `#[ignore]`d: 30 seconds is unreasonable
/// in a suite that otherwise finishes in two, and CI runs it with
/// `--run-ignored all`.
///
/// Both halves, because `Daemon::detach_limit` is a *choice* — 30 seconds where no
/// PTY was ever started, seven days once one was — and the rule was the untested one
/// of the two. A regression returning `FIRST_ATTACH_TIMEOUT` for both would reap
/// every real user's session half a minute after they shut their laptop, and nothing
/// in the suite would go red: the timeout half would pass, being what the regression
/// does everywhere. The other branch rides along at no cost in wall clock, since the
/// wait is the same wait.
#[test]
#[ignore = "waits out the 30-second first-attach timeout; run in CI, not on every commit"]
fn a_daemon_nobody_ever_attaches_to_reaps_itself() {
    // The seven-day branch is set up first so that under the regression above its
    // thirty seconds are up no later than the other session's. That ordering is not
    // enough on its own, and measuring says so: with the regression applied by hand
    // this session was reaped 107 ms *after* the wait below ended, so an assertion
    // taken at that instant passed over a daemon that was already doomed. Whichever
    // way that hundred milliseconds happens to fall is a matter of process startup
    // against the daemon noticing a closed socket, which is not something to hang a
    // guard on. So the assertion at the end asks for a margin instead.
    let (greeted, client, _) = Session::attached("attached_once");
    // The limit is consulted only while there is nobody attached, so a session still
    // holding its client would satisfy the assertion below by never having been asked
    // the question. The `Hello` that has just been answered is what makes this the
    // seven-day branch: it is what started the PTY.
    drop(client);
    let detached_at = Instant::now();

    let unattached = Session::start("unattached");
    assert!(unattached.socket.exists());

    assert!(
        poll_until(Duration::from_secs(45), || !unattached.socket.exists()),
        "daemon outlived its first-attach timeout"
    );

    // Stated rather than reasoned about: the wait above cannot end before the
    // unattached daemon's own 30 seconds are up, and this session was detached before
    // that daemon existed — so by here it has been clientless for longer than the
    // deadline it must not be holding.
    assert!(
        detached_at.elapsed() > Duration::from_secs(30),
        "the unattached daemon went in {:?}, which is short of the first-attach \
         timeout — so nothing below says anything about the limit this session is on",
        detached_at.elapsed()
    );
    // Asked as "still here three seconds from now" rather than "here at this
    // instant", which is what makes this falsifiable rather than nearly so: the
    // regression reaps this session within a hundred milliseconds either side of the
    // wait above, so only a margin tells a session on the seven-day limit from one
    // on the thirty-second limit that has not got round to it yet. Three seconds is
    // two orders of magnitude above that scatter and still nowhere near a limit
    // anything here holds.
    //
    // Answering, not merely present: the socket file outlives the process that bound
    // it, so a daemon that died without unlinking would leave one behind. A bare
    // `connect` is not an attach (§ 6.4) and costs this session nothing.
    let reaped = poll_until(Duration::from_secs(3), || {
        !greeted.socket.exists() || UnixStream::connect(&greeted.socket).is_err()
    });
    assert!(
        !reaped,
        "a session that was attached to and then detached was reaped on the \
         first-attach deadline, so closing a laptop for half a minute now costs the \
         user their shell"
    );
}

/// A daemon that reaps itself runs its shutdown to completion.
///
/// `Pty::terminate` signals the child's process group, and `kill_process_group`
/// negates the pid itself — so passing an already-negative one both defeated the
/// group kill and, because `Pid::from_raw` asserts its argument is non-negative,
/// aborted the daemon partway through `shutdown` in any debug build. The visible
/// symptom is this one: the run files outlive the session, and `list` then reports
/// a session nobody can attach to until something else garbage-collects it.
#[test]
fn a_daemon_that_reaps_itself_removes_its_run_files() {
    let (session, mut client, _) = Session::attached("shutdown_cleanup");

    let pid_file = session.pid_file();
    assert!(
        pid_file.exists(),
        "the daemon should have written its pidfile"
    );

    // The child exits and the client leaves. The linger window is deliberately *not*
    // collapsed by the departure — it is derived from `child_gone` alone, which
    // `on_detached` never touches, because the client the window exists for is the
    // one that has not arrived yet (§ 6.5) — so what ends the daemon here is the
    // five-second `EXIT_LINGER` measured from that moment expiring, and
    // `shutdown` then unlinks the run files. Hence the generous deadline below.
    client.input(0, b"exit 3\n");
    client.drain_available();
    drop(client);

    assert!(
        poll_until(Duration::from_secs(15), || !pid_file.exists()
            && !session.socket.exists()),
        "run files outlived the daemon: socket={} pid={}",
        session.socket.exists(),
        pid_file.exists()
    );
}

/// `SIGTERM` must leave through the shutdown path, not the default disposition.
///
/// `nomux kill` signals the daemon and gives it two seconds. Without a handler it
/// died where it stood, so `Pty::terminate` never ran — and closing the PTY master
/// hides that for the ordinary case, because the kernel delivers `SIGHUP` to the
/// foreground process group on the way out. What it does not cover is a
/// backgrounded process that ignores the hangup, which is what this starts: `trap
/// '' HUP` before the fork, since an *ignored* disposition is inherited through
/// `exec` where a trapped one is reset.
///
/// `set +m` is what puts that process where reaping can see it. An interactive
/// shell gives every job a process group of its own, and nothing in the session
/// ever signals those — a real gap, but a different one, and one no `SIGTERM`
/// handler would close. With job control off the job stays in the shell's group,
/// which is what `Pty::terminate` signals and what a script's background processes
/// do anyway.
#[test]
fn a_signalled_daemon_collects_a_process_that_ignores_sighup() {
    let (session, mut client, ok) = Session::attached("sigterm");

    // The marker trails the pid so that seeing it proves the digits already
    // arrived, and the arithmetic keeps it out of the line discipline's echo of the
    // command itself — which would otherwise match first, carrying `$!` unexpanded.
    client.input(
        0,
        b"set +m; trap '' HUP; sleep 300 & echo \"$!-NOMUX-ORPHAN-$((6*7))\"\n",
    );
    let (seen, _) = client.read_until("-NOMUX-ORPHAN-42", ok.resume_from);
    let orphan = trailing_pid(&seen, "-NOMUX-ORPHAN-42")
        .unwrap_or_else(|| panic!("no background pid in the transcript: {seen:?}"));
    // Everything below is an assertion about a process that is deliberately in
    // nobody's reach: if one of them fires, `sleep 300` outlives the whole suite.
    let _collected = Reaper(orphan);
    assert!(
        process_alive(orphan),
        "the backgrounded process was gone before the session ended"
    );
    let shell = shell_of(&session);
    assert_eq!(
        stat_field(orphan, StatField::ProcessGroup),
        Some(shell),
        "this shell kept job control on, so nothing here is testing reaping"
    );

    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    let pid_file = session.pid_file();
    // Signalled directly rather than through `nomux kill`, which unlinks the run
    // files itself and would answer the question for the daemon.
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");

    // Inside the two seconds `nomux kill` allows before `SIGKILL`, with room for a
    // loaded machine: an overrun there is this same bug wearing a hat.
    assert!(
        poll_until(Duration::from_secs(10), || !pid_file.exists()
            && !session.socket.exists()),
        "run files outlived the signalled daemon: socket={} pid={}",
        session.socket.exists(),
        pid_file.exists()
    );

    assert!(
        poll_until(Duration::from_secs(10), || !process_alive(orphan)),
        "pid {orphan} outlived the session it was backgrounded in"
    );
}

/// A session with nothing left running is torn down at once, rather than waiting
/// out the grace period that only the stubborn case needs.
///
/// The grace period is 500 ms, and it used to be spent on *every* shutdown. The
/// loop's exit condition asks the process group first and only then walks `/proc`,
/// and an unreaped zombie is still a member of its own group — so the group probe
/// answered "still alive" for the very child the daemon was about to collect, and
/// the `&&` short-circuited before the `/proc` walk, which filters zombies, could
/// disagree. On the path that matters the child *is* unreaped: `reap` runs only
/// once the PTY has reported end of file, which on the `nomux kill` path it has
/// not.
///
/// This used to assert one wall-clock number — under 400 ms — against an honest
/// path that measures about fifty and a regression with a hard floor of five
/// hundred. Defensible in intent and indefensible in mechanism: the bound was
/// wedged between the two with runqueue delay, which nothing here bounds, free to
/// move either. So the comparison is now between two shutdowns rather than between
/// one shutdown and a constant. Both sessions are signalled in the same test within
/// milliseconds of each other, so whatever the machine is doing it is doing to
/// both, and the ratio survives what an absolute bound cannot.
///
/// `quiet < stubborn / 2` is the assertion because the two answers are an order of
/// magnitude apart when the daemon is right and identical when it is wrong: the
/// regression makes *every* shutdown the stubborn one. The stubborn measurement is
/// itself checked against the grace period, so a run where nothing waited for
/// anything fails as an instrument rather than passing as a result.
#[test]
fn a_signalled_daemon_with_a_quiet_child_does_not_wait_out_the_grace_period() {
    /// `pty::HANGUP_GRACE`, which is private to the daemon. Used only to say that
    /// the stubborn measurement really did wait for something.
    const GRACE: Duration = Duration::from_millis(500);

    // Set up together, and signalled together below, so the two measurements meet
    // the same machine.
    let (mut stubborn, mut client, ok) = Session::attached("slowkill");
    // The shape `a_signalled_daemon_collects_a_process_that_ignores_sighup` uses,
    // and for the same reason: an *ignored* `SIGHUP` survives `exec` where a trapped
    // one is reset, so this is a process the daemon's first reach cannot collect and
    // must wait out. `set +m` keeps it in the shell's own group, which is what
    // `Pty::terminate` signals.
    client.input(
        0,
        b"set +m; trap '' HUP; sleep 300 & echo \"$!-NOMUX-ORPHAN-$((6*7))\"\n",
    );
    let (seen, _) = client.read_until("-NOMUX-ORPHAN-42", ok.resume_from);
    let orphan = trailing_pid(&seen, "-NOMUX-ORPHAN-42")
        .unwrap_or_else(|| panic!("no background pid in the transcript: {seen:?}"));
    // Deliberately in nobody's reach until the daemon collects it, so nothing else
    // would clean it up if an assertion below fired first.
    let _collected = Reaper(orphan);

    let (mut quiet, mut settled, ok) = Session::attached("fastkill");
    // So the measurement covers a session with a live shell in it, rather than the
    // window before the child exists at all.
    settled.input(0, b"echo NOMUX-READY\n");
    settled.read_until("NOMUX-READY", ok.resume_from);

    let stubborn = time_shutdown(&mut stubborn);
    let quiet = time_shutdown(&mut quiet);
    let load =
        fs::read_to_string("/proc/loadavg").unwrap_or_else(|err| format!("unreadable: {err}"));

    assert!(
        stubborn >= GRACE,
        "the stubborn session went in {stubborn:?}, inside the {GRACE:?} its \
         un-hangupable child should have cost it — so it is not a grace period this \
         run measured, and the comparison below would mean nothing. Load: {load}"
    );
    assert!(
        quiet < stubborn / 2,
        "a session with nothing left running took {quiet:?} to stop against \
         {stubborn:?} for one with a process that ignores SIGHUP: the two are the \
         same shutdown, so the grace period is being paid whether or not anything \
         is still there. Load: {load}"
    );
}

/// Signals a daemon and reports how long it took to leave.
///
/// Collected here as well as timed, so the harness does not go on to `SIGKILL` a
/// process that has already gone and the caller can compare two of these.
fn time_shutdown(session: &mut Session) -> Duration {
    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    let began = Instant::now();
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");

    let exited = poll_until(Duration::from_secs(10), || {
        session
            .child
            .try_wait()
            .expect("wait for the daemon")
            .is_some()
    });
    // Read before the assertion, since what is being measured is how long the
    // condition took to become true.
    let elapsed = began.elapsed();
    assert!(exited, "the signalled daemon never exited");
    elapsed
}

/// The run of digits immediately before `marker`, as a pid.
fn trailing_pid(transcript: &str, marker: &str) -> Option<u32> {
    let (head, _) = transcript.rsplit_once(marker)?;
    let reversed: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    reversed.chars().rev().collect::<String>().parse().ok()
}

/// A numeric field of `/proc/<pid>/stat`, by what it means.
#[derive(Clone, Copy)]
enum StatField {
    /// The process group the process belongs to.
    ProcessGroup = 2,
    /// The session it belongs to, which is its own pid exactly when it leads one.
    Session = 3,
    /// Clock ticks spent in user mode.
    UserTime = 11,
    /// Clock ticks spent in the kernel on this process's own behalf.
    SystemTime = 12,
}

/// Reads one field of `/proc/<pid>/stat`.
///
/// Counted from the state letter that follows the parenthesised command name,
/// because counting from the front stops working the moment a command name
/// contains a space or a bracket — and `sh` starting `a b )` is enough.
fn stat_field(pid: u32, field: StatField) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, tail) = stat.rsplit_once(')')?;
    tail.split_whitespace().nth(field as usize)?.parse().ok()
}

/// How much processor time `pid` has been charged, in the clock ticks `/proc`
/// counts in.
///
/// User and system together, because the two states this has to tell apart are
/// "asleep in `poll`" and "going round the loop as fast as the scheduler allows",
/// and the second spends its time on both sides of the syscall boundary. A process
/// that has gone reports nothing, which reads here as zero — the same answer the
/// caller's assertion wants, and one no daemon that is still there can produce
/// falsely, since these counters never go down.
fn cpu_ticks(pid: u32) -> u32 {
    [StatField::UserTime, StatField::SystemTime]
        .into_iter()
        .filter_map(|field| stat_field(pid, field))
        .sum()
}

/// The single-letter run state `/proc` reports for `pid`, or `None` once it is gone.
///
/// Read from after the parenthesised command name for the reason [`stat_field`]
/// gives: the name can contain a space or a bracket, and counting from the front
/// stops working the moment it does.
fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, tail) = stat.rsplit_once(')')?;
    tail.trim_start().chars().next()
}

/// Whether `pid` is still a process rather than gone or a zombie awaiting its
/// parent. A collected process group reaches one of the latter two promptly.
fn process_alive(pid: u32) -> bool {
    process_state(pid).is_some_and(|state| state != 'Z')
}

/// Regression: a reconnect racing with in-flight input must not discard it.
///
/// One `poll` can report a readable client and a `Hello` from its replacement
/// together. The daemon originally took over on the *connect* and dropped the
/// outgoing connection there and then — and with it any frame still unread in its
/// socket buffer — so keystrokes vanished whenever a reconnect landed in the same
/// iteration as input the user had already sent.
///
/// Each round sets that interleaving up on purpose rather than hoping for it: the
/// replacement connects and is left un-greeted until the daemon has certainly
/// accepted it, and only then does the outgoing client send input, immediately
/// followed by the `Hello` that evicts it. Both land in one wakeup, and the
/// outgoing connection is not closed until after the assertion — so nothing here
/// depends on how the kernel treats a socket closed with data still queued.
#[test]
fn a_takeover_never_discards_input_already_delivered() {
    let (session, mut client, _) = Session::attached("takeover_input");

    let command = b"true NOMUX-KEEP\n";
    let mut expected = 0u64;

    for round in 0..15 {
        let mut next = session.connect();
        // The accept, asked for rather than waited out. `connect` on a listening unix
        // socket completes in the kernel, so by the line above the connection is
        // already in the backlog and the next `poll` reports the listener; that same
        // pass services the client, then accepts, and only then writes what it queued
        // — so a `Pong` for a ping sent from here cannot have been written by a pass
        // that had not yet accepted. A sleep long enough to be safe was 900 ms across
        // the fifteen rounds and still only ever made the interleaving *likely*, which
        // is precisely what the paragraph above says this test does not do.
        client.send(&Frame::Ping { nonce: 0x7AC0 });
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
/// Version skew is the one compatibility case that exists (`DESIGN.md` § 6.4), and
/// its shape is a *newer* client reaching a session an older daemon is still
/// holding. The refusal used to happen after the takeover rather than before it, so
/// the failed handshake evicted the working client with `Error{TAKEOVER}` and then
/// dropped the newcomer too, leaving the session running with nobody attached. § 6.4
/// tells a client never to auto-reconnect after a takeover — so the user's shell
/// went quiet and stayed quiet, over a connection attempt that was refused.
#[test]
fn a_version_mismatch_refuses_the_newcomer_without_evicting_the_client() {
    let (session, mut client, ok) = Session::attached("skew");

    // The incumbent is serving before the newcomer knocks, or the assertion below
    // that it still is would be about nothing.
    let first = b"echo NOMUX-FIRST\n";
    client.input(0, first);
    let (_, from) = client.read_until("NOMUX-FIRST", ok.resume_from);

    let mut newcomer = session.connect();
    newcomer.send(&Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION + 1,
        flags: 0,
        out_offset: RESUME_FROM_START,
        win: harness::WIN,
        term: "xterm-256color",
    }));
    newcomer.expect_error(
        ErrorCode::Version,
        "a mismatched Hello must be refused as a version error",
    );

    // The incumbent kept the session: it never saw a takeover, and its input stream
    // carries on from where it was rather than restarting.
    client.input(first.len() as u64, b"echo NOMUX-STILL-HERE\n");
    client.read_until("NOMUX-STILL-HERE", from);
}

/// Regression: a client vanishing must never take the session with it.
///
/// Closing a socket that still has unread data queued makes the kernel send RST
/// rather than FIN, so the daemon's next read fails with `ECONNRESET`. That error
/// was originally propagated out of the event loop and terminated the daemon —
/// killing the shell over exactly the kind of unclean disconnect this project
/// exists to survive.
#[test]
fn an_abrupt_client_disconnect_does_not_kill_the_session() {
    let (session, mut client, _) = Session::attached("reset");

    let command = b"echo NOMUX-SURVIVED\n";
    client.input(0, command);

    // The daemon owns the command before the connection goes, so the assertion below
    // is about what the session kept rather than about what it managed to read in
    // the time somebody guessed at.
    client.wait_for_input_ack(command.len() as u64);
    // And it has written something nobody read, which is what makes the close an RST
    // rather than an orderly FIN — that reset is the whole fault under test.
    client.wait_for_unread_bytes();
    drop(client);

    // Straight into the reconnect: the handshake is itself the wait for the daemon to
    // have dealt with the disconnect, since `in_applied` in the reply is authoritative
    // and the takeover path runs before it is answered.
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    assert_eq!(
        ok.in_applied,
        command.len() as u64,
        "session lost its input state after an abrupt disconnect"
    );

    client.input(ok.in_applied, b"echo NOMUX-STILL-HERE\n");
    client.read_until("NOMUX-STILL-HERE", ok.resume_from);
}

/// Bulk traffic through the attach relay, both ways at once.
///
/// The relay moves bytes with `splice(2)` where the kernel allows it and by
/// copying where it does not, decided per direction at runtime — two paths through
/// the one component that must never break. Megabytes are what makes that
/// interesting: enough to fill and refill the pipe and the socket, so both paths
/// hit short transfers and full destinations. A chunk dropped, replayed or
/// reordered at a path boundary then shows up as a first-difference index instead
/// of as output that still looks plausible.
///
/// Which of the two this one takes is not in doubt, though: `Stdio::piped()` puts a
/// pipe on one end of every transfer, which is exactly what `splice` asks for, so
/// both directions here splice and neither ever copies. The test below is the same
/// traffic over stdio the kernel refuses, and is the only thing that pins the other
/// path.
///
/// No daemon here on purpose. The relay never parses a frame, so a bare socket is
/// a complete peer, and the assertions can be about bytes rather than about the
/// protocol.
#[test]
fn the_relay_moves_bulk_traffic_both_ways_without_losing_a_byte() {
    const BULK: usize = 2 * 1024 * 1024;

    let (mut child, peer, _listener) = relay_onto_a_socket("relay_bulk", Stdio::piped());
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    assert_relay_moves_bulk(
        child,
        peer,
        BULK,
        (0x5eed_1234, 0xfeed_9876),
        move |data| {
            stdin.write_all(data).expect("write to relay stdin");
            // Half-close, which the relay must turn into shutdown(SHUT_WR) on the
            // socket while still draining the other direction.
            drop(stdin);
        },
        move || {
            let mut got = Vec::new();
            stdout.read_to_end(&mut got).expect("read relay stdout");
            got
        },
    );
}

/// The same traffic again, over stdio no kernel will splice — which is the only way
/// to reach the half of the relay the test above never runs.
///
/// `Pump::transfer` reaches for `splice` first and copies through a 16 KiB buffer
/// only once the kernel has refused the pair, latching that refusal for the life of
/// the direction. Stdio on a `socketpair` is what takes the pipe away, and is the
/// case `splice_once` names in so many words: sshd handing the client socket-backed
/// stdio instead of pipes. Socket to socket is `EINVAL`, which is neither `EINTR`
/// nor `EAGAIN` and so arrives as `Spliced::Unusable`, so from the first wakeup in
/// each direction every byte below crosses through `copy_in` and `drain_to` and none
/// through the kernel.
///
/// Both endings are the fallback's too: the half-close on stdin and the one on the
/// socket each reach the relay as `copy_in` reading zero, and getting either wrong
/// truncates or hangs one of the two comparisons below.
#[test]
fn the_relay_moves_the_same_traffic_by_copying_when_the_kernel_will_not_splice_it() {
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;

    // A quarter of what the splice test moves, and still 32 buffers per direction:
    // what a mis-slice or a swallowed short read does at one 16 KiB boundary it does
    // at every one of them, so the extra megabytes buy only seconds. Copying is the
    // slower path by construction — one `read` and one `writev` per chunk, against
    // one `splice` per 64 KiB.
    const BULK: usize = 512 * 1024;

    let (mut feed, relay_stdin) = UnixStream::pair().expect("a socketpair for the relay's stdin");
    let (mut drain, relay_stdout) =
        UnixStream::pair().expect("a socketpair for the relay's stdout");
    let (child, peer, _listener) = relay_onto_a_socket_over(
        "relay_copy",
        Stdio::from(OwnedFd::from(relay_stdin)),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::piped(),
    );

    assert_relay_moves_bulk(
        child,
        peer,
        BULK,
        (0x0c07_9114, 0xc0de_5a1e),
        move |data| {
            feed.write_all(data).expect("write to relay stdin");
            // The half-close the relay must turn into shutdown(SHUT_WR) on the
            // socket while it goes on draining the other direction. A socket's, not
            // a pipe's, but `copy_in` reads the same zero from either.
            feed.shutdown(Shutdown::Write)
                .expect("half-close the relay's stdin");
        },
        move || {
            let mut got = Vec::new();
            drain.read_to_end(&mut got).expect("read relay stdout");
            got
        },
    );
}

/// How long *all four* of a relay's directions have between them before the wait on
/// them is called a hang rather than slowness.
///
/// Far above the second or so the transfers really take, and far below the
/// termination in `.config/nextest.toml`, so a stalled relay fails here — naming the
/// direction that stopped — rather than being killed there with nothing to point at.
///
/// The four joins share it rather than each getting one, which is what makes the
/// second half of that sentence true. Thirty seconds apiece was a hundred and twenty
/// against a runner that kills at forty: a relay that stalled in any direction but
/// the first was killed by nextest, and the named failure this exists to produce
/// never ran.
const RELAY_PATIENCE: Duration = Duration::from_secs(25);

/// Moves `bulk` bytes each way through a relay and compares both directions.
///
/// Shared by the two tests above, which differ only in the stdio the relay is handed
/// — and therefore in whether the kernel will splice it — and in how the feeding side
/// half-closes. Everything else was written twice: the same four threads, the same
/// order of joins, and the same pair of comparisons.
///
/// `feed` writes the upstream bytes and then half-closes; `drain` reads the
/// downstream ones to end of file. Both own their descriptor, so the choice of pipe
/// or `socketpair` stays with the caller that made it.
fn assert_relay_moves_bulk(
    mut child: Spawned,
    peer: UnixStream,
    bulk: usize,
    seeds: (u64, u64),
    feed: impl FnOnce(&[u8]) + Send + 'static,
    drain: impl FnOnce() -> Vec<u8> + Send + 'static,
) {
    use std::net::Shutdown;
    use std::sync::Arc;

    let peer = Arc::new(peer);
    let mut stderr = child.stderr.take().expect("stderr");

    let upstream = Rng::new(seeds.0).bytes(bulk);
    let downstream = Rng::new(seeds.1).bytes(bulk);

    // Four threads because all four flows must run at once: with any one of them
    // parked the relay's back pressure would deadlock the other three. More sharply
    // on the copying path, which writes to a *blocking* stdout — there a reader that
    // stops reading stops the relay rather than filling a buffer.
    let feeder = {
        let data = upstream.clone();
        thread::spawn(move || feed(&data))
    };
    let push = {
        let data = downstream.clone();
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            let mut peer = &*peer;
            peer.write_all(&data).expect("write to relay socket");
        })
    };
    let uplink = {
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            let mut peer = &*peer;
            let mut got = Vec::new();
            peer.read_to_end(&mut got).expect("read from relay socket");
            got
        })
    };
    let downlink = thread::spawn(drain);

    let deadline = Instant::now() + RELAY_PATIENCE;
    join_before(feeder, deadline, "feeder");
    let uplink = join_before(uplink, deadline, "socket reader");
    join_before(push, deadline, "pusher");
    // Only now: the relay ends the moment the socket reports EOF, so closing this
    // any earlier would truncate the direction under test rather than test it.
    peer.shutdown(Shutdown::Write)
        .expect("half-close the socket");
    let downlink = join_before(downlink, deadline, "stdout reader");

    // Killed before its stderr is read to the end. Every wait above goes through
    // `join_within` so that a stalled relay fails rather than hangs, and this read
    // has no deadline of its own: a relay that had closed both data directions but
    // not exited would park the run here until nextest's own kill, with nothing to
    // point at. By this line the three joins have established that both directions
    // reached EOF, so there is nothing left for it to say that this could cut off.
    drop(child.kill());
    let mut complaints = String::new();
    drop(stderr.read_to_string(&mut complaints));
    drop(child);

    assert_same(&upstream, &uplink, "stdin -> socket", &complaints);
    assert_same(&downstream, &downlink, "socket -> stdout", &complaints);
}

/// Regression: the relay must leave when its output has nowhere left to go.
///
/// `splice` into a full destination reports `EAGAIN`, which the relay records as
/// `dest_full` and answers by polling that destination for `POLLOUT` and holding
/// off on reading the source. If the destination's peer then dies, `poll` reports
/// `POLLERR` — never `POLLOUT`, because a pipe nobody is reading never becomes
/// writable — and the drain that would clear the latch was guarded on `POLLOUT`
/// alone, so nothing in the iteration could act and the loop spun at the speed of
/// the scheduler.
///
/// A bare socket for a peer, as in the bulk test above — the relay parses nothing,
/// so a daemon here would only add a protocol conversation the bug does not need.
#[test]
fn the_relay_exits_when_its_stdout_dies_with_the_destination_latched_full() {
    /// Far more than the ~264 KiB the socket buffer and the stdout pipe hold between
    /// them, so the push below cannot end by simply running out of bytes.
    const PUSH: usize = 8 << 20;

    let (mut child, mut peer, _listener) = relay_onto_a_socket("relay_spin", Stdio::null());
    // Stdin stays open and idle throughout. It is in the poll set the whole time,
    // which is the point: the wakeups being spun on come from stdout, so a relay
    // that blocked on stdin instead would hide the bug.
    let _stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    // Push until the kernel stops taking it: that is the socket buffer *and* the
    // stdout pipe both full, which is what leaves the relay's last `splice` sitting
    // on `EAGAIN` with `dest_full` latched and its buffer empty.
    peer.set_nonblocking(true).expect("nonblocking peer");
    let sent = push_until_refused(&mut peer, &vec![b'x'; PUSH], Duration::from_secs(1));
    // Asserted rather than assumed: every other way out of that push leaves the
    // destination unlatched, and stdout is then not in the relay's poll set at all —
    // which is the state the *next* test is about, and this one would pass while
    // proving it a second time.
    assert!(
        sent < PUSH,
        "the relay's socket and stdout pipe took all {PUSH} bytes, so nothing was \
         ever latched full"
    );

    // Nothing has read a byte of stdout, so the pipe is full and the relay is
    // waiting for it to become writable. Now take away the reader.
    drop(stdout);

    assert!(
        poll_until(Duration::from_secs(10), || !child.is_running()),
        "the relay was still running with its stdout gone and its buffer empty"
    );
}

/// Regression: the relay must leave when its stdout dies while nothing is owed to
/// it, which is the state it is in almost all of the time.
///
/// The regression is what the relay used to do about it: answer the `EPIPE` by
/// dropping the buffer and carrying on, so every byte the session produced was read
/// off the socket and discarded over a dead pipe, for as long as the session kept
/// producing, with the relay holding its one client slot throughout.
///
/// Which of the two discoveries arrives first depends on what stdout is. An idle
/// direction is out of the poll set altogether — an empty buffer wants nothing — so
/// nothing is noticed until the session produces something, and that first chunk is
/// buffered rather than written, the relay writing only to a descriptor `poll` has
/// just called writable. Buffering it is what puts stdout into the set. A pipe whose
/// read end is gone answers `POLLOUT | POLLERR`, so here the `ERR` branch wins and
/// the relay leaves without ever attempting the write. A socket whose peer has shut
/// down its read half answers `POLLOUT` alone, the write is made, and the `EPIPE` it
/// returns is the only thing that ever reports the death — which is
/// [`the_relay_exits_when_a_stdout_it_can_only_copy_to_stops_reading`], the sibling
/// that keeps that arm under test.
///
/// Asserted as the relay exiting rather than as bytes not moving, because that is
/// the only thing that distinguishes the two: a discard loop accepts everything it
/// is handed — 42 MB of it, when this was measured — and from the socket end looks
/// exactly like a relay doing its job.
///
/// The pipe is built and half-closed inside [`while_nothing_forks`], because a pipe
/// is broken only when the *last* descriptor onto its read end goes and another
/// test's `fork` in flight holds a copy of everything open here (`PLAN.md` § P2). The
/// relay is idle from birth either way: it does not touch stdout until it has
/// something for it.
#[test]
fn the_relay_exits_when_its_stdout_dies_with_nothing_owed_to_it() {
    // Before a single byte has crossed, so the direction is idle rather than
    // latched: nothing buffered, and no `splice` left sitting on a full pipe.
    let broken = while_nothing_forks(|| {
        let (reader, writer) = std::io::pipe().expect("a pipe for the relay's stdout");
        drop(reader);
        writer
    });
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_idle",
        Stdio::piped(),
        Stdio::from(broken),
        Stdio::null(),
    );
    // Stdin stays open and idle, so the only thing that can end this relay is the
    // stdout it can no longer reach: the socket is held by the test, and a stdin
    // closed here would only half-close that.
    let _stdin = child.stdin.take().expect("stdin");

    // One chunk is the whole provocation. The relay wakes on the readable socket,
    // takes it — by `splice` where the kernel allows it, which a pipe with no
    // reader refuses, and then by copying — and finds on the write that there is
    // nobody left to hand it to.
    peer.write_all(&vec![b'x'; 8 * 1024])
        .expect("write to the relay's socket");

    assert!(
        poll_until(Duration::from_secs(10), || !child.is_running()),
        "the relay was still running with its stdout gone and its buffer idle"
    );
}

/// The same ending on a relay that was already copying before its stdout died.
///
/// The two above take stdio the kernel will splice, so the death and the fallback
/// arrive together: `splice` into a pipe with no reader is `EPIPE`, `splice_once`
/// folds that into `Spliced::Unusable`, and the copying path is switched on *by* the
/// very thing it then has to report. Which leaves the ordinary case untested — a
/// relay that has been copying all along, on a host that never had a pipe to splice
/// through, losing its reader mid-session. Over a `socketpair` the two come apart:
/// `splice` is refused for being handed no pipe at all, and the `EPIPE` arrives
/// later and from somewhere else, `nbio::drain_to`'s `writev`, with `splice_refused`
/// long since latched.
///
/// Cheap enough to be worth having: one chunk, one process, and no timing to get
/// right, since the reader stops reading before the relay has anything to hand it.
#[test]
fn the_relay_exits_when_a_stdout_it_can_only_copy_to_stops_reading() {
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;

    // Held open and idle, as in the two tests above: the socket is the test's own, so
    // a stdin closed here would half-close the one direction that could otherwise end
    // this relay for a reason that is not the one under test.
    let (_stdin, relay_stdin) = UnixStream::pair().expect("a socketpair for the relay's stdin");
    let (reader, relay_stdout) = UnixStream::pair().expect("a socketpair for the relay's stdout");
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_copy_epipe",
        Stdio::from(OwnedFd::from(relay_stdin)),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::null(),
    );

    // Shut down rather than closed, and left open afterwards to make that the point:
    // `SHUT_RD` is a property of the socket rather than of any descriptor onto it, so
    // the copy another test's `fork` in flight is holding cannot undo it where a close
    // could (`PLAN.md` § P2).
    //
    // Before a byte has crossed, so nothing is owed to it and nothing is latched: the
    // relay is not watching this descriptor and cannot be told about it.
    reader
        .shutdown(Shutdown::Read)
        .expect("stop reading the relay's stdout");

    peer.write_all(&vec![b'x'; 8 * 1024])
        .expect("write to the relay's socket");

    assert!(
        poll_until(Duration::from_secs(10), || !child.is_running()),
        "the relay was still running with a stdout it could only copy to gone"
    );
}

/// Regression: a session that ends with the relay's own input still unread is a
/// clean exit, and what is buffered for stdout still gets there.
///
/// That is the ordinary way a session ends rather than an exotic one. § 4.1 stops
/// the daemon draining a client it is holding back, `write_client` drops a peer that
/// has stopped reading, and `shutdown` closes straight after `flush_final` — each of
/// them closes with bytes of the relay's still in the socket's receive queue, and a
/// unix socket closed in that state hands the peer the last of the data and then
/// `ECONNRESET` where an orderly close gives it a zero. Confirmed against a
/// socketpair before this test was written, since the whole thing rests on it.
///
/// `copy_in` mapped only `EIO` to an ending, so that reset came back out of `relay`
/// as a failure: `nomux: Connection reset by peer` and exit 126, where § 10 gives 0
/// to "the session ended and the `Exit` frame was delivered". And the last of the
/// session's output went with it — a `relay` that returns `Err` never goes back for
/// what stdout is owed, and the buffer holds it precisely here, since a direction
/// that had nothing queued when `poll` was called is not asking for `POLLOUT` yet.
///
/// Stdio on a socketpair for the reason [`the_relay_moves_the_same_traffic_by_copying_when_the_kernel_will_not_splice_it`]
/// gives, and here it is what makes the bug reachable at all: the first `splice`
/// consumes the socket's pending error, so a host whose stdio is a pipe never sees
/// the reset. § 7 gives the other kind a socketpair.
#[test]
fn a_session_that_ends_with_the_relays_input_unread_still_exits_clean() {
    use std::os::fd::OwnedFd;

    /// Written in the same breath as the close, so it is still in the relay's
    /// buffer when the reset arrives.
    const LAST: &[u8] = b"NOMUX-LAST-OUTPUT";

    let (mut feed, relay_stdin) = UnixStream::pair().expect("a socketpair for the relay's stdin");
    let (mut drain, relay_stdout) =
        UnixStream::pair().expect("a socketpair for the relay's stdout");
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_reset",
        Stdio::from(OwnedFd::from(relay_stdin)),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::piped(),
    );

    // Never read from this end, which is the whole provocation: the reset is the
    // kernel's answer to a close over a receive queue that still has something in it.
    feed.write_all(b"a keystroke this session never drains")
        .expect("write to the relay's stdin");
    // Waited for rather than assumed. A close that beats the relay's delivery of
    // those bytes is an orderly FIN, and this test would then pass having provoked
    // nothing at all.
    assert!(
        poll_until(RELAY_PATIENCE, || has_unread_bytes(&peer)),
        "the relay never delivered the input this test leaves unread"
    );

    peer.write_all(LAST)
        .expect("write the session's last words");
    drop(peer);

    assert!(
        poll_until(RELAY_PATIENCE, || !child.is_running()),
        "the relay never left after its session ended"
    );
    // After the exit, so nothing here can park: the relay's own end of this
    // socketpair went with it, and what it wrote is waiting in the buffer.
    let mut got = Vec::new();
    drop(drain.read_to_end(&mut got));
    let finished = child
        .into_exited()
        .wait_with_output()
        .expect("collect the relay");
    let complaints = String::from_utf8_lossy(&finished.stderr).into_owned();

    assert_eq!(
        got, LAST,
        "the relay dropped the output it was still holding; it said {complaints:?}"
    );
    assert!(
        finished.status.success(),
        "a session that ended is exit 0 (§ 10), got {}; the relay said {complaints:?}",
        finished.status
    );
}

/// Regression: a write to stdout that a signal cut short must not send the relay
/// straight back into the kernel for the rest of it.
///
/// `nbio::drain_to` used to write until the descriptor refused. Every descriptor in
/// the daemon is non-blocking, so there the retry could answer nothing but `EAGAIN` —
/// but the relay points it at *stdout*, which is deliberately left blocking, because
/// it may be a terminal whose open file description the user's shell shares and
/// `O_NONBLOCK` is not this process's to set (`attach.rs`). There the second `writev`
/// is a second block, and the relay sits inside it with the other direction unserved:
/// keystrokes stop reaching the session because the session's output has nowhere to
/// go. `POLLOUT` promises only that *some* write will succeed, which is exactly the
/// promise the loop was reading as more than that.
///
/// What makes it observable is a *short* write, and on Linux a blocking descriptor
/// short-writes only when a signal ends the call after it has already transferred
/// something. So this provides one: `SIGSTOP` cannot be caught, blocked or ignored,
/// so it always reaches a task parked in a write, and a write that has already moved
/// bytes reports the short count rather than being restarted. `SIGCONT` then puts the
/// relay back exactly where the fix has to matter — one `drain_to` call, mid-queue,
/// against a destination that is still full.
///
/// The destination is a socketpair with a shrunken send buffer, which is what makes
/// the rest exact rather than probable. A unix socket blocks only once its buffer is
/// at the limit — the same condition `POLLOUT` answers — so the write the relay makes
/// on `POLLOUT` always transfers at least one segment before it stops, and the write
/// it would go back for afterwards has no `POLLOUT` to start from. Shrinking the
/// buffer is what makes 16 KiB more than one segment; at the default 208 KiB the
/// whole write is a single one, which either fits or is refused outright. A socket is
/// also a destination the kernel will not splice into, which is what keeps the relay
/// on the copying path `drain_to` belongs to — a pipe would be moved inside the
/// kernel and never reach it (§ 7).
#[test]
fn a_write_to_stdout_a_signal_cut_short_does_not_park_the_relay_again() {
    use std::os::fd::OwnedFd;

    /// Small enough that one of the relay's 16 KiB writes is several segments, so it
    /// can stop partway rather than only at a boundary of its own.
    const STDOUT_BUFFER: libc::c_int = 4096;
    /// More than the shrunken socket and the relay's own 16 KiB buffer hold between
    /// them, so the write it parks in cannot end by running out of bytes.
    const PUSH: usize = 64 * 1024;
    /// Sent the other way, and nothing to do with the write above: this is the
    /// traffic the parked relay is failing to serve.
    const MARKER: &[u8] = b"NOMUX-OTHER-DIRECTION";
    /// How long the marker is given to *not* arrive. Only has to outlast a relay that
    /// is still going round its loop, which takes microseconds.
    const PARKED: Duration = Duration::from_millis(250);

    // Never read from, which is what keeps the relay's stdout full; held to the end
    // of the test, since a closed one would be an `EPIPE` rather than a block.
    let (_unread, relay_stdout) = UnixStream::pair().expect("a socketpair for the relay's stdout");
    shrink_send_buffer(&relay_stdout, STDOUT_BUFFER);
    let (mut child, mut peer, _listener) = relay_onto_a_socket_over(
        "relay_short_write",
        Stdio::piped(),
        Stdio::from(OwnedFd::from(relay_stdout)),
        Stdio::null(),
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let relay = child.id();

    peer.write_all(&vec![b'x'; PUSH])
        .expect("write to the relay's socket");
    // Short, because every look for the marker below reads through this and a relay
    // that is parked has nothing to say.
    peer.set_read_timeout(Some(Duration::from_millis(20)))
        .expect("a peer the polls below must not wait on");

    assert!(
        poll_until(Duration::from_secs(10), || parked_in_a_write(relay)),
        "the relay never parked inside a write to its stdout, so there is no \
         interrupted write below for either version of `drain_to` to answer"
    );

    // Written only now, so that it cannot have been served before the relay stopped.
    stdin.write_all(MARKER).expect("write to the relay's stdin");
    stdin.flush().expect("flush the relay's stdin");
    let mut seen = Vec::new();
    assert!(
        !poll_until(PARKED, || marker_arrived(&mut peer, &mut seen, MARKER)),
        "the relay served its stdin while it was supposed to be parked in a write, \
         so the wait below would be satisfied by a marker that had already arrived"
    );

    // The stop is what ends the write; the continue is what makes what happens next
    // the relay's own decision. Waited out rather than sent back to back: a `SIGCONT`
    // generated before the stop has been taken discards it, and the write would then
    // be restarted rather than cut short.
    let pid = rustix::process::Pid::from_raw(relay.cast_signed()).expect("the relay's pid");
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stop the relay");
    assert!(
        poll_until(Duration::from_secs(10), || process_state(relay)
            == Some('T')),
        "the relay never took the stop, so the write it is in was never interrupted"
    );
    rustix::process::kill_process(pid, rustix::process::Signal::CONT).expect("continue the relay");

    assert!(
        poll_until(Duration::from_secs(10), || marker_arrived(
            &mut peer, &mut seen, MARKER
        )),
        "the relay went back into the kernel for the rest of a write the signal had \
         already ended, leaving the other direction unserved"
    );
}

/// Whether `pid` is inside a `writev(2)` at this moment, as `/proc` reports it.
///
/// The relay makes exactly one kind of write — `nbio::drain_to`'s `writev` across the
/// two halves of its queue — so the syscall number is the most direct statement of
/// the state the test needs, and far cheaper than inferring it from what the relay
/// has stopped doing. `/proc/<pid>/syscall` gives a number and its arguments, or
/// `running`; anything that does not parse, including a kernel that does not offer
/// the file, reads as "not parked" and fails the wait that asks for it rather than
/// letting some other state pass for it.
fn parked_in_a_write(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/syscall"))
        .ok()
        .and_then(|reported| {
            reported
                .split_whitespace()
                .next()?
                .parse::<libc::c_long>()
                .ok()
        })
        .is_some_and(|syscall| syscall == libc::SYS_writev)
}

/// Whether `marker` has reached `peer` yet, keeping whatever else arrives on the way.
///
/// Everything read is kept and the answer is about the whole of it, so a marker split
/// across two reads is still found — and so a look that comes back empty cannot
/// discard what an earlier one collected.
fn marker_arrived(peer: &mut UnixStream, seen: &mut Vec<u8>, marker: &[u8]) -> bool {
    let mut chunk = [0u8; 8192];
    while let Ok(read) = read_uninterrupted(peer, &mut chunk) {
        if read == 0 {
            break;
        }
        seen.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
    }
    seen.windows(marker.len()).any(|window| window == marker)
}

/// A `nomux attach` relaying onto a socket the test holds the other end of, with
/// its first connection already accepted.
///
/// The scaffolding every relay test needs and none of them is about: a run directory
/// of the mode the binary insists on, a session socket bound by the test rather than
/// by a daemon, and the relay started against it. What they do differ in is where the
/// relay's complaints go, so that is the argument — the bulk test reads them into its
/// failure messages, and the ones about the relay leaving have nobody left to read
/// them.
///
/// The listener comes back with the rest because it has to outlive the relay: a
/// connection arriving at a closed one is refused, and a refusal would look like the
/// relay giving up rather than like the test having tidied away too early.
fn relay_onto_a_socket(id: &str, complaints: Stdio) -> (Spawned, UnixStream, UnixListener) {
    relay_onto_a_socket_over(id, Stdio::piped(), Stdio::piped(), complaints)
}

/// [`relay_onto_a_socket`] with the relay's stdin and stdout chosen by the caller.
///
/// What is on the far end of those two is not a detail of the scaffolding for the
/// tests about the copying path: `splice` wants one end of each transfer to be a
/// pipe, so `Stdio::piped()` is the reason the relay never copies, and a
/// `socketpair` is the reason it always does. Kept apart from the common form so
/// that the tests which only want a relay do not have to say which of the two they
/// are getting — the answer is the pipes everybody assumes.
fn relay_onto_a_socket_over(
    id: &str,
    input: Stdio,
    output: Stdio,
    complaints: Stdio,
) -> (Spawned, UnixStream, UnixListener) {
    use std::os::unix::fs::PermissionsExt;

    let root = run_root(id);
    let dir = root.join("nomux");
    fs::create_dir_all(&dir).expect("create run directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("tighten run dir");
    let listener = UnixListener::bind(dir.join(format!("{id}.sock"))).expect("bind session socket");

    // The `Command` is a temporary and dies with the statement, which is what closes
    // this process's copies of anything the caller passed in: a `socketpair` end
    // still held here would be a stdout that never reaches EOF.
    let child = Spawned::spawn(
        nomux(&root, &["attach", id])
            .stdin(input)
            .stdout(output)
            .stderr(complaints),
    );

    let peer = accept_within(
        &listener,
        Duration::from_secs(10),
        "`nomux attach` to connect to the session socket",
    );
    // `accept` hands back a socket with no deadline of its own, and the bulk tests
    // read it to end of file — so a relay that stalled would park a test thread for
    // ever. The timeout turns that into the named failure `join_within` reports.
    peer.set_read_timeout(Some(RELAY_PATIENCE))
        .expect("a peer the test must not park on");
    (child, peer, listener)
}

/// Compares by first difference rather than by value: a failure here is megabytes
/// wide, and the only useful part of it is where the two streams parted company.
fn assert_same(want: &[u8], got: &[u8], direction: &str, stderr: &str) {
    let at = want.iter().zip(got).position(|(a, b)| a != b);
    assert!(
        at.is_none(),
        "{direction} diverged at byte {at:?} of {}; relay stderr: {stderr:?}",
        want.len()
    );
    assert_eq!(
        got.len(),
        want.len(),
        "{direction} moved the wrong number of bytes; relay stderr: {stderr:?}"
    );
}
