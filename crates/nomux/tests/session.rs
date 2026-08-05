//! End-to-end tests against the real binary.
//!
//! These drive `nomux daemon` over its unix socket, speaking the wire protocol
//! directly, so they exercise the PTY, the ring buffer and the resume path rather
//! than a mock of them.
//!
//! The two invariants that matter (`IMPLEMENTATION.md` § 9): input is never
//! duplicated, and output is never lost unless a `Gap` was reported. What is left
//! here is what those two are made of — resume, gap and ring exactness, the
//! refusals a connection can earn, the takeover rules, and the repaint a gap owes
//! the child. The rest of the suite is its own binary: `attach.rs`, `agent.rs`,
//! `lifecycle.rs`, `flow.rs` and `spawn_lock.rs`.

#![allow(
    clippy::expect_used,
    reason = "the allow-expect-in-tests setting in clippy.toml reaches `#[test]` \
              bodies and `#[cfg(test)]` modules, not the helpers an integration \
              test crate keeps beside them"
)]

mod harness;

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{
    ErrorCode, Frame, FrameType, HELLO_REPAINT_CTRL_L, Hello, Linger, PROTOCOL_VERSION,
    RESUME_FROM_START, WinSize,
};

use harness::{
    Client, FRAME_PATIENCE, Rng, Session, hello_frame, poll_by, poll_until, reconnect_until_gap,
    still_serving,
};

#[test]
fn output_resumes_contiguously_after_a_reconnect() {
    let (session, mut client, ok) = Session::attached("resume");
    // The one field of the greeting that is the daemon's own answer rather than a
    // function of what this client asked for, checked here because this is the first
    // `HelloOk` in the suite from a session that has one: nothing else asserts it
    // against a running daemon, so a daemon reporting a linger state it made up would
    // be caught only by the client, which is a separate codebase. The revision is not
    // among them any more — `HelloOk` carries none, the daemon having already refused
    // a `Hello.protocol` that is not its own, which is what
    // `a_version_mismatch_refuses_the_newcomer_without_evicting_the_client` pins.
    assert_eq!(
        ok.linger,
        linger_on_this_host(),
        "the daemon must report a linger state it detected the way § 6.2 says, rather \
         than a default — it is what the client warns the user about, and see \
         `linger_on_this_host` for the part of that this can and cannot say"
    );
    assert!(
        !ok.gap(RESUME_FROM_START),
        "a fresh session has dropped nothing"
    );

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
    assert!(
        !ok.gap(offset),
        "nothing should have been dropped in this window"
    );

    client.input(ok.in_applied, b"echo NOMUX-AFTER\n");
    client.read_until("NOMUX-AFTER", ok.resume_from);
}

/// What `linger::detect` must answer on the host this test is running on, worked out
/// from the same two paths it stats (`IMPLEMENTATION.md` § 6.2).
///
/// What the comparison buys, stated exactly, because it is less than a second opinion
/// and more than nothing. It establishes that the daemon puts a *detected* state into
/// `HelloOk` rather than a constant: the field is asserted nowhere else against a
/// running daemon — the suite's only other mentions of it are `HelloOk`s the tests
/// build themselves — so a daemon answering `Unknown` for everything short of an
/// enabled marker passed every test in the workspace, measured. It does
/// *not* establish that § 6.2's rules are the right ones, because it applies the same
/// rules: this is a transcription of `detect` rather than an independent oracle, and a
/// misreading shared by both sides is invisible here. Where the classification itself
/// is pinned against written-down inputs is `linger.rs`'s own unit tests.
///
/// Two things soften it further, and both are the host's rather than the code's. Where
/// there is no `logind` — a container, a BSD — both sides answer `Unknown` before
/// reading anything, and the assertion holds whatever the daemon makes of the marker.
/// A host that resolves no login name lands in that same soft case, which is why the
/// fallback below is included rather than left out. So this is a real check on the
/// machines that have a marker directory to disagree about and a name to look up in
/// it, and a tautology on the rest; there is no arrangement of a filesystem the test
/// is allowed to make that would change that.
///
/// The rules, as § 6.2 gives them: no `logind` is `Unknown` and not "no marker,
/// therefore disabled", the marker's absence is a definite `Disabled`, and anything
/// else about the lookup is `Unknown`.
fn linger_on_this_host() -> Linger {
    if !Path::new("/run/systemd/system").is_dir() {
        return Linger::Unknown;
    }
    let Some(user) = login_name() else {
        return Linger::Unknown;
    };
    match fs::metadata(Path::new("/var/lib/systemd/linger").join(user)) {
        Ok(_) => Linger::Enabled,
        Err(err) if err.kind() == ErrorKind::NotFound => Linger::Disabled,
        Err(_) => Linger::Unknown,
    }
}

/// The name [`linger_on_this_host`] joins onto the linger directory, resolved in the
/// order `linger::username` resolves it.
///
/// The password database first, because it is authoritative; `$USER` — then
/// `$LOGNAME` — second, for a directory-backed account with no line in
/// `/etc/passwd`. The fallback is half the logic and the half a host in CI is most
/// likely to take, so leaving it out would leave this comparing `Unknown` against
/// `Unknown` and calling it a pass.
///
/// Read as bytes for the reason `passwd::lookup` gives: one Latin-1 name in
/// somebody else's GECOS field would otherwise fail the decode of the whole file and
/// silently move this to the fallback.
fn login_name() -> Option<String> {
    let uid = rustix::process::getuid().as_raw();
    let from_passwd = fs::read("/etc/passwd").ok().and_then(|database| {
        database
            .split(|byte| *byte == b'\n')
            .find_map(|line| {
                let mut fields = line.split(|byte| *byte == b':');
                let name = fields.next()?;
                let _password = fields.next()?;
                if str::from_utf8(fields.next()?).ok()?.parse::<u32>().ok()? != uid {
                    return None;
                }
                str::from_utf8(name).ok()
            })
            .map(str::to_owned)
    });
    from_passwd
        .or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .ok()
        })
        // A name usable as a path traversal is refused rather than joined onto a
        // system directory, which is the one thing `linger::username` does beyond
        // choosing between its two sources.
        .filter(|name| {
            !name.is_empty()
                && !name.contains('/')
                && !name.contains('\0')
                && name != "."
                && name != ".."
        })
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
///
/// The end of the stream is *known* here rather than bracketed, which is what makes
/// the clamp falsifiable: a window a megabyte wide is satisfied by a daemon that
/// clamped to any number at all between the two, and the one number § 4.2 names is
/// the end. Two things buy it. `-echo` puts the line discipline's copy of the command
/// line off the stream, so the read below stops at the child's own output rather than
/// at the echo with the output still to come; and `printf` without a newline makes
/// that output the last byte the child writes, against an empty `PS1` that follows it
/// with nothing. So the offset the read returns is where the stream ends, and the
/// daemon has to answer with it exactly.
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
    assert!(
        !resumed.gap(end + FAR),
        "nothing was dropped, so nothing may be reported as a gap"
    );
    // An equality rather than an upper bound, and pinned from below for the same
    // reason it is pinned from above: clamping to the ring's *base* also comes in
    // under anything claimed, also reports no gap, and also leaves the read at the
    // end of this test finding its marker — in a stream it simply receives again
    // from the start.
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
///
/// One deadline for the whole read rather than one per frame. A loop over
/// `next_frame` renews its patience on every frame that arrives, so a daemon
/// handing over a byte every fourteen seconds is never late by that measure and the
/// read has no bound at all — it would run until nextest's kill, which is exactly
/// the failure `join_before` and `.config/nextest.toml` are written to avoid.
#[expect(
    clippy::panic,
    reason = "clippy.toml's allow-panic-in-tests reaches `#[test]` bodies, not the \
              helpers an integration test crate keeps beside them"
)]
fn read_against(client: &mut Client, planted: &Planted, from: u64) -> Vec<(u64, u64)> {
    /// Two orders of magnitude above the tenth of a second the largest of these
    /// reads takes, and well under the kill in `.config/nextest.toml`.
    const PATIENCE: Duration = Duration::from_secs(15);

    let expected = &planted.expected;
    let end = planted.stream_start + expected.len() as u64;
    let mut offset = from;
    let mut gaps = Vec::new();
    let awaiting = format!("the {} bytes the child wrote", expected.len());
    let deadline = Instant::now() + PATIENCE;
    while offset < end {
        let (ty, payload) = client.frame_before(deadline, &awaiting).unwrap_or_else(|| {
            panic!(
                "the session stopped {} bytes short of everything the child wrote, \
                 with the stream standing at {offset}",
                end - offset
            )
        });
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
        !ok.gap(RESUME_FROM_START),
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
/// A mistyped tuning variable should never cost somebody their session, so the value
/// is dropped and the default used. `Ring::new` clamps rather than asserts — the clamp
/// exists precisely to keep an abort site out of a `panic = "abort"` binary — so what
/// a lost filter costs is not a daemon that dies before it binds but a session whose
/// scrollback is one byte, which the round trip below still catches: nothing about a
/// one-byte ring lets a marker survive the frame it arrived in.
#[test]
fn a_ring_capacity_the_daemon_cannot_use_falls_back_to_the_default() {
    for (name, value) in [("ring_zero", "0"), ("ring_garbage", "not-a-number")] {
        let session = Session::start_with_raw_ring(name, value);
        let mut client = session.connect();
        let ok = client.hello(RESUME_FROM_START);

        // Serving, rather than merely having bound a socket: the socket is bound
        // before the ring is built, so a daemon that died over one leaves the file
        // behind and the harness's wait is satisfied by a corpse.
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

/// An `OutputAck` is advisory: the ring keeps everything regardless
/// (`IMPLEMENTATION.md` § 3 and § 4's "never trimmed on ack").
///
/// The daemon's arm for it is empty on purpose, which is exactly the kind of thing a
/// later change fills in. The frame used to carry a `consumed_through`, which looked
/// like a low-water mark asking to be applied — and applying it would even have
/// looked like an improvement, since the bytes below it are ones somebody has already
/// seen. It has no offset any more, which is § 2.2 saying the same thing in bytes,
/// and this is what says it in behaviour: the frame that arrives is still allowed to
/// mean nothing to the ring, whatever a later revision decides to put back in it.
/// Nothing else in the suite would notice a daemon that trimmed: the codec tests
/// prove the frame survives a round trip, and every other test here reads its output
/// as it arrives, so a ring trimmed to what its reader already holds serves all of
/// them identically. What breaks is the one thing the ring is for — § 4's "a full
/// rolling window is the scrollback a fresh client gets" — and it breaks for the
/// *next* client, which never sent the ack.
///
/// So the marker is written, acked past, and then asked for by somebody who has
/// never seen it. The gap cannot be what fails here and is asserted anyway:
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
    // Read to the end before acking, so the ack is sent by a client that really has
    // consumed the marker — which is the state a daemon tempted to trim would trim on.
    client.read_until("NOMUX-BEFORE-ACK", ok.resume_from);

    client.send(&Frame::OutputAck);
    // Frames are handled in the order they arrive, so a `Pong` for a ping sent behind
    // the ack is the daemon having already done whatever it does with one. Without it
    // the reconnect below could win the race and pass against a daemon that trims.
    client.send(&Frame::Ping { nonce: 0xACED });
    drop(client.next_of(FrameType::Pong));
    drop(client);

    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    assert!(
        !resumed.gap(RESUME_FROM_START),
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
///
/// One session for all five, so each row's misbehaviour lands on a session the rows
/// before it have already abused — which is strictly stronger than five fresh ones,
/// and four daemons cheaper. One deadline for the whole table, per
/// `.config/nextest.toml`: five rows of consecutive fifteen-second waits sum past the
/// runner's kill, which reports nothing.
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
                    resume_from: 0,
                    in_applied: 0,
                    win: harness::WIN,
                    linger: Linger::Unknown,
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

    let session = Session::start("refuse");
    let deadline = Instant::now() + FRAME_PATIENCE;
    let mut client = session.connect();
    let start = client.hello(RESUME_FROM_START).resume_from;

    for (round, case) in cases.iter().enumerate() {
        // Greeted *and* serving: the session is created by the first `Hello`, so a
        // round trip through the child is what puts the connection in the state this
        // is about rather than in the middle of its own handshake. A marker of the
        // round's own, so a row cannot be satisfied by the one before it.
        still_serving(&mut client, &format!("NOMUX-BEFORE-{round}"));

        (case.write)(&mut client);
        client.expect_error_among_output(ErrorCode::Protocol, case.what);
        client.expect_eof(case.what);
        drop(client);

        // The whole point of refusing on the connection's own terms: the shell is
        // still there, at the offsets it had, for whoever attaches next.
        client = session.connect();
        let resumed = client.hello(start);
        assert!(
            !resumed.gap(start),
            "{}: the session lost output while refusing one connection",
            case.what
        );
        still_serving(&mut client, &format!("NOMUX-SERVING-{round}"));
        assert!(
            Instant::now() < deadline,
            "row {round} ({}) left the table past its deadline, so the rest of it \
             would be decided by nextest's kill rather than by an assertion",
            case.what
        );
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
/// `SIGWINCH` half observable at all. The repaint fires on the first pass that finds
/// the reconnected client holding the whole ring, which at a kilobyte is the pass
/// behind its own `HelloOk`, and the marker the child prints then has to survive
/// that same kilobyte: with tens of kilobytes of echo still in flight it
/// does not, and the first version of this test failed with a transcript of nothing
/// but filler. Reading to a marker of its own leaves the child idle and the ring
/// holding only what comes after — and it also turns the reconnect below into
/// arithmetic rather than a wait, since `base` is already tens of kilobytes above
/// where this client resumes from.
///
/// The setup line is written out here rather than through `Client::make_ready`, and
/// the reason is the whole of why the subshell announces itself. That helper's
/// marker is printed by the shell *before* the command behind it starts, so at the
/// moment it arrives the subshell may not exist and certainly has not run `trap` — a
/// `SIGWINCH` in that window lands on the default disposition, which is to ignore
/// it, and no marker ever comes. That is a failure of the fixture wearing the face
/// of a daemon that never repainted, and it was seen once in a full parallel run.
///
/// Waiting for a *second* marker behind the helper's does not fix it: `read_until`
/// returns the offset one past everything it consumed, so a subshell quick enough
/// to have printed before the daemon's next read puts both markers in one frame,
/// and the wait for the second one starts already past it. That failed one run in
/// three. One marker, printed by the subshell itself, is the shape with no race in
/// it: reaching it proves the `stty` in front of it took effect *and* that the trap
/// is armed, which is what the two markers were separately for.
///
/// `owed` names the marker this policy is obliged to produce, when the fence at the
/// end cannot bound it. The `Ctrl-L` half needs nothing: the daemon writes the
/// keystroke to the PTY and `cat` hands it back, so it travels the same path as the
/// fence behind it and is already read by the time the fence arrives. The `SIGWINCH`
/// half does not travel that path at all — the marker is printed by a *second*
/// process that `TIOCSWINSZ` has merely made runnable, and nothing orders it against
/// `cat` echoing the fence. Reading to the fence and then asking whether the marker
/// is there measures which of the two the scheduler happened to pick first, which on
/// an idle machine is the subshell and on a loaded one is `cat`: it passed forty runs
/// here and failed in CI. § 4.3 obliges the repaint to happen, not to beat an
/// unrelated round trip back, so what the wait is for is that it arrives at all.
fn repaint_transcript(name: &str, flags: u8, owed: Option<&str>) -> String {
    /// The child echoes far more than this, so what the client comes back to is a
    /// gap by construction.
    const RING: usize = 1024;
    /// The last line of the filler, and how the client learns the child has caught
    /// up: `cat` echoes it, so seeing it means everything before it is behind us.
    const DRAINED: &str = "NOMUX-FILLER-DRAINED";
    /// Printed by the subshell once its `SIGWINCH` trap is in place, which is behind
    /// the `stty` in the same line — so arriving at it is proof of both. Arithmetic
    /// for the reason [`WINCHED`] is: the line discipline echoes the command that
    /// sets it up before `stty -echo` takes effect, and that echo carries `$((6*7))`
    /// unexpanded.
    const ARMED: &str = "NOMUX-42-TRAP-ARMED";

    let session = Session::start_with_ring(name, RING);
    let mut client = session.connect();
    let ok = client.hello_with(flags, RESUME_FROM_START);

    // The sleep is short so that a subshell which somehow outlived its session is
    // asleep rather than looping, and gone within seconds either way. It does not
    // normally have to be: everything here shares the shell's process group, so
    // closing the PTY master hangs the lot up.
    let setup = "stty -echo -onlcr; set +m; \
                 (trap 'printf NOMUX-$((6*7))-WINCHED' WINCH; \
                 printf NOMUX-$((6*7))-TRAP-ARMED; \
                 while :; do sleep 5 & wait; done) & cat\n";
    client.input(0, setup.as_bytes());
    let (_, offset) = client.read_until(ARMED, ok.resume_from);

    // Echoed back by `cat`, which is what overflows the ring. In lines, because the
    // line discipline is still canonical: `cat` would see nothing at all until a
    // newline arrived, and the overflow would never happen.
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
    let resumed = client.hello_with(flags, offset);
    assert!(
        resumed.gap(offset),
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

    // A fence bounds the wait for everything the repaint puts through the PTY, which
    // the child echoes back ahead of it.
    client.input(in_offset, b"FENCE\n");
    let (mut transcript, _) = client.read_past_gaps("FENCE", resumed.resume_from);

    // What the fence cannot bound is waited for on its own — see above. Offsets stop
    // mattering here: the reads that own contiguity are behind us, and all this is
    // after is whether the marker comes at all. Collected rather than asserted on, so
    // that the verdict stays with the test, which is the only place that can say what
    // its absence would mean.
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
    let asked = repaint_transcript("repaint_ctrl_l", HELLO_REPAINT_CTRL_L, None);
    assert!(
        asked.contains('\u{c}'),
        "no Ctrl-L reached the child: {asked:?}"
    );
    assert!(
        !asked.contains(WINCHED),
        "a client that asked for Ctrl-L was also sent through the winsize dance, so \
         an editor gets both a redraw it did not want and a keystroke: {asked:?}"
    );

    let default = repaint_transcript("repaint_winch", 0, Some(WINCHED));
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

/// An overrun that goes on producing gaps owes the child *one* repaint, not one per
/// gap (`IMPLEMENTATION.md` § 4.3).
///
/// The `ctrl_l` policy because this counts repaints and that one is countable: the
/// daemon writes exactly one `0x0c` per repaint, where the winsize dance is two
/// `TIOCSWINSZ` in a row and standard signals do not queue — the child sees one
/// `SIGWINCH` or two depending on when it was last scheduled, so counting those
/// would be counting the scheduler.
///
/// The child records what reaches its terminal in a file rather than echoing it,
/// because the stream back to the client is the very thing with holes in it: a
/// repaint issued mid-overflow is discarded by the next overflow, so counting the
/// ones that reached the client would count only the ones that did no harm.
///
/// [`Session::start_with_ring`] is handed a ring larger than the megabyte of output
/// the daemon queues for one client plus the 256 KiB frame that overshoots it, which
/// is what makes "still behind" structural rather than a matter of timing: once the
/// ring has overflowed it stays full, so the pass that reports a gap can never also
/// hand this client the whole of it, and `sent_through` cannot reach the end of the
/// stream again until the child falls quiet.
#[test]
fn a_sustained_overflow_repaints_when_the_client_catches_up_rather_than_per_gap() {
    /// Above `MAX_PENDING_WRITE` + `MAX_PAYLOAD` — see above for what that buys.
    const RING: usize = 2 * 1024 * 1024;
    /// What makes the overrun sustained rather than an incident. The defect repaints
    /// once per gap, so it is also what [`BUDGET`] is being separated from.
    const GAPS: usize = 16;
    /// What the daemon is allowed: the one repaint owed once the child falls quiet,
    /// plus slack for a pass where this client happened to catch up mid-flood.
    const BUDGET: usize = 4;
    /// Between frames, so that the child outruns this client rather than the other
    /// way round — a frame per this is 25 MB/s, against the 150 MB/s the daemon was
    /// measured lifting off the PTY here. A client that keeps up never falls behind
    /// the ring at all, and there is nothing here to measure.
    const PACE: Duration = Duration::from_millis(10);
    /// Printed by the flooder as its last act, so reaching it means the client has
    /// been queued the whole stream — which is the condition the repaint waits for.
    /// Arithmetic for the reason [`WINCHED`] is: the line discipline echoes the setup
    /// line before `stty -echo` takes effect, unexpanded.
    const OVER: &str = "NOMUX-42-FLOOD-OVER";
    /// Sent as ordinary input once everything the repaint owes is behind it, so the
    /// count below is taken against a record that is complete rather than against
    /// whatever had been written when the test looked.
    const FENCE: &[u8] = b"FENCE\n";

    // One deadline for the four consecutive waits below rather than one each, which
    // would bound only their sum — see `.config/nextest.toml`.
    let deadline = Instant::now() + FRAME_PATIENCE;
    let session = Session::start_with_ring("repaint_storm", RING);
    let mut client = session.connect();
    let ok = client.hello_with(HELLO_REPAINT_CTRL_L, RESUME_FROM_START);

    // `cat` keeps the terminal and writes what arrives on it to a file, so nothing
    // the daemon injects is echoed back into the ring it would be lost from. The
    // flooder is a background subshell sharing the session's process group (`set +m`,
    // as in `repaint_transcript`), and it stops on a file rather than on a signal,
    // which would take `cat` with it. Non-canonical because the daemon's `0x0c`
    // carries no newline behind it: in line mode it would sit in the line discipline
    // until the fence flushed it, and 4 KiB of them would be dropped there rather
    // than counted.
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
    // collects a megabyte of two-kilobyte frames queued before it fell behind, and it
    // has to read all of them at this pace before it reaches the first `Gap` queued
    // behind them: measured, that is four seconds of stream that says nothing about
    // the defect.
    drop(client);
    let (mut client, resumed) = reconnect_until_gap(&session, HELLO_REPAINT_CTRL_L, ready.offset);

    // Paced reads against an unpaced child: every frame taken off the socket lets the
    // daemon's queue dip below its cap, which is what lets the next pass notice that
    // the ring has moved on and report a gap. That dip is the whole recurrence — the
    // defect answers each one with a repaint.
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
            Frame::InputAck { .. } | Frame::Pong { .. } => {}
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

/// Where `needle` starts in `haystack`.
///
/// `[u8]` has no `find`, and the record this reads is bytes rather than text: the
/// daemon's repaint keystroke is `0x0c`, which `String::from_utf8_lossy` would keep
/// but nothing else here needs decoded.
fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
        agent_forward: false,
        repaint_ctrl_l: false,
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
