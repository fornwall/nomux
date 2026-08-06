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
    reason = "the allow-*-in-tests settings in clippy.toml reach `#[test]` bodies \
              and `#[cfg(test)]` modules, not the helpers an integration test crate \
              keeps beside them"
)]

mod harness;

use std::io::{ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::{
    ErrorCode, Frame, FrameType, HEADER_LEN, HELLO_REPAINT_CTRL_L, Hello, Linger, PROTOCOL_VERSION,
    RESUME_FROM_START, WinSize, decode_header,
};

use harness::{
    Client, FRAME_PATIENCE, Rng, Session, Spawned, hello_frame, nomux_with_shell, poll_by,
    poll_until, read_uninterrupted, reconnect_until_gap, run_root, still_serving,
};

#[test]
fn output_resumes_contiguously_after_a_reconnect() {
    let (session, mut client, ok) = Session::attached("resume");
    // The one `HelloOk` field that is the daemon's own answer rather than a function of
    // what the client asked for, and checked against a running daemon nowhere else.
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
/// A transcription of `detect` rather than an independent oracle: what it buys is that
/// the daemon puts a *detected* state into `HelloOk` rather than a constant, and
/// whether § 6.2's rules are the right ones is `linger.rs`'s own unit tests. With no
/// `logind` — a container, a BSD — or no resolvable login name, both sides answer
/// `Unknown` before reading anything and this is a tautology.
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
/// order `linger::username` resolves it: the password database first, then `$USER` and
/// `$LOGNAME` for a directory-backed account with no line in `/etc/passwd`. Read as
/// bytes for the reason `passwd::lookup` gives — one Latin-1 name in somebody else's
/// GECOS field would fail the decode of the whole file and silently take the fallback.
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
        // A name usable as a path traversal is refused rather than joined onto a system
        // directory — the one thing `linger::username` does beyond choosing a source.
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
    assert!(
        !resumed.gap(end + FAR),
        "nothing was dropped, so nothing may be reported as a gap"
    );
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
/// against the byte its offset names, and returns the gaps followed on the way.
///
/// The assertion the gap tests exist for. Checking contiguity *relative to* the base the
/// daemon reported cannot fail whatever it says: a base N too low replays N bytes the
/// client already has, one N too high drops N it never will, and both produce a
/// perfectly contiguous stream that corrupts the user's scrollback. Indexing a model of
/// the child's own output by absolute offset is what makes that falsifiable.
fn read_against(client: &mut Client, planted: &Planted, from: u64) -> Vec<(u64, u64)> {
    let expected = &planted.expected;
    let end = planted.stream_start + expected.len() as u64;
    let mut offset = from;
    let mut gaps = Vec::new();
    let awaiting = format!("the {} bytes the child wrote", expected.len());
    let deadline = Instant::now() + FRAME_PATIENCE;
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
            Frame::InputAck { .. } | Frame::Pong => {}
            other => panic!("unexpected {other:?} while reading the session's output"),
        }
    }
    gaps
}

/// Fails saying which offset the stream stopped meaning what the child wrote there,
/// quoted from both sides: the number alone does not say which way the error went — a
/// stream that resumed too early repeats bytes the client has, one that resumed too
/// late is missing bytes it never will.
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
    assert!(
        !ok.gap(RESUME_FROM_START),
        "a session nobody has attached to before has nothing to report at the \
         handshake, so every gap below is one this connection was sent"
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

/// A `NOMUX_RING_BYTES` the daemon cannot use falls back to the default rather than
/// refusing to start (`IMPLEMENTATION.md` § 4).
///
/// A mistyped tuning variable should never cost somebody their session. `Ring::new`
/// clamps rather than asserts — the clamp keeps an abort site out of a `panic = "abort"`
/// binary — so what a lost filter costs is not a daemon that dies before it binds but a
/// session whose scrollback is one byte, which the round trip below still catches.
#[test]
fn a_ring_capacity_the_daemon_cannot_use_falls_back_to_the_default() {
    for (name, value) in [("ring_zero", "0"), ("ring_garbage", "not-a-number")] {
        let session = Session::start_with_raw_ring(name, value);
        let mut client = session.connect();
        let ok = client.hello(RESUME_FROM_START);

        // Serving, rather than merely having bound a socket: the socket is bound before
        // the ring is built, so a daemon that died over one leaves the file behind and
        // the harness's wait is satisfied by a corpse. The marker carries the case's own
        // name so that a timeout says which `NOMUX_RING_BYTES` the daemon choked on.
        let marker = format!("NOMUX-DEFAULT-RING-{name}");
        client.input(0, format!("echo {marker}\n").as_bytes());
        client.read_until(&marker, ok.resume_from);
    }
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
    let ok = second.hello(RESUME_FROM_START);

    first.expect_error(
        ErrorCode::Takeover,
        "an evicted client must learn it was a takeover, not a network fault",
    );
    // The refusal was the daemon's goodbye, and nothing may follow it — `expect_eof`
    // fails on a second `Error`, which would be the daemon refusing this peer for some
    // further reason rather than having finished with it.
    first.expect_eof("an Error{TAKEOVER}");

    // And the session is the newcomer's, which is the half the eviction exists for: a
    // round trip through the child, so what is asserted is a client that can drive the
    // shell rather than one that merely got a `HelloOk`.
    second.input(ok.in_applied, b"echo NOMUX-TOOK-OVER\n");
    second.read_until("NOMUX-TOOK-OVER", ok.resume_from);
}

/// The refusals an *attached* client can earn, and the session surviving each.
///
/// `handle_frame`'s "frame is not valid from a client" arm and both of `read_client`'s
/// `reject(Protocol, …)` sites have no other caller in the suite. The last of those is
/// the one that matters: a frame boundary the daemon has lost track of is a stream in
/// which every subsequent `Input` offset is somebody else's number.
///
/// Five rows reaching the refusal by three routes. A `HelloOk`, an `Output` and a `Gap`
/// are well-formed frames the *daemon* sends, so they decode perfectly and fall through
/// the match. A discriminant no `FrameType` has never reaches the match at all. And a
/// `Resize` whose payload is four bytes rather than eight has a header that decodes and
/// a body that does not — the one case where the daemon knows how many bytes to skip
/// and still must not. Each row asserts all three of what a refusal is: the code, that
/// the connection then closes without a second complaint — which is what
/// `Client::expect_eof` separates from a frame quietly *honoured* — and that a fresh
/// client can still drive the shell. One session for all five, so each row lands on one
/// the rows before it have abused.
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
            // `0xff` is past every variant, and the length is zero so that a daemon
            // which skipped the frame rather than refusing it would find the stream
            // still framed — the failure has to come from the unreadable header.
            write: |client| client.send_raw(&[0xff, 0x00, 0x00, 0x00]),
        },
        Refused {
            what: "a Resize whose payload is half a WinSize",
            // Four bytes where the frame's four `u16`s need eight.
            write: |client| client.send_raw(&[0x06, 0x00, 0x00, 0x04, 0, 80, 0, 24]),
        },
    ];

    let session = Session::start("refuse");
    // One deadline for the table, checked between rows (`harness::poll_by`): every wait
    // inside a row carries its own patience, so this is what bounds them in aggregate.
    let deadline = Instant::now() + FRAME_PATIENCE;
    let mut client = session.connect();
    let start = client.hello(RESUME_FROM_START).resume_from;

    for (round, case) in cases.iter().enumerate() {
        // Greeted *and* serving: the session is created by the first `Hello`, so a round
        // trip through the child is what puts the connection in the state this is about
        // rather than mid-handshake. A marker of the round's own, so a row cannot be
        // satisfied by the one before it.
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
/// The one `ErrorCode` a running daemon never produced anywhere else: the answer to the
/// single failure that can happen *after* a client has been accepted and before it has a
/// session, `Pty::spawn` failing. A client that gets silence there waits out its own
/// attach deadline instead of reporting a host whose `$SHELL` is wrong, and `DESIGN.md`
/// § 6.4 has the client treat `INTERNAL` and `PROTOCOL` differently. A directory rather
/// than a missing file, so the failure is `execve` refusing what it was handed:
/// `login_shell` falls back through the password database only when it is *absent*.
#[test]
fn a_session_whose_shell_cannot_be_started_is_refused_as_an_internal_failure() {
    let session = Session::start_with_shell("shell_broken", "/tmp");
    let mut client = session.connect();

    // By hand: `Client::hello` panics on anything but a `HelloOk`, and the refusal is
    // the whole point.
    client.send(&hello_frame(0, RESUME_FROM_START));
    client.expect_error_among_output(
        ErrorCode::Internal,
        "a shell that cannot be started must be reported as the daemon's failure",
    );
    client.expect_eof("an Error{INTERNAL}");
}

/// § 6.3's peer-credential rule from the side the suite can reach: a connection from
/// this uid is admitted and served, and the credentials the daemon admits it on are
/// the ones this host reports.
///
/// The refusal is the other side and needs a second uid, which the suite has no way to
/// become; `daemon.rs`'s `only_this_uid_may_have_the_session` holds that half against
/// the predicate. What a unit test cannot reach is the `getsockopt` itself, and a wrong
/// level, option or struct there answers `Err` for every peer — a session socket that
/// admits nobody. Every test in this file would fail with it and none would say why.
///
/// The probe is a bare connection because a `Client` keeps its socket to itself, and
/// because § 6.4 has connecting cost the attached client nothing.
#[test]
fn a_connection_from_this_uid_is_admitted_and_reports_its_credentials() {
    let (session, mut client, _ok) = Session::attached("peercred");

    let probe = UnixStream::connect(&session.socket).expect("connect to the session socket");
    assert_eq!(
        peer_uid(&probe),
        rustix::process::getuid().as_raw(),
        "the daemon serving this socket is the uid its clients are admitted for"
    );
    drop(probe);

    still_serving(&mut client, "NOMUX-ADMITTED");
}

/// The uid the kernel reports for the process at the other end of `stream` — for a
/// connected client, the one that called `listen`.
///
/// Through `libc` for `harness::shrink_send_buffer`'s reason: rustix's socket options
/// sit behind its `net` feature, which this tree does not enable.
fn peer_uid(stream: &UnixStream) -> u32 {
    use std::os::fd::AsRawFd;

    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut len = u32::try_from(size_of::<libc::ucred>()).expect("the size of a ucred");
    // SAFETY: `getsockopt` is given a `ucred` to fill and a `socklen_t` holding that
    // type's own size, both owned by this frame and unaliased across the call, on a
    // descriptor the borrow keeps open for it.
    let asked = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<libc::c_void>(),
            std::ptr::from_mut(&mut len),
        )
    };
    assert_eq!(
        asked,
        0,
        "SO_PEERCRED on a connected socket: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        usize::try_from(len).expect("what the kernel wrote"),
        size_of::<libc::ucred>(),
        "a partial ucred leaves the uid below whatever it was seeded with"
    );
    cred.uid
}

/// A connection that speaks out of turn is refused on its own terms, without
/// costing the session its client.
#[test]
fn a_connection_that_does_not_greet_first_is_refused_alone() {
    let (session, mut client, ok) = Session::attached("no_greeting");

    let mut rude = session.connect();
    rude.send(&Frame::Ping);
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
/// Nothing else in the suite sends a `0x06`. Both halves matter to the same user: the
/// window is resized while attached, and the session is then picked up from a terminal
/// of a different size. Asserted at the child both times, `stty` being the only witness
/// that the geometry was *applied* rather than merely received.
#[test]
fn a_resize_reaches_the_child_and_every_attach_restates_the_geometry() {
    let (session, mut client, ok) = Session::attached("resize");

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
    client.input(resumed.in_applied, b"stty size\n");
    client.read_until("24 80", resumed.resume_from);
}

/// `Detach` gives the connection up without giving up the session
/// (`IMPLEMENTATION.md` § 2.2).
///
/// Never sent by anything else here — every other departure in the suite is a socket
/// being dropped, the *unclean* case. What separates the deliberate one is that nothing
/// may be lost: the daemon closes the connection and keeps the input position, so the
/// client that comes back is told where it was rather than starting the stream again.
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
/// `owed` names the marker the fence cannot bound. `Ctrl-L` needs nothing, `cat` handing
/// the keystroke back along the same path as the fence; the `SIGWINCH` marker is printed
/// by a *second* process that `TIOCSWINSZ` has merely made runnable, and nothing orders
/// it against `cat` echoing the fence. § 4.3 obliges the repaint to happen, not to win
/// that race.
fn repaint_transcript(name: &str, flags: u8, owed: Option<&str>) -> String {
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
    let ok = client.hello_with(flags, RESUME_FROM_START);

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
    let resumed = client.hello_with(flags, offset);
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
/// `TIOCSWINSZ` in a row and standard signals do not queue — counting those would be
/// counting the scheduler. The child records what reaches its terminal in a file rather
/// than echoing it, because the stream back to the client is the very thing with holes
/// in it: a repaint issued mid-overflow is discarded by the next overflow, so counting
/// what reached the client would count only the repaints that did no harm.
///
/// The ring is larger than the megabyte of output the daemon queues for one client plus
/// the 256 KiB frame that overshoots it, which makes "still behind" structural rather
/// than timing: once the ring has overflowed it stays full, so the pass reporting a gap
/// can never also hand this client the whole of it.
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
    /// Between frames, so that the child outruns this client rather than the other way
    /// round — a frame per this is 25 MB/s, against the 150 MB/s the daemon was measured
    /// lifting off the PTY here. A client that keeps up never falls behind the ring.
    const PACE: Duration = Duration::from_millis(10);
    /// Printed by the flooder as its last act, so reaching it means the client has been
    /// queued the whole stream — the condition the repaint waits for. Arithmetic for the
    /// reason [`WINCHED`] is.
    const OVER: &str = "NOMUX-42-FLOOD-OVER";
    /// Sent as ordinary input once everything the repaint owes is behind it, so the
    /// count below is taken against a record that is complete.
    const FENCE: &[u8] = b"FENCE\n";

    // One deadline for the four consecutive waits below rather than one each
    // (`harness::poll_by`).
    let deadline = Instant::now() + FRAME_PATIENCE;
    let session = Session::start_with_ring("repaint_storm", RING);
    let mut client = session.connect();
    let ok = client.hello_with(HELLO_REPAINT_CTRL_L, RESUME_FROM_START);

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
    let (mut client, resumed) = reconnect_until_gap(&session, HELLO_REPAINT_CTRL_L, ready.offset);

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

/// Where `needle` starts in `haystack`. `[u8]` has no `find`, and the record this
/// reads is bytes rather than text: the daemon's repaint keystroke is `0x0c`.
fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

    let command = b"true NOMUX-KEEP\n";
    let mut expected = 0u64;

    for round in 0..15 {
        let mut next = session.connect();
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

    client.input(ok.in_applied, b"echo NOMUX-STILL-HERE\n");
    client.read_until("NOMUX-STILL-HERE", ok.resume_from);
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
/// (`startup::silence_stdio` has the argument). That is a guarantee from outside this
/// tree and invisible inside it, which is exactly why the property is asserted rather
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

    let socket = root.join("nomux").join("nsd.sock");
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
    hello_frame(0, RESUME_FROM_START)
        .encode(&mut hello)
        .expect("encode a Hello");
    if stream.write_all(&hello).is_err() {
        return false;
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut seen = Vec::new();
    while seen.len() < HEADER_LEN {
        if Instant::now() >= deadline {
            return false;
        }
        let mut chunk = [0u8; HEADER_LEN];
        match read_uninterrupted(&mut stream, &mut chunk) {
            Ok(0) => return false,
            Ok(n) => seen.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            // The read timeout expiring, which is the deadline above's to answer.
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
    let Some(head) = seen.get(..HEADER_LEN).and_then(|head| head.try_into().ok()) else {
        return false;
    };
    decode_header(head).is_ok_and(|header| header.ty == FrameType::HelloOk)
}
