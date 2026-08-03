//! Randomised disconnect injection (`IMPLEMENTATION.md` § 9).
//!
//! The other end-to-end tests sever the connection at points a human chose. These
//! sever it at points a generator chose, under the two workloads that break the
//! assumptions a shell transcript does not exercise: an escape-heavy full-screen
//! stream, where losing or duplicating one byte corrupts everything after it, and
//! an unbounded firehose, where the ring overflows while the client is away.
//!
//! The invariants under test are § 9's two: no duplicated input, and no lost
//! output unless a `Gap` was reported.
//!
//! Disconnect points come from a fixed seed so a failure is reproducible; override
//! it with `NOMUX_CHAOS_SEED` to explore other interleavings.

mod harness;

use std::time::{Duration, Instant};

use nomux_proto::{Frame, RESUME_FROM_START};

use harness::{Rng, Session};

/// Iterations of the escape-sequence emitter. Enough output to arrive as many
/// separate reads, so disconnects land mid-stream rather than between commands.
const EMIT_ROUNDS: u32 = 20_000;

/// Seed used when `NOMUX_CHAOS_SEED` is unset.
const DEFAULT_SEED: u64 = 0x6e6f_6d75_785f_3031;

fn chaos_seed() -> u64 {
    std::env::var("NOMUX_CHAOS_SEED")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

/// One iteration of the emitter's output: cursor addressing, an SGR colour, a
/// four-digit counter, a minimal sixel image, and a reset.
///
/// Chosen because every part of it is a *sequence*: a byte lost anywhere in here
/// does not merely lose a character, it changes the meaning of everything the
/// emulator reads afterwards. That is what makes byte-exactness the property
/// worth asserting.
fn emitted_chunk(i: u32) -> String {
    format!(
        "\x1b[{row};1H\x1b[38;5;{colour}m{i:04}\x1bPq#0;2;0;0;0~~\x1b\\\x1b[0m|",
        row = i % 24 + 1,
        colour = i % 256,
    )
}

/// Rounds between the emitter's pauses. See [`emitter_command`].
const BURST: u32 = 500;

/// The shell command that produces exactly [`emitted_chunk`] for each round,
/// bracketed by markers.
///
/// The pause every [`BURST`] rounds is what makes this a test rather than a
/// formality: without it the child outruns the client, the daemon coalesces the
/// whole run into two or three maximum-size frames, and there are almost no
/// moments at which a disconnect can land. Its stderr is discarded because a
/// `sleep` without sub-second support would otherwise write a complaint into the
/// very stream being compared.
fn emitter_command(rounds: u32) -> String {
    format!(
        "printf 'CHAOS-BEGIN'; i=0; while [ $i -lt {rounds} ]; do \
         printf '\\033[%d;1H\\033[38;5;%dm%04d\\033Pq#0;2;0;0;0~~\\033\\\\\\033[0m|' \
         $((i%24+1)) $((i%256)) $i; i=$((i+1)); \
         [ $((i%{BURST})) -eq 0 ] && sleep 0.02 2>/dev/null; done; printf 'CHAOS-END'\n"
    )
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A full-screen stream survives disconnects byte for byte.
///
/// The ring is large enough that nothing can be dropped, so the reconstructed
/// stream must equal what the child wrote, exactly, with no gap reported and no
/// byte repeated across a resume.
#[test]
fn an_escape_heavy_stream_is_byte_exact_across_random_disconnects() {
    let chaos_seed = chaos_seed();
    let session = Session::start_with_ring("chaos_exact", 8 << 20);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);

    // Echo and newline translation silenced, so what arrives is exactly what the
    // child wrote and the comparison below can be literal.
    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let mut offset = ready.offset;
    let mut in_offset = ready.in_offset;

    let command = emitter_command(EMIT_ROUNDS);
    client.input(in_offset, command.as_bytes());
    in_offset += command.len() as u64;

    let mut rng = Rng::new(chaos_seed);
    let mut seen: Vec<u8> = Vec::new();
    let mut disconnects = 0u32;
    let mut since_disconnect = 0usize;
    let deadline = Instant::now() + Duration::from_mins(1);

    while find(&seen, b"CHAOS-END").is_none() {
        assert!(
            Instant::now() < deadline,
            "emitter never finished (seed {chaos_seed})"
        );
        let (ty, payload) = client.next_frame();
        match Frame::decode(ty, &payload).expect("decode frame") {
            Frame::Output { offset: at, data } => {
                assert_eq!(
                    at, offset,
                    "output offsets must be contiguous (seed {chaos_seed})"
                );
                offset += data.len() as u64;
                since_disconnect += data.len();
                seen.extend_from_slice(data);
            }
            Frame::InputAck { .. } | Frame::Pong { .. } => {}
            Frame::Gap { .. } => panic!("an 8 MiB ring must not overflow on {EMIT_ROUNDS} rounds"),
            other => panic!("unexpected {other:?} (seed {chaos_seed})"),
        }

        // By volume rather than by frame count: one frame can carry anything from
        // a few bytes to `MAX_PAYLOAD`, so counting frames would make the
        // disconnect rate depend on how fast the machine happens to be.
        if since_disconnect >= 4 * 1024 + usize::try_from(rng.below(12 * 1024)).unwrap_or(0) {
            drop(client);
            client = session.connect();
            let resumed = client.hello(offset, in_offset);
            assert!(
                !resumed.gap,
                "nothing should be dropped (seed {chaos_seed})"
            );
            assert_eq!(
                resumed.resume_from, offset,
                "resume must be exact (seed {chaos_seed})"
            );
            assert_eq!(
                resumed.in_applied, in_offset,
                "input position must survive the drop (seed {chaos_seed})"
            );
            disconnects += 1;
            since_disconnect = 0;
        }
    }

    assert!(
        disconnects >= 3,
        "only {disconnects} disconnects landed; the test proved little (seed {chaos_seed})"
    );

    let begin = find(&seen, b"CHAOS-BEGIN").expect("start marker") + b"CHAOS-BEGIN".len();
    let expected: String = (0..EMIT_ROUNDS).map(emitted_chunk).collect();
    let expected = format!("{expected}CHAOS-END");
    let got = seen.get(begin..begin + expected.len()).unwrap_or_default();

    if got != expected.as_bytes() {
        let at = got
            .iter()
            .zip(expected.as_bytes())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| got.len().min(expected.len()));
        let from = at.saturating_sub(40);
        panic!(
            "stream diverged at byte {at} of {} after {disconnects} disconnects (seed {chaos_seed})\n\
             expected: {:?}\n     got: {:?}",
            expected.len(),
            String::from_utf8_lossy(&expected.as_bytes()[from..(at + 40).min(expected.len())]),
            String::from_utf8_lossy(&got[from..(at + 40).min(got.len())]),
        );
    }
}

/// Under a firehose and a ring too small to hold it, every byte that goes missing
/// is accounted for by a gap — and everything between gaps is still contiguous.
///
/// This is the other half of § 9's invariant. The client cannot be told "here is
/// where you are" and then quietly handed a stream with a hole in it.
#[test]
fn overflow_during_disconnects_is_always_reported() {
    let chaos_seed = chaos_seed();
    let session = Session::start_with_ring("chaos_firehose", 32 * 1024);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);

    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let mut offset = ready.offset;
    let mut in_offset = ready.in_offset;

    // `yes` outruns anything the client can do about it, which is the point.
    let command = b"yes\n";
    client.input(in_offset, command);
    in_offset += command.len() as u64;
    // Wait for the first of its output before starting to disconnect. Otherwise
    // the very first drop could discard the command itself — a client that closes
    // with output queued makes the kernel send RST, taking unread input with it —
    // and the test would sit waiting for a firehose that was never started.
    //
    // Past a gap rather than refusing one, which `read_until` would: the daemon
    // takes 64 KiB off the PTY in a single pass against the 32 KiB ring above, so
    // `yes` can overrun this client between the input frame and the first output
    // frame — and § 9 then *obliges* the daemon to report a `Gap`. Refusing it here
    // would fail the test for the behaviour it exists to demand. The gap is not
    // counted: `gaps` below is what the disconnect loop observed, and a setup that
    // could satisfy the closing assertion on its own would leave that loop proving
    // nothing. What this waits for is unchanged — a byte the firehose actually
    // wrote — and the contiguity of everything between gaps is still asserted.
    let (_, started) = client.read_past_gaps("y", offset);
    offset = started;

    let mut rng = Rng::new(chaos_seed);
    let mut gaps = 0u32;
    let mut received = 0u64;
    let deadline = Instant::now() + Duration::from_mins(1);

    for round in 0..24 {
        assert!(
            Instant::now() < deadline,
            "firehose stalled (seed {chaos_seed})"
        );
        // Read a few frames, then vanish for a moment so the ring overflows.
        for _ in 0..=rng.below(4) {
            let (ty, payload) = client.next_frame();
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(
                        at, offset,
                        "round {round}: output must be contiguous unless a gap said otherwise \
                         (seed {chaos_seed})"
                    );
                    offset += data.len() as u64;
                    received += data.len() as u64;
                    assert!(
                        data.iter().all(|byte| *byte == b'y' || *byte == b'\n'),
                        "round {round}: stream corrupted (seed {chaos_seed})"
                    );
                }
                Frame::Gap { new_base_offset } => {
                    assert!(
                        new_base_offset > offset,
                        "round {round}: a gap must move the stream forward (seed {chaos_seed})"
                    );
                    offset = new_base_offset;
                    gaps += 1;
                }
                Frame::InputAck { .. } | Frame::Pong { .. } => {}
                other => panic!("round {round}: unexpected {other:?} (seed {chaos_seed})"),
            }
        }

        drop(client);
        std::thread::sleep(Duration::from_millis(rng.below(30)));
        client = session.connect();
        let resumed = client.hello(offset, in_offset);
        assert!(
            resumed.resume_from >= offset,
            "round {round}: the daemon must never rewind (seed {chaos_seed})"
        );
        assert_eq!(
            resumed.gap,
            resumed.resume_from > offset,
            "round {round}: a moved resume point is exactly what `gap` reports (seed {chaos_seed})"
        );
        if resumed.gap {
            gaps += 1;
        }
        offset = resumed.resume_from;
    }

    assert!(received > 0, "no output at all (seed {chaos_seed})");
    assert!(
        gaps > 0,
        "a 32 KiB ring under `yes` should have overflowed at least once (seed {chaos_seed}); \
         received {received} bytes"
    );
}

/// Input is applied exactly once, whatever the disconnect pattern.
///
/// This is § 3 played out as a client actually experiences it. Every round writes
/// a line and then severs the connection immediately, so each frame lands in one
/// of three states: fully applied, partly applied, or lost entirely — a client that
/// closes with output still queued makes the kernel send RST, and the daemon answers
/// the `ECONNRESET` that follows by letting the connection go without decoding what
/// it had just read from it (§ 3). The client responds the way the
/// protocol says: take the daemon's `in_applied` as authoritative and resend from
/// there, deliberately overlapping into bytes already applied so the trimming path
/// is exercised too.
///
/// The shell counts what it actually received, and the count is what proves the
/// invariant: every line runs, and none runs twice.
#[test]
fn replayed_input_across_random_disconnects_is_applied_once() {
    let chaos_seed = chaos_seed();
    let session = Session::start_with_ring("chaos_input", 4 << 20);
    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START, 0);

    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let mut offset = ready.offset;
    // Everything the client has ever wanted the child to receive, the setup line
    // included. A real client keeps exactly this, because it is what a resend is
    // drawn from.
    let mut intended: Vec<u8> = ready.line.into_bytes();

    let mut rng = Rng::new(chaos_seed);
    let line = b"printf M\n";
    let rounds = 12usize;
    let mut applied = intended.len() as u64;

    for round in 0..rounds {
        intended.extend_from_slice(line);
        let from = usize::try_from(applied).expect("offset fits");
        client.input(applied, &intended[from..]);

        drop(client);
        client = session.connect();
        let resumed = client.hello(offset, intended.len() as u64);
        assert!(
            resumed.in_applied <= intended.len() as u64,
            "round {round}: the daemon applied input the client never sent (seed {chaos_seed})"
        );
        assert!(
            resumed.in_applied >= applied,
            "round {round}: applied input must never go backwards (seed {chaos_seed})"
        );
        offset = resumed.resume_from;

        // Resend from a point slightly before what the daemon reports, so the
        // overlap has to be trimmed rather than run a second time.
        applied = resumed.in_applied.saturating_sub(rng.below(6));
    }

    // A fence proves everything before it has been through the PTY.
    intended.extend_from_slice(b"printf FENCE\n");
    let from = usize::try_from(applied).expect("offset fits");
    client.input(applied, &intended[from..]);
    let (seen, _) = client.read_until("FENCE", offset);
    let marks = seen.matches('M').count();
    assert_eq!(
        marks, rounds,
        "each line must run exactly once; transcript: {seen:?} (seed {chaos_seed})"
    );
}
