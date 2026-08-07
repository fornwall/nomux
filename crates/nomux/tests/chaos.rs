//! Randomised disconnect injection (`IMPLEMENTATION.md` § 9).
//!
//! The other end-to-end tests sever the connection where a human chose; these sever it
//! where a generator chose, under the workloads a shell transcript does not exercise:
//! an escape-heavy full-screen stream, where one byte lost or duplicated corrupts
//! everything after it, and an unbounded firehose, where the ring overflows while the
//! client is away. § 9's two invariants — no duplicated input, and no lost output
//! unless a `Gap` was reported.
//!
//! - Bytes survive a disconnect exactly:
//!   [`an_escape_heavy_stream_is_byte_exact_across_random_disconnects`].
//! - Every byte lost to overflow is announced:
//!   [`overflow_during_disconnects_is_always_reported`].
//! - Input is applied once whatever the disconnect pattern:
//!   [`replayed_input_across_random_disconnects_is_applied_once`].
//! - The daemon's own boundaries — a `MAX_PAYLOAD` chunk, a send queue that filled
//!   mid-slice, a ring that rolled — cut a full-screen program's escape sequences in
//!   half without ever losing or repeating a byte:
//!   [`a_full_screen_stream_is_byte_exact_across_gaps_that_cut_its_escape_sequences`].
//!
//! Disconnect points come from a fixed seed so a failure is reproducible; override it
//! with `NOMUX_CHAOS_SEED` to explore other interleavings.

#![allow(
    clippy::panic,
    clippy::expect_used,
    reason = "clippy.toml's allow-panic-in-tests and allow-expect-in-tests reach \
              `#[test]` bodies, not the helpers an integration test crate keeps \
              beside them"
)]

mod harness;

use std::fmt::Write as _;
use std::fs;
use std::ops::Range;
use std::time::{Duration, Instant};

use nomux::{Frame, MAX_PAYLOAD, RESUME_FROM_START};

use harness::{Rng, Session, poll_by, socket_capacity};

/// `conn::MAX_PENDING_WRITE`, private to the daemon: what § 4.1 has it queue for a slow
/// client before it stops adding. Mirrored here as the harness mirrors its neighbours,
/// and the two must move together. Both tests below want it as an upper bound on how
/// far ahead of a client's own reads the daemon can be.
const MAX_PENDING_WRITE: usize = 1 << 20;

/// Iterations of the escape-sequence emitter. Enough output to arrive as many
/// separate reads, so disconnects land mid-stream rather than between commands.
const EMIT_ROUNDS: u32 = 20_000;

/// How long a chaos test waits for its workload before calling it stalled.
///
/// Under the forty-second kill in `.config/nextest.toml`, since a deadline at or above
/// that can never fire — and a stall killed from outside says nothing, losing § 9's
/// promise that every chaos failure carries its seed. Spent once per test, per
/// `harness::poll_by`. All four finish in under two seconds.
const PATIENCE: Duration = Duration::from_secs(20);

/// Seed used when `NOMUX_CHAOS_SEED` is unset.
const DEFAULT_SEED: u64 = 0x6e6f_6d75_785f_3031;

/// The next frame, bounded by the whole test's `deadline` rather than by one frame's
/// (`harness::poll_by`), and saying which seed the stall was under.
fn frame_by(
    client: &mut harness::Client,
    deadline: Instant,
    seed: u64,
    stalled: &str,
) -> (nomux::FrameType, Vec<u8>) {
    client
        .frame_before(deadline, stalled)
        .unwrap_or_else(|| panic!("{stalled} (seed {seed})"))
}

fn chaos_seed() -> u64 {
    std::env::var("NOMUX_CHAOS_SEED")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

/// One iteration of the emitter's output: cursor addressing, an SGR colour, a
/// four-digit counter, a minimal sixel image, and a reset.
///
/// Every part of it is a *sequence*, so a byte lost anywhere in here does not merely
/// lose a character — it changes the meaning of everything read afterwards. That is
/// what makes byte-exactness the property worth asserting.
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
/// The pause every [`BURST`] rounds is what makes this a test rather than a formality:
/// without it the child outruns the client, the daemon coalesces the run into two or
/// three maximum-size frames, and there is almost nowhere for a disconnect to land. Its
/// stderr is discarded because a `sleep` without sub-second support would otherwise
/// write a complaint into the very stream being compared.
fn emitter_command(rounds: u32) -> String {
    format!(
        "printf 'CHAOS-BEGIN'; i=0; while [ $i -lt {rounds} ]; do \
         printf '\\033[%d;1H\\033[38;5;%dm%04d\\033Pq#0;2;0;0;0~~\\033\\\\\\033[0m|' \
         $((i%24+1)) $((i%256)) $i; i=$((i+1)); \
         [ $((i%{BURST})) -eq 0 ] && sleep 0.02 2>/dev/null; done; printf 'CHAOS-END'\n"
    )
}

/// What `yes` writes `since` bytes into its output. Checking against position rather
/// than against "a `y` or a newline" is what catches a byte dropped, duplicated or
/// reordered inside the stream — as far as period 2 reaches, a stream shifted by an even
/// number passing the comparison and being left to the contiguity assertion beside it.
/// Carrying the content property on an aperiodic payload is [`Screen::image`]'s job, in
/// the test written for it; here volume is the point, and a byte that costs more to
/// generate is a byte fewer through the ring.
const fn yes_byte(since: u64) -> u8 {
    if since.is_multiple_of(2) { b'y' } else { b'\n' }
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A full-screen stream survives disconnects byte for byte: the ring is large enough
/// that nothing can be dropped, so the reconstructed stream must equal what the child
/// wrote exactly, with no gap reported and no byte repeated across a resume.
#[test]
fn an_escape_heavy_stream_is_byte_exact_across_random_disconnects() {
    let chaos_seed = chaos_seed();
    let session = Session::start_with_ring("chaos_exact", 8 << 20);
    let deadline = Instant::now() + PATIENCE;
    let mut client = session.connect();
    client.waits_by(deadline);
    let ok = client.hello(RESUME_FROM_START);

    // Echo and newline translation silenced, so what arrives is exactly what the child
    // wrote and the comparison below can be literal.
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
    let mut next_at = 4 * 1024 + usize::try_from(rng.below(12 * 1024)).unwrap_or(0);

    while find(&seen, b"CHAOS-END").is_none() {
        let (ty, payload) = frame_by(&mut client, deadline, chaos_seed, "emitter never finished");
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
            Frame::InputAck { .. } | Frame::Pong => {}
            Frame::Gap { .. } => panic!("an 8 MiB ring must not overflow on {EMIT_ROUNDS} rounds"),
            other => panic!("unexpected {other:?} (seed {chaos_seed})"),
        }

        // By volume rather than frame count: one frame carries anything from a few
        // bytes to `MAX_PAYLOAD`, so counting frames would make the disconnect rate
        // depend on how fast the machine happens to be; and the threshold is drawn
        // once per disconnect rather than per frame, so the seed replays the run.
        if since_disconnect >= next_at {
            drop(client);
            client = session.connect();
            client.waits_by(deadline);
            let resumed = client.hello_before(deadline, offset);
            assert!(
                !resumed.gap(offset),
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
            next_at = 4 * 1024 + usize::try_from(rng.below(12 * 1024)).unwrap_or(0);
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

/// Under a firehose and a ring too small to hold it, every byte that goes missing is
/// accounted for by a gap — and everything between gaps is still contiguous. § 9's
/// other half: a client cannot be told where it is and then handed a stream with an
/// unannounced hole in it.
#[test]
fn overflow_during_disconnects_is_always_reported() {
    let chaos_seed = chaos_seed();
    let session = Session::start_with_ring("chaos_firehose", 32 * 1024);
    let deadline = Instant::now() + PATIENCE;
    let mut client = session.connect();
    client.waits_by(deadline);
    let ok = client.hello(RESUME_FROM_START);

    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let mut offset = ready.offset;
    let in_offset = ready.in_offset;

    // `yes` outruns anything the client can do about it, which is the point.
    let command = b"yes\n";
    client.input(in_offset, command);
    // Wait for the first output before disconnecting: otherwise the first drop could
    // discard the command itself — a client that closes with output queued makes the
    // kernel send RST, taking unread input with it — and the test would sit waiting for
    // a firehose that was never started. Past a gap rather than refusing one, since
    // overflow against a 32 KiB ring is obliged here rather than a surprise; neither
    // counter below sees this one, so a setup satisfying them alone proves nothing.
    let (_, started) = client.read_past_gaps("y", offset);
    offset = started;

    let mut rng = Rng::new(chaos_seed);
    let capacity = socket_capacity();
    // Two promises, counted apart: § 9 obliges the daemon to announce an overflow to an
    // *attached* client, and to move the resume point of one that comes back.
    let mut announced_gaps = 0u32;
    let mut resume_gaps = 0u32;
    let mut received = 0u64;

    for round in 0..24 {
        // Read past everything already queued, because § 9's announcement is behind all
        // of it: the daemon fills `MAX_PENDING_WRITE` and the socket beneath it, stops adding, and
        // appends the `Gap` it then owes to the back of that queue. The random tail
        // keeps the disconnect below off the announcement.
        let through =
            MAX_PENDING_WRITE + capacity + usize::try_from(rng.below(16 * 1024)).unwrap_or(0);
        let mut read = 0usize;
        while read < through {
            let (ty, payload) = frame_by(&mut client, deadline, chaos_seed, "firehose stalled");
            read += payload.len();
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(
                        at, offset,
                        "round {round}: output must be contiguous unless a gap said otherwise \
                         (seed {chaos_seed})"
                    );
                    let since = at - ready.offset;
                    let wrong = (data.iter().enumerate())
                        .position(|(i, byte)| *byte != yes_byte(since + i as u64));
                    assert!(
                        wrong.is_none(),
                        "round {round}: byte {wrong:?} of the frame at {at} is not the one \
                         the firehose wrote there (seed {chaos_seed})"
                    );
                    offset += data.len() as u64;
                    received += data.len() as u64;
                }
                Frame::Gap { new_base_offset } => {
                    assert!(
                        new_base_offset > offset,
                        "round {round}: a gap must move the stream forward (seed {chaos_seed})"
                    );
                    offset = new_base_offset;
                    announced_gaps += 1;
                }
                Frame::InputAck { .. } | Frame::Pong => {}
                other => panic!("round {round}: unexpected {other:?} (seed {chaos_seed})"),
            }
        }

        drop(client);
        std::thread::sleep(Duration::from_millis(rng.below(30)));
        client = session.connect();
        client.waits_by(deadline);
        let resumed = client.hello_before(deadline, offset);
        assert!(
            resumed.resume_from >= offset,
            "round {round}: the daemon must never rewind (seed {chaos_seed})"
        );
        // A moved resume point is exactly what a gap is (`HelloOk::gap`).
        if resumed.gap(offset) {
            resume_gaps += 1;
        }
        offset = resumed.resume_from;
    }

    assert!(
        announced_gaps > 0,
        "the daemon never told an attached client it had dropped anything, so § 9's \
         announcement went untested (seed {chaos_seed}); received {received} bytes"
    );
    assert!(
        resume_gaps > 0,
        "a 32 KiB ring under `yes` should have overflowed at least once while the \
         client was away (seed {chaos_seed}); received {received} bytes"
    );
}

/// Input is applied exactly once, whatever the disconnect pattern (§ 3).
///
/// Every round writes a line and severs the connection at once, so each frame lands
/// fully applied, partly applied, or lost entirely — a client that closes with output
/// queued makes the kernel send RST, and the daemon answers the `ECONNRESET` by letting
/// the connection go without decoding what it had just read. The client then does what
/// the protocol says: take `in_applied` as authoritative and resend from there,
/// deliberately overlapping into applied bytes so the trimming path runs too. The
/// shell's own count of what reached it is the proof: every line once, none twice.
#[test]
fn replayed_input_across_random_disconnects_is_applied_once() {
    let chaos_seed = chaos_seed();
    let session = Session::start_with_ring("chaos_input", 4 << 20);
    // One deadline for all twelve rounds, as the two tests above have — handed to every
    // client the loop makes, since a fresh one would otherwise start the budget again.
    let deadline = Instant::now() + PATIENCE;
    let mut client = session.connect();
    client.waits_by(deadline);
    let ok = client.hello(RESUME_FROM_START);

    let ready = client.make_ready("-echo -onlcr", None, ok.resume_from);
    let mut offset = ready.offset;
    // Everything the client has ever wanted the child to receive, the setup line
    // included: a real client keeps exactly this, being what a resend is drawn from.
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
        client.waits_by(deadline);
        let resumed = client.hello_before(deadline, offset);
        assert!(
            resumed.in_applied <= intended.len() as u64,
            "round {round}: the daemon applied input the client never sent (seed {chaos_seed})"
        );
        assert!(
            resumed.in_applied >= applied,
            "round {round}: applied input must never go backwards (seed {chaos_seed})"
        );
        offset = resumed.resume_from;

        // Slightly before what the daemon reports, so the overlap has to be trimmed
        // rather than run a second time.
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

/// Ring capacity for
/// [`a_full_screen_stream_is_byte_exact_across_gaps_that_cut_its_escape_sequences`].
///
/// Above [`MAX_PENDING_WRITE`] plus the one [`MAX_PAYLOAD`] chunk `Conn::send_output`
/// may overshoot it by, which is the whole reason for the figure: past that, no single
/// pass of `pump_output` can queue the ring whole, so `send_output` has to stop partway
/// through a slice of it and the next pass has to resume on exactly the byte it stopped
/// at. Every other ring in the suite is 128 KiB or smaller — under one chunk, where that
/// arithmetic never runs — bar `tests/session.rs`'s repaint storm, whose 2 MiB reaches it
/// but reads the result for contiguity and a repaint count rather than for what the bytes
/// are.
const SCREEN_RING: usize = 1536 * 1024;

/// A synthetic full-screen program: every byte it will write, and where its escape
/// sequences begin and end.
///
/// Written for the test rather than driving a real `vim`, whose version, terminfo and
/// configuration would decide what the suite asserts. What a full-screen program adds
/// over a shell transcript is not the *meaning* of its escapes — the daemon is
/// byte-blind and could not act on it — but their *length*: a sixel image longer than
/// the ring makes it arithmetic rather than luck that a gap resumes strictly inside a
/// sequence, which is the state `IMPLEMENTATION.md` § 4.3 has the client reset its
/// emulator over.
struct Screen {
    /// Everything the child writes, in order: index `i` is stream offset
    /// `stream_start + i`.
    bytes: Vec<u8>,
    /// Half-open ranges over [`Screen::bytes`], one per escape sequence, ascending and
    /// disjoint — which is what lets [`Screen::straddled`] binary-search them.
    sequences: Vec<Range<usize>>,
    /// One past the last byte of each round's slice.
    rounds: Vec<usize>,
}

/// Glyph runs the redraw writes between its escapes.
///
/// Wide, combining and astral characters among them, so the boundaries this test is
/// about cut multi-byte characters in half as well as escape sequences — the other half
/// of what a client resuming mid-stream has to survive, and one the daemon is equally
/// not allowed to have an opinion about.
const GLYPHS: [&str; 8] = [
    "nomux",
    "\u{65e5}\u{672c}\u{8a9e}",
    "e\u{0301}\u{0331}",
    "\u{1f680}\u{1f680}",
    "\u{2502}\u{2500}\u{250c}\u{2518}",
    "0123456789",
    "\u{ff21}\u{ff22}\u{ff23}",
    "abcdefghijklmnop",
];

impl Screen {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            sequences: Vec::new(),
            rounds: Vec::new(),
        }
    }

    /// Appends an escape sequence, recording where it sits so that a boundary landing
    /// inside it can be recognised.
    fn sequence(&mut self, body: &str) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(body.as_bytes());
        self.sequences.push(start..self.bytes.len());
    }

    /// Appends bytes belonging to no sequence.
    fn text(&mut self, body: &str) {
        self.bytes.extend_from_slice(body.as_bytes());
    }

    /// Appends a sixel image of `payload` bytes as one DCS sequence.
    ///
    /// The payload is drawn from `?`..`~` — the sixel alphabet, and, far more to the
    /// point here, an alphabet with no `ESC` in it: one stray `0x1b` would make
    /// [`Screen::sequences`] a lie about the stream it describes. Random rather than
    /// patterned for [`Rng::bytes`]'s reason, a repeating payload being one a stream
    /// shifted by a whole period passes a byte comparison against.
    fn image(&mut self, rng: &mut Rng, payload: usize) {
        let start = self.bytes.len();
        self.bytes
            .extend_from_slice(b"\x1bPq\"1;1;800;480#0;2;0;0;0");
        let mut data = rng.bytes(payload);
        for byte in &mut data {
            *byte = 0x3f + *byte % 0x40;
        }
        self.bytes.extend_from_slice(&data);
        self.bytes.extend_from_slice(b"\x1b\\");
        self.sequences.push(start..self.bytes.len());
    }

    /// Closes a round off at whatever has been written so far.
    fn round(&mut self) {
        self.rounds.push(self.bytes.len());
    }

    /// The escape sequence `at` falls strictly inside, if any.
    ///
    /// Strictly, because a boundary *on* the `ESC` or one past the final byte splits the
    /// stream between sequences, which is the case that costs a client nothing.
    fn straddled(&self, at: usize) -> Option<&Range<usize>> {
        let next = self.sequences.partition_point(|seq| seq.end <= at);
        self.sequences.get(next).filter(|seq| seq.start < at)
    }
}

/// One glyph run, chosen by the seed so that a stream shifted by a few bytes stops
/// matching almost at once.
fn glyph(rng: &mut Rng) -> &'static str {
    let at = usize::try_from(rng.below(GLYPHS.len() as u64)).unwrap_or(0);
    GLYPHS.get(at).copied().unwrap_or("nomux")
}

/// One redraw of the synthetic program, in the order a full-screen application does it:
/// onto the alternate screen, a scroll region, then a row at a time addressed
/// absolutely and coloured before it is written.
fn redraw(screen: &mut Screen, rng: &mut Rng) {
    /// Rows the synthetic program paints, matching `harness::WIN`.
    const ROWS: u32 = 24;

    screen.sequence("\x1b[?1049h");
    screen.sequence(&format!("\x1b[1;{ROWS}r"));
    screen.sequence("\x1b[2J");
    for row in 1..=ROWS {
        screen.sequence(&format!("\x1b[{row};1H"));
        screen.sequence(&format!(
            "\x1b[38;5;{};48;5;{}m",
            rng.below(256),
            rng.below(256)
        ));
        for _ in 0..=rng.below(4) {
            screen.text(glyph(rng));
        }
        screen.sequence("\x1b[K");
    }
    screen.sequence("\x1b[0m");
    screen.sequence("\x1b[?1049l");
}

/// What the client does with a round's output once the child has written all of it.
///
/// Fixed rather than drawn from the seed, because each one is a different assertion
/// about where the daemon stands afterwards, and a round that could be any of them
/// could assert none of them. The seed decides the sizes and how much of a round the
/// client bothers to read.
#[derive(Clone, Copy, Debug)]
enum Round {
    /// Read this many bytes of the stream and stay attached; `usize::MAX` for all of it.
    Read(usize),
    /// Read none of it and come back on a fresh connection. The slice is longer than the
    /// ring, so § 4.2's comparison owes the newcomer a gap at the handshake.
    ReattachOverGap,
    /// Read none of it and come back, having stayed inside the ring: the handshake owes
    /// nothing and must resume on the very byte this client left off at.
    ReattachExact,
    /// Read none of it while staying attached, so what announces the loss is the
    /// mid-stream `Gap` frame `pump_output` sends rather than the handshake's comparison.
    ReadThroughGap,
}

/// The whole workload: the bytes the child will write, cut into the rounds the client
/// drives it through one line at a time, and what the client does after each.
///
/// `queued_ahead` is how far in front of a client's own reads the daemon can stand —
/// § 4.1's megabyte, the one chunk `send_output` may overshoot it by, and the kernel's
/// socket buffers. A round that means to gap an *attached* client has to beat the ring
/// and all of that; one that gaps a client which has read nothing has only the ring to
/// beat, nothing else being able to hold a byte on that client's behalf.
fn workload(rng: &mut Rng, queued_ahead: usize) -> (Screen, Vec<Round>) {
    /// A round of ordinary redraws: small against the ring, so it can never gap anyone
    /// by itself.
    const CHATTER: usize = 96 * 1024;
    /// What a round has to write past the ring to be sure of gapping a detached client.
    const OVER: usize = 256 * 1024;

    let mut screen = Screen::new();
    let mut plan = Vec::new();
    let chatter = |screen: &mut Screen, rng: &mut Rng| {
        let target = screen.bytes.len() + CHATTER;
        while screen.bytes.len() < target {
            redraw(screen, rng);
        }
        screen.round();
    };

    // Warm up: everything drained, so what follows starts from a client that is exactly
    // caught up and every gap below is arithmetic on the ring alone.
    chatter(&mut screen, rng);
    plan.push(Round::Read(usize::MAX));

    screen.image(rng, SCREEN_RING + OVER);
    screen.round();
    plan.push(Round::ReattachOverGap);

    // Behind by a random amount, so the mid-stream gap below is met from a position
    // nothing about the test chose.
    chatter(&mut screen, rng);
    plan.push(Round::Read(
        usize::try_from(rng.below(CHATTER as u64)).unwrap_or(0),
    ));

    screen.image(rng, SCREEN_RING + queued_ahead + OVER);
    screen.round();
    plan.push(Round::ReadThroughGap);

    chatter(&mut screen, rng);
    plan.push(Round::ReattachExact);

    // A second handshake gap, this time on a stream that has already been through a
    // mid-stream one — the case where a daemon that recorded the first in per-connection
    // state would have carried it across a connection that no longer exists.
    screen.image(rng, SCREEN_RING + OVER);
    screen.round();
    plan.push(Round::ReattachOverGap);

    (screen, plan)
}

/// The client's side of the model: what the child wrote, where on the stream it
/// started, and what the daemon's boundaries have landed on so far.
struct Replay<'a> {
    screen: &'a Screen,
    stream_start: u64,
    seed: u64,
    deadline: Instant,
    /// Every gap followed, as the offset the stream stood at and the one it resumed on.
    gaps: Vec<(u64, u64)>,
    /// `Output` frames whose first byte falls strictly inside an escape sequence.
    straddling_frames: u64,
    /// Gaps whose resume point does.
    straddling_gaps: u64,
}

/// A window of `bytes` around `at`, with the control bytes spelled out.
///
/// Read back raw, a stream of escape sequences would put the terminal running the test
/// into the state the failure is about — alternate screen, scroll region and all — which
/// is a poor way to report one.
fn quote(bytes: &[u8], at: usize) -> String {
    let mut out = String::new();
    let window = bytes
        .get(at.saturating_sub(24)..(at + 24).min(bytes.len()))
        .unwrap_or_default();
    for byte in window {
        match byte {
            0x1b => out.push_str("<ESC>"),
            0x20..=0x7e => out.push(char::from(*byte)),
            other => drop(write!(out, "<{other:02x}>")),
        }
    }
    out
}

impl Replay<'_> {
    /// Where `at` sits in the model.
    fn index(&self, at: u64) -> usize {
        usize::try_from(at.saturating_sub(self.stream_start)).unwrap_or(usize::MAX)
    }

    /// Fails unless `got` is what the child wrote at `at`.
    ///
    /// Against the model by absolute offset rather than against what arrived before it:
    /// contiguity checked relative to the daemon's own numbers cannot fail whatever they
    /// say, since a base too low replays bytes the client has and one too high drops
    /// bytes it never will, and both arrive perfectly contiguous.
    fn check(&self, at: u64, got: &[u8]) {
        let index = self.index(at);
        let seed = self.seed;
        let want = self
            .screen
            .bytes
            .get(index..index + got.len())
            .unwrap_or_else(|| {
                panic!(
                    "the daemon sent {} bytes at offset {at}, running past the end of \
                     everything the child ever wrote (seed {seed})",
                    got.len(),
                )
            });
        if want == got {
            return;
        }
        let diff = (want.iter().zip(got))
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| want.len().min(got.len()));
        let inside = self.screen.straddled(index + diff);
        panic!(
            "the daemon labelled a byte with an offset that is not where the child \
             wrote it: at offset {}, {} bytes into {}, the session sent\n  {}\nwhere \
             the child wrote\n  {}\nThe stream is contiguous and wrong, which is what \
             an off-by-N base or a slice resumed at the wrong byte looks like from a \
             client (seed {seed})",
            at + diff as u64,
            index + diff,
            inside.map_or_else(
                || "no escape sequence".to_owned(),
                |seq| format!("the escape sequence at {}..{}", seq.start, seq.end)
            ),
            quote(got, diff),
            quote(want, diff),
        );
    }

    /// Takes output until the stream reaches `through` or `budget` bytes of it have been
    /// taken, whichever comes first, checking every byte against the byte its offset
    /// names and following any gap the daemon announces.
    fn follow(
        &mut self,
        client: &mut harness::Client,
        from: u64,
        through: u64,
        budget: usize,
    ) -> u64 {
        let seed = self.seed;
        let mut offset = from;
        let mut taken = 0usize;
        while offset < through && taken < budget {
            let (ty, payload) = frame_by(client, self.deadline, seed, "the child's output");
            match Frame::decode(ty, &payload).expect("decode frame") {
                Frame::Output { offset: at, data } => {
                    assert_eq!(
                        at, offset,
                        "output must join up unless a Gap said otherwise (seed {seed})"
                    );
                    self.check(at, data);
                    self.straddling_frames += u64::from(self.straddles(at));
                    offset += data.len() as u64;
                    taken += data.len();
                }
                Frame::Gap { new_base_offset } => {
                    assert!(
                        new_base_offset > offset,
                        "a gap must move the stream forward (seed {seed})"
                    );
                    self.straddling_gaps += u64::from(self.straddles(new_base_offset));
                    self.gaps.push((offset, new_base_offset));
                    offset = new_base_offset;
                }
                Frame::InputAck { .. } | Frame::Pong => {}
                other => panic!("unexpected {other:?} (seed {seed})"),
            }
        }
        offset
    }

    /// Whether the stream is cut inside an escape sequence at `at`.
    fn straddles(&self, at: u64) -> bool {
        self.screen.straddled(self.index(at)).is_some()
    }
}

/// Where the client stands on both streams as the rounds move it.
struct Cursor {
    /// One past the last output byte this client has taken.
    offset: u64,
    /// One past everything the child has written, which the sentinel of the round just
    /// finished makes exact — and which every gap below is arithmetic on.
    written: u64,
    /// One past the last input byte sent, kept because a reattach is told the daemon's
    /// own count and the two must agree exactly (§ 3).
    in_offset: u64,
    reattaches: u32,
}

/// Writes each round's slice where the child can `cat` it.
fn plant(session: &Session, screen: &Screen) {
    let mut from = 0usize;
    for (round, end) in screen.rounds.iter().copied().enumerate() {
        let slice = screen
            .bytes
            .get(from..end)
            .expect("a round's slice inside the transcript");
        fs::write(session.root.join(format!("s{round}")), slice).expect("plant a round's slice");
        from = end;
    }
}

/// Reads a round's output the way `kind` says, and asserts what that leaves true.
///
/// `client` is replaced rather than borrowed back out, the two reattaching arms ending
/// the connection they were handed.
fn run_round(
    session: &Session,
    client: &mut harness::Client,
    replay: &mut Replay<'_>,
    cursor: &mut Cursor,
    round: usize,
    kind: Round,
) {
    let seed = replay.seed;
    let deadline = replay.deadline;
    // The whole of `Ring::base` once the ring has been full since long before this
    // round: `end - capacity`, where the sentinel has just made `end` exact. Saturating
    // for the opening round alone, where the stream is younger than the ring and no arm
    // below looks at this.
    let oldest_held = cursor.written.saturating_sub(SCREEN_RING as u64);
    let gaps_before = replay.gaps.len();
    match kind {
        Round::Read(budget) => {
            cursor.offset = replay.follow(client, cursor.offset, cursor.written, budget);
        }
        Round::ReadThroughGap => {
            cursor.offset = replay.follow(client, cursor.offset, cursor.written, usize::MAX);
            let (_, base) = *replay.gaps.get(gaps_before).unwrap_or_else(|| {
                panic!(
                    "round {round}: the ring overran a client that never detached and \
                     nothing said so; the whole stream arrived contiguous, which it \
                     cannot have been (seed {seed})"
                )
            });
            assert_eq!(
                replay.gaps.len() - gaps_before,
                1,
                "round {round}: the child had finished before this client read a byte, so \
                 the ring was static and one gap is all there was to report (seed {seed})"
            );
            assert_eq!(
                base, oldest_held,
                "round {round}: the daemon resumed this client at {base}, where the oldest \
                 byte a full {SCREEN_RING}-byte ring can still serve is {oldest_held}. \
                 Below it the stream is served from somewhere other than where it says; \
                 above it the daemon threw away scrollback it was still holding \
                 (seed {seed})"
            );
        }
        Round::ReattachOverGap | Round::ReattachExact => {
            // The outgoing connection goes when this assignment overwrites it, which is
            // after the new socket exists and before it greets. That window costs the
            // session nothing: § 6.4 has the daemon promote a connection on its `Hello`
            // and never on the `connect`, so nothing here is a takeover.
            *client = session.connect();
            client.waits_by(deadline);
            let resumed = client.hello_before(deadline, cursor.offset);
            assert_eq!(
                resumed.in_applied, cursor.in_offset,
                "round {round}: the sentinel proved the child ran this line, so the daemon \
                 must report it applied and no more (seed {seed})"
            );
            let over = matches!(kind, Round::ReattachOverGap);
            assert_eq!(
                resumed.resume_from,
                if over { oldest_held } else { cursor.offset },
                "round {round}: {} (seed {seed})",
                if over {
                    "the slice outran the ring, so the handshake owes this client the \
                     oldest byte the ring still holds"
                } else {
                    "this client never left the ring, so the handshake must resume it on \
                     the byte it stopped at rather than move it at all"
                }
            );
            if resumed.gap(cursor.offset) {
                replay.straddling_gaps += u64::from(replay.straddles(resumed.resume_from));
                replay.gaps.push((cursor.offset, resumed.resume_from));
            }
            cursor.offset = replay.follow(client, resumed.resume_from, cursor.written, usize::MAX);
            cursor.reattaches += 1;
        }
    }
}

/// A full-screen program's output survives the daemon's own boundaries byte for byte,
/// and every byte it loses to the ring is announced first (`IMPLEMENTATION.md` § 9).
///
/// The three tests above cut the *connection* where a generator chose; this one lets the
/// daemon cut the *stream* where its own machinery does — at a `MAX_PAYLOAD` chunk, at a
/// send queue that filled partway through a slice of the ring, and at a ring that rolled
/// while the client was not reading — and asks the same question of every byte: is it the
/// byte its offset names? Against a model of what the child wrote rather than against
/// what arrived before it, since a stream resumed at the wrong byte is contiguous and
/// wrong, which no contiguity check can see.
///
/// Three things here are reachable no other way in this suite.
///
/// What the child wrote, checked against a ring above `MAX_PENDING_WRITE`
/// ([`SCREEN_RING`]) — the size at which a pass of `pump_output` *cannot* queue the ring
/// whole, so `Conn::send_output` stops mid-slice and the next pass has to resume on the
/// byte it stopped at. `tests/session.rs`'s repaint storm is the only other test that
/// reaches that arithmetic, and it reads the result for contiguity alone: a stream
/// resumed one byte out is contiguous, and passes it.
///
/// Gaps that are pinned rather than merely counted. Each round is one line the client
/// sends and a sentinel file the child touches when it has written every byte of it, so
/// the stream's end is known exactly at the moment of each gap and `Ring::base` is
/// `end - SCREEN_RING` and nothing else. Both routes to one are pinned against it:
/// § 4.2's comparison at the handshake, and the mid-stream `Gap` frame.
///
/// And gaps that provably cut an escape sequence in half. Each gapping round is a single
/// sixel image longer than the ring, so the byte the stream resumes on is *inside* it by
/// arithmetic — § 4.3's premise for the client's reset, asserted rather than assumed.
/// The daemon must not align to any of it, and the assertion is that it does not have to.
#[test]
fn a_full_screen_stream_is_byte_exact_across_gaps_that_cut_its_escape_sequences() {
    /// What the child prints before the transcript, so the offset the stream starts at
    /// is exact rather than one past whatever else shared a frame with it.
    const BEGIN: &str = "nomux-screen-begin";

    let chaos_seed = chaos_seed();
    let mut rng = Rng::new(chaos_seed);
    // Measured rather than assumed, per `harness::socket_capacity`: the socket buffers
    // are a sysctl away from any figure written down here.
    let queued_ahead = MAX_PENDING_WRITE + MAX_PAYLOAD as usize + socket_capacity();
    let (screen, plan) = workload(&mut rng, queued_ahead);

    let session = Session::start_with_ring("chaos_screen", SCREEN_RING);
    let deadline = Instant::now() + PATIENCE;
    let mut client = session.connect();
    client.waits_by(deadline);
    let ok = client.hello(RESUME_FROM_START);

    // `-opost` rather than the `-onlcr` the tests above use: no output post-processing
    // at all, so a transcript of escapes and multi-byte characters reaches the stream
    // untouched and the model can be compared to it literally. A tab expanded by the
    // line discipline would be the test's own doing, reported as the daemon's.
    let ready = client.make_ready("-echo -opost", None, ok.resume_from);
    plant(&session, &screen);

    let begin = format!("printf '{BEGIN}'\n");
    client.input(ready.in_offset, begin.as_bytes());
    let (_, stream_start) = client.read_until(BEGIN, ready.offset);

    let mut replay = Replay {
        screen: &screen,
        stream_start,
        seed: chaos_seed,
        deadline,
        gaps: Vec::new(),
        straddling_frames: 0,
        straddling_gaps: 0,
    };
    let mut cursor = Cursor {
        offset: stream_start,
        written: stream_start,
        in_offset: ready.in_offset + begin.len() as u64,
        reattaches: 0,
    };
    let mut from = 0usize;

    for (round, (kind, end)) in plan.iter().zip(screen.rounds.iter().copied()).enumerate() {
        let line = format!("cat s{round}; touch m{round}\n");
        client.input(cursor.in_offset, line.as_bytes());
        cursor.in_offset += line.len() as u64;

        // The sentinel rather than an `InputAck`: it says the child has written every
        // byte of the slice, which is what makes `written` exact and each gap arithmetic
        // instead of a race against the scheduler. Waiting on it costs nothing, a client
        // that reads nothing meanwhile being what every round below wants.
        let done = session.root.join(format!("m{round}"));
        assert!(
            poll_by(deadline, || done.exists()),
            "round {round}: the child never finished writing its slice (seed {chaos_seed})"
        );
        cursor.written += (end - from) as u64;
        from = end;

        run_round(
            &session,
            &mut client,
            &mut replay,
            &mut cursor,
            round,
            *kind,
        );
    }

    let offset = replay.follow(&mut client, cursor.offset, cursor.written, usize::MAX);
    assert_eq!(
        offset, cursor.written,
        "every byte the child wrote must be accounted for, dropped behind a gap or \
         delivered (seed {chaos_seed})"
    );
    assert_eq!(
        cursor.reattaches, 3,
        "the plan reattaches three times (seed {chaos_seed})"
    );
    assert_eq!(
        replay.gaps.len(),
        3,
        "three rounds outran the ring and no other round can: {:?} (seed {chaos_seed})",
        replay.gaps
    );
    assert_eq!(
        replay.straddling_gaps,
        replay.gaps.len() as u64,
        "every gapping round is one sixel image longer than the ring, so every resume \
         point is strictly inside one by arithmetic; {} of {} were not, which means the \
         transcript is no longer shaped the way this test reasons about it \
         (seed {chaos_seed})",
        replay.gaps.len() as u64 - replay.straddling_gaps,
        replay.gaps.len()
    );
    assert!(
        replay.straddling_frames > 0,
        "no frame began inside an escape sequence, so the daemon never cut one — which \
         is the case § 4.3 is about, and the reason the transcript is shaped this way \
         (seed {chaos_seed})"
    );
}
