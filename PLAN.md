# nomux — Plan

Backlog. Rationale: [DESIGN.md](DESIGN.md). Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).
The `P` in `P1`–`P4` is priority, highest first: what is known to be wrong, then what
is merely awkward, then process, then depth nobody is blocked on.

## Status

Everything below this section is a feature not started, a decision deliberately
deferred, or client-side work recorded because its server-side contract is fixed
here. This section is the standing state; the deltas that produced it are what
`git log` is for.

Complete and under test on Linux, protocol revision 2, and not usable on its own:
the client that speaks this protocol is a separate, unreleased project, so a clone
of this repository gives you `probe`, `list`, `kill` and a daemon nothing can hold a
conversation with. What is complete is the whole server half. The daemon owns a PTY,
a child and a bounded ring buffer; clients resume by absolute byte offset across a
severed connection, replayed input is trimmed rather than re-applied, and overflow is
reported as an explicit gap rather than papered over. Agent forwarding proxies
`ssh-agent` to the client as a sub-channel of the same connection. `attach` spawns a
daemon on demand and relays bytes to it, knowing nothing of the protocol. `list` and
`kill` act on the run directory alone, so any build can manage any daemon whatever
protocol it speaks. Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).

- **Platform** — Linux only, by construction. Everything else degrades to plain SSH
  ([DESIGN.md § 7](DESIGN.md#7-degradation)).
- **Suite** — a per-test timeout in `.config/nextest.toml` makes a hang a failure
  rather than a hung run, and one test is `#[ignore]`d because it sits out the real
  30 s first-attach reap, which CI covers with `--run-ignored all`. The count is
  whatever `cargo nextest list --workspace` prints; it lives there rather than here,
  for the same reason the sizes live in `scripts/size-baseline`. What each layer
  covers, and the two invariants the whole thing exists to protect:
  [IMPLEMENTATION.md § 9](IMPLEMENTATION.md#9-testing).
- **Release** — all four musl targets build reproducibly, inside the 400 KiB budget
  and against a per-target growth gate, from `scripts/build-release.sh`. armv7 has by
  far the least headroom, for the reason in P1. The sizes live in
  `scripts/size-baseline`, which a build writes — and not in prose here, which is
  where every stale copy of them has been found so far.
- **Not started** — the release process of P3, and the client, which is a separate
  repository and whose server-side contract is the last section of this file.

## P1 — known gaps

Two, and in both the honest answer is a known cost rather than a missing line of
code. Each was found by review or by measurement rather than by guessing, and is
recorded with what it was measured against.

- **A hand-started daemon has a bind-to-publish window.** `attach` holds the spawn
  lock until `<id>.pid` exists, so a session it created is never visible without its
  pidfile. `nomux daemon <id>` run directly answers `connect` from its bind onward
  and publishes the pidfile a few syscalls later, so a `kill` landing in between
  sees a live session it cannot identify. It refuses rather than unlinking, and
  waits the window out, so the outcome is an honest non-zero exit rather than a
  destroyed session — but the window is still there. Only the hand-started case:
  a session `attach` spawned is never visible without its pidfile, and a pidfile
  caught between creation and its first write is waited out like a missing one.
- **The run-directory check costs armv7 66 KiB.** Bisected to `4d5d465`, the commit
  that introduced it, and the jump is that architecture alone: 148,292 → 215,884
  bytes, a 46% step against roughly 6 KiB for the whole branch on each of the other
  three. Ruled out by probe: the two dynamic error messages (168 bytes) and the
  `fchmod` repair (120 bytes). Removing the check recovers all of it, so the cost is
  in the `open`/`fstat`/`Mode` path as 32-bit ARM codegen renders it. It stays inside the
  budget, so this is a size regression rather than a broken release — but it is very
  nearly a third of the binary users upload over cellular, and armv7 is the target
  least likely to be on a fast link. It went unnoticed because the release script
  enforced the cap and not the delta; the 3% gate that now exists would fail the
  same commit.

## P2 — structure

- **`Hello.flags` could be unrepresentable rather than merely checked.** `HelloOk`
  packs typed fields (`gap: bool`, `linger: Linger`, `agent: bool`) through a private
  `flags()`, so an invalid combination cannot be built; `Hello` exposes a bare `u16`
  and validates it on both sides instead. Matching `HelloOk` would delete the
  encode-side check, both accessors, the test that undefined bits are refused *by the
  encoder*, and the proptest's `any_hello_flags`. It would **not** delete
  `HELLO_FLAG_BITS`: §2.3 makes an undefined bit a protocol error however the struct
  is typed, so the decode side keeps the constant and its check either way, exactly as
  `HelloOk` does today.

  The cost is two adjacent booleans threaded through every `Hello` literal and every
  test helper that currently forwards a `flags: u16` — a wider reach than it looks,
  and one where `HELLO_AGENT_FORWARD` presently reads better than a positional
  `true, false`. Worth doing if a third flag ever lands, but note the shape changes
  at that point: three booleans is worse than two, so the answer then is one `Copy`
  `HelloFlags` value with named constructors — a single argument to thread — rather
  than N adjacent bools.
- **A test can hold another test's descriptor without meaning to.** `fork` duplicates
  every open descriptor, and the copy lives until the child reaches `exec` —
  close-on-exec decides when it goes, not whether it is made. Under `cargo test`, where
  the whole binary is one process, that means every test's descriptors are briefly in
  every other test's children, and nextest's process-per-test isolation hides it
  entirely.

  It has bitten three times, in both of the shapes it has. The mild one is a lock: a
  duplicate of an `flock`ed descriptor keeps the lock alive, so a test that spawns
  while another holds `<id>.lock` open makes a concurrent `list` correctly find it
  busy. `a_held_spawn_lock_survives_a_concurrent_list` absorbs that with a bounded
  retry, which works because the condition clears on its own.

  The sharp one is a closed descriptor that is not closed: a pipe is broken when the
  last descriptor onto its read end goes, and "the last" is not the closing test's to
  decide. `the_relay_exits_when_its_stdout_dies_with_nothing_owed_to_it` and
  `the_relay_exits_when_a_stdout_it_can_only_copy_to_stops_reading` provoke the relay
  with a single write, so a duplicate alive for the microseconds of that one write
  costs the whole test — measured at 4 and 5 failures in 25 whole-suite runs, with the
  reader end outliving its close by between 0.5 ms and 50 ms, and `/proc` naming the
  holders as forks of the test binary still carrying the forking test's thread name.
  Nothing clears on its own afterwards, because a relay that has handed over its one
  chunk never writes again and so never learns.

  It reaches a *listening* socket in the same shape, and there what lies is the run
  directory itself: `StaleSession::create` binds `<id>.sock` and closes it to make the
  dead session [IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)
  defines, and a duplicate keeps that socket accepting — so `list` and `kill`
  correctly report a session alive that the test had promised was a corpse. Measured
  at 170–270 ms of afterlife on a machine with several times as many runnable threads
  as cores, with `/proc/net/unix` showing the socket still carrying `SO_ACCEPTCON` and
  a reference the closing test no longer held, against 5 failures in 400 whole-binary
  runs, shared between two of the three tests that start from one.

  Two answers, and the choice between them is whether the condition can be made a
  property of the object rather than of the descriptor. Where it can, it should be:
  `shutdown(SHUT_RD)` on a socket is what "stopped reading" means and no duplicate can
  undo it, and on a listener it is equally what "answers nothing" means — which is what
  `abandon_socket` does before letting the stale socket go. Where it cannot — a pipe
  has nothing of the kind — the descriptor is made and closed inside
  `harness::while_nothing_forks`, which every `Command` in the suite takes the other
  side of, so no `fork` can be in flight to copy it. That is sound only as long as
  every process the suite starts goes through `harness::launch`; a `Command::spawn`
  called directly is what would quietly bring this back.
- **A raw read in the harness has to resume what a signal ended.** Every socket the
  harness reads carries a receive timeout, and that is the one case `signal(7)` says
  is never restarted: with `SO_RCVTIMEO` set, a call the kernel finds a pending signal
  on returns `EINTR` whatever `SA_RESTART` asked for. It costs a test either way —
  reported, it fails the test for something that happened to the process rather than
  to the daemon; swallowed, it ends a drain or a back-pressure measurement early and
  says nothing. Both were observed:
  `a_child_that_stops_reading_input_does_not_wedge_the_daemon` failed 1 loaded
  `cargo test --locked --workspace` run in 25 on `EINTR` in its setup, and the same
  run swallowed one in `drain_available`. Nothing in the suite sends the signal, which
  is why the answer is a retry rather than a culprit: `harness::read_uninterrupted`
  and `harness::write_uninterrupted` are what every socket call in the harness goes
  through, for the same reason `nbio::read` is the only raw read in the daemon, and a
  bare `stream.read` added later is what would bring this back.

## P3 — release process

The four musl targets build, land under the 400 KiB budget, and are byte-reproducible;
`scripts/build-release.sh` enforces all three. What is left is process rather than code:

- Decide when the pinned nightly moves. It is named once now, in `scripts/nightly-version`, which the build script and CI both read — so a local build and the runner measure the same bytes against a baseline recorded by the same compiler. What is undecided is the *policy*: the toolchain and `scripts/size-baseline` have to move in one commit, because the figures are compiler-dependent and a bump that leaves the baseline behind either fails the 3% gate for no reason or hides a real regression behind a compiler that got smaller.
- Publish the checksums somewhere the client reads, and decide what it does when a host already holds a binary whose hash it no longer recognises. Nothing does this today: `SHA256SUMS` is built and uploaded as a CI artifact, which expires and sits behind a login, and no workflow triggers on a tag.

## P4 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`. The parser's fuzzing lives in `proptest` today: arbitrary bytes for every frame type, plus single-byte mutations of real encodings, which is what actually reaches past length prefixes and enum discriminants. It runs on stable in the normal suite. A nightly `cargo-fuzz` target would explore longer, and has not yet earned the nightly dependency.
- Chaos against a real full-screen program. The suite emits sixel and CSI sequences from `sh`, which keeps it deterministic and dependency-free; driving an actual `vim` would test `vim`. Worth revisiting only if a bug turns up that this shape misses.
- **`MAX_PENDING_READ` has no test and cannot easily have one.** The kernel's unix
  send buffer is roughly 212 KiB, five times tighter than the 1 MiB cap, so on a
  stock host the cap never binds and no socket-level test can pin it. Raising the
  peer's `SO_SNDBUF` to 4 MiB makes it bind — peak RSS 5.2 MB against 12.3 MB — but
  a test doing that silently clamps where `net.core.wmem_max` is small, which is a
  test that cannot fail. Documented as the belt-and-braces it is instead.

## Deferred by decision

Not backlog — recorded so they are not rediscovered as gaps.

| Item | Where |
| --- | --- |
| Read-only mirrors | Out of scope, [DESIGN.md § 2](DESIGN.md#2-scope) |
| Cross-device handover | [DESIGN.md § 10](DESIGN.md#10-open-questions), with its three prerequisites |
| `libvterm` overflow snapshot | [DESIGN.md § 10](DESIGN.md#10-open-questions) |
| Ring capacity default | [DESIGN.md § 10](DESIGN.md#10-open-questions); `NOMUX_RING_BYTES` makes it tunable, but the default is unchosen |
| `daemon::run` taking the spawn lock | `attach` holds it across the whole spawn, so a daemon taking it would block on its own parent until that attach times out. Closed from the attach side instead ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)) |
| Addressing the run files through a validated directory descriptor | There is no `bindat(2)`, so both sockets must resolve by name whatever the check returns; four files race-free and two not would read as if the race were closed. The check refuses a directory anyone else can write to, which is what makes the path-based calls safe ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)) |

## Client-side, not this repo

Listed because the server is useless without them, and because each has a
server-side contract already fixed here.

- `direct-streamlocal` warm path; the exec relay is the fallback.
- Bootstrap orchestration: probe, arch selection, upload, negative caching per host.
- N-1 codec retention and the "never auto-reconnect after `TAKEOVER`" rule.
- Emulator reset on `gap`, and the 8-sessions-per-host cap.
- The child's exit status. It arrives in the `Exit` frame; the relay cannot read it without parsing frames, which is exactly what keeps the relay version-independent ([IMPLEMENTATION.md § 10](IMPLEMENTATION.md#10-exit-codes)).
- Answering agent channels from the key store, and the per-host opt-in that sets `HELLO_AGENT_FORWARD`. The daemon never enables forwarding on its own.
- Choosing the repaint policy per attach via `HELLO_REPAINT_CTRL_L`; only the client knows whether an editor or a prompt is on screen.
- Minting `--label` when a session is created, so an orphan is recognisable in `nomux list` after the client loses its state.
