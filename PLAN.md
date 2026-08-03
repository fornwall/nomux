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
- **Release** — all four musl targets build reproducibly and inside the size and
  growth gates `scripts/build-release.sh` enforces
  ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)). armv7 has by far the least
  headroom, for the reason in P1. The sizes live in `scripts/size-baseline`, which a
  build writes.
- **Not started** — the release process of P3, and the client, which is a separate
  repository and whose server-side contract is the last section of this file.

## P1 — known gaps

Four, and in the first two the honest answer is a known cost rather than a
missing line of code; the third is a gap nothing can close, and the fourth a limit
nobody has built yet. Each was found by review or by measurement rather than by
guessing, and is recorded with what it was measured against.

- **A hand-started daemon has a bind-to-publish window.** `attach` holds the spawn
  lock until `<id>.pid` exists, so a session it created is never visible without its
  pidfile. `nomux daemon <id>` run directly answers `connect` from its bind onward
  and publishes the pidfile a few syscalls later, so a `kill` landing in between
  sees a live session it cannot identify. It refuses rather than unlinking, and
  waits the window out, so the outcome is an honest non-zero exit rather than a
  destroyed session — but the window is still there. `attach` narrows it rather than
  closing it: the lock goes as soon as the path exists, and the pidfile is created a
  syscall before it is filled, so the ordinary spawn can be caught holding an empty
  one. Both halves — no file, and a file with nothing in it — are waited out, so only
  a daemon that stays unpublished past that grace is reported. The third half was the
  one this argument missed, and is now closed: a pidfile that exists and parses is
  still not evidence that the number in it is the process behind the socket, since a
  `SIGKILL`ed daemon leaves its files and the kernel is free to reissue its pid. A
  `kill` that signals such a number kills a stranger, and used to unlink the live
  session's files afterwards regardless. It now confirms the session actually stopped
  before it removes anything, and reports the pid as not the one serving the session
  otherwise — so § 6.6's "a live session's files are never unlinked" holds without a
  caveat, and only the identification window above is left.
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
- **An abort still says nothing, and cannot.** The daemon now reports startup failures
  to the `attach` that spawned it and everything afterwards to syslog, which covers
  every failure it can see coming. An *abort* is not one of those: the shipping build
  is `-Cpanic=immediate-abort` with `strip = "symbols"`, so allocation failure and any
  surviving panic produce no message, no location and no symbol to forward. What is
  left is the `SIGQUIT` core § 6.5 preserves — and nothing publishes unstripped
  binaries for it to be read against, so today that core names no functions. Publishing
  them beside `SHA256SUMS`, keyed by the same hash, is the cheap half of the answer and
  belongs with the P3 release work.
- **Nothing bounds how many sessions one host will run.** The cap of eight is enforced
  client-side ([DESIGN.md § 5.1](DESIGN.md#51-identity)) and the daemon knows nothing
  of its siblings, so two devices on one account give sixteen and a client bug gives no
  limit at all. Each session is a daemon, a login shell and whatever that shell started,
  held for seven days. On a shared build host the only bound in the system is on the far
  side of a boundary this repository cannot see. The daemon already reads the run
  directory in `list`; counting entries at startup and refusing past a generous ceiling
  would put a floor under it without the client's cooperation.

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
  costs the whole test, and nothing clears on its own afterwards: a relay that has
  handed over its one chunk never writes again and so never learns. It reaches a
  *listening* socket in the same shape, where what lies is the run directory itself —
  `StaleSession::create` binds `<id>.sock` and closes it to make the dead session
  [IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface) defines, and a
  duplicate keeps that socket accepting, so `list` and `kill` correctly report a
  session alive that the test had promised was a corpse.

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
  says nothing — and both were observed, in
  `a_child_that_stops_reading_input_does_not_wedge_the_daemon` and in
  `drain_available`. Nothing in the suite sends the signal, which
  is why the answer is a retry rather than a culprit: `harness::read_uninterrupted`
  and `harness::write_uninterrupted` are what every socket call in the harness goes
  through, for the same reason `nbio::read` is the only raw read in the daemon, and a
  bare `stream.read` added later is what would bring this back.

- **"Frozen" is promised for a layout that has already grown once.**
  [IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface) says filenames
  and permissions may never change, and the set is five files having gained
  `<id>.agent`. Nothing says what an *older* binary's `kill` does with a name it does
  not know, and the answer today is that it leaves it behind — one leaked file per
  collected session, for as long as the two versions coexist. The promise holds for what
  it needs to cover if it is stated as the five existing names, their permissions and
  the pidfile format, with collection removing `<id>.*` rather than an enumerated list.
  That is a small change now and an impossible one once a sixth file exists in the wild.

## P3 — release process

The four musl targets build, land under the 400 KiB budget, and are byte-reproducible;
`scripts/build-release.sh` enforces all three. What is left is process rather than code:

- Decide when the pinned nightly moves. It is named once now, in `scripts/nightly-version`, which the build script and CI both read — so a local build and the runner measure the same bytes against a baseline recorded by the same compiler. What is undecided is the *policy*: the toolchain and `scripts/size-baseline` have to move in one commit, because the figures are compiler-dependent and a bump that leaves the baseline behind either fails the 3% gate for no reason or hides a real regression behind a compiler that got smaller.
- Publish the checksums somewhere the client reads, and decide what it does when a host already holds a binary whose hash it no longer recognises. Nothing does this today: `SHA256SUMS` is built and uploaded as a CI artifact, which expires and sits behind a login, and no workflow triggers on a tag.

## P4 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`. The parser's fuzzing lives in `proptest` today: arbitrary bytes for every frame type, plus single-byte mutations of real encodings, which is what actually reaches past length prefixes and enum discriminants. It runs on stable in the normal suite. A nightly `cargo-fuzz` target would explore longer, and has not yet earned the nightly dependency.
- Chaos against a real full-screen program. The suite emits sixel and CSI sequences from `sh`, which keeps it deterministic and dependency-free; driving an actual `vim` would test `vim`. Worth revisiting only if a bug turns up that this shape misses.
- **The wire vectors cannot be run by the implementation that most needs them.**
  `crates/nomux-proto/tests/wire.rs` is written from the § 2.2 table rather than from
  the encoder, which is exactly what makes it able to catch a changed field order — and
  it is locked inside a Rust integration test. [IMPLEMENTATION.md § 1](IMPLEMENTATION.md#1-layout)
  allows the client to reimplement the codec, which a mobile client in Swift or Kotlin
  will, and it cannot run any of this. Emitting the same table as a language-neutral
  fixture from the same test — hex per frame, checked in — would let an independent
  implementation be verified against the identical bytes. Until something does, the
  protocol has never met a second implementation.
- **Four documented numbers and arms still have nothing behind them.** Each was found
  by reading § 9 against the suite rather than by a failure, and each is cheap except
  where noted. `MAX_CHANNEL_QUEUE` — an agent channel whose local peer stops reading
  is closed once its queue passes 256 KiB; `agent_channels_are_capped` covers the
  count cap, not the byte cap. The 1 GiB ring ceiling — `ring_huge` in
  `a_ring_capacity_the_daemon_cannot_use_falls_back_to_the_default` pins that the
  daemon does not abort on a `NOMUX_RING_BYTES` mistyped upwards, which is what
  `MAX_RING_CAPACITY` exists for, but nothing separates the clamp
  [IMPLEMENTATION.md § 4](IMPLEMENTATION.md#4-ring-buffer) documents from the fallback
  the test is named after. The distinction is already on the wire: a
  `RESUME_FROM_START` greeting is answered with the ring's base, so writing a few MiB
  past the default and reading `resume_from` back says which capacity was built. The
  `frame is not valid from a client` arm — a server-only frame arriving *after* a
  successful greeting, which is a different function from the ungreeted refusal that
  is tested, and a different claim: that the session survives a client which
  misbehaves once attached. And exit codes 126 and 127, which are deliberately left:
  both are `attach`'s mapping of what it met, so reaching either honestly means a real
  relay — a mode that goes on to serve and so cannot be run to completion by a test
  that waits for it. What an argument-parsing test could reach is only the
  `io::ErrorKind`-to-number mapping, and asserting on that pins which kind a refusal
  happens to carry rather than anything a client depends on.
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
| Ring capacity default | [DESIGN.md § 10](DESIGN.md#10-open-questions); `NOMUX_RING_BYTES` makes it tunable, but the default is unchosen. § 10 has why the memory figure that argues for keeping it small overstates what a session holds; what argues for a larger default is the case § 10 does not name — an ordinary twenty-minute disconnect across a build, which overruns 4 MiB and loses the output the reconnect was for |
| `daemon::run` taking the spawn lock | `attach` holds it across the whole spawn, so a daemon taking it would block on its own parent until that attach times out. Closed from the attach side instead ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)) |
| Addressing the run files through a validated directory descriptor | There is no `bindat(2)`, so the sockets must resolve by name whatever the check returns ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)) |

## Client-side, not this repo

Listed because the server is useless without them, and because each has a
server-side contract already fixed here.

- `direct-streamlocal` warm path; the exec relay is the fallback.
- Bootstrap orchestration: probe, arch selection, upload, negative caching per host.
- Codec retention and the "never auto-reconnect after `TAKEOVER`" rule. N-1 is stated in
  [DESIGN.md § 6.4](DESIGN.md#64-version-skew), and its safety argument — that the client
  offers a restart while the session is *still reachable* — assumes the client runs under
  every release. App stores batch updates in the background, so a user who does not open
  the app for a month goes from release 5 to release 8 without ever running 6 or 7, and
  any session created under 5 is unreachable before the window opens. Keying retention to
  protocol revision instead, and keeping every revision ever shipped, removes the failure
  rather than bounding it: revisions are append-only integers and a codec is a few hundred
  lines, which costs an app nothing.
- Collecting binaries it has uploaded. `install_dir()` is referenced only by `probe`, and
  nothing in this repository ever unlinks one — so every release leaves another artifact
  in every user's home on every host they have touched, in a directory
  [DESIGN.md § 8](DESIGN.md#8-security-model) already expects file-integrity tooling to
  notice. The client knows the version each session is running, so it has what it needs
  to remove any `nomux-*` that is neither current nor holding a live session.
- Emulator reset on `gap`, and the 8-sessions-per-host cap.
- The child's exit status. It arrives in the `Exit` frame; the relay cannot read it without parsing frames, which is exactly what keeps the relay version-independent ([IMPLEMENTATION.md § 10](IMPLEMENTATION.md#10-exit-codes)).
- Answering agent channels from the key store, and the per-host opt-in that sets `HELLO_AGENT_FORWARD`. The daemon never enables forwarding on its own.
- Choosing the repaint policy per attach via `HELLO_REPAINT_CTRL_L`; only the client knows whether an editor or a prompt is on screen.
- Minting `--label` when a session is created, so an orphan is recognisable in `nomux list` after the client loses its state.
