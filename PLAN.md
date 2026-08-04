# nomux — Plan

Backlog. Rationale: [DESIGN.md](DESIGN.md). Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).
The `P` in `P1`–`P4` is priority, highest first: what is known to be wrong, then what
is merely awkward, then process, then depth nobody is blocked on.

## Status

Everything below this section is a feature not started, a decision deliberately
deferred, or client-side work recorded because its server-side contract is fixed
here. This section is the standing state; the deltas that produced it are what
`git log` is for.

Complete and under test on Linux, at the protocol revision
[IMPLEMENTATION.md § 2.2](IMPLEMENTATION.md#22-messages) states — the number lives
there, next to the bytes that carry it — and not usable on its own:
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
  for the same reason the sizes live in `scripts/size-baseline`. Which layers there
  are and where each one lives, and the two invariants the whole thing exists to
  protect: [IMPLEMENTATION.md § 9](IMPLEMENTATION.md#9-testing).
- **Release** — both musl targets build reproducibly and inside the size and
  growth gates `scripts/build-release.sh` enforces
  ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)). The sizes live in
  `scripts/size-baseline`, which a build writes.
- **Partly done** — P3's publishing half: a `v*` tag builds, checks and publishes a
  release, so what is left there is the policy question rather than the plumbing.
- **Not started** — the client, which is a separate repository and whose server-side
  contract is the last section of this file.

## P1 — known gaps

Five, and in the first the honest answer is a known cost rather than a missing line
of code; the second is a gap that cannot be closed from inside the process, the third a
limit nobody has built yet, the fourth the one wait on the control surface that has no
bound, and the fifth a hole in that surface's own promise. Each was found by review or
by measurement rather
than by guessing, and is recorded with what it was measured against.

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
  a daemon that stays unpublished past that grace is reported. A pidfile that exists
  and parses is not evidence either, since a `SIGKILL`ed daemon leaves its files and
  the kernel is free to reissue its pid — so `kill` confirms the session actually
  stopped before it removes anything, and otherwise reports the pid as not the one
  serving the session. § 6.6's "a live session's files are never unlinked" therefore
  holds without a caveat, and the identification window above is what is left.
- **An abort still says nothing from inside the process.** The daemon reports startup
  failures to the `attach` that spawned it and everything afterwards to syslog, which
  covers every failure it can see coming. An *abort* is not one of those: the shipping
  build is `-Cpanic=immediate-abort` with `strip = "symbols"`, so allocation failure and
  any surviving panic produce no message, no location and no symbol to forward. What is
  left is the `SIGQUIT` core § 6.5 preserves, and that core can now be read: every
  release publishes `nomux-<target>.debug`, the same build unstripped, with its own
  `SHA256SUMS.debug` ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)). It names
  functions rather than lines — the release profile carries no debuginfo for nomux's
  own code, so the companion's DWARF describes `std` and its `.symtab` describes the
  rest. Giving it lines as well means `debug = 1` in the release profile, which is a
  change to what the shipping build compiles and has not been made. What remains
  unfixable from inside is the message itself: an immediate abort has nowhere to write
  it.
- **Nothing bounds how many sessions one host will run.** The cap of eight is enforced
  client-side ([DESIGN.md § 5.1](DESIGN.md#51-identity)) and the daemon knows nothing
  of its siblings, so two devices on one account give sixteen and a client bug gives no
  limit at all. Each session is a daemon, a login shell and whatever that shell started,
  held for seven days. On a shared build host the only bound in the system is on the far
  side of a boundary this repository cannot see. The binary already reads the run
  directory in `list` (`control.rs`), though the daemon itself does not; counting
  entries at startup and refusing past a generous ceiling would put a floor under it
  without the client's cooperation.
- **The liveness probe is the one call on the escape hatch with no deadline.** Every
  other wait `list` and `kill` make is bounded — the spawn lock, the publish grace, the
  two signal graces
  ([IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)) — but the
  `connect` that decides whether a session is alive is a blocking one, and an `AF_UNIX`
  `connect` to a listener whose backlog is full does not fail, it waits. A daemon that
  has stopped accepting with a full queue therefore parks both modes for as long as it
  stays that way: against a listener that never accepts, with its queue filled, `list`
  and `kill` both come back only as rc=124 from `timeout`. It is as old as this
  surface rather than new — the probe has been a blocking `connect` since `a886313`,
  the commit that first wrote it — and it is the reason the backlog is the host's
  ceiling rather than a literal ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)),
  which is mitigation and not a fix, `somaxconn` being finite. The fix is a non-blocking
  `connect` with a `poll` deadline, read exactly as the blocking one is: anything that
  is not a refusal is a session too alive to unlink.
- **An id this run directory cannot hold makes its files invisible *and*
  uncollectable.** The `sun_path` refusal in
  [IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket) is environment-dependent — the
  same id fits under `/run/user/1000` and not under the `$HOME` fallback — and both
  modes meet it by giving up. `list` discovers the id from the filenames and then drops
  it, because building its paths is fallible in the middle of the sweep; `kill` cannot
  be told about it at all, since the id it is handed is refused before anything is
  read. Measured with four files planted under a 50-byte id in a 53-byte run directory:
  `list` prints nothing and exits 0, `kill` exits 64, all four files are still there
  afterwards. This binary cannot create that state, but § 6.6 freezes the layout
  *precisely* so that a directory can be managed by a binary that did not create it,
  and a bind mount, a symlinked `XDG_RUNTIME_DIR` or a file repaired by hand all reach
  it. The argument in § 6.3 for refusing early — that refusing at the `bind` would
  leave a `<id>.lock` behind from the command whose job is to collect it — is one-sided
  while the alternative leaves everything already there for good.

  The `list` half closes cheaply: report the id it cannot build paths for instead of
  skipping it, since reporting is not collecting and puts nothing at risk. The `kill`
  half has no such answer, and the obvious one is a trap. "No socket address can be
  formed" is not "no live session": it is "liveness cannot be *probed*", and two names
  for one run directory separate them. With a symlink at a 6-byte path pointing at a
  47-byte one, a session created through the short name — `attach` exits 0, `list`
  through that name shows it, `<id>.sock` is one inode under both names — is a session
  whose `connect` through the long name cannot even be attempted. A `kill` that
  collected by name there would unlink the socket, pidfile and lock of a daemon still
  holding the user's shell, which is the one thing § 6.6 promises never happens. So
  whatever closes this half has to establish liveness some other way — the id is
  reachable by a shorter path, and finding it is the work — or leave `kill` refusing
  and say so.

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
- **Collection names the five files it knows, so every name added after it leaks
  once.** The documentation half of this is done —
  [IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface) promises the
  five existing names, their permissions and the pidfile format rather than the layout
  as a whole, and says what growth costs. The code half is untouched.
  `SessionPaths::removal_order` is five paths and `control::session_id_of` — whose one
  caller is `list` — matches five extensions, so a *binary* older than a name neither
  discovers a session by it nor removes it: one file per collected session for as long
  as the two versions share a host, and an id that is invisible for good where that
  file is the last one left. It is what `<id>.agent` would have cost had it arrived
  after a release. Removing and discovering `<id>.*` instead covers every future name
  at once, and the window for it is closing rather than open: cheap while five names
  are all there have ever been, impossible once a binary in the wild depends on the
  enumeration.

## P3 — release process

Both musl targets build and land under the 400 KiB budget, which
`scripts/build-release.sh` enforces along with the growth gate. Reproducibility it
enforces in the only way a single machine can — by grepping each artifact for the
builder's paths, since two clean builds on one machine are byte-identical whether or
not those paths were remapped ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)).
What is left is process rather than code:

- Decide when the pinned nightly moves. It is named once, in `scripts/nightly-version`, which the build script and CI both read — so a local build and the runner measure the same bytes against a baseline recorded by the same compiler. The *consistency* is no longer a rule anyone has to remember: `scripts/size-baseline` records the compiler that measured it, and a build whose compiler does not match that line is refused, or, under `NOMUX_NIGHTLY` and `NOMUX_STABLE_STD`, says so and loses the growth gate. What is still undecided is the *policy* — when to take a newer compiler at all, given that the toolchain and the baseline then move in one commit.
- Decide what the client does when a host already holds a binary whose hash it no longer recognises. The publishing half of this is done: a `v*` tag promotes the artifact the release build produced into a GitHub release carrying the shipping binaries beside `SHA256SUMS`, so the sums are permanent and public and in the format `sha256sum -c` reads, rather than only the ninety-day artifact behind a login they were before. GitHub computes its own immutable SHA-256 per asset at upload time as well, exposed as `digest` on the releases API, which covers the same bytes with something nobody can rewrite after the fact. The unstripped companions of P1 ride along, with their own `SHA256SUMS.debug`. What is missing is the consuming half: nothing in the client reads any of it, so § 8's "verify it after upload" is still unwritten, and so is the answer to the question this bullet opens with.

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
- **The 1 GiB ring ceiling is exercised but never told apart from the default.** Found
  by reading § 9 against the suite rather than by a failure, and cheap. `ring_huge` in
  `a_ring_capacity_the_daemon_cannot_use_falls_back_to_the_default` pins that the
  daemon does not abort on a `NOMUX_RING_BYTES` mistyped upwards, which is what
  `MAX_RING_CAPACITY` exists for, but nothing separates the clamp
  [IMPLEMENTATION.md § 4](IMPLEMENTATION.md#4-ring-buffer) documents from the fallback
  the test is named after. The distinction is already on the wire: a
  `RESUME_FROM_START` greeting is answered with the ring's base, so writing a few MiB
  past the default and reading `resume_from` back says which capacity was built.
- **One arm of the publish grace decides nothing the suite can see.** `kill` waits out a
  `<id>.pid` that is *missing* as well as one that is empty
  ([IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)), and the
  empty arm is pinned twice over. The missing one is not: mutating it to settle at once
  rather than wait leaves the suite green, because the wait only decides an outcome
  where the socket names nobody, and every test that takes a live session's pidfile away
  leaves a socket that names its daemon. The state where it *does* decide is a
  fork-detached daemon between its own `bind` and its `listen` — § 6.2's parent has
  `_exit`ed, so the credentials on the socket name nothing extant and the pidfile is
  still to come — which is the same window P1's first entry is about, one witness
  narrower. Composing it means holding a daemon inside a few syscalls of its own
  startup, which is why it is recorded here rather than fixed with a test that would be
  a race.
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
| `daemon::run` *waiting* for the spawn lock | It takes one without blocking and goes on without one where somebody holds it. Waiting would park the session's own creation behind the `attach` that spawned it, since that attach holds this very lock on its behalf until the pidfile exists ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)) |
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
