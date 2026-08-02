# nomux — Plan

Backlog. Rationale: [DESIGN.md](DESIGN.md). Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Status

The daemon, attach relay, control surface and agent forwarding work on Linux.
Sessions survive a severed connection, resume by absolute byte offset, trim
replayed input, and report overflow as an explicit gap. The PTY master is
non-blocking, so a child that stops reading cannot wedge the event loop; the daemon
holds no working directory, ignores `SIGHUP`, keeps its PTY out of the child's
descriptor table, and reports through `HelloOk` whether `logind` will let the
session outlive the user's logout. Protocol revision 2, which gave both flag fields
meaning. The relay moves bytes with `splice(2)` where the host allows it.

The `daemon` mode now holds its own detachment rather than borrowing the caller's:
it leads a session, holds no controlling terminal, and redirects the stdio it was
handed, forking only when it cannot do so in place. It leaves on `SIGTERM` and
`SIGINT` through the shutdown path, so `nomux kill` collects the child's process
group instead of dropping the daemon where it stands. Both queue directions are
bounded, the input one where the queue grows rather than where the socket is read.

The five files of a session are removed only by a process holding `<id>.lock`,
which is removed last and revalidated by inode, so collection cannot take the spawn
mutex out from under an attach. `list`, `kill` and `attach` all check the run
directory before trusting a path inside it, and `/etc/passwd` is parsed over bytes,
so one Latin-1 GECOS field no longer costs every user on the host their shell.

Shutdown reaches the whole session rather than one process group: `terminate`
follows the group kill with a `/proc` walk for the `&` jobs job control scattered
into groups of their own, which is every job of every interactive shell. The linger
window of § 6.5 now holds in both orderings — a client that watches the child exit
and *then* closes no longer takes the five seconds with it. The attached client and
the three fields that mean nothing without it are one `Option<Attached>`, so a
takeover resets them together or not at all.

Four defects found by review since then, each now with a test that fails without
its fix. The relay spun at the speed of the scheduler when its stdout died with a
`splice` latched on a full destination — reachable whenever the network drops with
output backed up, which is the shape this project exists for. `Pty::terminate` paid
its whole 500 ms grace on *every* shutdown, because an unreaped zombie still
answers for its own process group and the group probe short-circuits the `/proc`
walk that would have disagreed. A `Hello` carrying the wrong protocol version was
refused only after the takeover had already evicted the working client, so a newer
client's failed handshake left the session running with nobody attached and a
client § 6.4 forbids from reconnecting. And `kill` refused a healthy session whose
pidfile it caught between creation and first write.

Two smaller ones went with them, both about answering the right way rather than
about behaviour anybody would notice twice: the relay now acts on a bare `POLLERR`
from stdin, as the socket direction and the daemon's own poll loop already did, and
`attach` reports a malformed session id as § 10's `EX_USAGE` rather than as a
session that resisted attaching — the client caches the latter per host, and would
have cached it off its own typo.

103 tests, one of which waits out a real reaping timeout and is `#[ignore]`d (CI
runs it with `--run-ignored all`), plus 2 doctests: property tests over the codec
including malformed and near-valid input, hand-written wire vectors that pin the
§ 2.2 byte layout, a model-checked ring, an integration suite driving the real
binary over its socket, and a seeded chaos suite that severs the connection at
generated points under an escape-heavy full-screen stream and under `yes`. Two of
them are verified against builds that restore the bug they guard: the event
ordering of § 6.4.1, against a fault-injected binary and against one that forces
only the interleaving, which must still pass; and the session reach of
`Pty::terminate`, against a build with the `/proc` walk removed.

The wire vectors are the newest of those and close the widest hole the suite had.
Every other codec test compared a frame to a frame, so the codec was only ever
checked against itself: swapping `Hello.out_offset` with `Hello.in_offset` on both
sides passed all 23 of them. The client is a separate codebase built from the § 2.2
table, so "encode and decode agree" was never the property that mattered.

The suite runs beside itself. Each test's run directory is named for a hash of the
test and the pid of the process running it, so a second copy of a binary in a
second terminal no longer deletes the first's sockets, and every process this
suite starts is killed and collected by a `Drop` guard rather than by a line the
author remembered to write. Both halves of the name are short on purpose: what the
suite adds to `CARGO_TARGET_TMPDIR` is 38 bytes against `sockaddr_un`'s 108, which
is what makes a worktree under `.claude/worktrees/` runnable.

All four musl targets build reproducibly via `scripts/build-release.sh`, against
the 400 KiB budget, and the largest of them — armv7, a little over 215 KiB — has
the least headroom by a wide margin. The other three are not repeated here: they
live in
`scripts/size-baseline`, which a build writes, and the two places that used to
copy them had both gone stale, one of them twice. The script holds each target
against
that baseline and fails a growth past 3%, so the next size regression is reported
in the commit that causes it — and the baseline now records the resolved `rustc
--version` rather than the toolchain alias it was asked for, since `nightly` floats
and two builds a day apart can both answer to it while disagreeing about every
figure. A missing baseline is refused outright rather than treated as "none yet",
which used to turn the gate off silently. The armv7 figure is one that arrived
before the gate did; see below.

Everything below is either a feature not started, a decision deliberately deferred,
or client-side work recorded because its server-side contract is fixed here.

## P1 — known gaps

Two left. What sat here before was found by review or measurement rather than by
guessing, and the same is true of these — which is worth saying because the two
that remain are both cases where the honest answer is a known cost rather than a
missing line of code.

- **A hand-started daemon has a bind-to-publish window.** `attach` holds the spawn
  lock until `<id>.pid` exists, so a session it created is never visible without its
  pidfile. `nomux daemon <id>` run directly answers `connect` from its bind onward
  and publishes the pidfile a few syscalls later, so a `kill` landing in between
  sees a live session it cannot identify. It refuses rather than unlinking, and
  waits the window out, so the outcome is an honest non-zero exit rather than a
  destroyed session — but the window is still there.

  One half of it turned out to be reachable from the ordinary spawn too, and is now
  closed: `write_pidfile` creates the file and fills it a syscall later, and `attach`
  releases the lock at the first of those, so a `kill` could read a zero-length
  pidfile. That read as a *corrupt* pidfile and was refused at once, where a missing
  one was patiently waited out. Both halves are waited out now, which leaves only
  the hand-started case this item is about.
- **The run-directory check costs armv7 66 KiB.** Bisected to the commit, and the
  jump is that architecture alone: 148,292 → 215,884 bytes, a 46% step against
  roughly 6 KiB for the whole branch on each of the other three. Ruled out by
  probe: the two dynamic error messages (168 bytes) and the `fchmod` repair (120
  bytes). Removing the check recovers all of it, so the cost is in the
  `open`/`fstat`/`Mode` path as 32-bit ARM codegen renders it. Under budget at 215
  KiB, so this is a size regression rather than a broken release — but it is very
  nearly a third of the binary users upload over cellular, and armv7 is the target
  least likely to be on a fast link. It went unnoticed because the release script
  enforced the cap and not the delta, which is now closed: the same commit today
  would fail the 3% gate.

## P2 — structure

- **`Hello.flags` could be unrepresentable rather than merely checked.** `HelloOk`
  packs typed fields (`gap: bool`, `linger: Linger`, `agent: bool`) through a private
  `flags()`, so an invalid combination cannot be built; `Hello` exposes a bare `u16`
  and validates it on both sides instead. Matching `HelloOk` would delete
  `HELLO_FLAG_BITS`, both accessors and the proptest's `any_hello_flags`, at the cost
  of two adjacent booleans at six call sites where `HELLO_AGENT_FORWARD` currently
  reads better. Worth doing if a third flag ever lands.
- **A test can hold the spawn lock without meaning to.** `fork` duplicates every
  open descriptor, and a duplicate of an `flock`ed one keeps that lock alive until it
  is closed — for a child of the test binary, until its `exec`. So any test that
  spawns a command while another holds `<id>.lock` open makes a concurrent `list`
  correctly find the lock busy. `a_held_spawn_lock_survives_a_concurrent_list`
  absorbs this with a bounded retry; the underlying sharpness is a property of
  running several tests in one process, which nextest's process-per-test isolation
  hides entirely.

## P3 — release process

The four musl targets build, land under the 400 KiB budget, and are byte-reproducible;
`scripts/build-release.sh` enforces all three. What is left is process rather than code:

- Pick and pin the release nightly. The shipping build needs one ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)), CI names a dated one, and nothing yet decides when it moves. A floating nightly silently invalidates the SHA-256 the client pinned.
- Publish the checksums somewhere the client reads, and decide what it does when a host already holds a binary whose hash it no longer recognises.

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
