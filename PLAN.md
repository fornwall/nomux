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

92 tests, one of which waits out a real reaping timeout and is `#[ignore]`d (CI
runs it with `--run-ignored all`), plus 2 doctests: property tests over the codec
including malformed and near-valid input, a model-checked ring, an integration
suite driving the real binary over its socket, and a seeded chaos suite that severs
the connection at generated points under an escape-heavy full-screen stream and
under `yes`. The regression test guarding the event ordering of § 6.4.1 is itself
verified, against a fault-injected build that restores the bug — and against one
that forces only the interleaving, which must still pass.

All four musl targets build reproducibly via `scripts/build-release.sh`, at 125.7,
144.4, 153.1 and 213.0 KiB against the 400 KiB budget. The armv7 figure is a
regression; see below.

Everything below is either a feature not started, a decision deliberately deferred,
or client-side work recorded because its server-side contract is fixed here.

## P1 — known gaps

The six items previously listed here are done. These replaced them, and each was
found by review or measurement rather than by guessing.

- **`Pty::terminate` misses every job of an interactive shell.** A shell with job
  control gives each `&` job its own process group, so `kill_process_group(child)`
  never reaches it — and neither does the `SIGHUP` the kernel sends when the master
  closes, since a background group is not the foreground one. Reaping the *session*
  is not something `kill(2)` can express; it needs a `/proc` walk. Distinct from the
  missing `SIGTERM` handler that used to sit here, and not closed by fixing it: the
  test for that one runs `set +m` precisely so it exercises the group path rather
  than silently testing nothing.
- **A hand-started daemon has a bind-to-publish window.** `attach` now holds the
  spawn lock until `<id>.pid` exists, so a session it created is never visible
  without its pidfile. `nomux daemon <id>` run directly answers `connect` from its
  bind onward and publishes the pidfile a few syscalls later, so a `kill` landing in
  between sees a live session it cannot identify. It refuses rather than unlinking,
  and waits the window out, so the outcome is an honest non-zero exit rather than a
  destroyed session — but the window is still there.
- **The linger window collapses whenever the client detaches after the child.**
  § 6.5 promises five seconds in which a client reconnecting into the race collects
  the final output and status. `on_detached` sets `linger_until` to *now* when the
  child is already gone, so that holds only in the other ordering. Verified: a
  client that ran `echo …; exit 3`, waited 700 ms and closed left the socket gone
  within 20 ms and the reconnect got `ENOENT`. Predates this work; the reasoning at
  `on_detached` ("with nobody left to tell") is exactly the assumption § 6.5 says
  not to make.
- **The run-directory check costs armv7 67.6 KiB.** Bisected to the commit, and the
  jump is that architecture alone: 148,292 → 215,884 bytes, against roughly 6 KiB
  for the whole branch on each of the other three. Ruled out by probe: the two
  dynamic error messages (168 bytes) and the `fchmod` repair (120 bytes). Removing
  the check recovers all of it, so the cost is in the `open`/`fstat`/`Mode` path as
  32-bit ARM codegen renders it. Under budget at 213 KiB, so this is a size
  regression rather than a broken release — but it is 48% of the binary users
  upload over cellular, and it went unnoticed because the release script enforces
  the cap and not the delta.

## P2 — structure

- **Collapse the four correlated client fields into one `Option`.** `client`,
  `greeted`, `exit_sent` and `sent_through` are meaningless without an attached
  connection and must be reset together by hand in five places; `accept_agent`
  writes `self.greeted && self.client.is_some()` precisely because the type permits
  those two to disagree. An `Option<Attached { .. }>` makes the reset a single
  assignment and removes the "field left stale across a takeover" class of bug.
  Worth more than any file split — and the obvious split is *not* worth doing, since
  `read_pending`, `on_hello`, `pump_output`, `handle_frame` and `watches` all touch
  the same eight fields.
- **`Hello.flags` could be unrepresentable rather than merely checked.** `HelloOk`
  packs typed fields (`gap: bool`, `linger: Linger`, `agent: bool`) through a private
  `flags()`, so an invalid combination cannot be built; `Hello` exposes a bare `u16`
  and validates it on both sides instead. Matching `HelloOk` would delete
  `HELLO_FLAG_BITS`, both accessors and the proptest's `any_hello_flags`, at the cost
  of two adjacent booleans at six call sites where `HELLO_AGENT_FORWARD` currently
  reads better. Worth doing if a third flag ever lands.
- **Test-harness duplication.** xorshift64 is implemented twice — as `Rng` in
  `chaos.rs` and inline in `session.rs`'s `bulk_bytes` — and the `stty -echo`
  readiness handshake has several copies across `session.rs` and `chaos.rs`. The
  `Drop`-guard gap is now half closed: `spawn_lock.rs` has `LiveSession` and
  `Reaped`, and `session.rs` has `Reaper` for the orphan it deliberately creates,
  but four `attach`- and `daemon`-spawning tests in `session.rs` still build a bare
  `Child`, so an assertion failure there leaks a relay whose daemon is in another
  process group.
- **The suite cannot be run twice concurrently, and cannot be run from a deep
  path.** Each test owns a fixed run directory named after itself and wipes it on
  entry, so two copies of one test binary delete each other's sockets — verified:
  three concurrent runs produced 6 to 12 unrelated-looking failures, with the daemon
  behaving correctly throughout. Safe under nextest, which never does this within a
  run. The same fixed names put the socket path over `sockaddr_un`'s 108 bytes once
  the checkout is deep enough — a git worktree under `.claude/worktrees/` is already
  past it, which makes the pre-commit hook unrunnable there without a short
  `CARGO_TARGET_DIR`. Interning the names shorter buys back both.
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

- **Track the size delta, not only the cap.** The script fails a build that misses
  400 KiB and says nothing about one that grows 48% in a single commit, which is how
  the armv7 regression above reached `main` unremarked. A recorded per-target
  baseline, compared and reported, would have caught it in the commit that caused it.
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
