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

All four musl targets build reproducibly at 121–147 KiB against the 400 KiB budget,
via `scripts/build-release.sh`.

65 tests: property tests over the codec including malformed and near-valid input, a
model-checked ring, an integration suite driving the real binary over its socket,
and a seeded chaos suite that severs the connection at generated points under an
escape-heavy full-screen stream and under `yes`. The regression test guarding the
event ordering of § 6.4.1 is itself verified, against a fault-injected build that
restores the bug — and against one that forces only the interleaving, which must
still pass.

A review of the above turned up four defects in code that predates it, all fixed
and each now covered: `Exit` reaching a reattaching client ahead of the output it
belonged to, an unbounded blocking write letting a half-dead client hang the whole
daemon, `nomux list` evicting the attached client of every session it probed, and
the PTY master leaking into every process the user ran.

Everything below is either a feature not started, a decision deliberately deferred,
or client-side work recorded because its server-side contract is fixed here.

## P1 — release process

The four musl targets build, land between 121 and 147 KiB against the 400 KiB
budget, and are byte-reproducible; `scripts/build-release.sh` enforces all three.
What is left is process rather than code:

- Pick and pin the release nightly. The shipping build needs one ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)), CI names a dated one, and nothing yet decides when it moves. A floating nightly silently invalidates the SHA-256 the client pinned.
- Publish the checksums somewhere the client reads, and decide what it does when a host already holds a binary whose hash it no longer recognises.

## P2 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`. The parser's fuzzing lives in `proptest` today: arbitrary bytes for every frame type, plus single-byte mutations of real encodings, which is what actually reaches past length prefixes and enum discriminants. It runs on stable in the normal suite. A nightly `cargo-fuzz` target would explore longer, and has not yet earned the nightly dependency.
- Chaos against a real full-screen program. The suite emits sixel and CSI sequences from `sh`, which keeps it deterministic and dependency-free; driving an actual `vim` would test `vim`. Worth revisiting only if a bug turns up that this shape misses.

## Deferred by decision

Not backlog — recorded so they are not rediscovered as gaps.

| Item | Where |
| --- | --- |
| Read-only mirrors | Out of scope, [DESIGN.md § 2](DESIGN.md#2-scope) |
| Cross-device handover | [DESIGN.md § 10](DESIGN.md#10-open-questions), with its three prerequisites |
| `libvterm` overflow snapshot | [DESIGN.md § 10](DESIGN.md#10-open-questions) |
| Ring capacity default | [DESIGN.md § 10](DESIGN.md#10-open-questions); `NOMUX_RING_BYTES` makes it tunable, but the default is unchosen |

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
