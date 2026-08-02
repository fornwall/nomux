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

69 tests, one of which waits out a real reaping timeout and is `#[ignore]`d (CI
runs it with `--run-ignored all`), plus 2 doctests: property tests over the codec
including malformed and near-valid input, a model-checked ring, an integration
suite driving the real binary over its socket, and a seeded chaos suite that severs
the connection at generated points under an escape-heavy full-screen stream and
under `yes`. The regression test guarding the event ordering of § 6.4.1 is itself
verified, against a fault-injected build that restores the bug — and against one
that forces only the interleaving, which must still pass.

Everything below is either a feature not started, a decision deliberately deferred,
or client-side work recorded because its server-side contract is fixed here.

## P1 — known gaps

Found by review and deliberately left for a later pass; none is reachable without
either an unusual host or a peer built from a different tree.

- **No `SIGTERM` handler.** `nomux kill` signals the daemon, which dies on the default disposition, so `Daemon::shutdown` never runs and `Pty::terminate` never collects the child's process group. Closing the PTY master delivers `SIGHUP` to the foreground group, which covers the ordinary case, but a backgrounded process that ignores it survives where reaping would have caught it. Needs a self-pipe or `signalfd` in the poll set.
- **`nomux daemon` does not detach itself.** `setsid` and the `/dev/null` stdio live in `attach::spawn_daemon`, so the property § 6.2 claims is held by the caller rather than by the mode. Invoked any other way, the daemon keeps its inherited stdio and process group.
- **Garbage collection can unlink a live session's lock.** `unlink_all` removes `<id>.lock`, which `attach` holds the spawn `flock` on, so a concurrent `list` or `kill` can take the spawn mutex out from under a process using it. Collection should take the lock first and skip entries it cannot get.
- **The input queue is unbounded.** `Conn::rx` and `pending_input` have no cap, unlike the output direction (`MAX_PENDING_WRITE`) and the agent direction (`MAX_CHANNEL_QUEUE`). A client writing faster than the child reads grows daemon memory without limit. Same uid, so robustness rather than security — but the asymmetry looks like an oversight rather than a decision.
- **`/etc/passwd` is parsed as UTF-8.** One non-UTF-8 byte anywhere in the file — a Latin-1 GECOS field is enough — makes the whole lookup miss, silently downgrading the user's shell to `/bin/sh`. The two fields actually read are ASCII; parse over bytes.
- **`ensure_dir` accepts an existing directory unchecked.** A symlink, or a mode loosened by something else, counts as success. Worth an `O_NOFOLLOW` open plus an `fstat` on owner and mode, with the run files opened relative to that descriptor.

## P2 — structure

- **Collapse the four correlated client fields into one `Option`.** `client`, `greeted`, `exit_sent` and `sent_through` are meaningless without an attached connection and must be reset together by hand in five places; `accept_agent` writes `self.greeted && self.client.is_some()` precisely because the type permits those two to disagree. An `Option<Attached { .. }>` makes the reset a single assignment and removes the "field left stale across a takeover" class of bug. Worth more than any file split — and the obvious split is *not* worth doing, since `read_pending`, `on_hello`, `pump_output`, `handle_frame` and `watches` all touch the same eight fields.
- **`Hello.flags` could be unrepresentable rather than merely checked.** `HelloOk` packs typed fields (`gap: bool`, `linger: Linger`, `agent: bool`) through a private `flags()`, so an invalid combination cannot be built; `Hello` exposes a bare `u16` and validates it on both sides instead. Matching `HelloOk` would delete `HELLO_FLAG_BITS`, both accessors and the proptest's `any_hello_flags`, at the cost of two adjacent booleans at six call sites where `HELLO_AGENT_FORWARD` currently reads better. Worth doing if a third flag ever lands.
- **Test-harness duplication.** xorshift64 is implemented identically in `chaos.rs` and `session.rs`; the `stty -echo` readiness handshake has four copies; contiguity-checked `Output` accumulation has four. The `attach`-spawning tests build a bare `Child` with no `Drop` guard, so an assertion failure leaks a relay whose daemon is in another process group and outlives the run.
- **The suite cannot be run twice concurrently.** Each test owns a fixed run directory named after itself and wipes it on entry, so two copies of one test binary delete each other's sockets — verified: three concurrent runs produced 6 to 12 unrelated-looking failures, with the daemon behaving correctly throughout. Safe under nextest, which never does this within a run. A per-process directory is the fix but costs `sockaddr_un` headroom the longest path cannot spare; interning the names shorter would buy it back.

## P3 — release process

The four musl targets build, land between 121 and 147 KiB against the 400 KiB
budget, and are byte-reproducible; `scripts/build-release.sh` enforces all three.
What is left is process rather than code:

- Pick and pin the release nightly. The shipping build needs one ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)), CI names a dated one, and nothing yet decides when it moves. A floating nightly silently invalidates the SHA-256 the client pinned.
- Publish the checksums somewhere the client reads, and decide what it does when a host already holds a binary whose hash it no longer recognises.

## P4 — test depth

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
