# nomux — Plan

Backlog. Rationale: [DESIGN.md](DESIGN.md). Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Status

The daemon, attach relay and control surface work on Linux. Sessions survive a
severed connection, resume by absolute byte offset, trim replayed input, and report
overflow as an explicit gap. 32 tests, including an integration suite that drives
the real binary over its socket.

Everything below is either a known gap in what ships, a feature not started, or a
decision deliberately deferred.

## P0 — correctness gaps in shipped code

| Gap | Symptom | Where |
| --- | --- | --- |
| PTY master is **blocking** | A full PTY input buffer blocks the whole event loop: one wedged child stalls output for the session. `write_pty`'s `EAGAIN` arm is currently dead code. | `pty.rs` — set `O_NONBLOCK` on the master |
| `<id>.label` is never written | `list` reads it and `kill` unlinks it, but nothing creates it. The frozen layout has a hole, so per-tab ids stay anonymous after client state loss — the exact case §5.1 added it for. | Needs a writer: a CLI flag, or a `Hello` field |
| No `chdir("/")` | The daemon inherits `attach`'s working directory and can pin a mount busy indefinitely. | `daemon.rs` startup |
| `SIGHUP` not ignored | Documented in §6.2. Harmless today because `setsid` leaves no controlling terminal, but it is one refactor away from mattering. | `daemon.rs` startup |
| No linger detection | §6.2 says detect `loginctl show-user -p Linger` and report it, so the client can warn that the session will die at logout. Not implemented, and `HelloOk` has no flag for it. | Needs a `HelloOk` flag bit |

## P1 — agent forwarding

The largest unbuilt piece, and the one that decides whether §5.3's transparency
claim holds. Frame types (`AgentOpen`/`AgentData`/`AgentClose`) and
`MAX_AGENT_CHANNELS` exist in the codec; nothing serves the socket.

1. Daemon listens on `$RUNDIR/<id>.agent`, `0600`.
2. Child env gets `SSH_AUTH_SOCK` pointing at it — gated on an opt-in flag, never by default (§6.7: this bypasses a deliberate `ForwardAgent` decision).
3. Channel table with monotonic, never-reused ids; cap at 8; refuse beyond.
4. Accept-and-close while detached, so `git push` fails fast instead of hanging.
5. Poll set grows from a fixed 3 fds to 3 + N. The current fixed-index revents mapping in `poll_once` will not survive this and needs restructuring first.

Step 5 is the real work; the rest is plumbing.

## P1 — build and release

None of this is verified, because the pinned `1.97.1` toolchain has no musl std
installed (see README).

- Build all four musl targets; confirm the ≤400 KiB budget per arch.
- `zig cc` as cross linker, one host toolchain.
- Reproducible builds, so the client can pin a SHA-256 per arch and verify after upload.
- Decide whether `-Z build-std` with `panic_immediate_abort` earns its nightly dependency.

## P2 — test depth

- `proptest` on the codec. §9 specifies it; current coverage is hand-written cases.
- Fuzz `decode_header` + `Frame::decode`. It parses attacker-adjacent bytes and must never panic — `indexing_slicing` is denied, but that is not proof.
- Chaos: randomised disconnect injection under `yes`, `vim`, and a sixel emitter. The suite currently proves byte-exactness for a shell, not for a full-screen program.
- Verify the takeover regression test against the pre-fix ordering. It is a probabilistic guard today; reverting the ordering does not compile, so it was never shown to fail on the bug it describes.
- CI. There is none.

## P2 — smaller items

- `getpwuid` fallback for shell selection; currently `$SHELL` then `/bin/sh`.
- `splice(2)` in the relay. Documented as intended, currently a userspace copy.
- Repaint policy is `winch`-only; §4.3 specifies a per-session `ctrl_l` alternative.
- Exit-code propagation. The §10 table promises the child's status through 1–125, but the relay is deliberately dumb and cannot parse `Exit` to learn it. Either the client owns this and the table is wrong, or the relay stops being dumb. Resolve the doc, do not quietly widen the relay.

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
