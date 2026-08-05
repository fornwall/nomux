# nomux — Plan

Backlog, `P1`–`P4` in priority order. Rationale: [DESIGN.md](DESIGN.md).
Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Status

Complete and under test on Linux at the protocol revision
[IMPLEMENTATION.md § 2.2](IMPLEMENTATION.md#22-messages) states: the whole server half,
unusable alone, since the client that speaks it is a separate unreleased project — a
clone gives you `list`, `kill` and a daemon nothing can talk to.

- **Platform** — Linux only; else, plain SSH ([DESIGN.md § 7](DESIGN.md#7-degradation)).
- **Suite** — layers and invariants in
  [IMPLEMENTATION.md § 9](IMPLEMENTATION.md#9-testing); CI adds `--run-ignored all`.
- **Release** — both musl targets build reproducibly inside the size and growth gates
  ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)).
- **Partly done** — P3's publishing half: a `v*` tag builds, checks and publishes.
- **Not started** — the client, whose server-side contract is the last section here.

## P1 — known gaps

Five open; the last three came out of a security review.

- **An id this run directory cannot hold is invisible *and* uncollectable.** `list` can
  cheaply report the `sun_path`-refused id it now skips; `kill` cannot collect it, since
  "no socket address can be formed" is not "no live session"
  ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)).
- **Nothing bounds sessions per host.** The daemon's backstop of 64 landed
  ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)); the cap of eight is
  client-side ([DESIGN.md § 5.1](DESIGN.md#51-identity)) and the client is unwritten.
- **`kill` re-checks identity by command line, not by start time** — screen's
  CVE-2023-24626 in shape, never in privilege; reuse `pty::stat_start_time` in
  `control::resolve`
  ([IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)).
- **`write_private` unlinks and then writes by name.** `O_NOFOLLOW | O_EXCL` would retire
  the directory-mode argument and cover the attacker-writable parent
  [IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket) concedes; `read_prefix` already
  opens that way.
- **Nothing asserts the uid of an accepted connection.** `Daemon::accept` reads no
  credentials, so file modes are the whole of the authentication; a `getsockopt` for
  `SO_PEERCRED` is a few lines of defence in depth.

**Known and accepted:**

- A hand-started `nomux daemon <id>` has a bind-to-publish window; a `kill` inside it
  refuses and waits it out — an honest non-zero exit, never a destroyed session.
- An abort says nothing from inside the process (`-Cpanic=immediate-abort`,
  `strip = "symbols"`); what is left is the `SIGQUIT` core against the
  `nomux-<target>.debug` companion ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)).
- Every ordinary departure costs up to 500 ms in `Conn::flush_final` and departures are
  unbounded; the socket's `0600` makes that process this uid's.

## P3 — release process

- Decide when the pinned nightly moves: `scripts/nightly-version` names it once and
  `scripts/size-baseline` records the compiler that measured the bytes, so a disagreeing
  compiler is refused; undecided is the policy for taking a newer one.
- Decide what the client does when a host holds a binary whose hash it no longer knows.
  A `v*` tag already publishes `SHA256SUMS`, but nothing in the client reads it, so
  [DESIGN.md § 8](DESIGN.md#8-security-model)'s "verify it after upload" is unwritten.

## P4 — test depth

- **A quiet `SIGTERM` shutdown paying `HANGUP_GRACE` is unpinned.** The timing test that
  covered it was deleted: it compared two wall-clock shutdowns, and the zombie
  short-circuit it guarded has no consequence outside the process except latency, so
  nothing observable distinguishes the bug. Pinning it needs a `/proc`-visible marker
  from inside `Pty::terminate`, or the § 9 fault injection.
- **A hung wait inside a test cannot be attributed.** Harness waits mint their own
  `FRAME_PATIENCE` rather than taking the caller's deadline, so a test whose rows each
  make several waits is bounded only by the runner's kill
  ([.config/nextest.toml](.config/nextest.toml)) — which reports a timeout without
  saying which wait hung. One deadline field on `Client`, consulted by `next_frame`,
  `expect_eof` and `read_until`, closes it; `frame_before`, `poll_by` and `hello_before`
  already take one.
- A `cargo-fuzz` target for `decode_header` and `Frame::decode`; `proptest` covers the
  parser on stable today, so the dependency has not earned itself.
- Chaos against a real full-screen program; the suite stays deterministic on sixel and
  CSI from `sh`, and driving an actual `vim` would test `vim`.
- The wire vectors are locked in `crates/nomux-proto/tests/wire.rs`; the same table as a
  language-neutral hex fixture would let another implementation check identical bytes.
- The *missing* `<id>.pid` arm of the publish grace is untested; only the empty arm is
  pinned ([IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)).
- `MAX_PENDING_READ` has no test: the kernel's send buffer is tighter than the 1 MiB cap
  on a stock host, and forcing it with `SO_SNDBUF` is a test that silently cannot fail.

## Deferred by decision

Recorded so they are not rediscovered as gaps.

- **Read-only mirrors.** Out of scope ([DESIGN.md § 2](DESIGN.md#2-scope)).
- **Ring capacity default**, and whether `Hello` should negotiate it at all, given that
  `NOMUX_RING_BYTES` already tunes it: larger reserves address space no administrator
  agreed to, smaller loses a twenty-minute disconnect across a build.
- **Compressing the output ring.** Measured at `b71db5f` (`git show` holds the tables):
  `lz4_flex` buys scrollback but is far slower on the PTY push path, worst on the armv7
  SBCs where 4 MiB a session is scarce — a larger default ring buys the same for nothing.
- **Server-side screen snapshot on overflow.** The second server-side emulator
  [DESIGN.md § 3](DESIGN.md#3-key-properties) rejects: deterministic but not exact, and
  the visible screen only. `libvterm` would be the first C object in a tree whose musl
  targets build from `rustup target add` alone
  ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)).
- **Cross-device handover.** Takeover is the right primitive
  ([IMPLEMENTATION.md § 6.4](IMPLEMENTATION.md#64-multiple-clients)) but needs an input
  offset in `Hello`, no auto-reconnect after `Error{TAKEOVER}` and geometry-conditional
  replay — a wire change and a bump regardless, so nothing is reserved now
  ([DESIGN.md § 2](DESIGN.md#2-scope)).
- **`daemon::run` *waiting* for the spawn lock** — it would park a session behind the
  `spawn` that holds it ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)).
- **Addressing run files through a validated directory descriptor** — there is no
  `bindat(2)` ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)).

## Client-side, not this repo

The server is useless without these, and each has a server-side contract fixed here.

- `direct-streamlocal` warm path; the exec relay is the fallback.
- Bootstrap orchestration: probe, arch selection, upload, negative caching per host.
- Codec retention ([DESIGN.md § 6.4](DESIGN.md#64-version-skew)), and the "never
  auto-reconnect after `TAKEOVER`" rule.
- Collecting binaries it has uploaded: nothing here ever unlinks one, so every release
  leaves another artifact in every user's home on every host they have touched
  ([DESIGN.md § 8](DESIGN.md#8-security-model)). It knows each session's version, so it
  can remove any `nomux-*` neither current nor holding a live session.
- Emulator reset on `gap`, and the 8-sessions-per-host cap.
- The child's exit status, in the `Exit` frame the relay cannot read without parsing
  frames ([IMPLEMENTATION.md § 10](IMPLEMENTATION.md#10-exit-codes)); `since_exit_secs`
  rides beside it, so a status collected as it happened and one collected days later are
  not the same thing to put in front of a user.
- Answering agent channels from the key store, and the per-host opt-in that sets
  `HELLO_AGENT_FORWARD`. The daemon never enables forwarding on its own.
- Choosing the repaint policy per attach via `HELLO_REPAINT_CTRL_L`; only the client
  knows whether an editor or a prompt is on screen.
- Minting `--label` on `spawn`, the mode that creates and therefore the one that takes
  it, so an orphan is recognisable in `nomux list` after the client loses its state.
