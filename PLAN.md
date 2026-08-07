# nomux — Backlog

Open questions, in priority order. Why the system is shaped as it is:
[DESIGN.md](DESIGN.md), whose § 10 records what was considered and refused. What it does
and what a second implementation must obey: [IMPLEMENTATION.md](IMPLEMENTATION.md).

## P1 — the client

The largest open item in the project: it does not exist. This repository is the server
half, and the server half is useless alone — the relay modes speak a binary frame protocol
over stdio, so nothing here gets a shell out of a host by itself. Every piece below has a
server-side contract already fixed, which is the whole of what this side owes it.

- **Transport.** Open a `direct-streamlocal` channel straight to the session socket once a
  host profile says it is allowed; [IMPLEMENTATION.md § 7](IMPLEMENTATION.md#7-attach-relay)'s
  relay is the path until then and wherever it is not, and both reach the same socket.
- **Bootstrap.** Probe, select an architecture, upload, cache a negative result per host.
  [§ 5.1](IMPLEMENTATION.md#51-probe-and-attach-in-one-round-trip)'s `NOMUX-BOOTSTRAP` line
  and [§ 5.2](IMPLEMENTATION.md#52-upload-and-attach-in-one-round-trip)'s shell are what
  this side offers; [§ 5.3](IMPLEMENTATION.md#53-decision-tree) is the decision tree.
- **Version skew.** Retain codecs ([DESIGN.md § 6.4](DESIGN.md#64-version-skew)), and never
  auto-reconnect after `Error{TAKEOVER}` — the daemon has given the session to somebody
  else ([IMPLEMENTATION.md § 6.4](IMPLEMENTATION.md#64-multiple-clients)).
- **Collecting uploaded binaries.** Nothing on the server ever unlinks one, so every
  release leaves another artifact in every user's home on every host they have touched.
  The client knows each session's version and is the only side that can tell a stale
  `nomux-*` from a live one.
- **Verifying an upload.** The producing half exists — a `v*` tag publishes `SHA256SUMS`
  per architecture — and nothing reads it. See P2, which is the same gap from the release
  side.
- **The session ceiling.** Eight per host ([DESIGN.md § 5.1](DESIGN.md#51-identity)). The
  daemon's 64 is a backstop under it; only the side that knows a tab was opened can hold
  the real one.
- **Gaps, repaint and agent forwarding.** Reset the emulator on a `Gap`
  ([IMPLEMENTATION.md § 4.3](IMPLEMENTATION.md#43-gap-handling)); choose the repaint policy
  per attach, since only the client knows whether an editor or a prompt is on screen; and
  answer agent channels from the key store behind a per-host opt-in, the daemon never
  turning forwarding on by itself.
- **Warn about the dangling agent.** Where the creating connection carried `ForwardAgent`
  but the nomux opt-in was not set, the child inherits sshd's `SSH_AUTH_SOCK` — and sshd
  unlinks that socket when the connection ends, leaving the session holding a path to
  nothing for the rest of its life. The obvious server-side fix is wrong: the daemon cannot
  tell sshd's forwarded socket from a stable local one (`gpg-agent --enable-ssh-support`,
  gnome-keyring, `keychain`), so scrubbing `SSH_AUTH_SOCK` would break the users whose agent
  lives on the server and survives every reconnect — and a child's environment cannot be
  mutated after `exec` anyway
  ([DESIGN.md § 5.3](DESIGN.md#53-transparency)). The client knows both whether it passed
  `ForwardAgent` and whether it asked for nomux forwarding, so it is the only side that can
  tell the two apart.
- **Exit status and labels.** The child's status rides in the `Exit` frame the relay cannot
  read, with `since_exit_secs` beside it: a status collected as it happened and one
  collected days later are not the same thing to show a user. And `--label` is minted on
  `spawn`, so an orphan is recognisable in `nomux list` after the client has lost its
  state.

## P2 — release process

- Decide when the pinned nightly moves: `scripts/nightly-version` names it once and
  `scripts/size-baseline` records the compiler that measured the bytes, so a disagreeing
  compiler is refused; undecided is the policy for taking a newer one.
- Decide what the client does when a host holds a binary whose hash it no longer knows.
  A `v*` tag already publishes `SHA256SUMS`, but nothing in the client reads it, so
  [DESIGN.md § 8](DESIGN.md#8-security-model)'s "verify it after upload" is unwritten.

## P3 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`. The codec's property
  tests drive a seeded generator of their own, which covers the shapes the parser has but
  not the ones it does not.
- Chaos against a real full-screen program; the suite stays deterministic on sixel and
  CSI from `sh`, and driving an actual `vim` would test `vim`.
- `MAX_PENDING_READ`'s *runtime* behaviour has no test. The arithmetic is pinned — a static
  assertion at the top of `conn.rs` against `HEADER_LEN + MAX_PAYLOAD`, and the unit test
  `a_maximum_payload_frame_fits_under_the_read_cap` for the largest frame there is — but
  nothing drives a peer into the cap itself: the kernel's send buffer is tighter than 1 MiB
  on a stock host, and forcing it with `SO_SNDBUF` is a test that silently cannot fail.

## P4 — optimisations already tried

Both of these were written, found to break a named guard, and reverted. Both still look
free from a distance, and neither is: what each costs is recorded here so the next person
to see it finds the reason rather than the diff.

- **Reap on `SIGCHLD` instead of polling for it.** `collect_status` spends a
  `waitpid(WNOHANG)` on every pass for the whole life of a running child, because
  `Child::try_wait` caches nothing until it has reaped. Gating it on `child_gone.is_some()`
  breaks `lifecycle::a_shell_that_exits_behind_a_background_job_is_still_reaped`, and so
  does every interval variant, for one reason: that test runs `sleep 300 & exit`, and the
  job holds the slave open, so the master never reports end of file and `child_gone` is
  never set. The whole of what the test gives the daemon is a single pass, supplied by a
  `Ping`, on which the shell must already have been collected — an interval has nothing to
  have elapsed. The fix that works is not a cheaper predicate but a different shape: a
  `SIGCHLD` handler writing into the stop pipe `startup.rs` already arms, which makes
  reaping event-driven and deletes the per-pass syscall rather than skipping it.
- **Drain the PTY to `EAGAIN` instead of one bufferful a pass.** `read_pty` takes 64 KiB and
  returns, so 100 MB of output is some 1600 poll round trips. Looping to `WouldBlock` breaks
  `session::an_overflow_that_outruns_an_attached_client_is_reported_as_a_gap_mid_stream`,
  whose 128 KiB ring is sized *against* the per-pass figure so that a client keeping up
  cannot be gapped by a single read — the premise the test's determinism rests on. Resizing
  the ring does not rescue it: with an unbounded drain one pass can take more than any ring,
  so the test would have to be restructured to have the client consume part of the stream
  before it stalls. **And the user-visible half is the one that decides it**: today a burst
  larger than the ring still delivers the client its first ~1 MiB and gaps after; drained to
  `EAGAIN` it would gap at once and serve only the tail. That is a change to what a person
  sees on reattach, and it wants judging on its own merits before any test is rewritten to
  permit it.
