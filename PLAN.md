# nomux — Backlog

Open questions, in priority order. Why the system is shaped as it is:
[DESIGN.md](DESIGN.md), whose § 10 records what was considered and refused. What it does
and what a second implementation must obey: [IMPLEMENTATION.md](IMPLEMENTATION.md).

## P3 — release process

- Decide when the pinned nightly moves: `scripts/nightly-version` names it once and
  `scripts/size-baseline` records the compiler that measured the bytes, so a disagreeing
  compiler is refused; undecided is the policy for taking a newer one.
- Decide what the client does when a host holds a binary whose hash it no longer knows.
  A `v*` tag already publishes `SHA256SUMS`, but nothing in the client reads it, so
  [DESIGN.md § 8](DESIGN.md#8-security-model)'s "verify it after upload" is unwritten.

## P4 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`; `proptest` covers the
  parser on stable today, so the dependency has not earned itself.
- Chaos against a real full-screen program; the suite stays deterministic on sixel and
  CSI from `sh`, and driving an actual `vim` would test `vim`.
- `MAX_PENDING_READ`'s *runtime* behaviour has no test. The arithmetic is pinned — a
  static assertion at `conn.rs:31` and a unit test at `conn.rs:499` cover a frame at
  exactly `MAX_PAYLOAD` clearing the cap — but nothing drives a peer into the cap itself:
  the kernel's send buffer is tighter than 1 MiB on a stock host, and forcing it with
  `SO_SNDBUF` is a test that silently cannot fail.
