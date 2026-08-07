# nomux — Backlog

Open questions, in priority order. Why the system is shaped as it is:
[DESIGN.md](DESIGN.md), whose § 10 records what was considered and refused. What it does
and what a second implementation must obey: [IMPLEMENTATION.md](IMPLEMENTATION.md).

The client is a separate project ([DESIGN.md § 4](DESIGN.md#4-architecture)) and none of
its work is tracked here; what this side owes it is fixed contract in
[IMPLEMENTATION.md](IMPLEMENTATION.md), not an open question.

## P1 — release process

- Decide when the pinned nightly moves. Where it is named, and why the compiler that
  measured a baseline is recorded beside it rather than checked against the one building,
  is [IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build). Undecided is the policy for taking
  a newer one.

## P2 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`. The codec's property
  tests drive a seeded generator of their own, which covers the shapes the parser has but
  not the ones it does not.
- Chaos against a real full-screen program; the suite stays deterministic on sixel and
  CSI from `sh`, and driving an actual `vim` would test `vim`.

## P3 — one the code argues against, and what is still open in it

It was written and reverted, and `daemon.rs` now carries the reason beside the code that
holds it. What that comment does *not* settle is left here.

- **Reaping on `SIGCHLD`.** `collect_status` spends a `waitpid` every pass for a running
  child's whole life; the comment there says why the cheap gate fails. Open is the shape
  that works: a handler writing into the stop pipe `startup.rs` already arms, which deletes
  the syscall rather than skipping it.
