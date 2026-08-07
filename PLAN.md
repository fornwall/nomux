# nomux — Backlog

Open questions, in priority order. Why the system is shaped as it is:
[DESIGN.md](DESIGN.md), whose § 10 records what was considered and refused. What it does
and what a second implementation must obey: [IMPLEMENTATION.md](IMPLEMENTATION.md).

The client is a separate project ([DESIGN.md § 4](DESIGN.md#4-architecture)) and none of
its work is tracked here; what this side owes it is fixed contract in
[IMPLEMENTATION.md](IMPLEMENTATION.md), not an open question.

## P1 — release process

- Decide when the pinned nightly moves — **two** independently dated pins, not one policy
  applied twice. `scripts/build-release.sh` dates its own so the bytes a client hashes
  cannot drift; `fuzz/run.sh` dates its own so a nightly regression cannot turn a green
  tree red with no commit behind it. They answer different questions and either can move
  without the other, and nothing compares them — so the policy has to say whether that
  stays true or one of the two becomes the other's floor. Where the release pin is named,
  and why the compiler that measured a baseline is recorded beside it rather than checked
  against the one building, is [IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build).

## P2 — test depth

- A repaint interleaved with an exactly-once resend: `ctrl_l` repainting
  ([IMPLEMENTATION.md § 4.3](IMPLEMENTATION.md#43-gap-handling)) puts a form feed into the
  child's input while the client resends from `in_applied` across repeated overflow, and
  the two are covered apart but never together. It wants a child that tolerates a stray
  `0x0c` in its input, which the marker-counting shells in `chaos.rs` do not — so it is a
  test of its own rather than a case added to one.
