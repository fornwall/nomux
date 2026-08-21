# nomux — Backlog

Open server-side work, in priority order; the client is a separate project.

1. **Measure the direct daemon's logout fate on a real host.** The `KillUserProcesses` ×
   linger × `pam_systemd` matrix is mechanized in [e2e-tests/](e2e-tests/README.md) — systemd
   as PID 1, real logind, real sshd, both orderly logouts and blackholed ones — and every
   cell matches its recorded verdict. What is left is where it runs: the cells want bare
   metal or a VM, and an architecture and distribution beyond Debian on x86-64.
2. **Exercise the real client lifecycle.** A reference client must cover upload verification,
   Hello, shell I/O, detach/replay, takeover, agent forwarding and exit before the protocol
   or control surface is declared stable.
3. **Retain checksum-addressed debug information for crash symbolization.** Note the shipped artifact now has its section header table removed as well as its symbols (§ 8), so symbolization has to work from a retained unstripped build keyed by the published hash — which is what this item is for, but it is no longer optional.
4. **Harden and soak the state machine.** Scheduled attach/detach/agent churn with FD and
   RSS bounds is still missing. Two of this item's three parts are now done: `pidfd_open`
   failure is injected with a seccomp filter answering `ENOSYS`, pinning that `kill` refuses
   and leaves the session serving rather than signalling a number that may have been
   recycled; and `fuzz_targets/framing.rs` fuzzes the stream-framing layer, comparing a
   whole-buffer decode against the same bytes delivered in arbitrary chunks. What framing
   fuzzing still cannot reach is `Conn`'s own buffer management — `MAX_PENDING_READ`, its
   growth and compaction, and the refusal of a peer declaring more than the reader will
   hold — because `conn.rs` lives in the binary and a fuzz target can only import the
   library. Closing that means moving the framing reader into `nomux_protocol`.
