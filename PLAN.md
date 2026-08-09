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
3. **Make every shipping architecture pass the same lifecycle.** Run the full release smoke
   natively on AArch64 (or under a self-exec-capable emulator) and retain checksum-addressed
   debug information for crash symbolization.
4. **Harden and soak the state machine.** Add stateful protocol fuzzing plus scheduled
   attach/detach/agent churn with FD and RSS bounds; inject `pidfd_open` failure to prove
   old-kernel teardown stays conservative.
