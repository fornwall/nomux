# nomux — Backlog

Open server-side work, in priority order; the client is a separate project.

1. **Measure the direct daemon's logout fate on a real host.** nomux no longer has a logout
   policy to validate: the systemd user scope is gone and `spawn` always launches the daemon
   directly, so what survives a logout is decided entirely by the host's `KillUserProcesses`
   and by nothing nomux does
   ([IMPLEMENTATION.md § 6.2](IMPLEMENTATION.md#62-terminal-detachment-and-logout-policy)).
   That is still worth measuring rather than reasoning about. The `KillUserProcesses` ×
   linger × `pam_systemd` matrix is mechanized in [e2e-tests/](e2e-tests/README.md) — systemd
   as PID 1, real logind, real sshd, real SSH logout — and every cell matches its recorded
   verdict, including a missing user bus and the cells where the login is **blackholed**
   rather than logged out of: a laptop lid, a dead NAT entry, reaching the logout through
   sshd's `ClientAlive` timeout instead of an orderly close. Those return their clean twins'
   verdicts, so the two paths converge at PAM's session close and the daemon's fate turns on
   the cgroup it is in and on nothing about how the login ended — which is the useful result,
   because the connection that vanishes is the case nomux exists for. What is left is where
   it runs: the cells want a bare-metal or VM host, and an architecture and distribution
   beyond Debian on x86-64, though what varies across distributions is mostly which cell a
   user lands in by default rather than the cells themselves.
2. **Exercise the real client lifecycle.** A reference client must cover upload verification,
   Hello, shell I/O, detach/replay, takeover, agent forwarding and exit before the protocol
   or control surface is declared stable.
3. **Make every shipping architecture pass the same lifecycle.** Run the full release smoke
   natively on AArch64 (or under a self-exec-capable emulator) and retain checksum-addressed
   debug information for crash symbolization.
4. **Harden and soak the state machine.** Add stateful protocol fuzzing plus scheduled
   attach/detach/agent churn with FD and RSS bounds; inject `pidfd_open` failure to prove
   old-kernel teardown stays conservative.
