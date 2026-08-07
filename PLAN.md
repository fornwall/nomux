# nomux — Backlog

Open server-side work, in priority order; the client is a separate project.

1. **Survive systemd logout policy honestly.** Launch or move the daemon into a user-manager
   scope/service, define behavior without a user bus, and test real SSH logout across the
   `KillUserProcesses` × linger matrix. POSIX `setsid` alone does not leave
   `session-*.scope`; make terminal-detach, directory-change and standard-I/O failures
   reportable before publication rather than best-effort.
2. **Exercise the real client lifecycle.** A reference client must cover upload verification,
   Hello, shell I/O, detach/replay, takeover, agent forwarding and exit before the protocol
   or control surface is declared stable.
3. **Make every shipping architecture pass the same lifecycle.** Run the full release smoke
   natively on AArch64 (or under a self-exec-capable emulator), require static PIE there,
   retain checksum-addressed debug information for crash symbolization, and rehearse the
   artifact manifest/download checks on every pull request.
4. **Harden and soak the state machine.** Add stateful protocol fuzzing plus scheduled
   attach/detach/agent churn with FD and RSS bounds; inject `pidfd_open` failure to prove
   old-kernel teardown stays conservative.
