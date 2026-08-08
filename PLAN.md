# nomux — Backlog

Open server-side work, in priority order; the client is a separate project.

1. **Validate systemd logout policy end to end.** The launcher now selects a transient user
   scope only when the user bus is reachable and logind reports linger, with an explicit
   direct fallback otherwise. Exercise real SSH logout across the `KillUserProcesses` ×
   linger matrix, including a missing user bus, and decide whether terminal-detach,
   directory-change and standard-I/O failures may remain best-effort after publication.
2. **Exercise the real client lifecycle.** A reference client must cover upload verification,
   Hello, shell I/O, detach/replay, takeover, agent forwarding and exit before the protocol
   or control surface is declared stable.
3. **Make every shipping architecture pass the same lifecycle.** Run the full release smoke
   natively on AArch64 (or under a self-exec-capable emulator) and retain checksum-addressed
   debug information for crash symbolization.
4. **Harden and soak the state machine.** Add stateful protocol fuzzing plus scheduled
   attach/detach/agent churn with FD and RSS bounds; inject `pidfd_open` failure to prove
   old-kernel teardown stays conservative.
