# nomux — Backlog

Open server-side work, in priority order; the client is a separate project.

1. **Validate systemd logout policy on a real host.** The `KillUserProcesses` × linger ×
   `pam_systemd` matrix is now mechanized in [e2e-tests/](e2e-tests/README.md) — systemd as
   PID 1, real logind, real sshd, real SSH logout — and all five cells match their predicted
   verdict, including a missing user bus. Two things it settles: a lingering user manager
   does carry a session through `KillUserProcesses=yes`, and without linger the direct
   fallback is killed at the final logout, so **`loginctl enable-linger` is a requirement on
   a strict host and not a nicety**. Three things are left. Every cell logs *out* cleanly,
   where the case nomux exists for is a connection that **drops** — a different teardown,
   reached through sshd's `ClientAlive` timeout rather than an orderly session close, and the
   gap worth closing first. The cells then want a bare-metal or VM host and an architecture
   and distribution beyond Debian on x86-64, though what varies across distributions is
   mostly which cell a user lands in by default rather than the cells themselves. Last,
   `release_startup_state`'s two best-effort calls now need deciding on, a session provably
   outliving its login: a failed `chdir("/")` pins the inherited directory for the daemon's
   whole idle life, and a `/dev/null` that will not open leaves all three standard
   descriptors inherited. Terminal detachment is *not* among them — `publish` propagates it,
   and has all along.
2. **Exercise the real client lifecycle.** A reference client must cover upload verification,
   Hello, shell I/O, detach/replay, takeover, agent forwarding and exit before the protocol
   or control surface is declared stable.
3. **Make every shipping architecture pass the same lifecycle.** Run the full release smoke
   natively on AArch64 (or under a self-exec-capable emulator) and retain checksum-addressed
   debug information for crash symbolization.
4. **Harden and soak the state machine.** Add stateful protocol fuzzing plus scheduled
   attach/detach/agent churn with FD and RSS bounds; inject `pidfd_open` failure to prove
   old-kernel teardown stays conservative.
