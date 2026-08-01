# nomux

A single static Linux binary that runs on an SSH server and keeps a terminal
session alive across the loss of the SSH connection that created it.

Persistence without a multiplexer: no prefix key, no panes, no status bar, no
rewritten `TERM`. Byte-exact passthrough, so sixel, OSC 52, hyperlinks, mouse
reporting and scrollback all work unchanged.

```
nomux daemon <session-id>   Own a PTY session
nomux attach <session-id>   Relay stdio to a session, spawning it if absent
nomux probe                 Report OS, architecture and install path
```

Four properties drive the design:

- **Byte-stream replay, not screen-state sync** — no terminal emulator on the server.
- **Resume over a fresh SSH connection, not a side channel** — inherits ProxyJump, certificates, 2FA, agent forwarding.
- **Zero server-side install** — the client carries the binary and pushes it on first use.
- **No new ports, no new crypto** — the only endpoint is a `0600` unix socket.

The SSH client and terminal emulator are a **separate project**; this repository is
the server-side binary only. The two ship as one unit and are versioned in lockstep,
so the wire protocol is private and carries no stability guarantee.

- [DESIGN.md](DESIGN.md) — problem, properties, architecture, security model, prior art.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — wire protocol, ring buffer, PTY handling, bootstrap, build.

## Build

Requires Rust 1.97.1, pinned in `rust-toolchain.toml`.

```sh
cargo clippy --workspace --all-targets
cargo test --workspace
```

The pin selects the `1.97.1` toolchain, which is a distinct rustup installation from
`stable` even when both resolve to the same version. Targets added to `stable` are
not visible here, so add them explicitly:

```sh
rustup target add --toolchain 1.97.1 \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf \
  riscv64gc-unknown-linux-musl

cargo build --release --target x86_64-unknown-linux-musl
```

Cross-linking uses `zig cc`; see [IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build).

## Status

Early. The protocol codec and CLI skeleton exist; the daemon, relay and bootstrap
are not implemented yet.

## License

MIT OR Apache-2.0
