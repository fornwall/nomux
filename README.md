# nomux

A single static Linux binary that runs on an SSH server and keeps a terminal
session alive across the loss of the SSH connection that created it.

Persistence without a multiplexer: no prefix key, no panes, no status bar, no
rewritten `TERM`. Byte-exact passthrough, so sixel, OSC 52, hyperlinks, mouse
reporting and scrollback all work unchanged.

> [!WARNING]
> **There is nothing to run yet, and none of it has seen real world usage.** This
> repository is the server half; the SSH client and terminal emulator that drive it are a
> separate, unreleased project, and without that client there is no way to get a shell out
> of this — the relay modes speak a binary frame protocol over stdio rather than driving a
> terminal, so `nomux list` and `nomux kill` are what works standalone. The daemon is
> started directly and stays in sshd's session cgroup, so on a host configured
> `KillUserProcesses=yes` logind kills it at the final logout and **the session does not
> survive** — the same footing `tmux` and `screen` are on, and survivable for the same
> reason: `KillUserProcesses=no` is the default nearly everywhere. Persistence on a strict
> host has to be arranged around nomux (`loginctl enable-linger` and a scope of your own).
> The logout matrix is exercised in containers ([e2e-tests/](e2e-tests/README.md)) but not
> yet on a real host. AI-generated, and experimental.

`nomux <mode> [session-id]`. The binary-protocol modes are `daemon`, `spawn` and
`attach`; `--label` is accepted only when creating through `daemon` or `spawn`.
`list` and `kill` are the human-facing control surface.
`nomux --help` has the rest.

The system is this binary plus the client that pushes and drives it, versioned and shipped
as one unit — which is why the wire protocol is private and carries no stability guarantee
([DESIGN.md § 2](DESIGN.md#2-scope)).

Four properties drive it, and two of them are held on this side. What each one costs is
[DESIGN.md § 3](DESIGN.md#3-key-properties):

- **Byte-stream replay, not screen-state sync** — no terminal emulator on the server. *This repository.*
- **No new ports, no new crypto** — the only endpoints are unix sockets, one per session, plus one more when agent forwarding is enabled. *This repository.*
- **Resume over a fresh SSH connection, not a side channel** — inherits ProxyJump, certificates, 2FA, agent forwarding. *The client's.*
- **Zero server-side install** — the client carries the binary and pushes it on first use. *The client's.*

## Build

The Rust toolchain is pinned in `rust-toolchain.toml`, and rustup fetches it on the first
Cargo command.

```sh
git clone https://github.com/fornwall/nomux && cd nomux
cargo build     # rustup installs the pinned toolchain on first use
cargo test      # unit and integration tests, plus the one doctest
```

The optional local commit gate additionally needs [prek](https://github.com/j178/prek),
`cargo-nextest`, `cargo-deny`, `shellcheck` and `actionlint` on `PATH`; CI pins their exact
versions. Run `prek install` once per clone or `prek run --all-files` directly. Release
builds, size budgets and the pinned nightly are in
[IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build).

## Status

Server prototype under extensive test on Linux with procfs and PTYs. Linux 5.3+ is
required for the complete control surface; older kernels support sessions and `list`, but
`kill` refuses without `pidfd_open`. Testing and release invariants are in
[IMPLEMENTATION.md](IMPLEMENTATION.md); production blockers are in [PLAN.md](PLAN.md).

## License

[Apache-2.0](LICENSE)
