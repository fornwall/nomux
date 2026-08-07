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
> terminal, so `nomux list` and `nomux kill` are what works standalone. On systemd hosts
> that kill SSH session scopes at logout, this release cannot yet keep a daemon alive; a
> user-manager-backed launch is an explicit release gate. AI-generated, and experimental.

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

Five files, held to a rule that none of them repeats another:

- [DESIGN.md](DESIGN.md) — problem, properties, architecture, security model, prior art, rejected alternatives.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — wire protocol, ring buffer, PTY handling, bootstrap, build.
- [PLAN.md](PLAN.md) — what is open on this side.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability, and what gets fixed.
- [LICENSE](LICENSE) — Apache-2.0.

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

Server prototype under extensive test on Linux at the protocol revision
[IMPLEMENTATION.md § 2.2](IMPLEMENTATION.md#22-messages) states. The remaining blockers
before a production claim are tracked in [PLAN.md](PLAN.md).

- **Platform** — Linux with procfs and PTYs. Linux 5.3+ is required for the complete
  control surface: on an older kernel `list` and sessions still work, but `kill` refuses
  rather than signal a reusable bare pid without `pidfd_open`. Everywhere else, plain SSH
  ([DESIGN.md § 7](DESIGN.md#7-degradation)). POSIX detachment survives an SSH-channel
  loss, but not a systemd policy that kills the containing login scope.
- **Suite** — layers and invariants in [IMPLEMENTATION.md § 9](IMPLEMENTATION.md#9-testing); CI adds `--run-ignored all`.
- **Release** — both musl targets build reproducibly inside the size and growth gates, and a `v*` tag builds, checks and publishes them ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)).
- **Client** — not started; the current server-side contract is documented in [IMPLEMENTATION.md](IMPLEMENTATION.md) and remains provisional until exercised end to end.

## License

[Apache-2.0](LICENSE)
