> [!WARNING]
> **Experimental.** This project is AI-generated and has not seen real world usage.

# nomux

A single static Linux binary that runs on an SSH server and keeps a terminal
session alive across the loss of the SSH connection that created it.

Persistence without a multiplexer: no prefix key, no panes, no status bar, no
rewritten `TERM`. Byte-exact passthrough, so sixel, OSC 52, hyperlinks, mouse
reporting and scrollback all work unchanged — up to the ring's capacity; a
disconnect that outlasts it is reported as an explicit gap, not silently truncated.

`nomux <mode> [session-id] [--label <text>]`. The modes are `daemon`, `spawn` and
`attach`; `list` and `kill` are the control surface, frozen across versions.
`nomux --help` has the rest.

Four properties drive the design. They are the system's — this binary and the client
that pushes and drives it, versioned as one unit — and two of them, the resume path
and the zero install, are the client's half to hold:

- **Byte-stream replay, not screen-state sync** — no terminal emulator on the server.
- **Resume over a fresh SSH connection, not a side channel** — inherits ProxyJump, certificates, 2FA, agent forwarding.
- **Zero server-side install** — the client carries the binary and pushes it on first use.
- **No new ports, no new crypto** — the only endpoints are unix sockets at `0600` inside a `0700` directory, one per session, plus one more when agent forwarding is enabled.

**There is nothing to run yet.** This repository is the server half. The SSH client
and terminal emulator that drive it are a separate, unreleased project, and both
`nomux spawn` and `nomux attach` relay a binary frame protocol over stdio rather than
driving a terminal — so without that client there is no way to get a shell out of
this. What works standalone today is `nomux list` and `nomux kill`. The two halves
ship as one unit, so the wire protocol is private and carries no stability guarantee
([DESIGN.md § 2](DESIGN.md#2-scope)).

- [DESIGN.md](DESIGN.md) — problem, properties, architecture, security model, prior art.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — wire protocol, ring buffer, PTY handling, bootstrap, build.
- [PLAN.md](PLAN.md) — backlog: known gaps, unbuilt features, deferred decisions.

## Build

Nothing has to be installed by hand: the toolchain is pinned in
`rust-toolchain.toml`, and rustup fetches it on the first command.

```sh
git clone https://github.com/fornwall/nomux && cd nomux
cargo build     # rustup installs the pinned 1.97.1 on first use
cargo test      # the whole suite, doctests included, about 20 s
prek install    # once per clone: the commit gate, `.pre-commit-config.yaml`
```

[prek](https://github.com/j178/prek) runs the same hooks CI does. Release builds,
size budgets, the pinned nightly and the debug companions are in
[IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build).

## Status

[PLAN.md § Status](PLAN.md#status) — the copy kept current.

## License

[Apache-2.0](LICENSE)
