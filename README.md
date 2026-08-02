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
nomux list                  List sessions in the run directory
nomux kill <session-id>     Terminate a session and unlink its run files

  --label <text>            Display name for `list`, recorded at session creation
  --version, -V             Print version and protocol revision
  --help, -h                Print this usage
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
- [PLAN.md](PLAN.md) — backlog: known gaps, unbuilt features, deferred decisions.

## Build

Requires Rust 1.97.1, pinned in `rust-toolchain.toml`.

```sh
cargo clippy --workspace --all-targets
cargo nextest run --workspace
```

Warnings are errors, configured in `Cargo.toml` via `warnings = { level = "deny",
priority = 1 }` rather than a command-line flag — so `cargo build`, `cargo clippy`
and every editor's rust-analyzer all agree, with no cache thrash from differing
`RUSTFLAGS`.

Commits are gated by [prek](https://github.com/j178/prek) on shellcheck, formatting,
clippy, tests and doctests:

```sh
prek install            # once, per clone
prek run --all-files    # run the gate manually
```

The hooks trigger on `*.rs`, `*.toml` and `Cargo.lock` — manifests included, because
the lint configuration lives in `Cargo.toml` — and on `*.sh`, because the release
build and the takeover guard are shell and no Rust hook would ever look at them.

Two things are deliberately left out of the pre-commit gate and run in CI instead,
because both cost far more than a commit should:

```sh
cargo nextest run --workspace --run-ignored all   # includes the reaping timeouts
sh scripts/verify-takeover-guard.sh               # rebuilds under fault injection
```

The chaos suite picks its disconnect points from a fixed seed, so a failure
reproduces; `NOMUX_CHAOS_SEED=<n>` explores other interleavings, and every failure
message carries the seed that produced it.

## Release builds

The four shipping binaries come from one script:

```sh
sh scripts/build-release.sh     # → target/dist/ plus SHA256SUMS
```

It builds every musl target, prints a size table with the change against the
per-target baseline in `scripts/size-baseline`, and fails if any binary exceeds the
400 KiB budget or has grown more than 3% since that baseline — the cap on its own
let a 48% armv7 regression through unremarked. `NOMUX_UPDATE_BASELINE=1` rewrites
the baseline from that build and skips the growth gate, so an intended size change
lands in the diff. There is no cross toolchain to install — `rust-lld` links all
four and each `rust-std` component carries its own musl objects — but the shipping
configuration rebuilds the standard library with panics compiled out, which needs
nightly and its sources:

```sh
rustup toolchain install nightly --component rust-src
rustup target add --toolchain nightly \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf \
  riscv64gc-unknown-linux-musl
```

That is not an optimisation: with the released standard library, every target
misses the size budget. `NOMUX_STABLE_STD=1` builds against the pinned stable
toolchain and is expected to fail the gate. `NOMUX_NIGHTLY=nightly-YYYY-MM-DD` pins
the compiler, which a release must do — the client pins a SHA-256 per architecture,
and a floating nightly moves it. See
[IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build) for the measurements.

## Status

Working end to end on Linux: the daemon owns a PTY and ring buffer, clients resume
by byte offset across a severed connection, agent forwarding proxies `ssh-agent`
over the same channel, `attach` spawns a daemon on demand and relays, and
`list`/`kill` operate on the run directory alone.

What is left is the release process — pinning the shipping nightly and publishing
the checksums the client verifies against — plus client-side work
(`direct-streamlocal`, bootstrap orchestration, emulator reset on gap) and a
handful of decisions deliberately deferred. See [PLAN.md](PLAN.md).

Tunables: `NOMUX_RING_BYTES` overrides the 4 MiB output ring per daemon.

## License

MIT OR Apache-2.0
