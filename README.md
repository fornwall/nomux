> [!WARNING]
> **Experimental.** nomux is AI-generated: written by an AI agent, reviewed but not
> battle-tested. It has a thorough test suite and no real-world mileage, and the
> client that drives it does not exist publicly yet — so this is something to read,
> not something to point at a server you care about.

# nomux

A single static Linux binary that runs on an SSH server and keeps a terminal
session alive across the loss of the SSH connection that created it.

Persistence without a multiplexer: no prefix key, no panes, no status bar, no
rewritten `TERM`. Byte-exact passthrough, so sixel, OSC 52, hyperlinks, mouse
reporting and scrollback all work unchanged — up to the ring's capacity; a
disconnect that outlasts it is reported as an explicit gap rather than silently
truncated.

```
nomux daemon <session-id>   Own a PTY session (normally spawned by `attach`)
nomux attach <session-id>   Relay stdio to a session, spawning it if absent
nomux probe                 Report OS, architecture and install path
nomux list                  List sessions in the run directory
nomux kill <session-id>     Terminate a session and unlink its run files

  --label <text>            Display name for `list`, recorded at session creation.
                            Honoured by `daemon` and `attach`; `kill` parses it and
                            ignores it, the label belonging to the session
  --version, -V             Print version and protocol revision
  --help, -h                Print this usage
```

Four properties drive the design:

- **Byte-stream replay, not screen-state sync** — no terminal emulator on the server.
- **Resume over a fresh SSH connection, not a side channel** — inherits ProxyJump, certificates, 2FA, agent forwarding.
- **Zero server-side install** — the client carries the binary and pushes it on first use.
- **No new ports, no new crypto** — the only endpoints are unix sockets at `0600` inside a `0700` directory, one per session, plus one more when agent forwarding is enabled.

**There is nothing to run yet.** This repository is the server half. The SSH client
and terminal emulator that drive it are a separate, unreleased project, and
`nomux attach` speaks a binary frame protocol over stdio rather than a terminal — so
without that client there is no way to get a shell out of this. What works standalone
today is `nomux probe`, `nomux list` and `nomux kill`. The two halves ship as one unit
and are versioned in lockstep, so the wire protocol is private and carries no
stability guarantee.

- [DESIGN.md](DESIGN.md) — problem, properties, architecture, security model, prior art.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — wire protocol, ring buffer, PTY handling, bootstrap, build.
- [PLAN.md](PLAN.md) — backlog: known gaps, unbuilt features, deferred decisions.

## Build

Nothing has to be installed by hand: the toolchain is pinned in
`rust-toolchain.toml`, and rustup fetches it on the first command.

```sh
git clone https://github.com/fornwall/nomux && cd nomux
cargo build     # rustup installs the pinned 1.97.1 on first use
cargo test      # 112 tests plus 2 doctests, about 10 s
```

Both runners are supported, and the line above is the one to start with. The tree is
developed against `cargo-nextest` — one more tool, for one property: it runs every
test in its own process. Several of these tests fork, and a forked child inherits
every open descriptor of whichever other test happens to be mid-flight, so under
`cargo test`'s single process that is a sharpness the suite absorbs rather than one
it is spared. What it takes to absorb it is written down in
[PLAN.md § P2](PLAN.md#p2--structure), and it is a standing obligation on new tests
rather than a thing that was fixed once.

```sh
cargo install cargo-nextest
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
Every hook is `language: system`, so prek installs nothing on their behalf:
`shellcheck` and `cargo-nextest` have to be on `$PATH` already, or the first run of
the gate in a fresh clone fails on a missing command rather than on anything in the
tree.

Two things are deliberately left out of the pre-commit gate and run in CI instead,
because both cost far more than a commit should:

```sh
cargo nextest run --workspace --run-ignored all   # includes the 30 s first-attach reap
sh scripts/verify-takeover-guard.sh               # rebuilds under fault injection
```

CI runs a third thing that is in neither list: the whole musl release build below.
It needs a nightly compiler and four cross targets installed, which makes it the one
check the local hooks genuinely cannot stand in for.

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
let a 46% armv7 regression through unremarked. `NOMUX_UPDATE_BASELINE=1` rewrites
the baseline from that build and skips the growth gate, so an intended size change
lands in the diff. There is no cross toolchain to install — `rust-lld` links all
four and each `rust-std` component carries its own musl objects — but the shipping
configuration rebuilds the standard library with panics compiled out, which needs
nightly and its sources:

```sh
nightly=$(cat scripts/nightly-version)
rustup toolchain install "$nightly" --component rust-src
rustup target add --toolchain "$nightly" \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf \
  riscv64gc-unknown-linux-musl
```

That is not an optimisation: with the released standard library, every target
misses the size budget. `NOMUX_STABLE_STD=1` builds against the pinned stable
toolchain and is expected to fail the gate. The nightly is dated rather than
floating, and `scripts/nightly-version` is where it is named: the script and CI both
read it from there, so a local build and the runner measure the same bytes against a
baseline recorded by the same compiler. `NOMUX_NIGHTLY` overrides it for a build that
is not a release; a release must pin, because the client is meant to pin a SHA-256
per architecture and a floating compiler moves the bytes that hash is taken over.
Nothing verifies a hash today — `SHA256SUMS` is built and nothing publishes it
([PLAN.md § P3](PLAN.md#p3--release-process)). The measurements are in
[IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build).

## Status

Complete and under test on Linux, and not released: every property above is
implemented in the daemon and covered by the suite, and what is left is the release
process and the client that drives it. The standing state — what works, what is
known to be missing, and what was deferred on purpose — is
[PLAN.md § Status](PLAN.md#status), which is the copy kept current rather than a
second copy that drifts.

## License

[Apache-2.0](LICENSE)
