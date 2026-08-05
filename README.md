> [!WARNING]
> **Experimental.** This project is AI-generated and has not seen real world usage.

# nomux

A single static Linux binary that runs on an SSH server and keeps a terminal
session alive across the loss of the SSH connection that created it.

Persistence without a multiplexer: no prefix key, no panes, no status bar, no
rewritten `TERM`. Byte-exact passthrough, so sixel, OSC 52, hyperlinks, mouse
reporting and scrollback all work unchanged — up to the ring's capacity; a
disconnect that outlasts it is reported as an explicit gap rather than silently
truncated.

`nomux --help`, verbatim, because a paraphrase here is a second copy that drifts:

```
usage: nomux <mode> [session-id] [--label <text>]

modes:
  daemon <session-id>   Own a PTY session (normally spawned by `spawn`)
  spawn <session-id>    Create a session and relay stdio to it; fails if it exists
  attach <session-id>   Relay stdio to an existing session; fails if it does not

control surface (frozen across versions, see IMPLEMENTATION.md 6.6):
  list                  List sessions in the run directory
  kill <session-id>     Terminate a session and unlink its run files

options:
  --label <text>        Display name for `list`, recorded when the session is
                        created, so `daemon` and `spawn` take it and `attach` does
                        not. Advisory: ids are opaque, so this is what makes an
                        orphaned session recognisable to a human.
  --version, -V         Print version and protocol revision
  --help, -h            Print this usage
```

Two things that text does not say: `--label=<text>` is accepted as well as the
two-word form, and `kill` parses a label and ignores it, the frozen surface accepting
what it always accepted.

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
ship as one unit and are versioned in lockstep, so the wire protocol is private and
carries no stability guarantee.

- [DESIGN.md](DESIGN.md) — problem, properties, architecture, security model, prior art.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — wire protocol, ring buffer, PTY handling, bootstrap, build.
- [PLAN.md](PLAN.md) — backlog: known gaps, unbuilt features, deferred decisions.

## How it works

The daemon leaves the login session before it publishes its pid, so no hangup and no
keystroke can reach it, and it opens every terminal `O_NOCTTY` so it never acquires
one: the only controlling terminal here is the child's, taken on the PTY slave in a
session of its own. That detachment and the stop pipe are both best-effort. A session
outlives its child, so the exit status and the last of the output are still there for
a client that arrives days later. Topology and states are
[DESIGN.md § 4](DESIGN.md#4-architecture) and [§ 5](DESIGN.md#5-session-lifecycle);
the poll set, and the reasoning behind every call, is
[IMPLEMENTATION.md § 6](IMPLEMENTATION.md#6-daemon).

## Build

Nothing has to be installed by hand: the toolchain is pinned in
`rust-toolchain.toml`, and rustup fetches it on the first command.

```sh
git clone https://github.com/fornwall/nomux && cd nomux
cargo build     # rustup installs the pinned 1.97.1 on first use
cargo test      # the whole suite, doctests included, about 20 s
```

Both runners are supported, and the line above is the one to start with. The tree is
developed against `cargo-nextest` — one more tool, for one property: it runs every
test in its own process, which spares the suite the descriptor sharing that
[PLAN.md § P2](PLAN.md#p2--structure) describes and makes a standing obligation on
new tests.

```sh
cargo install cargo-nextest
cargo clippy --workspace --all-targets
cargo nextest run --workspace   # the same suite, about 6 s
```

Commits are gated by [prek](https://github.com/j178/prek) on actionlint, shellcheck,
formatting, clippy, tests and doctests:

```sh
prek install            # once, per clone
prek run --all-files    # run the gate manually
```

`.pre-commit-config.yaml` is the gate, and it is the single source of truth for those
six: CI runs `prek run --all-files` rather than restating the commands, so a hook and
the step enforcing it cannot drift apart. It skips the one hook whose CI step is a
strict superset — the suite is too slow to run twice.

The hooks trigger on `*.rs`, `*.toml` and `Cargo.lock` — manifests included, because
the lint configuration lives in `Cargo.toml` — on `*.sh`, because the release build
and the takeover guard are shell and no Rust hook would ever look at them, and on
`.github/workflows/*.yml`, which is where the shell no `*.sh` glob reaches actually
lives. Every hook but one is `language: system` and expects its tool on `$PATH`
already, so a fresh clone missing `shellcheck` or `cargo-nextest` fails on the missing
command rather than on anything in the tree. The exception is `actionlint`, pinned by
version and built by prek itself, so a laptop and the runner lint against the same
release rather than against whatever each happens to have.

Four things are deliberately left out of the pre-commit gate and run in CI instead:

```sh
cargo deny check advisories bans licenses sources    # config in deny.toml
RUSTDOCFLAGS='-D warnings' cargo doc --document-private-items
cargo nextest run --workspace --run-ignored all      # includes the 30 s first-attach reap
sh scripts/verify-takeover-guard.sh                  # rebuilds under fault injection
```

The last two cost far more than a commit should. The first two cost seconds and are
out for a different reason: advisories go stale on the calendar rather than on the
diff, so the answer depends on the day and not on the commit, and rustdoc is a lint
namespace neither clippy nor `RUSTFLAGS` reaches — which matters in a tree that links
between items constantly, where a renamed function turns a link into nothing rather
than into an error. CI also asserts that `rust-toolchain.toml` and `Cargo.toml`'s
`rust-version` name the same compiler, since the declared MSRV is only tested while
those two strings agree.

CI runs one more thing that is in neither list: the whole musl release build below.
It needs a nightly compiler and the two musl targets installed, which makes it the one
check the local hooks genuinely cannot stand in for.

The chaos suite picks its disconnect points from a fixed seed, so a failure
reproduces; `NOMUX_CHAOS_SEED=<n>` explores other interleavings, and every failure
message carries the seed that produced it.

## Release builds

The two shipping binaries come from one script:

```sh
sh scripts/build-release.sh     # → target/dist/ and SHA256SUMS
```

It builds every musl target, prints a size table with the change against the
per-target baseline in `scripts/size-baseline`, and fails a binary that misses either
the size budget or the growth gate — both numbers are in
[IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build). There is no cross toolchain to
install — `rust-lld` links both and each `rust-std` component carries its own
musl objects — but the shipping configuration rebuilds the standard library with
panics compiled out, which needs nightly and its sources:

```sh
nightly=$(cat scripts/nightly-version)
rustup toolchain install "$nightly" --component rust-src,llvm-tools
rustup target add --toolchain "$nightly" \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl
```

Why the standard library is rebuilt at all, why `scripts/nightly-version` pins a
dated nightly rather than a floating one, and what `NOMUX_UPDATE_BASELINE=1` is for
are [IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)'s; when that pin moves is
[PLAN.md § P3](PLAN.md#p3--release-process)'s.

`llvm-tools` is for the debug companions below, which `NOMUX_DEBUG=1` asks for;
without it the run builds only the two that ship.

Pushing a `v*` tag runs that same build on CI and publishes a release from it: the
two binaries, and `SHA256SUMS` beside them. Verify a download against the file
rather than by eye:

```sh
sha256sum -c SHA256SUMS
```

GitHub computes its own SHA-256 for every release asset at upload time and shows it
in the UI, `gh release view` and the releases API, so the sums can be checked twice
over. The tag has to name the version the binaries report — CI asks the built binary
and fails the release if the two disagree — and what a *client* should do with these
sums, which is the half that does not exist yet, is
[PLAN.md § P3](PLAN.md#p3--release-process)'s.

### Debug companions

The shipping binaries are stripped and abort without a message, so the `SIGQUIT` core
they leave behind names no functions on its own. Each release carries
`nomux-<target>.debug` for that: the same build unstripped, with the symbols and DWARF
the shipping binary drops, and its own `SHA256SUMS.debug`. Nothing needs one to *run*
nomux — they are for reading a core:

```sh
gdb nomux-x86_64-unknown-linux-musl.debug core
```

`SHA256SUMS` deliberately names only the binaries that ship, because
`sha256sum -c` fails on a file it cannot open and nearly everyone downloads only what
they run. Why a companion is a second build rather than the shipping binary stripped
afterwards, and how the two are checked against each other, is
[IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)'s.

## Diagnostics

A daemon has nowhere to write. It redirects its own stdio to `/dev/null` as the last
thing startup does — under the relay those descriptors are the SSH channel carrying
the client's frame stream, and a diagnostic written there would land in the middle of
it — so from that point on a failure would be silent. Two things answer that.

A session that fails to *start* reports why at the `spawn` that tried to start it, and
an `attach` on an id nothing answers for fails there in the same breath rather than
inventing a session — both at the caller, which is where the reason is wanted:

```
$ nomux spawn work
nomux: run directory /run/user/1000/nomux: mode 770 lets other users create
       files in it; expected a directory owned by this user, mode 700
```

Everything after that goes to syslog, tagged `nomux`, as `user.err` for failures and
`user.info` for a session beginning or ending. On a systemd host:

```sh
journalctl -t nomux                  # everything nomux has said
journalctl -t nomux -f               # follow, while reproducing something
journalctl -t nomux -p err           # failures only
journalctl -t nomux --since -1h
```

Elsewhere it lands in the system log like anything else — `/var/log/syslog` on
Debian and Ubuntu, `/var/log/messages` on RHEL and Fedora, `logread` under busybox:

```sh
grep nomux /var/log/syslog
```

Reading another user's messages needs privilege, so on a shared host expect to be
root or in `adm`/`systemd-journal`; your own are readable without it. A host with no
syslog at all — a minimal container, typically — silently gets no logging, which is
deliberate: a daemon that refused to start because it could not describe itself would
be worse than one nobody can diagnose.

What is *not* logged is deliberate too. Session ids appear, because they are opaque
and are what `list` and `kill` take. `--label` does not, and neither does a single
byte of terminal traffic: syslog is a host-wide sink, and a session whose whole
footprint is otherwise `0600` files inside a `0700` directory should not announce a
tab title to everyone who can read the system log.

One case stays silent: the shipping build compiles panics down to a bare trap
([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)), so an abort produces no message
for anything to forward. `SIGQUIT` is left at its default disposition for that reason
— it still dumps core.

## Status

Complete and under test on Linux, and not released: every property above is
implemented in the daemon and covered by the suite, and what is left is the release
process and the client that drives it. The standing state — what works, what is
known to be missing, and what was deferred on purpose — is
[PLAN.md § Status](PLAN.md#status), which is the copy kept current rather than a
second copy that drifts.

## License

[Apache-2.0](LICENSE)
