# e2e-tests — the systemd logout matrix

`PLAN.md` item 1 asks one question that no unit test can reach:

> Does a session created in one SSH login still exist after that login has logged out?

The answer is not nomux's to give. `setsid` and `fork` move the daemon off the controlling
terminal but not out of sshd's `session-N.scope` cgroup ([`startup.rs`'s
`detach_from_controlling_terminal`](../crates/nomux/src/startup.rs) says so), so on a host
with `KillUserProcesses=yes` logind kills it at the final logout. The mitigation —
`systemd-run --user --scope`, chosen by
[`launcher.rs`](../crates/nomux/src/launcher.rs) — only helps when a lingering user manager
is there to own the scope. Whether each combination behaves as predicted is a fact about
logind, and the only way to learn it is to log in, log out, and look.

So each cell here is a container running **systemd as PID 1, a real logind, a real sshd and
a real PAM stack**, and the harness logs in over SSH twice: once to create a session, once
to ask whether it is still there. `docker exec` would bypass all four and prove nothing.

## Running it

```sh
./run.sh                       # build, measure every cell, tear down
./run.sh kup-on-linger-on      # one cell by name
NOMUX_E2E_KEEP=1 ./run.sh      # leave containers up to poke at
```

Needs Docker with the compose plugin, a cgroup v2 host, `ssh`, and the
`x86_64-unknown-linux-musl` Rust target (the binaries are built static so the Debian
containers need no toolchain). Nothing is installed on the host; a throwaway SSH keypair is
generated into `.keys/` and both it and `bin/` are gitignored.

## What is measured

`matrix.tsv` holds one row per cell with the verdict it predicts, and `run.sh` fails when a
measurement differs from the prediction **in either direction** — a cell that survives when
it was predicted to die is as much a finding as the reverse. The file is meant to be a
record of measured behaviour, not a wishlist.

| cell | `KillUserProcesses` | linger | `pam_systemd` | launch | verdict |
|---|---|---|---|---|---|
| `no-user-bus` | no | no | **no** | no-logind | survives |
| `kup-off-linger-off` | no | no | yes | direct | survives |
| `kup-off-linger-on` | no | yes | yes | scope | survives |
| `kup-on-linger-off` | **yes** | no | yes | direct | **dies** |
| `kup-on-linger-on` | **yes** | yes | yes | scope | survives |

`kup-on-linger-off` is the gap the README already warns about, now pinned rather than
suspected: no linger means `launcher::spawn_daemon` declines the scope path, the direct
fallback leaves the daemon in the login session's scope, and logind kills it. **On a strict
host, nomux needs `loginctl enable-linger`**; without it the promise does not hold, and
this row is what stops that regressing quietly into "probably fine".

Each run also records the daemon's cgroup, so `survives` under a scope launch is told apart
from `survives` on a host that would never have killed anything — the same word for two
quite different facts.

## What this does not prove

- **A container is not a host.** logind, PAM and cgroup delegation here are real, but the
  kernel, the init path and the sshd configuration are this image's. A bare-metal or VM
  confirmation is still worth having; `matrix.tsv` and `probe/` transfer to one unchanged,
  since only `run.sh`'s transport would differ.
- **One distro, one architecture.** Debian bookworm on x86-64. Distros differ in their
  `logind.conf` default and their PAM stack.
- **Not the second half of the plan item.** Whether the best-effort failures in
  `release_startup_state` — `chdir`, the `/dev/null` descriptors — may stay silent is a
  decision informed by these results, not settled by them.
- **The client is a stub.** `probe/` speaks just enough protocol to greet a session, type a
  marker and re-attach. It is not the reference client `PLAN.md` item 2 wants, though it is
  a start on one.

## Layout

| path | what it is |
|---|---|
| `run.sh` | builds, boots the cells, measures each, prints the table |
| `matrix.tsv` | the cells and their predicted verdicts |
| `docker-compose.yml` | one service per cell; ports match `matrix.tsv` |
| `Dockerfile` | Debian + systemd + sshd + PAM |
| `image/` | per-cell configuration applied before PID 1, and the in-session recorder |
| `probe/` | a separate cargo workspace: the minimal protocol client |

`probe/` is its own workspace for the reason `fuzz/` is — it builds against the crate but
has nothing to do with the shipping binary's size budget or lint set.

## Adding a cell

Add a row to `matrix.tsv` with an unused port, add the matching service to
`docker-compose.yml`, and give `image/cell-entrypoint.sh` the axis if it is a new one.
Predict the verdict *before* running it; a matrix that is written down after the fact
records what happened rather than what was expected, which is a much weaker thing.
