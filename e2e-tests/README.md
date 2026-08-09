# e2e-tests — the systemd logout matrix

This suite answers the host-policy question in `PLAN.md` item 1: does a session created
in one SSH login still exist after that login has logged out?

Each cell is a container running systemd as PID 1, logind, sshd and PAM. The harness logs
in over SSH to create a session, then logs in again to check it. Two cells instead
blackhole port 22 and wait for sshd's `ClientAlive` timeout, covering a dropped connection
rather than only an orderly logout. `docker exec` would bypass the behavior under test.

The daemon starts directly and remains in sshd's `session-N.scope`; `setsid` and `fork`
detach it from the terminal, not the cgroup. Its fate is therefore host policy, chiefly
`KillUserProcesses`, rather than a choice nomux makes.

## Running it

```sh
./run.sh                       # build, measure every cell, tear down
./run.sh kup-on-linger-on      # one cell by name
NOMUX_E2E_KEEP=1 ./run.sh      # leave containers up to inspect
```

This needs Docker with the compose plugin, a cgroup v2 host, `ssh`, and the
`x86_64-unknown-linux-musl` Rust target. A throwaway SSH keypair and the static test
binaries are generated under gitignored `.keys/` and `bin/`.

## Matrix and verdict

`matrix.tsv` records six cells and their predicted result. `run.sh` fails when a measured
result differs in either direction.

| cell | `KillUserProcesses` | linger | `pam_systemd` | logout | launch | verdict |
|---|---|---|---|---|---|---|
| `no-user-bus` | no | no | **no** | clean | no-logind | survives |
| `kup-off-linger-off` | no | no | yes | clean | direct | survives |
| `kup-on-linger-off` | **yes** | no | yes | clean | direct | **dies** |
| `kup-on-linger-on` | **yes** | yes | yes | clean | direct | **dies** |
| `drop-kup-off-linger-off` | no | no | yes | **abrupt** | direct | survives |
| `drop-kup-on-linger-off` | **yes** | no | yes | **abrupt** | direct | **dies** |

On a host with `KillUserProcesses=yes`, a directly launched nomux session dies at the
final logout. Linger alone does not help because the daemon is not in the lingering user
manager. With `KillUserProcesses=no`, the session survives. This is the same constraint
`tmux` and `screen` face; a strict host needs persistence arranged above nomux, such as a
user-owned scope.

The harness independently verifies each cell's configured axes and the daemon's cgroup.
A transient `nomux-*.scope` or an unknown launch location fails even if the final verdict
matches. Abrupt cells blackhole packets in both directions; killing the local SSH process
would send an ordinary socket close and duplicate the clean case. Their measured teardown
must be slow enough to prove sshd's timeout fired.

## Limits

- Containers exercise real logind, PAM and cgroups, but not a bare-metal or VM init path.
- Debian bookworm on x86-64 is the only distribution and architecture covered here.
- A blackhole covers lid-close and dead-NAT behavior, not every possible network ending.
- Six of the twelve axis combinations are measured. The retained rows cover clean and
  abrupt outcomes on both sides of `KillUserProcesses`, plus no-logind and linger states.
- `probe/` is a minimal protocol client, not the reference client `PLAN.md` item 2 needs.

## Layout

| path | purpose |
|---|---|
| `run.sh` | build, boot, measure and tear down cells |
| `matrix.tsv` | axes and predicted verdicts |
| `docker-compose.yml` | one service per cell |
| `Dockerfile`, `image/` | Debian/systemd image and in-session scripts |
| `probe/` | separate Cargo workspace with the minimal protocol client |

## Adding a cell

Add a row with an unused port to `matrix.tsv`, add the matching service to
`docker-compose.yml`, and teach `image/cell-entrypoint.sh` any new host axis. `run.sh`
reads `/run-cell.env` back from each container and rejects a mismatch between the files.

Predict the verdict before running the cell, state what it learns that no existing row
does, and give any run-level axis (such as `logout=abrupt`) an independent proof that the
claimed path actually ran.
