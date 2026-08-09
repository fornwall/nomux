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

And half the cells never log out at all. The case nomux exists for is a connection that
**drops** — a closed lid, a dead NAT entry — which sshd learns of only when its
`ClientAlive` timer expires, and which reaches the logout down a different path from an
orderly channel close. Those cells hold the login open and then blackhole port 22 inside
the container, so nothing can tell sshd the client has gone.

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

| cell | `KillUserProcesses` | linger | `pam_systemd` | logout | launch | verdict |
|---|---|---|---|---|---|---|
| `no-user-bus` | no | no | **no** | clean | no-logind | survives |
| `kup-off-linger-off` | no | no | yes | clean | direct | survives |
| `kup-off-linger-on` | no | yes | yes | clean | scope | survives |
| `kup-on-linger-off` | **yes** | no | yes | clean | direct | **dies** |
| `kup-on-linger-on` | **yes** | yes | yes | clean | scope | survives |
| `drop-no-user-bus` | no | no | **no** | **abrupt** | no-logind | survives |
| `drop-kup-off-linger-off` | no | no | yes | **abrupt** | direct | survives |
| `drop-kup-off-linger-on` | no | yes | yes | **abrupt** | scope | survives |
| `drop-kup-on-linger-off` | **yes** | no | yes | **abrupt** | direct | **dies** |
| `drop-kup-on-linger-on` | **yes** | yes | yes | **abrupt** | scope | survives |

`kup-on-linger-off` is the gap the README already warns about, now pinned rather than
suspected: no linger means `launcher::spawn_daemon` declines the scope path, the direct
fallback leaves the daemon in the login session's scope, and logind kills it. **On a strict
host, nomux needs `loginctl enable-linger`**; without it the promise does not hold, and
this row is what stops that regressing quietly into "probably fine".

Each run also records the daemon's cgroup, so `survives` under a scope launch is told apart
from `survives` on a host that would never have killed anything — the same word for two
quite different facts.

### The dropped-wire half

The `drop-` rows repeat the five hosts with the login taken away rather than ended. What
they settle is that the two teardowns converge: sshd differs only in *how* it learns the
client has gone, and what it does next — PAM's `session close`, pam_systemd's release of
the session, logind stopping `session-N.scope` and applying `KillUserProcesses` to whatever
is still in it — is the same code either way. So the daemon's fate turns on the cgroup it
is in and nothing else, and `survives` on a clean logout is a promise nomux also keeps to a
connection that vanishes.

Which makes these five cells easy to fake, and that is the thing to be careful about.
A cell that *believes* it disconnected abruptly but really produced an orderly close is a
silent duplicate of its clean twin: it passes, it proves nothing, and it reads exactly like
coverage. In particular **killing the local ssh client is not a disconnect** — the host
kernel still closes the socket and sshd sees an ordinary logout. So `abrupt_login`
blackholes port 22 in both directions inside the container, and `run.sh` times the login's
death and fails the run if it came too quickly to have been a timeout.

The two paths are nowhere near each other, so the floor is not a close call. One
`drop-kup-on-linger-on` run's journal, the blackholed login and then the check login that
followed it in the same container:

```
11:49:48.532 sshd[78]:  pam_unix(sshd:session): session opened for user nomuxer
11:49:48.659 systemd[63]: Started nomux-celldropkuponlingeron-88.scope - ...
                          # the wire goes here, and twenty seconds of nothing follow
11:50:08.709 sshd[84]:  Timeout, client not responding from user nomuxer ... port 47342
11:50:08.711 sshd[78]:  pam_unix(sshd:session): session closed for user nomuxer
11:50:08.723 systemd[1]: Stopping session-380.scope - Session 380 of User nomuxer...

11:50:15.715 sshd[266]: pam_unix(sshd:session): session opened for user nomuxer
11:50:15.795 sshd[272]: Received disconnect from ... port 50870:11: disconnected by user
11:50:15.796 sshd[266]: pam_unix(sshd:session): session closed for user nomuxer
```

`Timeout, client not responding` against `Received disconnect`, and 20s against 80ms. That
is the whole difference between the two halves of the matrix, and `kill -9` on the local ssh
client produces the second line, not the first. The `TEARDOWN` column in the run's output is
that gap measured, and it is the reason to believe the row.

## What this does not prove

- **A container is not a host.** logind, PAM and cgroup delegation here are real, but the
  kernel, the init path and the sshd configuration are this image's. A bare-metal or VM
  confirmation is still worth having; `matrix.tsv` and `probe/` transfer to one unchanged,
  since only `run.sh`'s transport would differ.
- **A blackhole is not every way a connection can end.** The `drop-` cells cut the packets
  and leave sshd to notice, which is the lid-closed and NAT-timeout case. A middlebox that
  answers with an RST, or a client host that reboots and RSTs on the next packet, would
  present sshd with a closed socket instead and land back on the clean half's path. What is
  untested is neither of those but the `ClientAliveInterval 0` host, where sshd never asks
  and the login can outlive the connection indefinitely — a session that survives there
  proves less than one that survives here, because nothing was torn down at all.
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
| `Dockerfile` | Debian + systemd + sshd + PAM + `iptables` to cut the wire with |
| `image/` | per-cell configuration applied before PID 1, and the in-session scripts |
| `probe/` | a separate cargo workspace: the minimal protocol client |

`probe/` is its own workspace for the reason `fuzz/` is — it builds against the crate but
has nothing to do with the shipping binary's size budget or lint set.

## Adding a cell

Add a row to `matrix.tsv` with an unused port (2201-2210 are taken), add the matching
service to `docker-compose.yml`, and give `image/cell-entrypoint.sh` the axis if it is a new
one. Predict the verdict *before* running it; a matrix that is written down after the fact
records what happened rather than what was expected, which is a much weaker thing.

An axis that is about the *run* rather than about the host — `logout` is the one such axis
so far — belongs in `run.sh` instead, and needs its own answer to "how would I know this
cell really did the thing it claims?". `logout=abrupt` answers it with the `TEARDOWN`
measurement and a floor the run dies on. Without an answer like that, a new cell is a row
that passes rather than a fact that was learned.
