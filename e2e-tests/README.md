# e2e-tests — the systemd logout matrix

`PLAN.md` item 1 asks one question that no unit test can reach:

> Does a session created in one SSH login still exist after that login has logged out?

The answer is not nomux's to give, and it is no longer nomux's to influence either.
`setsid` and `fork` move the daemon off the controlling terminal but not out of sshd's
`session-N.scope` cgroup ([`startup.rs`'s
`detach_from_controlling_terminal`](../crates/nomux/src/startup.rs) says so), and
[`attach.rs`'s `spawn_daemon`](../crates/nomux/src/attach.rs) now launches the daemon
**directly and always** — there is no scope to escape into, nothing is probed before the launch, and the
daemon's fate is decided by `logind.conf`'s `KillUserProcesses` and by nothing else. That
makes the matrix a measurement of host policy rather than of a choice nomux makes, which
is a smaller claim but the same amount of work to check: whether each combination behaves
as predicted is a fact about logind, and the only way to learn it is to log in, log out,
and look.

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
| `kup-off-linger-on` | no | yes | yes | clean | direct | survives |
| `kup-on-linger-off` | **yes** | no | yes | clean | direct | **dies** |
| `kup-on-linger-on` | **yes** | yes | yes | clean | direct | **dies** |
| `drop-no-user-bus` | no | no | **no** | **abrupt** | no-logind | survives |
| `drop-kup-off-linger-off` | no | no | yes | **abrupt** | direct | survives |
| `drop-kup-off-linger-on` | no | yes | yes | **abrupt** | direct | survives |
| `drop-kup-on-linger-off` | **yes** | no | yes | **abrupt** | direct | **dies** |
| `drop-kup-on-linger-on` | **yes** | yes | yes | **abrupt** | direct | **dies** |

The finding is the `KillUserProcesses` column and nothing else: **on a host that sets
`KillUserProcesses=yes`, a nomux session does not survive the final logout**, and no
configuration of the other two axes changes that. Where `pam_systemd` is out of the way
there is no login session to be killed in, and where `KillUserProcesses=no` — the default
nearly everywhere, and the reason a direct launch is survivable in practice — logind sees
the logout and leaves the scope's contents alone. This is the position `tmux` and GNU
`screen` are in, and on this axis nomux is now neither better nor worse than they are.
Somebody who needs persistence on a strict host arranges it above nomux: `loginctl
enable-linger` **plus a scope of their own**, or a `systemd-run --user --scope` wrapper
around the `spawn` command.

### What the linger cells are for now

Nothing in nomux reads linger any more, so the four linger cells no longer exercise a
nomux code path. They are kept because that is the claim worth pinning, and because the
measurement is cheap — one environment variable and a container that would be booted
anyway.

`kup-on-linger-on` earns its place twice over. It read `survives` until the launcher was
deleted: `spawn` used to detect a lingering user manager and start the daemon through
`systemd-run --user --scope`, which put it in a manager-owned transient scope that outlived
the login session and so outlived `KillUserProcesses`. With the scope gone, linger buys
nothing — a lingering `user@UID.service` owns nothing the daemon is in — and the cell dies
with its linger-off twin. It is now the regression test for the deletion itself: a
`survives` measured here again means a scope launch has come back, and `run.sh` fails on a
verdict that is better than predicted exactly as readily as on one that is worse.
`kup-off-linger-on` is its control, and says a `survives` under linger is not evidence
that linger did anything.

The cells make that argument only if the lingering user manager is really there, which is
why `session-create.sh` still reports `LINGER`, `XDG_RUNTIME_DIR` and `USER-BUS` although
nothing consults them: a cell that dies with `LINGER=yes` and a live user bus has measured
linger being irrelevant, and one whose linger marker quietly failed to take has measured
nothing at all.

### The `LAUNCH` column

Each run still records the daemon's cgroup, and the column still separates two real
states. `direct` is a daemon inside a logind-managed `session-N.scope`, where `survives`
means logind saw the logout and chose not to kill; `no-logind` is a daemon in sshd's own
unit with no session around it, where `survives` means nothing would ever have killed it.
That is the same word for two quite different facts, and only this column tells them apart.

Its third value, `scope`, is now unreachable: no launcher asks for a transient scope. It
is kept as a value to *recognise* rather than to report, and `run.sh` **fails the run** on
seeing one, along with any cgroup the classification does not recognise at all. A cell can
reach the verdict it predicted down a path that no longer exists — `kup-on-linger-on` did
precisely that for as long as the scope launch was there — so the launch path is checked
on its own and not folded into the verdict.

### The dropped-wire half

The `drop-` rows repeat the five hosts with the login taken away rather than ended. What
they settle is that the two teardowns converge: sshd differs only in *how* it learns the
client has gone, and what it does next — PAM's `session close`, pam_systemd's release of
the session, logind stopping `session-N.scope` and applying `KillUserProcesses` to whatever
is still in it — is the same code either way. So the daemon's fate turns on the cgroup it
is in and nothing else, and a verdict on a clean logout is the same promise nomux makes to
a connection that vanishes.

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
12:35:03.286 sshd[78]:   pam_unix(sshd:session): session opened for user nomuxer
12:35:03.305 systemd[1]: Started session-463.scope - Session 463 of User nomuxer.
                         # the wire goes here, and twenty seconds of nothing follow
12:35:23.453 sshd[84]:   Timeout, client not responding from user nomuxer ... port 54128
12:35:23.455 sshd[78]:   pam_unix(sshd:session): session closed for user nomuxer
12:35:23.460 systemd[1]: Stopping session-463.scope - Session 463 of User nomuxer...

12:35:30.238 sshd[263]:  pam_unix(sshd:session): session opened for user nomuxer
12:35:30.329 sshd[269]:  Received disconnect from ... port 50406:11: disconnected by user
12:35:30.330 sshd[263]:  pam_unix(sshd:session): session closed for user nomuxer
```

`Timeout, client not responding` against `Received disconnect`, and 20s against 90ms. That
is the whole difference between the two halves of the matrix, and `kill -9` on the local ssh
client produces the second line, not the first. The `TEARDOWN` column in the run's output is
that gap measured, and it is the reason to believe the row. `Stopping session-463.scope` is
also where this cell's daemon went: `spawn` put it in that scope, the user was lingering,
and lingering saved nothing that was not inside `user@UID.service`.

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
- **Nothing about arranging persistence above nomux.** The matrix measures what a strict
  host does to a directly launched daemon; that a user-owned scope or a lingering wrapper
  would carry it through is the reasoning behind the advice above, not a row here.
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
