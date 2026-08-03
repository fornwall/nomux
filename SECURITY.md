# Security policy

nomux uploads a binary to other people's servers, leaves a daemon holding a shell
there after the login session that started it has gone, and — when it is switched
on — proxies `ssh-agent`. Each of those is something a user has to decide to trust,
so this file says where to send a report and which of them are decisions rather
than defects.

## Reporting

Report privately via GitHub's ["Report a vulnerability"](https://github.com/fornwall/nomux/security/advisories/new)
button, or by email to fredrik@fornwall.net. Please do not open a public issue.

There is no SLA — this is a personal project — but reports are read.

## Scope

nomux has no released version and none receives security updates; fixes land on
`main`. See [DESIGN.md § 8](DESIGN.md#8-security-model) for the threat model and
[PLAN.md](PLAN.md) for known gaps — notably that publishing and verifying the
per-architecture binary checksums is unfinished: the release build emits
`SHA256SUMS`, but nothing yet puts it anywhere a client can read it.

## Not in scope

Both of these are deliberate, and saying so here is cheaper than answering the same
report twice.

- **An attacker who is already the user.** The uploaded binary lands in
  `~/.local/share/nomux/`, and anyone who can write there *as that user* can
  already edit `.bashrc`. nomux adds no capability shell startup files do not
  already grant (DESIGN.md § 8).

  Note the qualifier: that argument is about the same user, and does not cover a
  *different* one. The install directory is created by a shell `mkdir -p` that
  takes whatever the umask leaves and asks nothing about where `$XDG_DATA_HOME`
  points, so on a lax umask or with that variable aimed at a shared directory,
  another local user can replace a binary the victim then execs. That is a real
  gap, it is in scope, and it is recorded in DESIGN.md § 8 — the fix belongs to
  the client, which is what composes that command line.
- **The wire protocol's lack of authentication.** A session's endpoints are unix
  sockets — `<id>.sock`, plus `<id>.agent` when agent forwarding is enabled — each
  `0600` inside a `0700` run directory. Reaching either already means being the user
  who owns the session, which is the whole of the authentication and is meant to be.
  The protocol itself is private and versioned in lockstep with its client, so it
  carries no compatibility or authentication guarantee of its own.
