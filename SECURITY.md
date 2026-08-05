# Security policy

nomux uploads a binary to other people's servers, leaves a daemon holding a shell
there after the login session has gone, and — when switched on — proxies
`ssh-agent`. Each is something a user has to decide to trust.

## Reporting

Report privately via GitHub's ["Report a vulnerability"](https://github.com/fornwall/nomux/security/advisories/new)
button, or by email to fredrik@fornwall.net. Please do not open a public issue.

There is no SLA — this is a personal project — but reports are read.

## Scope

nomux has no released version and none receives security updates; fixes land on
`main`. The threat model is [DESIGN.md § 8](DESIGN.md#8-security-model); known gaps
are [PLAN.md](PLAN.md)'s, notably [§ P3](PLAN.md#p3--release-process): a `v*` tag
publishes the per-architecture checksums, and nothing verifies an upload against
them yet — the client's half.

Two things are deliberate, and DESIGN § 8 has both:

- **An attacker who is already the user.** The uploaded binary lands where `.bashrc`
  does. A *different* user replacing a binary the victim then execs is a real gap and
  is in scope.
- **The wire protocol's lack of authentication.** A session's sockets are `0600`
  inside a `0700` run directory, so reaching one already means being the user.
