# Security policy

nomux uploads a binary to other people's servers, leaves a daemon holding a shell
there after the login session has gone, and — when switched on — proxies
`ssh-agent`. Each is something a user has to decide to trust.

## Reporting

Report privately via GitHub's ["Report a vulnerability"](https://github.com/fornwall/nomux/security/advisories/new)
button, or by email to fredrik@fornwall.net. Please do not open a public issue.

There is no SLA — this is a personal project — but reports are read.

## Scope

No released version of nomux receives security updates; fixes land on
`main`. The threat model is [DESIGN.md § 8](DESIGN.md#8-security-model). The gap worth
naming here: a `v*` tag publishes per-architecture checksums, and nothing verifies an
upload against them yet — that half is the client's, and it is unwritten.

Two things are deliberate, both in [DESIGN.md § 8](DESIGN.md#8-security-model): an
attacker who is already the user — though a *different* user replacing a binary the
victim then execs is a real gap, and in scope — and the wire protocol's lack of
authentication, its sockets being `0600` inside a `0700` run directory, so reaching
one already means being the user.
