# Security policy

nomux uploads a binary to other people's servers, leaves a daemon holding a shell
there after the login session has gone, and — when switched on — proxies
`ssh-agent`. Each is something a user has to decide to trust.

## Reporting

Report privately via GitHub's ["Report a vulnerability"](https://github.com/fornwall/nomux/security/advisories/new)
button, or by email to fredrik@fornwall.net. Please do not open a public issue.

There is no SLA — this is a personal project — but reports are read.

## Supported versions

None. No released version receives security updates; fixes land on `main`.

What is in scope, what is deliberately accepted, and who each boundary holds against are
[DESIGN.md § 8](DESIGN.md#8-security-model); the gaps that are known and open are
[PLAN.md](PLAN.md).
