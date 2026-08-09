#!/bin/sh
# Runs inside the one SSH session whose logout is the experiment: creates the session and
# then records where the daemon actually landed.
#
# The evidence matters as much as the verdict. `spawn` launches directly and always, so the
# cgroup is not a choice it made but the one its login already had — and `survives` in a
# login session logind chose not to kill is a different fact from `survives` on a host with
# no logind-managed session at all. Only the daemon's cgroup tells the two apart.
set -eu

id=${1:?usage: nomux-cell-create <session-id>}

nomux-probe create "$id"

pid=$(nomux list | awk -F'\t' -v want="$id" '$1 == want { print $2 }')
printf 'DAEMON-PID=%s\n' "${pid:-<none>}"
if [ -n "${pid:-}" ] && [ -r "/proc/$pid/cgroup" ]; then
    # `…/session-N.scope` says the daemon is inside sshd's login session, and so still
    # whatever KillUserProcesses says it is. A `…/nomux-<id>-<pid>.scope` under
    # `user@UID.service` would say a transient scope launch had come back; run.sh fails on
    # one rather than tabulating it.
    printf 'DAEMON-CGROUP=%s\n' "$(tr '\n' ' ' < "/proc/$pid/cgroup")"
fi

# The host state nomux used to read before it chose a launcher, reported as the session
# itself sees it. Nothing consults these any more, which is why they are still printed: a
# linger=on cell that shows `LINGER=yes` with a live user bus and dies anyway is the
# measurement, and without these lines it would be indistinguishable from a cell whose
# linger marker never took effect.
printf 'LINGER=%s\n' "$(loginctl show-user "$(id -u)" --property=Linger --value 2>/dev/null || echo '?')"
printf 'XDG_RUNTIME_DIR=%s\n' "${XDG_RUNTIME_DIR:-<unset>}"
printf 'USER-BUS=%s\n' "$(
    if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/bus" ]; then
        echo present
    else
        echo absent
    fi
)"
printf 'SESSION-SCOPE=%s\n' "$(cat /proc/self/cgroup | tr '\n' ' ')"
