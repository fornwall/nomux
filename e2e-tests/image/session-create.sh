#!/bin/sh
# Runs inside the one SSH session whose logout is the experiment: creates the session and
# then records which startup path the launcher actually chose.
#
# The evidence matters as much as the verdict. `survives` under a scope launch and
# `survives` under a direct launch on a host that never kills anything are the same word
# for two different facts, and only the daemon's cgroup tells them apart.
set -eu

id=${1:?usage: nomux-cell-create <session-id>}

nomux-probe create "$id"

pid=$(nomux list | awk -F'\t' -v want="$id" '$1 == want { print $2 }')
printf 'DAEMON-PID=%s\n' "${pid:-<none>}"
if [ -n "${pid:-}" ] && [ -r "/proc/$pid/cgroup" ]; then
    # `…/session-N.scope` is the direct path — still inside sshd's login session, and so
    # still whatever KillUserProcesses says it is. `…/nomux-<id>-<pid>.scope` under
    # `user@UID.service` is the transient scope `launcher::scope_command` asked for.
    printf 'DAEMON-CGROUP=%s\n' "$(tr '\n' ' ' < "/proc/$pid/cgroup")"
fi

# The three signals `launcher::spawn_daemon` reads before it decides, reported as the
# session itself sees them.
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
