#!/bin/sh
# Creates a session inside the SSH login under test and records where the daemon landed.
set -eu

id=${1:?usage: nomux-cell-create <session-id>}

nomux-probe create "$id"

pid=$(nomux list | awk -F'\t' -v want="$id" '$1 == want { print $2 }')
printf 'DAEMON-PID=%s\n' "${pid:-<none>}"
if [ -n "${pid:-}" ] && [ -r "/proc/$pid/cgroup" ]; then
    # run.sh rejects a transient nomux scope rather than tabulating the wrong launch path.
    printf 'DAEMON-CGROUP=%s\n' "$(tr '\n' ' ' < "/proc/$pid/cgroup")"
fi

# Record the login state so a policy result cannot be mistaken for failed setup.
printf 'LINGER=%s\n' "$(loginctl show-user "$(id -u)" --property=Linger --value 2>/dev/null || echo '?')"
printf 'XDG_RUNTIME_DIR=%s\n' "${XDG_RUNTIME_DIR:-<unset>}"
printf 'USER-BUS=%s\n' "$(
    if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/bus" ]; then
        echo present
    else
        echo absent
    fi
)"
printf 'SESSION-SCOPE=%s\n' "$(tr '\n' ' ' < /proc/self/cgroup)"
