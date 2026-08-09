#!/bin/sh
# Measures PLAN.md item 1: does a session created in one SSH login survive that login's
# logout, across the KillUserProcesses x linger x pam_systemd matrix?
#
# One cell per container, one real SSH login to create and one to check. Runs from
# anywhere in the tree. See README.md for what this proves and what it does not.
#
#   ./run.sh                 build, measure every cell, tear down
#   ./run.sh kup-on-linger-on   one cell by name
#   NOMUX_E2E_KEEP=1 ./run.sh   leave the containers up to poke at
set -eu

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd -P)
here="$repo/e2e-tests"
cd "$here"

target=${CARGO_TARGET_DIR:-$repo/target}
# The one architecture the compose images run. Static, so the Debian containers need no
# toolchain and no matching libc.
arch=x86_64-unknown-linux-musl
# How long logind is given to act on the final logout before the session is asked about.
# Generous: what is being waited for is a policy decision, not a syscall.
settle=${NOMUX_E2E_SETTLE:-6}
keep=${NOMUX_E2E_KEEP:-0}
wanted=${1:-}

die() {
    printf '%s\n' "$@" >&2
    exit 1
}

command -v docker > /dev/null || die "docker is not on PATH"
docker compose version > /dev/null 2>&1 || die "this docker has no compose plugin"
command -v ssh > /dev/null || die "ssh is not on PATH"

# ---------------------------------------------------------------- binaries under test

echo "building nomux and the probe for $arch..." >&2
rustup target list --installed | grep -qx "$arch" ||
    die "the $arch target is not installed: rustup target add $arch"

( cd "$repo" && cargo build --release --target "$arch" --bin nomux ) >&2
( cd "$here/probe" && cargo build --release --target "$arch" ) >&2

mkdir -p "$here/bin"
cp "$target/$arch/release/nomux" "$here/bin/nomux"
cp "$here/probe/target/$arch/release/nomux-probe" "$here/bin/nomux-probe"

# ------------------------------------------------------------------------- throwaway key

mkdir -p "$here/.keys"
key="$here/.keys/id_ed25519"
if [ ! -f "$key" ]; then
    ssh-keygen -q -t ed25519 -N '' -C nomux-e2e -f "$key"
fi
chmod 600 "$key"

# Never a known_hosts entry and never an agent: these containers are rebuilt constantly
# and share a host key only by accident, and the matrix must not consult the user's.
ssh_to() {
    port=$1
    shift
    # `-n` is load-bearing, not tidiness: without it ssh reads the caller's stdin, and the
    # cell loop below is fed by a here-document — so the first login swallowed every
    # remaining cell and the run reported "all matched" having measured one of five.
    ssh -q -n -p "$port" -i "$key" \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ControlMaster=no \
        -o ControlPath=none \
        -o LogLevel=ERROR \
        nomuxer@127.0.0.1 "$@"
}

# ------------------------------------------------------------------------------ the cells

cells=$(sed 's/#.*//' matrix.tsv | awk 'NF == 6 { print }')
[ -n "$cells" ] || die "matrix.tsv named no cells"
if [ -n "$wanted" ]; then
    cells=$(printf '%s\n' "$cells" | awk -v w="$wanted" '$1 == w')
    [ -n "$cells" ] || die "no cell named $wanted in matrix.tsv"
fi
services=$(printf '%s\n' "$cells" | awk '{ printf "%s ", $1 }')

echo "starting cells: $services" >&2
# shellcheck disable=SC2086 # deliberate word splitting: one argument per service.
docker compose up -d --build $services >&2

teardown() {
    if [ "$keep" = 1 ]; then
        echo "containers left up (NOMUX_E2E_KEEP=1); \`docker compose down\` when done" >&2
    else
        # shellcheck disable=SC2086
        docker compose down --remove-orphans > /dev/null 2>&1 || true
    fi
}
trap teardown EXIT
trap 'teardown; exit 130' INT TERM HUP

# sshd comes up behind systemd, so the first connections are refused as a matter of
# course. Waited for per cell rather than slept through.
await_ssh() {
    port=$1
    name=$2
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ssh_to "$port" true 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    # The container's own boot log, before the teardown trap takes it away. A cell that
    # never came up is the one failure with nothing in the run's output to explain it,
    # and on a CI runner there is no container left afterwards to go and look at.
    echo "--- $name: last 60 lines of container log ---" >&2
    docker compose logs --tail 60 "$name" >&2 2>&1 || true
    die "$name: sshd on port $port never accepted a key login" \
        "      systemd may not have booted in this container: check the log above for" \
        "      cgroup or PID 1 failures rather than assuming nomux is at fault."
}

# ------------------------------------------------------------------------------ measure

results=''
failed=''
measured_count=0
expected_count=$(printf '%s\n' "$cells" | wc -l | tr -d ' ')
nl='
'

# `while read` in a pipeline runs in a subshell, whose variables do not survive it, so
# the loop reads from a here-document instead and the tallies below are this shell's.
while IFS='	' read -r name port kup linger pam expect; do
    [ -n "$name" ] || continue
    printf '\n=== %s (KillUserProcesses=%s linger=%s pam_systemd=%s, expect %s)\n' \
        "$name" "$kup" "$linger" "$pam" "$expect" >&2
    await_ssh "$port" "$name"

    id="cell$(printf '%s' "$name" | tr -cd 'a-z0-9')"
    # One login: create the session, report which path the launcher took, then log out.
    if ! created=$(ssh_to "$port" "nomux-cell-create $id" 2>&1); then
        printf '%s\n' "$created" | sed 's/^/    /' >&2
        die "$name: could not create a session to test"
    fi
    printf '%s\n' "$created" | sed 's/^/    /' >&2

    # The logout has happened; give logind its moment to act on it.
    sleep "$settle"

    # A second, independent login asks whether the session is still there. ssh hands back
    # the remote command's own status, so the probe's three answers arrive intact and are
    # kept apart: a probe that broke is not evidence that a session died.
    status=0
    checked=$(ssh_to "$port" "nomux-probe check $id" 2>&1) || status=$?
    case "$status" in
    0) measured=survives ;;
    20) measured=dies ;;
    *) measured="probe-failed($status)" ;;
    esac
    printf '%s\n' "$checked" | sed 's/^/    /' >&2

    scope=$(printf '%s\n' "$created" | sed -n 's/^DAEMON-CGROUP=//p' | head -1)
    case "$scope" in
    # The transient scope `launcher::scope_command` asked for, under `user@UID.service`.
    *nomux-*.scope*) path=scope ;;
    # Still in sshd's login session, so still whatever KillUserProcesses says it is.
    *session-*.scope*) path=direct ;;
    # No pam_systemd, so no login session at all: the daemon inherits sshd's own unit.
    # A direct launch too, but worth naming apart — nothing here is logind-managed.
    *ssh.service*) path=no-logind ;;
    *) path='?' ;;
    esac

    verdict=ok
    if [ "$measured" != "$expect" ]; then
        verdict=DEVIATES
        failed=1
    fi
    results="$results$(printf '%-20s %-4s %-7s %-4s %-9s %-9s %-9s %s' \
        "$name" "$kup" "$linger" "$pam" "$path" "$expect" "$measured" "$verdict")$nl"
    measured_count=$((measured_count + 1))
done <<EOF
$cells
EOF

# A cell that never ran must never read as a cell that passed. This caught a real bug —
# an ssh without `-n` consuming the loop's own input — and the only reason it was
# noticed is that the count was checked rather than the verdicts trusted.
if [ "$measured_count" != "$expected_count" ]; then
    printf '%s' "$results"
    die "FAIL: matrix.tsv named $expected_count cells and only $measured_count were measured." \
        "      The unmeasured ones are not passes; something ended the loop early."
fi

# ------------------------------------------------------------------------------- report

echo
printf '%-20s %-4s %-7s %-4s %-9s %-9s %-9s %s\n' \
    CELL KUP LINGER PAM LAUNCH EXPECT MEASURED ''
printf '%s' "$results"
echo

if [ -n "$failed" ]; then
    echo "FAIL: a cell behaved differently from matrix.tsv's prediction." >&2
    echo "      Either the prediction is wrong and the file should record what was" >&2
    echo "      measured, or nomux changed and this is the regression the matrix is for." >&2
    exit 1
fi
echo "every cell matched its prediction in matrix.tsv"
