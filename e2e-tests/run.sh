#!/bin/sh
# Measures PLAN.md item 1: does a session created in one SSH login survive that login's
# logout, across the KillUserProcesses x linger x pam_systemd matrix, and does the answer
# hold when the login does not end in a logout at all but in a dropped connection?
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

# The two numbers that keep an `abrupt` cell honest, in seconds from the moment the wire
# is cut to the moment the login is gone.
#
# The floor is the whole guard against this half of the matrix being a silent duplicate of
# the clean half. `image/sshd_config` sets ClientAliveInterval 5 / ClientAliveCountMax 1,
# so a genuinely blackholed connection can only end when that timer expires, and the two
# paths are nowhere near each other: measured on this image, a blackhole takes 15-20s and
# `kill -9` on the local ssh client takes 0.1s, because the host kernel still closes the
# socket politely and sshd sees an ordinary logout. Anything under the floor did not
# partition the connection, whatever it did.
abrupt_floor=5
# And the ceiling says the login ended at all. A cell that sat out its whole disconnect
# with the session still logged in measured nothing either.
abrupt_ceiling=90

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

# `--locked` on both, as every other cargo invocation in the tree has it: what this harness
# measures is the behaviour of a committed tree, and a resolver quietly moving past either lock
# file would make the run a fact about whatever crates.io held that morning.
( cd "$repo" && cargo build --locked --release --target "$arch" --bin nomux ) >&2
( cd "$here/probe" && cargo build --locked --release --target "$arch" ) >&2

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
#
# `-n` is load-bearing, not tidiness: without it ssh reads the caller's stdin, and the cell
# loop below is fed by a here-document — so the first login swallowed every remaining cell
# and the run reported "all matched" having measured one of five.
#
# Held as one list because `abrupt_login` needs the same flags on an `exec`, and two copies
# of this drifting apart would mean two kinds of login that are not comparable.
ssh_flags="-q -n
    -o BatchMode=yes
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ControlMaster=no
    -o ControlPath=none
    -o LogLevel=ERROR"

ssh_to() {
    port=$1
    shift
    # shellcheck disable=SC2086 # deliberate word splitting: $ssh_flags is a list of flags.
    ssh $ssh_flags -p "$port" -i "$key" nomuxer@127.0.0.1 "$@"
}

# ------------------------------------------------------------------------------ the cells

cells=$(sed 's/#.*//' matrix.tsv | awk 'NF == 7 { print }')
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

# What the container on the other end of this port actually booted with, against what the
# row asked for. `image/cell-entrypoint.sh` writes /run-cell.env after applying the three
# axes and before handing over to PID 1, so it is the configuration itself rather than the
# compose file's request for one.
#
# This is the harness's one silent-wrong failure mode closed. Everything else here fails
# loudly: a cell that will not boot, a login that will not die, a cgroup nothing recognises.
# But a port swapped between matrix.tsv and docker-compose.yml produces a run where every
# login works, every verdict is a real measurement, and each one is filed against another
# cell's axes — and if the two rows happen to predict the same thing, it passes.
confirm_axes() {
    cid=$(docker compose ps -q "$1")
    [ -n "$cid" ] || die "$1: no running container to read /run-cell.env from"
    booted=$(docker exec "$cid" cat /run-cell.env) ||
        die "$1: the container never wrote /run-cell.env, so it did not get through" \
            "      image/cell-entrypoint.sh and its axes are whatever the image defaults to."
    # `asked` rather than `wanted`: a function's variables are this shell's, and `wanted` is
    # already the cell name from the command line up at the top of the file.
    asked="CELL_KILL_USER_PROCESSES=$2
CELL_LINGER=$3
CELL_PAM_SYSTEMD=$4"
    [ "$booted" = "$asked" ] || die \
        "$1: the container on port $5 booted axes this row did not ask for." \
        "      matrix.tsv:    $(printf '%s' "$asked" | tr '\n' ' ')" \
        "      the container: $(printf '%s' "$booted" | tr '\n' ' ')" \
        "      A port that disagrees between matrix.tsv and docker-compose.yml looks exactly" \
        "      like this. Reconcile the two files; do not adjust the prediction."
}

# ------------------------------------------------------------------- the dropped wire

# sshd's unprivileged child for the one login a cell makes — `sshd: nomuxer@notty`. It is
# the login: while it is there the session is logged in, and when it goes PAM's session
# close has run and logind has been told. Matched by uid and exact name rather than by
# process title, which is an sshd version's business and not a fact to build on.
login_present() {
    docker exec "$1" pgrep -u nomuxer -x sshd > /dev/null 2>&1
}

# The tidying every `abrupt_login` failure past the first has to do, plus the complaint.
# Leaving the client behind would be the worse half: it holds a login open, and a login
# still there is exactly what the next cell in this container would measure. Reads `out` and
# `client` from its one caller, which is where they are set.
abrupt_abort() {
    rm -f "$out"
    kill "$client" 2>/dev/null || true
    wait "$client" 2>/dev/null || true
    printf '%s\n' "$@" >&2
}

# One `abrupt` cell's first login: create the session, then take the network away under it
# instead of logging out.
#
# A clean cell lets `ssh host 'cmd'` return, which closes the connection in an orderly way
# and lets sshd end the login at once. This one holds the login open with `nomux-cell-hold`
# and then blackholes port 22 *inside the container*, both directions, so sshd's packets go
# nowhere and no FIN or RST can reach it from the client either. What is left is the case
# nomux exists for — a laptop lid, a dead NAT entry — where the only thing that can end the
# login is sshd's `ClientAlive` timer, and the logout is reached through `cleanup_exit`
# rather than through an orderly channel close.
#
# Killing the local ssh client is emphatically *not* this. The host kernel still closes the
# socket, sshd sees an ordinary logout, and the cell becomes a silent duplicate of its
# clean twin that passes and proves nothing. Measured on this image, that takes 0.1s
# against 15-20s for the blackhole, which is why the caller checks the number.
#
# Prints the create login's own report with a TEARDOWN-SECONDS line appended, and is called
# from a command substitution — so the variables below are a subshell's and the background
# client cannot outlive the cell.
abrupt_login() {
    port=$1
    name=$2
    id=$3

    cid=$(docker compose ps -q "$name")
    [ -n "$cid" ] || {
        echo "$name: no running container to cut the wire in" >&2
        return 1
    }

    out=$(mktemp)
    client=''
    # A trap of this subshell's own. `abrupt_login` is called from a command substitution, and
    # a POSIX subshell starts with every trap its parent caught reset to the default — so the
    # run's INT/TERM handler is not installed in here, and nothing else in this function is
    # reached on a signal. What would be left behind is not only the temporary file: the
    # background ssh client below holds a login open inside the container, which is exactly
    # what the next cell in that container would measure. `abrupt_abort` removes both, which
    # is why `client` is emptied above rather than left unset for it to trip over. The
    # parent's trap still runs afterwards and still takes the containers down.
    trap 'abrupt_abort "$name: interrupted before the disconnect was measured"; exit 130' \
        INT TERM HUP
    # `exec`, so `$!` is ssh itself rather than a subshell holding it. This client has to be
    # killed by hand at the end — it is talking to a blackhole and will never learn
    # otherwise — and killing a wrapper would leave the connection open behind it.
    # shellcheck disable=SC2086 # deliberate word splitting: $ssh_flags is a list of flags.
    ( exec ssh $ssh_flags -p "$port" -i "$key" nomuxer@127.0.0.1 \
        "nomux-cell-create $id && nomux-cell-hold" ) > "$out" 2>&1 &
    client=$!

    # Cut the wire only once the session exists and the login has gone quiet, so what the
    # next `ClientAlive` request meets is the blackhole and not a still-busy connection.
    deadline=$(( $(date +%s) + 60 ))
    while ! grep -q NOMUX-HOLD-READY "$out" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            sed 's/^/    /' < "$out" >&2
            abrupt_abort "$name: the create-and-hold login never reported itself ready"
            return 1
        fi
        sleep 1
    done

    # There has to be a login to lose. A cell that measures an instant teardown because
    # there was nothing left to tear down is the false pass all of this is guarding against.
    if ! login_present "$cid"; then
        abrupt_abort "$name: no sshd login process to disconnect; nothing was measured here"
        return 1
    fi

    # Both rules to stdout-as-stderr: this function's stdout is the cell's report and gets
    # parsed, so nothing else may land in it.
    started=$(date +%s)
    if ! docker exec "$cid" iptables -I INPUT 1 -p tcp --dport 22 -j DROP >&2 ||
        ! docker exec "$cid" iptables -I OUTPUT 1 -p tcp --sport 22 -j DROP >&2; then
        abrupt_abort "$name: could not blackhole port 22 in the container"
        return 1
    fi

    gone=timeout
    limit=$(( started + abrupt_ceiling ))
    while [ "$(date +%s)" -lt "$limit" ]; do
        if ! login_present "$cid"; then
            gone=$(( $(date +%s) - started ))
            break
        fi
        sleep 1
    done

    # The wire back before anything else touches this cell: the check login is a fresh
    # connection to the same port and would be blackholed along with the old one. Deleted
    # by rule rather than flushed, so a cell that ever grows a firewall of its own keeps it.
    docker exec "$cid" iptables -D INPUT -p tcp --dport 22 -j DROP >&2 || true
    docker exec "$cid" iptables -D OUTPUT -p tcp --sport 22 -j DROP >&2 || true

    # The client is still waiting on a connection whose server has gone, and nothing will
    # ever tell it so. It is told here.
    kill "$client" 2>/dev/null || true
    wait "$client" 2>/dev/null || true

    cat "$out"
    rm -f "$out"
    printf 'TEARDOWN-SECONDS=%s\n' "$gone"
}

# ------------------------------------------------------------------------------ measure

results=''
failed=''
launch_bad=''
measured_count=0
expected_count=$(printf '%s\n' "$cells" | wc -l | tr -d ' ')
nl='
'

# `while read` in a pipeline runs in a subshell, whose variables do not survive it, so
# the loop reads from a here-document instead and the tallies below are this shell's.
while IFS='	' read -r name port kup linger pam logout expect; do
    [ -n "$name" ] || continue
    printf '\n=== %s (KillUserProcesses=%s linger=%s pam_systemd=%s %s logout, expect %s)\n' \
        "$name" "$kup" "$linger" "$pam" "$logout" "$expect" >&2
    await_ssh "$port" "$name"
    confirm_axes "$name" "$kup" "$linger" "$pam" "$port"

    id="cell$(printf '%s' "$name" | tr -cd 'a-z0-9')"
    # One login: create the session, report which path the launcher took, then end — by
    # logging out, or by losing the network under it. That difference is the whole of the
    # `logout` axis; everything from here down is the same measurement either way.
    if [ "$logout" = abrupt ]; then
        # No `2>&1` on this branch, unlike the clean one below. `abrupt_login` has five
        # distinct explanations for giving up and writes every one of them to stderr, so
        # merging them into `$created` would leave `die` printing the generic line below and
        # nothing else — on a CI runner, with the containers already torn down, that is the
        # whole of what there is to go on. Letting them stream out live is also what keeps
        # the invariant `abrupt_login`'s own redirections exist for: its stdout is the cell's
        # report and gets parsed for TEARDOWN-SECONDS and DAEMON-CGROUP below, and the
        # `iptables -D` at the end of it is `|| true`, so its complaints have somewhere to go
        # that is not the parsed stream.
        if ! created=$(abrupt_login "$port" "$name" "$id"); then
            die "$name: the abrupt-disconnect login did not get as far as a disconnect."
        fi
    elif ! created=$(ssh_to "$port" "nomux-cell-create $id" 2>&1); then
        printf '%s\n' "$created" | sed 's/^/    /' >&2
        die "$name: could not create a session to test"
    fi
    printf '%s\n' "$created" | sed 's/^/    /' >&2

    # How long the login took to die, which for an abrupt cell is the evidence that the
    # disconnect was one. Kept out of the verdict and checked on its own: a cell that
    # reached the right answer down the wrong teardown path has not measured this row.
    teardown='-'
    if [ "$logout" = abrupt ]; then
        teardown=$(printf '%s\n' "$created" | sed -n 's/^TEARDOWN-SECONDS=//p' | head -1)
        case "$teardown" in
        '' | *[!0-9]*)
            die "$name: the login was still there ${abrupt_ceiling}s after the wire was cut" \
                "      (TEARDOWN-SECONDS=${teardown:-<none>}). sshd never reached its" \
                "      ClientAlive timeout, so nothing about a dropped connection was" \
                "      measured here."
            ;;
        esac
        if [ "$teardown" -lt "$abrupt_floor" ]; then
            die "$name: the login ended ${teardown}s after the wire was cut, under the" \
                "      ${abrupt_floor}s floor. That is an orderly close, not a partition:" \
                "      sshd was told the client had gone instead of having to time it out," \
                "      which makes this cell a silent duplicate of its clean twin. Fix the" \
                "      blackhole in \`abrupt_login\` rather than the floor."
        fi
        teardown="${teardown}s"
    fi

    # The login is over, however it ended; give logind its moment to act on it.
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

    # Where the daemon ended up, which is the whole of what decides its fate now that
    # nothing is chosen at launch. Two of these are real states a host can be in and the
    # third is one this product can no longer produce.
    scope=$(printf '%s\n' "$created" | sed -n 's/^DAEMON-CGROUP=//p' | head -1)
    case "$scope" in
    # A transient scope of nomux's own, under `user@UID.service`. No launcher asks for one
    # any more, so this is not a state the matrix can reach — it is kept as a value to
    # recognise rather than to report, and failed on below.
    *nomux-*.scope*) path=scope ;;
    # Still in sshd's login session, so still whatever KillUserProcesses says it is. The
    # only thing a `spawn` on a pam_systemd host can now produce.
    *session-*.scope*) path=direct ;;
    # No pam_systemd, so no login session at all: the daemon inherits sshd's own unit.
    # A direct launch too, and worth naming apart — nothing here is logind-managed, so
    # `survives` means nothing would ever have killed it rather than that logind saw the
    # logout and chose not to. The same word for two quite different facts, told apart
    # only by this column.
    *ssh.service*) path=no-logind ;;
    *) path='?' ;;
    esac

    verdict=ok
    if [ "$measured" != "$expect" ]; then
        verdict=DEVIATES
        failed=1
    fi
    # A daemon in a transient `nomux-*.scope` means `systemd-run --user --scope` is back in
    # the launcher, and a cgroup this does not recognise means the column has stopped
    # telling `direct` from `no-logind` and is decorating the table rather than saying
    # anything. Both are failures on their own, apart from the verdict: a cell can reach
    # the predicted verdict down a path that no longer exists, and did — `kup-on-linger-on`
    # read `survives` for exactly that reason until the scope launch was deleted.
    case "$path" in
    scope | '?')
        verdict="$verdict/LAUNCH"
        launch_bad="$launch_bad$(printf '  %-24s %s -> %s' "$name" "$path" "$scope")$nl"
        failed=1
        ;;
    esac
    results="$results$(printf '%-24s %-4s %-7s %-4s %-7s %-9s %-9s %-9s %-9s %s' \
        "$name" "$kup" "$linger" "$pam" "$logout" "$path" "$teardown" \
        "$expect" "$measured" "$verdict")$nl"
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
printf '%-24s %-4s %-7s %-4s %-7s %-9s %-9s %-9s %-9s %s\n' \
    CELL KUP LINGER PAM LOGOUT LAUNCH TEARDOWN EXPECT MEASURED ''
printf '%s' "$results"
echo

if [ -n "$launch_bad" ]; then
    echo "FAIL: a daemon landed somewhere a direct launch cannot put it:" >&2
    printf '%s' "$launch_bad" >&2
    echo "      A nomux-*.scope means a transient systemd scope is back in the launcher," >&2
    echo "      which would make a cell's verdict a fact about a code path that was" >&2
    echo "      deleted; a '?' means this classification no longer recognises what it" >&2
    echo "      measured, so the LAUNCH column has stopped telling direct from no-logind." >&2
fi
if [ -n "$failed" ]; then
    echo "FAIL: a cell behaved differently from matrix.tsv's prediction, or reached its" >&2
    echo "      verdict by a launch path that no longer exists. Either the prediction is" >&2
    echo "      wrong and the file should record what was measured, or nomux changed and" >&2
    echo "      this is the regression the matrix is for." >&2
    exit 1
fi
echo "every cell matched its prediction in matrix.tsv"
