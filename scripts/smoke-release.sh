#!/bin/sh
# Exercises the artifact users receive, not Cargo's debug binary.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: sh scripts/smoke-release.sh <nomux-binary>" >&2
    exit 64
fi

unset CDPATH
LC_ALL=C
export LC_ALL
binary_dir=$(cd -- "$(dirname -- "$1")" && pwd -P)
binary="$binary_dir/$(basename -- "$1")"
if [ ! -x "$binary" ]; then
    echo "$binary is not executable" >&2
    exit 1
fi

run_root=$(mktemp -d)
state_root="$run_root/state"
session=release-smoke
relay=
cleanup() {
    exec 3>&- 4>&-
    if [ -n "$relay" ]; then
        kill "$relay" >/dev/null 2>&1 || :
        wait "$relay" 2>/dev/null || :
    fi
    XDG_STATE_HOME="$state_root" "$binary" kill "$session" >/dev/null 2>&1 || :
    rm -rf -- "$run_root"
}
trap cleanup EXIT HUP INT TERM

# Emit a byte without relying on a non-POSIX `printf \xNN` extension.
emit_byte() {
    byte_octal=$(printf '%03o' "$1")
    printf '%b' "\\$byte_octal"
}

# The protocol's type byte and big-endian u24 payload length.
emit_header() {
    frame_type=$1
    payload_length=$2
    emit_byte "$frame_type"
    emit_byte $((payload_length / 65536))
    emit_byte $(((payload_length / 256) % 256))
    emit_byte $((payload_length % 256))
}

# Protocol 10, no agent, replay from the ring's beginning, 80x24, TERM=dumb.
emit_hello() {
    emit_header 1 25
    for byte in \
        0 10 0 \
        255 255 255 255 255 255 255 255 \
        0 80 0 24 0 0 0 0 \
        0 4 100 117 109 98
    do
        emit_byte "$byte"
    done
}

emit_input() {
    input=$1
    input_len=$((${#input} + 1))
    emit_header 3 $((8 + input_len))
    for byte in 0 0 0 0 0 0 0 0; do
        emit_byte "$byte"
    done
    printf '%s\n' "$input"
}

emit_detach() {
    emit_header 9 0
}

# Parse every complete frame in a transcript. In `before` mode an Exit is a failure:
# the shell is waiting on our marker file and must still be alive when detached. In
# `complete` mode require HelloOk, the marker reconstructed across Output-frame
# boundaries, and Exit{status=0, kind=exited}; any Error fails both modes.
inspect_transcript() {
    od -An -v -tu1 "$1" | awk -v mode="$2" '
        BEGIN {
            marker_count = split("78 79 77 85 88 45 82 69 76 69 65 83 69 45 83 77 79 75 69", marker, " ")
        }
        function clear_payload( key) {
            for (key in first) delete first[key]
        }
        function note_output(byte) {
            if (byte == marker[matched + 1]) {
                matched++
            } else if (byte == marker[1]) {
                matched = 1
            } else {
                matched = 0
            }
            if (matched == marker_count) found_marker = 1
        }
        function finish_frame() {
            if (type == 2 && frame_len == 17) saw_hello_ok = 1
            if (type == 8) {
                saw_exit = 1
                if (frame_len == 9 && first[0] == 0 && first[1] == 0 &&
                    first[2] == 0 && first[3] == 0 && first[4] == 0) clean_exit = 1
            }
            if (type == 12) saw_error = 1
            header_bytes = 0
            payload_bytes = 0
        }
        {
            for (column = 1; column <= NF; column++) {
                byte = $column + 0
                if (header_bytes < 4) {
                    header[header_bytes++] = byte
                    if (header_bytes == 4) {
                        type = header[0]
                        frame_len = header[1] * 65536 + header[2] * 256 + header[3]
                        payload_bytes = 0
                        clear_payload()
                        if (type < 1 || type > 15 || frame_len > 262144) malformed = 1
                        if (frame_len == 0) finish_frame()
                    }
                } else {
                    if (payload_bytes < 18) first[payload_bytes] = byte
                    if (type == 5 && payload_bytes >= 8) note_output(byte)
                    payload_bytes++
                    if (payload_bytes == frame_len) finish_frame()
                }
            }
        }
        END {
            failed = malformed || saw_error || !saw_hello_ok || !found_marker
            if (mode == "before" && saw_exit) failed = 1
            if (mode == "complete" && (header_bytes != 0 || !clean_exit)) failed = 1
            exit failed
        }
    '
}

wait_for_transcript() {
    transcript=$1
    mode=$2
    what=$3
    attempt=0
    while [ "$attempt" -lt 200 ]; do
        if inspect_transcript "$transcript" "$mode"; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    echo "timed out waiting for $what" >&2
    return 1
}

# A bounded wait for a child shell cannot express with POSIX `wait`. A child remains a
# zombie, and keeps its pid, until the final wait, so `/proc` gives a race-free completion
# probe on the only platform this binary supports.
wait_for_relay() {
    relay_pid=$1
    what=$2
    attempt=0
    while [ "$attempt" -lt 200 ]; do
        state=$(awk '{ print $3 }' "/proc/$relay_pid/stat" 2>/dev/null || :)
        if [ -z "$state" ] || [ "$state" = Z ]; then
            if wait "$relay_pid"; then
                return 0
            fi
            echo "$what exited unsuccessfully" >&2
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    kill "$relay_pid" >/dev/null 2>&1 || :
    wait "$relay_pid" 2>/dev/null || :
    echo "$what did not exit within ten seconds" >&2
    return 1
}

marker_octal='\116\117\115\125\130\055\122\105\114\105\101\123\105\055\123\115\117\113\105\012'
continue_file="$run_root/continue"
command="stty -echo; printf '$marker_octal'; while [ ! -f '$continue_file' ]; do sleep 0.05; done; exit"

# Create a real PTY and detach while its shell is provably still running.
mkfifo "$run_root/spawn-input"
: >"$run_root/spawn-transcript"
XDG_STATE_HOME="$state_root" SHELL=/bin/sh \
    "$binary" spawn "$session" <"$run_root/spawn-input" \
    >"$run_root/spawn-transcript" 2>"$run_root/spawn-stderr" &
relay=$!
exec 3>"$run_root/spawn-input"
emit_hello >&3
emit_input "$command" >&3
wait_for_transcript "$run_root/spawn-transcript" before "the live shell marker"
emit_detach >&3
exec 3>&-
wait_for_relay "$relay" "the spawn relay"
relay=

# Let the detached shell finish, then resume from the ring and require its output and Exit.
touch "$continue_file"
mkfifo "$run_root/attach-input"
: >"$run_root/attach-transcript"
XDG_STATE_HOME="$state_root" \
    "$binary" attach "$session" <"$run_root/attach-input" \
    >"$run_root/attach-transcript" 2>"$run_root/attach-stderr" &
relay=$!
exec 4>"$run_root/attach-input"
emit_hello >&4
wait_for_transcript "$run_root/attach-transcript" complete "replayed output and a clean Exit"
emit_detach >&4
exec 4>&-
wait_for_relay "$relay" "the attach relay"
relay=
inspect_transcript "$run_root/attach-transcript" complete

listing=$(XDG_STATE_HOME="$state_root" "$binary" list)
if ! printf '%s\n' "$listing" | awk -F '\t' -v id="$session" '$1 == id { found = 1 } END { exit !found }'; then
    echo "the completed release session is not listable" >&2
    exit 1
fi

if ! XDG_STATE_HOME="$state_root" "$binary" kill "$session"; then
    echo "the release binary could not kill its own completed session" >&2
    exit 1
fi
listing=$(XDG_STATE_HOME="$state_root" "$binary" list)
if printf '%s\n' "$listing" | awk -F '\t' -v id="$session" '$1 == id { found = 1 } END { exit !found }'; then
    echo "the killed release session is still listed" >&2
    exit 1
fi
