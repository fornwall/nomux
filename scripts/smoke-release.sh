#!/bin/sh
# Exercises the artifact users receive, not Cargo's debug binary.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: sh scripts/smoke-release.sh <nomux-binary>" >&2
    exit 64
fi

unset CDPATH
binary_dir=$(cd -- "$(dirname -- "$1")" && pwd -P)
binary="$binary_dir/$(basename -- "$1")"
if [ ! -x "$binary" ]; then
    echo "$binary is not executable" >&2
    exit 1
fi

run_root=$(mktemp -d)
session=release-smoke
launcher=
cleanup() {
    XDG_RUNTIME_DIR="$run_root" "$binary" kill "$session" >/dev/null 2>&1 || :
    if [ -n "$launcher" ]; then
        kill "$launcher" >/dev/null 2>&1 || :
        wait "$launcher" 2>/dev/null || :
    fi
    rm -rf -- "$run_root"
}
trap cleanup EXIT HUP INT TERM

XDG_RUNTIME_DIR="$run_root" SHELL=/bin/sh \
    "$binary" daemon "$session" </dev/null >"$run_root/stdout" 2>"$run_root/stderr" &
launcher=$!

ready=false
attempt=0
while [ "$attempt" -lt 200 ]; do
    listing=$(XDG_RUNTIME_DIR="$run_root" "$binary" list) || listing=
    if printf '%s\n' "$listing" | awk -F '\t' -v id="$session" '$1 == id { found = 1 } END { exit !found }'; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.05
done
if [ "$ready" != true ]; then
    echo "the release binary never published a listable session" >&2
    cat "$run_root/stderr" >&2
    exit 1
fi

if ! XDG_RUNTIME_DIR="$run_root" "$binary" kill "$session"; then
    echo "the release binary could not kill its own session" >&2
    cat "$run_root/stderr" >&2
    exit 1
fi

listing=$(XDG_RUNTIME_DIR="$run_root" "$binary" list)
if printf '%s\n' "$listing" | awk -F '\t' -v id="$session" '$1 == id { found = 1 } END { exit !found }'; then
    echo "the killed release session is still listed" >&2
    exit 1
fi

if ! wait "$launcher"; then
    echo "the release daemon launcher exited unsuccessfully" >&2
    exit 1
fi
launcher=
