#!/bin/sh
# Runs one of fuzz/fuzz_targets/ under libFuzzer:
#
#   sh fuzz/run.sh frame                     until it crashes or you stop it
#   sh fuzz/run.sh frame -max_total_time=60  time-boxed, as .github/workflows/ci.yml does
#
# Anything after the target name goes to libFuzzer. A finding lands in
# fuzz/artifacts/<target>/ and is replayed with `cargo fuzz run <target> <that file>`.
#
# Exists so a laptop and the runner fuzz the same way. Two things have to be right and
# neither is discoverable — which nightly, and which directories are corpus.
#
# `cargo fuzz` resolves ./fuzz from the working directory and the target process resolves
# the corpus paths against the same one, so this runs from the repository root whatever
# directory it was invoked from.
set -eu

unset CDPATH
repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo"

# Nightly, because `-Zsanitizer=address` is. Dated so a nightly regression cannot turn a
# green tree red with no commit behind it, and read from the release build's tracked pin so
# the two workflows always exercise one compiler version.
nightly_file="$repo/scripts/nightly-version"
read -r nightly < "$nightly_file" || {
    echo "could not read a toolchain name from $nightly_file" >&2
    exit 1
}
case "$nightly" in
nightly-[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) ;;
*)
    echo "$nightly_file must name a dated nightly toolchain" >&2
    exit 1
    ;;
esac

if [ "$#" -lt 1 ]; then
    echo "usage: sh fuzz/run.sh <target> [libfuzzer args...]" >&2
    exit 64
fi
target=$1
shift

# The name is used as both a cargo argument and a directory below fuzz/corpus/. Keep an
# accidental path (or a leading option) from escaping that directory or being interpreted by
# cargo-fuzz. Cargo target names use this same conservative alphabet.
case "$target" in
'' | -* | *[!A-Za-z0-9_-]*)
    echo "invalid fuzz target name: $target" >&2
    exit 64
    ;;
esac
if [ ! -f "fuzz/fuzz_targets/$target.rs" ]; then
    echo "unknown fuzz target: $target" >&2
    exit 64
fi

# Installed rather than detected and complained about, as scripts/build-release.sh does it:
# one idempotent command, so a runner and a laptop provision identically and ci.yml needs no
# step of its own that could drift from the name above. Chatter to stderr, stdout being
# libFuzzer's.
rustup toolchain install "$nightly" --profile minimal --no-self-update >&2

# libFuzzer will not create the directory it is told to write to.
mkdir -p "fuzz/corpus/$target"

# Two corpus directories where a target has seeds: libFuzzer writes what it finds into the
# first and only reads the rest, so seeds/ stays a fixed input rather than a directory that
# grows under `git status` after every run. corpus/ is ignored, seeds/ is tracked.
if [ -d "fuzz/seeds/$target" ]; then
    exec cargo "+$nightly" fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" -- "$@"
fi
exec cargo "+$nightly" fuzz run "$target" "fuzz/corpus/$target" -- "$@"
