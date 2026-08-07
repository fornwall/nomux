#!/bin/sh
# Runs one of fuzz/fuzz_targets/ under libFuzzer:
#
#   sh fuzz/run.sh frame                      until it crashes or you stop it
#   sh fuzz/run.sh header -max_total_time=60  time-boxed, as .github/workflows/ci.yml does
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

# Nightly, because `-Zsanitizer=address` is. Named here as scripts/build-release.sh names
# its own, and for a different reason: that one is dated so the bytes a client hashes cannot
# drift, this one so a nightly regression cannot turn a green tree red with no commit behind
# it — the argument ci.yml makes for pinning every tool it installs. Two lines rather than
# one shared file, because they answer different questions and either can move without the
# other; nothing compares them.
nightly='nightly-2026-08-07'

if [ "$#" -lt 1 ]; then
    echo "usage: sh fuzz/run.sh <target> [libfuzzer args...]" >&2
    exit 64
fi
target=$1
shift

unset CDPATH
cd -- "$(dirname -- "$0")/.."

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
