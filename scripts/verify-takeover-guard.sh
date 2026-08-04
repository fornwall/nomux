#!/bin/sh
# Proves that the takeover regression test still detects the bug it describes.
#
# `a_takeover_never_discards_input_already_delivered` guards the event ordering of
# IMPLEMENTATION.md 6.4.1. A test like that is only worth its runtime if it fails
# when the ordering is wrong, and reverting the ordering by hand no longer
# compiles — so the pre-fix behaviour is kept behind a cfg and exercised here.
#
# Two runs, because the bug only bites when a client's input and the takeover that
# follows it land in one poll wakeup, and whether that happens is otherwise a
# matter of microseconds:
#
#   nomux_fault_settle      forces that interleaving and nothing else. The guard
#                           must still PASS. This is what shows the second run
#                           fails because of the ordering rather than the delay.
#   nomux_fault_injection   forces the interleaving and restores the pre-fix
#                           ordering. The guard must FAIL.
#
# Run from anywhere: the script works in the repository it lives in, whatever the
# caller's directory. Exits non-zero if either expectation is broken, which means the
# guard has stopped guarding anything.
set -eu

# Checked up front: cargo reports a missing subcommand with a non-zero exit, exactly
# as it reports a failing test, so without this the first run below would be announced
# as the guard failing on correct code.
if ! command -v cargo-nextest >/dev/null 2>&1; then
    echo "this script runs the guard under cargo-nextest, which is not installed:" >&2
    echo "  cargo install cargo-nextest --locked" >&2
    exit 1
fi

test_name=a_takeover_never_discards_input_already_delivered

# Only 100 means "the test ran and failed". A build error (102), a setup error (101)
# and a filter that matched nothing (4) are all non-zero too, so testing for non-zero
# would accept a run in which the guard never executed.
NEXTEST_TEST_FAILURE=100

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
# cargo and rustup resolve the workspace and the toolchain by walking up from the
# working directory, so the cd is what makes the "run from anywhere" promise above
# mean what it says.
cd "$repo"

# A separate target directory: RUSTFLAGS changes the fingerprint of every crate, so
# sharing one would rebuild everything twice on every switch. Absolute, so it does not
# depend on anyone's working directory.
base_target="${CARGO_TARGET_DIR:-$repo/target}"

log=$(mktemp)
cleanup() { rm -f "$log"; }
trap cleanup EXIT
# INT TERM HUP as well as EXIT: each run compiles from scratch, so Ctrl-C is an
# ordinary way to end one, and a shell killed by a signal is not guaranteed to run its
# EXIT trap. Exiting from the handler keeps an interrupted cargo out of the failure
# path below; 130 rather than 1, so it is not read as the guard reporting a failure.
trap 'cleanup; exit 130' INT TERM HUP

# The directory names are kept short on purpose: the integration tests bind unix
# sockets underneath them, and `sockaddr_un` truncates at 108 bytes.
#
# `-p nomux --test session` rather than `--workspace`: the guard is one test in
# crates/nomux/tests/session.rs, and this runs twice under RUSTFLAGS that share no
# artifacts, so everything outside that target is compiled twice and run never.
# `--workspace` also built the chaos, spawn_lock, codec and wire test binaries and
# proptest with its dependency tree behind them. Narrowing does not lose the daemon:
# the harness resolves it through `env!("CARGO_BIN_EXE_nomux")`, which cargo defines
# by building the package's binary for its own integration tests.
run_with() {
    CARGO_TARGET_DIR="$base_target/fi-$2" \
    RUSTFLAGS="${RUSTFLAGS:-} --cfg $1" \
        cargo nextest run --locked -p nomux --test session -E "test($test_name)" >"$log" 2>&1
}

# Output is captured rather than discarded, and replayed on every failure path. A
# silent failure here is indistinguishable from the bug being undetected, and the
# usual cause is environmental — an over-long $CARGO_TARGET_DIR pushing the tests'
# socket paths past the 108-byte limit, for one.
fail() {
    echo "FAIL: $1" >&2
    echo "--- output of the run ---" >&2
    cat "$log" >&2
    exit 1
}

echo "running $test_name with the interleaving forced, ordering intact..."
run_with nomux_fault_settle settle ||
    fail "the guard fails on correct code once the interleaving is forced,
      so a failure below would prove nothing about the ordering."

echo "running $test_name against the pre-fix takeover ordering..."
run_with nomux_fault_injection order && status=0 || status=$?
if [ "$status" = 0 ]; then
    fail "the guard passes with the pre-fix ordering, so it proves nothing."
elif [ "$status" != "$NEXTEST_TEST_FAILURE" ]; then
    fail "expected a test failure ($NEXTEST_TEST_FAILURE), got exit $status —
      the guard never ran, so this run says nothing about the ordering."
fi

echo "ok: the guard survives the interleaving and fails on the pre-fix ordering."
