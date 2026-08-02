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
# Run from anywhere in the repository. Exits non-zero if either expectation is
# broken, which means the guard has stopped guarding anything.
set -eu

test_name=a_takeover_never_discards_input_already_delivered

# nextest's exit code, which is what makes the second run's expectation meaningful:
# only 100 means "the test ran and failed". A build error (102), a setup error (101)
# or a filter that matched nothing (4) all mean the guard never executed, and all
# three are non-zero — so testing for "non-zero" would accept a run that proved
# nothing, which is exactly the failure this script exists to rule out.
NEXTEST_TEST_FAILURE=100

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)

# A separate target directory: RUSTFLAGS changes the fingerprint of every crate,
# so sharing one would rebuild the whole workspace twice on every switch. Anchored
# to the repository rather than the working directory, so the script really can be
# run from anywhere in the tree as documented above.
base_target="${CARGO_TARGET_DIR:-$repo/target}"

log=$(mktemp)
cleanup() { rm -f "$log"; }
trap cleanup EXIT

# The directory names are kept short on purpose: the integration tests bind unix
# sockets underneath them, and `sockaddr_un` truncates at 108 bytes.
run_with() {
    CARGO_TARGET_DIR="$base_target/fi-$2" \
    RUSTFLAGS="${RUSTFLAGS:-} --cfg $1" \
        cargo nextest run --locked --workspace -E "test($test_name)" >"$log" 2>&1
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
