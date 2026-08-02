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

# A separate target directory: RUSTFLAGS changes the fingerprint of every crate,
# so sharing one would rebuild the whole workspace twice on every switch.
base_target="${CARGO_TARGET_DIR:-target}"

# The directory names are kept short on purpose: the integration tests bind unix
# sockets underneath them, and `sockaddr_un` truncates at 108 bytes.
run_with() {
    CARGO_TARGET_DIR="$base_target/fi-$2" \
    RUSTFLAGS="${RUSTFLAGS:-} --cfg $1" \
        cargo nextest run --workspace -E "test($test_name)" >/dev/null 2>&1
}

echo "running $test_name with the interleaving forced, ordering intact..."
if ! run_with nomux_fault_settle settle; then
    echo "FAIL: the guard fails on correct code once the interleaving is forced," >&2
    echo "      so a failure below would prove nothing about the ordering." >&2
    exit 1
fi

echo "running $test_name against the pre-fix takeover ordering..."
if run_with nomux_fault_injection order; then
    echo "FAIL: the guard passes with the pre-fix ordering, so it proves nothing." >&2
    exit 1
fi

echo "ok: the guard survives the interleaving and fails on the pre-fix ordering."
