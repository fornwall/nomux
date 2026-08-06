#!/bin/sh
# Proves that the quiet-shutdown regression test still detects the bug it describes.
#
# `terminate_ends_a_settled_session_without_reaching_for_sigkill` guards the reap inside
# `Pty::terminate`'s grace loop (IMPLEMENTATION.md 6.5). Deleting that reap costs nothing
# a caller can see but half a second of latency and one `SIGKILL` at a group holding
# nothing but a zombie, so the test watches for the kill — and a test whose subject is a
# syscall that changes nothing is exactly the kind that quietly stops guarding. The
# pre-fix behaviour therefore lives behind a cfg and is exercised here.
#
# Two runs:
#
#   (none)                  the build the suite already runs. The guard must PASS. Any
#                           cfg here would make the run below a comparison against
#                           something nobody ships.
#   nomux_fault_unreaped    drops the reap out of the grace loop. The guard must FAIL.
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

test_name=terminate_ends_a_settled_session_without_reaching_for_sigkill

# Only 100 means "the test ran and failed". A build error (102), a setup error (101)
# and a filter that matched nothing (4) are all non-zero too, so testing for non-zero
# would accept a run in which the guard never executed.
NEXTEST_TEST_FAILURE=100

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
# cargo and rustup resolve the workspace and the toolchain by walking up from the
# working directory, so the cd is what makes the "run from anywhere" promise above
# mean what it says.
cd "$repo"

base_target="${CARGO_TARGET_DIR:-$repo/target}"
# The same 56 bytes verify-takeover-guard.sh checks. Nothing here binds a socket — the
# guard is a unit test on a pty — but the first run below writes the target directory
# the session suite then binds under, and a root already over the limit is worth saying
# so before two compiles rather than after.
if [ "${#base_target}" -gt 56 ]; then
    echo "the target directory is ${#base_target} bytes, over the 56 the tests bind under:" >&2
    echo "  $base_target" >&2
    exit 1
fi

log=$(mktemp)
cleanup() { rm -f "$log"; }
trap cleanup EXIT
# INT TERM HUP as well as EXIT: the second run compiles from scratch, so Ctrl-C is an
# ordinary way to end one, and a shell killed by a signal is not guaranteed to run its
# EXIT trap. Exiting from the handler keeps an interrupted cargo out of the failure
# path below; 130 rather than 1, so it is not read as the guard reporting a failure.
trap 'cleanup; exit 130' INT TERM HUP

# `-p nomux --bin nomux` rather than `--workspace`: the guard is a unit test in
# crates/nomux/src/pty.rs, which compiles into the binary's own test target, and the
# faulted run shares no artifacts with anything — so a wider selection would build the
# integration suites and proptest twice over and run neither.
run_plain() {
    cargo nextest run --locked -p nomux --bin nomux -E "test($test_name)" >"$log" 2>&1
}

# A separate target directory: RUSTFLAGS changes the fingerprint of every crate, so
# sharing the one above would rebuild everything twice on every switch. Absolute, so it
# does not depend on anyone's working directory.
run_faulted() {
    CARGO_TARGET_DIR="$base_target/fi-unreaped" \
    RUSTFLAGS="${RUSTFLAGS:-} --cfg nomux_fault_unreaped" \
        cargo nextest run --locked -p nomux --bin nomux -E "test($test_name)" >"$log" 2>&1
}

# Output is captured rather than discarded, and replayed on every failure path. A
# silent failure here is indistinguishable from the bug being undetected, and the
# usual cause is environmental rather than the reap under test.
fail() {
    echo "FAIL: $1" >&2
    echo "--- output of the run ---" >&2
    cat "$log" >&2
    exit 1
}

echo "running $test_name as it ships..."
run_plain ||
    fail "the guard fails on correct code, so a failure below would prove nothing
      about the reap."

echo "running $test_name with the grace loop's reap dropped..."
run_faulted && status=0 || status=$?
if [ "$status" = 0 ]; then
    fail "the guard passes without the reap, so it proves nothing. It returns without
      asserting on a host that refuses a seccomp filter, which is the other way to
      reach this line."
elif [ "$status" != "$NEXTEST_TEST_FAILURE" ]; then
    fail "expected a test failure ($NEXTEST_TEST_FAILURE), got exit $status —
      the guard never ran, so this run says nothing about the reap."
fi

echo "ok: the guard passes as shipped and fails without the grace loop's reap."
