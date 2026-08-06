#!/bin/sh
# Proves that a regression test still detects the bug it describes. Reverting either fix by
# hand no longer compiles, so the pre-fix behaviour is kept behind a cfg and exercised here:
# a guard that passes on the bug guards nothing.
#
#   sh scripts/verify-guard.sh <takeover|hangup-grace>
#
# Run from anywhere: the script works in the repository it lives in, whatever the caller's
# directory. Exits non-zero if an expectation is broken.
set -eu

# Checked up front: cargo reports a missing subcommand with a non-zero exit, exactly as it
# reports a failing test, so without this the first run below would be announced as the
# guard failing on correct code.
if ! command -v cargo-nextest >/dev/null 2>&1; then
    echo "this script runs the guard under cargo-nextest, which is not installed:" >&2
    echo "  cargo install cargo-nextest --locked" >&2
    exit 1
fi

# Per guard: the test, the cargo target it compiles into, the cfg it must still PASS under
# (empty for none) and the cfg it must FAIL under. One target rather than all of them: no
# two cfgs below share an artifact, so a wider selection compiles the rest of the workspace
# once per run and runs none of it. `-p nomux` narrows nothing today, there being one
# package.
case "${1-}" in
takeover)
    # Guards the event ordering documented at `ACCEPT_BEFORE_READ` in
    # crates/nomux/src/daemon.rs, where the takeover was serviced before the client it was
    # replacing. Two runs, because the bug only bites when a client's input and the takeover
    # that follows it land in one poll wakeup, and whether that happens is otherwise a matter
    # of microseconds: `nomux_fault_settle` forces that interleaving and nothing else, which
    # is what shows the faulted run fails on the ordering rather than on the delay.
    #
    # The test is in crates/nomux/tests/session.rs, and narrowing to it does not lose the
    # daemon: the harness resolves that through `env!("CARGO_BIN_EXE_nomux")`, which cargo
    # defines by building the package's binary for its own integration tests.
    test_name=a_takeover_never_discards_input_already_delivered
    target_flag=--test
    target_name=session
    pass_cfg=nomux_fault_settle
    fail_cfg=nomux_fault_injection
    caveat=''
    ;;
hangup-grace)
    # Guards the reap inside `Pty::terminate`'s grace loop (§ 6.5). Deleting that reap costs
    # nothing a caller can see but half a second of latency and one `SIGKILL` at a group
    # holding nothing but a zombie — so the test watches for the kill rather than timing the
    # shutdown, a wall clock measuring the machine as much as it measures the reap. A test
    # whose subject is a syscall that changes nothing is exactly the kind that quietly stops
    # guarding.
    #
    # One run: the unfaulted build is the one the `check` job already runs, and that job is a
    # `needs:` dependency of this one, so a control run here could only fail after it had.
    # The test is a unit test in crates/nomux/src/pty.rs, compiled into the binary's own test
    # target.
    test_name=terminate_ends_a_settled_session_without_reaching_for_sigkill
    target_flag=--bin
    target_name=nomux
    pass_cfg=''
    fail_cfg=nomux_fault_unreaped
    caveat=' It also returns
      without asserting on a host that refuses a seccomp filter, which is the other way
      to reach this line.'
    ;;
*)
    echo "usage: sh scripts/verify-guard.sh <takeover|hangup-grace>" >&2
    exit 1
    ;;
esac

# Only 100 means "the test ran and failed". A build error (102), a setup error (101) and a
# filter that matched nothing (4) are all non-zero too, so testing for non-zero would accept
# a run in which the guard never executed.
NEXTEST_TEST_FAILURE=100

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
# cargo and rustup resolve the workspace and the toolchain by walking up from the working
# directory, so the cd is what makes the "run from anywhere" promise above mean what it says.
cd "$repo"

# A separate target directory per cfg: RUSTFLAGS changes the fingerprint of every crate, so
# sharing one would rebuild everything twice on every switch. Absolute, so it does not depend
# on anyone's working directory, and named short on purpose — the session tests bind unix
# sockets underneath it, and `sockaddr_un` truncates at 108 bytes.
base_target="${CARGO_TARGET_DIR:-$repo/target}"
if [ "${#base_target}" -gt 56 ]; then
    echo "the target directory is ${#base_target} bytes, over the 56 the tests bind under:" >&2
    echo "  $base_target" >&2
    exit 1
fi

log=$(mktemp)
cleanup() { rm -f "$log"; }
trap cleanup EXIT
# INT TERM HUP as well as EXIT: each run compiles from scratch, so Ctrl-C is an ordinary way
# to end one, and a shell killed by a signal is not guaranteed to run its EXIT trap. Exiting
# from the handler keeps an interrupted cargo out of the failure path below; 130 rather than
# 1, so it is not read as the guard reporting a failure.
trap 'cleanup; exit 130' INT TERM HUP

run_with() {
    CARGO_TARGET_DIR="$base_target/fi-${1#nomux_fault_}" \
    RUSTFLAGS="${RUSTFLAGS:-} --cfg $1" \
        cargo nextest run --locked -p nomux "$target_flag" "$target_name" \
        -E "test($test_name)" >"$log" 2>&1
}

# Output is captured rather than discarded, and replayed on every failure path. A silent
# failure here is indistinguishable from the bug being undetected, and the usual cause is
# environmental rather than the behaviour under test.
fail() {
    echo "FAIL: $1" >&2
    echo "--- output of the run ---" >&2
    cat "$log" >&2
    exit 1
}

if [ -n "$pass_cfg" ]; then
    echo "running $test_name under --cfg $pass_cfg, the fix intact..."
    run_with "$pass_cfg" ||
        fail "the guard fails under --cfg $pass_cfg, which restores no bug, so a
      failure below would prove nothing about the fix."
fi

echo "running $test_name under --cfg $fail_cfg, the fix undone..."
run_with "$fail_cfg" && status=0 || status=$?
if [ "$status" = 0 ]; then
    fail "the guard passes under --cfg $fail_cfg, so it proves nothing.$caveat"
elif [ "$status" != "$NEXTEST_TEST_FAILURE" ]; then
    fail "expected a test failure ($NEXTEST_TEST_FAILURE), got exit $status — the
      guard never ran, so this run says nothing about the fix."
fi

echo "ok: $test_name still fails under --cfg $fail_cfg."
