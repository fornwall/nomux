#!/bin/sh
# Builds the four shipping binaries and the checksums the client pins them by.
#
# nomux uploads itself over whatever link the user's ssh session is riding, so the
# binary is on the critical path of every cold start and IMPLEMENTATION.md § 8 caps
# it at 400 KiB per architecture. That cap is not decoration: this script exits
# non-zero if any binary misses it, because a release that blows the budget is a
# regression in the one number users feel.
#
# Two things have to be true of the output:
#
#   1. It is byte-identical everywhere. The client pins a SHA-256 per architecture
#      and re-checks it after upload, so "the same commit" has to mean "the same
#      bytes" whether it was built in CI or on a laptop. Cargo hands rustc absolute
#      paths for registry crates and for the standard library, and those paths end
#      up verbatim in panic-location strings — so an unremapped build embeds the
#      builder's home directory and is reproducible only on the builder's machine.
#      The --remap-path-prefix flags below are what make it portable. Two clean
#      builds of one commit from different checkout paths are byte-identical with
#      them and were already so without them, which is exactly the trap: the naive
#      check passes on one machine and tells you nothing about the next one. Grep
#      the artifact for the builder's home directory instead; that is the real test.
#
#   2. Nothing on the host leaks into it. .cargo/config.toml pins rust-lld as the
#      linker for all four targets, including x86_64, so the host's gcc and binutils
#      never get a vote. Combined with rust-toolchain.toml the whole toolchain is
#      version-pinned, and `rustup target add` is the entire cross-compilation setup:
#      no gcc, no zig, no sysroot. That works because the tree is pure Rust — rustix
#      is on its linux_raw backend, so nothing links a C object — and each rust-std
#      component ships the musl CRT and libc.a in `self-contained/`.
#
# Why nightly by default: with the released standard library the binary does not fit.
# The panic machinery — formatting, backtrace symbolisation, gimli, addr2line — is
# most of it, and it cannot be dropped from a precompiled std no matter how the
# release profile is tuned. Rebuilding std from source with -Cpanic=immediate-abort
# turns every panic into a bare trap and takes x86_64 from 493 KiB to 147 KiB. The
# budget is missed on every target without it — 440 to 493 KiB against a 400 KiB cap,
# armv7 included — and cleared by roughly 3x with it. So it is not an optimisation, it
# is the only configuration that ships. The cost is a nightly compiler and panics that
# abort with no message — acceptable only because the clippy wall in Cargo.toml
# already denies unwrap, expect, panic and indexing. Point NOMUX_NIGHTLY at a dated
# nightly for a real release: a floating one is a moving target, and the SHA-256 the
# client pins would drift under it.
#
# The figures above are what this script prints; see IMPLEMENTATION.md § 8 for the
# per-target table. Re-measure with NOMUX_STABLE_STD=1 rather than trusting them.
#
# Set NOMUX_STABLE_STD=1 to build against the pinned stable toolchain's released std
# instead. Expect it to fail the size gate; it is kept to make that cost visible and
# to leave the tree buildable without nightly.
#
# Run from anywhere in the repository. Artifacts land in target/dist/.
set -eu

max_bytes=409600 # 400 KiB
targets='x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
armv7-unknown-linux-musleabihf
riscv64gc-unknown-linux-musl'

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
dist="$repo/target/dist"

# Selecting the toolchain through RUSTUP_TOOLCHAIN rather than a `+toolchain` argument
# means every rustc and cargo call below agrees about which one it is — including the
# `--print sysroot` whose answer gets remapped, which would otherwise silently name the
# stable sysroot while nightly did the building.
if [ "${NOMUX_STABLE_STD:-0}" = 1 ]; then
    build_std=0
    toolchain=$(rustup show active-toolchain | cut -d' ' -f1)
else
    build_std=1
    RUSTUP_TOOLCHAIN="${NOMUX_NIGHTLY:-nightly}"
    export RUSTUP_TOOLCHAIN
    toolchain="$RUSTUP_TOOLCHAIN"
fi

# Every path that could differ between two machines building the same commit. $repo is
# remapped even though cargo already passes workspace paths relative, so that a future
# path-dependent dependency cannot quietly reintroduce the problem.
sysroot=$(rustc --print sysroot)
remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap="$remap --remap-path-prefix=$sysroot=/rust"
remap="$remap --remap-path-prefix=$repo=/nomux"

# crt-static is explicit because riscv64gc-unknown-linux-musl is the one target of the
# four whose spec does not default to it. Left alone it links dynamically against
# libc.so and libgcc_s, which fails outright under rust-lld — and had it linked, it
# would have produced the one thing this project cannot ship: a binary with runtime
# dependencies on a host we know nothing about.
rustflags="-C link-self-contained=yes -C target-feature=+crt-static $remap"
if [ "$build_std" = 1 ]; then
    rustflags="$rustflags -Zunstable-options -Cpanic=immediate-abort"
    set -- -Z build-std=std,panic_abort
else
    set --
fi

# build-std compiles std from source but still links the musl CRT objects and libc.a
# out of the target's rust-std component, so the component is needed either way. Check
# for it here: cargo's failure without it is an unreadable wall of linker errors.
missing=''
for target in $targets; do
    libdir=$(rustc --print target-libdir --target "$target" 2>/dev/null) || libdir=''
    if [ -z "$libdir" ] || [ ! -e "$libdir/self-contained/libc.a" ]; then
        missing="$missing $target"
    fi
done
if [ -n "$missing" ]; then
    echo "no rust-std for:$missing" >&2
    echo "  rustup target add --toolchain $toolchain$missing" >&2
    exit 1
fi
if [ "$build_std" = 1 ] && [ ! -e "$sysroot/lib/rustlib/src/rust/library/std/Cargo.toml" ]; then
    echo "build-std needs the standard library sources." >&2
    echo "  rustup component add --toolchain $toolchain rust-src" >&2
    exit 1
fi

rm -rf "$dist"
mkdir -p "$dist"

for target in $targets; do
    echo "building $target ($toolchain)..." >&2
    RUSTFLAGS="$rustflags" cargo build --locked --release --target "$target" --bin nomux "$@" >&2
    cp "${CARGO_TARGET_DIR:-$repo/target}/$target/release/nomux" "$dist/nomux-$target"

    # The remap check, actually run. Two clean builds on one machine are
    # byte-identical with or without --remap-path-prefix, so comparing them proves
    # nothing about the next machine; what does is that no builder-specific path
    # survives in the artifact. Without this the flags above could stop matching —
    # a moved $CARGO_HOME, a new sysroot layout — and nothing would say so until a
    # client somewhere failed a checksum it could not diagnose.
    # `-a` is load-bearing: without it grep classifies the artifact as binary and
    # reports no match even where one exists, so the check would silently pass on
    # every input and prove nothing.
    for leak in "${CARGO_HOME:-$HOME/.cargo}" "$sysroot" "$repo"; do
        if LC_ALL=C grep -qaF -- "$leak" "$dist/nomux-$target"; then
            echo "FAIL: $target embeds the build path $leak" >&2
            echo "      the artifact is reproducible only on this machine." >&2
            exit 1
        fi
    done
done

# Emitted in `sha256sum -c` format so a verifier needs no bespoke tooling.
(cd "$dist" && sha256sum nomux-* > SHA256SUMS)

status=0
echo
printf '%-34s %9s %9s  %s\n' TARGET BYTES KIB SHA256
for target in $targets; do
    bytes=$(stat -c %s "$dist/nomux-$target")
    sha=$(sha256sum "$dist/nomux-$target" | cut -c1-16)
    if [ "$bytes" -gt "$max_bytes" ]; then
        verdict=' OVER BUDGET'
        status=1
    else
        verdict=''
    fi
    printf '%-34s %9d %7d.%d  %s%s\n' "$target" "$bytes" \
        "$((bytes / 1024))" "$(((bytes % 1024) * 10 / 1024))" "$sha" "$verdict"
done
echo
echo "artifacts and SHA256SUMS in ${dist#"$repo"/}"

if [ "$status" != 0 ]; then
    echo "FAIL: over the $((max_bytes / 1024)) KiB budget of IMPLEMENTATION.md § 8." >&2
    if [ "$build_std" = 0 ]; then
        echo "note: NOMUX_STABLE_STD=1 build; the shipping build uses build-std." >&2
    fi
    exit 1
fi
