#!/bin/sh
# Builds the four shipping binaries and the checksums the client pins them by.
#
# nomux uploads itself over whatever link the user's ssh session is riding, so the
# binary is on the critical path of every cold start and IMPLEMENTATION.md § 8 caps
# it at 400 KiB per architecture. That cap is not decoration: this script exits
# non-zero if any binary misses it, because a release that blows the budget is a
# regression in the one number users feel.
#
# The cap on its own is not enough, which is what the armv7 regression taught: one
# commit grew that binary 46% and nothing said a word, because 213 KiB still fits in
# 400 KiB comfortably. A number is only watched if something compares it to what it
# was. So the script also keeps a per-target baseline in scripts/size-baseline, prints
# the signed delta against it beside every size, and fails a build that grows a target
# by more than 3%. A shrink never fails, however large. When the growth is intended,
# NOMUX_UPDATE_BASELINE=1 rewrites the baseline from this build and skips the gate —
# which puts the new figure in the diff, so accepting a size regression becomes
# something a reviewer sees rather than something nobody measured.
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
# turns every panic into a bare trap and cuts each target to roughly a third: the
# budget is missed on every one of them without it — 440 to 493 KiB against a 400 KiB
# cap, armv7 included — and cleared with it. So it is not an optimisation, it is the
# only configuration that ships. The cost is a nightly compiler and panics that abort
# with no message — acceptable only because the clippy wall in Cargo.toml already
# denies unwrap, expect, panic and indexing. The compiler is dated rather than
# floating — scripts/nightly-version names it and this script defaults to it, with
# NOMUX_NIGHTLY overriding for a one-off — because a floating one is a moving target
# and the SHA-256 the client pins would drift under it.
#
# No shipping figure is written down in this comment. scripts/size-baseline holds
# them, written by a build rather than by hand, and the copy that used to live on
# this line had gone stale — which is the whole argument for keeping one of them.
# The stable-std figures above are the ones NOMUX_STABLE_STD=1 reproduces; see
# IMPLEMENTATION.md § 8.
#
# Set NOMUX_STABLE_STD=1 to build against the pinned stable toolchain's released std
# instead. Expect it to fail the size gate; it is kept to make that cost visible and
# to leave the tree buildable without nightly. NOMUX_UPDATE_BASELINE=1 is refused
# alongside it, since the sizes it measures are not the ones the release ships.
#
# Run from anywhere: the script works in the repository it lives in, whatever the
# caller's directory. Artifacts land in target/dist/.
set -eu

max_bytes=409600 # 400 KiB

# Growth past 3% of the baseline fails the build. The threshold has to sit above
# ordinary drift and well below a regression, and there is a wide gap between the two:
# a compiler bump or a handful of new match arms moves these binaries by hundreds of
# bytes, a few tenths of a percent of the smallest of them, while the armv7 jump this
# gate exists to catch was 46%. Three percent is around 4 KiB on x86_64 — loose enough
# that no honest commit trips it and nobody learns to rerun with the escape hatch out
# of habit, tight enough that nothing on the scale of a real regression gets through.
max_growth_pct=3

targets='x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
armv7-unknown-linux-musleabihf
riscv64gc-unknown-linux-musl'

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
# Most of what this script depends on is resolved from the working directory rather
# than from $repo: cargo finds the workspace and reads .cargo/config.toml — where
# rust-lld is pinned for all four targets — by walking up from where it was started,
# rustup reads rust-toolchain.toml the same way, and the copy out of $repo/target
# below assumes cargo wrote there. From a subdirectory of the tree that walk still
# lands on the right files; from another crate's directory it lands on that crate and
# builds it. The cd is what makes the promise above mean what it says.
cd "$repo"

dist="$repo/target/dist"
baseline_file="$repo/scripts/size-baseline"
nightly_file="$repo/scripts/nightly-version"
update_baseline="${NOMUX_UPDATE_BASELINE:-0}"

# A stable-std build measures a binary three times the size of the one that ships, so
# recording it would raise every baseline past the point where any later regression
# could reach the threshold — the gate would still run and would never fire again.
# Refuse the combination rather than write it.
if [ "$update_baseline" = 1 ] && [ "${NOMUX_STABLE_STD:-0}" = 1 ]; then
    echo "NOMUX_UPDATE_BASELINE=1 refuses a NOMUX_STABLE_STD=1 build:" >&2
    echo "  its figures are not the ones the release ships, and recording them" >&2
    echo "  would leave the growth gate unable to fire." >&2
    exit 1
fi

# Read the baseline before building rather than when the table is printed. Parsing it
# is the one part of this script that a typo can break, and discovering that after four
# cross-compiles have run is discovering it twenty minutes too late. Comments and blank
# lines are dropped here so nothing downstream has to think about them, and anything
# that is not a target and a byte count is an error rather than a silently ignored line
# — a baseline that quietly holds no entry for a target is a gate that passes everything.
baselines=''
if [ ! -e "$baseline_file" ] && [ "$update_baseline" != 1 ]; then
    # Refused rather than treated as "no baseline yet". A missing file used to leave
    # every target `new`, print a note to stderr and exit 0 — so the one gate standing
    # between the tree and another armv7-shaped regression turned itself off if the
    # file was renamed, moved, or lost in a bad merge, and the build stayed green while
    # it did. Creating a baseline is a deliberate act, and it already has a flag.
    echo "missing ${baseline_file#"$repo"/}, which is the growth gate's only reference." >&2
    echo "      rerun with NOMUX_UPDATE_BASELINE=1 to record one from this build." >&2
    exit 1
fi
if [ -e "$baseline_file" ]; then
    if ! baselines=$(awk '
        { orig = $0; sub(/#.*/, "") }
        NF == 0 { next }
        NF != 2 || $2 !~ /^[0-9]+$/ { bad = bad "  line " NR ": " orig "\n"; next }
        { good = good $1 " " $2 "\n" }
        END { if (bad != "") { printf "%s", bad; exit 1 } printf "%s", good }
    ' "$baseline_file"); then
        echo "malformed ${baseline_file#"$repo"/}, expected \`target bytes\` per line:" >&2
        printf '%s\n' "$baselines" >&2
        exit 1
    fi
fi
# A file that exists and holds no entries is refused for the same reason a missing one
# is, and it is the likelier accident of the two: a merge that keeps the comment header
# and drops the four data lines leaves something that parses cleanly, passes every
# check above, and reports every target as `new` — the gate present, running, and
# unable to fail. Nothing tells that apart from a first build except this check.
if [ -z "$baselines" ] && [ "$update_baseline" != 1 ]; then
    echo "no entries in ${baseline_file#"$repo"/}, which is the growth gate's only reference." >&2
    echo "      every target would be recorded as new and nothing could fail the gate." >&2
    echo "      rerun with NOMUX_UPDATE_BASELINE=1 to record one from this build." >&2
    exit 1
fi

# Selecting the toolchain through RUSTUP_TOOLCHAIN rather than a `+toolchain` argument
# means every rustc and cargo call below agrees about which one it is — including the
# `--print sysroot` whose answer gets remapped, which would otherwise silently name the
# stable sysroot while nightly did the building.
if [ "${NOMUX_STABLE_STD:-0}" = 1 ]; then
    build_std=0
    toolchain=$(rustup show active-toolchain | cut -d' ' -f1)
else
    build_std=1
    # The release compiler is named in scripts/nightly-version and nowhere else. It
    # used to be a literal in .github/workflows/ci.yml while this script defaulted to
    # a floating `nightly`, so the documented local run measured whatever compiler the
    # day handed it against a baseline recorded by a dated one. That shows up as growth
    # nobody introduced, and the way out of it is NOMUX_UPDATE_BASELINE=1 — the exact
    # habit the growth gate exists to prevent — or it masks a real regression under a
    # compiler that happens to have got smaller. One file, read here and by CI, so a
    # laptop and the runner measure the same bytes by construction. It holds the
    # toolchain name and nothing else: both readers take the file verbatim, so a
    # comment added to it would become the toolchain name.
    nightly="${NOMUX_NIGHTLY:-}"
    if [ -z "$nightly" ] && [ -r "$nightly_file" ]; then
        nightly=$(cat "$nightly_file")
    fi
    if [ -z "$nightly" ]; then
        echo "no toolchain name in ${nightly_file#"$repo"/}, which names the release compiler." >&2
        echo "      restore it, or set NOMUX_NIGHTLY for a build that is not a release." >&2
        exit 1
    fi
    RUSTUP_TOOLCHAIN="$nightly"
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

# A run that dies partway must not leave something that looks like release output.
# Between here and the checksums below, target/dist holds some of the four binaries
# and no SHA256SUMS, and nothing in it says which — an upload step, or a person
# coming back to it an hour later, cannot tell it from a complete set. So it is
# cleared on the way out instead, on a signal as well as on a failed command: these
# are four cross builds and Ctrl-C is an ordinary way to end one, and a shell killed
# by a signal is not guaranteed to run its EXIT trap at all.
dist_cleanup() { rm -rf "$dist"; }
trap dist_cleanup EXIT
trap 'dist_cleanup; exit 130' INT TERM HUP

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

# Complete from here, so the cleanup is disarmed: the size gates below still have to
# be able to fail, and a build that is over budget or has grown is exactly the one
# whose binaries someone will want to measure.
trap - EXIT INT TERM HUP

# Both gates are recorded per target and neither exits early, so one run tells you
# everything that is wrong with the build. Bailing on the first failure would hide the
# other three targets behind whichever one happens to be listed first, and a size
# problem is usually not confined to one architecture — the whole point of the table is
# to be read across.
over_budget=''
grown=''
unknown=''
measured=''
nl='
'
echo
printf '%-34s %9s %9s %9s %8s  %s\n' TARGET BYTES KIB DELTA PCT SHA256
for target in $targets; do
    bytes=$(stat -c %s "$dist/nomux-$target")
    sha=$(sha256sum "$dist/nomux-$target" | cut -c1-16)
    # Accumulated in the same two column widths the table above uses, so a refreshed
    # baseline is diffable against the one it replaced instead of reflowing every line
    # the moment one binary crosses a power of ten.
    measured="$measured$(printf '%-34s %9d' "$target" "$bytes")$nl"

    verdict=''
    if [ "$bytes" -gt "$max_bytes" ]; then
        verdict="$verdict OVER BUDGET"
        over_budget="$over_budget $target"
    fi

    # A target the baseline has never seen is reported, not punished: the first build
    # of a newly added architecture has nothing to have grown against, and failing it
    # would mean the only way to add a target is with the escape hatch already set.
    base=$(printf '%s\n' "$baselines" | awk -v t="$target" '$1 == t { print $2; exit }')
    if [ -z "$base" ]; then
        delta='new'
        pct=''
        unknown="$unknown $target"
    else
        diff=$((bytes - base))
        # The sign is carried separately and the magnitude divided as a positive
        # number, because the truncation of a negative quotient is the sort of detail
        # that differs between shells, and a percentage that is wrong in the last digit
        # on someone else's machine is worse than no percentage at all.
        if [ "$diff" -lt 0 ]; then
            sign='-'
            magnitude=$((-diff))
        else
            sign='+'
            magnitude=$diff
        fi
        tenths=$((magnitude * 1000 / base))
        delta="$sign$magnitude"
        pct="$sign$((tenths / 10)).$((tenths % 10))%"
        # Integer arithmetic throughout: comparing diff*100 against base*max_growth_pct
        # asks the same question as a percentage would without rounding anything, and
        # `sh` has no floating point to round with anyway. The printed percentage is
        # therefore a rendering and never the thing being tested, so a figure that
        # displays as exactly the threshold is decided by the bytes rather than by which
        # way the tenths digit fell. Growth only — a smaller binary is the outcome this
        # project wants and never a reason to fail, however far it drops.
        if [ "$update_baseline" != 1 ] && [ "$diff" -gt 0 ] &&
            [ $((diff * 100)) -gt $((base * max_growth_pct)) ]; then
            verdict="$verdict GROWN"
            grown="$grown $target"
        fi
    fi

    printf '%-34s %9d %7d.%d %9s %8s  %s%s\n' "$target" "$bytes" \
        "$((bytes / 1024))" "$(((bytes % 1024) * 10 / 1024))" \
        "$delta" "$pct" "$sha" "$verdict"
done
echo
echo "artifacts and SHA256SUMS in ${dist#"$repo"/}"

# Not on the run that already sets the flag: that run records these very sizes a few
# lines below, or says why it did not, and telling someone to set a flag they have set
# reads as the script not having noticed.
if [ -n "$unknown" ] && [ "$update_baseline" != 1 ]; then
    echo "note: no baseline entry for:$unknown" >&2
    echo "      recorded as new; rerun with NOMUX_UPDATE_BASELINE=1 to record the sizes." >&2
fi

if [ "$update_baseline" = 1 ]; then
    if [ -n "$over_budget" ]; then
        # Writing these figures would make the next build's delta look healthy while
        # the binary is still too big for the one gate that is not negotiable.
        echo "baseline left alone: a build that misses the cap is not one to record." >&2
    else
        {
            cat <<EOF
# Per-target size baseline for scripts/build-release.sh, in bytes: one
# \`target bytes\` pair per line, blank lines and # comments ignored. The script
# prints the signed delta against these figures and fails a build that grows a
# target by more than $max_growth_pct%; NOMUX_UPDATE_BASELINE=1 rewrites the file, so
# accepting a size change is a commit someone signs rather than a number nobody
# looked at.
#
# Measured on $(date -u '+%Y-%m-%d') by:
#   $(rustc --version)
# The resolved compiler rather than the toolchain name it was asked for, because
# \`nightly\` floats: two builds a day apart can both call themselves that and disagree
# about every figure below. These are toolchain-dependent — a compiler bump moves them
# all — so a refresh belongs in the commit that moved the bytes, and nowhere else.
EOF
            printf '%s' "$measured"
        } > "$baseline_file"
        echo "baseline refreshed in ${baseline_file#"$repo"/}; commit it with the change that moved the bytes."
    fi
fi

if [ -n "$over_budget" ] || [ -n "$grown" ]; then
    if [ -n "$over_budget" ]; then
        echo "FAIL: over the $((max_bytes / 1024)) KiB budget of IMPLEMENTATION.md § 8:$over_budget" >&2
    fi
    if [ -n "$grown" ]; then
        echo "FAIL: grown more than $max_growth_pct% against ${baseline_file#"$repo"/}:$grown" >&2
        echo "      find what did it — the cost is paid on every cold upload — or accept it" >&2
        echo "      deliberately with NOMUX_UPDATE_BASELINE=1 and commit the new baseline." >&2
    fi
    if [ "$build_std" = 0 ]; then
        echo "note: NOMUX_STABLE_STD=1 build; the shipping build uses build-std." >&2
    fi
    exit 1
fi
