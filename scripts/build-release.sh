#!/bin/sh
# Builds the two shipping binaries and the checksums the client pins them by; with
# NOMUX_DEBUG=1, an unstripped companion per target for a core to be read against.
# Runs from anywhere in the tree; artifacts land in target/dist/.
#
# nomux uploads itself over whatever link the user's ssh session is riding, so the binary
# is on the critical path of every cold start and IMPLEMENTATION.md § 8 caps it at 400 KiB
# per architecture. The cap alone is not enough — one commit grew armv7 46% back when it
# shipped and nothing said a word, because the result still fitted — so scripts/size-baseline
# holds a figure per target and growth past 3% fails too. A shrink never does, however large.
# NOMUX_UPDATE_BASELINE=1 rewrites the baseline and skips the gate, which puts an accepted
# regression in a diff a reviewer reads.
#
# Nightly, because the released std does not fit: rebuilding it with -Cpanic=immediate-abort
# is the only configuration that ships. scripts/nightly-version names the compiler, dated
# rather than floating because the SHA-256 the client pins would drift under one that floats.
# To build with another, edit that one-line file — `git status` then shows you did, which an
# environment override would not.
#
# NOMUX_STABLE_STD=1 builds the released std instead and is expected to miss the cap. It is
# a measurement tool, not an escape hatch: the tree is already buildable without nightly by
# plain `cargo build --release --target ...`. What this uniquely does is re-derive § 8's
# stable-vs-nightly size table with the leak check and the checksums around it, which § 8
# invites readers to do rather than trust the prose. Those figures are not the release's, so
# the run loses the growth gate and refuses NOMUX_UPDATE_BASELINE=1.
set -eu

die() {
    printf '%s\n' "$@" >&2
    exit 1
}

max_bytes=409600 # 400 KiB
# Well above ordinary drift — a compiler bump or a few match arms move these by hundreds of
# bytes, tenths of a percent — and well below the 46% jump the gate was written for. Around
# 4 KiB on x86_64: loose enough that nobody learns to rerun with the escape hatch by habit.
max_growth_pct=3

targets='x86_64-unknown-linux-musl
aarch64-unknown-linux-musl'

# cargo resolves the workspace and .cargo/config.toml — where rust-lld is pinned for both
# targets — by walking up from where it was started, and rustup reads rust-toolchain.toml the
# same way; from another crate's directory that walk lands on that crate and builds it. The
# cd is what makes "runs from anywhere" above mean what it says.
repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

dist="$repo/target/dist"
baseline_file="$repo/scripts/size-baseline"
nightly_file="$repo/scripts/nightly-version"
update_baseline="${NOMUX_UPDATE_BASELINE:-0}"
# The shipping build is `-Cpanic=immediate-abort` with `strip = "symbols"`, so an abort emits
# no message, location or symbol; what is left is the `SIGQUIT` core of § 6.5, which names no
# functions without a companion (PLAN.md § P1). Off unless asked for: it doubles the cross
# builds, and only the publishing path keeps what they produce.
companions="${NOMUX_DEBUG:-0}"

# Recording a stable-std build would raise every baseline past the point where a later
# regression could reach the threshold: the gate would run and never fire again.
if [ "$update_baseline" = 1 ] && [ "${NOMUX_STABLE_STD:-0}" = 1 ]; then
    die "NOMUX_UPDATE_BASELINE=1 refuses a NOMUX_STABLE_STD=1 build: its figures are" \
        "  not the release's, and recording them would leave the growth gate unable to fire."
fi

# Read before building: finding a typo here after the cross builds have run is finding it too
# late. Missing, malformed, and a header whose data lines were dropped are one condition —
# the gate has no reference — and all refused rather than reported as a first build. The last
# is likeliest and worst: it parses, passes, marks every target `new`, and leaves the gate
# present, running, and unable to fail.
baselines=''
if [ -e "$baseline_file" ]; then
    baselines=$(awk '
        { sub(/#.*/, "") }
        NF == 0 { next }
        NF != 2 || $2 !~ /^[0-9]+$/ { exit 1 }
        { print $1, $2 }
    ' "$baseline_file") || baselines=''
fi
if [ -z "$baselines" ] && [ "$update_baseline" != 1 ]; then
    die "no usable ${baseline_file#"$repo"/}, the growth gate's only reference. It holds" \
        "  one \`target bytes\` pair per line, # comments ignored; rerun with" \
        "  NOMUX_UPDATE_BASELINE=1 to record one from this build."
fi

# Through RUSTUP_TOOLCHAIN rather than a `+toolchain` argument, so every rustc and cargo
# call below agrees which one it is — including the `--print sysroot` whose answer gets
# remapped, which would otherwise name the stable sysroot while nightly did the building.
if [ "${NOMUX_STABLE_STD:-0}" = 1 ]; then
    build_std=0
    toolchain=$(rustup show active-toolchain | cut -d' ' -f1)
else
    build_std=1
    # One file, read here and by CI, so a laptop and the runner measure the same bytes by
    # construction: a literal in ci.yml against a floating `nightly` here once meant the
    # documented local run measured whatever compiler the day handed it. It holds the name and
    # nothing else — this reader takes it verbatim while CI round-trips it through the
    # line-oriented $GITHUB_OUTPUT, so anything the two could read differently is rejected there.
    nightly=''
    if [ -r "$nightly_file" ]; then
        nightly=$(cat "$nightly_file")
    fi
    if [ -z "$nightly" ]; then
        die "no toolchain name in ${nightly_file#"$repo"/}, which names the release" \
            "  compiler. Restore it, or set NOMUX_STABLE_STD=1 to measure without it."
    fi
    RUSTUP_TOOLCHAIN="$nightly"
    export RUSTUP_TOOLCHAIN
    toolchain="$nightly"
fi

# The resolved compiler, never the name it was asked for: `nightly` floats, and two builds
# a day apart can both answer to that name and disagree about every figure below.
version=$(rustc --version)

# -Zbuild-std and -Cpanic=immediate-abort are nightly-only, and scripts/nightly-version is the
# one place a stable toolchain can now get in: it passes every check below, which looks at the
# sysroot and so says nothing about the channel, then dies minutes into the first cross build
# nowhere near the cause. Asked of rustc, not matched on the name, so a linked nightly stands.
if [ "$build_std" = 1 ]; then
    case "$version" in
    *-nightly* | *-dev*) ;;
    *) die "$toolchain is not a nightly toolchain: $version" \
            "  the shipping build rebuilds std with panics compiled out, which only" \
            "  nightly accepts. Name a nightly in ${nightly_file#"$repo"/}, or set" \
            "  NOMUX_STABLE_STD=1 and expect to miss the size budget." ;;
    esac
fi

# The gate holds this build's bytes against another build's, which is a comparison only if one
# compiler produced both: a bump moves these by hundreds of bytes against a threshold of a few
# thousand. So the baseline records the compiler that wrote it, and nightly-version and
# size-baseline are checked against each other rather than trusted to move in one commit.
#
# A stable-std run measures a different standard library, so its bytes are not the baseline's
# to hold against at all. Keyed on build_std, not on a version mismatch: a baseline that had
# lost its `# Measured on` line would otherwise leave the gate on and reporting GROWN against
# figures this script has just called incomparable.
skip_growth=0
if [ "$build_std" != 1 ]; then
    skip_growth=1
elif [ "$update_baseline" != 1 ]; then
    measured_by=$(awk '/^#[[:space:]]*Measured on/ {
        getline; sub(/^#[[:space:]]*/, ""); print; exit }' "$baseline_file")
    if [ -n "$measured_by" ] && [ "$measured_by" != "$version" ]; then
        die "${baseline_file#"$repo"/} was measured by a different compiler than" \
            "  ${nightly_file#"$repo"/} names, so its figures are not this build's:" \
            "    building with: $version" \
            "    measured by:   $measured_by" \
            "  the two move in one commit. Rerun with NOMUX_UPDATE_BASELINE=1 and commit" \
            "  the refreshed baseline beside the toolchain bump."
    fi
fi

# Joined by U+001F as CARGO_ENCODED_RUSTFLAGS, not a whitespace-split RUSTFLAGS: three of
# these interpolate a path — $CARGO_HOME, the sysroot, $repo — and one space in any of them
# split a `--remap-path-prefix=FROM=TO` in two, the one place "runs from anywhere" did not
# hold. All-or-nothing, so every flag lives here; nothing splits them further, so each is one
# whole argument. printf, so the byte survives an editor, a diff and a copy-paste.
us=$(printf '\037')

# Every path that could differ between two machines building the same commit. $repo is remapped
# even though cargo already passes workspace paths relative, so a future path-dependent
# dependency cannot quietly reintroduce the problem.
sysroot=$(rustc --print sysroot)
# Beside the toolchain's own `rust-lld`, so it is the same LLVM that linked and it reads every
# target the cross builds emit. Resolved after the toolchain is chosen, which decides which.
objcopy="$(rustc --print target-libdir)/../bin/llvm-objcopy"
# Its own target directory: the companion differs by one rustc flag, so sharing one would make
# each build invalidate the other's cache and turn every one of them cold.
companion_dir="${CARGO_TARGET_DIR:-$repo/target}/companion"
remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap="$remap$us--remap-path-prefix=$sysroot=/rust"
remap="$remap$us--remap-path-prefix=$repo=/nomux"

# crt-static stated rather than left to each target's spec to default to. Both musl targets do,
# so this is belt and braces — but not every target this script has built did, and the failure
# it prevents is the one thing this project cannot ship: a binary with runtime dependencies on
# a host we know nothing about, discovered at a user's shell rather than here.
rustflags="-Clink-self-contained=yes$us-Ctarget-feature=+crt-static$us$remap"
if [ "$build_std" = 1 ]; then
    rustflags="$rustflags$us-Zunstable-options$us-Cpanic=immediate-abort"
    set -- -Z build-std=std,panic_abort
else
    set --
fi

# build-std compiles std from source but still links the musl CRT objects and libc.a out of
# the target's rust-std component, so it is needed either way. Checked here because cargo's
# failure without it is an unreadable wall of linker errors.
for target in $targets; do
    libdir=$(rustc --print target-libdir --target "$target" 2>/dev/null) || libdir=''
    if [ -z "$libdir" ] || [ ! -e "$libdir/self-contained/libc.a" ]; then
        die "no rust-std for $target" "  rustup target add --toolchain $toolchain $target"
    fi
done
if [ "$build_std" = 1 ] && [ ! -e "$sysroot/lib/rustlib/src/rust/library/std/Cargo.toml" ]; then
    die "build-std needs the standard library sources." \
        "  rustup component add --toolchain $toolchain rust-src"
fi
# llvm-objcopy compares the two builds below and ships with the toolchain rather than the
# host: one target is cross-compiled, and a host binutils that cannot read aarch64 is the
# ordinary case rather than the odd one.
if [ "$companions" = 1 ] && [ ! -x "$objcopy" ]; then
    die "the debug companions are checked against the binaries they describe." \
        "  rustup component add --toolchain $toolchain llvm-tools"
fi

rm -rf "$dist"
mkdir -p "$dist"

# Between here and the checksums, target/dist holds some of the binaries and no SHA256SUMS, and
# nothing in it says which — an upload step, or a person coming back an hour later, cannot tell
# it from a complete set. Cleared on a signal as well as on a failed command: these are cross
# builds, Ctrl-C is an ordinary way to end one, and a shell killed by a signal need not run its
# EXIT trap at all.
dist_cleanup() { rm -rf "$dist"; }
trap dist_cleanup EXIT
trap 'dist_cleanup; exit 130' INT TERM HUP

# The reproducibility check, actually run, over every artifact published. Two clean builds on
# one machine are byte-identical with or without --remap-path-prefix, so comparing them proves
# nothing about the next machine; what does is that no builder-specific path survives in the
# artifact. Without this the flags above could stop matching — a moved $CARGO_HOME, a new
# sysroot layout — and nothing would say so until a client failed a checksum it could not
# diagnose. `-a` is load-bearing: without it grep calls the artifact binary and finds nothing.
check_leaks() {
    for leak in "${CARGO_HOME:-$HOME/.cargo}" "$sysroot" "$repo"; do
        if LC_ALL=C grep -qaF -- "$leak" "$1"; then
            die "FAIL: ${1##*/} embeds the build path $leak" \
                "      the artifact is reproducible only on this machine."
        fi
    done
}

for target in $targets; do
    echo "building $target ($toolchain)..." >&2
    CARGO_ENCODED_RUSTFLAGS="$rustflags" cargo build --locked --release --target "$target" --bin nomux "$@" >&2
    cp "${CARGO_TARGET_DIR:-$repo/target}/$target/release/nomux" "$dist/nomux-$target"
    check_leaks "$dist/nomux-$target"

    if [ "$companions" = 1 ]; then
        echo "building $target debug companion..." >&2
        # A second build with the strip turned off, not the shipping binary with symbols added
        # back — there is no adding back, and stripping this one does not reproduce the shipping
        # bytes either: rustc strips at link time and llvm-strip after it, and the two ELFs
        # differ. Deriving one from the other would change what ships, and what ships is what
        # the checksums and the baseline cover.
        CARGO_TARGET_DIR="$companion_dir" CARGO_ENCODED_RUSTFLAGS="$rustflags$us-Cstrip=none" \
            cargo build --locked --release --target "$target" --bin nomux "$@" >&2
        cp "$companion_dir/$target/release/nomux" "$dist/nomux-$target.debug"
        # Matters more here: DWARF is made of file paths, so a companion is where an
        # unremapped sysroot or checkout surfaces first.
        check_leaks "$dist/nomux-$target.debug"

        # That the two line up is the whole of what makes a companion worth publishing, and it
        # is an inference rather than a guarantee: `-Cstrip` is documented to drop sections, not
        # to leave code alone, and a companion whose addresses have moved is worse than none —
        # it names functions, and names the wrong ones. `.text` is what a core is read against;
        # identical contents at an identical address is what "these symbols describe it" means.
        "$objcopy" --dump-section .text="$companion_dir/ship.text" "$dist/nomux-$target" /dev/null
        "$objcopy" --dump-section .text="$companion_dir/comp.text" "$dist/nomux-$target.debug" /dev/null
        if ! cmp -s "$companion_dir/ship.text" "$companion_dir/comp.text"; then
            die "FAIL: the $target companion's .text is not the shipping binary's." \
                "      its symbols would name the wrong functions in a core."
        fi
    fi
done

# `sha256sum -c` format so a verifier needs no bespoke tooling, naming the shipping binaries and
# nothing else: `sha256sum -c` fails on a file it cannot open, so folding the companions in
# would break the check for everyone who downloaded only what they run. They get a file of
# their own, read the same way. Listed target by target rather than by globbing `nomux-*`,
# which would sweep the companions into both.
(cd "$dist" && for t in $targets; do sha256sum "nomux-$t"; done > SHA256SUMS)
if [ "$companions" = 1 ]; then
    (cd "$dist" && for t in $targets; do sha256sum "nomux-$t.debug"; done > SHA256SUMS.debug)
fi

# Complete from here, so the cleanup is disarmed: the gates below still have to be able to fail,
# and a build that is over budget or has grown is exactly the one whose binaries someone will
# want to measure.
trap - EXIT INT TERM HUP

# Neither gate exits early, so one run tells you everything wrong with the build: a size problem
# is rarely confined to one architecture, and the table is meant to be read across.
over_budget=''
grown=''
unknown=''
measured=''
nl='
'
echo
printf '%-34s %9s %9s %8s  %s\n' TARGET BYTES KIB PCT SHA256
for target in $targets; do
    bytes=$(stat -c %s "$dist/nomux-$target")
    sha=$(sha256sum "$dist/nomux-$target" | cut -c1-16)
    # Same column widths as the table, so a refreshed baseline is diffable against the one
    # it replaced instead of reflowing when a binary crosses a power of ten.
    measured="$measured$(printf '%-34s %9d' "$target" "$bytes")$nl"

    verdict=''
    if [ "$bytes" -gt "$max_bytes" ]; then
        verdict="$verdict OVER BUDGET"
        over_budget="$over_budget $target"
    fi

    # A target the baseline has never seen is reported, not punished: a newly added architecture
    # has nothing to have grown against, and failing it would mean the only way to add one is
    # with the escape hatch already set.
    base=$(printf '%s\n' "$baselines" | awk -v t="$target" '$1 == t { print $2; exit }')
    if [ -z "$base" ]; then
        pct='new'
        unknown="$unknown $target"
    else
        diff=$((bytes - base))
        # The magnitude is divided as a positive number and the sign carried separately, because
        # the truncation of a negative quotient differs between shells. The percentage is a
        # rendering and never the thing tested: the gate compares diff*100 against
        # base*max_growth_pct, the same question without rounding — `sh` has no floating point
        # to round with — so a figure displaying as exactly the threshold is decided by the
        # bytes. Growth only; a shrink is what this project wants. Under skip_growth it is still
        # printed — what another std costs is the point of those runs — but is not a verdict.
        sign='+'
        if [ "$diff" -lt 0 ]; then sign='-'; fi
        tenths=$(((diff < 0 ? -diff : diff) * 1000 / base))
        pct="$sign$((tenths / 10)).$((tenths % 10))%"
        if [ "$update_baseline" != 1 ] && [ "$skip_growth" != 1 ] && [ "$diff" -gt 0 ] &&
            [ $((diff * 100)) -gt $((base * max_growth_pct)) ]; then
            verdict="$verdict GROWN"
            grown="$grown $target"
        fi
    fi

    printf '%-34s %9d %7d.%d %8s  %s%s\n' "$target" "$bytes" "$((bytes / 1024))" \
        "$(((bytes % 1024) * 10 / 1024))" "$pct" "$sha" "$verdict"
done
echo
if [ "$companions" = 1 ]; then
    echo "artifacts, companions and both SHA256SUMS in ${dist#"$repo"/}"
else
    echo "artifacts and SHA256SUMS in ${dist#"$repo"/} (NOMUX_DEBUG=1 adds companions)"
fi

# Not on the run that already sets the flag: it records these very sizes below, or says why
# it did not, and naming a flag someone has set reads as not having noticed.
if [ -n "$unknown" ] && [ "$update_baseline" != 1 ]; then
    echo "note: no baseline entry for:$unknown" >&2
    echo "      recorded as new; rerun with NOMUX_UPDATE_BASELINE=1 to record the sizes." >&2
fi

if [ "$update_baseline" = 1 ]; then
    if [ -n "$over_budget" ]; then
        # These figures would make the next build's delta look healthy while the binary is
        # still too big for the one gate that is not negotiable.
        echo "baseline left alone: a build that misses the cap is not one to record." >&2
    else
        # The baseline's prose header is its own and is carried forward, not reproduced here: a
        # copy in this script would be a second original, free to drift from the file it rewrites
        # because nothing compares the two. awk replays the comment block up to the first data
        # line, re-stamping only the two lines that are measurements — appending them to a header
        # that has lost them, since they are what the consistency check above reads.
        stamp=$(printf '# Measured on %s by:\n#   %s' "$(date -u '+%Y-%m-%d')" "$version")
        header="$stamp"
        if [ -e "$baseline_file" ]; then
            header=$(awk -v stamp="$stamp" '
                /^[^#]/ { exit }
                /^#[[:space:]]*Measured on/ { print stamp; getline; seen = 1; next }
                { print }
                END { if (!seen) print stamp }
            ' "$baseline_file")
        fi
        printf '%s\n%s' "$header" "$measured" > "$baseline_file"
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
