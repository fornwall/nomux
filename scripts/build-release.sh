#!/bin/sh
# Builds the four shipping binaries and the checksums the client pins them by, and an
# unstripped companion per target for a core dump to be read against.
#
# The companion is a second build with `-Cstrip=none` rather than the shipping binary
# with its symbols put back, because there is no putting them back, and it is not the
# shipping binary stripped afterwards either: rustc strips at link time and `llvm-strip`
# after it, and the two ELFs differ. Deriving one from the other would change what
# ships, and what ships is what the checksums are taken over. The two builds are
# checked against each other instead — identical `.text` at an identical address is
# what makes the companion's symbols describe the binary someone actually ran.
# `NOMUX_SKIP_DEBUG=1` builds only the four that ship.
#
# nomux uploads itself over whatever link the user's ssh session is riding, so the
# binary is on the critical path of every cold start and IMPLEMENTATION.md § 8 caps
# it at 400 KiB per architecture. That cap is not decoration: this script exits
# non-zero if any binary misses it, because a release that blows the budget is a
# regression in the one number users feel.
#
# The cap on its own is not enough, which is what the armv7 regression taught: one
# commit grew that binary 46% and nothing said a word, because the result still fitted
# the cap comfortably. A number is only watched if something compares it to what it
# was. So the script also keeps a per-target baseline in scripts/size-baseline, prints
# the signed delta against it beside every size, and fails a build that grows a target
# by more than 3%. A shrink never fails, however large. When the growth is intended,
# NOMUX_UPDATE_BASELINE=1 rewrites the baseline from this build and skips the gate —
# which puts the new figure in the diff, so accepting a size regression becomes
# something a reviewer sees rather than something nobody measured.
#
# Two things have to be true of the output, and IMPLEMENTATION.md § 8 says why: it is
# byte-identical everywhere, which the --remap-path-prefix flags below are what buy —
# so the check is a grep of each artifact for the builder's home directory, not a
# comparison of two builds on one machine — and nothing on the host leaks into it,
# which .cargo/config.toml and rust-toolchain.toml between them decide.
#
# Nightly by default because the released standard library does not fit; rebuilding it
# with -Cpanic=immediate-abort is the only configuration that ships. The compiler is
# dated rather than floating — scripts/nightly-version names it and this script
# defaults to it, with NOMUX_NIGHTLY overriding for a one-off — because the SHA-256
# the client pins would drift under a floating one.
#
# No shipping figure is written down here: scripts/size-baseline holds them, written
# by a build rather than by hand.
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
# An unstripped binary per target, published beside the stripped one it describes.
# The shipping build is `-Cpanic=immediate-abort` with `strip = "symbols"`, so an abort
# produces no message, no location and no symbol — what is left is the `SIGQUIT` core
# of IMPLEMENTATION.md § 6.5, and without these it names no functions — PLAN.md § P1.
# On by default so that a laptop build produces what the release publishes;
# NOMUX_SKIP_DEBUG=1 is for a run that only wants the size table, since this doubles
# the four cross builds into eight.
companions=1
if [ "${NOMUX_SKIP_DEBUG:-0}" = 1 ]; then
    companions=0
fi

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
    # toolchain name and nothing else: this reader takes the file verbatim and CI's
    # round-trips it through the line-oriented $GITHUB_OUTPUT, so a file the two could
    # read differently — a second line, a comment, surrounding space — is rejected
    # there rather than installed under one name and measured under another.
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

    # -Zbuild-std and -Cpanic=immediate-abort are nightly-only, and NOMUX_NIGHTLY is
    # the one place a stable toolchain can get in. It passes every check below — the
    # rust-std and rust-src ones both look at the sysroot, which says nothing about the
    # channel — and then the first cross build dies on `the -Z flag is only accepted on
    # the nightly channel`, minutes in and nowhere near the variable that caused it.
    # Asked of rustc rather than pattern-matched on the toolchain name, so a custom
    # `rustup toolchain link` to a nightly is not refused for what it is called.
    version=$(rustc --version)
    case "$version" in
    *-nightly* | *-dev*) ;;
    *)
        echo "$toolchain is not a nightly toolchain:" >&2
        echo "  $version" >&2
        echo "  the shipping build rebuilds std with panics compiled out, which only" >&2
        echo "  nightly accepts. Name a nightly, or set NOMUX_STABLE_STD=1 to build" >&2
        echo "  against the released std and expect to miss the size budget." >&2
        exit 1
        ;;
    esac
fi

# The growth gate compares this build's bytes against figures another build measured,
# and that is only a comparison if the same compiler produced both — these sizes move
# by hundreds of bytes on a compiler bump, against a threshold of a few thousand. The
# two files that decide it are `scripts/nightly-version`, which names the compiler, and
# `scripts/size-baseline`, which holds the figures; the rule has always been that they
# move in one commit. Nothing enforced it, so it was a rule people had to remember.
#
# It does not need a third file to be the source of truth for both. The baseline
# already records the compiler that measured it — the resolved `rustc --version`,
# written by the refresh below — so the tree can be asked whether it still agrees with
# itself, which is what this does. Comparing the resolved string rather than the
# toolchain name is the point: `nightly` floats, and two builds a day apart can both
# answer to that name and disagree about every figure.
#
# A build that names its own compiler is a different case from one that is inconsistent
# with itself. Under NOMUX_NIGHTLY or NOMUX_STABLE_STD the mismatch is what was asked
# for, and the script already says both are for builds that are not releases — so those
# say so and lose the growth gate, which could only report the compiler as a
# regression. Everything else is `scripts/nightly-version` and `scripts/size-baseline`
# having drifted apart, and that is the mistake both exist to make visible.
overridden=0
if [ -n "${NOMUX_NIGHTLY:-}" ] || [ "${NOMUX_STABLE_STD:-0}" = 1 ]; then
    overridden=1
fi
building_with=$(rustc --version)
measured_by=''
if [ -e "$baseline_file" ]; then
    measured_by=$(awk '
        /^#[[:space:]]*Measured on/ { getline; sub(/^#[[:space:]]*/, ""); print; exit }
    ' "$baseline_file")
fi
skip_growth=0
if [ "$update_baseline" != 1 ] && [ -n "$measured_by" ] && [ "$measured_by" != "$building_with" ]; then
    if [ "$overridden" = 1 ]; then
        skip_growth=1
        echo "note: growth gate off; ${baseline_file#"$repo"/} was measured by another compiler." >&2
        echo "      building with: $building_with" >&2
        echo "      measured by:   $measured_by" >&2
    else
        echo "${baseline_file#"$repo"/} was measured by a different compiler than the" >&2
        echo "  one ${nightly_file#"$repo"/} now names, so its figures are not this" >&2
        echo "  build's to be held against:" >&2
        echo "    building with: $building_with" >&2
        echo "    measured by:   $measured_by" >&2
        echo "  the two move in one commit. Rerun with NOMUX_UPDATE_BASELINE=1 and" >&2
        echo "  commit the refreshed baseline beside the toolchain bump." >&2
        exit 1
    fi
fi

# Flags are joined by U+001F and handed to cargo as CARGO_ENCODED_RUSTFLAGS, not as a
# space-separated RUSTFLAGS. Cargo splits RUSTFLAGS on whitespace, and three of the
# flags below interpolate a path — $repo, the sysroot, $CARGO_HOME — so a single space
# anywhere in any of them split one `--remap-path-prefix=FROM=TO` into two arguments
# and the build died on `--remap-path-prefix must contain '=' between FROM and TO`.
# That was the one place the "run from anywhere" promise in the header did not hold.
# CARGO_ENCODED_RUSTFLAGS splits on the separator alone, so a path may contain
# anything but that byte.
#
# It is all-or-nothing: setting it makes cargo ignore RUSTFLAGS entirely, so every
# flag has to be here rather than split across the two. And every flag has to be one
# whole argument, since nothing splits them further: `-Clink-self-contained=yes`, not
# the `-C link-self-contained=yes` that whitespace splitting used to take apart —
# passed whole, rustc reads the option name as ` link-self-contained` and refuses it.
#
# printf rather than a literal control character in the source, so the byte survives
# an editor, a diff and a copy-paste; /bin/sh is dash on the runner and this is a
# POSIX octal escape, not a bashism.
us=$(printf '\037')

# Every path that could differ between two machines building the same commit. $repo is
# remapped even though cargo already passes workspace paths relative, so that a future
# path-dependent dependency cannot quietly reintroduce the problem.
sysroot=$(rustc --print sysroot)
# Beside the toolchain's own `rust-lld`, so it is the same LLVM that did the linking
# and it reads every target the four cross builds emit. Resolved after the toolchain is
# chosen, since that is what decides which one this is.
objcopy="$(rustc --print target-libdir)/../bin/llvm-objcopy"
# Its own target directory: the companion differs from the shipping build by a rustc
# flag, so sharing one would make each build invalidate the other's cache and turn
# every one of the eight into a cold one.
companion_dir="${CARGO_TARGET_DIR:-$repo/target}/companion"
remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap="$remap$us--remap-path-prefix=$sysroot=/rust"
remap="$remap$us--remap-path-prefix=$repo=/nomux"

# crt-static is explicit because riscv64gc-unknown-linux-musl is the one target of the
# four whose spec does not default to it. Left alone it links dynamically against
# libc.so and libgcc_s, which fails outright under rust-lld — and had it linked, it
# would have produced the one thing this project cannot ship: a binary with runtime
# dependencies on a host we know nothing about.
rustflags="-Clink-self-contained=yes$us-Ctarget-feature=+crt-static$us$remap"
if [ "$build_std" = 1 ]; then
    rustflags="$rustflags$us-Zunstable-options$us-Cpanic=immediate-abort"
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

# `llvm-objcopy` is what compares the two builds below, and it ships with the
# toolchain rather than with the host: the four targets include riscv64 and armv7, and
# a host binutils that cannot read those is the ordinary case rather than the odd one.
if [ "$companions" = 1 ] && [ ! -x "$objcopy" ]; then
    echo "the debug companions need llvm-objcopy to be checked against the" >&2
    echo "  binaries they describe." >&2
    echo "  rustup component add --toolchain $toolchain llvm-tools" >&2
    echo "  or set NOMUX_SKIP_DEBUG=1 for a build that is not a release." >&2
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

# The remap check, actually run, against every artifact that gets published. Two clean
# builds on one machine are byte-identical with or without --remap-path-prefix, so
# comparing them proves nothing about the next machine; what does is that no
# builder-specific path survives in the artifact. Without this the flags above could
# stop matching — a moved $CARGO_HOME, a new sysroot layout — and nothing would say so
# until a client somewhere failed a checksum it could not diagnose.
#
# `-a` is load-bearing: without it grep classifies the artifact as binary and reports
# no match even where one exists, so the check would silently pass on every input and
# prove nothing.
#
# A function rather than the loop it used to be, because it now has two kinds of
# artifact to run over and their names differ; passing paths around in a
# space-separated string is the one thing this script cannot do, `$repo` being a path
# the caller chose.
check_leaks() {
    for leak in "${CARGO_HOME:-$HOME/.cargo}" "$sysroot" "$repo"; do
        if LC_ALL=C grep -qaF -- "$leak" "$1"; then
            echo "FAIL: ${1##*/} embeds the build path $leak" >&2
            echo "      the artifact is reproducible only on this machine." >&2
            exit 1
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
        # The same build with the strip turned off, rather than the shipping binary
        # with symbols added back — there is no adding back. It is a second build
        # because stripping this one does *not* reproduce the shipping bytes: rustc
        # strips at link time and `llvm-strip` after it, and the two ELFs differ by a
        # couple of hundred bytes. Deriving one from the other would therefore change
        # what ships, and what ships is what the checksums and the size baseline are
        # taken over.
        CARGO_TARGET_DIR="$companion_dir" \
            CARGO_ENCODED_RUSTFLAGS="$rustflags$us-Cstrip=none" \
            cargo build --locked --release --target "$target" --bin nomux "$@" >&2
        cp "$companion_dir/$target/release/nomux" "$dist/nomux-$target.debug"
        # Checked here too, and it matters more here: DWARF is made of file paths, so
        # a companion is where an unremapped sysroot or checkout would surface first.
        check_leaks "$dist/nomux-$target.debug"

        # That the two builds line up is the whole of what makes a companion worth
        # publishing, and it is an inference rather than a guarantee — `-Cstrip` is
        # documented to drop sections, not to leave code alone. A companion whose
        # addresses have moved is worse than none: it names functions, and names the
        # wrong ones. So it is checked rather than assumed, per target, per build.
        # `.text` is the section a core is read against; identical contents at an
        # identical address is what "these symbols describe that binary" means.
        "$objcopy" --dump-section .text="$companion_dir/ship.text" \
            "$dist/nomux-$target" /dev/null
        "$objcopy" --dump-section .text="$companion_dir/companion.text" \
            "$dist/nomux-$target.debug" /dev/null
        if ! cmp -s "$companion_dir/ship.text" "$companion_dir/companion.text"; then
            echo "FAIL: the $target companion's .text is not the shipping binary's." >&2
            echo "      its symbols would name the wrong functions in a core." >&2
            exit 1
        fi
    fi

done

# Emitted in `sha256sum -c` format so a verifier needs no bespoke tooling, and naming
# the four shipping binaries and nothing else. `sha256sum -c` fails on a file it cannot
# open, so folding the companions in here would break the check for everyone who
# downloaded only what they run — which is nearly everyone. They get a file of their
# own, in the same format, read the same way. Listed target by target rather than by
# globbing `nomux-*`, which would sweep the companions into both.
(cd "$dist" && for t in $targets; do sha256sum "nomux-$t"; done > SHA256SUMS)
if [ "$companions" = 1 ]; then
    (cd "$dist" && for t in $targets; do sha256sum "nomux-$t.debug"; done > SHA256SUMS.debug)
fi

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
        # `skip_growth` is the compiler having moved under an override, above: the delta
        # is still printed, because seeing what another compiler costs is what those
        # runs are for, but it is not a verdict anyone can act on.
        if [ "$update_baseline" != 1 ] && [ "$skip_growth" != 1 ] && [ "$diff" -gt 0 ] &&
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
if [ "$companions" = 1 ]; then
    echo "artifacts, companions and both SHA256SUMS in ${dist#"$repo"/}"
else
    echo "artifacts and SHA256SUMS in ${dist#"$repo"/} (NOMUX_SKIP_DEBUG=1, no companions)"
fi

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
#
# Which is also why the toolchain is pinned in \`scripts/nightly-version\` rather than
# named at each site: that file and this one move together, and a commit that changes
# one without the other is the mistake both exist to make visible.
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
