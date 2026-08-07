#!/bin/sh
# Builds the two shipping binaries and the checksums the client pins them by. Runs from
# anywhere in the tree; artifacts land in target/dist/.
#
# nomux uploads itself over whatever link the user's ssh session is riding, so the binary is
# on the critical path of every cold start and IMPLEMENTATION.md § 8 caps it at 400 KiB per
# architecture. The cap alone is not enough — one commit grew armv7 46% back when it shipped
# and nothing said a word, because the result still fitted — so scripts/size-baseline holds a
# figure per target and growth past 3% fails too. A shrink never does, however large.
# NOMUX_UPDATE_BASELINE=1 rewrites the baseline and skips the gate, which puts an accepted
# regression in a diff a reviewer reads.
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
#
# `pwd -P` rather than the logical path, for the reason $target_root below resolves one too:
# rustc records the physical path it opened a file through, and both uses of $repo are held
# against that record — the --remap-path-prefix that has to cover it, and the check_leaks
# needle that has to find it if the remap missed. Run through a symlinked checkout, the
# logical path names a directory rustc never wrote down; the remap would then rewrite nothing
# and the grep would agree, and the real path would ship unremapped and unreported.
repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo"

dist="$repo/target/dist"
baseline_file="$repo/scripts/size-baseline"
update_baseline="${NOMUX_UPDATE_BASELINE:-0}"

# Nightly, because the released std does not fit: rebuilding it with -Cpanic=immediate-abort
# is the only configuration that ships. Dated rather than floating, because the SHA-256 the
# client pins would drift under a name that moves. Named here and nowhere else, so a laptop
# and the runner measure the same bytes by construction; editing it shows up in `git status`,
# which an environment override would not.
nightly='nightly-2026-08-07'

# The file holds one `target bytes` pair per line, # comments ignored; this prints nothing at
# all for a target it has no usable figure for. The gate below treats that as a failure rather
# than as a first build, so a line dropped from an otherwise fine file cannot leave the gate
# present, running, and unable to fail.
baseline_for() {
    [ -r "$baseline_file" ] || return 0
    awk -v t="$1" '{ sub(/#.*/, "") }
        $1 == t && NF == 2 && $2 ~ /^[0-9]+$/ { print $2; exit }' "$baseline_file"
}

# Installed rather than detected and complained about: past the compiler this needs std's
# sources (-Zbuild-std compiles it here), both musl rust-std components (that build still
# links their CRT objects and libc.a) and llvm-tools (the $readobj every run checks a binary
# with). One idempotent command, so a runner and a laptop provision identically. The target
# list is joined out of $targets rather than restated, so what is installed cannot drift from
# what is built. Chatter to stderr: stdout is the size table's.
rustup toolchain install "$nightly" --profile minimal --no-self-update \
    --component rust-src,llvm-tools \
    --target "$(printf '%s' "$targets" | tr '\n' ',')" >&2

RUSTUP_TOOLCHAIN="$nightly"
export RUSTUP_TOOLCHAIN
toolchain="$nightly"

# The resolved compiler, never the name it was asked for: `nightly` floats, and two builds
# a day apart can both answer to that name and disagree about every figure below.
version=$(rustc --version)

# -Zbuild-std and -Cpanic=immediate-abort are nightly-only, and the `nightly` pin above is the
# one place a stable toolchain can now get in: rustup installs one just as willingly as a
# nightly, and nothing after this point looks at the channel — so unchecked it would die
# minutes into the first cross build, nowhere near the cause. Asked of rustc rather than
# matched on the name, so a linked nightly stands.
case "$version" in
*-nightly* | *-dev*) ;;
*) die "$toolchain is not a nightly toolchain: $version" \
        "  the shipping build rebuilds std with panics compiled out, which only" \
        "  nightly accepts. Name a nightly in \$nightly at the top of this script." ;;
esac

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
# Beside the toolchain's own `rust-lld`, so it is the same LLVM that linked and they read every
# target the cross builds emit. Out of the toolchain rather than off the host for that reason:
# one of the two targets is cross-compiled, and a host binutils that cannot read aarch64 is the
# ordinary case rather than the odd one. Resolved after the toolchain is chosen, which decides
# which — and after the install above, which is what put them there.
# `llvm-readobj` rather than `llvm-readelf`: llvm-tools ships only the former, and it is the
# same program — readelf is that binary under another name, differing in default output style.
readobj="$(rustc --print target-libdir)/../bin/llvm-readobj"
# Resolved rather than taken as spelled: cargo accepts a *relative* $CARGO_TARGET_DIR and reads
# it against this script's cwd, and both uses below need an absolute path — rustc matches a
# remap prefix component-wise, and check_leaks greps the artifact for this literal. A bare `t`
# would remap nothing and then fail every build on a byte that occurs in any 175 KiB binary.
# `pwd -P` also settles a symlink and a trailing slash.
#
# Created first, so the `cd` cannot fail: a target directory that does not exist yet is the
# ordinary case on a cold checkout, and the fallback this replaces used the *unresolved* path
# as both a remap prefix and a check_leaks needle — the remap would then miss the physical
# path rustc recorded and the grep would agree, which is the exact failure the remapping
# exists to prevent.
mkdir -p -- "${CARGO_TARGET_DIR:-$repo/target}"
target_root=$(unset CDPATH; cd -- "${CARGO_TARGET_DIR:-$repo/target}" && pwd -P)

# The `t` hazard above, which is not particular to $CARGO_TARGET_DIR: check_leaks searches each
# artifact for these four paths as bare substrings, and a short one turns up in any 175 KiB
# binary by chance. `CARGO_TARGET_DIR=/t` is only the reachable case — it clears the check just
# above and then fails every build on a coincidence — but a checkout or a $CARGO_HOME can be
# just as short. Held up front rather than inside check_leaks: it is a property of the setting,
# so it earns one message naming the setting, not one per artifact blaming an artifact that is
# fine.
for leak in "${CARGO_HOME:-$HOME/.cargo}" "$sysroot" "$repo" "$target_root"; do
    [ "${#leak}" -ge 8 ] || die \
        "the build path '$leak' is too short to search a binary for. Every artifact is" \
        "  grepped for it, and something that short appears in any of them by chance, so" \
        "  the build would fail on a coincidence rather than on a leak. Give the checkout," \
        "  \$CARGO_HOME or \$CARGO_TARGET_DIR a longer path."
done

remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap="$remap$us--remap-path-prefix=$sysroot=/rust"
remap="$remap$us--remap-path-prefix=$repo=/nomux"
# Only the same path as $repo when the target directory is left where cargo puts it. A
# $CARGO_TARGET_DIR outside the checkout — which the test suite needs, sockaddr_un being
# 108 bytes — otherwise leaves every build-script path unremapped and undetected: the one
# below would report the artifact clean and the checksum would differ on the next machine.
[ "$target_root" = "$repo/target" ] || remap="$remap$us--remap-path-prefix=$target_root=/target"

# crt-static stated rather than left to each target's spec to default to. Both musl targets do,
# so this is belt and braces — but not every target this script has built did, and the failure
# it prevents is the one thing this project cannot ship: a binary with runtime dependencies on
# a host we know nothing about, discovered at a user's shell rather than here.
rustflags="-Clink-self-contained=yes$us-Ctarget-feature=+crt-static$us$remap"
rustflags="$rustflags$us-Zunstable-options$us-Cpanic=immediate-abort"

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
    for leak in "${CARGO_HOME:-$HOME/.cargo}" "$sysroot" "$repo" "$target_root"; do
        if LC_ALL=C grep -qaF -- "$leak" "$1"; then
            die "FAIL: ${1##*/} embeds the build path $leak" \
                "      the artifact is reproducible only on this machine."
        fi
    done

    # Those four say what this environment *claims* the paths are, which need not be how rustc
    # spelled the ones it embedded — so a remap that never fired reads exactly like one that
    # worked. These two are chosen by shape instead: substrings that survive only in an
    # unremapped path, however this machine spells $HOME, $CARGO_HOME or its sysroot, and that
    # cannot occur in a correct one — `/cargo/registry/src/…` never has a `.` before `cargo`,
    # and nothing under the remapped `/rust` is named `rustup`. A positive control is not
    # available: with no DWARF and -Cpanic=immediate-abort there is no path left in the binary
    # at all, so asserting the remapped form is present is a gate that can only fail.
    # `rustlib/src/rust` is unusable for the same reason in reverse — the correctly remapped
    # std path contains it verbatim.
    for leak in .cargo/registry rustup/toolchains; do
        if LC_ALL=C grep -qaF -- "$leak" "$1"; then
            die "FAIL: ${1##*/} embeds an unremapped build path containing '$leak'" \
                "      the remap flags name paths this script derived, and rustc wrote down" \
                "      one they do not cover — so the exact needles above missed it too."
        fi
    done
}

# The rustflags above ask for a static binary; this is what says one came out. Asking is not
# the same as getting — a target spec that ignored crt-static, a dependency that pulled in a
# dynamic libc — and the failure lands at a stranger's shell, on a host we know nothing about,
# rather than here. A static-pie carries neither a PT_INTERP segment naming a loader nor a
# DT_NEEDED entry naming a library; either one means something has to be present on that host.
# Read into a variable first, so a readobj that fails is `set -e` rather than a grep that
# matches nothing and calls the binary clean.
check_static() {
    elf=$("$readobj" --program-headers --dynamic-table "$1")
    # That the output was parsed at all, before any weight is put on its silence. The verdict
    # below is drawn from two patterns *not* matching — which is equally what an empty output,
    # a readobj that wrote its complaint to stderr and exited 0, or a future release that
    # renamed these fields would produce, and every binary would then be pronounced static
    # without having been looked at. Every ELF that runs has at least one PT_LOAD; if that is
    # missing, nothing was read and there is no verdict to give.
    case "$elf" in
    *PT_LOAD*) ;;
    *) die "FAIL: could not read the program headers of ${1##*/}: $readobj reported no" \
            "      PT_LOAD, so it did not parse the file, and its silence about PT_INTERP" \
            "      and NEEDED says nothing about what this binary needs at runtime." ;;
    esac
    if printf '%s\n' "$elf" | grep -qE 'PT_INTERP|NEEDED'; then
        die "FAIL: ${1##*/} is dynamically linked:" \
            "$(printf '%s\n' "$elf" | grep -E 'PT_INTERP|NEEDED')" \
            "      it needs those present on a host nobody has looked at."
    fi
}

for target in $targets; do
    echo "building $target ($toolchain)..." >&2
    CARGO_ENCODED_RUSTFLAGS="$rustflags" \
        cargo build --locked --release --target "$target" --bin nomux \
        -Zbuild-std=std,panic_abort >&2
    cp "$target_root/$target/release/nomux" "$dist/nomux-$target"
    check_leaks "$dist/nomux-$target"
    check_static "$dist/nomux-$target"
done

# `sha256sum -c` format, so a verifier needs no bespoke tooling. Listed target by target rather
# than by globbing, which would sweep in anything else that landed here.
(cd "$dist" && for t in $targets; do sha256sum "nomux-$t"; done > SHA256SUMS)

# Complete from here, so the cleanup is disarmed: the gates below still have to be able to fail,
# and a build that is over budget or has grown is exactly the one whose binaries someone will
# want to measure.
trap - EXIT INT TERM HUP

# Neither gate exits early, so one run tells you everything wrong with the build: a size problem
# is rarely confined to one architecture, and the table is meant to be read across.
failed=''
measured=''
nl='
'
echo
printf '%-34s %9s %9s %9s  %s\n' TARGET BYTES KIB DELTA SHA256
for target in $targets; do
    bytes=$(($(wc -c < "$dist/nomux-$target")))
    sha=$(sha256sum "$dist/nomux-$target" | cut -c1-16)
    # Same column widths as the table, so a refreshed baseline is diffable against the one
    # it replaced instead of reflowing when a binary crosses a power of ten.
    measured="$measured$(printf '%-34s %9d' "$target" "$bytes")$nl"

    verdict=''
    if [ "$bytes" -gt "$max_bytes" ]; then
        verdict=' OVER BUDGET'
        failed=1
        echo "FAIL: $target is over the $((max_bytes / 1024)) KiB budget of IMPLEMENTATION.md § 8." >&2
    fi

    # Bytes rather than a percentage: this is the number the gate compares, `sh` having no
    # floating point to round one with. Empty only on a refresh run, every target having been
    # held against the baseline before the builds started.
    base=$(baseline_for "$target")
    delta=new
    # A target with no usable figure is the gate's own failure, not a first build: missing,
    # malformed and a line dropped from an otherwise fine file all reach here, and the last
    # parses, passes, and would otherwise leave the gate running and unable to fail.
    if [ -z "$base" ] && [ "$update_baseline" != 1 ]; then
        verdict=' NO BASELINE'
        failed=1
        echo "FAIL: no usable entry for $target in ${baseline_file#"$repo"/}, the growth" >&2
        echo "      gate's only reference. It holds one \`target bytes\` pair per line, #" >&2
        echo "      comments ignored. Restore the line if it was dropped or its target" >&2
        echo "      misspelled; if the architecture is new, rerun with" >&2
        echo "      NOMUX_UPDATE_BASELINE=1 and commit the recorded sizes." >&2
    fi
    if [ -n "$base" ]; then
        diff=$((bytes - base))
        delta=$(printf '%+d' "$diff")
        # A negative diff cannot exceed a positive threshold, so only growth can fail here; a
        # shrink is what this project wants, however large.
        if [ "$update_baseline" != 1 ] && [ $((diff * 100)) -gt $((base * max_growth_pct)) ]; then
            verdict=' GROWN'
            failed=1
            echo "FAIL: $target grew $delta bytes against ${baseline_file#"$repo"/}, over" >&2
            echo "      $max_growth_pct%. Find what did it — the cost is paid on every cold upload" >&2
            echo "      — or accept it with NOMUX_UPDATE_BASELINE=1 and commit the new baseline." >&2
        fi
    fi

    printf '%-34s %9d %7d.%d %9s  %s%s\n' "$target" "$bytes" "$((bytes / 1024))" \
        "$(((bytes % 1024) * 10 / 1024))" "$delta" "$sha" "$verdict"
done
echo
echo "artifacts and SHA256SUMS in ${dist#"$repo"/}"

if [ "$update_baseline" = 1 ]; then
    if [ -n "$failed" ]; then
        # The growth gate does not run on a refresh, so the cap is the only thing that can have
        # failed — and these figures would make the next build's delta look healthy while the
        # binary is still too big for the one gate that is not negotiable.
        echo "baseline left alone: a build that misses the cap is not one to record." >&2
    else
        # The compiler that measured these, written down but deliberately not checked against
        # the one building. A bump moves the figures by hundreds of bytes, tenths of a percent
        # — see max_growth_pct above — against a threshold of some four thousand, so a stamp
        # that disagrees never means a delta anyone would act on, and refusing to build on one
        # only taught people to reach for the escape hatch. It stays as a comment, for a reader
        # working out why a number moved between two commits.
        printf '%s\n# Measured on %s by:\n#   %s\n%s' \
            '# Per-target size baseline for scripts/build-release.sh, which says what it is for.' \
            "$(date -u '+%Y-%m-%d')" "$version" "$measured" > "$baseline_file"
        echo "baseline refreshed in ${baseline_file#"$repo"/}; commit it with the change that moved the bytes."
    fi
fi

[ -z "$failed" ] || exit 1
