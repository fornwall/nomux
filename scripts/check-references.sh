#!/bin/sh
# Every `§ N` in this tree names a section of IMPLEMENTATION.md or DESIGN.md, and nothing
# checks that the section is there. The documents carry 700-odd of these citations and the
# source carries most of them, so a renumbering breaks references in files no one reopens
# and the loss is silent: a comment pointing at a section that no longer exists reads
# exactly like one that does.
#
# The rule this enforces is the convention the tree already follows: a citation qualified
# with a document name means that document, an unqualified one means IMPLEMENTATION.md
# from the source and the enclosing document from a document. RFC citations are named as
# such and are nobody's section number here.
#
# Exits non-zero listing every citation that resolves to nothing.
set -eu

repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

# The numbered headings each document defines: `## 6. Daemon` and `### 6.3 Socket` both
# define a section, and `#### Identification` defines none. The trailing dot is optional
# and inconsistent in the tree, so it is stripped on both sides of the comparison.
sections() {
    sed -n 's/^#\{2,4\} \([0-9][0-9.]*\)\.\? .*/\1/p' "$1" | sed 's/\.$//'
}

impl_sections=$(sections IMPLEMENTATION.md)
design_sections=$(sections DESIGN.md)

# The fragment a heading answers to, by the rule GitHub renders with: lowercased, with
# everything that is not alphanumeric, a space or a hyphen dropped — backticks, dots and
# `§` included — and spaces then turned into hyphens. `### 6.1.1 What the child runs`
# becomes `611-what-the-child-runs`.
anchors() {
    sed -n 's/^#\{1,6\} //p' "$1" |
        tr '[:upper:]' '[:lower:]' |
        sed 's/[^a-z0-9 -]//g; s/ /-/g'
}

# A citation is `§` plus a number, optionally preceded on the same line by the document it
# names. `RFC <n> §` is a citation into somebody else's document and is skipped.
#
# grep -o loses the line number, so the scan is per file per line: the tree is small and
# this runs in well under a second.
failures=0
report() {
    printf '%s:%s: § %s does not name a section of %s\n' "$1" "$2" "$3" "$4" >&2
    failures=$((failures + 1))
}

for file in $(git ls-files '*.rs' '*.md' '*.sh' '*.toml' '*.yml'); do
    case "$file" in
        # This script names section numbers only as examples.
        scripts/check-references.sh) continue ;;
    esac
    line_no=0
    # SC2094: `report` names the file being read, but writes only to stderr.
    # shellcheck disable=SC2094
    while IFS= read -r line || [ -n "$line" ]; do
        line_no=$((line_no + 1))
        case "$line" in
            *§*) ;;
            *) continue ;;
        esac
        # Each `§` on the line, with the text before it, so the qualifier is visible.
        rest=$line
        while :; do
            case "$rest" in
                *§*) ;;
                *) break ;;
            esac
            before=${rest%%§*}
            rest=${rest#*§}
            number=$(printf '%s' "$rest" | sed -n 's/^ \{0,1\}\([0-9][0-9.]*\).*/\1/p' | sed 's/\.$//')
            [ -n "$number" ] || continue
            # Whose section is it? The last document named before the `§` wins; an RFC
            # citation is not ours to check.
            case "$before" in
                *RFC*) continue ;;
                *DESIGN.md*) doc=DESIGN.md; known=$design_sections ;;
                *PLAN.md*) continue ;;
                *IMPLEMENTATION.md*) doc=IMPLEMENTATION.md; known=$impl_sections ;;
                *)
                    case "$file" in
                        DESIGN.md) doc=DESIGN.md; known=$design_sections ;;
                        *) doc=IMPLEMENTATION.md; known=$impl_sections ;;
                    esac
                    ;;
            esac
            printf '%s\n' "$known" | grep -qxF "$number" || report "$file" "$line_no" "$number" "$doc"
        done
    done < "$file"
done

# Markdown links to files in this repository. A document that is deleted or renamed takes
# every link to it down silently, and the § check above cannot see it: a citation of
# `PLAN.md § P3` names a section of a file rather than one of ours, so it is skipped there
# and would be missed entirely.
for md in $(git ls-files '*.md'); do
    line_no=0
    while IFS= read -r line || [ -n "$line" ]; do
        line_no=$((line_no + 1))
        rest=$line
        while :; do
            case "$rest" in
                *']('*) ;;
                *) break ;;
            esac
            rest=${rest#*](}
            target=${rest%%)*}
            case "$target" in
                # Other people's servers, mail, and same-document anchors.
                http://* | https://* | mailto:* | '#'*) continue ;;
            esac
            path=${target%%#*}
            [ -n "$path" ] || continue
            if [ ! -e "$repo/$path" ]; then
                printf '%s:%s: link to %s, which is not in the repository\n' \
                    "$md" "$line_no" "$path" >&2
                failures=$((failures + 1))
                continue
            fi
            # The `#anchor` half, which rots exactly as quietly as the path: a renamed
            # heading leaves a link that still opens the right file at the wrong place.
            case "$target" in
                *'#'*) ;;
                *) continue ;;
            esac
            case "$path" in
                *.md) ;;
                *) continue ;;
            esac
            anchor=${target#*#}
            printf '%s\n' "$(anchors "$repo/$path")" | grep -qxF "$anchor" || {
                printf '%s:%s: %s has no heading anchored at #%s\n' \
                    "$md" "$line_no" "$path" "$anchor" >&2
                failures=$((failures + 1))
            }
        done
    done < "$md"
done

if [ "$failures" -ne 0 ]; then
    printf '\n%s dangling reference(s).\n' "$failures" >&2
    exit 1
fi
printf 'all § references and document links resolve\n'
