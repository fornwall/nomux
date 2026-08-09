#!/bin/sh
# Every `§ N` in this tree names a section of IMPLEMENTATION.md or DESIGN.md, and nothing
# checks that the section is there. The tree carries ~700 of these, most of them in source
# comments, so a renumbering breaks references in files no one reopens and the loss is
# silent: a comment pointing at a section that has gone reads exactly like one that has not.
# Markdown links rot the same way and in two halves — the path, which a rename empties, and
# the `#anchor`, which a retitled heading empties while the link still opens the right file.
#
# The rule enforced is the convention the tree already follows: a citation qualified with a
# document name means that document, an unqualified one means IMPLEMENTATION.md from the
# source and the enclosing document from within a document. RFC citations are somebody
# else's numbers, so they are not checked; PLAN.md carries no numbered sections, so it is
# skipped.
#
# Exits non-zero listing every citation and link that resolves to nothing.
set -eu
unset CDPATH
cd -- "$(dirname -- "$0")/.."

# One awk over the whole tree. NUL-delimited so a path with a space survives; `scripts/`
# picks up the extensionless configuration files the extension globs miss. awk opens each
# file itself rather than taking them as operands: a path can be in the index and gone from
# the worktree mid-rename, where `getline` answers -1 instead of dying, and a name holding
# `=` cannot be mistaken for a variable assignment.
git ls-files -z '*.rs' '*.md' '*.sh' '*.toml' '*.yml' '*.yaml' scripts/ | tr '\0' '\n' | awk '
function bad(f, n, m) { printf "%s:%s: %s\n", f, n, m > "/dev/stderr"; fails++ }
function whose(q) {  # the document a citation names; "-" for one that is not ours to check
    if (q ~ /RFC/) return "-"
    if (q ~ /DESIGN\.md/) return "DESIGN.md"
    if (q ~ /PLAN\.md/) return "-"
    return (q ~ /IMPLEMENTATION\.md/) ? "IMPLEMENTATION.md" : ""
}
# The headings of one file, read once. `## 6. Daemon` and `### 6.3 Socket` each define a
# section and `#### Identification` defines none; the trailing dot is inconsistent in the
# tree, so it is stripped on both sides. Every heading also answers to the fragment GitHub
# derives: lowercased, all but alphanumeric, space and hyphen dropped, spaces to hyphens.
function load(p,   r, l, h, n) {
    if (p in done) return
    done[p] = ex[p] = 1
    while ((r = (getline l < p)) > 0) {
        if (l !~ /^#+ /) continue
        h = substr(l, index(l, " ") + 1)
        if (l ~ /^###?#? / && match(h, /^[0-9][0-9.]* /)) {
            n = substr(h, 1, RLENGTH - 1); sub(/\.$/, "", n); sec[p, n] = 1
        }
        h = tolower(h); gsub(/[^a-z0-9 -]/, "", h); gsub(/ /, "-", h); anc[p, h] = 1
    }
    if (r < 0) ex[p] = 0
    close(p)
}
# A link target is not prose: read as prose, the filename in a neighbouring URL would
# qualify a citation it says nothing about. So every link collapses to its visible text,
# with the target kept in front only when that text carries a `§` — the one citation that
# target may speak for.
function delink(s,   t, g, i, r) {
    while (match(s, /\[[^][]*\]\([^()]*\)/)) {
        t = substr(s, RSTART, RLENGTH); i = index(t, "](")
        g = substr(t, i + 2, length(t) - i - 2); t = substr(t, 2, i - 2)
        r = (t ~ /§/) ? g " " t : t
        s = substr(s, 1, RSTART - 1) r substr(s, RSTART + RLENGTH)
    }
    return s
}
# A markdown link is relative to the document carrying it, which is only the same thing as
# repository-root-relative while every document sits at the root. e2e-tests/README.md links
# `../crates/nomux/src/startup.rs`, so a target is joined to its document`s directory and
# normalised before anything is opened. Root-level documents are unaffected: their prefix is
# empty and there is nothing to normalise away.
function reldir(f,   d) {
    d = f
    return sub(/\/[^/]*$/, "", d) ? d "/" : ""
}
function normalise(p,   parts, n, i, out, k, j) {
    n = split(p, parts, "/"); k = 0
    for (i = 1; i <= n; i++) {
        if (parts[i] == "" || parts[i] == ".") continue
        # A `..` that would climb past the root is left in place rather than dropped, so the
        # result names nothing and is reported instead of silently becoming another file.
        if (parts[i] == ".." && k > 0 && out[k] != "..") { k--; continue }
        out[++k] = parts[i]
    }
    p = ""
    for (j = 1; j <= k; j++) p = p (j > 1 ? "/" : "") out[j]
    return p
}
function scan(f,   n, l, t, m, g, p, a, q, k, doc, num, prev) {
    while ((getline l < f) > 0) {
        n++; t = l
        # Links into the repository, from the documents that carry them; other servers, mail
        # and same-document anchors are nothing here to resolve.
        while (f ~ /\.md$/ && match(t, /\]\([^()]*\)/)) {
            g = substr(t, RSTART + 2, RLENGTH - 3); t = substr(t, RSTART + RLENGTH)
            if (g ~ /^(https?:|mailto:|#)/) continue
            p = g; sub(/#.*/, "", p); a = substr(g, index(g, "#") + 1)
            p = normalise(reldir(f) p); load(p)
            if (!ex[p]) bad(f, n, "link to " p ", which is not in the repository")
            else if (index(g, "#") && p ~ /\.md$/ && !((p, a) in anc))
                bad(f, n, p " has no heading anchored at #" a)
        }
        # A citation is `§` and a number, or the same thing spelled out — `IMPLEMENTATION.md
        # 6.6` is user-visible in `--help` and rots identically. What qualifies it is the
        # text back to the previous citation on the line, and nothing further.
        t = l = delink(l); k = 0
        while (match(t, /(§ ?|(IMPLEMENTATION|DESIGN)\.md )[0-9][0-9.]*/)) {
            q = substr(t, 1, RSTART - 1); m = substr(t, RSTART, RLENGTH); k++
            t = substr(t, RSTART + RLENGTH)
            num = m; sub(/^[^0-9]*/, "", num); sub(/\.$/, "", num)
            if (m ~ /^§/) doc = whose(q); else { doc = m; sub(/ .*/, "", doc) }
            # A citation wraps: a comment names DESIGN.md at the end of one line and cites
            # `§ 6.4` at the start of the next. So the window carries over the break — but
            # only what the line before left after its own last citation, or a document
            # already spoken for there would qualify this one too.
            if (doc == "" && k == 1 && f !~ /\.md$/) doc = whose(prev)
            if (doc == "-") continue
            if (doc == "") doc = (f == "DESIGN.md") ? f : "IMPLEMENTATION.md"
            if (!((doc, num) in sec)) bad(f, n, "§ " num " does not name a section of " doc)
        }
        prev = t
    }
    close(f)
}
{ if ($0 != "scripts/check-references.sh") list[++nf] = $0 }  # this one cites by example only
END {
    # An empty list is a broken invocation, not a clean tree: `#!/bin/sh` has no
    # `pipefail`, so this pipeline exits on awk alone, and awk over no input would run
    # this block, print the success line and exit 0 — the whole ~700-citation check
    # passing vacuously because `git ls-files` was the thing that failed.
    if (nf == 0) { print "no files to scan" > "/dev/stderr"; exit 1 }
    # Documents first: one that links to itself would otherwise have awk reopen the very
    # file it is in the middle of reading.
    for (i = 1; i <= nf; i++) if (list[i] ~ /\.md$/) load(list[i])
    for (i = 1; i <= nf; i++) scan(list[i])
    if (fails) { printf "\n%d dangling reference(s).\n", fails > "/dev/stderr"; exit 1 }
    print "all § references and document links resolve"
}
'
