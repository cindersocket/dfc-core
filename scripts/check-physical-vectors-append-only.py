#!/usr/bin/env python3
"""Fail if any change edits, deletes or replaces a physical-card conformance vector.

A vector with `origin: physical-card` records what genuine silicon did. Code and
synthetic tests are written to match it, never the reverse, so no genuine byte may
be changed. A wrong capture is retired by adding a corrected one and saying why in
review, not by editing the original in place.

One kind of edit IS allowed: annotation that tells the replay what to do without
touching anything the card did. That is comment lines, blank lines, `inject-random`
steps (the random the card drew, recovered from the capture itself) and the
`replayable:` / `requires:` headers. The check strips exactly those from the old
and the new text and requires the rest to be identical, line for line, so every
frame, status, exchange, setup header and the origin stay as captured.

The check looks at every commit in BASE..HEAD, including merge commits (against
each parent), and at the cumulative change from BASE to HEAD, so a change cannot
hide in a merge resolution or be split across commits. It reports modification,
deletion, rename and a change of file type (for example a vector replaced by a
symlink). The origin header is recognised anywhere in the file, with any spacing,
using the same reading as the vector integrity check.

Usage: check-physical-vectors-append-only.py [BASE_REF] [--repo PATH]
       (default BASE_REF origin/master, default repo is the current directory)
"""

from __future__ import annotations

import re
import subprocess
import sys

VECTORS = "tests/vectors/desfire"
# Horizontal whitespace of any kind, Unicode included, exactly as the vector
# integrity check (which strips with str.strip) reads a header line.
ORIGIN = re.compile(r"^[^\S\r\n]*origin[^\S\r\n]*:[^\S\r\n]*physical-card[^\S\r\n]*$", re.MULTILINE)
CHANGES = "MDRT"  # modified, deleted, renamed, type changed
# A capture can be marked provisional when it is first added (for example a batch
# taken from a card that may turn out to be faulty). A provisional capture may be
# DELETED later, so a bad batch can be thrown away; it can still never be edited
# or renamed, and a capture cannot be made provisional afterwards (adding the
# header would be an edit, which this gate rejects).
PROVISIONAL = re.compile(
    r"^[^\S\r\n]*capture-status[^\S\r\n]*:[^\S\r\n]*provisional[^\S\r\n]*$", re.MULTILINE
)


def git(repo: str, *args: str) -> str:
    return subprocess.run(
        ["git", "--no-pager", "-C", repo, *args], check=True, capture_output=True, text=True
    ).stdout


def is_physical(repo: str, revision: str, path: str) -> bool:
    try:
        text = git(repo, "show", f"{revision}:{path}")
    except subprocess.CalledProcessError:
        return False
    # Header lines are `key: value`; a comment line that mentions the words does not count.
    return bool(
        ORIGIN.search(
            "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        )
    )


def is_provisional(repo: str, revision: str, path: str) -> bool:
    try:
        text = git(repo, "show", f"{revision}:{path}")
    except subprocess.CalledProcessError:
        return False
    return bool(
        PROVISIONAL.search(
            "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        )
    )


# Lines that only instruct the replay, never record what the card did.
ANNOTATION_HEADERS = ("replayable", "requires")


def genuine_lines(text: str) -> list[str]:
    """The text of a vector with annotation-only lines removed, one entry per line."""
    kept = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.split(None, 1)[0] == "inject-random":
            continue
        key = line.split(":", 1)[0].strip() if ":" in line else None
        if key in ANNOTATION_HEADERS:
            continue
        kept.append(line)
    return kept


def is_annotation_only_change(repo: str, old_rev: str, new_rev: str, path: str) -> bool:
    try:
        old = git(repo, "show", f"{old_rev}:{path}")
        new = git(repo, "show", f"{new_rev}:{path}")
    except subprocess.CalledProcessError:
        return False
    return genuine_lines(old) == genuine_lines(new)


def changed_vectors(repo: str, *diff_args: str) -> list[tuple[str, str]]:
    # NUL-delimited so git never quotes an unusual filename (non-ASCII, a quote or
    # a tab) into something that no longer names the file.
    fields = git(
        repo, *diff_args, "-z", "--name-status", "-M", f"--diff-filter={CHANGES}", "--", VECTORS
    ).split("\0")
    out, index = [], 0
    while index < len(fields) and fields[index]:
        status = fields[index]
        count = 2 if status[0] in "RC" else 1
        out.append((status[0], fields[index + 1]))
        index += 1 + count
    return out


def check(base: str, repo: str = ".") -> tuple[list[str], int]:
    commits = git(repo, "rev-list", "--reverse", f"{base}..HEAD").split()
    violations: list[str] = []

    def examine(label: str, parent: str, child: str, entries: list[tuple[str, str]]) -> None:
        for status, path in entries:
            if path.endswith(".vec") and is_physical(repo, parent, path):
                if status == "D" and is_provisional(repo, parent, path):
                    continue  # a provisional capture may be retired by deleting it
                if status == "M" and is_annotation_only_change(repo, parent, child, path):
                    continue  # annotation for the replay; every genuine line is unchanged
                violations.append(f"{label} {status} {path}")

    for commit in commits:
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).split()[1:]
        for parent in parents or []:
            examine(
                commit[:9],
                parent,
                commit,
                changed_vectors(repo, "diff-tree", "-r", "--no-commit-id", parent, commit),
            )
    examine("cumulative", base, "HEAD", changed_vectors(repo, "diff", base, "HEAD"))
    return sorted(set(violations)), len(commits)


def main() -> int:
    args = sys.argv[1:]
    repo = "."
    if "--repo" in args:
        index = args.index("--repo")
        repo = args[index + 1]
        del args[index : index + 2]
    base = args[0] if args else "origin/master"
    violations, count = check(base, repo)
    for violation in violations:
        print(f"physical-card vector changed: {violation}", file=sys.stderr)
    if violations:
        return 1
    print(f"physical-card vectors unchanged across {count} commit(s) since {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
