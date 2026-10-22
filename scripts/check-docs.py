#!/usr/bin/env python3
"""Reject broken repository-local Markdown links."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")


def tracked_markdown(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(root / os.fsdecode(path) for path in result.stdout.split(b"\0") if path)


def broken_links(root: Path) -> list[str]:
    failures: list[str] = []
    for document in tracked_markdown(root):
        for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            for raw in LINK.findall(line):
                destination = raw.split("#", 1)[0].strip().strip("<>")
                if not destination or "://" in destination or destination.startswith("mailto:"):
                    continue
                target = (document.parent / unquote(destination)).resolve()
                if not target.exists():
                    failures.append(f"{document.relative_to(root)}:{number}: {destination}")
    return failures


def main() -> None:
    failures = broken_links(ROOT)
    if failures:
        raise SystemExit("broken local documentation links:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
