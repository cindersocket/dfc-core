#!/usr/bin/env python3
"""Reject broken repository-local Markdown links."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")


def main() -> None:
    failures: list[str] = []
    for document in sorted(ROOT.rglob("*.md")):
        relative_parts = document.relative_to(ROOT).parts
        if any(part.startswith(".") or part in {"build", "target", "dist"} for part in relative_parts):
            continue
        for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            for raw in LINK.findall(line):
                destination = raw.split("#", 1)[0].strip().strip("<>")
                if not destination or "://" in destination or destination.startswith("mailto:"):
                    continue
                target = (document.parent / unquote(destination)).resolve()
                if not target.exists():
                    failures.append(f"{document.relative_to(ROOT)}:{number}: {destination}")
    if failures:
        raise SystemExit("broken local documentation links:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
