#!/usr/bin/env python3
"""Print one reviewed changelog section for GitHub release notes."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    args = parser.parse_args()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## {re.escape(args.version)} "
        rf"\((?:Unreleased|[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\)\n\n"
        r"(.*?)(?=\n## |\Z)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise SystemExit(f"CHANGELOG.md: missing release section for {args.version}")
    print(match.group(1).rstrip())


if __name__ == "__main__":
    main()
