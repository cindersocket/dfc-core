#!/usr/bin/env python3
"""Create or verify portable SHA-256 release manifests."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def create(output: Path, files: list[Path]) -> None:
    names = [path.name for path in files]
    if len(names) != len(set(names)):
        raise SystemExit("artifact basenames must be unique")
    lines = [f"{digest(path)}  {path.name}\n" for path in files]
    output.write_text("".join(lines), encoding="utf-8")


def check(manifest: Path) -> None:
    failed = False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if match is None:
            raise SystemExit(f"{manifest}: invalid checksum line: {line!r}")
        path = manifest.parent / match.group(2)
        if path.is_file() and digest(path) == match.group(1):
            print(f"{path.name}: OK")
        else:
            print(f"{path.name}: FAILED", file=sys.stderr)
            failed = True
    if failed:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("files", type=Path, nargs="+")
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("manifest", type=Path)
    args = parser.parse_args()

    if args.command == "create":
        create(args.output, args.files)
    else:
        check(args.manifest)


if __name__ == "__main__":
    main()
