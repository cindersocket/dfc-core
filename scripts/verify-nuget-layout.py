#!/usr/bin/env python3
"""Verify that a NuGet package contains exactly one native library per supported RID."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

EXPECTED = {
    "linux-x64": "libdfc.so",
    "linux-arm64": "libdfc.so",
    "osx-x64": "libdfc.dylib",
    "osx-arm64": "libdfc.dylib",
    "win-x64": "libdfc.dll",
    "win-arm64": "libdfc.dll",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    with zipfile.ZipFile(args.package) as archive:
        actual = {
            name
            for name in archive.namelist()
            if name.startswith("runtimes/")
            and "/native/" in name
            and not name.endswith("/")
        }
    expected = {f"runtimes/{rid}/native/{library}" for rid, library in EXPECTED.items()}
    if actual != expected:
        raise SystemExit(
            f"NuGet native assets differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


if __name__ == "__main__":
    main()
