#!/usr/bin/env python3
"""Create the self-contained Python package tree used for wheels and the sdist."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def copy(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists():
        raise SystemExit(f"destination already exists: {destination}")

    binding = ROOT / "bindings/python"
    for name in ("README.md", "pyproject.toml", "src"):
        copy(binding / name, destination / name)
    native = destination / "native"
    for name in ("CMakeLists.txt", "LICENSE", "cmake", "ffi", "port", "src"):
        copy(ROOT / name, native / name)

    manifest = destination / "pyproject.toml"
    text = manifest.read_text(encoding="utf-8")
    text = text.replace('cmake.source-dir = "../.."', 'cmake.source-dir = "native"')
    if 'cmake.source-dir = "native"' not in text:
        raise SystemExit("Python package CMake source was not rewritten")
    manifest.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
