#!/usr/bin/env python3
"""Validate GCC stack-usage records and report static frames by size."""

from __future__ import annotations

import argparse
from pathlib import Path


def stack_frames(
    paths: list[Path], expected_file_count: int | None = None
) -> list[tuple[int, str]]:
    if expected_file_count is not None and len(paths) != expected_file_count:
        raise ValueError(f"expected {expected_file_count} stack-usage files, found {len(paths)}")

    frames: list[tuple[int, str]] = []
    for path in paths:
        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw_line:
                continue
            fields = raw_line.split("\t")
            if len(fields) != 3:
                raise ValueError(f"{path}:{line_number}: malformed stack-usage record")

            location, size_text, qualifier = fields
            try:
                size = int(size_text)
            except ValueError as error:
                raise ValueError(
                    f"{path}:{line_number}: invalid stack size {size_text!r}"
                ) from error
            if size < 0:
                raise ValueError(f"{path}:{line_number}: negative stack size {size}")
            if qualifier != "static":
                raise ValueError(f"{path}:{line_number}: unsupported stack qualifier {qualifier!r}")
            frames.append((size, location))

    return sorted(frames, key=lambda frame: (-frame[0], frame[1]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-file-count", type=int, required=True)
    parser.add_argument("paths", nargs="+", type=Path)
    arguments = parser.parse_args()
    try:
        frames = stack_frames(arguments.paths, arguments.expected_file_count)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    if not frames:
        raise SystemExit("stack-usage files contain no function records")

    print(frames[0][0])
    for size, location in frames:
        print(f"{size}\t{location}")


if __name__ == "__main__":
    main()
