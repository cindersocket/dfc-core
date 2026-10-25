"""Keep target common code independent of hosted formatting support."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMON_C = ROOT / "src" / "dfc_common.c"
COMMON_H = ROOT / "src" / "dfc_common.h"
STDIO_SYMBOLS = {
    "fprintf",
    "fwrite",
    "printf",
    "putchar",
    "puts",
    "snprintf",
    "sprintf",
    "vfprintf",
    "vprintf",
    "vsnprintf",
}


def symbols(path: Path, *flags: str) -> set[str]:
    output = subprocess.run(
        [os.environ.get("NM", "nm"), *flags, str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {line.split()[-1].lstrip("_") for line in output.splitlines() if line.split()}


def main() -> None:
    source = COMMON_C.read_text(encoding="utf-8")
    header = COMMON_H.read_text(encoding="utf-8")

    assert "#include <stdio.h>" not in source
    assert "dfc_log_buffer" not in source
    assert "dfc_log_buffer" not in header

    with tempfile.TemporaryDirectory() as directory:
        obj = Path(directory) / "dfc_common.o"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-DDFC_BUILD_ROLE=DFC_ROLE_TARGET",
                "-I",
                str(ROOT / "src"),
                "-I",
                str(ROOT / "port"),
                "-c",
                str(COMMON_C),
                "-o",
                str(obj),
            ],
            check=True,
        )
        assert not symbols(obj, "-u") & STDIO_SYMBOLS
        assert "dfc_log_buffer" not in symbols(obj, "-g")


if __name__ == "__main__":
    main()
