#!/usr/bin/env python3
"""Tests for portable release checksum generation."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/checksums.py"


class ChecksumsTests(unittest.TestCase):
    def test_create_and_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.tar.gz"
            second = root / "second.zip"
            manifest = root / "SHA256SUMS"
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "create",
                    "--output",
                    str(manifest),
                    str(first),
                    str(second),
                ],
                check=True,
            )
            subprocess.run(["python3", str(SCRIPT), "check", str(manifest)], check=True)

            first.write_bytes(b"changed")
            result = subprocess.run(
                ["python3", str(SCRIPT), "check", str(manifest)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("first.tar.gz: FAILED", result.stderr)


if __name__ == "__main__":
    unittest.main()
