"""Regression tests for the tracked C formatting scope."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CheckCFormatTests(unittest.TestCase):
    def test_misformatted_tracked_core_source_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            (checkout / "scripts").mkdir()
            (checkout / "src").mkdir()
            shutil.copy(ROOT / ".clang-format", checkout / ".clang-format")
            shutil.copy(
                ROOT / "scripts" / "check-c-format.sh",
                checkout / "scripts" / "check-c-format.sh",
            )
            (checkout / "src" / "bad.c").write_text(
                "int deliberately_misformatted( void ){return 0;}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
            subprocess.run(["git", "add", "."], cwd=checkout, check=True)

            result = subprocess.run(
                ["./scripts/check-c-format.sh"],
                cwd=checkout,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("src/bad.c", result.stdout)


if __name__ == "__main__":
    unittest.main()
