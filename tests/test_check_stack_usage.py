"""Regression tests for the GCC stack-usage gate."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "check_stack_usage", ROOT / "scripts" / "check-stack-usage.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load scripts/check-stack-usage.py")
CHECK_STACK_USAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_STACK_USAGE)


class CheckStackUsageTests(unittest.TestCase):
    def test_static_frames_are_sorted_largest_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "static.su"
            path.write_text(
                "source.c:1:1:small\t16\tstatic\nsource.c:2:1:large\t64\tstatic\n", encoding="utf-8"
            )

            self.assertEqual(
                CHECK_STACK_USAGE.stack_frames([path]),
                [(64, "source.c:2:1:large"), (16, "source.c:1:1:small")],
            )

    def test_dynamic_stack_records_are_rejected(self) -> None:
        for qualifier in ("dynamic", "dynamic,bounded"):
            with self.subTest(qualifier=qualifier), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "dynamic.su"
                path.write_text(f"source.c:1:1:vla\t32\t{qualifier}\n", encoding="utf-8")

                with self.assertRaisesRegex(ValueError, "unsupported stack qualifier"):
                    CHECK_STACK_USAGE.stack_frames([path])

    def test_missing_stack_usage_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "only.su"
            path.write_text("source.c:1:1:function\t16\tstatic\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "expected 2 stack-usage files, found 1"):
                CHECK_STACK_USAGE.stack_frames([path], expected_file_count=2)


if __name__ == "__main__":
    unittest.main()
