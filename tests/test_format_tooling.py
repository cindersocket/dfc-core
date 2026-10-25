"""Keep formatting independent from native package builds."""

from __future__ import annotations

import re
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class FormatToolingTests(unittest.TestCase):
    def test_ruff_does_not_build_the_python_binding(self) -> None:
        for relative in ("scripts/check-format.sh", "scripts/format-staged.sh"):
            with self.subTest(script=relative):
                script = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn("uv run", script)
                self.assertIn("uvx --from ruff==0.17.1", script)

    def test_python_format_paths_cover_each_source_tree_once(self) -> None:
        script = (ROOT / "scripts/check-format.sh").read_text(encoding="utf-8")
        assignment = re.search(r'python_paths="(?P<paths>.*?)"\n', script, re.DOTALL)

        self.assertIsNotNone(assignment)
        paths = assignment.group("paths").split()
        self.assertEqual(
            paths,
            ["bindings/python/src", "bindings/python/tests", "examples/python", "scripts", "tests"],
        )
        duplicates = [path for path, count in Counter(paths).items() if count > 1]
        self.assertFalse(duplicates, f"duplicate Python format paths: {duplicates}")
        self.assertEqual(script.count("$python_paths"), 2)
        self.assertEqual(script.count("src = ['bindings/python/src']"), 2)

    def test_java_format_paths_include_native_binding_tests(self) -> None:
        script = (ROOT / "scripts/check-format.sh").read_text(encoding="utf-8")

        self.assertIn("'tests/java/*.java'", script)

    def test_format_job_installs_rustfmt(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        format_job = workflow.split("  source-archives:", 1)[0]

        self.assertRegex(
            format_job,
            r"dtolnay/rust-toolchain@stable\n\s+with:\n\s+components: rustfmt",
        )


if __name__ == "__main__":
    unittest.main()
