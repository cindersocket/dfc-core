"""Regression tests for the host-suite Makefile contract."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "tests" / "Makefile"


def makefile_text() -> str:
    return MAKEFILE.read_text(encoding="utf-8")


def target(text: str, name: str) -> tuple[str, str]:
    match = re.search(
        rf"(?ms)^{re.escape(name)}:(?P<dependencies>[^\n]*(?:\\\n\t[^\n]*)*)\n"
        rf"(?P<recipe>(?:\t[^\n]*\n)*)",
        text,
    )
    if match is None:
        raise AssertionError(f"{name} target not found")
    return match.group("dependencies"), match.group("recipe")


class MakefileContractTests(unittest.TestCase):
    def test_default_suite_replays_vectors_under_reduced_profiles(self) -> None:
        dependencies, _recipe = target(makefile_text(), "test")

        self.assertIn("vector-profiles", dependencies.replace("\\\n\t", " ").split())

    def test_reduced_tests_share_one_complete_aggregate(self) -> None:
        text = makefile_text()
        reduced_tests = re.findall(r"(?m)^(REDUCED_[A-Z_]+_TEST)\s*:=", text)
        aggregate = re.search(r"(?m)^REDUCED_TESTS\s*:=(?P<value>[^\n]*)$", text)

        self.assertTrue(reduced_tests)
        self.assertIsNotNone(aggregate)
        for variable in reduced_tests:
            with self.subTest(variable=variable):
                self.assertIn(f"$({variable})", aggregate.group("value"))

        dependencies, recipe = target(text, "test")
        self.assertIn("$(REDUCED_TESTS)", dependencies)
        self.assertIn("for test in $(REDUCED_TESTS)", recipe)

        _dependencies, recipe = target(text, "clean")
        self.assertIn("$(REDUCED_TESTS)", recipe)


if __name__ == "__main__":
    unittest.main()
