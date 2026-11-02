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


def assignment(text: str, name: str) -> str:
    """Return one Make assignment after joining tab-indented continuations."""
    lines = text.splitlines()
    prefix = f"{name} :="
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        value = line.removeprefix(prefix).strip()
        while value.endswith("\\"):
            index += 1
            value = value[:-1].rstrip() + " " + lines[index].strip()
        return value
    raise AssertionError(f"{name} assignment not found")


class MakefileContractTests(unittest.TestCase):
    def test_default_suite_replays_vectors_under_reduced_profiles(self) -> None:
        dependencies, _recipe = target(makefile_text(), "test")

        self.assertIn("vector-profiles", dependencies.replace("\\\n\t", " ").split())

    def test_every_vector_directory_is_replayed(self) -> None:
        # Dropping the hardware directory would silently stop replaying every
        # genuine-card capture, so the list is pinned.
        text = makefile_text().replace("\\\n\t", " ")
        line = next(row for row in text.splitlines() if row.startswith("VECTOR_DIRS"))
        for kind in ("emulator", "hardware", "synthetic"):
            self.assertIn(f"vectors/desfire/v*/{kind}", line)

    def test_the_safety_checks_stay_in_the_default_suite(self) -> None:
        # Deleting these from the aggregate would stop the lint, the block-number
        # model and the property test from ever running, and nothing else notices.
        dependencies, _recipe = target(makefile_text(), "test")
        names = dependencies.replace("\\\n\t", " ").split()
        for required in ("check-virtual-picc-staging", "check-iso-dep-block-numbers"):
            self.assertIn(required, names)
        tests = assignment(makefile_text(), "TESTS")
        self.assertIn("test_dfc_iso_dep_frame_properties", tests.split())

    def test_every_vector_file_is_in_a_replayed_directory(self) -> None:
        # The Makefile replays vectors/desfire/v*/{emulator,hardware,synthetic}/*.vec,
        # one level deep. A vector anywhere else would be accepted by the catalogue
        # checks and never replayed.
        root = ROOT / "tests" / "vectors" / "desfire"
        stray = [
            str(path.relative_to(root))
            for path in root.rglob("*.vec")
            if not (
                re.fullmatch(r"v\d+", path.relative_to(root).parts[0])
                and len(path.relative_to(root).parts) == 3
                and path.relative_to(root).parts[1] in ("emulator", "hardware", "synthetic")
            )
        ]
        self.assertEqual(stray, [])

    def test_the_wiring_runs_what_it_names(self) -> None:
        text = makefile_text()
        dependencies, _recipe = target(text, "test")
        names = dependencies.replace("\\\n\t", " ").split()
        # The plain vector replay (which includes every genuine capture) is part of
        # the default suite, not only the reduced-profile replay.
        self.assertIn("vectors", names)
        # Each safety check's recipe must actually run its script, not just exist.
        for name, script in (
            ("check-virtual-picc-staging", "check_virtual_picc_staging.py"),
            ("check-iso-dep-block-numbers", "check_iso_dep_block_numbers.py"),
        ):
            _deps, recipe = target(text, name)
            self.assertEqual(recipe.strip(), f"python3 {script}")
        # TESTS may only ever grow: removing a test with filter-out would stop it
        # running without touching the list the other pins read.
        self.assertNotRegex(text, r"TESTS\s*[:+]?=\s*\$\(filter-out[^)]*\bTESTS\b")
        # The vector directory list is pinned exactly, so wrapping it in a filter
        # that drops the genuine-card captures is noticed.
        self.assertIn(
            "VECTOR_DIRS := $(wildcard vectors/desfire/v*/emulator "
            "vectors/desfire/v*/hardware \\\n\tvectors/desfire/v*/synthetic)",
            text,
        )

    def test_reduced_tests_share_one_complete_aggregate(self) -> None:
        text = makefile_text()
        reduced_tests = re.findall(r"(?m)^(REDUCED_[A-Z_]+_TEST)\s*:=", text)
        aggregate = assignment(text, "REDUCED_TESTS")

        self.assertTrue(reduced_tests)
        for variable in reduced_tests:
            with self.subTest(variable=variable):
                self.assertIn(f"$({variable})", aggregate)

        dependencies, recipe = target(text, "test")
        self.assertIn("$(REDUCED_TESTS)", dependencies)
        self.assertIn("for test in $(REDUCED_TESTS)", recipe)

        _dependencies, recipe = target(text, "clean")
        self.assertIn("$(REDUCED_TESTS)", recipe)

    def test_reduced_ffi_suite_compiles_the_target_role(self) -> None:
        _dependencies, recipe = target(makefile_text(), "test_dfc_ffi_reduced_profile")

        self.assertIn("-DDFC_BUILD_ROLE=DFC_ROLE_TARGET", recipe)


if __name__ == "__main__":
    unittest.main()
