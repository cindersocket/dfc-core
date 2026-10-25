#!/usr/bin/env python3
"""Tests for release-heading validation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("check_version", ROOT / "scripts/check-version.py")
assert SPEC is not None and SPEC.loader is not None
CHECK_VERSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_VERSION)


class ChangelogHeadingTests(unittest.TestCase):
    def test_accepts_unreleased_heading_for_project_version(self) -> None:
        self.assertEqual(
            CHECK_VERSION.changelog_version("# Changelog\n\n## 2.0.0 (Unreleased)\n", "2.0.0"),
            "2.0.0",
        )

    def test_accepts_iso_date_heading_for_project_version(self) -> None:
        self.assertEqual(
            CHECK_VERSION.changelog_version("# Changelog\n\n## 2.0.0 (2026-10-23)\n", "2.0.0"),
            "2.0.0",
        )

    def test_rejects_wrong_version_or_invalid_release_heading(self) -> None:
        invalid = (
            "## 1.2.1 (Unreleased)\n",
            "## 2.0.0 (unreleased)\n",
            "## 2.0.0 (2026-02-30)\n",
            "## 2.0.0 (2026-2-03)\n",
            "## 2.0.0 (23 October 2026)\n",
            "## 2.0.0\n",
        )
        for changelog in invalid:
            with self.subTest(changelog=changelog):
                self.assertIsNone(CHECK_VERSION.changelog_version(changelog, "2.0.0"))


if __name__ == "__main__":
    unittest.main()
