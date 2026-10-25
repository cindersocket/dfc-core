"""Regression tests for the published Rust source archives."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_SYS_FILES = {
    "CMakeLists.txt",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE",
    "bindings/rust/README.md",
}

EXPECTED_SYS_TREES = ("cmake", "ffi", "port", "src", "bindings/rust/dfc-core-sys")
GENERATED_PACKAGE_FILES = {".cargo_vcs_info.json"}
PACKAGE_PATH_ALIASES = {"README.md": "bindings/rust/README.md"}


def packaged_files(package: str) -> set[str]:
    result = subprocess.run(
        ["cargo", "package", "--package", package, "--list", "--allow-dirty"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        PACKAGE_PATH_ALIASES.get(path, path)
        for path in result.stdout.splitlines()
        if path not in GENERATED_PACKAGE_FILES
    }


def publishable_sys_sources() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for tree in EXPECTED_SYS_TREES
        for path in (ROOT / tree).rglob("*")
        if path.is_file()
    }


class CargoPackageTests(unittest.TestCase):
    def test_archive_check_does_not_require_git_metadata(self) -> None:
        with mock.patch("subprocess.run", side_effect=AssertionError("unexpected command")):
            sources = publishable_sys_sources()

        self.assertIn("src/dfc.h", sources)

    def test_sys_package_contains_only_publishable_sources(self) -> None:
        expected = EXPECTED_SYS_FILES | publishable_sys_sources()

        self.assertEqual(packaged_files("dfc-core-sys"), expected)


if __name__ == "__main__":
    unittest.main()
