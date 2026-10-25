"""Regression tests for the published Rust source archives."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_SYS_FILES = {
    ".cargo_vcs_info.json",
    "CMakeLists.txt",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE",
    "README.md",
    "bindings/rust/dfc-core-sys/build.rs",
    "bindings/rust/dfc-core-sys/src/bindings.rs",
    "bindings/rust/dfc-core-sys/src/lib.rs",
    "bindings/rust/dfc-core-sys/src/target.rs",
}

EXPECTED_SYS_TREES = ("ffi", "port", "src", "bindings/rust/dfc-core-sys")


def packaged_files(package: str) -> set[str]:
    result = subprocess.run(
        ["cargo", "package", "--package", package, "--list", "--allow-dirty"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return set(result.stdout.splitlines())


def tracked_sys_sources() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "--", *EXPECTED_SYS_TREES],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return set(result.stdout.splitlines())


class CargoPackageTests(unittest.TestCase):
    def test_sys_package_contains_only_publishable_sources(self) -> None:
        expected = EXPECTED_SYS_FILES | tracked_sys_sources()

        self.assertEqual(packaged_files("dfc-core-sys"), expected)


if __name__ == "__main__":
    unittest.main()
