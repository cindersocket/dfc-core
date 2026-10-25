#!/usr/bin/env python3
"""Keep the manual release checklist complete and reproducible."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ReleaseProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guide = (ROOT / "RELEASING.md").read_text(encoding="utf-8")

    def test_requires_the_repository_validation_gates(self) -> None:
        required = (
            "./scripts/check-format.sh",
            "python3 tests/test_check_docs.py",
            "python3 tests/test_check_stack_usage.py",
            "python3 tests/test_ci_unit_workflow.py",
            "python3 tests/test_check_version.py",
            "python3 tests/test_release_process.py",
            "python3 scripts/check-docs.py",
            "python3 scripts/check-version.py",
            'TINY_CRYPTO_DIR="$PWD/dependencies/tiny-crypto-c" python3 scripts/check-cmake-pic.py',
            (
                'TINY_CRYPTO_DIR="$PWD/dependencies/tiny-crypto-c" '
                "./scripts/check-embedded-footprint.sh"
            ),
            "make -C tests test CRYPTO_BACKEND=mbedtls",
            "make -C tests test CRYPTO_BACKEND=tiny",
            "SANITIZE=address,undefined",
            "SANITIZE=memory CC=clang",
            "RELEASE=1",
            "cargo test --workspace",
            "dotnet test bindings/dotnet/Dfc.sln -c Release",
        )
        for command in required:
            with self.subTest(command=command):
                self.assertIn(command, self.guide)

    def test_requires_every_ci_job(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        jobs_section = workflow.split("\njobs:\n", 1)[1]
        workflow_jobs = set(re.findall(r"^  ([a-z][a-z0-9-]*):$", jobs_section, re.MULTILINE))
        documented = re.search(
            r"Required CI jobs \(exact IDs\):\n\n((?:- `[a-z][a-z0-9-]*`\n)+)",
            self.guide,
        )
        self.assertIsNotNone(documented)
        documented_jobs = set(re.findall(r"^- `([^`]+)`$", documented.group(1), re.MULTILINE))
        self.assertEqual(documented_jobs, workflow_jobs)

    def test_uses_the_cmake_dependency_pin_for_immutable_checkout(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        pin = re.search(r"GIT_TAG ([0-9a-f]{40})", cmake)
        self.assertIsNotNone(pin)
        revision = pin.group(1)
        required = (
            f"tiny_crypto_revision={revision}",
            "git init dependencies/tiny-crypto-c",
            (
                "git -C dependencies/tiny-crypto-c remote add origin "
                "https://github.com/mistial-dev/tiny-crypto-c.git"
            ),
            'git -C dependencies/tiny-crypto-c fetch --depth=1 origin "$tiny_crypto_revision"',
            'git -C dependencies/tiny-crypto-c checkout --detach "$tiny_crypto_revision"',
            'test "$(git -C dependencies/tiny-crypto-c rev-parse HEAD)" = "$tiny_crypto_revision"',
        )
        for command in required:
            with self.subTest(command=command):
                self.assertIn(command, self.guide)

    def test_creates_notes_from_the_reviewed_changelog_section(self) -> None:
        command = 'python3 scripts/release-notes.py "$version" > release-notes.md'
        self.assertIn(command, self.guide)
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/release-notes.py"), "2.0.0"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("- Add Java and Android JNI bindings", result.stdout)

    def test_requires_signed_tag_source_artifacts_and_github_release(self) -> None:
        required = (
            "git tag -s -a",
            "git tag -v",
            "git archive",
            "python3 scripts/checksums.py create",
            "python3 scripts/checksums.py check",
            "gh workflow run release.yml",
            "publish=true",
            "complete verified artifact bundle",
        )
        for text in required:
            with self.subTest(text=text):
                self.assertIn(text, self.guide)

    def test_defines_the_complete_distribution_policy(self) -> None:
        published = (
            "dfc-core-$version.tar.gz",
            "dfc-core-$version.zip",
            "SHA256SUMS",
        )
        package_outputs = (
            "native libraries",
            "Android AAR",
            "NuGet package",
            "Python wheel",
            "Java/JNI",
            "Rust crates",
        )
        for artifact in published + package_outputs:
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, self.guide)
        self.assertIn("release-artifacts.json", self.guide)
        self.assertIn("PyPI, NuGet, and crates.io use trusted publishing", self.guide)

    def test_requires_archive_inspection_and_source_entry_point_smokes(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        required = (
            "python3 scripts/check-release-artifacts.py inspect",
            "python3 scripts/check-release-artifacts.py smoke",
            "source-archives",
        )
        for text in required:
            with self.subTest(text=text):
                self.assertIn(text, self.guide + workflow)


if __name__ == "__main__":
    unittest.main()
