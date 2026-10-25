#!/usr/bin/env python3
"""Regression tests for the machine-readable release artifact contract."""

from __future__ import annotations

import json
import re
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ReleaseInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads((ROOT / "release-artifacts.json").read_text())
        cls.workflow = (ROOT / ".github/workflows/release.yml").read_text()

    def test_inventory_validator_passes(self) -> None:
        subprocess.run(
            ["python3", str(ROOT / "scripts/check-release-inventory.py")], check=True
        )

    def test_artifact_directory_verification_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/check-release-inventory.py"),
                    "--directory",
                    directory,
                ],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing=", result.stderr)

    def test_complete_artifact_directory_is_accepted(self) -> None:
        files = (
            "dfc-core-2.0.0.tar.gz",
            "dfc-core-2.0.0.zip",
            *(
                f"dfc-core-native-{target}-2.0.0.zip"
                for target in (
                    "linux-x64",
                    "linux-arm64",
                    "osx-x64",
                    "osx-arm64",
                    "win-x64",
                    "win-arm64",
                )
            ),
            "dfc_core-2.0.0.tar.gz",
            "dfc_core-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl",
            "dfc_core-2.0.0-cp312-cp312-manylinux_2_17_aarch64.whl",
            "dfc_core-2.0.0-cp312-cp312-macosx_10_13_x86_64.whl",
            "dfc_core-2.0.0-cp312-cp312-macosx_11_0_arm64.whl",
            "dfc_core-2.0.0-cp312-cp312-win_amd64.whl",
            "dfc-core-sys-2.0.0.crate",
            "dfc-core-2.0.0.crate",
            "dfc-core-2.0.0.jar",
            "dfc-core-2.0.0-sources.jar",
            "dfc-core-2.0.0-javadoc.jar",
            "dfc-core-2.0.0.pom",
            *(
                f"dfc-core-2.0.0-{target}.jar"
                for target in (
                    "linux-x86_64",
                    "linux-aarch64",
                    "osx-x86_64",
                    "osx-aarch64",
                    "windows-x86_64",
                    "windows-aarch64",
                )
            ),
            "dfc-core-android-2.0.0.aar",
            "dfc-core-android-2.0.0-sources.jar",
            "dfc-core-android-2.0.0-javadoc.jar",
            "dfc-core-android-2.0.0.pom",
            "Dfc.2.0.0.nupkg",
            "Dfc.2.0.0.snupkg",
            "SHA256SUMS",
        )
        with tempfile.TemporaryDirectory() as directory:
            for name in files:
                (Path(directory) / name).touch()
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/check-release-inventory.py"),
                    "--directory",
                    directory,
                ],
                check=True,
            )

    def test_every_inventory_artifact_is_built_by_the_workflow(self) -> None:
        for artifact in self.inventory["artifacts"]:
            with self.subTest(artifact=artifact["id"]):
                self.assertIn(f"inventory:{artifact['id']}", self.workflow)

    def test_publish_requires_a_tag_and_explicit_switch(self) -> None:
        self.assertIn("refs/tags/v", self.workflow)
        self.assertIn("inputs.publish == true", self.workflow)
        self.assertIn("id-token: write", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertIn("bootstrap_crates:", self.workflow)
        self.assertIn("CARGO_BOOTSTRAP_TOKEN", self.workflow)
        self.assertIn(
            "needs: [validate, checksum, publish-pypi, publish-rust,", self.workflow
        )

    def test_release_actions_are_immutably_pinned(self) -> None:
        uses = re.findall(r"^\s*- uses: ([^\s#]+)", self.workflow, re.MULTILINE)
        self.assertGreater(len(uses), 10)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_packages_are_smoke_tested_before_publication(self) -> None:
        for command in (
            "twine check",
            "cargo publish --dry-run",
            "unzip -t",
            "jar tf",
            "checksum",
        ):
            with self.subTest(command=command):
                self.assertIn(command, self.workflow)

    def test_release_workflow_preserves_verified_artifacts(self) -> None:
        publisher = (ROOT / "scripts/publish-crates.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/publish-crate.py", publisher)
        self.assertNotIn("cargo publish --locked --package", self.workflow)
        self.assertIn("packages-dir: pypi", self.workflow)
        self.assertIn("verification.verified", self.workflow)
        self.assertIn("verify-nuget-layout.py", self.workflow)

    def test_rust_sys_package_contains_cmake_modules(self) -> None:
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('"/cmake/**"', manifest)
        self.assertIn('p["features2"]["bundled"] == ["dep:cmake"]', self.workflow)

    def test_python_release_uses_a_self_contained_stage(self) -> None:
        self.assertIn("stage-python-package.py", self.workflow)
        self.assertIn("package-dir: build/python-package", self.workflow)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/stage-python-package.py"),
                    str(package),
                ],
                check=True,
            )
            self.assertTrue((package / "native/CMakeLists.txt").is_file())
            self.assertTrue(
                (package / "native/cmake/dfc-core-config.cmake.in").is_file()
            )
            self.assertIn(
                'cmake.source-dir = "native"',
                (package / "pyproject.toml").read_text(encoding="utf-8"),
            )

    def test_android_inventory_excludes_repository_metadata(self) -> None:
        android = next(
            item for item in self.inventory["artifacts"] if item["id"] == "android"
        )
        self.assertNotIn("dfc-core-android-{version}.module", android["files"])
        self.assertIn("dfc-core-android-{version}-javadoc.jar", android["files"])

    def test_nuget_native_layout_is_exact(self) -> None:
        expected = {
            "linux-x64": "libdfc.so",
            "linux-arm64": "libdfc.so",
            "osx-x64": "libdfc.dylib",
            "osx-arm64": "libdfc.dylib",
            "win-x64": "libdfc.dll",
            "win-arm64": "libdfc.dll",
        }
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "Dfc.2.0.0.nupkg"
            with zipfile.ZipFile(package, "w") as archive:
                for rid, library in expected.items():
                    archive.writestr(f"runtimes/{rid}/native/{library}", b"")
            subprocess.run(
                ["python3", str(ROOT / "scripts/verify-nuget-layout.py"), str(package)],
                check=True,
            )
            with zipfile.ZipFile(package, "a") as archive:
                archive.writestr("runtimes/linux-x64/native/unexpected.so", b"")
            result = subprocess.run(
                ["python3", str(ROOT / "scripts/verify-nuget-layout.py"), str(package)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("extra=", result.stderr)

    def test_crate_publisher_uses_archive_metadata_and_readme(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sample-1.0.0"
            root.mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname="sample"\nversion="1.0.0"\n'
                'description="sample"\nlicense="MIT"\nreadme="README.md"\n'
                '[features]\ndefault=["bundled","ordinary"]\n'
                'bundled=["dep:cmake"]\nordinary=["feature-a"]\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text("# Packaged readme\n", encoding="utf-8")
            archive = Path(directory) / "sample-1.0.0.crate"
            with tarfile.open(archive, "w:gz") as crate:
                crate.add(root, arcname=root.name)
            result = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/publish-crate.py"),
                    "--check",
                    str(archive),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            metadata = json.loads(result.stdout)
            self.assertEqual(metadata["name"], "sample")
            self.assertEqual(metadata["readme"], "# Packaged readme\n")
            self.assertEqual(metadata["v"], 2)
            self.assertEqual(metadata["features2"], {"bundled": ["dep:cmake"]})
            self.assertNotIn("bundled", metadata["features"])
            self.assertEqual(metadata["features"]["ordinary"], ["feature-a"])
            self.assertEqual(metadata["features"]["default"], ["bundled", "ordinary"])


if __name__ == "__main__":
    unittest.main()
