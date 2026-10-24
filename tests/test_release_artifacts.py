#!/usr/bin/env python3
"""Tests for source release archive inspection."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "check_release_artifacts", ROOT / "scripts/check-release-artifacts.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ReleaseArtifactTests(unittest.TestCase):
    def archives(
        self, changed_zip: str | None = None
    ) -> tuple[Path, Path, tempfile.TemporaryDirectory]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        tar_path = root / "dfc-core-2.0.0.tar.gz"
        zip_path = root / "dfc-core-2.0.0.zip"
        prefix = "dfc-core-2.0.0"
        files = {name: f"content:{name}".encode() for name in CHECK.REQUIRED_FILES}
        with tarfile.open(tar_path, "w:gz") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.mode = 0o775 if name.endswith("gradlew") else 0o664
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        with zipfile.ZipFile(zip_path, "w") as archive:
            for name, content in files.items():
                info = zipfile.ZipInfo(f"{prefix}/{name}")
                if name.endswith("gradlew"):
                    info.create_system = 3
                    info.external_attr = 0o755 << 16
                else:
                    info.create_system = 0
                    info.external_attr = 0
                archive.writestr(info, changed_zip.encode() if name == changed_zip else content)
        return tar_path, zip_path, temporary

    def test_accepts_matching_complete_archives(self) -> None:
        tar_path, zip_path, temporary = self.archives()
        self.addCleanup(temporary.cleanup)
        CHECK.inspect_archives("2.0.0", tar_path, zip_path)

    def test_rejects_archives_with_different_content(self) -> None:
        changed = CHECK.REQUIRED_FILES[0]
        tar_path, zip_path, temporary = self.archives(changed)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValueError, "source archives differ"):
            CHECK.inspect_archives("2.0.0", tar_path, zip_path)

    def test_rejects_members_outside_versioned_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsafe or unexpected"):
            CHECK.safe_relative("dfc-core-2.0.0/../escape", "dfc-core-2.0.0")

    def test_actual_git_archives_preserve_executable_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            files = (*CHECK.REQUIRED_FILES, "README.md")
            for name in files:
                path = repository / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"content:{name}\n", encoding="utf-8")
            (repository / "bindings/android/gradlew").chmod(0o755)
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            tree = subprocess.run(
                ["git", "write-tree"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            prefix = "dfc-core-2.0.0/"
            tar_path = repository / "dfc-core-2.0.0.tar.gz"
            zip_path = repository / "dfc-core-2.0.0.zip"
            subprocess.run(
                ["git", "archive", "--format=tar.gz", f"--prefix={prefix}", "-o", tar_path, tree],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "archive", "--format=zip", f"--prefix={prefix}", "-o", zip_path, tree],
                cwd=repository,
                check=True,
            )

            CHECK.inspect_archives("2.0.0", tar_path, zip_path)
            tar_files = CHECK.tar_contents(tar_path, prefix.rstrip("/"))
            zip_files = CHECK.zip_contents(zip_path, prefix.rstrip("/"))
            self.assertFalse(tar_files["README.md"][1])
            self.assertFalse(zip_files["README.md"][1])
            self.assertTrue(tar_files["bindings/android/gradlew"][1])
            self.assertTrue(zip_files["bindings/android/gradlew"][1])


if __name__ == "__main__":
    unittest.main()
