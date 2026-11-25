#!/usr/bin/env python3
"""Keep the manual release checklist complete and reproducible."""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from os import environ
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
            "python3 tests/test_binding_documentation_ci.py",
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

    def test_android_archive_smoke_retries_the_shared_ndk_version(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        gradle_properties = (ROOT / "bindings/android/gradle.properties").read_text(
            encoding="utf-8"
        )
        android_build = (ROOT / "bindings/android/dfc/build.gradle.kts").read_text(encoding="utf-8")

        installer = (ROOT / "scripts/install-android-ndk.sh").read_text(encoding="utf-8")

        self.assertRegex(gradle_properties, r"(?m)^dfc\.ndkVersion=\d+(?:\.\d+)+$")
        self.assertIn('providers.gradleProperty("dfc.ndkVersion").get()', android_build)
        self.assertEqual(workflow.count("./scripts/install-android-ndk.sh"), 2)
        self.assertIn("if: matrix.entry_point == 'android'", workflow)
        self.assertIn("max_attempts=3", installer)
        self.assertIn('rm -rf "$ANDROID_SDK_ROOT/ndk/$ndk_version"', installer)

    def test_android_ndk_installer_retries_after_scoped_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "sdk"
            partial = sdk / "ndk" / "28.2.13676358"
            partial.mkdir(parents=True)
            (partial / "partial-download").touch()
            attempts = root / "attempts"
            fake_sdkmanager = sdk / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
            fake_sdkmanager.parent.mkdir(parents=True)
            fake_sdkmanager.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                '[[ -f "$SDKMANAGER_ATTEMPTS" ]] && count="$(cat "$SDKMANAGER_ATTEMPTS")"\n'
                "count=$((count + 1))\n"
                'printf "%s" "$count" > "$SDKMANAGER_ATTEMPTS"\n'
                '[[ "$count" -ge 2 ]]\n',
                encoding="utf-8",
            )
            fake_sdkmanager.chmod(0o755)
            environment = environ.copy()
            environment.update(
                {
                    "ANDROID_SDK_ROOT": str(sdk),
                    "SDKMANAGER_ATTEMPTS": str(attempts),
                }
            )

            subprocess.run(
                [str(ROOT / "scripts/install-android-ndk.sh")],
                check=True,
                env=environment,
            )

            self.assertEqual(attempts.read_text(encoding="utf-8"), "2")
            self.assertFalse(partial.exists())

    def test_release_consumers_use_portable_install_locations(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        native = (ROOT / "bindings/python/src/dfc_core/_native.py").read_text(encoding="utf-8")
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('root="$PWD/stage/dfc-core-native-', workflow)
        self.assertIn('PATH="$root/bin:$PATH" ctest', workflow)
        self.assertIn("CIBW_ARCHS_WINDOWS: AMD64", workflow)
        self.assertIn("wheel_pattern='*cp312*win_amd64.whl'", workflow)
        self.assertIn('("libdfc.dll", "dfc.dll")', native)
        self.assertIn('package_path / "bin" / name', native)
        self.assertIn('package_path / "lib64" / name', native)
        self.assertIn('package_path.parent / "bin" / name', native)
        self.assertIn('package_path.parent / "lib64" / name', native)
        self.assertIn("*.dfc text eol=lf", attributes.splitlines())
        self.assertIn('CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded', cmake)

    def test_rust_package_owns_its_test_fixtures(self) -> None:
        fixture_dir = ROOT / "bindings/rust/dfc-core/tests/fixtures"
        fixtures = {
            "authentication-boundaries.txt": ROOT / "tests/authentication-boundaries.txt",
            "v6-minimal.dfcb": ROOT / "examples/credentials/v6-minimal.dfcb",
            "v6-minimal.dfc": ROOT / "examples/credentials/v6-minimal.dfc",
            "v6-maximal.dfcb": ROOT / "examples/credentials/v6-maximal.dfcb",
            "v6-maximal.dfc": ROOT / "examples/credentials/v6-maximal.dfc",
            "v6-auth-commands.dfcb": ROOT / "examples/credentials/v6-auth-commands.dfcb",
            "command-constructor-vectors.txt": ROOT / "tests/command-constructor-vectors.txt",
            "command-constructor-boundaries.txt": ROOT / "tests/command-constructor-boundaries.txt",
            "iso7816-helper-vectors.txt": ROOT / "tests/iso7816-helper-vectors.txt",
        }
        for name, canonical in fixtures.items():
            with self.subTest(fixture=name):
                self.assertEqual((fixture_dir / name).read_bytes(), canonical.read_bytes())

        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "bindings/rust/dfc-core/src").glob("*.rs")
        )
        self.assertNotIn("../../../../examples/", sources)
        self.assertNotIn("../../../../tests/", sources)

        manifest = (ROOT / "bindings/rust/dfc-core/Cargo.toml").read_text(encoding="utf-8")
        # Both tests read files outside the package (the generated bindings, the committed
        # replay plans), so neither may ship in the published crate.
        self.assertIn(
            'exclude = ["tests/generated_bindings.rs", "tests/replay_plans.rs"]', manifest
        )


if __name__ == "__main__":
    unittest.main()
