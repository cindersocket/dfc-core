from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY_URL = "https://github.com/cindersocket/dfc-core/security/policy"
PACKAGE_READMES = (
    "bindings/android/README.md",
    "bindings/dotnet/README.md",
    "bindings/java/README.md",
    "bindings/python/README.md",
    "bindings/rust/README.md",
)


class SecurityPolicyTests(unittest.TestCase):
    def test_policy_and_private_reporting_link_stay_consistent(self) -> None:
        policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        config = (ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")
        advisory = "https://github.com/cindersocket/dfc-core/security/advisories/new"

        self.assertIn(advisory, policy)
        self.assertIn("cindersocket@protonmail.ch", policy)
        self.assertIn(f"url: {advisory}", config)
        self.assertIn("blank_issues_enabled: true", config)

    def test_supported_versions_match_release_metadata(self) -> None:
        policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        version = re.search(r"project\([^)]*VERSION ([0-9]+\.[0-9]+\.[0-9]+)", cmake, re.DOTALL)

        self.assertIsNotNone(version)
        current = version.group(1)
        heading = re.search(
            rf"^## {re.escape(current)} \((Unreleased|\d{{4}}-\d{{2}}-\d{{2}})\)$",
            changelog,
            re.MULTILINE,
        )
        self.assertIsNotNone(heading)
        released = heading.group(1) != "Unreleased"
        expected_rows = [
            (
                f"| {current.rsplit('.', 1)[0]}.x | Supported |"
                if released
                else f"| {current.rsplit('.', 1)[0]}.x (unreleased) | Development fixes |"
            ),
            (
                "| 1.2.x | Not supported |"
                if released
                else f"| 1.2.x | Supported until {current} is released |"
            ),
            "| Earlier releases | Not supported |",
        ]
        table_rows = [
            line
            for line in policy.splitlines()
            if line.startswith("| ") and not line.startswith("| ---")
        ]
        self.assertEqual(table_rows, ["| Version | Security support |", *expected_rows])

    def test_packaged_bindings_link_to_private_reporting_policy(self) -> None:
        for relative in PACKAGE_READMES:
            with self.subTest(readme=relative):
                readme = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(POLICY_URL, readme)

        pyproject = (ROOT / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'Security = "{POLICY_URL}"', pyproject)

        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        safe_cargo = (ROOT / "bindings/rust/dfc-core/Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('readme = "bindings/rust/README.md"', cargo)
        self.assertIn('"/bindings/rust/README.md"', cargo)
        self.assertIn('readme = "../README.md"', safe_cargo)

        project = (ROOT / "bindings/dotnet/src/Dfc/Dfc.csproj").read_text(encoding="utf-8")
        self.assertIn("<PackageReadmeFile>README.md</PackageReadmeFile>", project)
        self.assertIn(
            "<RepositoryUrl>https://github.com/cindersocket/dfc-core</RepositoryUrl>", project
        )


if __name__ == "__main__":
    unittest.main()
