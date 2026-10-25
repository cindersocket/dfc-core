from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "dependency-inventory.json"
WORKFLOW = ROOT / ".github/workflows/dependency-graph.yml"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"


def repository_manifests() -> set[str]:
    exact_names = {
        "Cargo.lock",
        "Cargo.toml",
        "CMakeLists.txt",
        "Directory.Build.props",
        "Directory.Packages.props",
        "Pipfile",
        "Pipfile.lock",
        "gradle-wrapper.properties",
        "gradle.properties",
        "packages.lock.json",
        "poetry.lock",
        "pyproject.toml",
        "uv.lock",
    }
    ignored_parts = {
        ".git",
        ".cxx",
        ".venv",
        ".worktrees",
        "build",
        "dist",
        "node_modules",
        "target",
    }
    found: set[str] = set()
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if not path.is_file() or ignored_parts.intersection(relative.parts):
            continue
        is_workflow = relative.parts[:2] == (
            ".github",
            "workflows",
        ) and path.suffix in {
            ".yml",
            ".yaml",
        }
        is_manifest = (
            path.name in exact_names
            or (path.name.startswith("requirements") and path.suffix == ".txt")
            or path.suffix in {".csproj", ".gradle"}
            or path.name.endswith(".gradle.kts")
        )
        if is_workflow or is_manifest:
            found.add(relative.as_posix())
    return found


def workflow_files() -> list[Path]:
    root = ROOT / ".github/workflows"
    return sorted((*root.glob("*.yml"), *root.glob("*.yaml")))


class DependencyGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    def test_every_manifest_has_one_inventory_owner(self) -> None:
        owners: dict[str, list[str]] = {}
        for surface in self.inventory["surfaces"]:
            for manifest in surface["manifests"]:
                owners.setdefault(manifest, []).append(surface["id"])

        expected = repository_manifests()
        self.assertEqual(set(owners), expected)
        self.assertEqual(
            [], [f"{path}: {ids}" for path, ids in owners.items() if len(ids) != 1]
        )

    def test_ingestion_contracts_are_complete(self) -> None:
        valid = {"manifest", "dependency-submission", "not-applicable"}
        identifiers = set()
        for surface in self.inventory["surfaces"]:
            with self.subTest(surface=surface["id"]):
                self.assertNotIn(surface["id"], identifiers)
                identifiers.add(surface["id"])
                self.assertIn(surface["ingestion"], valid)
                for manifest in surface["manifests"]:
                    self.assertTrue((ROOT / manifest).is_file(), manifest)
                if surface["ingestion"] == "dependency-submission":
                    self.assertEqual(
                        surface["workflow"], ".github/workflows/dependency-graph.yml"
                    )
                if surface["ingestion"] == "not-applicable":
                    self.assertTrue(surface.get("notes"))

    def test_submission_workflow_is_pinned_and_least_privilege(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        trigger = text[text.index("on:\n") : text.index("\n\npermissions:")]
        self.assertEqual(
            trigger,
            "on:\n  push:\n    branches: [master]\n  workflow_dispatch:",
        )
        permissions = text[
            text.index("permissions:\n") : text.index("\n\nconcurrency:")
        ]
        self.assertEqual(permissions, "permissions:\n  contents: write")
        self.assertEqual(text.count("\npermissions:\n"), 1)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("permissions: write-all", text)
        uses = re.findall(r"^\s*- uses:\s*([^\s#]+)", text, re.MULTILINE)
        self.assertGreaterEqual(len(uses), 3)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_each_dependency_submitter_is_unique(self) -> None:
        workflows = "\n".join(
            path.read_text(encoding="utf-8") for path in workflow_files()
        )
        self.assertEqual(workflows.count("native-dependency-snapshot.py --submit"), 1)
        self.assertEqual(workflows.count("gradle/actions/dependency-submission@"), 1)
        self.assertEqual(workflows.count("dependency-graph: generate-and-submit"), 1)

    def test_inventory_check_runs_in_pull_request_ci(self) -> None:
        text = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("python3 tests/test_dependency_graph.py", text)

    def test_native_snapshot_tracks_the_cmake_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "snapshot.json"
            subprocess.run(
                [
                    "python3",
                    "scripts/native-dependency-snapshot.py",
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                check=True,
            )
            snapshot = json.loads(output.read_text(encoding="utf-8"))
        manifest = snapshot["manifests"]["CMakeLists.txt"]
        resolved = next(iter(manifest["resolved"].values()))
        self.assertRegex(
            resolved["package_url"],
            r"^pkg:github/mistial-dev/tiny-crypto-c@[0-9a-f]{40}$",
        )
        self.assertEqual(resolved["relationship"], "direct")
        self.assertEqual(resolved["scope"], "runtime")

    def test_native_snapshot_identity_replaces_prior_run(self) -> None:
        script = ROOT / "scripts/native-dependency-snapshot.py"

        def generate(run_id: str, run_attempt: str) -> dict[str, object]:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "snapshot.json"
                env = {
                    **os.environ,
                    "GITHUB_RUN_ID": run_id,
                    "GITHUB_RUN_ATTEMPT": run_attempt,
                }
                subprocess.run(
                    ["python3", str(script), "--output", str(output)],
                    cwd=ROOT,
                    env=env,
                    check=True,
                )
                return json.loads(output.read_text(encoding="utf-8"))

        first = generate("100", "1")["job"]
        rerun = generate("100", "2")["job"]
        later = generate("101", "1")["job"]
        self.assertEqual(first["correlator"], rerun["correlator"])
        self.assertEqual(first["correlator"], later["correlator"])
        self.assertEqual(3, len({first["id"], rerun["id"], later["id"]}))


if __name__ == "__main__":
    unittest.main()
