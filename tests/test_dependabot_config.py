from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / ".github/dependabot.yml"

EXPECTED = {
    ("cargo", "/"),
    ("cargo", "/examples/rust-virtual-picc"),
    ("uv", "/bindings/python"),
    ("gradle", "/bindings/android"),
    ("gradle", "/examples/android"),
    ("nuget", "/bindings/dotnet"),
    ("nuget", "/examples/dotnet"),
    ("github-actions", "/"),
}

IGNORED_PARTS = {
    ".git",
    ".gradle",
    ".release-build",
    ".worktrees",
    "bin",
    "build",
    "node_modules",
    "obj",
    "target",
}


def scalar(value: str) -> object:
    if value.startswith('"'):
        return json.loads(value)
    if value.isdecimal():
        return int(value)
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip('"') for item in value[1:-1].split(",") if item.strip()]
    return value


def mapping(lines: list[str], index: int, indent: int) -> tuple[dict[str, object], int]:
    result: dict[str, object] = {}
    while index < len(lines):
        line = lines[index]
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent < indent:
            break
        if current_indent != indent or line.lstrip().startswith("-"):
            raise AssertionError(f"invalid indentation at line {index + 1}")
        key, separator, value = line.strip().partition(":")
        if not separator or not key or key in result:
            raise AssertionError(f"invalid or duplicate key at line {index + 1}")
        index += 1
        if value.strip():
            result[key] = scalar(value.strip())
        else:
            child, index = mapping(lines, index, indent + 2)
            if not child:
                raise AssertionError(f"empty mapping for {key}")
            result[key] = child
    return result, index


def load_config() -> dict[str, object]:
    lines = [
        line.rstrip()
        for line in CONFIG.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(lines) < 3 or lines[0] != "version: 2" or lines[1] != "updates:":
        raise AssertionError("dependabot.yml must start with version 2 and updates")

    updates: list[dict[str, object]] = []
    index = 2
    while index < len(lines):
        line = lines[index]
        if not line.startswith("  - "):
            raise AssertionError(f"expected update entry at line {index + 1}")
        key, separator, value = line[4:].partition(":")
        if not separator or not key or not value.strip():
            raise AssertionError(f"invalid update entry at line {index + 1}")
        entry: dict[str, object] = {key: scalar(value.strip())}
        remainder, index = mapping(lines, index + 1, 4)
        if key in remainder:
            raise AssertionError(f"duplicate update key: {key}")
        entry.update(remainder)
        updates.append(entry)
    return {"version": 2, "updates": updates}


def manifest_owner(path: Path) -> tuple[str, str] | None:
    relative = path.relative_to(ROOT).as_posix()
    name = path.name

    if relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
        return ("github-actions", "/")

    if name in {"Cargo.toml", "Cargo.lock"}:
        if relative.startswith("examples/rust-virtual-picc/"):
            return ("cargo", "/examples/rust-virtual-picc")
        if relative in {
            "Cargo.toml",
            "Cargo.lock",
            "bindings/rust/dfc-core/Cargo.toml",
        }:
            return ("cargo", "/")
        return ("cargo", "/unowned")

    if name in {"pyproject.toml", "uv.lock"}:
        root = "/bindings/python" if relative.startswith("bindings/python/") else "/unowned"
        return ("uv", root)
    if (name.startswith("requirements") and name.endswith((".txt", ".in"))) or name in {
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "pdm.lock",
    }:
        return ("pip", "/unowned")

    gradle_names = {
        "build.gradle",
        "build.gradle.kts",
        "gradle.properties",
        "gradle-wrapper.properties",
        "libs.versions.toml",
        "settings.gradle",
        "settings.gradle.kts",
    }
    if name in gradle_names:
        if relative.startswith("bindings/android/"):
            return ("gradle", "/bindings/android")
        if relative.startswith("examples/android/"):
            return ("gradle", "/examples/android")
        return ("gradle", "/unowned")

    dotnet_names = {
        "Directory.Build.props",
        "Directory.Packages.props",
        "global.json",
        "packages.config",
        "packages.lock.json",
    }
    if name in dotnet_names or path.suffix in {".csproj", ".fsproj", ".sln", ".vbproj"}:
        if relative.startswith("bindings/dotnet/"):
            return ("nuget", "/bindings/dotnet")
        if relative.startswith("examples/dotnet/"):
            return ("nuget", "/examples/dotnet")
        return ("nuget", "/unowned")
    return None


class DependabotConfigTests(unittest.TestCase):
    def test_every_update_is_complete_and_unique(self) -> None:
        config = load_config()
        self.assertEqual(config["version"], 2)
        updates = config["updates"]
        self.assertIsInstance(updates, list)

        identities: list[tuple[str, str]] = []
        required = {
            "package-ecosystem",
            "directory",
            "schedule",
            "target-branch",
            "open-pull-requests-limit",
            "commit-message",
            "groups",
        }
        for update in updates:
            self.assertIsInstance(update, dict)
            self.assertEqual(set(update), required)
            identities.append((str(update["package-ecosystem"]), str(update["directory"])))
            self.assertEqual(
                update["schedule"],
                {
                    "interval": "weekly",
                    "day": "monday",
                    "time": "09:00",
                    "timezone": "America/Los_Angeles",
                },
            )
            self.assertEqual(update["target-branch"], "master")
            self.assertEqual(update["open-pull-requests-limit"], 5)
            self.assertEqual(update["commit-message"], {"prefix": "deps", "include": "scope"})
            self.assertEqual(
                update["groups"],
                {
                    "compatible-updates": {
                        "patterns": ["*"],
                        "update-types": ["minor", "patch"],
                    }
                },
            )

        self.assertEqual(set(identities), EXPECTED)
        self.assertEqual(len(identities), len(set(identities)))

    def test_every_dependency_manifest_has_exactly_one_owner(self) -> None:
        updates = {
            (str(update["package-ecosystem"]), str(update["directory"]))
            for update in load_config()["updates"]
        }
        discovered: dict[str, tuple[str, str]] = {}
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(part in IGNORED_PARTS for part in path.parts):
                continue
            owner = manifest_owner(path)
            if owner is None:
                continue
            relative = path.relative_to(ROOT).as_posix()
            discovered[relative] = owner
            self.assertIn(owner, updates, f"{relative} has no Dependabot update owner")

        required = {
            "Cargo.toml",
            "Cargo.lock",
            "bindings/python/pyproject.toml",
            "bindings/python/uv.lock",
            "bindings/android/build.gradle.kts",
            "bindings/android/gradle/wrapper/gradle-wrapper.properties",
            "bindings/dotnet/Directory.Build.props",
            "examples/dotnet/Dfc.TransceiveExample.csproj",
            ".github/workflows/ci.yml",
        }
        self.assertTrue(required <= set(discovered))


if __name__ == "__main__":
    unittest.main()
