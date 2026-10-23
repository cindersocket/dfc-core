#!/usr/bin/env python3
"""Require release metadata to use one project version."""

from __future__ import annotations

import re
import tomllib
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def changelog_version(changelog: str, expected: str) -> str | None:
    """Return the matching version for an unreleased or dated top entry."""
    heading = re.search(r"^## (.+)$", changelog, re.MULTILINE)
    if heading is None:
        return None

    match = re.fullmatch(
        r"([0-9]+\.[0-9]+\.[0-9]+) \((Unreleased|[0-9]{4}-[0-9]{2}-[0-9]{2})\)",
        heading.group(1),
    )
    if match is None or match.group(1) != expected:
        return None
    if match.group(2) != "Unreleased":
        try:
            date.fromisoformat(match.group(2))
        except ValueError:
            return None
    return expected


def read_toml(path: str) -> dict[str, Any]:
    with (ROOT / path).open("rb") as source:
        return tomllib.load(source)


def package_versions(path: str, *names: str) -> list[tuple[str, str | None]]:
    packages = read_toml(path)["package"]
    by_name = {package["name"]: package["version"] for package in packages}
    return [(f"{path}:{name}", by_name.get(name)) for name in names]


def main() -> None:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"project\(dfc-core VERSION ([0-9]+\.[0-9]+\.[0-9]+) LANGUAGES C\)", cmake)
    if match is None:
        raise SystemExit("CMakeLists.txt: missing dfc-core project version")
    expected = match.group(1)

    cargo = read_toml("Cargo.toml")
    rust = read_toml("bindings/rust/dfc-core/Cargo.toml")
    python = read_toml("bindings/python/pyproject.toml")
    dotnet = ET.parse(ROOT / "bindings/dotnet/src/Dfc/Dfc.csproj").getroot()
    dotnet_version = dotnet.findtext("./PropertyGroup/Version")

    versions = [
        ("Cargo.toml workspace", cargo["workspace"]["package"]["version"]),
        ("dfc-core Rust dependency", rust["dependencies"]["dfc-core-sys"]["version"]),
        ("Python project", python["project"]["version"]),
        (".NET package", dotnet_version),
        *package_versions("Cargo.lock", "dfc-core", "dfc-core-sys"),
        *package_versions("examples/rust-virtual-picc/Cargo.lock", "dfc-core", "dfc-core-sys"),
        *package_versions("bindings/python/uv.lock", "dfc-core"),
    ]

    readme = (ROOT / "bindings/rust/README.md").read_text(encoding="utf-8")
    documented = re.findall(r'dfc-core = (?:"([^"]+)"|\{ version = "([^"]+)")', readme)
    if not documented:
        versions.append(("Rust README dependency examples", None))
    else:
        versions.extend(
            (f"Rust README dependency example {index}", direct or table)
            for index, (direct, table) in enumerate(documented, 1)
        )

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    versions.append(
        (
            "CHANGELOG.md release heading",
            changelog_version(changelog, expected),
        )
    )

    mismatches = [
        f"{name}: expected {expected}, found {actual or 'missing'}"
        for name, actual in versions
        if actual != expected
    ]
    if mismatches:
        raise SystemExit("inconsistent release metadata:\n" + "\n".join(mismatches))


if __name__ == "__main__":
    main()
