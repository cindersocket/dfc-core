#!/usr/bin/env python3
"""Validate the complete release artifact contract against package metadata."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "release-artifacts.json"
REQUIRED_IDS = {
    "source",
    "native",
    "python",
    "rust-sys",
    "rust",
    "java",
    "jni",
    "android",
    "dotnet",
    "checksums",
}
REQUIRED_NATIVE_TARGETS = {
    "linux-x64",
    "linux-arm64",
    "osx-x64",
    "osx-arm64",
    "win-x64",
    "win-arm64",
}


def cmake_version() -> str:
    text = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"project\(dfc-core VERSION ([0-9]+\.[0-9]+\.[0-9]+)", text)
    if not match:
        raise ValueError("CMakeLists.txt does not declare the project version")
    return match.group(1)


def metadata_versions() -> dict[str, str]:
    python = tomllib.loads((ROOT / "bindings/python/pyproject.toml").read_text())
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    dotnet = ET.parse(ROOT / "bindings/dotnet/src/Dfc/Dfc.csproj").getroot()
    dotnet_version = dotnet.findtext(".//Version")
    if dotnet_version is None:
        raise ValueError("NuGet project does not declare Version")
    return {
        "python": python["project"]["version"],
        "rust": cargo["workspace"]["package"]["version"],
        "dotnet": dotnet_version,
    }


def validate() -> dict[str, object]:
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError("unsupported release inventory schema")
    version = cmake_version()
    if document.get("version") != version:
        raise ValueError("release inventory version differs from CMake")
    mismatches = {
        name: value for name, value in metadata_versions().items() if value != version
    }
    if mismatches:
        raise ValueError(f"package versions differ from {version}: {mismatches}")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("artifacts must be a list")
    ids = [entry.get("id") for entry in artifacts if isinstance(entry, dict)]
    if len(ids) != len(set(ids)):
        raise ValueError("release artifact ids must be unique")
    if set(ids) != REQUIRED_IDS:
        raise ValueError(f"release artifact ids differ: {set(ids) ^ REQUIRED_IDS}")
    for entry in artifacts:
        for field in ("id", "ecosystem", "package", "files"):
            if not entry.get(field):
                raise ValueError(f"{entry.get('id', '<unknown>')} lacks {field}")
        if entry["id"] != "checksums" and not all(
            "{version}" in pattern for pattern in entry["files"]
        ):
            raise ValueError(f"{entry['id']} has an unversioned file pattern")
    native = next(entry for entry in artifacts if entry["id"] == "native")
    if set(native["targets"]) != REQUIRED_NATIVE_TARGETS:
        raise ValueError("native target matrix is incomplete")
    jni = next(entry for entry in artifacts if entry["id"] == "jni")
    if len(jni["targets"]) != len(set(jni["targets"])) or len(jni["targets"]) != 6:
        raise ValueError("JNI classifier matrix must contain six unique targets")
    return document


def verify_files(document: dict[str, object], directory: Path) -> None:
    artifacts = document["artifacts"]
    assert isinstance(artifacts, list)
    patterns: list[str] = []
    version = str(document["version"])
    for entry in artifacts:
        assert isinstance(entry, dict)
        files = entry["files"]
        assert isinstance(files, list)
        for pattern in files:
            rendered = str(pattern).replace("{version}", version)
            placeholder = "{rid}" if "{rid}" in rendered else "{classifier}"
            if placeholder in rendered:
                targets = entry.get("targets")
                assert isinstance(targets, list)
                patterns.extend(
                    rendered.replace(placeholder, str(target)) for target in targets
                )
            else:
                patterns.append(rendered)

    actual = [path.name for path in directory.iterdir() if path.is_file()]
    if len(actual) != len(set(actual)):
        raise ValueError("release artifact basenames must be unique")
    missing = [
        pattern
        for pattern in patterns
        if not any(fnmatch.fnmatch(name, pattern) for name in actual)
    ]
    extra = [
        name
        for name in actual
        if not any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
    ]
    if missing or extra:
        raise ValueError(f"release files differ: missing={missing}, extra={extra}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    try:
        document = validate()
        if args.directory is not None:
            verify_files(document, args.directory)
    except (
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        ET.ParseError,
    ) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
