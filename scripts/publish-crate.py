#!/usr/bin/env python3
"""Upload one already-verified .crate archive without repackaging it."""

from __future__ import annotations

import argparse
import json
import os
import struct
import tarfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def dependency(
    name: str, value: str | dict[str, Any], kind: str, target: str | None
) -> dict[str, Any]:
    details = {"version": value} if isinstance(value, str) else value
    return {
        "name": details.get("package", name),
        "version_req": details.get("version", "*"),
        "features": details.get("features", []),
        "optional": details.get("optional", False),
        "default_features": details.get("default-features", True),
        "target": target,
        "kind": kind,
        "registry": details.get("registry"),
        "explicit_name_in_toml": name if details.get("package") else None,
    }


def metadata(archive: Path) -> dict[str, Any]:
    with tarfile.open(archive, "r:gz") as crate:
        manifest_name = next(
            name for name in crate.getnames() if name.endswith("/Cargo.toml")
        )
        archive_root = manifest_name.rsplit("/", 1)[0]
        member = crate.extractfile(manifest_name)
        if member is None:
            raise ValueError("crate lacks Cargo.toml")
        manifest = tomllib.loads(member.read().decode())
        readme_file = manifest["package"].get("readme")
        readme = None
        if readme_file:
            readme_member = crate.extractfile(f"{archive_root}/{readme_file}")
            if readme_member is None:
                raise ValueError(f"crate lacks declared readme: {readme_file}")
            readme = readme_member.read().decode()
    package = manifest["package"]
    declared_features = manifest.get("features", {})
    features2 = {
        name: values
        for name, values in declared_features.items()
        if any(value.startswith("dep:") or "?/" in value for value in values)
    }
    features = {
        name: values
        for name, values in declared_features.items()
        if name not in features2
    }
    dependencies: list[dict[str, Any]] = []
    for table, kind in (
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    ):
        dependencies.extend(
            dependency(name, value, kind, None)
            for name, value in manifest.get(table, {}).items()
        )
    for target, tables in manifest.get("target", {}).items():
        for table, kind in (
            ("dependencies", "normal"),
            ("dev-dependencies", "dev"),
            ("build-dependencies", "build"),
        ):
            dependencies.extend(
                dependency(name, value, kind, target)
                for name, value in tables.get(table, {}).items()
            )
    return {
        "name": package["name"],
        "vers": package["version"],
        "deps": dependencies,
        "features": features,
        "features2": features2,
        "authors": package.get("authors", []),
        "description": package.get("description"),
        "documentation": package.get("documentation"),
        "homepage": package.get("homepage"),
        "readme": readme,
        "readme_file": readme_file,
        "keywords": package.get("keywords", []),
        "categories": package.get("categories", []),
        "license": package.get("license"),
        "license_file": package.get("license-file"),
        "repository": package.get("repository"),
        "badges": manifest.get("badges", {}),
        "links": package.get("links"),
        "rust_version": package.get("rust-version"),
        "v": 2,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="validate metadata without uploading"
    )
    args = parser.parse_args()
    document = metadata(args.archive)
    if args.check:
        print(json.dumps(document, sort_keys=True))
        return
    token = os.environ.get("CARGO_REGISTRY_TOKEN")
    if not token:
        raise SystemExit("CARGO_REGISTRY_TOKEN is required")
    crate = args.archive.read_bytes()
    encoded = json.dumps(document, separators=(",", ":")).encode()
    body = (
        struct.pack("<I", len(encoded))
        + encoded
        + struct.pack("<I", len(crate))
        + crate
    )
    request = urllib.request.Request(
        "https://crates.io/api/v1/crates/new",
        data=body,
        method="PUT",
        headers={
            "Authorization": token,
            "Content-Type": "application/octet-stream",
            "User-Agent": "dfc-core-release/2.0",
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            if response.status not in (200, 201):
                raise SystemExit(f"crates.io returned HTTP {response.status}")
            payload = json.loads(response.read() or b"{}")
            if payload.get("errors"):
                raise SystemExit(f"crates.io rejected the crate: {payload['errors']}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise SystemExit(f"crates.io returned HTTP {error.code}: {detail}") from error


if __name__ == "__main__":
    main()
