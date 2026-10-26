#!/usr/bin/env python3
"""Generate or submit dfc-core's resolved native dependency snapshot."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tiny_revision() -> str:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(
        r"GIT_REPOSITORY\s+https://github\.com/mistial-dev/tiny-crypto-c\.git\s+"
        r"GIT_TAG\s+([0-9a-f]{40})",
        cmake,
    )
    if match is None:
        raise ValueError("cannot find the pinned tiny-crypto-c revision")
    return match.group(1)


def snapshot(
    repository: str,
    commit: str,
    ref: str,
    run_id: str,
    run_attempt: str,
    scanned: str,
) -> dict[str, object]:
    revision = tiny_revision()
    package_url = f"pkg:github/mistial-dev/tiny-crypto-c@{revision}"
    return {
        "version": 0,
        "sha": commit,
        "ref": ref,
        "scanned": scanned,
        "job": {
            # GitHub replaces the previous snapshot for this stable job identity.
            "correlator": "dfc-core-native-cmake",
            # Keep individual submissions distinguishable, including reruns.
            "id": f"native-cmake-{run_id}-{run_attempt}",
        },
        "detector": {
            "name": "dfc-core native dependency inventory",
            "version": "1",
            "url": f"https://github.com/{repository}/blob/{commit}/scripts/native-dependency-snapshot.py",
        },
        "manifests": {
            "CMakeLists.txt": {
                "name": "dfc-core native dependencies",
                "file": {"source_location": "CMakeLists.txt"},
                "resolved": {
                    package_url: {
                        "package_url": package_url,
                        "relationship": "direct",
                        "scope": "runtime",
                        "dependencies": [],
                    }
                },
            }
        },
    }


def submit(payload: dict[str, object], repository: str, token: str) -> None:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/dependency-graph/snapshots",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 201:
                raise RuntimeError(f"dependency submission returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"dependency submission returned HTTP {error.code}: {detail}") from error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--submit", action="store_true")
    args = parser.parse_args()

    repository = os.environ.get("GITHUB_REPOSITORY", "cindersocket/dfc-core")
    commit = os.environ.get("GITHUB_SHA", "0" * 40)
    ref = os.environ.get("GITHUB_REF", "refs/heads/local")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    scanned = os.environ.get("DFC_DEPENDENCY_SCANNED_AT") or datetime.datetime.now(
        datetime.UTC
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    payload = snapshot(repository, commit, ref, run_id, run_attempt, scanned)

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    if args.submit:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise SystemExit("GITHUB_TOKEN is required with --submit")
        submit(payload, repository, token)


if __name__ == "__main__":
    main()
