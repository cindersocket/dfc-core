"""Validate the public DESFire conformance-vector corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VECTOR_ROOT = ROOT / "vectors" / "desfire"
MANIFEST = VECTOR_ROOT / "manifest.json"
VOCABULARY = VECTOR_ROOT / "vector-vocabulary.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vector_paths() -> list[Path]:
    return sorted(VECTOR_ROOT.glob("v[0-9]/*/*.vec"))


def validate_vector(path: Path, vocabulary: dict[str, object]) -> tuple[str, int, bool]:
    headers = set(vocabulary["headers"])
    steps = set(vocabulary["steps"])
    dialects = set(vocabulary["dialects"])
    values: dict[str, str] = {}
    step_count = 0
    saw_step = False
    saw_provenance = False

    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if line.startswith("# PROVENANCE:"):
            saw_provenance = True
        if not line or line.startswith("#"):
            continue
        location = f"{path.relative_to(ROOT)}:{number}"
        if not saw_step and ":" in line:
            key, value = (part.strip() for part in line.split(":", 1))
            if key not in headers:
                raise ValueError(f"{location}: unknown header {key!r}")
            if not value:
                raise ValueError(f"{location}: empty header {key!r}")
            if key in values and key in {"name", "origin", "source", "case-id", "feature-version"}:
                raise ValueError(f"{location}: duplicate header {key!r}")
            values[key] = value
            continue

        saw_step = True
        words = line.split()
        if words[0] not in steps:
            raise ValueError(f"{location}: unknown step {words[0]!r}")
        if words[0] == "exchange" and (
            len(words) < 4 or words[1] not in dialects or "=>" not in words
        ):
            raise ValueError(f"{location}: malformed exchange")
        if words[0] == "frame-exchange" and (len(words) < 3 or "=>" not in words):
            raise ValueError(f"{location}: malformed frame exchange")
        step_count += 1

    for required in ("name", "origin"):
        if required not in values:
            raise ValueError(f"{path.relative_to(ROOT)}: missing {required} header")
    if "source" not in values and not saw_provenance:
        raise ValueError(f"{path.relative_to(ROOT)}: missing source provenance")
    if values["origin"] not in {"physical-card", "synthetic"}:
        raise ValueError(f"{path.relative_to(ROOT)}: invalid origin")
    version = int(path.relative_to(VECTOR_ROOT).parts[0][1:])
    if int(values.get("feature-version", version)) > version:
        raise ValueError(f"{path.relative_to(ROOT)}: feature-version exceeds directory version")
    replayable = values.get("replayable", "true") != "false"
    if replayable and not saw_step:
        raise ValueError(f"{path.relative_to(ROOT)}: replayable vector has no steps")
    return values["name"], step_count, replayable


def build_manifest() -> dict[str, object]:
    return {
        "schema": 1,
        "files": [
            {
                "path": path.relative_to(VECTOR_ROOT).as_posix(),
                "sha256": digest(path),
                "size": path.stat().st_size,
            }
            for path in vector_paths()
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    vocabulary = json.loads(VOCABULARY.read_text(encoding="utf-8"))
    names: dict[str, Path] = {}
    total_steps = 0
    replayable = 0
    try:
        for path in vector_paths():
            name, steps, can_replay = validate_vector(path, vocabulary)
            if name in names:
                raise ValueError(f"duplicate vector name {name!r}: {names[name]} and {path}")
            names[name] = path
            if can_replay:
                replayable += 1
                total_steps += steps
        expected = build_manifest()
        if args.write_manifest:
            MANIFEST.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        elif json.loads(MANIFEST.read_text(encoding="utf-8")) != expected:
            raise ValueError("manifest does not match the vector corpus")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"DESFire vector check failed: {error}", file=sys.stderr)
        return 1
    print(f"DESFire vectors: {len(names)} files, {replayable} replayable, {total_steps} steps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
