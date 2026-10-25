"""Validate the public DESFire conformance-vector corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VECTOR_ROOT = ROOT / "vectors" / "desfire"
MANIFEST = VECTOR_ROOT / "manifest.json"
VOCABULARY = VECTOR_ROOT / "vector-vocabulary.json"
MAXIMUM_LINE_BYTES = 4095
HEX_HEADERS = {
    "delegated-default-key",
    "new-key",
    "picc-atqa",
    "picc-ats",
    "picc-auth-commands",
    "picc-dam-auth-key",
    "picc-dam-encryption-key",
    "picc-dam-mac-key",
    "picc-ev2-card-capabilities",
    "picc-hardware-version",
    "picc-key",
    "picc-key-settings-1",
    "picc-key-settings-2",
    "picc-key-version",
    "picc-proximity-bitrate",
    "picc-proximity-key",
    "picc-proximity-option",
    "picc-proximity-published-response-time",
    "picc-sak",
    "picc-software-version",
    "picc-static-signature",
    "uid",
    "vc-capabilities",
    "vc-iid",
    "vc-info",
    "vc-select-enc-key",
    "vc-select-mac-key",
    "vc-uid",
}
UNSIGNED_HEADERS = {
    "delegated-default-key-version",
    "feature-version",
    "new-key-version",
    "picc-format-disabled",
    "picc-key-len",
    "picc-random-id",
    "picc-storage",
    "target-key-number",
    "target-key-set",
    "target-key-set-version",
    "vc-auth-mandatory",
    "vc-pc-mandatory",
}
BYTE_ASSERTION_PATH = re.compile(
    r"(?:credential\.uid|apps\[\d+\]\.(?:aid|keys\[\d+\])|files\[\d+\]\.data|"
    r"session\.(?:transaction_identifier|command_counter|encryption_key|mac_key)|"
    r"activation\.(?:uid|atqa|ats))\Z"
)
ENUM_ASSERTION_PATHS = {"credential.model_status", "emulator.secure_messaging"}
INDEXED_PATH = re.compile(r"(?:apps|files)\[\d+\](?:\.[a-z0-9_]+(?:\[\d+\])?)+\Z")


def parse_hex(text: str, *, wildcards: bool = False) -> int:
    compact = "".join(text.split())
    if len(compact) % 2:
        raise ValueError("odd-length hex")
    for offset in range(0, len(compact), 2):
        pair = compact[offset : offset + 2]
        if wildcards and pair == "??":
            continue
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
            raise ValueError("invalid hex")
    return len(compact) // 2


def parse_unsigned(text: str, *, base: int = 10, maximum: int | None = None) -> int:
    pattern = r"(?:0[xX][0-9A-Fa-f]+|0[0-7]*|[1-9][0-9]*|0)" if base == 0 else r"[0-9]+"
    if not re.fullmatch(pattern, text):
        raise ValueError("invalid unsigned integer")
    if base == 0:
        if text.lower().startswith("0x"):
            value = int(text, 0)
        elif len(text) > 1 and text.startswith("0"):
            value = int(text, 8)
        else:
            value = int(text, 10)
    else:
        value = int(text, base)
    if maximum is not None and value > maximum:
        raise ValueError("unsigned integer is out of range")
    return value


def split_expected(text: str) -> tuple[str, list[tuple[int, int, int]]]:
    pieces = re.split(r"\s+tolerance\s+", text.strip())
    expected = pieces[0]
    tolerances: list[tuple[int, int, int]] = []
    for clause in pieces[1:]:
        match = re.fullmatch(r"([0-9]+)\+([0-9]+)\s+([0-9]+)", clause)
        if not match:
            raise ValueError("malformed tolerance")
        offset, length, delta = (int(value) for value in match.groups())
        if length not in range(1, 5) or len(tolerances) == 4:
            raise ValueError("invalid tolerance length or count")
        if delta > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("tolerance delta is out of range")
        tolerances.append((offset, length, delta))
    return expected, tolerances


def validate_expected(text: str, *, allow_tolerance: bool = True) -> None:
    expected, tolerances = split_expected(text)
    length = parse_hex(expected, wildcards=True)
    wildcard_bytes = {
        index
        for index, pair in enumerate(re.findall(r"..", "".join(expected.split())))
        if pair == "??"
    }
    occupied: set[int] = set()
    for offset, field_length, _delta in tolerances:
        if not allow_tolerance:
            raise ValueError("tolerance is not allowed here")
        if offset > length or field_length > length - offset:
            raise ValueError("tolerance extends past expected response")
        field = set(range(offset, offset + field_length))
        if field & wildcard_bytes or field & occupied:
            raise ValueError("tolerance overlaps wildcard or another tolerance")
        occupied |= field


def validate_step(line: str, dialects: set[str]) -> None:
    words = line.split()
    verb = words[0]
    if verb in {"scan", "field-off", "clear-dirty"}:
        if len(words) != 1:
            raise ValueError(f"{verb} takes no arguments")
        return
    if verb == "random-source":
        if words != ["random-source", "finite"]:
            raise ValueError("malformed random-source")
        return
    if verb == "inject-random":
        if len(words) < 2 or parse_hex(" ".join(words[1:])) == 0:
            raise ValueError("malformed inject-random")
        return
    if verb == "advance-time":
        if len(words) != 2 or parse_unsigned(words[1]) > 0xFFFFFFFF:
            raise ValueError("malformed advance-time")
        return
    if verb == "roll-model-key-set":
        if len(words) != 3:
            raise ValueError("malformed roll-model-key-set")
        parse_unsigned(words[1], base=0)
        parse_unsigned(words[2], base=0)
        return
    if verb in {"assert", "set-model"}:
        if len(words) != 4 or words[2] != "=":
            raise ValueError(f"malformed {verb}")
        path, value = words[1], words[3]
        if path.startswith(("apps[", "files[")) and not INDEXED_PATH.fullmatch(path):
            raise ValueError("malformed indexed path")
        if verb == "assert" and path in ENUM_ASSERTION_PATHS:
            if value not in {"ok", "malformed", "present", "null"}:
                raise ValueError("invalid assertion enum")
        elif verb == "set-model" or not BYTE_ASSERTION_PATH.fullmatch(path):
            parse_unsigned(value, base=0)
        else:
            parse_hex(value)
        return
    if verb == "expect-error":
        if len(words) < 3 or words[1] != "random-source":
            raise ValueError("malformed expect-error")
        operation = words[2]
        if operation == "scan":
            if len(words) != 3:
                raise ValueError("malformed expect-error scan")
            return
        command_index = 3
        if operation == "exchange":
            if len(words) != 5 or words[3] not in dialects:
                raise ValueError("malformed expect-error exchange")
            command_index = 4
        elif operation != "frame-exchange" or len(words) != 4:
            raise ValueError("malformed expect-error operation")
        parse_hex(words[command_index])
        return
    if verb in {"exchange", "frame-exchange", "status", "select-application"}:
        try:
            arrow = words.index("=>")
        except ValueError as error:
            raise ValueError(f"malformed {verb}") from error
        command_index = 1
        if verb == "exchange":
            if len(words) < 5 or words[1] not in dialects:
                raise ValueError("malformed exchange")
            command_index = 2
        parse_hex(words[command_index])
        expected = " ".join(words[arrow + 1 :])
        if verb == "status":
            if parse_hex(expected) != 1:
                raise ValueError("status expects one byte")
        else:
            validate_expected(expected)
        if verb == "select-application" and parse_hex(words[command_index]) != 3:
            raise ValueError("select-application expects three-byte AID")


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

    text = path.read_text(encoding="utf-8")
    for number, raw in enumerate(text.splitlines(), 1):
        if len(raw.encode("utf-8")) > MAXIMUM_LINE_BYTES:
            raise ValueError(f"{path.relative_to(ROOT)}:{number}: line is too long")
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
            if key in values and key in {
                "name",
                "origin",
                "source",
                "case-id",
                "feature-version",
            }:
                raise ValueError(f"{location}: duplicate header {key!r}")
            if key in HEX_HEADERS:
                try:
                    parse_hex(value)
                except ValueError as error:
                    raise ValueError(f"{location}: invalid hex header {key!r}") from error
            if key in UNSIGNED_HEADERS:
                try:
                    parse_unsigned(value, maximum=0xFFFFFFFF)
                except ValueError as error:
                    raise ValueError(f"{location}: invalid integer header {key!r}") from error
            values[key] = value
            continue

        saw_step = True
        words = line.split()
        if words[0] not in steps:
            raise ValueError(f"{location}: unknown step {words[0]!r}")
        try:
            validate_step(line, dialects)
        except (ValueError, IndexError) as error:
            raise ValueError(f"{location}: {error}") from error
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
