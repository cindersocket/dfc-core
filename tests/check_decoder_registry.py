#!/usr/bin/env python3
"""Keep every credential decoder under the failure-atomicity suite.

A function that fills a caller's credential from outside input must leave the
empty credential behind on any failure. tests/test_dfc_decode_failure_atomicity.c
holds each decoder to that; its DECODERS table is the registry. A decoder is a
declared function whose name says it reads (decode, parse, load, import) and
whose first parameter is a mutable credential, or, for the target bridge, the
caller's untyped credential storage. This check fails when a header declares one
that the registry does not name, so a new entry point cannot ship untested.

The FFI's dfc_ffi_credential_* readers allocate the credential they fill and free
it on failure, so they take no caller destination and are not decoders here.
"""

import re
from pathlib import Path

SUITE = "tests/test_dfc_decode_failure_atomicity.c"
READS = re.compile(r"(decode|parse|load|import|deserialize)")
DECLARATION = re.compile(r"\b(dfc_\w+)\s*\(([^;{}]*?)\)\s*;")
MUTABLE_CREDENTIAL = re.compile(r"(?!const\b)DfcCredential\s*\*")
UNTYPED_STORAGE = re.compile(r"(?!const\b)void\s*\*")
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def decoders(root: Path) -> list[str]:
    names: set[str] = set()
    for header in sorted([*root.glob("src/*.h"), *root.glob("ffi/*.h")]):
        text = COMMENTS.sub("", header.read_text(encoding="utf-8"))
        for name, parameters in DECLARATION.findall(text):
            if not READS.search(name):
                continue
            first = parameters.split(",", 1)[0].strip()
            if MUTABLE_CREDENTIAL.match(first) or (
                name.startswith("dfc_target_credential_") and UNTYPED_STORAGE.match(first)
            ):
                names.add(name)
    return sorted(names)


def unregistered(root: Path) -> list[str]:
    suite = (root / SUITE).read_text(encoding="utf-8")
    return [name for name in decoders(root) if f'"{name}"' not in suite]


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    missing = unregistered(root)
    if missing:
        raise SystemExit(
            f"decoders missing from the DECODERS table in {SUITE}:\n" + "\n".join(missing)
        )


if __name__ == "__main__":
    main()
