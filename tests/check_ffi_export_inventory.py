#!/usr/bin/env python3
"""Keep every public FFI declaration implemented once, in its owning module."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
HEADER = ROOT / "ffi" / "dfc_ffi.h"
DEFINITION = re.compile(r"^[A-Za-z_][^\n]*\b(dfc_ffi_[A-Za-z0-9_]+)\s*\(", re.MULTILINE)


def declared_exports() -> set[str]:
    source = HEADER.read_text(encoding="utf-8")
    return set(re.findall(r"DFC_FFI_EXPORT\s+[^;]*?\b(dfc_ffi_[A-Za-z0-9_]+)\s*\(", source))


def definition_files(name: str) -> list[Path]:
    pattern = re.compile(rf"^[A-Za-z_][^\n]*\b{re.escape(name)}\s*\(", re.MULTILINE)
    return [
        path
        for path in sorted((ROOT / "ffi").glob("dfc_ffi*.c"))
        if path.name != "dfc_target_ffi.c" and pattern.search(path.read_text(encoding="utf-8"))
    ]


def expected_owner(name: str) -> str:
    credential_io = {
        "dfc_ffi_credential_clone",
        "dfc_ffi_credential_decode",
        "dfc_ffi_credential_encode",
        "dfc_ffi_credential_free",
        "dfc_ffi_credential_load",
        "dfc_ffi_credential_parse_text",
        "dfc_ffi_credential_validate",
        "dfc_ffi_credential_write_text",
    }
    if name in credential_io:
        return "dfc_ffi_credential.c"
    if name.startswith("dfc_ffi_credential_"):
        return "dfc_ffi_model.c"
    families = (
        ("dfc_ffi_an10922_", "dfc_ffi_an10922.c"),
        ("dfc_ffi_picc_", "dfc_ffi_picc.c"),
        ("dfc_ffi_reader_", "dfc_ffi_reader.c"),
        ("dfc_ffi_response_", "dfc_ffi_response.c"),
        ("dfc_ffi_sdm_", "dfc_ffi_sdm.c"),
        ("dfc_ffi_transaction_mac_", "dfc_ffi_transaction_mac.c"),
    )
    for prefix, owner in families:
        if name.startswith(prefix):
            return owner
    return "dfc_ffi.c"


def main() -> None:
    declarations = declared_exports()
    if not declarations:
        raise SystemExit("no public FFI exports found")

    failures: list[str] = []
    implementation_sources = {
        path.name for path in (ROOT / "ffi").glob("dfc_ffi*.c") if path.name != "dfc_target_ffi.c"
    }
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    cmake_block = cmake[
        cmake.index("set(DFC_FFI_IMPLEMENTATION_SOURCES") : cmake.index("set(DFC_FFI_SOURCES")
    ]
    missing_sources = sorted(
        source for source in implementation_sources if f"ffi/{source}" not in cmake_block
    )
    if missing_sources:
        failures.append("FFI sources absent from the library target: " + ", ".join(missing_sources))

    definitions: set[str] = set()
    for source in implementation_sources:
        definitions.update(DEFINITION.findall((ROOT / "ffi" / source).read_text(encoding="utf-8")))
    extra_definitions = sorted(definitions - declarations)
    if extra_definitions:
        failures.append("undeclared FFI definitions: " + ", ".join(extra_definitions))

    for name in sorted(declarations):
        definitions = definition_files(name)
        owners = [path.name for path in definitions]
        if len(definitions) != 1:
            failures.append(f"{name}: expected one definition, found {owners}")
        elif owners[0] != expected_owner(name):
            failures.append(f"{name}: implemented by {owners[0]}, expected {expected_owner(name)}")

    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
