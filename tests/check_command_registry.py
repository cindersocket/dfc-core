#!/usr/bin/env python3
"""Keep native command routing complete, unique, and generated from one list."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
ALIASES_NORMALIZED_BEFORE_DISPATCH = {
    "DFC_CMD_READ_DATA_ISO",
    "DFC_CMD_WRITE_DATA_ISO",
    "DFC_CMD_READ_RECORDS_ISO",
    "DFC_CMD_WRITE_RECORD_ISO",
    "DFC_CMD_UPDATE_RECORD_ISO",
}


def main() -> None:
    common = (ROOT / "src" / "dfc_common.h").read_text(encoding="utf-8")
    registry = (ROOT / "src" / "dfc_emulator_native_command_registry.inc").read_text(
        encoding="utf-8"
    )
    commands = (ROOT / "src" / "dfc_emulator_commands.c").read_text(encoding="utf-8")

    declared = set(re.findall(r"^#define\s+(DFC_CMD_[A-Z0-9_]+)\s+", common, re.MULTILINE))
    routed = re.findall(r"DFC_NATIVE_COMMAND\((DFC_CMD_[A-Z0-9_]+)\)", registry)
    duplicates = sorted({command for command in routed if routed.count(command) > 1})
    if duplicates:
        raise SystemExit("commands routed more than once: " + ", ".join(duplicates))

    missing = sorted(declared - set(routed) - ALIASES_NORMALIZED_BEFORE_DISPATCH)
    extra = sorted(set(routed) - declared)
    if missing:
        raise SystemExit("commands missing from native registry: " + ", ".join(missing))
    if extra:
        raise SystemExit("unknown commands in native registry: " + ", ".join(extra))

    dispatch = commands[commands.index("static bool dispatch_native_command(") :]
    include = '#include "dfc_emulator_native_command_registry.inc"'
    if dispatch.count(include) != 1:
        raise SystemExit("native dispatcher must include its registry exactly once")
    if re.search(r"^\s*case\s+DFC_CMD_", dispatch, re.MULTILINE):
        raise SystemExit("native command label bypasses the compile-time registry")


if __name__ == "__main__":
    main()
