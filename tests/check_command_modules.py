#!/usr/bin/env python3
"""Keep split command-family modules wired into every CMake build."""

import re
from pathlib import Path


ROOT = Path(__file__).parents[1]


def main() -> None:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    modules = sorted((ROOT / "src").glob("dfc_emulator_commands_*.c"))
    missing = [path.name for path in modules if f"src/{path.name}" not in cmake]
    if missing:
        raise SystemExit("command modules missing from CMake: " + ", ".join(missing))

    monolith = (ROOT / "src" / "dfc_emulator_commands.c").read_text(encoding="utf-8")
    families = {
        "keys": (
            "get_key_settings",
            "get_key_version",
            "change_key",
            "change_key_settings",
            "initialize_key_set",
            "finalize_key_set",
            "roll_key_set",
            "change_key_ev2",
            "set_configuration",
        ),
        "lifecycle": (
            "select_application",
            "free_mem",
            "get_df_names",
            "format_picc",
            "get_file_ids",
            "get_iso_file_ids",
            "get_file_settings",
            "change_file_settings",
            "get_application_ids",
            "create_application",
            "delete_application",
            "create_std_data_file",
            "create_record_file",
            "create_value_file",
            "delete_file",
            "create_transaction_mac_file",
        ),
        "data": (
            "read_data",
            "get_file_counters",
            "write_data",
        ),
        "records": (
            "write_record",
            "update_record",
            "clear_record_file",
        ),
        "transactions": (
            "get_value",
            "value_delta",
            "commit_reader_id",
            "commit_transaction",
            "abort_transaction",
        ),
    }
    for family, names in families.items():
        module = (ROOT / "src" / f"dfc_emulator_commands_{family}.c").read_text(encoding="utf-8")
        for name in names:
            handler = f"dfc_emulator_command_{name}"
            definition = re.compile(
                rf"^(?:static\s+)?(?:bool|void)\s+{re.escape(handler)}\(",
                re.MULTILINE,
            )
            if not definition.search(module):
                raise SystemExit(f"{family} command module is missing {handler}")
            if definition.search(monolith):
                raise SystemExit(f"{family} handler moved back into command monolith: {handler}")


if __name__ == "__main__":
    main()
