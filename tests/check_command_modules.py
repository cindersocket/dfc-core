#!/usr/bin/env python3
"""Keep split command-family modules wired into every CMake build."""

from pathlib import Path


ROOT = Path(__file__).parents[1]


def main() -> None:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    modules = sorted((ROOT / "src").glob("dfc_emulator_commands_*.c"))
    missing = [path.name for path in modules if f"src/{path.name}" not in cmake]
    if missing:
        raise SystemExit("command modules missing from CMake: " + ", ".join(missing))

    monolith = (ROOT / "src" / "dfc_emulator_commands.c").read_text(encoding="utf-8")
    keys = (ROOT / "src" / "dfc_emulator_commands_keys.c").read_text(encoding="utf-8")
    handlers = (
        "dfc_emulator_command_get_key_settings",
        "dfc_emulator_command_get_key_version",
        "dfc_emulator_command_change_key",
        "dfc_emulator_command_change_key_settings",
        "dfc_emulator_command_initialize_key_set",
        "dfc_emulator_command_finalize_key_set",
        "dfc_emulator_command_roll_key_set",
        "dfc_emulator_command_change_key_ev2",
        "dfc_emulator_command_set_configuration",
    )
    for handler in handlers:
        definition = f"{handler}("
        if definition not in keys:
            raise SystemExit(f"key command module is missing {handler}")
        if f"void {definition}" in monolith or f"static void {definition}" in monolith:
            raise SystemExit(f"key handler moved back into command monolith: {handler}")


if __name__ == "__main__":
    main()
