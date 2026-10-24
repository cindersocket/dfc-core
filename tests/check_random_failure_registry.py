#!/usr/bin/env python3
"""Require every production random draw to name its failure-atomicity test."""

import re
from pathlib import Path

CALL = re.compile(r"dfc_random_fill\(\s*([^,\n]+)")
REGISTRY = {
    ("src/dfc_credential.c", "uid"): "test_random_failures_are_atomic",
    ("src/dfc_virtual_picc.c", "challenge"): "test_random_failures_are_atomic",
    ("src/dfc_virtual_picc.c", "clear"): "test_random_failures_are_atomic",
    ("src/dfc_virtual_picc.c", "virtual_card_challenge"): "test_random_failures_are_atomic",
    ("src/dfc_virtual_picc.c", "random_uid_tail"): "test_random_failures_are_atomic",
    ("src/dfc_emulator_commands.c", "proximity_random"): "test_random_failures_are_atomic",
    ("src/dfc_emulator_commands.c", "random_material"): "test_random_failures_are_atomic",
    ("src/dfc_emulator_commands.c", "rnd_b"): "test_random_failures_are_atomic",
    (
        "src/dfc_emulator_commands.c",
        "picc_clear + random_offset",
    ): "test_sdm_random_padding_failure_is_atomic",
}


def call_sites(root: Path) -> set[tuple[str, str]]:
    sites = set()
    for source in sorted((root / "src").glob("*.c")):
        for argument in CALL.findall(source.read_text(encoding="utf-8")):
            sites.add((source.relative_to(root).as_posix(), " ".join(argument.split())))
    return sites


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sites = call_sites(root)
    missing = sites - REGISTRY.keys()
    stale = REGISTRY.keys() - sites
    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((root / "tests").glob("test_*.c"))
    )
    missing_tests = sorted({test for test in REGISTRY.values() if test not in test_source})
    if missing or stale or missing_tests:
        details = [
            f"unregistered random draw: {path}: {argument}"
            for path, argument in sorted(missing)
        ]
        details += [f"stale random draw: {path}: {argument}" for path, argument in sorted(stale)]
        details += [f"missing random-failure test: {test}" for test in missing_tests]
        raise SystemExit("\n".join(details))


if __name__ == "__main__":
    main()
