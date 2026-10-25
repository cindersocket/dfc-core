"""Keep authenticator comparisons on the constant-time helper."""

from pathlib import Path

SOURCE_DIR = Path(__file__).parents[1] / "src"


def main() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(SOURCE_DIR.glob("dfc_emulator_commands*.c"))
    )
    required = (
        "dfc_ct_equal(clear + DFC_EV2_RANDOM_LENGTH, rotated_b, sizeof(rotated_b))",
        "dfc_ct_equal(rnd_b_rot, expected_rnd_b_rot, challenge_len)",
        "dfc_ct_equal(expected_dam_mac, dam_mac, sizeof(expected_dam_mac))",
    )
    missing = [expression for expression in required if expression not in source]
    if missing:
        raise SystemExit("non-constant-time authenticator comparison:\n" + "\n".join(missing))

    violations: list[str] = []
    for path in sorted(SOURCE_DIR.glob("dfc_emulator*.c")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "memcmp(" not in line:
                continue
            if "iso_aid" in line or "DFC_ISO_AID" in line:
                continue
            violations.append(f"{path.name}:{line_number}: {line.strip()}")
    if violations:
        raise SystemExit(
            "non-public emulator comparison still uses memcmp:\n" + "\n".join(violations)
        )


if __name__ == "__main__":
    main()
