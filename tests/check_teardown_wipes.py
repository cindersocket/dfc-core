#!/usr/bin/env python3
"""Verify that secret-bearing owned storage is wiped on teardown."""

from pathlib import Path
import re


ROOT = Path(__file__).parents[1]


def main() -> None:
    emulator = (ROOT / "src" / "dfc_emulator.c").read_text(encoding="utf-8")
    commands = (ROOT / "src" / "dfc_emulator_commands.c").read_text(encoding="utf-8")
    credential = (ROOT / "src" / "dfc_credential.c").read_text(encoding="utf-8")
    required = {
        "emulator teardown": "dfc_secure_wipe(emulator, sizeof(*emulator))",
        "credential teardown": "dfc_secure_wipe(credential, sizeof(*credential))",
        "response storage": "dfc_secure_wipe(emulator->tx_buffer, sizeof(*emulator->tx_buffer))",
        "command-chain helper": "dfc_emulator_discard_command_chain(emulator)",
        "snapshot helper": "dfc_emulator_discard_transaction_snapshot(emulator)",
    }
    combined = emulator + commands + credential
    missing = [name for name, expression in required.items() if expression not in combined]
    if missing:
        raise SystemExit("missing teardown wipe coverage: " + ", ".join(missing))

    direct_command_frees = re.findall(
        r"dfc_platform_free\(emulator->command_chain\)", combined
    )
    direct_snapshot_frees = re.findall(
        r"dfc_platform_free\(emulator->transaction_snapshot_pool\)", combined
    )
    if len(direct_command_frees) != 1 or len(direct_snapshot_frees) != 1:
        raise SystemExit("owned emulator buffers must only be freed by their wipe helpers")

    if combined.count("dfc_emulator_discard_command_chain(emulator)") < 6:
        raise SystemExit("not every command-chain teardown path uses the wipe helper")
    if combined.count("dfc_emulator_discard_transaction_snapshot(emulator)") < 4:
        raise SystemExit("not every transaction-snapshot teardown path uses the wipe helper")

    credential_free = credential[credential.index("void dfc_credential_free(") :]
    if credential_free.index("dfc_secure_wipe(credential") > credential_free.index(
        "free(credential)"
    ):
        raise SystemExit("credential is freed before it is wiped")

    emulator_free = emulator[emulator.index("void dfc_emulator_free(") :]
    if emulator_free.index("dfc_secure_wipe(emulator->tx_buffer") > emulator_free.index(
        "dfc_bytebuf_free(emulator->tx_buffer)"
    ):
        raise SystemExit("response buffer is freed before it is wiped")


if __name__ == "__main__":
    main()
