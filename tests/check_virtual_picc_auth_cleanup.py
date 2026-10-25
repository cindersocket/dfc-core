#!/usr/bin/env python3
"""Keep virtual-PICC authentication secrets on one cleanup path."""

from pathlib import Path

ROOT = Path(__file__).parents[1]


def function(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    return source[start : source.index(next_signature, start)]


def require_cleanup(
    source: str,
    signature: str,
    next_signature: str,
    first_secret: str,
    label: str,
    wipes: tuple[str, ...],
) -> None:
    body = function(source, signature, next_signature)
    secret_region = body[body.index(first_secret) :]
    if secret_region.count(label) != 1:
        raise SystemExit(f"{signature} must have one {label} label")
    before, cleanup = secret_region.split(label, 1)
    if "return" in before:
        raise SystemExit(f"{signature} returns before secret cleanup")
    if cleanup.count("return result;") != 1:
        raise SystemExit(f"{signature} must return once after secret cleanup")
    for wipe in wipes:
        if wipe not in cleanup:
            raise SystemExit(f"{signature} cleanup is missing {wipe}")


def check(source: str) -> None:
    require_cleanup(
        source,
        "static DfcVirtualPiccStatus handle_iso_external_authenticate(",
        "static DfcVirtualPiccStatus handle_iso_internal_authenticate(",
        "uint8_t clear[",
        "iso_external_cleanup:",
        (
            "dfc_secure_wipe(clear, sizeof(clear))",
            "dfc_secure_wipe(iv, sizeof(iv))",
        ),
    )
    require_cleanup(
        source,
        "static DfcVirtualPiccStatus handle_iso_internal_authenticate(",
        "static DfcVirtualPiccStatus handle_iso_authenticate(",
        "uint8_t clear[",
        "iso_internal_cleanup:",
        (
            "dfc_secure_wipe(clear, sizeof(clear))",
            "dfc_secure_wipe(iv, sizeof(iv))",
            "dfc_secure_wipe(session_key, sizeof(session_key))",
            "dfc_secure_wipe(&candidate, sizeof(candidate))",
        ),
    )
    require_cleanup(
        source,
        "static DfcVirtualPiccStatus handle_virtual_card_select(",
        "static DfcVirtualPiccStatus handle_virtual_card_external_authenticate(",
        "uint8_t virtual_card_challenge[",
        "virtual_card_select_cleanup:",
        (
            "dfc_secure_wipe(virtual_card_challenge, sizeof(virtual_card_challenge))",
            "dfc_secure_wipe(virtual_card_clear_data, sizeof(virtual_card_clear_data))",
            "dfc_secure_wipe(clear, sizeof(clear))",
            "dfc_secure_wipe(iv, sizeof(iv))",
            "dfc_secure_wipe(encrypted, sizeof(encrypted))",
        ),
    )
    require_cleanup(
        source,
        "static DfcVirtualPiccStatus handle_virtual_card_external_authenticate(",
        "DfcVirtualPiccSession* dfc_virtual_picc_session_alloc(",
        "uint8_t input[",
        "virtual_card_auth_cleanup:",
        (
            "dfc_secure_wipe(input, sizeof(input))",
            "dfc_secure_wipe(full_mac, sizeof(full_mac))",
            "dfc_secure_wipe(wire_mac, sizeof(wire_mac))",
        ),
    )


def main() -> None:
    source = (ROOT / "src" / "dfc_virtual_picc.c").read_text(encoding="utf-8")
    check(source)
    mutants = (
        source.replace("goto iso_external_cleanup;", "return result;", 1),
        source.replace("goto iso_internal_cleanup;", "return result;", 1),
        source.replace("goto virtual_card_select_cleanup;", "return result;", 1),
        source.replace("goto virtual_card_auth_cleanup;", "return result;", 1),
    )
    for mutant in mutants:
        try:
            check(mutant)
        except SystemExit:
            continue
        raise SystemExit("virtual-PICC cleanup guard failed its mutation self-test")


if __name__ == "__main__":
    main()
