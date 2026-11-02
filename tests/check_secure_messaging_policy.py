#!/usr/bin/env python3
"""Keep every native command in an explicit secure-messaging policy."""

import re
from pathlib import Path

COMMAND = re.compile(r"^#define (DFC_CMD_[A-Z0-9_]+)\s+0x[0-9A-Fa-f]+", re.MULTILINE)
CASE = re.compile(r"case (DFC_CMD_[A-Z0-9_]+):")
COMMAND_TOKEN = re.compile(r"\bDFC_CMD_[A-Z0-9_]+\b")
GENERIC_CALL = re.compile(
    r"dfc_secure_messaging_(?:wrap|unwrap|generate_response(?:_with_length_marker)?|verify_command)\s*\("
)

EV1_BYPASS = {
    "DFC_CMD_ADDITIONAL_FRAME",
    "DFC_CMD_AUTHENTICATE_AES",
    "DFC_CMD_AUTHENTICATE_EV2_FIRST",
    "DFC_CMD_AUTHENTICATE_EV2_NON_FIRST",
    "DFC_CMD_AUTHENTICATE_ISO",
    "DFC_CMD_AUTHENTICATE_LEGACY",
    "DFC_CMD_SELECT_APPLICATION",
}

EV1_TRANSMITTED_MAC = {
    "DFC_CMD_CREDIT",
    "DFC_CMD_DEBIT",
    "DFC_CMD_COMMIT_READER_ID",
    "DFC_CMD_GET_FILE_COUNTERS",
    "DFC_CMD_LIMITED_CREDIT",
    "DFC_CMD_UPDATE_RECORD",
    "DFC_CMD_UPDATE_RECORD_ISO",
    "DFC_CMD_WRITE_DATA",
    "DFC_CMD_WRITE_DATA_ISO",
    "DFC_CMD_WRITE_RECORD",
    "DFC_CMD_WRITE_RECORD_ISO",
}

EV1_TRANSMITTED_SWITCH_CASES = EV1_TRANSMITTED_MAC - {
    "DFC_CMD_UPDATE_RECORD_ISO",
    "DFC_CMD_WRITE_DATA_ISO",
    "DFC_CMD_WRITE_RECORD_ISO",
}

EV1_CHAINED_CMAC = {
    "DFC_CMD_ABORT_TRANSACTION",
    "DFC_CMD_CHANGE_FILE_SETTINGS",
    "DFC_CMD_CHANGE_KEY",
    "DFC_CMD_CHANGE_KEY_EV2",
    "DFC_CMD_CHANGE_KEY_SETTINGS",
    "DFC_CMD_CLEAR_RECORD_FILE",
    "DFC_CMD_COMMIT_TRANSACTION",
    "DFC_CMD_CREATE_APPLICATION",
    "DFC_CMD_CREATE_BACKUP_DATA_FILE",
    "DFC_CMD_CREATE_CYCLIC_RECORD_FILE",
    "DFC_CMD_CREATE_DELEGATED_APPLICATION",
    "DFC_CMD_CREATE_LINEAR_RECORD_FILE",
    "DFC_CMD_CREATE_STD_DATA_FILE",
    "DFC_CMD_CREATE_TRANSACTION_MAC_FILE",
    "DFC_CMD_CREATE_VALUE_FILE",
    "DFC_CMD_DELETE_APPLICATION",
    "DFC_CMD_DELETE_FILE",
    "DFC_CMD_FINALIZE_KEY_SET",
    "DFC_CMD_FORMAT_PICC",
    "DFC_CMD_FREE_MEM",
    "DFC_CMD_GET_APPLICATION_IDS",
    "DFC_CMD_GET_CARD_UID",
    "DFC_CMD_GET_DELEGATED_INFO",
    "DFC_CMD_GET_DF_NAMES",
    "DFC_CMD_GET_FILE_IDS",
    "DFC_CMD_GET_FILE_SETTINGS",
    "DFC_CMD_GET_ISO_FILE_IDS",
    "DFC_CMD_GET_KEY_SETTINGS",
    "DFC_CMD_GET_KEY_VERSION",
    "DFC_CMD_GET_VALUE",
    "DFC_CMD_GET_VERSION",
    "DFC_CMD_INITIALIZE_KEY_SET",
    "DFC_CMD_NOTIFY_TRANSACTION_SUCCESS",
    "DFC_CMD_PREPARE_PROXIMITY_CHECK",
    "DFC_CMD_PROXIMITY_CHECK",
    "DFC_CMD_READ_DATA",
    "DFC_CMD_READ_DATA_ISO",
    "DFC_CMD_READ_RECORDS",
    "DFC_CMD_READ_RECORDS_ISO",
    "DFC_CMD_READ_SIGNATURE",
    "DFC_CMD_ROLL_KEY_SET",
    "DFC_CMD_SET_CONFIGURATION",
    "DFC_CMD_VERIFY_PROXIMITY_CHECK",
}


def function_body(source: str, name: str) -> str:
    start = source.index(name)
    opening = source.index("{", start)
    depth = 1
    for index in range(opening + 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise SystemExit(f"unterminated function: {name}")


def call_arguments(source: str, opening: int) -> list[str]:
    arguments = []
    start = opening + 1
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                arguments.append(source[start:index].strip())
                return arguments
        elif source[index] == "," and depth == 1:
            arguments.append(source[start:index].strip())
            start = index + 1
    raise SystemExit("unterminated secure-messaging call")


def command_policy_mismatches(body: str, expected: set[str]) -> list[str]:
    return sorted(set(COMMAND_TOKEN.findall(body)) ^ expected)


def self_test() -> None:
    expected = {"DFC_CMD_EXPECTED"}
    extra = "return cmd != DFC_CMD_EXPECTED && cmd != DFC_CMD_UNEXPECTED;"
    missing = "return false;"
    if command_policy_mismatches(extra, expected) != ["DFC_CMD_UNEXPECTED"]:
        raise SystemExit("secure-messaging policy checker self-test failed")
    if command_policy_mismatches(missing, expected) != ["DFC_CMD_EXPECTED"]:
        raise SystemExit("secure-messaging policy checker self-test failed")


def main() -> None:
    self_test()
    root = Path(__file__).resolve().parents[1]
    commands = set(COMMAND.findall((root / "src/dfc_common.h").read_text(encoding="utf-8")))
    policies = EV1_BYPASS | EV1_TRANSMITTED_MAC | EV1_CHAINED_CMAC
    overlaps = (
        (EV1_BYPASS & EV1_TRANSMITTED_MAC)
        | (EV1_BYPASS & EV1_CHAINED_CMAC)
        | (EV1_TRANSMITTED_MAC & EV1_CHAINED_CMAC)
    )
    missing = sorted(commands - policies)
    stale = sorted(policies - commands)

    source = (root / "src/dfc_secure_messaging.c").read_text(encoding="utf-8")
    transmitted = set(
        CASE.findall(function_body(source, "dfc_secure_messaging_ev1_transmits_command_mac"))
    )
    mismatched = sorted(transmitted ^ EV1_TRANSMITTED_SWITCH_CASES)
    applies_body = function_body(source, "dfc_secure_messaging_applies_ev1")
    mismatched_bypass = command_policy_mismatches(applies_body, EV1_BYPASS)

    errors = [f"command lacks secure-messaging policy: {name}" for name in missing]
    errors += [f"stale secure-messaging policy: {name}" for name in stale]
    errors += [f"overlapping secure-messaging policy: {name}" for name in sorted(overlaps)]
    errors += [f"EV1 transmitted-MAC policy mismatch: {name}" for name in mismatched]
    errors += [f"EV1 bypass policy mismatch: {name}" for name in mismatched_bypass]
    for path in sorted((root / "src").glob("*.c")):
        if path.name == "dfc_secure_messaging.c":
            continue
        production = path.read_text(encoding="utf-8")
        for match in GENERIC_CALL.finditer(production):
            arguments = call_arguments(production, match.end() - 1)
            if len(arguments) < 2 or arguments[1] not in {
                "DFC_COMM_PLAIN",
                "DFC_COMM_ENCIPHERED",
            }:
                mode = arguments[1] if len(arguments) >= 2 else "<missing>"
                errors.append(
                    f"generic helper has non-explicit mode in {path.relative_to(root)}: {mode}"
                )
    if errors:
        raise SystemExit("\n".join(errors))


if __name__ == "__main__":
    main()
