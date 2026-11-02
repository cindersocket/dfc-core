from __future__ import annotations

import ctypes as C
from pathlib import Path

import pytest

from dfc_core import (
    Card,
    Command,
    _native,
    build_iso_append_record_apdu,
    fixed_time_equal,
    parse_iso7816_response,
)


def test_model_is_frozen() -> None:
    card = Card(3, 8, 0, b"1234567")
    with pytest.raises(AttributeError):
        card.storage = 4  # type: ignore[misc]


def test_command_validation_and_encoding() -> None:
    assert Command.select_application(bytes.fromhex("D3494F")).data == bytes.fromhex("4F49D3")
    assert Command.read_data(2, 0x1234, 7).data == bytes.fromhex("02341200070000")
    with pytest.raises(ValueError):
        Command.select_application(b"short")


def test_iso_append_record_helpers() -> None:
    vectors = Path(__file__).parents[3] / "tests" / "iso7816-helper-vectors.txt"
    for line in vectors.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        operation, input_hex, auxiliary, expected = line.split("|")
        if operation == "append-record":
            assert build_iso_append_record_apdu(
                int(auxiliary), bytes.fromhex(input_hex)
            ) == bytes.fromhex(expected)
        else:
            assert operation == "parse-response"
            assert parse_iso7816_response(bytes.fromhex(input_hex)) == (
                bytes.fromhex(auxiliary),
                int(expected, 16),
            )


def test_command_constructors_match_shared_vectors() -> None:
    constructors = {
        "get-version": lambda _: Command.get_version(),
        "get-free-memory": lambda _: Command.get_free_memory(),
        "format-picc": lambda _: Command.format_picc(),
        "get-key-settings": lambda _: Command.get_key_settings(),
        "get-application-ids": lambda _: Command.get_application_ids(),
        "get-df-names": lambda _: Command.get_df_names(),
        "get-file-ids": lambda _: Command.get_file_ids(),
        "get-iso-file-ids": lambda _: Command.get_iso_file_ids(),
        "get-card-uid": lambda _: Command.get_card_uid(),
        "read-signature": lambda args: Command.read_signature(int(args)),
        "get-key-version": lambda args: Command.get_key_version(int(args)),
        "select-application": lambda args: Command.select_application(bytes.fromhex(args)),
        "get-file-settings": lambda args: Command.get_file_settings(int(args)),
        "get-file-counters": lambda args: Command.get_file_counters(int(args)),
        "delete-file": lambda args: Command.delete_file(int(args)),
        "clear-record-file": lambda args: Command.clear_record_file(int(args)),
        "get-value": lambda args: Command.get_value(int(args)),
        "read-data": lambda args: Command.read_data(*(int(value) for value in args.split(","))),
        "read-data-iso-chaining": lambda args: Command.read_data(
            *(int(value) for value in args.split(",")), iso_chaining=True
        ),
        "write-data": lambda args: Command.write_data(
            int(args.split(",")[0]), int(args.split(",")[1]), bytes.fromhex(args.split(",")[2])
        ),
        "write-data-iso-chaining": lambda args: Command.write_data(
            int(args.split(",")[0]),
            int(args.split(",")[1]),
            bytes.fromhex(args.split(",")[2]),
            iso_chaining=True,
        ),
        "read-records": lambda args: Command.read_records(
            *(int(value) for value in args.split(","))
        ),
        "read-records-iso-chaining": lambda args: Command.read_records(
            *(int(value) for value in args.split(",")), iso_chaining=True
        ),
        "write-record": lambda args: Command.write_record(
            int(args.split(",")[0]), int(args.split(",")[1]), bytes.fromhex(args.split(",")[2])
        ),
        "write-record-iso-chaining": lambda args: Command.write_record(
            int(args.split(",")[0]),
            int(args.split(",")[1]),
            bytes.fromhex(args.split(",")[2]),
            iso_chaining=True,
        ),
        "update-record": lambda args: Command.update_record(
            int(args.split(",")[0]),
            int(args.split(",")[1]),
            int(args.split(",")[2]),
            bytes.fromhex(args.split(",")[3]),
        ),
        "update-record-iso-chaining": lambda args: Command.update_record(
            int(args.split(",")[0]),
            int(args.split(",")[1]),
            int(args.split(",")[2]),
            bytes.fromhex(args.split(",")[3]),
            iso_chaining=True,
        ),
        "credit": lambda args: Command.credit(*(int(value) for value in args.split(","))),
        "debit": lambda args: Command.debit(*(int(value) for value in args.split(","))),
        "limited-credit": lambda args: Command.limited_credit(
            *(int(value) for value in args.split(","))
        ),
        "commit-transaction": lambda args: Command.commit_transaction(
            None if not args else int(args)
        ),
        "abort-transaction": lambda _: Command.abort_transaction(),
    }
    vectors = Path(__file__).parents[3] / "tests" / "command-constructor-vectors.txt"
    for line in vectors.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, arguments, expected = line.split("|")
        command = constructors[name](arguments)
        assert bytes((command.instruction,)) + command.data == bytes.fromhex(expected), name


@pytest.mark.parametrize("file_number", [-1, 32, 256])
def test_file_command_constructors_reject_invalid_file_numbers(file_number: int) -> None:
    constructors = (
        Command.get_file_settings,
        Command.get_file_counters,
        Command.delete_file,
        Command.clear_record_file,
        Command.get_value,
        lambda number: Command.read_data(number, 0, 1),
        lambda number: Command.write_data(number, 0, b"x"),
        lambda number: Command.credit(number, 1),
    )
    for constructor in constructors:
        with pytest.raises(ValueError):
            constructor(file_number)


def test_command_payload_boundaries_match_shared_vectors() -> None:
    constructors = {
        "write-data": lambda length: Command.write_data(1, 0, bytes(length)),
        "write-record": lambda length: Command.write_record(1, 0, bytes(length)),
        "update-record": lambda length: Command.update_record(1, 0, 0, bytes(length)),
    }
    vectors = Path(__file__).parents[3] / "tests" / "command-constructor-boundaries.txt"
    for line in vectors.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, length, expected = line.split("|")
        if expected == "accept":
            constructors[name](int(length))
        else:
            with pytest.raises(ValueError):
                constructors[name](int(length))


def test_declared_layouts_are_stable() -> None:
    assert C.sizeof(_native.Error) == 104
    assert C.sizeof(_native.Key) == 32
    assert C.sizeof(_native.Card) > 80


def test_fixed_time_length_mismatch_needs_no_library() -> None:
    assert not fixed_time_equal(b"a", b"bb")
