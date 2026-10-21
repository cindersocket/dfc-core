from __future__ import annotations

import ctypes as C

import pytest

from dfc_core import Card, Command, _native, fixed_time_equal


def test_model_is_frozen() -> None:
    card = Card(3, 8, 0, b"1234567")
    with pytest.raises(AttributeError):
        card.storage = 4  # type: ignore[misc]


def test_command_validation_and_encoding() -> None:
    assert Command.select_application(bytes.fromhex("D3494F")).data == bytes.fromhex("4F49D3")
    assert Command.read_data(2, 0x1234, 7).data == bytes.fromhex("02341200070000")
    with pytest.raises(ValueError):
        Command.select_application(b"short")


def test_declared_layouts_are_stable() -> None:
    assert C.sizeof(_native.Error) == 104
    assert C.sizeof(_native.Key) == 32
    assert C.sizeof(_native.Card) > 80


def test_fixed_time_length_mismatch_needs_no_library() -> None:
    assert not fixed_time_equal(b"a", b"bb")
