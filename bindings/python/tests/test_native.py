from __future__ import annotations

import ctypes as C
from pathlib import Path

import pytest

from dfc_core import Command, Credential, Reader, VirtualPicc, _native, capabilities

FIXTURE = Path(__file__).parents[3] / "examples" / "credentials" / "v6-minimal.dfcb"


def test_abi_sizes_and_field_fingerprint() -> None:
    library = _native.library()
    assert capabilities().abi_version == _native.ABI_VERSION
    assert library.dfc_ffi_layout_fingerprint() == _native.layout_fingerprint()


def test_codec_picc_and_reader_lifecycle() -> None:
    encoded = FIXTURE.read_bytes()
    credential = Credential.decode(encoded)
    assert credential.encode() == encoded
    assert Credential.parse(credential.to_text()).encode() == encoded

    with VirtualPicc(credential) as picc:
        assert credential.closed
        assert picc.activate().uid
        with Reader(picc) as reader:
            response = reader.exchange(Command(0x60))
            assert response.status == 0
            assert len(response.data) == 28


def test_callback_exception_is_deferred_safely() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())

    def broken(_: int) -> bytes:
        raise LookupError("script exhausted")

    with VirtualPicc(credential, broken) as picc:
        output = (C.c_uint8 * 16)()
        assert picc._random_callback(0, output, 16) == _native.RANDOM_FAILED
        assert bytes(output) == bytes(16)
        with pytest.raises(RuntimeError, match="random source failed"):
            picc._check_callback()


def test_callback_failure_does_not_mutate_picc() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())

    with VirtualPicc(credential, lambda _: b"") as picc:
        picc.activate()
        before = picc.snapshot()
        with pytest.raises(RuntimeError, match="random source failed"):
            picc.exchange(bytes.fromhex("901A0000010000"))
        assert picc.snapshot() == before
