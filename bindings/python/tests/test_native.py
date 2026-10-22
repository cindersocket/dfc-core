from __future__ import annotations

import ctypes as C
from pathlib import Path

import pytest

from dfc_core import (
    Command,
    Credential,
    RandomSourceError,
    Reader,
    VirtualPicc,
    _native,
    capabilities,
)

FIXTURE = Path(__file__).parents[3] / "examples" / "credentials" / "v6-minimal.dfcb"


def test_reader_native_signatures_are_complete() -> None:
    library = _native.library()
    handle = _native.Handle
    pointer = _native.P8
    size = C.c_size_t
    status = C.c_int32
    signatures = {
        "dfc_ffi_reader_session_new": ([C.POINTER(handle)], status),
        "dfc_ffi_reader_session_free": ([handle], None),
        "dfc_ffi_reader_session_clear": ([handle], None),
        "dfc_ffi_reader_session_state": ([handle, C.POINTER(_native.ReaderState)], status),
        "dfc_ffi_reader_exchange_new": ([C.POINTER(handle)], status),
        "dfc_ffi_reader_exchange_free": ([handle], None),
        "dfc_ffi_reader_authenticate_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                C.c_uint8,
                C.c_uint8,
                pointer,
                size,
                pointer,
                size,
            ],
            status,
        ),
        "dfc_ffi_reader_authenticate_iso7816_begin": (
            [
                handle,
                handle,
                C.c_uint8,
                pointer,
                size,
                C.c_uint8,
                pointer,
                pointer,
                size,
            ],
            status,
        ),
        "dfc_ffi_reader_authenticate_ev2_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                C.c_uint8,
                C.c_uint8,
                pointer,
                pointer,
                pointer,
                size,
            ],
            status,
        ),
        "dfc_ffi_reader_exchange_begin": (
            [handle, handle, C.c_uint32, C.c_uint8, pointer, size, C.c_uint8, C.c_int32],
            status,
        ),
        "dfc_ffi_reader_write_data_begin": (
            [handle, handle, C.c_uint32, C.c_uint8, C.c_uint32, pointer, size, C.c_uint8],
            status,
        ),
        "dfc_ffi_reader_write_record_begin": (
            [handle, handle, C.c_uint32, C.c_uint8, C.c_uint32, pointer, size, C.c_uint8],
            status,
        ),
        "dfc_ffi_reader_update_record_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                C.c_uint8,
                C.c_uint32,
                C.c_uint32,
                pointer,
                size,
                C.c_uint8,
            ],
            status,
        ),
        "dfc_ffi_reader_create_delegated_application_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                pointer,
                size,
                pointer,
                pointer,
                pointer,
                pointer,
                size,
                C.c_uint8,
            ],
            status,
        ),
        "dfc_ffi_reader_step": (
            [handle, pointer, size, pointer, size, C.POINTER(size)],
            status,
        ),
        "dfc_ffi_reader_result_status": ([handle], C.c_uint8),
        "dfc_ffi_reader_result_data": (
            [handle, pointer, size, C.POINTER(size)],
            status,
        ),
        "dfc_ffi_reader_change_key_cryptogram": (
            [
                handle,
                C.c_uint8,
                pointer,
                size,
                pointer,
                C.c_uint8,
                C.c_uint8,
                pointer,
                size,
                C.POINTER(size),
            ],
            status,
        ),
        "dfc_ffi_reader_change_key_ev2_data": (
            [
                handle,
                C.c_uint8,
                C.c_uint8,
                pointer,
                pointer,
                C.c_uint8,
                pointer,
                size,
                C.POINTER(size),
            ],
            status,
        ),
    }

    for name, (argtypes, restype) in signatures.items():
        function = getattr(library, name)
        assert function.argtypes == argtypes, name
        assert function.restype is restype, name


def test_reader_authenticate_reaches_the_native_begin_function() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        picc.activate()
        with Reader(picc) as reader:
            response = reader.authenticate(0x1A, 0, bytes(16), random_a=bytes(8))

            assert response.status == 0
            assert reader.state.auth_mode == 0x1A


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
        with pytest.raises(RandomSourceError, match="random source failed") as failure:
            picc._check_callback()
        assert failure.value.status == _native.RANDOM_FAILED
        assert isinstance(failure.value.__cause__, LookupError)


def test_callback_failure_does_not_mutate_picc() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())

    with VirtualPicc(credential, lambda _: b"") as picc:
        picc.activate()
        before = picc.snapshot()
        with pytest.raises(RandomSourceError, match="random source failed") as failure:
            picc.exchange(bytes.fromhex("901A0000010000"))
        assert failure.value.status == _native.RANDOM_FAILED
        assert picc.snapshot() == before
        picc.reset_protocol()
        assert picc.exchange(bytes.fromhex("9060000000"))[-2:] == bytes.fromhex("91AF")


def test_callback_failure_is_reported_once_per_operation() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    calls = 0

    def exhausted(length: int) -> bytes:
        nonlocal calls
        calls += 1
        return bytes(max(0, length - 1))

    with VirtualPicc(credential, exhausted) as picc:
        picc.activate()
        for _ in range(2):
            with pytest.raises(RandomSourceError) as failure:
                picc.exchange(bytes.fromhex("901A0000010000"))
            assert failure.value.status == _native.RANDOM_FAILED
        assert calls == 2
