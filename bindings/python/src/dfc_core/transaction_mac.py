from __future__ import annotations

import ctypes as C
from typing import Self

from . import _native
from .errors import DfcError


class TransactionMacError(DfcError):
    pass


def _unsigned(name: str, value: int, bits: int) -> int:
    if not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must fit in {bits} bits")
    return value


class TransactionMacVerifier:
    """Collect plain transaction inputs and verify one returned receipt."""

    def __init__(self, key: bytes, uid: bytes, counter: int, capacity: int = 128) -> None:
        if len(key) != 16 or len(uid) not in (4, 7) or capacity <= 0:
            raise ValueError("expected a 16-byte key, 4- or 7-byte UID, and positive capacity")
        _unsigned("counter", counter, 32)
        _unsigned("capacity", capacity, C.sizeof(C.c_size_t) * 8)
        key_raw, key_pointer = _native.byte_pointer(key)
        uid_raw, uid_pointer = _native.byte_pointer(uid)
        handle = _native.Handle()
        try:
            status = _native.library().dfc_ffi_transaction_mac_verifier_new(
                capacity, key_pointer, uid_pointer, len(uid), counter, C.byref(handle)
            )
            self._raise(status)
        finally:
            _native.secure_zero(key_raw)
            _native.secure_zero(uid_raw)
        self._handle = handle

    @staticmethod
    def _raise(status: int) -> None:
        if status:
            raise TransactionMacError(
                status, f"transaction MAC operation failed with status {status}"
            )

    def close(self) -> None:
        handle = getattr(self, "_handle", None)
        if handle:
            _native.library().dfc_ffi_transaction_mac_verifier_free(handle)
            self._handle = _native.Handle()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _data(
        self, name: str, command: int, file_number: int, offset: int, length: int, data: bytes
    ) -> None:
        _unsigned("command", command, 8)
        _unsigned("file number", file_number, 8)
        _unsigned("offset", offset, 32)
        _unsigned("length", length, 32)
        raw, pointer = _native.byte_pointer(data)
        function = getattr(_native.library(), f"dfc_ffi_transaction_mac_{name}")
        try:
            self._raise(
                function(self._handle, command, file_number, offset, length, pointer, len(data))
            )
        finally:
            _native.secure_zero(raw)

    def add_data(
        self, command: int, file_number: int, offset: int, length: int, data: bytes
    ) -> None:
        self._data("add_data", command, file_number, offset, length, data)

    def add_record_update(
        self,
        command: int,
        file_number: int,
        record_number: int,
        offset: int,
        length: int,
        data: bytes,
    ) -> None:
        _unsigned("command", command, 8)
        _unsigned("file number", file_number, 8)
        _unsigned("record number", record_number, 32)
        _unsigned("offset", offset, 32)
        _unsigned("length", length, 32)
        raw, pointer = _native.byte_pointer(data)
        try:
            self._raise(
                _native.library().dfc_ffi_transaction_mac_add_record_update(
                    self._handle,
                    command,
                    file_number,
                    record_number,
                    offset,
                    length,
                    pointer,
                    len(data),
                )
            )
        finally:
            _native.secure_zero(raw)

    def add_value(self, command: int, file_number: int, value: int) -> None:
        _unsigned("command", command, 8)
        _unsigned("file number", file_number, 8)
        _unsigned("value", value, 32)
        self._raise(
            _native.library().dfc_ffi_transaction_mac_add_value(
                self._handle, command, file_number, value
            )
        )

    def add_clear_record(self, file_number: int) -> None:
        _unsigned("file number", file_number, 8)
        self._raise(
            _native.library().dfc_ffi_transaction_mac_add_clear_record(self._handle, file_number)
        )

    def add_reader_id(self, current: bytes, encrypted_previous: bytes) -> None:
        if len(current) != 16 or len(encrypted_previous) != 16:
            raise ValueError("reader IDs must be 16 bytes")
        current_raw, current_pointer = _native.byte_pointer(current)
        previous_raw, previous_pointer = _native.byte_pointer(encrypted_previous)
        try:
            self._raise(
                _native.library().dfc_ffi_transaction_mac_add_reader_id(
                    self._handle, current_pointer, previous_pointer
                )
            )
        finally:
            _native.secure_zero(current_raw)
            _native.secure_zero(previous_raw)

    def verify(self, mac: bytes) -> bool:
        if len(mac) != 8:
            raise ValueError("transaction MAC must be 8 bytes")
        raw, pointer = _native.byte_pointer(mac)
        verified = C.c_uint8()
        try:
            self._raise(
                _native.library().dfc_ffi_transaction_mac_verify(
                    self._handle, pointer, C.byref(verified)
                )
            )
            return bool(verified.value)
        finally:
            _native.secure_zero(raw)
