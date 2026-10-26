from __future__ import annotations

import ctypes as C
from typing import Self

from . import _native
from .errors import DfcError


class TransactionMacError(DfcError):
    """The native Transaction MAC verifier rejected an operation or receipt."""


def _unsigned(name: str, value: int, bits: int) -> int:
    if not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must fit in {bits} bits")
    return value


class TransactionMacVerifier:
    """Collect transaction inputs in card order and verify one returned receipt.

    The native verifier owns private key and transcript copies until ``close``.
    Use the object as a context manager so those copies are wiped promptly.
    """

    def __init__(self, key: bytes, uid: bytes, counter: int, capacity: int = 128) -> None:
        """Create a verifier with a private key and bounded transcript.

        Args:
            key: Secret 16-byte Transaction-MAC key.
            uid: Four- or seven-byte card UID.
            counter: Initial unsigned 32-bit transaction counter.
            capacity: Positive maximum transcript size in bytes.

        Raises:
            ValueError: If a length, counter, or capacity is invalid.
            TransactionMacError: If native verifier allocation fails.
        """

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
        """Wipe and release the native verifier; repeated calls are safe."""

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
        """Append a data-file operation and its plain bytes.

        Args:
            command: One-byte command instruction.
            file_number: One-byte file number.
            offset: Unsigned 32-bit file offset.
            length: Unsigned 32-bit command length field.
            data: Plain operation bytes in card-processing order.

        Raises:
            ValueError: If a numeric field is out of range.
            TransactionMacError: If the transcript has insufficient capacity.
        """

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
        """Append a record update and its plain record bytes.

        Args:
            command: One-byte command instruction.
            file_number: One-byte file number.
            record_number: Unsigned 32-bit record number.
            offset: Unsigned 32-bit offset within the record.
            length: Unsigned 32-bit command length field.
            data: Plain operation bytes in card-processing order.

        Raises:
            ValueError: If a numeric field is out of range.
            TransactionMacError: If the transcript has insufficient capacity.
        """

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
        """Append a value-file operation using its unsigned wire value.

        Args:
            command: One-byte command instruction.
            file_number: One-byte file number.
            value: Unsigned 32-bit value carried by the command.

        Raises:
            ValueError: If a numeric field is out of range.
            TransactionMacError: If the transcript has insufficient capacity.
        """

        _unsigned("command", command, 8)
        _unsigned("file number", file_number, 8)
        _unsigned("value", value, 32)
        self._raise(
            _native.library().dfc_ffi_transaction_mac_add_value(
                self._handle, command, file_number, value
            )
        )

    def add_clear_record(self, file_number: int) -> None:
        """Append a clear-record-file operation.

        Args:
            file_number: One-byte file number.

        Raises:
            ValueError: If ``file_number`` is out of range.
            TransactionMacError: If the transcript has insufficient capacity.
        """

        _unsigned("file number", file_number, 8)
        self._raise(
            _native.library().dfc_ffi_transaction_mac_add_clear_record(self._handle, file_number)
        )

    def add_reader_id(self, current: bytes, encrypted_previous: bytes) -> None:
        """Append the current and encrypted previous reader identifiers.

        Args:
            current: Current 16-byte reader identifier.
            encrypted_previous: Encrypted 16-byte previous reader identifier.

        Raises:
            ValueError: If either identifier is not 16 bytes.
            TransactionMacError: If the transcript has insufficient capacity.
        """

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
        """Verify the receipt for the accumulated transcript.

        Args:
            mac: Eight-byte transaction MAC returned by the card.

        Returns:
            ``True`` for a valid receipt, otherwise ``False``.

        Raises:
            ValueError: If ``mac`` is not eight bytes.
            TransactionMacError: If native verification cannot be performed.
        """

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
