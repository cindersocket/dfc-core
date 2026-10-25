from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
from enum import IntEnum

from . import _native
from .errors import DfcError
from .models import CommunicationMode, FileType


class ResponseDecodeError(DfcError):
    pass


class AccessKind(IntEnum):
    KEY = 0
    FREE = 1
    DENIED = 2


@dataclass(frozen=True)
class Access:
    kind: AccessKind
    key_number: int | None = None


@dataclass(frozen=True)
class AccessRights:
    read: Access
    write: Access
    read_write: Access
    change: Access


@dataclass(frozen=True)
class VersionPart:
    vendor_id: int
    type: int
    subtype: int
    major_version: int
    minor_version: int
    storage_size: int
    protocol: int


@dataclass(frozen=True)
class Version:
    hardware: VersionPart
    software: VersionPart
    uid: bytes
    batch_number: bytes
    production_week: int
    production_year: int


@dataclass(frozen=True)
class FileSettings:
    type: FileType
    communication_mode: CommunicationMode
    access_rights_raw: int
    access: AccessRights
    size: int | None = None
    lower_limit: int | None = None
    upper_limit: int | None = None
    limited_credit_value: int | None = None
    limited_credit_enabled: bool | None = None
    record_size: int | None = None
    max_records: int | None = None
    current_records: int | None = None


@dataclass(frozen=True)
class KeySettings:
    settings_1: int
    settings_2: int
    key_type: int
    key_count: int
    active_key_set_version: int | None = None
    key_set_count: int | None = None
    max_key_size: int | None = None
    key_set_settings: int | None = None


def _input(data: bytes) -> tuple[C.Array[C.c_uint8], _native.P8]:  # type: ignore[valid-type]
    return _native.byte_pointer(data)


def _check(status: int) -> None:
    if status:
        raise ResponseDecodeError(status, f"response decode failed with status {status}")


def _part(data: bytes) -> VersionPart:
    return VersionPart(*data)


def decode_version(response: bytes) -> Version:
    raw, pointer = _input(response)
    output = (C.c_uint8 * 28)()
    _check(_native.library().dfc_ffi_response_decode_version(pointer, len(response), output, 28))
    _ = raw
    data = bytes(output)
    return Version(_part(data[:7]), _part(data[7:14]), data[14:21], data[21:26], data[26], data[27])


def decode_application_ids(response: bytes) -> tuple[bytes, ...]:
    if len(response) % 3:
        raise ResponseDecodeError(1, "application ID response length is not divisible by three")
    raw, pointer = _input(response)
    output = (C.c_uint8 * max(1, len(response)))()
    length = C.c_size_t()
    _check(
        _native.library().dfc_ffi_response_decode_application_ids(
            pointer, len(response), output, len(response), C.byref(length)
        )
    )
    _ = raw
    data = bytes(output[: length.value])
    return tuple(data[index : index + 3] for index in range(0, len(data), 3))


def decode_file_ids(response: bytes) -> tuple[int, ...]:
    raw, pointer = _input(response)
    output = (C.c_uint8 * max(1, len(response)))()
    length = C.c_size_t()
    _check(
        _native.library().dfc_ffi_response_decode_file_ids(
            pointer, len(response), output, len(response), C.byref(length)
        )
    )
    _ = raw
    return tuple(output[: length.value])


def _access(data: bytes) -> Access:
    kind = AccessKind(data[0])
    return Access(kind, data[1] if kind is AccessKind.KEY else None)


def decode_file_settings(response: bytes) -> FileSettings:
    raw, pointer = _input(response)
    output = (C.c_uint8 * 32)()
    _check(
        _native.library().dfc_ffi_response_decode_file_settings(pointer, len(response), output, 32)
    )
    _ = raw
    data = bytes(output)
    file_type = FileType(data[0])
    communication_mode = CommunicationMode(data[1])
    access_rights_raw = int.from_bytes(data[4:6], "little")
    access_rights = AccessRights(*(_access(data[index : index + 2]) for index in range(6, 14, 2)))
    if file_type in (FileType.STANDARD_DATA, FileType.BACKUP_DATA):
        return FileSettings(
            file_type,
            communication_mode,
            access_rights_raw,
            access_rights,
            size=int.from_bytes(data[14:18], "little"),
        )
    if file_type is FileType.VALUE:
        return FileSettings(
            file_type,
            communication_mode,
            access_rights_raw,
            access_rights,
            lower_limit=int.from_bytes(data[14:18], "little", signed=True),
            upper_limit=int.from_bytes(data[18:22], "little", signed=True),
            limited_credit_value=int.from_bytes(data[22:26], "little", signed=True),
            limited_credit_enabled=bool(data[26]),
        )
    return FileSettings(
        file_type,
        communication_mode,
        access_rights_raw,
        access_rights,
        record_size=int.from_bytes(data[14:18], "little"),
        max_records=int.from_bytes(data[18:22], "little"),
        current_records=int.from_bytes(data[22:26], "little"),
    )


def decode_key_settings(response: bytes) -> KeySettings:
    raw, pointer = _input(response)
    output = (C.c_uint8 * 9)()
    _check(
        _native.library().dfc_ffi_response_decode_key_settings(pointer, len(response), output, 9)
    )
    _ = raw
    values = bytes(output)
    return KeySettings(
        values[0],
        values[1],
        values[2],
        values[3],
        values[5] if values[4] else None,
        values[6] if values[4] else None,
        values[7] if values[4] else None,
        values[8] if values[4] else None,
    )


def decode_key_version(response: bytes) -> int:
    raw, pointer = _input(response)
    output = C.c_uint8()
    _check(
        _native.library().dfc_ffi_response_decode_key_version(
            pointer, len(response), C.byref(output)
        )
    )
    _ = raw
    return output.value
