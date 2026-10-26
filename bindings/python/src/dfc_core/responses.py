from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
from enum import IntEnum

from . import _native
from .errors import DfcError
from .models import CommunicationMode, FileType


class ResponseDecodeError(DfcError):
    """A clear card response is malformed or unsupported by its typed decoder."""


class AccessKind(IntEnum):
    """Meaning of one four-bit file access-right entry.

    Values:
        KEY: Access requires authentication with ``Access.key_number``.
        FREE: Access does not require authentication.
        DENIED: Access is disabled.
    """

    KEY = 0
    FREE = 1
    DENIED = 2


@dataclass(frozen=True)
class Access:
    """Decoded access requirement for one file operation.

    Attributes:
        kind: Whether access uses a key, is free, or is denied.
        key_number: Required key number only when ``kind`` is ``KEY``.
    """

    kind: AccessKind
    key_number: int | None = None


@dataclass(frozen=True)
class AccessRights:
    """Decoded file access requirements.

    Attributes:
        read: Requirement for read operations.
        write: Requirement for write operations.
        read_write: Combined read/write key requirement.
        change: Requirement for changing file settings.
    """

    read: Access
    write: Access
    read_write: Access
    change: Access


@dataclass(frozen=True)
class VersionPart:
    """One seven-byte hardware or software version block.

    Attributes:
        vendor_id: Manufacturer identifier.
        type: Product-type byte.
        subtype: Product-subtype byte.
        major_version: Major version byte.
        minor_version: Minor version byte.
        storage_size: Encoded storage-size byte.
        protocol: Protocol identifier byte.
    """

    vendor_id: int
    type: int
    subtype: int
    major_version: int
    minor_version: int
    storage_size: int
    protocol: int


@dataclass(frozen=True)
class Version:
    """Typed, fully assembled GetVersion response.

    Attributes:
        hardware: Hardware version block.
        software: Software version block.
        uid: Seven-byte manufacturing UID in response order.
        batch_number: Five-byte manufacturing batch number.
        production_week: Production-week byte as encoded by the card.
        production_year: Production-year byte as encoded by the card.
    """

    hardware: VersionPart
    software: VersionPart
    uid: bytes
    batch_number: bytes
    production_week: int
    production_year: int


@dataclass(frozen=True)
class FileSettings:
    """Typed fields from a supported GetFileSettings response.

    Type-specific attributes are ``None`` when they do not apply. Transaction-MAC
    file settings are not decoded by this API and return ``ResponseDecodeError``.

    Attributes:
        type: Standard, backup, value, linear-record, or cyclic-record file type.
        communication_mode: Configured secure-messaging mode.
        access_rights_raw: Packed two-byte access-rights value.
        access: Decoded read, write, read/write, and change requirements.
        size: Data-file size in bytes.
        lower_limit: Signed lower limit for a value file.
        upper_limit: Signed upper limit for a value file.
        limited_credit_value: Signed limited-credit amount for a value file.
        limited_credit_enabled: Whether limited credit is enabled.
        record_size: Record size in bytes.
        max_records: Configured record capacity.
        current_records: Current record count.
    """

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
    """Typed fields from a GetKeySettings response.

    Extended key-set attributes are ``None`` when the response carries only the
    basic four-byte form.

    Attributes:
        settings_1: First raw key-settings byte.
        settings_2: Second raw key-settings byte.
        key_type: Encoded key-type bits.
        key_count: Number of configured keys.
        active_key_set_version: Optional active key-set version.
        key_set_count: Optional number of key sets.
        max_key_size: Optional maximum keys per set.
        key_set_settings: Optional raw key-set policy byte.
    """

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
    """Decode an assembled GetVersion response.

    Args:
        response: All 28 response-data bytes, without status or APDU framing.

    Returns:
        The hardware, software, UID, batch, week, and year fields.

    Raises:
        ResponseDecodeError: If the response is not exactly 28 bytes.
    """

    raw, pointer = _input(response)
    output = (C.c_uint8 * 28)()
    _check(_native.library().dfc_ffi_response_decode_version(pointer, len(response), output, 28))
    _ = raw
    data = bytes(output)
    return Version(_part(data[:7]), _part(data[7:14]), data[14:21], data[21:26], data[26], data[27])


def decode_application_ids(response: bytes) -> tuple[bytes, ...]:
    """Decode application IDs into model/display-order values.

    Args:
        response: Concatenated three-byte wire-order AIDs, without status framing.

    Returns:
        Three-byte AIDs in model/display order.

    Raises:
        ResponseDecodeError: If the length is not divisible by three or decoding fails.
    """

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
    """Decode file numbers from GetFileIDs response data.

    Args:
        response: Response data without status or APDU framing.

    Returns:
        File numbers in card-returned order.

    Raises:
        ResponseDecodeError: If native decoding rejects the response.
    """

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
    """Decode supported file settings into type-specific fields.

    Args:
        response: GetFileSettings response data without status or APDU framing.

    Returns:
        Common settings plus fields for the decoded file type.

    Raises:
        ResponseDecodeError: If the response is malformed or its file type is unsupported.
    """

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
    """Decode basic or extended PICC/application key settings.

    Args:
        response: GetKeySettings response data without status or APDU framing.

    Returns:
        Basic fields and optional extended key-set fields.

    Raises:
        ResponseDecodeError: If the response has an unsupported length or encoding.
    """

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
    """Decode the byte returned by GetKeyVersion.

    Args:
        response: Response data without status or APDU framing.

    Returns:
        The unsigned key-version byte.

    Raises:
        ResponseDecodeError: If the response does not contain exactly one byte.
    """

    raw, pointer = _input(response)
    output = C.c_uint8()
    _check(
        _native.library().dfc_ffi_response_decode_key_version(
            pointer, len(response), C.byref(output)
        )
    )
    _ = raw
    return output.value
