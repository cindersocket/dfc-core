from __future__ import annotations

import ctypes as C
from dataclasses import dataclass

from . import _native
from .errors import DfcError


class SdmVerificationError(DfcError):
    pass


@dataclass(frozen=True)
class SdmField:
    offset: int
    length: int


@dataclass(frozen=True)
class SdmConfig:
    mac_input_offset: int
    mac_offset: int
    plain_uid: SdmField | None = None
    plain_read_counter_offset: int | None = None
    encrypted_picc_data: SdmField | None = None
    encrypted_file_data: SdmField | None = None


@dataclass(frozen=True)
class SdmResult:
    uid: bytes | None
    read_counter: int | None
    decrypted_file_data: bytes


def _validate_field(name: str, field: SdmField | None, message_length: int, scale: int = 1) -> None:
    if field is None:
        return
    offset = _native.unsigned(field.offset, C.sizeof(C.c_size_t) * 8, f"{name} offset")
    length = _native.unsigned(field.length, C.sizeof(C.c_size_t) * 8, f"{name} length")
    if offset > message_length or length > (message_length - offset) // scale:
        raise ValueError(f"{name} lies outside the message")


def _validate_config(message_length: int, config: SdmConfig) -> None:
    bits = C.sizeof(C.c_size_t) * 8
    mac_input = _native.unsigned(config.mac_input_offset, bits, "MAC input offset")
    mac = _native.unsigned(config.mac_offset, bits, "MAC offset")
    if mac_input > mac or mac > message_length or message_length - mac < 16:
        raise ValueError("MAC offsets lie outside the message")
    _validate_field("plain UID", config.plain_uid, message_length, 2)
    if config.plain_read_counter_offset is not None:
        counter = _native.unsigned(config.plain_read_counter_offset, bits, "counter offset")
        if counter > message_length or message_length - counter < 6:
            raise ValueError("counter lies outside the message")
    _validate_field("encrypted PICC data", config.encrypted_picc_data, message_length)
    _validate_field("encrypted file data", config.encrypted_file_data, message_length)
    for name, field in (
        ("encrypted PICC data", config.encrypted_picc_data),
        ("encrypted file data", config.encrypted_file_data),
    ):
        if field is not None and field.length % 2:
            raise ValueError(f"{name} must contain complete hexadecimal bytes")


def verify_sdm(
    message: bytes,
    config: SdmConfig,
    file_read_key: bytes,
    meta_read_key: bytes | None = None,
) -> SdmResult:
    """Authenticate one ASCII SDM message and return only verified fields."""
    if len(file_read_key) != 16 or (meta_read_key is not None and len(meta_read_key) != 16):
        raise ValueError("SDM keys must be 16 bytes")
    _validate_config(len(message), config)
    fields = 0
    if config.plain_uid is not None:
        fields |= 1
    if config.plain_read_counter_offset is not None:
        fields |= 2
    if config.encrypted_picc_data is not None:
        fields |= 4
    if config.encrypted_file_data is not None:
        fields |= 8
    uid = config.plain_uid or SdmField(0, 0)
    encrypted_picc = config.encrypted_picc_data or SdmField(0, 0)
    encrypted_file = config.encrypted_file_data or SdmField(0, 0)
    decrypted_length = encrypted_file.length // 2

    message_raw, message_pointer = _native.byte_pointer(message)
    file_raw, file_pointer = _native.byte_pointer(file_read_key)
    meta_raw, meta_pointer = _native.byte_pointer(meta_read_key or b"")
    decrypted = (C.c_uint8 * max(1, decrypted_length))()
    required = C.c_size_t()
    packed = (C.c_uint8 * 20)()
    try:
        status = _native.library().dfc_ffi_sdm_verify_ascii(
            message_pointer,
            len(message),
            fields,
            uid.offset,
            uid.length,
            config.plain_read_counter_offset or 0,
            encrypted_picc.offset,
            encrypted_picc.length,
            encrypted_file.offset,
            encrypted_file.length,
            config.mac_input_offset,
            config.mac_offset,
            meta_pointer if meta_read_key is not None else None,
            file_pointer,
            decrypted if decrypted_length else None,
            decrypted_length,
            C.byref(required),
            packed,
            len(packed),
        )
        if status:
            raise SdmVerificationError(status, f"SDM verification failed with status {status}")
        result = bytes(packed)
        clear = bytes(decrypted[: required.value])
        return SdmResult(
            result[2 : 2 + result[1]] if result[0] else None,
            int.from_bytes(result[16:20], "little") if result[12] else None,
            clear,
        )
    finally:
        for temporary in (message_raw, file_raw, meta_raw, decrypted, packed):
            _native.secure_zero(temporary)
