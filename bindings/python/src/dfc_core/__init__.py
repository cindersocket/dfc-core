"""Safe, blocking Python bindings for dfc-core."""

from __future__ import annotations

import ctypes as C

from . import _native
from .credential import Credential
from .errors import (
    BufferTooSmallError,
    CredentialError,
    DfcError,
    DfcMemoryError,
    InvalidArgumentError,
    ProtocolError,
    UnsupportedError,
)
from .models import (
    Activation,
    Application,
    BuildProfile,
    BuildRole,
    Capabilities,
    Card,
    CredentialModel,
    File,
    Key,
    PiccSettings,
    ReaderState,
    Response,
    Snapshot,
    Transport,
)
from .picc import VirtualPicc
from .reader import Command, Reader


def capabilities() -> Capabilities:
    raw = _native.Capabilities()
    _native.library().dfc_ffi_capabilities(raw)
    feature_names = [field[0] for field in raw._fields_[3:-5] if field[1] is C.c_uint8]
    return Capabilities(
        raw.abi_version,
        raw.build_role,
        raw.build_profile,
        frozenset(name for name in feature_names if getattr(raw, name)),
        raw.max_applications,
        raw.max_files,
        raw.max_keys,
        raw.file_pool_size,
        raw.key_pool_size,
    )


def random_bytes(length: int) -> bytes:
    if length < 0:
        raise ValueError("length cannot be negative")
    result = (C.c_uint8 * max(1, length))()
    _native.raise_status(_native.library().dfc_ffi_random_fill(result, length))
    return bytes(result[:length])


def fixed_time_equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    _left_raw, left_pointer = _native.byte_pointer(left)
    _right_raw, right_pointer = _native.byte_pointer(right)
    return bool(_native.library().dfc_ffi_fixed_time_equal(left_pointer, right_pointer, len(left)))


__all__ = [
    "Activation",
    "Application",
    "BufferTooSmallError",
    "BuildProfile",
    "BuildRole",
    "Capabilities",
    "Card",
    "Command",
    "Credential",
    "CredentialError",
    "CredentialModel",
    "DfcError",
    "DfcMemoryError",
    "File",
    "InvalidArgumentError",
    "Key",
    "PiccSettings",
    "ProtocolError",
    "Reader",
    "ReaderState",
    "Response",
    "Snapshot",
    "Transport",
    "UnsupportedError",
    "VirtualPicc",
    "capabilities",
    "fixed_time_equal",
    "random_bytes",
]
