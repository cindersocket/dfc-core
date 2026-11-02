"""Safe, blocking Python bindings for dfc-core."""

from __future__ import annotations

import ctypes as C

from . import _native
from .credential import Credential
from .crypto import DiversificationAlgorithm, diversify_key
from .errors import (
    BufferTooSmallError,
    CardError,
    CredentialError,
    DfcError,
    DfcMemoryError,
    InvalidArgumentError,
    ProtocolError,
    RandomSourceError,
    UnsupportedError,
)
from .models import (
    Activation,
    Application,
    BuildProfile,
    BuildRole,
    Capabilities,
    Card,
    CommunicationMode,
    CredentialModel,
    File,
    FileType,
    Framing,
    Key,
    PiccAuthenticationMode,
    PiccSettings,
    ReaderAuthenticationMode,
    ReaderState,
    Response,
    Selection,
    Snapshot,
    Transport,
)
from .picc import VirtualPicc
from .reader import Command, Reader, build_iso_append_record_apdu, parse_iso7816_response
from .responses import (
    Access,
    AccessKind,
    AccessRights,
    FileSettings,
    KeySettings,
    ResponseDecodeError,
    Version,
    VersionPart,
    decode_application_ids,
    decode_file_ids,
    decode_file_settings,
    decode_key_settings,
    decode_key_version,
    decode_version,
)
from .sdm import SdmConfig, SdmField, SdmResult, SdmVerificationError, verify_sdm
from .transaction_mac import TransactionMacError, TransactionMacVerifier


def capabilities() -> Capabilities:
    """Read build capabilities from the loaded native library.

    Returns:
        The ABI version, role, profile, enabled features, and model limits.
    """

    raw = _native.Capabilities()
    _native.library().dfc_ffi_capabilities(raw)
    feature_names = [field[0] for field in raw._fields_[3:-5] if field[1] is C.c_uint8]
    return Capabilities(
        raw.abi_version,
        BuildRole(raw.build_role),
        BuildProfile(raw.build_profile),
        frozenset(name for name in feature_names if getattr(raw, name)),
        raw.max_applications,
        raw.max_files,
        raw.max_keys,
        raw.file_pool_size,
        raw.key_pool_size,
    )


def random_bytes(length: int) -> bytes:
    """Return ``length`` bytes from the core's operating-system random source.

    Args:
        length: Number of random bytes to produce.

    Returns:
        Exactly ``length`` bytes.

    Raises:
        ValueError: If ``length`` is negative.
        DfcError: If the operating-system source cannot satisfy the request.
    """

    if length < 0:
        raise ValueError("length cannot be negative")
    result = (C.c_uint8 * max(1, length))()
    _native.raise_status(_native.library().dfc_ffi_random_fill(result, length))
    return bytes(result[:length])


def fixed_time_equal(left: bytes, right: bytes) -> bool:
    """Compare equal-length byte strings without data-dependent early exit.

    Inputs of different lengths return ``False`` without calling the native
    comparison because their lengths are already public to the Python caller.

    Args:
        left: First byte string.
        right: Second byte string.

    Returns:
        ``True`` only when the lengths and contents match.
    """

    if len(left) != len(right):
        return False
    _left_raw, left_pointer = _native.byte_pointer(left)
    _right_raw, right_pointer = _native.byte_pointer(right)
    return bool(_native.library().dfc_ffi_fixed_time_equal(left_pointer, right_pointer, len(left)))


__all__ = [
    "Access",
    "AccessKind",
    "AccessRights",
    "Activation",
    "Application",
    "BufferTooSmallError",
    "BuildProfile",
    "BuildRole",
    "Capabilities",
    "Card",
    "CardError",
    "Command",
    "CommunicationMode",
    "Credential",
    "CredentialError",
    "CredentialModel",
    "DfcError",
    "DfcMemoryError",
    "DiversificationAlgorithm",
    "File",
    "FileSettings",
    "FileType",
    "Framing",
    "InvalidArgumentError",
    "Key",
    "KeySettings",
    "PiccAuthenticationMode",
    "PiccSettings",
    "ProtocolError",
    "RandomSourceError",
    "Reader",
    "ReaderAuthenticationMode",
    "ReaderState",
    "Response",
    "ResponseDecodeError",
    "SdmConfig",
    "SdmField",
    "SdmResult",
    "SdmVerificationError",
    "Selection",
    "Snapshot",
    "TransactionMacError",
    "TransactionMacVerifier",
    "Transport",
    "UnsupportedError",
    "Version",
    "VersionPart",
    "VirtualPicc",
    "build_iso_append_record_apdu",
    "capabilities",
    "decode_application_ids",
    "decode_file_ids",
    "decode_file_settings",
    "decode_key_settings",
    "decode_key_version",
    "decode_version",
    "diversify_key",
    "fixed_time_equal",
    "parse_iso7816_response",
    "random_bytes",
    "verify_sdm",
]
