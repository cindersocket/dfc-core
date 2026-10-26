"""Private ctypes layouts, library loading, and checked scalar conversion.

Function declarations live in the named registries beside this module.  This
module remains the compatibility facade imported by the public binding.
"""

from __future__ import annotations

import ctypes as C
import operator
import os
import sys
from importlib.resources import files
from pathlib import Path

from ._layout import CONSTANTS as LAYOUT_CONSTANTS
from ._layout import SIZE_FIELDS as LAYOUT_SIZE_FIELDS
from ._layout import STRUCTS as LAYOUT_STRUCTS
from ._layout import VALUES as LAYOUT_VALUES

ABI_VERSION = LAYOUT_VALUES["DFC_FFI_ABI_VERSION"]
OK, INVALID_ARGUMENT, BUFFER_TOO_SMALL, OUT_OF_MEMORY, UNSUPPORTED, RANDOM_FAILED = (
    LAYOUT_VALUES["DFC_FFI_OK"],
    LAYOUT_VALUES["DFC_FFI_INVALID_ARGUMENT"],
    LAYOUT_VALUES["DFC_FFI_BUFFER_TOO_SMALL"],
    LAYOUT_VALUES["DFC_FFI_OUT_OF_MEMORY"],
    LAYOUT_VALUES["DFC_FFI_UNSUPPORTED"],
    LAYOUT_VALUES["DFC_FFI_RANDOM_FAILED"],
)
OWNER_PICC = LAYOUT_VALUES["DFC_FFI_OWNER_PICC"]
PICC_BUFFER_TOO_SMALL = LAYOUT_VALUES["DFC_FFI_PICC_BUFFER_TOO_SMALL"]
READER_PENDING = LAYOUT_VALUES["DFC_FFI_READER_PENDING"]
READER_BUFFER_TOO_SMALL = LAYOUT_VALUES["DFC_FFI_READER_BUFFER_TOO_SMALL"]
READER_CARD_ERROR = LAYOUT_VALUES["DFC_FFI_READER_CARD_ERROR"]
MESSAGE_MAX = LAYOUT_VALUES["DFC_FFI_MESSAGE_MAX"]
AUTH_AES = LAYOUT_VALUES["DFC_FFI_AUTH_AES"]
ISO_AUTH_TDEA2 = LAYOUT_VALUES["DFC_FFI_ISO_AUTH_TDEA2"]
Handle = C.c_void_p
P8 = C.POINTER(C.c_uint8)


class Capabilities(C.Structure):
    _fields_ = (
        [("abi_version", C.c_uint32), ("build_role", C.c_uint32), ("build_profile", C.c_uint32)]
        + [
            (name, C.c_uint8)
            for name in [
                "generation_ev1",
                "generation_ev2",
                "generation_ev3",
                "storage_2k",
                "storage_4k",
                "storage_8k",
                "ev2_secure_messaging",
                "iso7816",
                "transaction_mac",
                "secure_dynamic_messaging",
                "proximity_check",
                "virtual_card",
                "key_sets",
                "delegated_applications",
                "transaction_timer",
                "application_capability_data",
                "static_signature",
                "auth_d40",
                "auth_iso",
                "auth_aes",
                "emulator",
                "reader",
                "der_decoder",
                "der_encoder",
                "text_codec",
            ]
        ]
        + [
            (name, C.c_uint32)
            for name in [
                "max_applications",
                "max_files",
                "max_keys",
                "file_pool_size",
                "key_pool_size",
            ]
        ]
    )


class StructSizes(C.Structure):
    _fields_ = [(name, C.c_uint32) for name, _type_name in LAYOUT_SIZE_FIELDS]


class Error(C.Structure):
    _fields_ = [("status", C.c_int32), ("line", C.c_uint32), ("message", C.c_char * MESSAGE_MAX)]


class Card(C.Structure):
    _fields_ = [
        ("generation", C.c_uint32),
        ("storage", C.c_uint32),
        ("uid_provenance", C.c_uint32),
        ("uid_len", C.c_uint32),
        ("uid", C.c_uint8 * 10),
        ("has_hardware_version", C.c_uint8),
        ("hardware_version", C.c_uint8 * 7),
        ("has_software_version", C.c_uint8),
        ("software_version", C.c_uint8 * 7),
        ("has_static_signature", C.c_uint8),
        ("static_signature", C.c_uint8 * 56),
    ]


class PiccSettings(C.Structure):
    _fields_ = [
        ("num_keys", C.c_uint32),
        ("key_len", C.c_uint32),
        *[
            (n, C.c_uint8)
            for n in [
                "key_settings_1",
                "key_settings_2",
                "auth_command",
                "random_id",
                "random_id_legacy",
                "format_disabled",
                "ats_len",
            ]
        ],
        ("ats", C.c_uint8 * 20),
        ("has_sak", C.c_uint8),
        ("sak", C.c_uint8),
        ("has_atqa", C.c_uint8),
        ("atqa", C.c_uint8 * 2),
        ("has_sm_disable", C.c_uint8),
        ("sm_disable", C.c_uint8),
        ("has_ev2_capabilities", C.c_uint8),
        ("ev2_capabilities", C.c_uint8 * 6),
        ("has_proximity_key", C.c_uint8),
        ("proximity_key", C.c_uint8 * 16),
        ("proximity_option", C.c_uint8),
        ("has_proximity_bitrate", C.c_uint8),
        ("proximity_bitrate", C.c_uint8),
        ("proximity_published_response_time", C.c_uint16),
        ("virtual_card_configured", C.c_uint8),
        ("virtual_card_installation_id_len", C.c_uint8),
        ("virtual_card_installation_id", C.c_uint8 * 16),
        ("virtual_card_information", C.c_uint8),
        ("virtual_card_capabilities", C.c_uint8 * 2),
        ("virtual_card_uid_len", C.c_uint8),
        ("virtual_card_uid", C.c_uint8 * 10),
        ("virtual_card_select_mac_key", C.c_uint8 * 16),
        ("virtual_card_select_encryption_key", C.c_uint8 * 16),
        ("virtual_card_authentication_mandatory", C.c_uint8),
        ("virtual_card_proximity_mandatory", C.c_uint8),
        ("has_dam_keys", C.c_uint8),
        ("dam_auth_key", C.c_uint8 * 16),
        ("dam_mac_key", C.c_uint8 * 16),
        ("dam_encryption_key", C.c_uint8 * 16),
        ("has_auth_commands", C.c_uint8),
        ("auth_commands", C.c_uint8),
        ("has_preferred_auth_command", C.c_uint8),
        ("preferred_auth_command", C.c_uint8),
    ]


class Application(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ["num_keys", "key_len", "df_name_len", "num_key_sets"]] + [
        ("iso_file_id", C.c_uint16),
        ("delegated_slot_number", C.c_uint16),
        ("delegated_quota_limit", C.c_uint16),
        ("delegated_free_blocks", C.c_uint16),
        ("aid", C.c_uint8 * 3),
        ("has_iso_file_id", C.c_uint8),
        ("df_name", C.c_uint8 * 16),
        *[
            (n, C.c_uint8)
            for n in [
                "key_settings_1",
                "key_settings_2",
                "auth_command",
                "key_set_max_size",
                "key_set_settings",
            ]
        ],
        ("key_set_versions", C.c_uint8 * 16),
        ("key_set_types", C.c_uint8 * 16),
        ("key_set_initialized", C.c_uint8 * 16),
        ("has_capability_data", C.c_uint8),
        ("capability_data", C.c_uint8 * 10),
        *[
            (n, C.c_uint8)
            for n in [
                "delegated",
                "delegated_slot_version",
                "delegated_format_disabled",
                "has_auth_commands",
                "auth_commands",
                "has_preferred_auth_command",
                "preferred_auth_command",
                "has_sm_disable",
                "sm_disable",
            ]
        ],
    ]


class File(C.Structure):
    _fields_ = (
        [("owner", C.c_int32)]
        + [(n, C.c_uint32) for n in ["declared_size", "data_len"]]
        + [
            (n, C.c_int32)
            for n in [
                "value_lower_limit",
                "value_upper_limit",
                "value",
                "limited_credit_value",
                "value_pending_delta",
            ]
        ]
        + [
            (n, C.c_uint32)
            for n in [
                "record_size",
                "max_records",
                "record_count",
                "sdm_uid_offset",
                "sdm_counter_offset",
                "sdm_picc_data_offset",
                "sdm_mac_input_offset",
                "sdm_mac_offset",
                "sdm_encrypted_file_offset",
                "sdm_encrypted_file_length",
                "sdm_counter_limit",
                "sdm_read_counter",
                "transaction_counter",
            ]
        ]
        + [
            ("access_rights", C.c_uint16),
            ("iso_file_id", C.c_uint16),
            ("sdm_access_rights", C.c_uint16),
        ]
        + [
            (n, C.c_uint8)
            for n in [
                "number",
                "type",
                "comm_settings",
                "has_iso_file_id",
                "contents_complete",
                "transaction_pending",
                "limited_credit",
                "value_pending",
                "sdm_enabled",
                "sdm_options",
                "sdm_has_uid_offset",
                "sdm_has_counter_offset",
                "sdm_has_picc_data_offset",
                "sdm_has_mac_input_offset",
                "sdm_has_mac_offset",
                "sdm_has_encrypted_file_offset",
                "sdm_has_counter_limit",
                "transaction_mac_key_type",
                "transaction_mac_key_version",
            ]
        ]
        + [
            ("transaction_mac_key", C.c_uint8 * 16),
            ("transaction_mac", C.c_uint8 * 8),
            ("previous_reader_id", C.c_uint8 * 16),
        ]
    )


class Key(C.Structure):
    _fields_ = [("len", C.c_uint32), ("value", C.c_uint8 * 24), ("version", C.c_uint8)]


class Activation(C.Structure):
    _fields_ = [
        (n, C.c_uint32) for n in ["uid_len", "ats_len", "atqa_len", "protocol_len", "rf_detail_len"]
    ] + [
        ("uid", C.c_uint8 * 10),
        ("ats", C.c_uint8 * 20),
        ("atqa", C.c_uint8 * 2),
        ("sak", C.c_uint8),
        ("protocol", C.c_uint8 * 2),
        ("rf_detail", C.c_uint8 * 3),
    ]


class Snapshot(C.Structure):
    _fields_ = (
        [
            ("selected", C.c_uint32),
            ("selected_application_index", C.c_uint32),
            ("ev2_command_counter", C.c_uint32),
            ("selected_aid", C.c_uint8 * 3),
        ]
        + [
            (n, C.c_uint8)
            for n in ["dirty", "auth_mode", "auth_key_no", "ev2_active", "ev2_key_no"]
        ]
        + [
            ("virtual_card_selected", C.c_uint8),
            ("proximity_verified", C.c_uint8),
        ]
    )


class DiagnosticSnapshot(C.Structure):
    """Secret-bearing native state. Keep this out of the public Python API."""

    _fields_ = [
        ("transaction_identifier", C.c_uint8 * 4),
        ("encryption_key", C.c_uint8 * 16),
        ("mac_key", C.c_uint8 * 16),
    ]


class ReaderState(C.Structure):
    _fields_ = [
        ("ev2_command_counter", C.c_uint32),
        ("auth_mode", C.c_uint8),
        ("key_no", C.c_uint8),
        ("ev2_transaction_identifier", C.c_uint8 * 4),
        ("ev2_card_capabilities", C.c_uint8 * 6),
        ("ev2_reader_capabilities", C.c_uint8 * 6),
    ]


RANDOM_CALLBACK = C.CFUNCTYPE(C.c_int32, C.c_void_p, P8, C.c_size_t)


def layout_fingerprint() -> int:
    """Hash the complete generated FFI contract using the active ctypes ABI."""
    value = 14695981039346656037
    mask = (1 << 64) - 1

    def word(number: int) -> None:
        nonlocal value
        for shift in range(0, 64, 8):
            value ^= (number >> shift) & 0xFF
            value = (value * 1099511628211) & mask

    for _name, number in LAYOUT_CONSTANTS:
        word(number & mask)
    for structure_name, fields in LAYOUT_STRUCTS:
        structure = globals()[structure_name]
        word(C.sizeof(structure))
        for field in fields:
            word(getattr(structure, field).offset)
    return value


def require_layout_fingerprint(actual: int) -> None:
    expected = layout_fingerprint()
    if actual != expected:
        raise ImportError(
            "dfc native layout fingerprint mismatch: "
            f"native {actual:#018x}, Python {expected:#018x}"
        )


def _library_candidates() -> list[Path | str]:
    override = os.environ.get("DFC_LIBRARY_PATH")
    if override:
        return [Path(override)]
    name = (
        "dfc.dll"
        if sys.platform == "win32"
        else "libdfc.dylib"
        if sys.platform == "darwin"
        else "libdfc.so"
    )
    package = files("dfc_core")
    package_path = Path(str(package))
    return [
        package_path / "lib" / name,
        package_path / "lib64" / name,
        package_path.parent / "lib" / name,
        package_path.parent / "lib64" / name,
        package_path / name,
        name,
    ]


def _declare(lib: C.CDLL) -> None:
    from ._native_signatures import declare

    try:
        declare(lib, globals())
    except AttributeError as error:
        raise ImportError(f"dfc native library is missing {error.name}") from error


_loaded: C.CDLL | None = None


def library() -> C.CDLL:
    global _loaded
    if _loaded is not None:
        return _loaded
    errors: list[str] = []
    for candidate in _library_candidates():
        try:
            lib = C.CDLL(str(candidate))
            _declare(lib)
            if lib.dfc_ffi_abi_version() != ABI_VERSION:
                raise ImportError(f"dfc ABI {lib.dfc_ffi_abi_version()} is not {ABI_VERSION}")
            actual = StructSizes()
            lib.dfc_ffi_struct_sizes(C.byref(actual))
            expected = [C.sizeof(globals()[type_name]) for _field, type_name in LAYOUT_SIZE_FIELDS]
            got = [getattr(actual, field) for field, _type_name in LAYOUT_SIZE_FIELDS]
            if got != expected:
                raise ImportError(f"dfc structure layout mismatch: native {got}, Python {expected}")
            require_layout_fingerprint(lib.dfc_ffi_layout_fingerprint())
            _loaded = lib
            return lib
        except (OSError, ImportError) as exc:
            errors.append(f"{candidate}: {exc}")
    raise ImportError("could not load a compatible libdfc; " + "; ".join(errors))


def byte_pointer(data: bytes | bytearray | memoryview) -> tuple[C.Array[C.c_uint8], P8]:
    raw = bytes(data)
    array = (C.c_uint8 * max(1, len(raw)))()
    if raw:
        C.memmove(array, raw, len(raw))
    return array, C.cast(array, P8)


def secure_zero(value: C.Array[C.c_uint8]) -> None:
    """Wipe a temporary native byte array owned by the Python binding."""
    library().dfc_ffi_secure_zero(C.cast(value, C.c_void_p), C.sizeof(value))


def variable_output(call: object, *args: object) -> bytes:
    size = C.c_size_t()
    status = call(*args, None, 0, C.byref(size))  # type: ignore[operator]
    if status not in (OK, BUFFER_TOO_SMALL):
        raise_status(status)
    out = (C.c_uint8 * max(1, size.value))()
    output_type = call.argtypes[-3]  # type: ignore[attr-defined]
    output = C.cast(out, output_type)
    status = call(*args, output, size.value, C.byref(size))  # type: ignore[operator]
    raise_status(status)
    return bytes(out[: size.value])


def _integer(value: int, name: str) -> int:
    from .errors import InvalidArgumentError

    try:
        return operator.index(value)
    except TypeError as error:
        raise InvalidArgumentError(-1, f"{name} must be an integer") from error


def unsigned(value: int, bits: int, name: str) -> int:
    """Return ``value`` unchanged if it fits an unsigned ``bits``-wide native parameter.

    ctypes truncates silently, so ``comm_mode=256`` would reach the core as 0 (plain).
    A value that does not fit is refused as ``InvalidArgumentError`` instead.
    """
    from .errors import InvalidArgumentError

    number = _integer(value, name)
    if not 0 <= number < 1 << bits:
        raise InvalidArgumentError(-1, f"{name} does not fit an unsigned {bits}-bit integer")
    return number


def signed(value: int, bits: int, name: str) -> int:
    """Return ``value`` unchanged if it fits a signed ``bits``-wide native parameter."""
    from .errors import InvalidArgumentError

    number = _integer(value, name)
    limit = 1 << (bits - 1)
    if not -limit <= number < limit:
        raise InvalidArgumentError(-1, f"{name} does not fit a signed {bits}-bit integer")
    return number


def raise_status(status: int) -> None:
    if status != OK:
        from .errors import exception_for_status

        raise exception_for_status(status)
