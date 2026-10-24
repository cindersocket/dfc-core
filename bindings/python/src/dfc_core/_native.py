from __future__ import annotations

import ctypes as C
import operator
import os
import sys
from importlib.resources import files
from pathlib import Path

ABI_VERSION = 4
OK, INVALID_ARGUMENT, BUFFER_TOO_SMALL, OUT_OF_MEMORY, UNSUPPORTED, RANDOM_FAILED = (
    0,
    -1,
    -2,
    -3,
    -4,
    -5,
)
OWNER_PICC = -1
PICC_BUFFER_TOO_SMALL = 3
MESSAGE_MAX = 96
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
    _fields_ = [
        (name, C.c_uint32)
        for name in [
            "capabilities",
            "error",
            "card",
            "picc",
            "application",
            "file",
            "key",
            "activation",
            "snapshot",
            "reader_state",
        ]
    ]


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
            for n in ["value_lower_limit", "value_upper_limit", "value", "value_pending_delta"]
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
            ("ev2_transaction_identifier", C.c_uint8 * 4),
            ("ev2_encryption_key", C.c_uint8 * 16),
            ("ev2_mac_key", C.c_uint8 * 16),
            ("virtual_card_selected", C.c_uint8),
            ("proximity_verified", C.c_uint8),
        ]
    )


class ReaderState(C.Structure):
    _fields_ = [
        ("ev2_command_counter", C.c_uint32),
        ("auth_mode", C.c_uint8),
        ("key_no", C.c_uint8),
        ("ev2_transaction_identifier", C.c_uint8 * 4),
        ("ev2_card_capabilities", C.c_uint8 * 6),
        ("ev2_reader_capabilities", C.c_uint8 * 6),
    ]


STRUCTS = (
    Capabilities,
    Error,
    Card,
    PiccSettings,
    Application,
    File,
    Key,
    Activation,
    Snapshot,
    ReaderState,
)
RANDOM_CALLBACK = C.CFUNCTYPE(C.c_int32, C.c_void_p, P8, C.c_size_t)


def layout_fingerprint() -> int:
    """Mirror dfc_ffi_layout_fingerprint using the active ctypes ABI."""
    value = 14695981039346656037
    mask = (1 << 64) - 1

    def word(number: int) -> None:
        nonlocal value
        for shift in range(0, C.sizeof(C.c_size_t) * 8, 8):
            value ^= (number >> shift) & 0xFF
            value = (value * 1099511628211) & mask

    word(ABI_VERSION)
    entries = (
        (Capabilities, "generation_ev1", "max_applications", "key_pool_size"),
        (Error, "line", "message"),
        (Card, "uid", "hardware_version", "static_signature"),
        (
            PiccSettings,
            "ats",
            "ev2_capabilities",
            "virtual_card_installation_id",
            "dam_auth_key",
            "preferred_auth_command",
        ),
        (Application, "aid", "key_set_versions", "capability_data", "preferred_auth_command"),
        (File, "access_rights", "number", "transaction_mac_key", "previous_reader_id"),
        (Key, "value", "version"),
        (Activation, "uid", "protocol", "rf_detail"),
        (
            Snapshot,
            "selected_aid",
            "ev2_transaction_identifier",
            "ev2_mac_key",
            "proximity_verified",
        ),
        (ReaderState, "auth_mode", "ev2_transaction_identifier", "ev2_reader_capabilities"),
    )
    for structure, *fields in entries:
        word(C.sizeof(structure))
        for field in fields:
            word(getattr(structure, field).offset)
    return value


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
        package_path.parent / "lib" / name,
        package_path / name,
        name,
    ]


def _declare(lib: C.CDLL) -> None:
    lib.dfc_ffi_abi_version.restype = C.c_uint32
    if hasattr(lib, "dfc_ffi_layout_fingerprint"):
        lib.dfc_ffi_layout_fingerprint.restype = C.c_uint64
    lib.dfc_ffi_struct_sizes.argtypes = [C.POINTER(StructSizes)]
    lib.dfc_ffi_capabilities.argtypes = [C.POINTER(Capabilities)]
    for name in ("credential_free", "picc_free"):
        getattr(lib, f"dfc_ffi_{name}").argtypes = [Handle]
    # Pointer-heavy calls use explicit signatures where ctypes conversion matters.
    lib.dfc_ffi_credential_parse_text.argtypes = [
        C.c_char_p,
        C.c_size_t,
        C.POINTER(Handle),
        C.POINTER(Error),
    ]
    lib.dfc_ffi_credential_decode.argtypes = [P8, C.c_size_t, C.POINTER(Handle), C.POINTER(Error)]
    lib.dfc_ffi_credential_load.argtypes = lib.dfc_ffi_credential_decode.argtypes
    for n in ("encode", "write_text"):
        getattr(lib, f"dfc_ffi_credential_{n}").argtypes = [
            Handle,
            C.c_void_p,
            C.c_size_t,
            C.POINTER(C.c_size_t),
        ]
    lib.dfc_ffi_credential_validate.argtypes = [Handle]
    lib.dfc_ffi_credential_get_card.argtypes = [Handle, C.POINTER(Card)]
    lib.dfc_ffi_credential_get_picc.argtypes = [Handle, C.POINTER(PiccSettings)]
    for n in ("application_count", "file_count"):
        getattr(lib, f"dfc_ffi_credential_{n}").argtypes = [Handle]
        getattr(lib, f"dfc_ffi_credential_{n}").restype = C.c_uint32
    lib.dfc_ffi_credential_get_application.argtypes = [Handle, C.c_uint32, C.POINTER(Application)]
    lib.dfc_ffi_credential_get_file.argtypes = [Handle, C.c_uint32, C.POINTER(File)]
    lib.dfc_ffi_credential_get_file_data.argtypes = [
        Handle,
        C.c_uint32,
        P8,
        C.c_size_t,
        C.POINTER(C.c_size_t),
    ]
    lib.dfc_ffi_credential_get_key.argtypes = [
        Handle,
        C.c_int32,
        C.c_uint32,
        C.c_uint32,
        C.POINTER(Key),
    ]
    # A void pointer permits NULL as well as a live CFUNCTYPE callback.
    lib.dfc_ffi_picc_create.argtypes = [Handle, C.c_void_p, C.c_void_p, C.POINTER(Handle)]
    for name, typ in (("activate", Activation), ("snapshot", Snapshot)):
        getattr(lib, f"dfc_ffi_picc_{name}").argtypes = [Handle, C.POINTER(typ)]
    for name in ("exchange", "frame_exchange"):
        getattr(lib, f"dfc_ffi_picc_{name}").argtypes = [
            Handle,
            P8,
            C.c_size_t,
            P8,
            C.c_size_t,
            C.POINTER(C.c_size_t),
        ]
    lib.dfc_ffi_picc_response_capacity.argtypes = []
    lib.dfc_ffi_picc_response_capacity.restype = C.c_size_t
    lib.dfc_ffi_picc_export.argtypes = [Handle, C.POINTER(Handle)]
    lib.dfc_ffi_picc_advance_time.argtypes = [Handle, C.c_uint32]
    lib.dfc_ffi_reader_session_new.argtypes = [C.POINTER(Handle)]
    lib.dfc_ffi_reader_session_new.restype = C.c_int32
    lib.dfc_ffi_reader_session_free.argtypes = [Handle]
    lib.dfc_ffi_reader_session_free.restype = None
    lib.dfc_ffi_reader_session_clear.argtypes = [Handle]
    lib.dfc_ffi_reader_session_clear.restype = None
    lib.dfc_ffi_reader_session_state.argtypes = [Handle, C.POINTER(ReaderState)]
    lib.dfc_ffi_reader_session_state.restype = C.c_int32
    lib.dfc_ffi_reader_exchange_new.argtypes = [C.POINTER(Handle)]
    lib.dfc_ffi_reader_exchange_new.restype = C.c_int32
    lib.dfc_ffi_reader_exchange_free.argtypes = [Handle]
    lib.dfc_ffi_reader_exchange_free.restype = None
    lib.dfc_ffi_reader_authenticate_begin.argtypes = [
        Handle,
        Handle,
        C.c_uint32,
        C.c_uint8,
        C.c_uint8,
        P8,
        C.c_size_t,
        P8,
        C.c_size_t,
    ]
    lib.dfc_ffi_reader_authenticate_begin.restype = C.c_int32
    lib.dfc_ffi_reader_authenticate_iso7816_begin.argtypes = [
        Handle,
        Handle,
        C.c_uint8,
        P8,
        C.c_size_t,
        C.c_uint8,
        P8,
        P8,
        C.c_size_t,
    ]
    lib.dfc_ffi_reader_authenticate_iso7816_begin.restype = C.c_int32
    lib.dfc_ffi_reader_authenticate_ev2_begin.argtypes = [
        Handle,
        Handle,
        C.c_uint32,
        C.c_uint8,
        C.c_uint8,
        P8,
        P8,
        P8,
        C.c_size_t,
    ]
    lib.dfc_ffi_reader_authenticate_ev2_begin.restype = C.c_int32
    lib.dfc_ffi_reader_exchange_begin.argtypes = [
        Handle,
        Handle,
        C.c_uint32,
        C.c_uint8,
        P8,
        C.c_size_t,
        C.c_uint8,
        C.c_int32,
    ]
    lib.dfc_ffi_reader_exchange_begin.restype = C.c_int32
    for name in ("write_data", "write_record"):
        function = getattr(lib, f"dfc_ffi_reader_{name}_begin")
        function.argtypes = [
            Handle,
            Handle,
            C.c_uint32,
            C.c_uint8,
            C.c_uint32,
            P8,
            C.c_size_t,
            C.c_uint8,
        ]
        function.restype = C.c_int32
    lib.dfc_ffi_reader_update_record_begin.argtypes = [
        Handle,
        Handle,
        C.c_uint32,
        C.c_uint8,
        C.c_uint32,
        C.c_uint32,
        P8,
        C.c_size_t,
        C.c_uint8,
    ]
    lib.dfc_ffi_reader_update_record_begin.restype = C.c_int32
    lib.dfc_ffi_reader_create_delegated_application_begin.argtypes = [
        Handle,
        Handle,
        C.c_uint32,
        P8,
        C.c_size_t,
        P8,
        P8,
        P8,
        P8,
        C.c_size_t,
        C.c_uint8,
    ]
    lib.dfc_ffi_reader_create_delegated_application_begin.restype = C.c_int32
    lib.dfc_ffi_reader_step.argtypes = [
        Handle,
        P8,
        C.c_size_t,
        P8,
        C.c_size_t,
        C.POINTER(C.c_size_t),
    ]
    lib.dfc_ffi_reader_step.restype = C.c_int32
    lib.dfc_ffi_reader_result_data.argtypes = [Handle, P8, C.c_size_t, C.POINTER(C.c_size_t)]
    lib.dfc_ffi_reader_result_data.restype = C.c_int32
    lib.dfc_ffi_reader_result_status.argtypes = [Handle]
    lib.dfc_ffi_reader_result_status.restype = C.c_uint8
    lib.dfc_ffi_reader_change_key_cryptogram.argtypes = [
        Handle,
        C.c_uint8,
        P8,
        C.c_size_t,
        P8,
        C.c_uint8,
        C.c_uint8,
        P8,
        C.c_size_t,
        C.POINTER(C.c_size_t),
    ]
    lib.dfc_ffi_reader_change_key_cryptogram.restype = C.c_int32
    lib.dfc_ffi_reader_change_key_ev2_data.argtypes = [
        Handle,
        C.c_uint8,
        C.c_uint8,
        P8,
        P8,
        C.c_uint8,
        P8,
        C.c_size_t,
        C.POINTER(C.c_size_t),
    ]
    lib.dfc_ffi_reader_change_key_ev2_data.restype = C.c_int32


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
            expected = [C.sizeof(t) for t in STRUCTS]
            got = [getattr(actual, n) for n, _ in StructSizes._fields_]
            if got != expected:
                raise ImportError(f"dfc structure layout mismatch: native {got}, Python {expected}")
            if (
                hasattr(lib, "dfc_ffi_layout_fingerprint")
                and lib.dfc_ffi_layout_fingerprint() != layout_fingerprint()
            ):
                raise ImportError("dfc structure field layout fingerprint mismatch")
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


def variable_output(call: object, *args: object) -> bytes:
    size = C.c_size_t()
    status = call(*args, None, 0, C.byref(size))  # type: ignore[operator]
    if status not in (OK, BUFFER_TOO_SMALL):
        raise_status(status)
    out = (C.c_uint8 * max(1, size.value))()
    status = call(*args, out, size.value, C.byref(size))  # type: ignore[operator]
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
