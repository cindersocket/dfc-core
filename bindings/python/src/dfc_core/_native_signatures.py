"""Readable declarations for the flat C ABI used by the Python binding.

ctypes ultimately needs a positional ``argtypes`` list.  Keeping the parameter
names beside their types makes that order reviewable against ``ffi/dfc_ffi.h``
instead of presenting a wall of indistinguishable pointers and integers.
"""

from __future__ import annotations

import ctypes as C
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Parameter:
    """One named C parameter and its ctypes representation."""

    name: str
    ctype: Any


@dataclass(frozen=True)
class Signature:
    """The result and ordered parameters of one exported C function."""

    name: str
    parameters: tuple[Parameter, ...] = ()
    result: Any = C.c_int32


def _parameters(**parameters: Any) -> tuple[Parameter, ...]:
    """Preserve declaration order while making every argument self-describing."""

    return tuple(Parameter(name, ctype) for name, ctype in parameters.items())


def signatures(types: Mapping[str, Any]) -> tuple[Signature, ...]:
    """Return the complete Python declaration of the current public C ABI."""

    handle = types["Handle"]
    pointer = types["P8"]
    size = C.c_size_t
    output_size = C.POINTER(size)
    output_handle = C.POINTER(handle)

    def p(**parameters: Any) -> tuple[Parameter, ...]:
        return _parameters(**parameters)

    library = (
        Signature("dfc_ffi_abi_version", result=C.c_uint32),
        Signature("dfc_ffi_layout_fingerprint", result=C.c_uint64),
        Signature("dfc_ffi_random_fill", p(out=pointer, len=size)),
        Signature(
            "dfc_ffi_fixed_time_equal",
            p(left=pointer, right=pointer, len=size),
            C.c_bool,
        ),
        Signature("dfc_ffi_secure_zero", p(buffer=C.c_void_p, len=size), None),
        Signature(
            "dfc_ffi_capabilities",
            p(out=C.POINTER(types["Capabilities"])),
            None,
        ),
        Signature(
            "dfc_ffi_struct_sizes",
            p(out=C.POINTER(types["StructSizes"])),
            None,
        ),
    )

    standalone = (
        Signature(
            "dfc_ffi_an10922_diversify",
            p(
                algorithm=C.c_uint32,
                master_key=pointer,
                master_key_len=size,
                diversification_input=pointer,
                diversification_input_len=size,
                diversified_key=pointer,
                diversified_key_capacity=size,
                diversified_key_len=output_size,
            ),
        ),
        *(
            Signature(
                f"dfc_ffi_response_decode_{name}",
                p(response=pointer, response_len=size, out=pointer, out_capacity=size),
            )
            for name in ("version", "file_settings", "key_settings")
        ),
        *(
            Signature(
                f"dfc_ffi_response_decode_{name}",
                p(
                    response=pointer,
                    response_len=size,
                    out=pointer,
                    out_capacity=size,
                    out_len=output_size,
                ),
            )
            for name in ("application_ids", "file_ids")
        ),
        Signature(
            "dfc_ffi_response_decode_key_version",
            p(response=pointer, response_len=size, key_version=pointer),
        ),
        Signature(
            "dfc_ffi_sdm_verify_ascii",
            p(
                message=pointer,
                message_len=size,
                fields=C.c_uint32,
                plain_uid_offset=size,
                plain_uid_len=size,
                plain_read_counter_offset=size,
                encrypted_picc_data_offset=size,
                encrypted_picc_data_len=size,
                encrypted_file_data_offset=size,
                encrypted_file_data_len=size,
                mac_input_offset=size,
                mac_offset=size,
                meta_read_key=pointer,
                file_read_key=pointer,
                decrypted_file_data=pointer,
                decrypted_file_data_capacity=size,
                required_decrypted_file_data_len=output_size,
                result=pointer,
                result_capacity=size,
            ),
        ),
        Signature(
            "dfc_ffi_transaction_mac_verifier_new",
            p(
                input_capacity=size,
                key=pointer,
                uid=pointer,
                uid_len=size,
                counter=C.c_uint32,
                out=output_handle,
            ),
        ),
        Signature("dfc_ffi_transaction_mac_verifier_free", p(verifier=handle), None),
        Signature(
            "dfc_ffi_transaction_mac_add_data",
            p(
                verifier=handle,
                command=C.c_uint8,
                file_number=C.c_uint8,
                offset=C.c_uint32,
                length=C.c_uint32,
                data=pointer,
                data_len=size,
            ),
        ),
        Signature(
            "dfc_ffi_transaction_mac_add_record_update",
            p(
                verifier=handle,
                command=C.c_uint8,
                file_number=C.c_uint8,
                record_number=C.c_uint32,
                offset=C.c_uint32,
                length=C.c_uint32,
                data=pointer,
                data_len=size,
            ),
        ),
        Signature(
            "dfc_ffi_transaction_mac_add_value",
            p(verifier=handle, command=C.c_uint8, file_number=C.c_uint8, value=C.c_uint32),
        ),
        Signature(
            "dfc_ffi_transaction_mac_add_clear_record",
            p(verifier=handle, file_number=C.c_uint8),
        ),
        Signature(
            "dfc_ffi_transaction_mac_add_reader_id",
            p(verifier=handle, current_reader_id=pointer, encrypted_previous_reader_id=pointer),
        ),
        Signature(
            "dfc_ffi_transaction_mac_verify",
            p(verifier=handle, mac=pointer, verified=pointer),
        ),
    )

    credential = (
        Signature(
            "dfc_ffi_credential_parse_text",
            p(text=C.c_char_p, len=size, out=output_handle, error=C.POINTER(types["Error"])),
        ),
        Signature(
            "dfc_ffi_credential_decode",
            p(dfcb=pointer, len=size, out=output_handle, error=C.POINTER(types["Error"])),
        ),
        Signature(
            "dfc_ffi_credential_load",
            p(content=pointer, len=size, out=output_handle, error=C.POINTER(types["Error"])),
        ),
        Signature(
            "dfc_ffi_credential_encode",
            p(credential=handle, out=pointer, cap=size, len=output_size),
        ),
        Signature(
            "dfc_ffi_credential_write_text",
            p(
                credential=handle,
                out=C.POINTER(C.c_char),
                cap=size,
                len=output_size,
            ),
        ),
        Signature("dfc_ffi_credential_validate", p(credential=handle)),
        Signature("dfc_ffi_credential_clone", p(credential=handle, out=output_handle)),
        Signature("dfc_ffi_credential_free", p(credential=handle), None),
        Signature(
            "dfc_ffi_credential_get_card",
            p(credential=handle, out=C.POINTER(types["Card"])),
        ),
        Signature(
            "dfc_ffi_credential_get_picc",
            p(credential=handle, out=C.POINTER(types["PiccSettings"])),
        ),
        Signature("dfc_ffi_credential_application_count", p(credential=handle), C.c_uint32),
        Signature(
            "dfc_ffi_credential_get_application",
            p(credential=handle, index=C.c_uint32, out=C.POINTER(types["Application"])),
        ),
        Signature("dfc_ffi_credential_file_count", p(credential=handle), C.c_uint32),
        Signature(
            "dfc_ffi_credential_get_file",
            p(credential=handle, index=C.c_uint32, out=C.POINTER(types["File"])),
        ),
        Signature(
            "dfc_ffi_credential_get_file_data",
            p(credential=handle, index=C.c_uint32, out=pointer, cap=size, len=output_size),
        ),
        Signature(
            "dfc_ffi_credential_get_key",
            p(
                credential=handle,
                owner=C.c_int32,
                key_set=C.c_uint32,
                slot=C.c_uint32,
                out=C.POINTER(types["Key"]),
            ),
        ),
        Signature("dfc_ffi_credential_new", p(out=output_handle)),
        Signature(
            "dfc_ffi_credential_set_card",
            p(credential=handle, card=C.POINTER(types["Card"])),
        ),
        Signature(
            "dfc_ffi_credential_set_picc",
            p(credential=handle, picc=C.POINTER(types["PiccSettings"])),
        ),
        Signature(
            "dfc_ffi_credential_add_application",
            p(
                credential=handle,
                application=C.POINTER(types["Application"]),
                index=C.POINTER(C.c_uint32),
            ),
        ),
        Signature(
            "dfc_ffi_credential_add_file",
            p(credential=handle, file=C.POINTER(types["File"]), index=C.POINTER(C.c_uint32)),
        ),
        Signature(
            "dfc_ffi_credential_set_file_data",
            p(credential=handle, index=C.c_uint32, data=pointer, len=size),
        ),
        Signature(
            "dfc_ffi_credential_set_key",
            p(
                credential=handle,
                owner=C.c_int32,
                key_set=C.c_uint32,
                slot=C.c_uint32,
                key=C.POINTER(types["Key"]),
            ),
        ),
        Signature(
            "dfc_ffi_credential_finish",
            p(credential=handle, error=C.POINTER(types["Error"])),
        ),
    )

    picc = (
        Signature(
            "dfc_ffi_picc_create",
            p(credential=handle, random=C.c_void_p, random_context=C.c_void_p, out=output_handle),
        ),
        Signature(
            "dfc_ffi_picc_create_take",
            p(
                credential=C.POINTER(handle),
                random=C.c_void_p,
                random_context=C.c_void_p,
                out=output_handle,
            ),
        ),
        Signature("dfc_ffi_picc_free", p(picc=handle), None),
        Signature("dfc_ffi_picc_activate", p(picc=handle, out=C.POINTER(types["Activation"]))),
        Signature("dfc_ffi_picc_response_capacity", result=size),
        Signature(
            "dfc_ffi_picc_exchange",
            p(
                picc=handle,
                command=pointer,
                command_len=size,
                response=pointer,
                response_cap=size,
                response_len=output_size,
            ),
        ),
        Signature(
            "dfc_ffi_picc_frame_exchange",
            p(
                picc=handle,
                frame=pointer,
                frame_len=size,
                response=pointer,
                response_cap=size,
                response_len=output_size,
            ),
        ),
        *(
            Signature(f"dfc_ffi_picc_{name}", p(picc=handle))
            for name in ("field_off", "reset_protocol")
        ),
        Signature(
            "dfc_ffi_picc_advance_time",
            p(picc=handle, elapsed_milliseconds=C.c_uint32),
        ),
        Signature("dfc_ffi_picc_snapshot", p(picc=handle, out=C.POINTER(types["Snapshot"]))),
        Signature(
            "dfc_ffi_picc_diagnostic_snapshot",
            p(picc=handle, out=C.POINTER(types["DiagnosticSnapshot"])),
        ),
        Signature("dfc_ffi_picc_export", p(picc=handle, out=output_handle)),
        Signature("dfc_ffi_picc_mark_persisted", p(picc=handle)),
    )

    from ._native_reader_signatures import reader_signatures

    return library + standalone + credential + picc + reader_signatures(types)


def declare(lib: C.CDLL, types: Mapping[str, Any]) -> tuple[Signature, ...]:
    """Apply the named signature registry to one loaded library."""

    registry = signatures(types)
    for signature in registry:
        function = getattr(lib, signature.name)
        function.argtypes = [parameter.ctype for parameter in signature.parameters]
        function.restype = signature.result
    return registry
