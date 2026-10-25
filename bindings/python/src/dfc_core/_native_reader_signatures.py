"""Named ctypes declarations for the reader portion of the public ABI."""

from __future__ import annotations

import ctypes as C
from collections.abc import Mapping
from typing import Any


def reader_signatures(types: Mapping[str, Any]) -> tuple[Any, ...]:
    """Build reader declarations without coupling this module to ctypes structs."""

    from ._native_signatures import Signature, _parameters

    handle = types["Handle"]
    pointer = types["P8"]
    size = C.c_size_t
    output_size = C.POINTER(size)
    output_handle = C.POINTER(handle)

    def p(**parameters: Any) -> tuple[Any, ...]:
        return _parameters(**parameters)

    return (
        Signature("dfc_ffi_reader_session_new", p(out=output_handle)),
        Signature("dfc_ffi_reader_session_free", p(session=handle), None),
        Signature("dfc_ffi_reader_session_clear", p(session=handle), None),
        Signature(
            "dfc_ffi_reader_session_state",
            p(session=handle, out=C.POINTER(types["ReaderState"])),
        ),
        Signature("dfc_ffi_reader_exchange_new", p(out=output_handle)),
        Signature("dfc_ffi_reader_exchange_free", p(exchange=handle), None),
        Signature(
            "dfc_ffi_reader_authenticate_begin",
            p(
                exchange=handle,
                session=handle,
                framing=C.c_uint32,
                cipher=C.c_uint8,
                key_no=C.c_uint8,
                key=pointer,
                key_len=size,
                random_a=pointer,
                random_a_len=size,
            ),
        ),
        Signature(
            "dfc_ffi_reader_authenticate_iso7816_begin",
            p(
                exchange=handle,
                session=handle,
                key_reference=C.c_uint8,
                key=pointer,
                key_len=size,
                algorithm=C.c_uint8,
                random_first=pointer,
                random_second=pointer,
                random_len=size,
            ),
        ),
        Signature(
            "dfc_ffi_reader_authenticate_ev2_begin",
            p(
                exchange=handle,
                session=handle,
                framing=C.c_uint32,
                first=C.c_uint8,
                key_no=C.c_uint8,
                key=pointer,
                random_a=pointer,
                capabilities=pointer,
                capabilities_len=size,
            ),
        ),
        Signature(
            "dfc_ffi_reader_exchange_begin",
            p(
                exchange=handle,
                session=handle,
                framing=C.c_uint32,
                ins=C.c_uint8,
                data=pointer,
                data_len=size,
                comm_mode=C.c_uint8,
                header_len=C.c_int32,
            ),
        ),
        *(
            Signature(
                f"dfc_ffi_reader_{name}_begin",
                p(
                    exchange=handle,
                    session=handle,
                    framing=C.c_uint32,
                    file_number=C.c_uint8,
                    offset=C.c_uint32,
                    data=pointer,
                    data_len=size,
                    comm_mode=C.c_uint8,
                ),
            )
            for name in ("write_data", "write_record")
        ),
        Signature(
            "dfc_ffi_reader_update_record_begin",
            p(
                exchange=handle,
                session=handle,
                framing=C.c_uint32,
                file_number=C.c_uint8,
                record_number=C.c_uint32,
                offset=C.c_uint32,
                data=pointer,
                data_len=size,
                comm_mode=C.c_uint8,
            ),
        ),
        Signature(
            "dfc_ffi_reader_create_delegated_application_begin",
            p(
                exchange=handle,
                session=handle,
                framing=C.c_uint32,
                header=pointer,
                header_len=size,
                dam_encryption_key=pointer,
                dam_mac_key=pointer,
                random_prefix=pointer,
                initial_key=pointer,
                initial_key_len=size,
                initial_version=C.c_uint8,
            ),
        ),
        Signature(
            "dfc_ffi_reader_step",
            p(
                exchange=handle,
                response=pointer,
                response_len=size,
                out=pointer,
                out_cap=size,
                out_len=output_size,
            ),
        ),
        Signature("dfc_ffi_reader_result_status", p(exchange=handle), C.c_uint8),
        Signature(
            "dfc_ffi_reader_result_data",
            p(exchange=handle, out=pointer, cap=size, len=output_size),
        ),
        Signature(
            "dfc_ffi_reader_change_key_cryptogram",
            p(
                session=handle,
                key_no=C.c_uint8,
                new_key=pointer,
                key_len=size,
                current_key=pointer,
                aes_key=C.c_uint8,
                new_version=C.c_uint8,
                out=pointer,
                out_cap=size,
                out_len=output_size,
            ),
        ),
        Signature(
            "dfc_ffi_reader_change_key_ev2_data",
            p(
                session=handle,
                key_set_no=C.c_uint8,
                key_no=C.c_uint8,
                new_key=pointer,
                current_key=pointer,
                new_version=C.c_uint8,
                out=pointer,
                out_cap=size,
                out_len=output_size,
            ),
        ),
    )
