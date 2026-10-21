from __future__ import annotations

import ctypes as C
import threading
import weakref
from collections.abc import Callable
from typing import Any, Self

from . import _native as N
from .credential import Credential
from .models import Activation, Snapshot


class VirtualPicc:
    """An owned virtual PICC. Creating it consumes ``credential`` on success."""

    def __init__(
        self, credential: Credential, random: Callable[[int], bytes] | None = None
    ) -> None:
        self._lock = threading.RLock()
        self._callback_error: BaseException | None = None
        self._callback = N.RANDOM_CALLBACK(self._random_callback) if random else None
        self._random = random
        callback_pointer = C.cast(self._callback, C.c_void_p) if self._callback else None
        out = N.Handle()
        with credential._lock:
            source = credential._open()
            if hasattr(N.library(), "dfc_ffi_picc_create_take"):
                N.library().dfc_ffi_picc_create_take.argtypes = [
                    C.POINTER(N.Handle),
                    C.c_void_p,
                    C.c_void_p,
                    C.POINTER(N.Handle),
                ]
                moving = N.Handle(source.value)
                status = N.library().dfc_ffi_picc_create_take(
                    C.byref(moving), callback_pointer, None, C.byref(out)
                )
                if status == 0:
                    credential._finalizer.detach()
                    credential._handle = N.Handle()
            else:
                status = N.library().dfc_ffi_picc_create(
                    source, callback_pointer, None, C.byref(out)
                )
        N.raise_status(status)
        self._handle = out
        self._finalizer = weakref.finalize(self, N.library().dfc_ffi_picc_free, out)

    def _random_callback(self, _context: int, buffer: Any, length: int) -> int:
        try:
            assert self._random is not None
            result = self._random(length)
            if len(result) != length:
                raise ValueError(f"random source returned {len(result)} bytes, expected {length}")
            C.memmove(buffer, result, length)
            return 0
        except BaseException as exc:  # noqa: BLE001, nothing may unwind through C
            self._callback_error = exc
            return -5

    def _open(self) -> N.Handle:
        if not self._finalizer.alive:
            raise RuntimeError("virtual PICC is closed")
        return self._handle

    def _check_callback(self) -> None:
        if self._callback_error is not None:
            error, self._callback_error = self._callback_error, None
            raise RuntimeError("virtual PICC random source failed") from error

    def close(self) -> None:
        with self._lock:
            self._finalizer()

    def __enter__(self) -> Self:
        self._open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def activate(self) -> Activation:
        with self._lock:
            value = N.Activation()
            status = N.library().dfc_ffi_picc_activate(self._open(), C.byref(value))
            self._check_callback()
            N.raise_status(status)
            return Activation(
                bytes(value.uid[: value.uid_len]),
                bytes(value.ats[: value.ats_len]),
                bytes(value.atqa[: value.atqa_len]),
                value.sak,
                bytes(value.protocol[: value.protocol_len]),
                bytes(value.rf_detail[: value.rf_detail_len]),
            )

    def _exchange(self, name: str, content: bytes) -> bytes:
        with self._lock:
            _raw, pointer = N.byte_pointer(content)
            output = (C.c_uint8 * 4096)()
            length = C.c_size_t()
            status = getattr(N.library(), f"dfc_ffi_picc_{name}")(
                self._open(), pointer, len(content), output, len(output), C.byref(length)
            )
            self._check_callback()
            N.raise_status(status)
            return bytes(output[: length.value])

    def exchange(self, command: bytes) -> bytes:
        return self._exchange("exchange", command)

    def transceive(self, command: bytes) -> bytes:
        """Use this PICC directly as a blocking reader transport."""
        return self.exchange(command)

    def frame_exchange(self, frame: bytes) -> bytes:
        return self._exchange("frame_exchange", frame)

    def _simple(self, name: str, *args: int) -> None:
        with self._lock:
            N.raise_status(getattr(N.library(), f"dfc_ffi_picc_{name}")(self._open(), *args))

    def field_off(self) -> None:
        self._simple("field_off")

    def reset_protocol(self) -> None:
        self._simple("reset_protocol")

    def advance_time(self, milliseconds: int) -> None:
        self._simple("advance_time", milliseconds)

    def mark_persisted(self) -> None:
        self._simple("mark_persisted")

    def snapshot(self) -> Snapshot:
        with self._lock:
            s = N.Snapshot()
            N.raise_status(N.library().dfc_ffi_picc_snapshot(self._open(), C.byref(s)))
            return Snapshot(
                s.selected,
                s.selected_application_index,
                bytes(s.selected_aid),
                bool(s.dirty),
                s.auth_mode,
                s.auth_key_no,
                bool(s.ev2_active),
                s.ev2_key_no,
                s.ev2_command_counter,
                bytes(s.ev2_transaction_identifier),
                bytes(s.ev2_encryption_key),
                bytes(s.ev2_mac_key),
                bool(s.virtual_card_selected),
                bool(s.proximity_verified),
            )

    def export(self) -> Credential:
        with self._lock:
            out = N.Handle()
            N.raise_status(N.library().dfc_ffi_picc_export(self._open(), C.byref(out)))
            return Credential(out)
