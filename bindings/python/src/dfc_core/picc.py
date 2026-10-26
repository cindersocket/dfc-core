from __future__ import annotations

import ctypes as C
import sys
import threading
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Self

from . import _native as N
from .credential import Credential
from .errors import RandomSourceError
from .models import Activation, PiccAuthenticationMode, Selection, Snapshot

_INITIAL_RESPONSE_CAPACITY = 256


def _retry_capacity(reported: int) -> int | None:
    """Accept one native capacity only when it can grow the initial buffer safely."""
    return reported if _INITIAL_RESPONSE_CAPACITY < reported <= sys.maxsize else None


class VirtualPicc:
    """An owned virtual PICC.

    Construction transfers ``credential`` into the card on success. A failed
    construction leaves the credential owned by its caller. Pass ``random``
    only for deterministic testing; it must return exactly the requested
    number of bytes. Callback failures surface from the later operation that
    requests randomness, rather than from construction.
    """

    def __init__(
        self, credential: Credential, random: Callable[[int], bytes] | None = None
    ) -> None:
        """Create a virtual card and transfer ``credential`` on success.

        Args:
            credential: Owned credential to move into the native card.
            random: Optional deterministic source for tests. It must return the
                exact requested byte count.

        Raises:
            DfcError: If native card construction fails. The caller retains the
                credential when construction fails.
        """

        self._lock = threading.RLock()
        self._lifetime_lock = threading.Lock()
        self._closed = False
        self._active_calls = 0
        self._callback_error: BaseException | None = None
        self._callback = N.RANDOM_CALLBACK(self._random_callback) if random else None
        self._random = random
        callback_pointer = C.cast(self._callback, C.c_void_p) if self._callback else None
        out = N.Handle()
        with credential._lock:
            source = credential._open()
            moving = N.Handle(source.value)
            status = N.library().dfc_ffi_picc_create_take(
                C.byref(moving), callback_pointer, None, C.byref(out)
            )
            if status == 0:
                credential._finalizer.detach()
                credential._handle = N.Handle()
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
        with self._lifetime_lock:
            if self._closed:
                raise RuntimeError("virtual PICC is closed")
            return N.Handle(self._handle.value)

    @contextmanager
    def _lease(self) -> Iterator[N.Handle]:
        with self._lifetime_lock:
            if self._closed:
                raise RuntimeError("virtual PICC is closed")
            self._active_calls += 1
            handle = N.Handle(self._handle.value)
        try:
            yield handle
        finally:
            finalize = False
            with self._lifetime_lock:
                self._active_calls -= 1
                finalize = self._closed and self._active_calls == 0
            if finalize:
                self._finalizer()

    def _check_callback(self) -> None:
        if self._callback_error is not None:
            error, self._callback_error = self._callback_error, None
            raise RandomSourceError(N.RANDOM_FAILED, "virtual PICC random source failed") from error

    def close(self) -> None:
        """Release the card after any in-flight operation finishes.

        New operations fail as soon as closing begins. Repeated calls are safe.
        """

        with self._lifetime_lock:
            if self._closed:
                return
            self._closed = True
            self._handle = N.Handle()
            finalize = self._active_calls == 0
        if finalize:
            self._finalizer()

    def __enter__(self) -> Self:
        self._open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def activate(self) -> Activation:
        """Read the card's activation data without changing protocol state.

        Returns:
            UID, ATS, ATQA, SAK, protocol, and RF-detail bytes.

        Raises:
            RuntimeError: If the virtual card is closed.
            DfcError: If native activation fails.
        """

        with self._lock, self._lease() as handle:
            value = N.Activation()
            status = N.library().dfc_ffi_picc_activate(handle, C.byref(value))
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
        with self._lock, self._lease() as handle:
            _raw, pointer = N.byte_pointer(content)
            initial_capacity = _INITIAL_RESPONSE_CAPACITY
            output = (C.c_uint8 * initial_capacity)()
            length = C.c_size_t()
            library = N.library()
            call = getattr(library, f"dfc_ffi_picc_{name}")
            status = call(handle, pointer, len(content), output, len(output), C.byref(length))
            self._check_callback()
            if status == N.PICC_BUFFER_TOO_SMALL:
                capacity = _retry_capacity(library.dfc_ffi_picc_response_capacity())
                # A retry is useful only when the native contract reports a larger,
                # representable buffer. One retry keeps stale libraries bounded.
                if capacity is None:
                    N.raise_status(status)
                    raise AssertionError("buffer-too-small status unexpectedly accepted")
                try:
                    output = (C.c_uint8 * capacity)()
                except (MemoryError, OverflowError):
                    N.raise_status(N.OUT_OF_MEMORY)
                length.value = 0
                status = call(handle, pointer, len(content), output, len(output), C.byref(length))
                self._check_callback()
            N.raise_status(status)
            if length.value > len(output):
                N.raise_status(N.INVALID_ARGUMENT)
            return bytes(output[: length.value])

    def exchange(self, command: bytes) -> bytes:
        """Exchange one complete native command or ISO 7816 APDU.

        Args:
            command: Unframed native command or complete ISO 7816 APDU.

        Returns:
            Native status plus data, or a complete ISO 7816 response APDU.

        Raises:
            RandomSourceError: If the configured random callback fails or has
                the wrong output length during this operation.
            RuntimeError: If the virtual card is closed.
            DfcError: If protocol processing fails.
        """

        return self._exchange("exchange", command)

    def transceive(self, command: bytes) -> bytes:
        """Exchange reader framing bytes as a blocking transport.

        Args:
            command: Bytes emitted by ``Reader`` in its configured framing.

        Returns:
            Response bytes in the same framing convention.

        Raises:
            RandomSourceError: If a random-using operation fails its callback.
            RuntimeError: If the virtual card is closed.
            DfcError: If protocol processing fails.
        """
        return self.exchange(command)

    def frame_exchange(self, frame: bytes) -> bytes:
        """Exchange one complete ISO-DEP block.

        Args:
            frame: Complete ISO-DEP block, including its PCB byte.

        Returns:
            One complete ISO-DEP response block.

        Raises:
            RandomSourceError: If a random-using operation fails its callback.
            RuntimeError: If the virtual card is closed.
            DfcError: If frame processing fails.
        """

        return self._exchange("frame_exchange", frame)

    def _simple(self, name: str, *args: int) -> None:
        with self._lock, self._lease() as handle:
            N.raise_status(getattr(N.library(), f"dfc_ffi_picc_{name}")(handle, *args))

    def field_off(self) -> None:
        """End the RF session and clear transient protocol state.

        Raises:
            RuntimeError: If the virtual card is closed.
            DfcError: If native processing fails.
        """

        self._simple("field_off")

    def reset_protocol(self) -> None:
        """Reset protocol state while retaining the persistent model.

        Raises:
            RuntimeError: If the virtual card is closed.
            DfcError: If native processing fails.
        """

        self._simple("reset_protocol")

    def advance_time(self, milliseconds: int) -> None:
        """Advance the card timer by a nonnegative duration.

        Args:
            milliseconds: Elapsed time in milliseconds, limited to unsigned 32 bits.

        Raises:
            InvalidArgumentError: If the duration is out of range.
            RuntimeError: If the virtual card is closed.
        """

        self._simple("advance_time", N.unsigned(milliseconds, 32, "milliseconds"))

    def mark_persisted(self) -> None:
        """Mark the current model clean after persisting an export.

        Raises:
            RuntimeError: If the virtual card is closed.
            DfcError: If native processing fails.
        """

        self._simple("mark_persisted")

    def snapshot(self) -> Snapshot:
        """Read non-secret selection, authentication, and transaction state.

        Returns:
            A Python-owned state snapshot. Inactive optional fields are ``None``
            and inactive byte fields are empty.

        Raises:
            RuntimeError: If the virtual card is closed.
            DfcError: If native state cannot be read.
        """

        with self._lock, self._lease() as handle:
            s = N.Snapshot()
            N.raise_status(N.library().dfc_ffi_picc_snapshot(handle, C.byref(s)))
            selection = Selection(s.selected)
            authentication = PiccAuthenticationMode(s.auth_mode) if s.auth_mode else None
            application_selected = selection is Selection.APPLICATION
            ev2_active = bool(s.ev2_active)
            return Snapshot(
                selection,
                s.selected_application_index if application_selected else None,
                bytes(s.selected_aid) if application_selected else b"",
                bool(s.dirty),
                authentication,
                s.auth_key_no if authentication is not None else None,
                s.ev2_key_no if ev2_active else None,
                s.ev2_command_counter if ev2_active else None,
                bool(s.virtual_card_selected),
                bool(s.proximity_verified),
            )

    @contextmanager
    def _diagnostic_snapshot(
        self,
    ) -> Iterator[tuple[bytearray, bytearray, bytearray]]:
        """Yield secret state for conformance tests and clear every mutable copy."""
        with self._lock, self._lease() as handle:
            native = N.DiagnosticSnapshot()
            values: tuple[bytearray, bytearray, bytearray] | None = None
            try:
                N.raise_status(
                    N.library().dfc_ffi_picc_diagnostic_snapshot(handle, C.byref(native))
                )
                values = (
                    bytearray(native.transaction_identifier),
                    bytearray(native.encryption_key),
                    bytearray(native.mac_key),
                )
                yield values
            finally:
                if values is not None:
                    for value in values:
                        value[:] = b"\0" * len(value)
                N.library().dfc_ffi_secure_zero(C.byref(native), C.sizeof(native))

    def export(self) -> Credential:
        """Copy the card's current model into a credential.

        Returns:
            A newly owned credential that must be closed.

        Raises:
            RuntimeError: If the virtual card is closed.
            DfcError: If the model cannot be copied.
        """

        with self._lock, self._lease() as handle:
            out = N.Handle()
            N.raise_status(N.library().dfc_ffi_picc_export(handle, C.byref(out)))
            return Credential(out)
