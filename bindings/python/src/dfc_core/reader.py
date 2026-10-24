from __future__ import annotations

import ctypes as C
import secrets
import threading
import weakref
from dataclasses import dataclass
from typing import Self

from . import _native as N
from .errors import CardError
from .models import ReaderState, Response, Transport

READER_PENDING = 1
READER_BUFFER_TOO_SMALL = 3
READER_CARD_ERROR = 6
INITIAL_OUTPUT_CAPACITY = 64


@dataclass(frozen=True, slots=True)
class Command:
    instruction: int
    data: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.instruction <= 255:
            raise ValueError("instruction must fit in one byte")

    @classmethod
    def select_application(cls, aid: bytes) -> Command:
        if len(aid) != 3:
            raise ValueError("AID must be three bytes")
        # Credential files and APIs use the human-readable AID order. The
        # protocol carries the three-byte value least-significant byte first.
        return cls(0x5A, aid[::-1])

    @classmethod
    def get_version(cls) -> Command:
        return cls(0x60)

    @classmethod
    def get_free_memory(cls) -> Command:
        return cls(0x6E)

    @classmethod
    def get_key_settings(cls) -> Command:
        return cls(0x45)

    @classmethod
    def get_application_ids(cls) -> Command:
        return cls(0x6A)

    @classmethod
    def get_file_ids(cls) -> Command:
        return cls(0x6F)

    @classmethod
    def get_card_uid(cls) -> Command:
        return cls(0x51)

    @classmethod
    def commit_transaction(cls, option: int | None = None) -> Command:
        return cls(0xC7, b"" if option is None else bytes((option,)))

    @classmethod
    def abort_transaction(cls) -> Command:
        return cls(0xA7)

    @classmethod
    def file_operation(cls, instruction: int, file_number: int) -> Command:
        if not 0 <= file_number <= 31:
            raise ValueError("file number must be between 0 and 31")
        return cls(instruction, bytes((file_number,)))

    @classmethod
    def read_data(cls, file_number: int, offset: int, length: int) -> Command:
        if not 0 <= file_number <= 31 or not 0 <= offset < 1 << 24 or not 0 <= length < 1 << 24:
            raise ValueError("read-data field is out of range")
        return cls(
            0xBD,
            bytes((file_number,)) + offset.to_bytes(3, "little") + length.to_bytes(3, "little"),
        )


class Reader:
    def __init__(self, transport: Transport, framing: int = 0) -> None:
        self.transport, self.framing = transport, framing
        self._lock = threading.RLock()
        self._in_transport_callback = False
        self._session, self._exchange = N.Handle(), N.Handle()
        lib = N.library()
        N.raise_status(lib.dfc_ffi_reader_session_new(C.byref(self._session)))
        try:
            N.raise_status(lib.dfc_ffi_reader_exchange_new(C.byref(self._exchange)))
        except BaseException:
            lib.dfc_ffi_reader_session_free(self._session)
            raise
        self._finalizer = weakref.finalize(self, self._free, lib, self._session, self._exchange)

    @staticmethod
    def _free(lib: C.CDLL, session: N.Handle, exchange: N.Handle) -> None:
        lib.dfc_ffi_reader_exchange_free(exchange)
        lib.dfc_ffi_reader_session_free(session)

    def _open(self) -> None:
        if self._in_transport_callback:
            raise RuntimeError("reader transport callback is active")
        if not self._finalizer.alive:
            raise RuntimeError("reader is closed")

    def _native_framing(self) -> int:
        return N.unsigned(self.framing, 32, "framing")

    def close(self) -> None:
        with self._lock:
            self._finalizer()
            self._session = N.Handle()
            self._exchange = N.Handle()

    def __enter__(self) -> Self:
        self._open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def state(self) -> ReaderState:
        with self._lock:
            self._open()
            s = N.ReaderState()
            N.raise_status(N.library().dfc_ffi_reader_session_state(self._session, C.byref(s)))
            return ReaderState(
                s.auth_mode,
                s.key_no,
                s.ev2_command_counter,
                bytes(s.ev2_transaction_identifier),
                bytes(s.ev2_card_capabilities),
                bytes(s.ev2_reader_capabilities),
            )

    def clear(self) -> None:
        with self._lock:
            self._open()
            N.library().dfc_ffi_reader_session_clear(self._session)

    def _run(self) -> Response:
        with self._lock:
            self._open()
            answer = b""
            while True:
                _raw, pointer = N.byte_pointer(answer)
                capacity, length = INITIAL_OUTPUT_CAPACITY, C.c_size_t()
                out = (C.c_uint8 * capacity)()
                while True:
                    status = N.library().dfc_ffi_reader_step(
                        self._exchange, pointer, len(answer), out, capacity, C.byref(length)
                    )
                    if status != READER_BUFFER_TOO_SMALL:
                        break
                    capacity *= 2
                    out = (C.c_uint8 * capacity)()
                if status == READER_PENDING:
                    try:
                        self._in_transport_callback = True
                        try:
                            answer = bytes(self.transport.transceive(bytes(out[: length.value])))
                        finally:
                            self._in_transport_callback = False
                    except BaseException:
                        if self._finalizer.alive:
                            self.clear()
                        raise
                    self._open()
                    continue
                if status == READER_CARD_ERROR:
                    raise CardError(
                        status, N.library().dfc_ffi_reader_result_status(self._exchange)
                    )
                N.raise_status(status)
                data = N.variable_output(N.library().dfc_ffi_reader_result_data, self._exchange)
                return Response(N.library().dfc_ffi_reader_result_status(self._exchange), data)

    def exchange(self, command: Command, comm_mode: int = 0, header_len: int = -1) -> Response:
        """Exchange one command.

        ``header_len`` is -1 to derive the clear header, or a non-negative
        length accepted by the native reader.
        """
        clear_header_length = N.signed(header_len, 32, "header_len")
        comm = N.unsigned(comm_mode, 8, "comm_mode")
        framing = self._native_framing()
        with self._lock:
            self._open()
            _raw, pointer = N.byte_pointer(command.data)
            status = N.library().dfc_ffi_reader_exchange_begin(
                self._exchange,
                self._session,
                framing,
                N.unsigned(command.instruction, 8, "instruction"),
                pointer,
                len(command.data),
                comm,
                clear_header_length,
            )
            N.raise_status(status)
            return self._run()

    def authenticate(
        self, cipher: int, key_no: int, key: bytes, random_a: bytes | None = None
    ) -> Response:
        cipher_id = N.unsigned(cipher, 8, "cipher")
        key_number = N.unsigned(key_no, 8, "key_no")
        framing = self._native_framing()
        challenge = bytearray(
            random_a or secrets.token_bytes(16 if cipher_id == N.AUTH_AES or len(key) == 24 else 8)
        )
        keybuf, keyptr = N.byte_pointer(key)
        randbuf, randptr = N.byte_pointer(challenge)
        try:
            with self._lock:
                self._open()
                status = N.library().dfc_ffi_reader_authenticate_begin(
                    self._exchange,
                    self._session,
                    framing,
                    cipher_id,
                    key_number,
                    keyptr,
                    len(key),
                    randptr,
                    len(challenge),
                )
                N.raise_status(status)
                return self._run()
        finally:
            C.memset(randbuf, 0, len(challenge))
            C.memset(keybuf, 0, len(key))

    def authenticate_ev2(
        self,
        key_no: int,
        key: bytes,
        *,
        first: bool = True,
        random_a: bytes | None = None,
        capabilities: bytes = b"",
    ) -> Response:
        key_number = N.unsigned(key_no, 8, "key_no")
        framing = self._native_framing()
        challenge = bytearray(random_a or secrets.token_bytes(16))
        kb, kp = N.byte_pointer(key)
        rb, rp = N.byte_pointer(challenge)
        _cb, cp = N.byte_pointer(capabilities)
        try:
            with self._lock:
                self._open()
                status = N.library().dfc_ffi_reader_authenticate_ev2_begin(
                    self._exchange,
                    self._session,
                    framing,
                    int(first),
                    key_number,
                    kp,
                    rp,
                    cp if capabilities else None,
                    len(capabilities),
                )
                N.raise_status(status)
                return self._run()
        finally:
            C.memset(kb, 0, len(key))
            C.memset(rb, 0, len(challenge))

    def authenticate_iso7816(
        self,
        key_reference: int,
        algorithm: int,
        key: bytes,
        random_first: bytes | None = None,
        random_second: bytes | None = None,
    ) -> Response:
        key_ref = N.unsigned(key_reference, 8, "key_reference")
        algorithm_id = N.unsigned(algorithm, 8, "algorithm")
        length = 8 if algorithm_id == N.ISO_AUTH_TDEA2 else 16
        first = bytearray(random_first or secrets.token_bytes(length))
        second = bytearray(random_second or secrets.token_bytes(length))
        if len(first) != length or len(second) != length:
            raise ValueError(f"algorithm requires {length}-byte challenges")
        kb, kp = N.byte_pointer(key)
        fb, fp = N.byte_pointer(first)
        sb, sp = N.byte_pointer(second)
        try:
            with self._lock:
                self._open()
                status = N.library().dfc_ffi_reader_authenticate_iso7816_begin(
                    self._exchange,
                    self._session,
                    key_ref,
                    kp,
                    len(key),
                    algorithm_id,
                    fp,
                    sp,
                    length,
                )
                N.raise_status(status)
                return self._run()
        finally:
            C.memset(kb, 0, len(key))
            C.memset(fb, 0, length)
            C.memset(sb, 0, length)

    def create_delegated_application(
        self,
        header: bytes,
        dam_encryption_key: bytes,
        dam_mac_key: bytes,
        random_prefix: bytes,
        initial_key: bytes,
        initial_version: int,
    ) -> Response:
        version = N.unsigned(initial_version, 8, "initial_version")
        framing = self._native_framing()
        values = [
            N.byte_pointer(v)
            for v in (header, dam_encryption_key, dam_mac_key, random_prefix, initial_key)
        ]
        try:
            with self._lock:
                self._open()
                status = N.library().dfc_ffi_reader_create_delegated_application_begin(
                    self._exchange,
                    self._session,
                    framing,
                    values[0][1],
                    len(header),
                    values[1][1],
                    values[2][1],
                    values[3][1],
                    values[4][1],
                    len(initial_key),
                    version,
                )
                N.raise_status(status)
                return self._run()
        finally:
            for (buffer, _), value in zip(
                values, (header, dam_encryption_key, dam_mac_key, random_prefix, initial_key)
            ):
                C.memset(buffer, 0, len(value))

    def change_key_cryptogram(
        self, key_no: int, new_key: bytes, current_key: bytes, *, aes_key: bool, new_version: int
    ) -> bytes:
        key_number = N.unsigned(key_no, 8, "key_no")
        version = N.unsigned(new_version, 8, "new_version")
        new, newp = N.byte_pointer(new_key)
        old, oldp = N.byte_pointer(current_key)
        try:
            with self._lock:
                self._open()
                return N.variable_output(
                    N.library().dfc_ffi_reader_change_key_cryptogram,
                    self._session,
                    key_number,
                    newp,
                    len(new_key),
                    oldp,
                    int(aes_key),
                    version,
                )
        finally:
            C.memset(new, 0, len(new_key))
            C.memset(old, 0, len(current_key))

    def change_key_ev2_data(
        self, key_set_no: int, key_no: int, new_key: bytes, current_key: bytes, new_version: int
    ) -> bytes:
        if len(new_key) != 16 or len(current_key) != 16:
            raise ValueError("EV2 keys must be 16 bytes")
        key_set = N.unsigned(key_set_no, 8, "key_set_no")
        key_number = N.unsigned(key_no, 8, "key_no")
        version = N.unsigned(new_version, 8, "new_version")
        new, newp = N.byte_pointer(new_key)
        old, oldp = N.byte_pointer(current_key)
        try:
            with self._lock:
                self._open()
                return N.variable_output(
                    N.library().dfc_ffi_reader_change_key_ev2_data,
                    self._session,
                    key_set,
                    key_number,
                    newp,
                    oldp,
                    version,
                )
        finally:
            C.memset(new, 0, 16)
            C.memset(old, 0, 16)

    def _write(
        self,
        kind: str,
        file_number: int,
        offset: int,
        data: bytes,
        comm_mode: int,
        record_number: int | None = None,
    ) -> Response:
        file_no = N.unsigned(file_number, 8, "file_number")
        position = N.unsigned(offset, 32, "offset")
        record = None if record_number is None else N.unsigned(record_number, 32, "record_number")
        comm = N.unsigned(comm_mode, 8, "comm_mode")
        framing = self._native_framing()
        _raw, pointer = N.byte_pointer(data)
        with self._lock:
            self._open()
            function = getattr(N.library(), f"dfc_ffi_reader_{kind}_begin")
            prefix = (self._exchange, self._session, framing, file_no)
            status = function(
                *prefix,
                *((record, position) if record is not None else (position,)),
                pointer,
                len(data),
                comm,
            )
            N.raise_status(status)
            return self._run()

    def write_data(
        self, file_number: int, offset: int, data: bytes, comm_mode: int = 0
    ) -> Response:
        return self._write("write_data", file_number, offset, data, comm_mode)

    def write_record(
        self, file_number: int, offset: int, data: bytes, comm_mode: int = 0
    ) -> Response:
        return self._write("write_record", file_number, offset, data, comm_mode)

    def update_record(
        self, file_number: int, record_number: int, offset: int, data: bytes, comm_mode: int = 0
    ) -> Response:
        return self._write("update_record", file_number, offset, data, comm_mode, record_number)
