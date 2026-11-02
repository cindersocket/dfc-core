from __future__ import annotations

import ctypes as C
import secrets
import threading
import weakref
from dataclasses import dataclass
from typing import Self

from . import _native as N
from .errors import CardError, InvalidArgumentError
from .models import (
    CommunicationMode,
    Framing,
    ReaderAuthenticationMode,
    ReaderState,
    Response,
    Transport,
)

READER_PENDING = N.READER_PENDING
READER_BUFFER_TOO_SMALL = N.READER_BUFFER_TOO_SMALL
READER_CARD_ERROR = N.READER_CARD_ERROR
INITIAL_OUTPUT_CAPACITY = 64
MAX_RANGE_DATA = 255 - 7
MAX_UPDATE_DATA = 255 - 10
AUTHENTICATE_LEGACY = 0x0A
AUTHENTICATE_ISO = 0x1A
AUTHENTICATE_AES = 0xAA


def build_iso_append_record_apdu(short_file_id: int, data: bytes) -> bytes:
    """Build a standard ISO/IEC 7816 APPEND RECORD command APDU.

    Args:
        short_file_id: Zero for the current file, or an SFI from 1 through 30.
        data: Non-empty record data to append.

    Returns:
        The complete short- or extended-length command APDU.

    Raises:
        ValueError: If the SFI or record-data length is invalid.
    """

    payload = bytes(data)
    if not 0 <= short_file_id <= 0x1E:
        raise ValueError("short file identifier is out of range")
    if not payload or len(payload) > 0xFFFF:
        raise ValueError("record data length is out of range")
    p2 = short_file_id << 3
    if len(payload) <= 0xFF:
        return bytes((0x00, 0xE2, 0x00, p2, len(payload))) + payload
    return bytes((0x00, 0xE2, 0x00, p2, 0x00)) + len(payload).to_bytes(2, "big") + payload


def parse_iso7816_response(response: bytes) -> tuple[bytes, int]:
    """Return response data and the unsigned two-byte ISO status word.

    Args:
        response: Complete response APDU including SW1 and SW2.

    Returns:
        Response data and its unsigned status word.

    Raises:
        ValueError: If the response does not contain SW1 and SW2.
    """

    value = bytes(response)
    if len(value) < 2:
        raise ValueError("ISO response must include SW1 and SW2")
    return value[:-2], int.from_bytes(value[-2:], "big")


def _closed_enum(value: int, enum_type: type[Framing | CommunicationMode], name: str) -> int:
    """Validate a closed wire-domain value without changing binding error behavior."""
    narrowed = N.unsigned(value, 8, name)
    try:
        return int(enum_type(narrowed))
    except ValueError as error:
        raise InvalidArgumentError(-1, f"{name} is not supported") from error


def _validate_challenge(value: bytes | None, length: int, name: str) -> None:
    """Reject a supplied replay challenge whose length is not exact."""
    if value is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")


def _challenge(value: bytes | None, length: int, name: str) -> bytearray:
    """Return an exact replay challenge, drawing randomness only when omitted."""
    _validate_challenge(value, length, name)
    return bytearray(secrets.token_bytes(length) if value is None else value)


def _native_auth_challenge_length(cipher: int, key_length: int) -> int:
    """Return the challenge size for one valid native authentication pair."""
    if cipher == AUTHENTICATE_LEGACY and key_length in (8, 16):
        return 8
    if cipher == AUTHENTICATE_ISO and key_length in (8, 16, 24):
        return 16 if key_length == 24 else 8
    if cipher == AUTHENTICATE_AES and key_length == 16:
        return 16
    raise InvalidArgumentError(-1, "cipher and key length are incompatible")


@dataclass(frozen=True, slots=True)
class Command:
    """One native command before transport framing and secure messaging.

    Attributes:
        instruction: Native one-byte instruction.
        data: Command bytes following the instruction.
    """

    instruction: int
    data: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.instruction <= 255:
            raise ValueError("instruction must fit in one byte")

    @staticmethod
    def _validate_file_number(file_number: int) -> None:
        if not 0 <= file_number <= 31:
            raise ValueError("file number must be between 0 and 31")

    @classmethod
    def select_application(cls, aid: bytes) -> Command:
        """Build SelectApplication from a three-byte model/display-order AID.

        Args:
            aid: Three-byte AID in model/display order.

        Returns:
            A command carrying the AID in least-significant-byte-first wire order.

        Raises:
            ValueError: If ``aid`` is not exactly three bytes.
        """

        if len(aid) != 3:
            raise ValueError("AID must be three bytes")
        # Credential files and APIs use the human-readable AID order. The
        # protocol carries the three-byte value least-significant byte first.
        return cls(0x5A, aid[::-1])

    @classmethod
    def get_version(cls) -> Command:
        """Build GetVersion.

        Returns:
            The unframed native command.
        """

        return cls(0x60)

    @classmethod
    def get_free_memory(cls) -> Command:
        """Build GetFreeMemory.

        Returns:
            The unframed native command.
        """

        return cls(0x6E)

    @classmethod
    def format_picc(cls) -> Command:
        """Build FormatPICC.

        Returns:
            The unframed native command.
        """

        return cls(0xFC)

    @classmethod
    def get_key_settings(cls) -> Command:
        """Build GetKeySettings for the current selection.

        Returns:
            The unframed native command.
        """

        return cls(0x45)

    @classmethod
    def get_application_ids(cls) -> Command:
        """Build GetApplicationIDs.

        Returns:
            The unframed native command.
        """

        return cls(0x6A)

    @classmethod
    def get_df_names(cls) -> Command:
        """Build GetDFNames.

        Returns:
            The unframed native command.
        """

        return cls(0x6D)

    @classmethod
    def get_file_ids(cls) -> Command:
        """Build GetFileIDs for the current selection.

        Returns:
            The unframed native command.
        """

        return cls(0x6F)

    @classmethod
    def get_iso_file_ids(cls) -> Command:
        """Build GetISOFileIDs.

        Returns:
            The unframed native command.
        """

        return cls(0x61)

    @classmethod
    def get_card_uid(cls) -> Command:
        """Build GetCardUID.

        Returns:
            The unframed native command.
        """

        return cls(0x51)

    @classmethod
    def read_signature(cls, signature_id: int = 0) -> Command:
        """Build ReadSignature.

        Args:
            signature_id: One-byte signature identifier.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``signature_id`` does not fit in one byte.
        """

        return cls(0x3C, bytes((signature_id,)))

    @classmethod
    def get_key_version(cls, key_number: int) -> Command:
        """Build GetKeyVersion.

        Args:
            key_number: One-byte key number.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``key_number`` does not fit in one byte.
        """

        return cls(0x64, bytes((key_number,)))

    @classmethod
    def commit_transaction(cls, option: int | None = None) -> Command:
        """Build CommitTransaction.

        Args:
            option: Optional one-byte command option.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``option`` does not fit in one byte.
        """

        return cls(0xC7, b"" if option is None else bytes((option,)))

    @classmethod
    def abort_transaction(cls) -> Command:
        """Build AbortTransaction.

        Returns:
            The unframed native command.
        """

        return cls(0xA7)

    @classmethod
    def file_operation(cls, instruction: int, file_number: int) -> Command:
        """Build a one-file command from its instruction and file number.

        Args:
            instruction: One-byte native instruction.
            file_number: File number from 0 through 31.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``file_number`` is outside 0 through 31.
        """

        cls._validate_file_number(file_number)
        return cls(instruction, bytes((file_number,)))

    @classmethod
    def get_file_settings(cls, file_number: int) -> Command:
        """Build GetFileSettings.

        Args:
            file_number: File number from 0 through 31.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``file_number`` is outside 0 through 31.
        """

        return cls.file_operation(0xF5, file_number)

    @classmethod
    def get_file_counters(cls, file_number: int) -> Command:
        """Build GetFileCounters.

        Args:
            file_number: File number from 0 through 31.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``file_number`` is outside 0 through 31.
        """

        return cls.file_operation(0xF6, file_number)

    @classmethod
    def delete_file(cls, file_number: int) -> Command:
        """Build DeleteFile.

        Args:
            file_number: File number from 0 through 31.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``file_number`` is outside 0 through 31.
        """

        return cls.file_operation(0xDF, file_number)

    @classmethod
    def clear_record_file(cls, file_number: int) -> Command:
        """Build ClearRecordFile.

        Args:
            file_number: File number from 0 through 31.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``file_number`` is outside 0 through 31.
        """

        return cls.file_operation(0xEB, file_number)

    @classmethod
    def get_value(cls, file_number: int) -> Command:
        """Build GetValue.

        Args:
            file_number: File number from 0 through 31.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If ``file_number`` is outside 0 through 31.
        """

        return cls.file_operation(0x6C, file_number)

    @classmethod
    def read_data(
        cls, file_number: int, offset: int, length: int, *, iso_chaining: bool = False
    ) -> Command:
        """Build ReadData with unsigned 24-bit offset and length fields.

        Args:
            file_number: File number from 0 through 31.
            offset: Unsigned 24-bit byte offset.
            length: Unsigned 24-bit requested byte count; zero means to end.
            iso_chaining: Select the ISO-DEP chained instruction variant.

        Returns:
            The unframed native command with little-endian numeric fields.

        Raises:
            ValueError: If the file number or either 24-bit field is out of range.
        """

        cls._validate_file_number(file_number)
        if not 0 <= offset < 1 << 24 or not 0 <= length < 1 << 24:
            raise ValueError("read-data field is out of range")
        return cls(
            0xAD if iso_chaining else 0xBD,
            bytes((file_number,)) + offset.to_bytes(3, "little") + length.to_bytes(3, "little"),
        )

    @classmethod
    def _range_with_data(
        cls, instruction: int, file_number: int, offset: int, data: bytes
    ) -> Command:
        cls._validate_file_number(file_number)
        if not 0 <= offset < 1 << 24:
            raise ValueError("file range is out of range")
        if len(data) > MAX_RANGE_DATA:
            raise ValueError("command data does not fit one native frame")
        return cls(
            instruction,
            bytes((file_number,))
            + offset.to_bytes(3, "little")
            + len(data).to_bytes(3, "little")
            + data,
        )

    @classmethod
    def write_data(
        cls, file_number: int, offset: int, data: bytes, *, iso_chaining: bool = False
    ) -> Command:
        """Build WriteData.

        Args:
            file_number: File number from 0 through 31.
            offset: Unsigned 24-bit byte offset.
            data: Payload copied into the command.
            iso_chaining: Select the ISO-DEP chained instruction variant.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If a field is out of range or the payload exceeds one frame.
        """

        return cls._range_with_data(
            0x8D if iso_chaining else 0x3D, file_number, offset, bytes(data)
        )

    @classmethod
    def read_records(
        cls,
        file_number: int,
        record_number: int,
        count: int,
        *,
        iso_chaining: bool = False,
    ) -> Command:
        """Build ReadRecords.

        Args:
            file_number: File number from 0 through 31.
            record_number: Unsigned 24-bit first record number.
            count: Unsigned 24-bit record count; zero means all remaining records.
            iso_chaining: Select the ISO-DEP chained instruction variant.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If the file number or a 24-bit field is out of range.
        """

        command = cls.read_data(file_number, record_number, count)
        return cls(0xAB if iso_chaining else 0xBB, command.data)

    @classmethod
    def write_record(
        cls, file_number: int, offset: int, data: bytes, *, iso_chaining: bool = False
    ) -> Command:
        """Build WriteRecord.

        Args:
            file_number: File number from 0 through 31.
            offset: Unsigned 24-bit byte offset within the record.
            data: Payload copied into the command.
            iso_chaining: Select the ISO-DEP chained instruction variant.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If a field is out of range or the payload exceeds one frame.
        """

        return cls._range_with_data(
            0x8B if iso_chaining else 0x3B, file_number, offset, bytes(data)
        )

    @classmethod
    def update_record(
        cls,
        file_number: int,
        record_number: int,
        offset: int,
        data: bytes,
        *,
        iso_chaining: bool = False,
    ) -> Command:
        """Build UpdateRecord.

        Args:
            file_number: File number from 0 through 31.
            record_number: Unsigned 24-bit record number.
            offset: Unsigned 24-bit byte offset within the record.
            data: Payload copied into the command.
            iso_chaining: Select the ISO-DEP chained instruction variant.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If a field is out of range or the payload exceeds one frame.
        """

        if not 0 <= record_number < 1 << 24:
            raise ValueError("record number is out of range")
        if len(data) > MAX_UPDATE_DATA:
            raise ValueError("command data does not fit one native frame")
        instruction = 0xBA if iso_chaining else 0xDB
        tail = cls._range_with_data(instruction, file_number, offset, bytes(data)).data
        return cls(instruction, tail[:1] + record_number.to_bytes(3, "little") + tail[1:])

    @classmethod
    def _value_operation(cls, instruction: int, file_number: int, amount: int) -> Command:
        cls._validate_file_number(file_number)
        return cls(instruction, bytes((file_number,)) + amount.to_bytes(4, "little", signed=True))

    @classmethod
    def credit(cls, file_number: int, amount: int) -> Command:
        """Build Credit.

        Args:
            file_number: File number from 0 through 31.
            amount: Signed 32-bit value to add.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If the file number is out of range.
            OverflowError: If ``amount`` does not fit a signed 32-bit integer.
        """

        return cls._value_operation(0x0C, file_number, amount)

    @classmethod
    def debit(cls, file_number: int, amount: int) -> Command:
        """Build Debit.

        Args:
            file_number: File number from 0 through 31.
            amount: Signed 32-bit value to subtract.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If the file number is out of range.
            OverflowError: If ``amount`` does not fit a signed 32-bit integer.
        """

        return cls._value_operation(0xDC, file_number, amount)

    @classmethod
    def limited_credit(cls, file_number: int, amount: int) -> Command:
        """Build LimitedCredit.

        Args:
            file_number: File number from 0 through 31.
            amount: Signed 32-bit value to add under the file's limited-credit rule.

        Returns:
            The unframed native command.

        Raises:
            ValueError: If the file number is out of range.
            OverflowError: If ``amount`` does not fit a signed 32-bit integer.
        """

        return cls._value_operation(0x1C, file_number, amount)


class Reader:
    """Stateful blocking reader with authentication and secure messaging.

    The reader owns native session and exchange handles. Close it promptly or use
    it as a context manager. A transport exception clears the protocol session
    before it is re-raised.
    """

    def __init__(self, transport: Transport, framing: Framing | int = Framing.ISO_7816) -> None:
        """Create a reader over ``transport`` using the selected frame convention.

        Args:
            transport: Blocking command transport retained for this reader's lifetime.
            framing: Wire framing expected by ``transport``.

        Raises:
            ValueError: If ``framing`` is not a supported ``Framing`` value.
            DfcError: If native reader state cannot be allocated.
        """

        self.transport, self.framing = transport, Framing(framing)
        self._lock = threading.RLock()
        self._in_transport_callback = False
        self._step_output = (C.c_uint8 * INITIAL_OUTPUT_CAPACITY)()
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
        return _closed_enum(self.framing, Framing, "framing")

    def close(self) -> None:
        """Wipe and release native reader state; repeated calls are safe."""

        with self._lock:
            N.secure_zero(self._step_output)
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
        """Read non-secret session state.

        Returns:
            Authentication state with inactive optional fields ``None`` and
            inactive EV2 byte fields empty.

        Raises:
            RuntimeError: If the reader is closed.
            DfcError: If native state cannot be read.
        """

        with self._lock:
            self._open()
            s = N.ReaderState()
            N.raise_status(N.library().dfc_ffi_reader_session_state(self._session, C.byref(s)))
            authentication = ReaderAuthenticationMode(s.auth_mode) if s.auth_mode else None
            ev2 = authentication is ReaderAuthenticationMode.EV2
            return ReaderState(
                authentication,
                s.key_no if authentication is not None else None,
                s.ev2_command_counter if ev2 else None,
                bytes(s.ev2_transaction_identifier) if ev2 else b"",
                bytes(s.ev2_card_capabilities) if ev2 else b"",
                bytes(s.ev2_reader_capabilities) if ev2 else b"",
            )

    def clear(self) -> None:
        """Clear authentication and secure-messaging state.

        Raises:
            RuntimeError: If the reader is closed.
        """

        with self._lock:
            self._open()
            N.library().dfc_ffi_reader_session_clear(self._session)

    def _run(self) -> Response:
        with self._lock:
            self._open()
            answer = b""
            while True:
                _raw, pointer = N.byte_pointer(answer)
                length = C.c_size_t()
                while True:
                    capacity = len(self._step_output)
                    status = N.library().dfc_ffi_reader_step(
                        self._exchange,
                        pointer,
                        len(answer),
                        self._step_output,
                        capacity,
                        C.byref(length),
                    )
                    if status != READER_BUFFER_TOO_SMALL:
                        break
                    required = length.value
                    if required <= capacity:
                        required = capacity * 2
                    grown = (C.c_uint8 * required)()
                    N.secure_zero(self._step_output)
                    self._step_output = grown
                if status == READER_PENDING:
                    try:
                        self._in_transport_callback = True
                        try:
                            frame = bytes(self._step_output[: length.value])
                            N.secure_zero(self._step_output)
                            answer = bytes(self.transport.transceive(frame))
                        finally:
                            self._in_transport_callback = False
                    except BaseException:
                        if self._finalizer.alive:
                            self.clear()
                        raise
                    self._open()
                    continue
                N.secure_zero(self._step_output)
                if status == READER_CARD_ERROR:
                    raise CardError(
                        status, N.library().dfc_ffi_reader_result_status(self._exchange)
                    )
                N.raise_status(status)
                data = N.variable_output(N.library().dfc_ffi_reader_result_data, self._exchange)
                return Response(N.library().dfc_ffi_reader_result_status(self._exchange), data)

    def exchange(
        self,
        command: Command,
        comm_mode: CommunicationMode | int = CommunicationMode.PLAIN,
        header_len: int = -1,
    ) -> Response:
        """Exchange one command.

        ``header_len`` is -1 to derive the clear header, or a non-negative
        length accepted by the native reader.

        Args:
            command: Native instruction and data in model form.
            comm_mode: Requested communication protection.
            header_len: Derived (``-1``) or explicit clear-header byte count.

        Returns:
            The status and response data after removing transport framing.

        Raises:
            InvalidArgumentError: If an integer or closed enum is out of range.
            CardError: If the card returns a terminal error status.
            DfcError: If native processing fails.
        """
        clear_header_length = N.signed(header_len, 32, "header_len")
        comm = _closed_enum(comm_mode, CommunicationMode, "comm_mode")
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
        """Authenticate with a native legacy, ISO, or AES instruction.

        ``random_a`` is a deterministic replay value. When omitted, the binding
        draws an exact-length challenge. Supplied values must be eight bytes for
        DES/2K3DES or sixteen bytes for AES/3K3DES.

        Args:
            cipher: One-byte native authentication instruction.
            key_no: One-byte key number.
            key: Authentication key in the length required by ``cipher``.
            random_a: Optional deterministic reader challenge for replay tests.

        Returns:
            Final card status and response data.

        Raises:
            ValueError: If a supplied challenge length is wrong.
            InvalidArgumentError: If a numeric input or key shape is invalid.
            CardError: If authentication is rejected by the card.
            DfcError: If reader processing fails.
        """

        cipher_id = N.unsigned(cipher, 8, "cipher")
        key_number = N.unsigned(key_no, 8, "key_no")
        framing = self._native_framing()
        challenge_length = _native_auth_challenge_length(cipher_id, len(key))
        challenge = _challenge(random_a, challenge_length, "random_a")
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
        """Perform EV2 first or non-first authentication.

        ``random_a`` is an optional deterministic 16-byte replay value.
        ``capabilities`` is empty or six bytes for first authentication and must
        be empty for non-first authentication.

        Args:
            key_no: One-byte AES key number.
            key: Sixteen-byte AES key.
            first: Select first or non-first EV2 authentication.
            random_a: Optional deterministic 16-byte reader challenge.
            capabilities: Empty or six-byte reader capabilities for first authentication.

        Returns:
            Final card status and response data.

        Raises:
            ValueError: If a replay challenge has the wrong length.
            InvalidArgumentError: If the key, key number, or capabilities are invalid.
            CardError: If authentication is rejected by the card.
            DfcError: If reader processing fails.
        """

        key_number = N.unsigned(key_no, 8, "key_no")
        framing = self._native_framing()
        challenge = _challenge(random_a, 16, "random_a")
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
        """Perform the two-random ISO 7816 authentication flow.

        Each replay challenge may be omitted independently. All explicit values
        are validated before either omitted challenge draws randomness.

        Args:
            key_reference: One-byte ISO key reference.
            algorithm: One-byte ISO authentication algorithm identifier.
            key: Authentication key accepted by ``algorithm``.
            random_first: Optional deterministic first reader challenge.
            random_second: Optional deterministic second reader challenge.

        Returns:
            Final card status and response data.

        Raises:
            ValueError: If a supplied replay challenge has the wrong length.
            InvalidArgumentError: If the reference, algorithm, or key is invalid.
            CardError: If authentication is rejected by the card.
            DfcError: If reader processing fails.
        """

        key_ref = N.unsigned(key_reference, 8, "key_reference")
        algorithm_id = N.unsigned(algorithm, 8, "algorithm")
        length = 8 if algorithm_id == N.ISO_AUTH_TDEA2 else 16
        # Validate both replay inputs before drawing either omitted challenge.
        # This keeps rejected calls free of observable random-source side effects.
        _validate_challenge(random_first, length, "random_first")
        _validate_challenge(random_second, length, "random_second")
        first = _challenge(random_first, length, "random_first")
        second = _challenge(random_second, length, "random_second")
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
        """Create a delegated application from a prepared 19-byte header.

        Secret inputs are copied into mutable native buffers and wiped when the
        operation returns. The caller's immutable ``bytes`` objects remain.

        Args:
            header: Prepared 19-byte delegated-application command header.
            dam_encryption_key: Sixteen-byte delegated-management encryption key.
            dam_mac_key: Sixteen-byte delegated-management MAC key.
            random_prefix: Seven-byte random prefix used by the cryptogram.
            initial_key: Initial application key.
            initial_version: One-byte initial key version.

        Returns:
            Final card status and response data.

        Raises:
            InvalidArgumentError: If a field, key, or version has an invalid shape.
            CardError: If the card rejects the command.
            DfcError: If reader processing fails.
        """

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
        """Build protected ChangeKey data for the current authenticated session.

        Native temporary key copies are wiped before return. The caller retains
        responsibility for its immutable Python key objects.

        Args:
            key_no: One-byte target key number.
            new_key: Replacement key bytes.
            current_key: Current key bytes used when required by the operation.
            aes_key: Whether the replacement is an AES key.
            new_version: One-byte replacement key version.

        Returns:
            Protected command data without instruction or transport framing.

        Raises:
            InvalidArgumentError: If a numeric field or key shape is invalid.
            DfcError: If no compatible authenticated session is active.
        """

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
        """Build EV2 ChangeKey data from two 16-byte AES keys.

        Args:
            key_set_no: One-byte target key-set number.
            key_no: One-byte target key number.
            new_key: New 16-byte AES key.
            current_key: Current 16-byte AES key.
            new_version: One-byte replacement key version.

        Returns:
            Protected EV2 command data without instruction or transport framing.

        Raises:
            ValueError: If either key is not 16 bytes.
            InvalidArgumentError: If a key number, set number, or version is invalid.
            DfcError: If no compatible authenticated session is active.
        """

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
        comm_mode: CommunicationMode | int,
        record_number: int | None = None,
    ) -> Response:
        file_no = N.unsigned(file_number, 8, "file_number")
        position = N.unsigned(offset, 32, "offset")
        record = None if record_number is None else N.unsigned(record_number, 32, "record_number")
        comm = _closed_enum(comm_mode, CommunicationMode, "comm_mode")
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
        self,
        file_number: int,
        offset: int,
        data: bytes,
        comm_mode: CommunicationMode | int = CommunicationMode.PLAIN,
    ) -> Response:
        """Write bytes to a standard or backup data file.

        Args:
            file_number: One-byte target file number.
            offset: Unsigned 32-bit byte offset.
            data: Plain bytes to write.
            comm_mode: Communication protection for this command.

        Returns:
            Final card status and response data.

        Raises:
            InvalidArgumentError: If a numeric field or communication mode is invalid.
            CardError: If the card rejects the command.
            DfcError: If reader processing fails.
        """

        return self._write("write_data", file_number, offset, data, comm_mode)

    def write_record(
        self,
        file_number: int,
        offset: int,
        data: bytes,
        comm_mode: CommunicationMode | int = CommunicationMode.PLAIN,
    ) -> Response:
        """Append bytes at an offset within a new record.

        Args:
            file_number: One-byte target file number.
            offset: Unsigned 32-bit offset within the new record.
            data: Plain record bytes to append.
            comm_mode: Communication protection for this command.

        Returns:
            Final card status and response data.

        Raises:
            InvalidArgumentError: If a numeric field or communication mode is invalid.
            CardError: If the card rejects the command.
            DfcError: If reader processing fails.
        """

        return self._write("write_record", file_number, offset, data, comm_mode)

    def update_record(
        self,
        file_number: int,
        record_number: int,
        offset: int,
        data: bytes,
        comm_mode: CommunicationMode | int = CommunicationMode.PLAIN,
    ) -> Response:
        """Update bytes in an existing record.

        Args:
            file_number: One-byte target file number.
            record_number: Zero-based unsigned 32-bit record number.
            offset: Unsigned 32-bit offset within the record.
            data: Plain replacement bytes.
            comm_mode: Communication protection for this command.

        Returns:
            Final card status and response data.

        Raises:
            InvalidArgumentError: If a numeric field or communication mode is invalid.
            CardError: If the card rejects the command.
            DfcError: If reader processing fails.
        """

        return self._write("update_record", file_number, offset, data, comm_mode, record_number)
