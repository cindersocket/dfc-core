from __future__ import annotations

import ctypes as C
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from dfc_core import (
    CardError,
    Command,
    Credential,
    InvalidArgumentError,
    RandomSourceError,
    Reader,
    VirtualPicc,
    _native,
    capabilities,
)
from dfc_core import reader as reader_module

FIXTURE = Path(__file__).parents[3] / "examples" / "credentials" / "v6-minimal.dfcb"


CLOSED_READER_CALLS: list[tuple[str, Callable[[Reader], object]]] = [
    ("state", lambda reader: reader.state),
    ("clear", lambda reader: reader.clear()),
    ("run", lambda reader: reader._run()),
    ("exchange", lambda reader: reader.exchange(Command.get_version())),
    (
        "authenticate",
        lambda reader: reader.authenticate(0x1A, 0, bytes(16), random_a=bytes(8)),
    ),
    (
        "authenticate_ev2",
        lambda reader: reader.authenticate_ev2(0, bytes(16), random_a=bytes(16)),
    ),
    (
        "authenticate_iso7816",
        lambda reader: reader.authenticate_iso7816(
            0, 0x09, bytes(16), random_first=bytes(16), random_second=bytes(16)
        ),
    ),
    (
        "create_delegated_application",
        lambda reader: reader.create_delegated_application(
            bytes(19), bytes(16), bytes(16), bytes(7), bytes(16), 0
        ),
    ),
    (
        "change_key_cryptogram",
        lambda reader: reader.change_key_cryptogram(
            0, bytes(16), bytes(16), aes_key=True, new_version=0
        ),
    ),
    (
        "change_key_ev2_data",
        lambda reader: reader.change_key_ev2_data(0, 0, bytes(16), bytes(16), 0),
    ),
    ("write_data", lambda reader: reader.write_data(0, 0, b"data")),
    ("write_record", lambda reader: reader.write_record(0, 0, b"data")),
    ("update_record", lambda reader: reader.update_record(0, 0, 0, b"data")),
]

REENTRANT_CLOSE_READER_CALLS: list[tuple[str, Callable[[Reader], object], str | None]] = [
    ("run", lambda reader: reader._run(), None),
    (
        "exchange",
        lambda reader: reader.exchange(Command.get_version()),
        "dfc_ffi_reader_exchange_begin",
    ),
    (
        "authenticate",
        lambda reader: reader.authenticate(0x1A, 0, bytes(16), random_a=bytes(8)),
        "dfc_ffi_reader_authenticate_begin",
    ),
    (
        "authenticate_ev2",
        lambda reader: reader.authenticate_ev2(0, bytes(16), random_a=bytes(16)),
        "dfc_ffi_reader_authenticate_ev2_begin",
    ),
    (
        "authenticate_iso7816",
        lambda reader: reader.authenticate_iso7816(
            0, 0x09, bytes(16), random_first=bytes(16), random_second=bytes(16)
        ),
        "dfc_ffi_reader_authenticate_iso7816_begin",
    ),
    (
        "create_delegated_application",
        lambda reader: reader.create_delegated_application(
            bytes(19), bytes(16), bytes(16), bytes(7), bytes(16), 0
        ),
        "dfc_ffi_reader_create_delegated_application_begin",
    ),
    (
        "write_data",
        lambda reader: reader.write_data(0, 0, b"data"),
        "dfc_ffi_reader_write_data_begin",
    ),
    (
        "write_record",
        lambda reader: reader.write_record(0, 0, b"data"),
        "dfc_ffi_reader_write_record_begin",
    ),
    (
        "update_record",
        lambda reader: reader.update_record(0, 0, 0, b"data"),
        "dfc_ffi_reader_update_record_begin",
    ),
]


def test_reader_native_signatures_are_complete() -> None:
    library = _native.library()
    handle = _native.Handle
    pointer = _native.P8
    size = C.c_size_t
    status = C.c_int32
    signatures = {
        "dfc_ffi_reader_session_new": ([C.POINTER(handle)], status),
        "dfc_ffi_reader_session_free": ([handle], None),
        "dfc_ffi_reader_session_clear": ([handle], None),
        "dfc_ffi_reader_session_state": ([handle, C.POINTER(_native.ReaderState)], status),
        "dfc_ffi_reader_exchange_new": ([C.POINTER(handle)], status),
        "dfc_ffi_reader_exchange_free": ([handle], None),
        "dfc_ffi_reader_authenticate_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                C.c_uint8,
                C.c_uint8,
                pointer,
                size,
                pointer,
                size,
            ],
            status,
        ),
        "dfc_ffi_reader_authenticate_iso7816_begin": (
            [
                handle,
                handle,
                C.c_uint8,
                pointer,
                size,
                C.c_uint8,
                pointer,
                pointer,
                size,
            ],
            status,
        ),
        "dfc_ffi_reader_authenticate_ev2_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                C.c_uint8,
                C.c_uint8,
                pointer,
                pointer,
                pointer,
                size,
            ],
            status,
        ),
        "dfc_ffi_reader_exchange_begin": (
            [handle, handle, C.c_uint32, C.c_uint8, pointer, size, C.c_uint8, C.c_int32],
            status,
        ),
        "dfc_ffi_reader_write_data_begin": (
            [handle, handle, C.c_uint32, C.c_uint8, C.c_uint32, pointer, size, C.c_uint8],
            status,
        ),
        "dfc_ffi_reader_write_record_begin": (
            [handle, handle, C.c_uint32, C.c_uint8, C.c_uint32, pointer, size, C.c_uint8],
            status,
        ),
        "dfc_ffi_reader_update_record_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                C.c_uint8,
                C.c_uint32,
                C.c_uint32,
                pointer,
                size,
                C.c_uint8,
            ],
            status,
        ),
        "dfc_ffi_reader_create_delegated_application_begin": (
            [
                handle,
                handle,
                C.c_uint32,
                pointer,
                size,
                pointer,
                pointer,
                pointer,
                pointer,
                size,
                C.c_uint8,
            ],
            status,
        ),
        "dfc_ffi_reader_step": (
            [handle, pointer, size, pointer, size, C.POINTER(size)],
            status,
        ),
        "dfc_ffi_reader_result_status": ([handle], C.c_uint8),
        "dfc_ffi_reader_result_data": (
            [handle, pointer, size, C.POINTER(size)],
            status,
        ),
        "dfc_ffi_reader_change_key_cryptogram": (
            [
                handle,
                C.c_uint8,
                pointer,
                size,
                pointer,
                C.c_uint8,
                C.c_uint8,
                pointer,
                size,
                C.POINTER(size),
            ],
            status,
        ),
        "dfc_ffi_reader_change_key_ev2_data": (
            [
                handle,
                C.c_uint8,
                C.c_uint8,
                pointer,
                pointer,
                C.c_uint8,
                pointer,
                size,
                C.POINTER(size),
            ],
            status,
        ),
    }

    for name, (argtypes, restype) in signatures.items():
        function = getattr(library, name)
        assert function.argtypes == argtypes, name
        assert function.restype is restype, name


def test_reader_authenticate_reaches_the_native_begin_function() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        picc.activate()
        with Reader(picc) as reader:
            response = reader.authenticate(0x1A, 0, bytes(16), random_a=bytes(8))

            assert response.status == 0
            assert reader.state.auth_mode == 0x1A


def test_reader_preserves_card_status_after_growing_command_buffer() -> None:
    class RejectingTransport:
        def __init__(self) -> None:
            self.command = b""

        def transceive(self, command: bytes) -> bytes:
            self.command = command
            return bytes((0x91, 0x1C))

    transport = RejectingTransport()
    with Reader(transport) as reader, pytest.raises(CardError) as caught:
        reader.exchange(Command(0x3D, bytes(200)))

    assert caught.value.card_status == 0x1C
    assert len(transport.command) == reader_module.INITIAL_OUTPUT_CAPACITY + 1


@pytest.mark.parametrize(
    ("name", "invoke"), CLOSED_READER_CALLS, ids=[name for name, _ in CLOSED_READER_CALLS]
)
def test_closed_reader_rejects_every_native_call(
    name: str, invoke: Callable[[Reader], object], monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        reader = Reader(picc)
        reader.close()

        def unexpected_native_access() -> None:
            pytest.fail(f"{name} accessed the native library after close")

        monkeypatch.setattr(_native, "library", unexpected_native_access)
        with pytest.raises(RuntimeError, match="reader is closed"):
            invoke(reader)


def test_reader_close_is_idempotent() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        reader = Reader(picc)
        reader.close()
        reader.close()

        assert reader._session.value is None
        assert reader._exchange.value is None


def test_reader_close_waits_for_in_flight_run(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        reader = Reader(picc)
        library = _native.library()
        step_entered = threading.Event()
        release_step = threading.Event()
        close_started = threading.Event()
        close_returned = threading.Event()
        run_errors: list[BaseException] = []

        def blocked_step(*_: object) -> int:
            step_entered.set()
            if not release_step.wait(5):
                raise TimeoutError("reader step was not released")
            return _native.INVALID_ARGUMENT

        def run() -> None:
            try:
                reader._run()
            except BaseException as exc:  # noqa: BLE001, reported in the test thread
                run_errors.append(exc)

        def close() -> None:
            close_started.set()
            reader.close()
            close_returned.set()

        monkeypatch.setattr(library, "dfc_ffi_reader_step", blocked_step)
        run_thread = threading.Thread(target=run)
        close_thread = threading.Thread(target=close)
        run_thread.start()
        assert step_entered.wait(5)
        close_thread.start()
        assert close_started.wait(5)
        try:
            assert not close_returned.wait(0.1)
        finally:
            release_step.set()
            run_thread.join(5)
            close_thread.join(5)

        assert not run_thread.is_alive()
        assert not close_thread.is_alive()
        assert len(run_errors) == 1
        assert close_returned.is_set()
        assert reader._session.value is None
        assert reader._exchange.value is None


@pytest.mark.parametrize(
    ("name", "invoke", "begin_name"),
    REENTRANT_CLOSE_READER_CALLS,
    ids=[name for name, _, _ in REENTRANT_CLOSE_READER_CALLS],
)
@pytest.mark.parametrize(
    "transport_result",
    [
        "returns_after_close",
        "raises_after_close",
        "conversion_raises_after_close",
        "raises_while_open",
    ],
)
def test_transport_reentry_is_safe_for_every_reader_exchange_path(
    name: str,
    invoke: Callable[[Reader], object],
    begin_name: str | None,
    transport_result: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TransportFailure(Exception):
        pass

    failure = TransportFailure("transport failed after close")

    class ConversionFailure:
        def __bytes__(self) -> bytes:
            raise failure

    reader: Reader

    class ClosingTransport:
        def transceive(self, _: bytes) -> bytes:
            if transport_result != "raises_while_open":
                reader.close()
                assert reader._session.value is None
                assert reader._exchange.value is None
            if transport_result in ("raises_after_close", "raises_while_open"):
                raise failure
            if transport_result == "conversion_raises_after_close":
                return cast(bytes, ConversionFailure())
            return b""

    reader = Reader(ClosingTransport())
    library = _native.library()
    native_clear = library.dfc_ffi_reader_session_clear
    step_calls = 0
    clear_calls = 0

    if begin_name is not None:
        monkeypatch.setattr(library, begin_name, lambda *_: 0)

    def pending_once(
        exchange: _native.Handle,
        _answer: object,
        _answer_len: int,
        output: object,
        _capacity: int,
        output_len: object,
    ) -> int:
        nonlocal step_calls
        step_calls += 1
        if step_calls != 1:
            pytest.fail(f"{name} called native step after the transport closed the reader")
        assert exchange.value is not None
        C.cast(output, _native.P8)[0] = 0x60
        C.cast(output_len, C.POINTER(C.c_size_t))[0] = 1
        return 1

    monkeypatch.setattr(library, "dfc_ffi_reader_step", pending_once)

    def checked_clear(session: _native.Handle) -> None:
        nonlocal clear_calls
        clear_calls += 1
        assert session.value is not None
        native_clear(session)

    monkeypatch.setattr(library, "dfc_ffi_reader_session_clear", checked_clear)

    if transport_result == "returns_after_close":
        with pytest.raises(RuntimeError, match="reader is closed"):
            invoke(reader)
    else:
        with pytest.raises(TransportFailure) as caught:
            invoke(reader)
        assert caught.value is failure

    assert step_calls == 1
    assert clear_calls == (1 if transport_result == "raises_while_open" else 0)
    reader.close()


@pytest.mark.parametrize(
    ("name", "invoke"),
    CLOSED_READER_CALLS,
    ids=[name for name, _ in CLOSED_READER_CALLS],
)
def test_transport_callback_rejects_every_reader_native_call(
    name: str, invoke: Callable[[Reader], object]
) -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    reader: Reader
    attempted = False

    with VirtualPicc(credential) as picc:
        picc.activate()

        class ReentrantTransport:
            def transceive(self, command: bytes) -> bytes:
                nonlocal attempted
                if not attempted:
                    attempted = True
                    with pytest.raises(RuntimeError, match="reader transport callback is active"):
                        invoke(reader)
                return picc.transceive(command)

        with Reader(ReentrantTransport()) as reader:
            response = reader.exchange(Command.get_version())
            assert response.status == 0
            assert len(response.data) == 28

    assert attempted, f"{name} did not reach the transport callback"


def test_abi_sizes_and_field_fingerprint() -> None:
    library = _native.library()
    assert capabilities().abi_version == _native.ABI_VERSION
    assert library.dfc_ffi_layout_fingerprint() == _native.layout_fingerprint()


def test_codec_picc_and_reader_lifecycle() -> None:
    encoded = FIXTURE.read_bytes()
    credential = Credential.decode(encoded)
    assert credential.encode() == encoded
    assert Credential.parse(credential.to_text()).encode() == encoded

    with VirtualPicc(credential) as picc:
        assert credential.closed
        assert picc.activate().uid
        with Reader(picc) as reader:
            response = reader.exchange(Command(0x60))
            assert response.status == 0
            assert len(response.data) == 28


NATIVE_MAX_CLEAR_HEADER = 10


@pytest.mark.parametrize(
    ("value", "bits"),
    [(255, 8), (2**32 - 1, 32)],
)
def test_unsigned_native_integer_accepts_maximum(value: int, bits: int) -> None:
    assert _native.unsigned(value, bits, "value") == value


@pytest.mark.parametrize("value", [256, -1, 1.5])
def test_unsigned_native_integer_refuses_out_of_range_or_non_integer(value: object) -> None:
    with pytest.raises(InvalidArgumentError):
        _native.unsigned(value, 8, "value")  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [-(2**31), 2**31 - 1])
def test_signed_native_integer_accepts_boundaries(value: int) -> None:
    assert _native.signed(value, 32, "value") == value


@pytest.mark.parametrize("value", [-(2**31) - 1, 2**31, 1.5])
def test_signed_native_integer_refuses_out_of_range_or_non_integer(value: object) -> None:
    with pytest.raises(InvalidArgumentError):
        _native.signed(value, 32, "value")  # type: ignore[arg-type]


def _exchange_with_framing(reader: Reader, framing: int) -> object:
    previous = reader.framing
    try:
        reader.framing = framing
        return reader.exchange(Command.get_version())
    finally:
        reader.framing = previous


def test_reader_header_len_reaches_native_unnarrowed() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        picc.activate()
        with Reader(picc) as reader:
            command = Command.get_version()
            assert reader.exchange(command, header_len=-1).status == 0
            assert reader.exchange(command, header_len=NATIVE_MAX_CLEAR_HEADER).status == 0
            for bad in (NATIVE_MAX_CLEAR_HEADER + 1, -2, 2**31, 2**32 + 3, -(2**31) - 1):
                with pytest.raises(InvalidArgumentError):
                    reader.exchange(command, header_len=bad)
            with pytest.raises(InvalidArgumentError):
                reader.exchange(command, header_len=1.5)  # type: ignore[arg-type]
            assert reader.exchange(command).status == 0


@pytest.mark.parametrize(
    "call",
    [
        lambda reader, _picc: reader.exchange(Command.get_version(), comm_mode=256),
        lambda reader, _picc: _exchange_with_framing(reader, 2**32),
        lambda reader, _picc: reader.write_data(1, 0, b"x", comm_mode=256),
        lambda reader, _picc: reader.authenticate(0x1A, 256, bytes(16), random_a=bytes(8)),
        lambda reader, _picc: reader.authenticate(256, 0, bytes(16), random_a=bytes(8)),
        lambda reader, _picc: reader.authenticate_ev2(256, bytes(16), random_a=bytes(16)),
        lambda reader, _picc: reader.authenticate_iso7816(0, 256, bytes(16), bytes(16), bytes(16)),
        lambda reader, _picc: reader.create_delegated_application(
            b"", bytes(16), bytes(16), bytes(7), bytes(16), 256
        ),
        lambda reader, _picc: reader.write_data(1, 2**32, b"x"),
        lambda reader, _picc: reader.update_record(1, -1, 0, b"x"),
        lambda reader, _picc: reader.change_key_cryptogram(
            0, bytes(16), bytes(16), aes_key=True, new_version=256
        ),
        lambda _reader, picc: picc.advance_time(-1),
        lambda _reader, picc: picc.advance_time(2**32),
    ],
)
def test_caller_integers_are_refused_not_narrowed(
    call: Callable[[Reader, VirtualPicc], object],
) -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    with VirtualPicc(credential) as picc:
        picc.activate()
        with Reader(picc) as reader:
            with pytest.raises(InvalidArgumentError):
                call(reader, picc)
            assert reader.exchange(Command.get_version()).status == 0


def test_callback_exception_is_deferred_safely() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())

    def broken(_: int) -> bytes:
        raise LookupError("script exhausted")

    with VirtualPicc(credential, broken) as picc:
        output = (C.c_uint8 * 16)()
        assert picc._random_callback(0, output, 16) == _native.RANDOM_FAILED
        assert bytes(output) == bytes(16)
        with pytest.raises(RandomSourceError, match="random source failed") as failure:
            picc._check_callback()
        assert failure.value.status == _native.RANDOM_FAILED
        assert isinstance(failure.value.__cause__, LookupError)


def test_callback_failure_does_not_mutate_picc() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())

    with VirtualPicc(credential, lambda _: b"") as picc:
        picc.activate()
        before = picc.snapshot()
        with pytest.raises(RandomSourceError, match="random source failed") as failure:
            picc.exchange(bytes.fromhex("901A0000010000"))
        assert failure.value.status == _native.RANDOM_FAILED
        assert picc.snapshot() == before
        picc.reset_protocol()
        assert picc.exchange(bytes.fromhex("9060000000"))[-2:] == bytes.fromhex("91AF")


def test_callback_failure_is_reported_once_per_operation() -> None:
    credential = Credential.decode(FIXTURE.read_bytes())
    calls = 0

    def exhausted(length: int) -> bytes:
        nonlocal calls
        calls += 1
        return bytes(max(0, length - 1))

    with VirtualPicc(credential, exhausted) as picc:
        picc.activate()
        for _ in range(2):
            with pytest.raises(RandomSourceError) as failure:
                picc.exchange(bytes.fromhex("901A0000010000"))
            assert failure.value.status == _native.RANDOM_FAILED
        assert calls == 2
