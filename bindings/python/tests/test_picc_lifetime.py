from __future__ import annotations

import gc
import threading
import weakref
from collections.abc import Callable
from pathlib import Path

import pytest

from dfc_core import Credential, InvalidArgumentError, RandomSourceError, VirtualPicc, _native

FIXTURE = Path(__file__).parents[3] / "examples" / "credentials" / "v6-minimal.dfcb"
GET_CHALLENGE = bytes.fromhex("0084000008")


@pytest.fixture
def freed_piccs(monkeypatch: pytest.MonkeyPatch) -> list[int | None]:
    library = _native.library()
    native_free = library.dfc_ffi_picc_free
    freed: list[int | None] = []

    def tracked_free(handle: _native.Handle) -> None:
        freed.append(handle.value)
        native_free(handle)

    monkeypatch.setattr(library, "dfc_ffi_picc_free", tracked_free)
    return freed


def make_picc(random: Callable[[int], bytes] | None = None) -> VirtualPicc:
    return VirtualPicc(Credential.decode(FIXTURE.read_bytes()), random)


def test_model_wipes_partial_picc_output_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _native.library()
    retained: list[_native.PiccSettings] = []

    def fail(_handle: _native.Handle, output: object) -> int:
        picc = output._obj  # type: ignore[attr-defined]
        picc.proximity_key[:] = b"\xa5" * 16
        retained.append(picc)
        return -1

    monkeypatch.setattr(library, "dfc_ffi_credential_get_picc", fail)
    with Credential.decode(FIXTURE.read_bytes()) as credential:
        with pytest.raises(InvalidArgumentError):
            credential.model()
    assert retained and not any(retained[0].proximity_key)


def test_model_wipes_partial_file_output_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _native.library()
    retained: list[_native.File] = []

    def fail(_handle: _native.Handle, _index: int, output: object) -> int:
        file = output._obj  # type: ignore[attr-defined]
        file.transaction_mac_key[:] = b"\xa5" * 16
        retained.append(file)
        return -1

    monkeypatch.setattr(library, "dfc_ffi_credential_file_count", lambda _handle: 1)
    monkeypatch.setattr(library, "dfc_ffi_credential_get_file", fail)
    with Credential.decode(FIXTURE.read_bytes()) as credential:
        with pytest.raises(InvalidArgumentError):
            credential.model()
    assert retained and not any(retained[0].transaction_mac_key)


def test_diagnostic_snapshot_clears_binding_owned_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    picc = make_picc()
    library = _native.library()

    def diagnostic(_handle: _native.Handle, output: object) -> int:
        snapshot = output._obj  # type: ignore[attr-defined]
        snapshot.transaction_identifier[:] = b"\x11" * 4
        snapshot.encryption_key[:] = b"\x22" * 16
        snapshot.mac_key[:] = b"\x33" * 16
        return 0

    monkeypatch.setattr(library, "dfc_ffi_picc_diagnostic_snapshot", diagnostic)
    with picc._diagnostic_snapshot() as values:
        assert values == (bytearray(b"\x11" * 4), bytearray(b"\x22" * 16), bytearray(b"\x33" * 16))
    assert all(not any(value) for value in values)
    picc.close()


def test_callback_close_defers_native_free_until_exchange_returns(
    freed_piccs: list[int | None],
) -> None:
    holder: dict[str, VirtualPicc] = {}
    callback_free_counts: list[int] = []
    callback_handles: list[int | None] = []

    def close_from_callback(length: int) -> bytes:
        picc = holder["picc"]
        picc.close()
        callback_free_counts.append(len(freed_piccs))
        callback_handles.append(picc._handle.value)
        return b"\x5a" * length

    picc = make_picc(close_from_callback)
    holder["picc"] = picc
    picc.activate()

    assert picc.exchange(GET_CHALLENGE) == bytes.fromhex("5a5a5a5a5a5a5a5a9000")
    assert callback_free_counts == [0]
    assert callback_handles == [None]
    assert len(freed_piccs) == 1
    with pytest.raises(RuntimeError, match="virtual PICC is closed"):
        picc.snapshot()


@pytest.mark.parametrize("_iteration", range(32))
def test_concurrent_close_marks_closed_before_in_flight_exchange_returns(
    _iteration: int,
    freed_piccs: list[int | None],
) -> None:
    callback_entered = threading.Event()
    release_callback = threading.Event()
    close_returned = threading.Event()
    exchange_result: list[bytes] = []
    errors: list[BaseException] = []

    def blocking_random(length: int) -> bytes:
        callback_entered.set()
        if not release_callback.wait(5):
            raise TimeoutError("callback was not released")
        return b"\xa5" * length

    picc = make_picc(blocking_random)
    picc.activate()

    def exchange() -> None:
        try:
            exchange_result.append(picc.exchange(GET_CHALLENGE))
        except BaseException as exc:  # noqa: BLE001, reported in the test thread
            errors.append(exc)

    def close() -> None:
        picc.close()
        close_returned.set()

    exchange_thread = threading.Thread(target=exchange)
    close_thread = threading.Thread(target=close)
    exchange_thread.start()
    assert callback_entered.wait(5)
    close_thread.start()
    try:
        assert close_returned.wait(1)
        assert picc._handle.value is None
        assert not freed_piccs
    finally:
        release_callback.set()
        exchange_thread.join(5)
        close_thread.join(5)

    assert not exchange_thread.is_alive()
    assert not close_thread.is_alive()
    assert not errors
    assert exchange_result == [bytes.fromhex("a5a5a5a5a5a5a5a59000")]
    assert len(freed_piccs) == 1


CLOSED_PICC_CALLS: list[tuple[str, Callable[[VirtualPicc], object]]] = [
    ("enter", lambda picc: picc.__enter__()),
    ("activate", lambda picc: picc.activate()),
    ("exchange", lambda picc: picc.exchange(b"")),
    ("transceive", lambda picc: picc.transceive(b"")),
    ("frame_exchange", lambda picc: picc.frame_exchange(b"")),
    ("field_off", lambda picc: picc.field_off()),
    ("reset_protocol", lambda picc: picc.reset_protocol()),
    ("advance_time", lambda picc: picc.advance_time(1)),
    ("mark_persisted", lambda picc: picc.mark_persisted()),
    ("snapshot", lambda picc: picc.snapshot()),
    ("export", lambda picc: picc.export()),
]


@pytest.mark.parametrize(
    ("name", "invoke"), CLOSED_PICC_CALLS, ids=[name for name, _ in CLOSED_PICC_CALLS]
)
def test_closed_picc_rejects_every_native_path(
    name: str,
    invoke: Callable[[VirtualPicc], object],
    freed_piccs: list[int | None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    picc = make_picc()
    picc.close()
    picc.close()
    assert picc._handle.value is None
    assert len(freed_piccs) == 1

    def unexpected_native_access() -> None:
        pytest.fail(f"{name} accessed the native library after close")

    monkeypatch.setattr(_native, "library", unexpected_native_access)
    with pytest.raises(RuntimeError, match="virtual PICC is closed"):
        invoke(picc)


@pytest.mark.parametrize("with_callback", [False, True])
def test_finalizer_only_cleanup(with_callback: bool, freed_piccs: list[int | None]) -> None:
    picc = make_picc((lambda length: bytes(length)) if with_callback else None)
    reference = weakref.ref(picc)

    del picc
    gc.collect()

    assert reference() is None
    assert len(freed_piccs) == 1


def test_throwing_callback_releases_its_operation_lease(
    freed_piccs: list[int | None],
) -> None:
    def broken(_: int) -> bytes:
        raise LookupError("script exhausted")

    picc = make_picc(broken)
    picc.activate()
    with pytest.raises(RandomSourceError, match="random source failed") as failure:
        picc.exchange(GET_CHALLENGE)
    assert isinstance(failure.value.__cause__, LookupError)
    assert picc._active_calls == 0

    picc.close()
    assert picc._handle.value is None
    assert len(freed_piccs) == 1
