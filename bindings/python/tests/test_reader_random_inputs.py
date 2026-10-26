from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from dfc_core import InvalidArgumentError, Reader, _native
from dfc_core import reader as reader_module

AUTH_BOUNDARIES = Path(__file__).parents[3] / "tests" / "authentication-boundaries.txt"

ChallengeCall = Callable[[Reader, bytes | None], object]

RANDOM_CHALLENGE_CASES: list[tuple[str, int, str, ChallengeCall]] = [
    (
        "native-legacy",
        8,
        "dfc_ffi_reader_authenticate_begin",
        lambda reader, value: reader.authenticate(0x0A, 0, bytes(8), random_a=value),
    ),
    (
        "native-iso-two-key",
        8,
        "dfc_ffi_reader_authenticate_begin",
        lambda reader, value: reader.authenticate(0x1A, 0, bytes(16), random_a=value),
    ),
    (
        "native-iso-three-key",
        16,
        "dfc_ffi_reader_authenticate_begin",
        lambda reader, value: reader.authenticate(0x1A, 0, bytes(24), random_a=value),
    ),
    (
        "native-aes",
        16,
        "dfc_ffi_reader_authenticate_begin",
        lambda reader, value: reader.authenticate(0xAA, 0, bytes(16), random_a=value),
    ),
    (
        "ev2-first",
        16,
        "dfc_ffi_reader_authenticate_ev2_begin",
        lambda reader, value: reader.authenticate_ev2(0, bytes(16), first=True, random_a=value),
    ),
    (
        "ev2-non-first",
        16,
        "dfc_ffi_reader_authenticate_ev2_begin",
        lambda reader, value: reader.authenticate_ev2(0, bytes(16), first=False, random_a=value),
    ),
    (
        "iso-two-key-first",
        8,
        "dfc_ffi_reader_authenticate_iso7816_begin",
        lambda reader, value: reader.authenticate_iso7816(
            0, 0x02, bytes(16), random_first=value, random_second=bytes(8)
        ),
    ),
    (
        "iso-two-key-second",
        8,
        "dfc_ffi_reader_authenticate_iso7816_begin",
        lambda reader, value: reader.authenticate_iso7816(
            0, 0x02, bytes(16), random_first=bytes(8), random_second=value
        ),
    ),
    (
        "iso-three-key-first",
        16,
        "dfc_ffi_reader_authenticate_iso7816_begin",
        lambda reader, value: reader.authenticate_iso7816(
            0, 0x04, bytes(24), random_first=value, random_second=bytes(16)
        ),
    ),
    (
        "iso-three-key-second",
        16,
        "dfc_ffi_reader_authenticate_iso7816_begin",
        lambda reader, value: reader.authenticate_iso7816(
            0, 0x04, bytes(24), random_first=bytes(16), random_second=value
        ),
    ),
    (
        "iso-aes-first",
        16,
        "dfc_ffi_reader_authenticate_iso7816_begin",
        lambda reader, value: reader.authenticate_iso7816(
            0, 0x09, bytes(16), random_first=value, random_second=bytes(16)
        ),
    ),
    (
        "iso-aes-second",
        16,
        "dfc_ffi_reader_authenticate_iso7816_begin",
        lambda reader, value: reader.authenticate_iso7816(
            0, 0x09, bytes(16), random_first=bytes(16), random_second=value
        ),
    ),
]


def test_native_authentication_boundaries_match_shared_contract() -> None:
    cipher_ids = {
        "legacy": reader_module.AUTHENTICATE_LEGACY,
        "iso": reader_module.AUTHENTICATE_ISO,
        "aes": reader_module.AUTHENTICATE_AES,
    }
    for raw in AUTH_BOUNDARIES.read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        cipher, key_length, challenge_length, accepted = raw.split("|")
        try:
            actual = reader_module._native_auth_challenge_length(
                cipher_ids[cipher], int(key_length)
            )
        except InvalidArgumentError:
            assert accepted == "no", raw
        else:
            assert (actual == int(challenge_length)) == (accepted == "yes"), raw


@pytest.mark.parametrize(
    ("name", "required", "begin_name", "invoke"),
    RANDOM_CHALLENGE_CASES,
    ids=[name for name, *_ in RANDOM_CHALLENGE_CASES],
)
@pytest.mark.parametrize("supplied_kind", ["omitted", "empty", "short", "exact", "long"])
def test_replay_randomness_distinguishes_omitted_from_explicit(
    name: str,
    required: int,
    begin_name: str,
    invoke: ChallengeCall,
    supplied_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NoTransport:
        calls = 0

        def transceive(self, _command: bytes) -> bytes:
            self.calls += 1
            pytest.fail(f"{name} reached transport")

    random_draws: list[int] = []

    def draw(length: int) -> bytes:
        random_draws.append(length)
        return bytes((0xA5,)) * length

    transport = NoTransport()
    with Reader(transport) as reader:
        library = _native.library()
        begin_calls = 0

        def reject(*_args: object) -> int:
            nonlocal begin_calls
            begin_calls += 1
            return _native.INVALID_ARGUMENT

        monkeypatch.setattr(reader_module.secrets, "token_bytes", draw)
        monkeypatch.setattr(library, begin_name, reject)

        supplied = {
            "omitted": None,
            "empty": b"",
            "short": bytes(required - 1),
            "exact": bytes(required),
            "long": bytes(required + 1),
        }[supplied_kind]
        with pytest.raises(ValueError):
            invoke(reader, supplied)

        assert random_draws == ([required] if supplied is None else [])
        assert begin_calls == (1 if supplied is None or len(supplied) == required else 0)
        assert transport.calls == 0


@pytest.mark.parametrize(
    ("algorithm", "key", "required"),
    [
        pytest.param(0x02, bytes(16), 8, id="two-key-tdea"),
        pytest.param(0x04, bytes(24), 16, id="three-key-tdea"),
        pytest.param(0x09, bytes(16), 16, id="aes"),
    ],
)
@pytest.mark.parametrize("invalid_kind", ["empty", "short", "long"])
@pytest.mark.parametrize("invalid_argument", ["first", "second"])
def test_iso_replay_validates_all_supplied_randomness_before_drawing(
    algorithm: int,
    key: bytes,
    required: int,
    invalid_kind: str,
    invalid_argument: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NoTransport:
        def transceive(self, _command: bytes) -> bytes:
            pytest.fail("invalid ISO replay randomness reached transport")

    invalid = {
        "empty": b"",
        "short": bytes(required - 1),
        "long": bytes(required + 1),
    }[invalid_kind]
    first = invalid if invalid_argument == "first" else None
    second = invalid if invalid_argument == "second" else None
    random_draws: list[int] = []
    begin_calls = 0

    def reject(*_args: object) -> int:
        nonlocal begin_calls
        begin_calls += 1
        return _native.INVALID_ARGUMENT

    monkeypatch.setattr(
        reader_module.secrets,
        "token_bytes",
        lambda length: random_draws.append(length) or bytes(length),
    )
    monkeypatch.setattr(_native.library(), "dfc_ffi_reader_authenticate_iso7816_begin", reject)

    with Reader(NoTransport()) as reader, pytest.raises(ValueError):
        reader.authenticate_iso7816(
            0,
            algorithm,
            key,
            random_first=first,
            random_second=second,
        )

    assert random_draws == []
    assert begin_calls == 0
