import re
from pathlib import Path

from dfc_core import reader

REPOSITORY = Path(__file__).parents[3]
READER_STATUS_BLOCK = re.compile(
    r"// Stable reader-step statuses returned by dfc_ffi_reader_step\.\n"
    r"(?P<definitions>(?:#define DFC_FFI_READER_[A-Z0-9_]+\s+-?\d+\n)+)"
)
READER_STATUS = re.compile(r"^#define (DFC_FFI_READER_[A-Z0-9_]+)\s+(-?\d+)\s*$")
READER_STATUS_ASSERTION = re.compile(r"ASSERT_READER_STATUS\((DFC_FFI_READER_[A-Z0-9_]+),")


def reader_statuses(header: str) -> dict[str, int]:
    block = READER_STATUS_BLOCK.search(header)
    assert block is not None
    return {
        match.group(1): int(match.group(2))
        for line in block.group("definitions").splitlines()
        if (match := READER_STATUS.fullmatch(line))
    }


def registered_reader_statuses(source: str) -> set[str]:
    return set(READER_STATUS_ASSERTION.findall(source))


def ffi_sources() -> str:
    return "\n".join(path.read_text() for path in sorted((REPOSITORY / "ffi").glob("dfc_ffi*.c")))


def test_python_reader_statuses_match_the_complete_c_family() -> None:
    header = (REPOSITORY / "ffi" / "dfc_ffi.h").read_text()
    source = ffi_sources()
    statuses = reader_statuses(header)

    assert set(statuses) == registered_reader_statuses(source)
    assert len(statuses.values()) == len(set(statuses.values()))
    assert {
        name: statuses[name]
        for name in (
            "DFC_FFI_READER_OK",
            "DFC_FFI_READER_PENDING",
            "DFC_FFI_READER_BUFFER_TOO_SMALL",
            "DFC_FFI_READER_CARD_ERROR",
        )
    } == {
        "DFC_FFI_READER_OK": 0,
        "DFC_FFI_READER_PENDING": 1,
        "DFC_FFI_READER_BUFFER_TOO_SMALL": 3,
        "DFC_FFI_READER_CARD_ERROR": 6,
    }

    assert reader.READER_PENDING == statuses["DFC_FFI_READER_PENDING"]
    assert reader.READER_BUFFER_TOO_SMALL == statuses["DFC_FFI_READER_BUFFER_TOO_SMALL"]
    assert reader.READER_CARD_ERROR == statuses["DFC_FFI_READER_CARD_ERROR"]
    assert {
        name.removeprefix("DFC_FFI_"): value
        for name, value in statuses.items()
        if name.removeprefix("DFC_FFI_") in vars(reader)
    } == {
        name: value
        for name, value in vars(reader).items()
        if name.startswith("READER_") and isinstance(value, int)
    }


def test_new_c_reader_status_requires_registration() -> None:
    header = (REPOSITORY / "ffi" / "dfc_ffi.h").read_text()
    source = ffi_sources()

    statuses = reader_statuses(
        header.replace(
            "\n\n// Largest explicit clear-header length",
            "\n#define DFC_FFI_READER_EV2_NEW 8\n\n// Largest explicit clear-header length",
        )
    )

    assert set(statuses) != registered_reader_statuses(source)
    assert registered_reader_statuses(
        "ASSERT_READER_STATUS(DFC_FFI_READER_EV2_NEW, DfcReaderEv2New);"
    ) == {"DFC_FFI_READER_EV2_NEW"}
