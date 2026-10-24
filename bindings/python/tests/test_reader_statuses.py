from pathlib import Path

from dfc_core import reader

REPOSITORY = Path(__file__).parents[3]
READER_STATUS_NAMES = {
    "DFC_FFI_READER_OK",
    "DFC_FFI_READER_PENDING",
    "DFC_FFI_READER_INVALID",
    "DFC_FFI_READER_BUFFER_TOO_SMALL",
    "DFC_FFI_READER_PROTOCOL_ERROR",
    "DFC_FFI_READER_INTEGRITY_ERROR",
    "DFC_FFI_READER_CARD_ERROR",
    "DFC_FFI_READER_UNSUPPORTED",
}


def reader_statuses() -> dict[str, int]:
    statuses: dict[str, int] = {}
    for line in (REPOSITORY / "ffi" / "dfc_ffi.h").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "#define" and fields[1] in READER_STATUS_NAMES:
            statuses[fields[1]] = int(fields[2])
    return statuses


def test_python_reader_statuses_match_the_complete_c_family() -> None:
    statuses = reader_statuses()

    assert set(statuses) == READER_STATUS_NAMES
    assert reader.READER_PENDING == statuses["DFC_FFI_READER_PENDING"]
    assert reader.READER_BUFFER_TOO_SMALL == statuses["DFC_FFI_READER_BUFFER_TOO_SMALL"]
    assert reader.READER_CARD_ERROR == statuses["DFC_FFI_READER_CARD_ERROR"]
