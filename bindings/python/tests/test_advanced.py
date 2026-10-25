from __future__ import annotations

import pytest

from dfc_core import (
    AccessKind,
    DiversificationAlgorithm,
    ResponseDecodeError,
    SdmConfig,
    SdmField,
    SdmVerificationError,
    TransactionMacError,
    TransactionMacVerifier,
    decode_application_ids,
    decode_file_settings,
    diversify_key,
    verify_sdm,
)


def test_diversification_and_typed_decoders() -> None:
    master = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    diversifier = bytes.fromhex("04782E21801D803042F54E585020416275")
    assert diversify_key(DiversificationAlgorithm.AES128, master, diversifier) == bytes.fromhex(
        "A8DD63A3B89D54B37CA802473FDA9175"
    )
    assert decode_application_ids(bytes.fromhex("030201CCBBAA")) == (
        bytes.fromhex("010203"),
        bytes.fromhex("AABBCC"),
    )
    settings = decode_file_settings(bytes.fromhex("000312EF800000"))
    assert settings.size == 128
    assert settings.access.read.kind is AccessKind.FREE
    assert settings.access.write.kind is AccessKind.DENIED
    with pytest.raises(ResponseDecodeError):
        decode_file_settings(b"\0")


def test_captured_sdm_and_transaction_receipts() -> None:
    message = b"0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E"
    config = SdmConfig(
        mac_input_offset=20,
        mac_offset=52,
        plain_uid=SdmField(0, 7),
        plain_read_counter_offset=14,
        encrypted_file_data=SdmField(20, 32),
    )
    result = verify_sdm(message, config, bytes(16))
    assert result.uid == bytes.fromhex("0483B4F2CF1890")
    assert result.read_counter == 1
    assert result.decrypted_file_data == bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    changed = bytearray(message)
    changed[-1] = ord("F") if changed[-1] != ord("F") else ord("E")
    with pytest.raises(SdmVerificationError):
        verify_sdm(bytes(changed), config, bytes(16))
    with pytest.raises(SdmVerificationError):
        verify_sdm(message, config, bytes([1]) * 16)
    with pytest.raises(ValueError):
        verify_sdm(message, SdmConfig(-1, 52), bytes(16))

    with TransactionMacVerifier(
        bytes(16), bytes.fromhex("0483B4F2CF1890"), counter=1, capacity=64
    ) as verifier:
        verifier.add_value(0x0C, 5, 1)
        assert verifier.verify(bytes.fromhex("352E57ADDA911EDC"))
        assert not verifier.verify(bytes.fromhex("352E57ADDA911EDD"))

    with TransactionMacVerifier(
        bytes(16), bytes.fromhex("0483B4F2CF1890"), counter=2, capacity=64
    ) as wrong_counter:
        wrong_counter.add_value(0x0C, 5, 1)
        assert not wrong_counter.verify(bytes.fromhex("352E57ADDA911EDC"))

    with TransactionMacVerifier(
        bytes(16), bytes.fromhex("0483B4F2CF1890"), counter=1, capacity=64
    ) as changed_value:
        changed_value.add_value(0x0C, 5, 2)
        assert not changed_value.verify(bytes.fromhex("352E57ADDA911EDC"))

    with TransactionMacVerifier(
        bytes([1]) + bytes(15), bytes.fromhex("0483B4F2CF1890"), counter=1, capacity=64
    ) as wrong_key:
        wrong_key.add_value(0x0C, 5, 1)
        assert not wrong_key.verify(bytes.fromhex("352E57ADDA911EDC"))

    expected_ordered = bytes.fromhex("7BEE577D5D8D0C69")
    with TransactionMacVerifier(
        bytes(16), bytes.fromhex("0483B4F2CF1890"), counter=1, capacity=64
    ) as reordered:
        reordered.add_value(0xDC, 5, 2)
        reordered.add_value(0x0C, 5, 1)
        assert not reordered.verify(expected_ordered)

    with (
        TransactionMacVerifier(
            bytes(16), bytes.fromhex("0483B4F2CF1890"), counter=1, capacity=64
        ) as omitted,
        pytest.raises(TransactionMacError),
    ):
        omitted.verify(bytes.fromhex("352E57ADDA911EDC"))

    with pytest.raises(ValueError):
        TransactionMacVerifier(bytes(16), bytes.fromhex("0483B4F2CF1890"), counter=1 << 32)


def test_transaction_input_helpers_validate_before_native_narrowing() -> None:
    with TransactionMacVerifier(bytes(16), bytes.fromhex("0483B4F2CF1890"), 1, 160) as verifier:
        verifier.add_data(0x3D, 2, 0x030201, 3, bytes.fromhex("A1B2C3"))
        verifier.add_record_update(0xDB, 3, 4, 5, 2, bytes.fromhex("4455"))
        verifier.add_reader_id(bytes([0x66]) * 16, bytes([0x77]) * 16)
        with pytest.raises(ValueError):
            verifier.add_data(0x100, 2, 0, 0, b"")
        with pytest.raises(ValueError):
            verifier.add_record_update(0xDB, 3, 1 << 32, 0, 0, b"")
