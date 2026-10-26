"""Verify backend data and a receipt returned by a virtual card."""

from pathlib import Path

from dfc_core import (
    Command,
    Credential,
    Reader,
    SdmConfig,
    SdmField,
    TransactionMacVerifier,
    VirtualPicc,
    decode_file_settings,
    verify_sdm,
)


def main() -> None:
    message = b"0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E"
    verified = verify_sdm(
        message,
        SdmConfig(
            mac_input_offset=20,
            mac_offset=52,
            plain_uid=SdmField(0, 7),
            plain_read_counter_offset=14,
            encrypted_file_data=SdmField(20, 32),
        ),
        file_read_key=bytes(16),
    )
    if verified.uid is None:
        raise RuntimeError("verified message did not contain a UID")
    print(f"verified SDM UID={verified.uid.hex()}, counter={verified.read_counter}")

    credential_path = Path(__file__).parents[1] / "credentials" / "v6-maximal.dfc"
    # This example does not submit a reader ID, so disable that optional policy
    # in its private credential copy before starting the virtual card.
    credential_text = credential_path.read_text().replace(
        "Application 00 File 05 Access Rights: 1F 00",
        "Application 00 File 05 Access Rights: FF FF",
    )
    credential = Credential.parse(credential_text)
    model = credential.model()
    transaction_file = next(file for file in model.files if file.type == 5)
    application = model.applications[0]

    with VirtualPicc(credential) as picc, Reader(picc) as reader:
        picc.activate()
        reader.exchange(Command.select_application(application.aid))
        settings_response = reader.exchange(Command.file_operation(0xF5, 3))
        settings = decode_file_settings(settings_response.data)
        print(f"value file communication mode={settings.communication_mode}")

        reader.exchange(Command(0x0C, bytes((3,)) + (1).to_bytes(4, "little")))
        commit = reader.exchange(Command.commit_transaction(1))

    if len(commit.data) != 12:
        raise RuntimeError("commit did not return a counter and transaction MAC")
    counter = int.from_bytes(commit.data[:4], "little")
    with TransactionMacVerifier(
        transaction_file.transaction_mac_key, model.card.uid, counter
    ) as receipt:
        receipt.add_value(0x0C, 3, 1)
        if not receipt.verify(commit.data[4:]):
            raise RuntimeError("transaction receipt did not match")
    print(f"transaction receipt {counter} verified")


if __name__ == "__main__":
    main()
