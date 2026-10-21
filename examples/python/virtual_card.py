"""Inspect a credential and read a data file through a virtual card."""

from __future__ import annotations

import argparse
from pathlib import Path

from dfc_core import Command, Credential, Reader, VirtualPicc


def inspect_card(credential_path: Path) -> tuple[str, str, bytes]:
    """Load a credential, activate it, and read application file 2."""
    credential = Credential.load(credential_path.read_bytes())
    model = credential.model()
    if not model.applications:
        raise ValueError("the credential has no applications to inspect")

    application = model.applications[0]

    # VirtualPicc takes ownership of the credential. Context managers clear
    # native handles, including keys and session state, promptly.
    with VirtualPicc(credential) as picc:
        activation = picc.activate()
        with Reader(picc) as reader:
            # Reader drives the complete exchange. VirtualPicc implements the
            # same transport protocol as a USB or NFC adapter.
            select = reader.exchange(Command.select_application(application.aid))
            if select.status != 0:
                raise RuntimeError(f"select application failed: {select.status:#04x}")

            response = reader.exchange(Command.read_data(file_number=2, offset=0, length=0))
            if response.status != 0:
                raise RuntimeError(f"read data failed: {response.status:#04x}")

    return activation.uid.hex(":"), application.aid.hex(), response.data


def main() -> None:
    default_credential = Path(__file__).parents[1] / "credentials" / "v6-maximal.dfcb"
    parser = argparse.ArgumentParser(
        description="Read a public data file by transceiving with a dfc-core virtual card."
    )
    parser.add_argument(
        "credential",
        nargs="?",
        type=Path,
        default=default_credential,
        help="credential to emulate (default: examples/credentials/v6-maximal.dfcb)",
    )
    args = parser.parse_args()

    uid, aid, data = inspect_card(args.credential)
    print(f"Activated card UID: {uid}")
    print(f"Application {aid}, file 2: {data.hex(' ')}")


if __name__ == "__main__":
    main()
