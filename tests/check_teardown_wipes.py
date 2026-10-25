#!/usr/bin/env python3
"""Verify that secret-bearing owned storage is wiped on teardown."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def main() -> None:
    emulator = (ROOT / "src" / "dfc_emulator.c").read_text(encoding="utf-8")
    commands = (ROOT / "src" / "dfc_emulator_commands.c").read_text(encoding="utf-8")
    credential = (ROOT / "src" / "dfc_credential.c").read_text(encoding="utf-8")
    emulator_crypto = (ROOT / "src" / "dfc_emulator_crypto.c").read_text(encoding="utf-8")
    ffi = (ROOT / "ffi" / "dfc_ffi.c").read_text(encoding="utf-8")
    reader = (ROOT / "src" / "dfc_reader.c").read_text(encoding="utf-8")
    virtual_picc = (ROOT / "src" / "dfc_virtual_picc.c").read_text(encoding="utf-8")
    emulator_commands = (ROOT / "src" / "dfc_emulator_commands.c").read_text(encoding="utf-8")
    required = {
        "emulator teardown": "dfc_secure_wipe(emulator, sizeof(*emulator))",
        "credential teardown": "dfc_secure_wipe(credential, sizeof(*credential))",
        "response storage": "dfc_secure_wipe(emulator->tx_buffer, sizeof(*emulator->tx_buffer))",
        "command-chain helper": "dfc_emulator_discard_command_chain(emulator)",
        "snapshot helper": "dfc_emulator_discard_transaction_snapshot(emulator)",
    }
    combined = emulator + commands + credential
    missing = [name for name, expression in required.items() if expression not in combined]
    if missing:
        raise SystemExit("missing teardown wipe coverage: " + ", ".join(missing))

    direct_command_frees = re.findall(r"dfc_platform_free\(emulator->command_chain\)", combined)
    direct_snapshot_frees = re.findall(
        r"dfc_platform_free\(emulator->transaction_snapshot_pool\)", combined
    )
    if len(direct_command_frees) != 1 or len(direct_snapshot_frees) != 1:
        raise SystemExit("owned emulator buffers must only be freed by their wipe helpers")

    if combined.count("dfc_emulator_discard_command_chain(emulator)") < 6:
        raise SystemExit("not every command-chain teardown path uses the wipe helper")
    if combined.count("dfc_emulator_discard_transaction_snapshot(emulator)") < 4:
        raise SystemExit("not every transaction-snapshot teardown path uses the wipe helper")

    credential_free = credential[credential.index("void dfc_credential_free(") :]
    if credential_free.index("dfc_secure_wipe(credential") > credential_free.index(
        "free(credential)"
    ):
        raise SystemExit("credential is freed before it is wiped")

    emulator_free = emulator[emulator.index("void dfc_emulator_free(") :]
    if emulator_free.index("dfc_secure_wipe(emulator->tx_buffer") > emulator_free.index(
        "dfc_bytebuf_free(emulator->tx_buffer)"
    ):
        raise SystemExit("response buffer is freed before it is wiped")

    native_exchange = virtual_picc[
        virtual_picc.index(
            "static DfcVirtualPiccStatus handle_native_exchange("
        ) : virtual_picc.index("static DfcVirtualPiccStatus virtual_picc_iso_dep_exchange(")
    ]
    native_required = {
        "native clear command": "dfc_secure_wipe(short_clear_command, sizeof(short_clear_command))",
        "borrowed native clear command": "dfc_emulator_discard_command_chain(session->emulator)",
        "native secured response": "dfc_secure_wipe(secured_response, sizeof(secured_response))",
        "native response bytebuf": "dfc_secure_wipe(tx, sizeof(*tx))",
    }
    native_missing = [
        name for name, expression in native_required.items() if expression not in native_exchange
    ]
    if native_missing:
        raise SystemExit("missing native-exchange wipe coverage: " + ", ".join(native_missing))
    if "dfc_bytebuf_free(tx)" in native_exchange:
        raise SystemExit("native exchange must not free the emulator-owned response buffer")
    native_cleanup = native_exchange[native_exchange.index("cleanup:") :]
    if any(expression not in native_cleanup for expression in native_required.values()):
        raise SystemExit("native exchange must wipe all owned buffers through cleanup")
    if "session->emulator->command_chain_len = command_len" not in native_exchange:
        raise SystemExit("borrowed native clear command must retain its used length for wiping")

    d40_helpers = {
        "emulator D40 receive": emulator_crypto[
            emulator_crypto.index("bool dfc_emulator_d40_receive_plain(") : emulator_crypto.index(
                "uint8_t dfc_emulator_des_key_version("
            )
        ],
        "reader D40 send": reader[
            reader.index("static bool\n    d40_send(") : reader.index("static void put_le32(")
        ],
    }
    for name, helper in d40_helpers.items():
        if "dfc_secure_wipe(block, sizeof(block))" not in helper:
            raise SystemExit(f"missing {name} block wipe")
        if helper.count("return") != 1:
            raise SystemExit(f"{name} must use one cleanup return")
        if helper.index("dfc_secure_wipe(block, sizeof(block))") > helper.index("return"):
            raise SystemExit(f"{name} returns before wiping its local block")

    change_key = reader[
        reader.index("DfcReaderStatus dfc_reader_change_key_cryptogram(") : reader.index(
            "static bool wire_mac_8("
        )
    ]
    for local in ("stored", "clear", "iv"):
        expression = f"dfc_secure_wipe({local}, sizeof({local}))"
        if expression not in change_key:
            raise SystemExit(f"change-key cryptogram does not wipe {local}")
        if change_key.index(expression) > change_key.index("return"):
            raise SystemExit(f"change-key cryptogram returns before wiping {local}")
    if change_key.count("return") != 1:
        raise SystemExit("change-key cryptogram must use one cleanup return")

    ev2_change_key = emulator_commands[
        emulator_commands.index("static void handle_change_key_ev2(") : emulator_commands.index(
            "#endif\n\n#if DFC_ENABLE_DELEGATED_APPLICATIONS"
        )
    ]
    if ev2_change_key.count("dfc_secure_wipe(new_key, sizeof(new_key))") < 2:
        raise SystemExit("EV2 ChangeKey must wipe its candidate key on CRC failure and success")

    commit_transaction = emulator_commands[
        emulator_commands.index("static void handle_commit_transaction(") : emulator_commands.index(
            "static void handle_abort_transaction("
        )
    ]
    mac_failure = commit_transaction[
        commit_transaction.index("if(!transaction_mac_calculate(") : commit_transaction.index(
            "#else\n    DFC_UNUSED(return_transaction_mac);"
        )
    ]
    if "dfc_secure_wipe(pending_reader_id, sizeof(pending_reader_id))" not in mac_failure:
        raise SystemExit("CommitTransaction MAC failure does not wipe its pending reader ID")

    iso_cleanup = emulator[
        emulator.index("void dfc_emulator_clear_iso_authentication(") : emulator.index(
            "void dfc_emulator_reset_session("
        )
    ]
    for local in (
        "iso_auth_card_first",
        "iso_auth_host_first",
        "iso_auth_external_iv",
        "iso_auth_key",
    ):
        expression = f"dfc_secure_wipe(emulator->{local}, sizeof(emulator->{local}))"
        if expression not in iso_cleanup:
            raise SystemExit(f"ISO authentication cleanup does not wipe {local}")
    if "dfc_emulator_clear_iso_authentication(emulator)" not in virtual_picc:
        raise SystemExit("virtual PICC does not use centralized ISO authentication cleanup")

    ffi_exchange_begin = ffi[
        ffi.index("int32_t dfc_ffi_reader_exchange_begin(") : ffi.index(
            "int32_t dfc_ffi_reader_write_data_begin("
        )
    ]
    command_lifetime = ffi_exchange_begin[ffi_exchange_begin.index("DfcCommand command") :]
    if command_lifetime.count("return") != 1 or (
        command_lifetime.index("dfc_secure_wipe(&command, sizeof(command))")
        > command_lifetime.index("return")
    ):
        raise SystemExit("FFI exchange command must leave through its wipe cleanup")

    ffi_ev2_key = ffi[
        ffi.index("int32_t dfc_ffi_reader_change_key_ev2_data(") : ffi.index(
            "#else", ffi.index("int32_t dfc_ffi_reader_change_key_ev2_data(")
        )
    ]
    ev2_command_lifetime = ffi_ev2_key[ffi_ev2_key.index("DfcCommand command") :]
    if ev2_command_lifetime.count("return") != 1 or (
        ev2_command_lifetime.index("dfc_secure_wipe(&command, sizeof(command))")
        > ev2_command_lifetime.index("return")
    ):
        raise SystemExit("FFI EV2 ChangeKey command must leave through its wipe cleanup")

    result_data = ffi[
        ffi.index("int32_t dfc_ffi_reader_result_data(") : ffi.index(
            "int32_t dfc_ffi_reader_change_key_cryptogram("
        )
    ]
    if (
        "dfc_secure_wipe(exchange->exchange.data, sizeof(exchange->exchange.data))"
        not in result_data
    ):
        raise SystemExit("FFI reader results are not wiped after delivery")

    ffi_step = ffi[
        ffi.index("int32_t dfc_ffi_reader_step(") : ffi.index(
            "uint8_t dfc_ffi_reader_result_status("
        )
    ]
    if "dfc_secure_wipe(exchange->exchange.data, sizeof(exchange->exchange.data))" not in ffi_step:
        raise SystemExit("failed FFI reader exchanges do not wipe their result storage")

    stream_chunk = reader[
        reader.index("static DfcReaderStatus begin_stream_chunk(") : reader.index(
            "static DfcReaderStatus begin_stream("
        )
    ]
    if stream_chunk.count("dfc_secure_wipe(&command, sizeof(command))") != 1:
        raise SystemExit("reader stream chunks must wipe their stack command")
    if stream_chunk.index("dfc_secure_wipe(&command, sizeof(command))") > stream_chunk.rindex(
        "return"
    ):
        raise SystemExit("reader stream chunks return before wiping their stack command")

    delegated = reader[
        reader.index(
            "DfcReaderStatus dfc_reader_create_delegated_application_begin("
        ) : reader.index("// ---------------------------------------------------- proximity check")
    ]
    if delegated.count("dfc_secure_wipe(&header, sizeof(header))") != 2:
        raise SystemExit(
            "delegated application setup must wipe its header on rejection and cleanup"
        )


if __name__ == "__main__":
    main()
