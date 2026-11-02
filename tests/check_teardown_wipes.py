#!/usr/bin/env python3
"""Verify that secret-bearing owned storage is wiped on teardown."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def command_sources() -> str:
    """Read every native command module as one policy-checking surface."""
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src").glob("dfc_emulator_commands*.c"))
    )


def emulator_auth_cleanup_problems(source: str) -> list[str]:
    """Require each secret-bearing authentication handler to have one exit."""
    functions = (
        (
            "EV2 start",
            "dfc_emulator_command_authenticate_ev2_start",
            "ev2_start_cleanup:",
        ),
        (
            "EV2 continuation",
            "dfc_emulator_command_authenticate_ev2_continuation",
            "ev2_continuation_cleanup:",
        ),
        (
            "native start",
            "dfc_emulator_command_authenticate_step1",
            "auth_start_cleanup:",
        ),
        (
            "native continuation",
            "dfc_emulator_command_authenticate_step2",
            "auth_step2_cleanup:",
        ),
    )
    problems = []
    for index, (name, signature, label) in enumerate(functions):
        start = source.index(signature)
        end = (
            source.index(functions[index + 1][1], start)
            if index + 1 < len(functions)
            else len(source)
        )
        function = source[start:end]
        secret_start = function.find("Secrets secrets;")
        cleanup_start = function.find(label)
        wipe = "dfc_secure_wipe(&secrets, sizeof(secrets))"
        if secret_start < 0 or cleanup_start < 0 or function.count(wipe) != 1:
            problems.append(f"{name} does not use one secret cleanup")
            continue
        if "return" in function[secret_start:cleanup_start]:
            problems.append(f"{name} returns before secret cleanup")
    return problems


def main() -> None:
    emulator = (ROOT / "src" / "dfc_emulator.c").read_text(encoding="utf-8")
    emulator_header = (ROOT / "src" / "dfc_emulator.h").read_text(encoding="utf-8")
    production = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "src").glob("*.[ch]"))
    )
    commands = command_sources()
    credential = (ROOT / "src" / "dfc_credential.c").read_text(encoding="utf-8")
    emulator_crypto = (ROOT / "src" / "dfc_emulator_crypto.c").read_text(encoding="utf-8")
    des_chain = (ROOT / "src" / "dfc_crypto_des_chain.c").read_text(encoding="utf-8")
    emulator_auth = (ROOT / "src" / "dfc_emulator_commands_auth.c").read_text(encoding="utf-8")
    ffi = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "ffi").glob("dfc_ffi*.c"))
        if path.name != "dfc_target_ffi.c"
    )
    reader = (ROOT / "src" / "dfc_reader.c").read_text(encoding="utf-8")
    virtual_picc = (ROOT / "src" / "dfc_virtual_picc.c").read_text(encoding="utf-8")
    emulator_commands = commands
    auth_cleanup_failures = emulator_auth_cleanup_problems(emulator_auth)
    if auth_cleanup_failures:
        raise SystemExit("; ".join(auth_cleanup_failures))
    cleanup_wipe = "dfc_secure_wipe(&secrets, sizeof(secrets));"
    mutant = emulator_auth.replace(cleanup_wipe, "", 1)
    if not emulator_auth_cleanup_problems(mutant):
        raise SystemExit("emulator authentication cleanup guard failed its mutation self-test")
    if "rnd_a[" in emulator_header or "->rnd_a" in production:
        raise SystemExit("completed host challenges must remain operation-local")
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
    if combined.count("dfc_emulator_discard_transaction_snapshot(emulator)") < 3:
        raise SystemExit("transaction-snapshot storage bypasses the wipe helper")
    snapshot_clear = emulator[
        emulator.index("static void transaction_snapshot_clear_state(") : emulator.index(
            "bool dfc_emulator_transaction_snapshot_insert_file("
        )
    ]
    if "dfc_emulator_discard_transaction_snapshot(emulator)" not in snapshot_clear:
        raise SystemExit("transaction-snapshot state cleanup does not wipe owned storage")
    if emulator.count("transaction_snapshot_clear_state(emulator)") < 3:
        raise SystemExit("transaction-snapshot terminal paths bypass centralized cleanup")

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
            "static DfcVirtualPiccStatus handle_native_exchange_inner("
        ) : virtual_picc.index("static DfcVirtualPiccStatus virtual_picc_iso_dep_exchange(")
    ]
    native_required = {
        "native command scratch": "dfc_secure_wipe(command_scratch, command_scratch_capacity)",
        "borrowed native clear command": "dfc_emulator_discard_command_chain(session->emulator)",
        "native response bytebuf": "dfc_secure_wipe(tx, sizeof(*tx))",
    }
    native_missing = [
        name for name, expression in native_required.items() if expression not in native_exchange
    ]
    if native_missing:
        raise SystemExit("missing native-exchange wipe coverage: " + ", ".join(native_missing))
    if "dfc_bytebuf_free(tx)" in native_exchange:
        raise SystemExit("native exchange must not free the emulator-owned response buffer")
    if "secured_response[" in native_exchange or "pending_response[" in virtual_picc:
        raise SystemExit("native exchange must reuse the emulator response buffer")
    if "short_clear_command[" in native_exchange:
        raise SystemExit("native exchange must reuse its caller-owned command scratch")
    native_cleanup = native_exchange[native_exchange.index("cleanup:") :]
    if any(expression not in native_cleanup for expression in native_required.values()):
        raise SystemExit("native exchange must wipe all owned buffers through cleanup")
    if "session->emulator->command_chain_len = command_len" not in native_exchange:
        raise SystemExit("borrowed native clear command must retain its used length for wiping")

    d40_callers = {
        "emulator D40 receive": emulator_crypto[
            emulator_crypto.index("bool dfc_emulator_d40_receive_plain(") : emulator_crypto.index(
                "uint8_t dfc_emulator_des_key_version("
            )
        ],
        "reader D40 send": reader[
            reader.index("static bool\n    d40_send(") : reader.index(
                "// The full EV1 CMAC chained from the session IV."
            )
        ],
    }
    for name, caller in d40_callers.items():
        if "dfc_crypto_des_chain(" not in caller:
            raise SystemExit(f"{name} bypasses the wiping DES chain helper")
    if "dfc_secure_wipe(block, sizeof(block))" not in des_chain:
        raise SystemExit("DES chain helper does not wipe its local block")
    if "dfc_crypto_des_block_clear(&cipher)" not in des_chain:
        raise SystemExit("DES chain helper does not clear its cipher state")
    if des_chain.count("return") != 1:
        raise SystemExit("DES chain helper must use one cleanup return")

    reader_auth_functions = {
        "ISO": reader[
            reader.index("static DfcReaderStatus step_authenticate_iso7816(") : reader.index(
                "static DfcReaderStatus step_authenticate("
            )
        ],
        "native": reader[
            reader.index("static DfcReaderStatus step_authenticate(") : reader.index(
                "static DfcReaderStatus step_authenticate_ev2("
            )
        ],
        "EV2": reader[
            reader.index("static DfcReaderStatus step_authenticate_ev2(") : reader.index(
                "// ----------------------------------------------------------- command ---"
            )
        ],
    }
    reader_auth_cleanups = {
        "ISO external authentication": (
            "ISO",
            "uint8_t clear[DFC_ISO7816_AUTH_CHALLENGE_LONG * 2];",
            "iso_external_cleanup:",
            1,
            ("clear", "apdu", "iv"),
        ),
        "native authentication challenge": (
            "native",
            "uint8_t token[32];",
            "auth_challenge_cleanup:",
            2,
            ("token", "encrypted", "chain", "iv"),
        ),
        "EV2 authentication challenge": (
            "EV2",
            "uint8_t token[2 * DFC_EV2_RANDOM_LENGTH];",
            "ev2_challenge_cleanup:",
            1,
            ("token", "encrypted", "iv"),
        ),
        "EV2 authentication confirmation": (
            "EV2",
            "uint8_t transaction[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH];",
            "ev2_confirmation_cleanup:",
            1,
            (
                "encryption_key",
                "mac_key",
                "clear",
                "expected",
                "transaction",
                "card_caps",
                "reader_caps",
                "iv",
            ),
        ),
    }
    for name, (
        function_name,
        first_secret,
        label,
        expected_gotos,
        locals_,
    ) in reader_auth_cleanups.items():
        function = reader_auth_functions[function_name]
        goto = f"goto {label[:-1]};"
        if function.count(label) != 1 or function.count(goto) != expected_gotos:
            raise SystemExit(f"{name} does not route every failure through one cleanup")
        cleanup_start = function.index(label)
        region_start = function.index(first_secret)
        cleanup_end = function.index("return result;", cleanup_start) + len("return result;")
        region = function[region_start:cleanup_end]
        if region[: region.index(label)].count("return") != 0:
            raise SystemExit(f"{name} bypasses cleanup with an early return")
        cleanup = region[region.index(label) :]
        for local in locals_:
            expression = f"dfc_secure_wipe({local}, sizeof({local}))"
            if expression not in cleanup:
                raise SystemExit(f"{name} cleanup does not wipe {local}")

    change_key = reader[
        reader.index("DfcReaderStatus dfc_reader_change_key_cryptogram(") : reader.index(
            "// ------------------------------------------------------------ EV2 keys ---"
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
        emulator_commands.index(
            "void dfc_emulator_command_change_key_ev2("
        ) : emulator_commands.index("#endif\n\nvoid dfc_emulator_command_set_configuration(")
    ]
    if ev2_change_key.count("dfc_secure_wipe(new_key, sizeof(new_key))") < 2:
        raise SystemExit("EV2 ChangeKey must wipe its candidate key on CRC failure and success")

    commit_transaction = emulator_commands[
        emulator_commands.index(
            "void dfc_emulator_command_commit_transaction("
        ) : emulator_commands.index("void dfc_emulator_command_abort_transaction(")
    ]
    mac_failure = commit_transaction[
        commit_transaction.index("if(!transaction_mac_calculate(") : commit_transaction.index(
            "#else\n    DFC_UNUSED(return_transaction_mac);"
        )
    ]
    if "dfc_secure_wipe(mac, sizeof(mac))" not in mac_failure:
        raise SystemExit("CommitTransaction MAC failure does not wipe its local MAC")
    if "transaction_pending_reader_id" in mac_failure:
        raise SystemExit("retryable CommitTransaction failure must retain its pending reader ID")

    transaction_cleanup = {
        "abort": emulator[
            emulator.index("bool dfc_emulator_abort_transaction(") : emulator.index(
                "void dfc_emulator_publish_transaction("
            )
        ],
        "publish": emulator[
            emulator.index("void dfc_emulator_publish_transaction(") : emulator.index(
                "void dfc_emulator_clear_iso_authentication("
            )
        ],
        "selected-app cleanup": emulator_commands[
            emulator_commands.index(
                "void dfc_emulator_command_clear_selected_app_pending_values("
            ) :
        ],
    }
    pending_reader_wipe = re.compile(
        r"dfc_secure_wipe\(\s*emulator->transaction_pending_reader_id,\s*"
        r"sizeof\(emulator->transaction_pending_reader_id\)\)"
    )
    for name, cleanup in transaction_cleanup.items():
        if not pending_reader_wipe.search(cleanup):
            raise SystemExit(f"transaction {name} does not wipe its pending reader ID")
        for reset in (
            "emulator->transaction_reader_id_pending = false",
            "emulator->transaction_reader_id_persist = false",
        ):
            if reset not in cleanup:
                raise SystemExit(f"transaction {name} does not reset reader-ID ownership")

    iso_cleanup = emulator[
        emulator.index("void dfc_emulator_clear_iso_authentication(") : emulator.index(
            "void dfc_emulator_reset_session("
        )
    ]
    if "dfc_emulator_clear_pending_authentication_storage(emulator)" not in iso_cleanup:
        raise SystemExit("ISO authentication cleanup does not wipe shared pending secrets")
    pending_cleanup = emulator[
        emulator.index("void dfc_emulator_clear_pending_authentication_storage(") : emulator.index(
            "void dfc_emulator_clear_iso_authentication("
        )
    ]
    if "dfc_secure_wipe(&emulator->pending_authentication" not in pending_cleanup:
        raise SystemExit("shared pending authentication cleanup does not wipe its union")
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
