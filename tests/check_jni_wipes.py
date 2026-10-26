"""Keep JNI-owned credential, session, and plaintext buffers on wiped exits."""

import re
from pathlib import Path

SOURCE = Path(__file__).parents[1] / "bindings" / "jni" / "dfc_jni.c"


def problems(source: str) -> list[str]:
    failures: list[str] = []
    raw_frees = [
        f"{line_number}: {line.strip()}"
        for line_number, line in enumerate(source.splitlines(), 1)
        if re.search(r"\bfree\(", line) and line.strip() != "free(buffer);"
    ]
    if raw_frees:
        failures.append("JNI heap buffer bypasses wipe-before-free:\n" + "\n".join(raw_frees))

    required = {
        "central heap cleanup": "static void secure_free(void* buffer, size_t length)",
        "activation stack": "dfc_ffi_secure_zero(&activation, sizeof(activation))",
        "snapshot stack": "dfc_ffi_secure_zero(&snapshot, sizeof(snapshot))",
        "reader state stack": "dfc_ffi_secure_zero(&state, sizeof(state))",
        "stack array cleanup": "make_array_and_wipe",
    }
    missing = [name for name, expression in required.items() if expression not in source]
    if missing:
        failures.append("missing JNI wipe family: " + ", ".join(missing))

    direct_array_returns = [
        f"{line_number}: {line.strip()}"
        for line_number, line in enumerate(source.splitlines(), 1)
        if "return make_array(env," in line
    ]
    if direct_array_returns:
        failures.append(
            "JNI stack or heap result bypasses post-copy wipe:\n" + "\n".join(direct_array_returns)
        )

    picc_create = re.search(
        r"JNIEXPORT jlong JNICALL Java_com_cindersocket_dfc_DfcNative_piccCreate\(.*?\n}\n",
        source,
        re.DOTALL,
    )
    if picc_create is None or not re.search(
        r"dfc_ffi_picc_create_take\s*\(\s*&credential\b", picc_create.group()
    ):
        failures.append("JNI PICC creation copies rather than transfers its decoded credential")

    bounded_methods = {
        "an10922Diversify": {"master_bytes": 2, "input_bytes": 2},
        "decode_fixed": {"response_bytes": 2},
        "responseDecodeKeyVersion": {"response_bytes": 2},
        "sdmVerify": {"meta_bytes": 4, "file_bytes": 4},
        "transactionMacCreate": {"key_bytes": 2, "uid_bytes": 2},
        "transactionMacAddReaderId": {"current_bytes": 2, "previous_bytes": 2},
        "transactionMacVerify": {"mac_bytes": 2},
        "readerAuthenticate": {"key_bytes": 1, "random_bytes": 1},
        "readerAuthenticateIso7816": {
            "key_bytes": 1,
            "first_bytes": 1,
            "second_bytes": 1,
        },
        "readerAuthenticateEv2": {
            "key_bytes": 1,
            "random_bytes": 1,
            "capability_bytes": 1,
        },
    }
    allowed_heap_copies = {"sdmVerify": 1}
    if "static bool copy_bounded_array(" not in source:
        failures.append("bounded JNI inputs have no fixed-scratch copy helper")
    for method, scratch_buffers in bounded_methods.items():
        body = re.search(
            (
                rf"(?:JNIEXPORT\s+\w+\s+JNICALL\s+"
                rf"Java_com_cindersocket_dfc_DfcNative_)?{method}\(.*?\n}}\n"
            ),
            source,
            re.DOTALL,
        )
        if body is None:
            failures.append(f"missing bounded JNI method: {method}")
        elif body.group().count("copy_array(") != allowed_heap_copies.get(method, 0):
            failures.append(f"bounded JNI input uses an unexpected heap copy: {method}")
        else:
            for buffer, expected_wipes in scratch_buffers.items():
                wipe = f"dfc_ffi_secure_zero({buffer}, sizeof({buffer}));"
                actual_wipes = body.group().count(wipe)
                if actual_wipes != expected_wipes:
                    failures.append(
                        f"bounded JNI scratch {method}.{buffer} has {actual_wipes} wipes, "
                        f"expected {expected_wipes}"
                    )
    return failures


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    failures = problems(source)
    mutants = (
        source.replace("dfc_ffi_secure_zero(&snapshot, sizeof(snapshot));", ""),
        source.replace("make_array_and_wipe", "make_array"),
        re.sub(
            r"dfc_ffi_picc_create_take\s*\(\s*&credential\b",
            "dfc_ffi_picc_create(credential",
            source,
            count=1,
        ),
        source.replace("if(!copy_bounded_array(", "if(!copy_array(", 1),
    )
    scratch_wipe_mutants = [
        source.replace(f"dfc_ffi_secure_zero({name}, sizeof({name}));", "", 1)
        for name in (
            "master_bytes",
            "input_bytes",
            "response_bytes",
            "meta_bytes",
            "file_bytes",
            "key_bytes",
            "uid_bytes",
            "current_bytes",
            "previous_bytes",
            "mac_bytes",
            "random_bytes",
            "first_bytes",
            "second_bytes",
            "capability_bytes",
        )
    ]
    if any(not problems(mutant) for mutant in (*mutants, *scratch_wipe_mutants)):
        failures.append("JNI wipe policy failed its mutation self-test")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
