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
    )
    if any(not problems(mutant) for mutant in mutants):
        failures.append("JNI wipe policy failed its mutation self-test")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
