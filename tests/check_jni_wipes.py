#!/usr/bin/env python3
"""Keep JNI-owned credential, session, and plaintext buffers on wiped exits."""

from pathlib import Path
import re


SOURCE = Path(__file__).parents[1] / "bindings" / "jni" / "dfc_jni.c"


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    raw_frees = [
        f"{line_number}: {line.strip()}"
        for line_number, line in enumerate(source.splitlines(), 1)
        if re.search(r"\bfree\(", line) and line.strip() != "free(buffer);"
    ]
    if raw_frees:
        raise SystemExit("JNI heap buffer bypasses wipe-before-free:\n" + "\n".join(raw_frees))

    required = {
        "central heap cleanup": "static void secure_free(void* buffer, size_t length)",
        "activation stack": "dfc_ffi_secure_zero(&activation, sizeof(activation))",
        "snapshot stack": "dfc_ffi_secure_zero(&snapshot, sizeof(snapshot))",
        "reader state stack": "dfc_ffi_secure_zero(&state, sizeof(state))",
        "stack array cleanup": "make_array_and_wipe",
    }
    missing = [name for name, expression in required.items() if expression not in source]
    if missing:
        raise SystemExit("missing JNI wipe family: " + ", ".join(missing))

    direct_array_returns = [
        f"{line_number}: {line.strip()}"
        for line_number, line in enumerate(source.splitlines(), 1)
        if "return make_array(env," in line
    ]
    if direct_array_returns:
        raise SystemExit(
            "JNI stack or heap result bypasses post-copy wipe:\n" + "\n".join(direct_array_returns)
        )


if __name__ == "__main__":
    main()
