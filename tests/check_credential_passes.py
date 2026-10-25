"""Prevent redundant full-credential initialization passes at FFI boundaries."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError(f"unterminated function: {signature}")


def braced_block(source: str, start: int) -> tuple[str, int]:
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1], index + 1
    raise ValueError("unterminated block")


def replace_in_function(source: str, signature: str, old: str, new: str) -> str:
    body = function(source, signature)
    changed = body.replace(old, new, 1)
    if changed == body:
        raise ValueError(f"mutation target missing from {signature}")
    return source.replace(body, changed, 1)


def move_before(source: str, signature: str, statement: str, marker: str) -> str:
    body = function(source, signature)
    without_statement = body.replace(statement, "", 1)
    match = re.search(marker, without_statement)
    if without_statement == body or not match:
        raise ValueError(f"mutation target missing from {signature}")
    changed = (
        without_statement[: match.start()]
        + statement
        + "\n    "
        + without_statement[match.start() :]
    )
    return source.replace(body, changed, 1)


def problems(ffi: str, der: str) -> list[str]:
    failures: list[str] = []
    raw = function(ffi, "static DfcFfiCredential* credential_alloc_uninitialized(")
    canonical = function(ffi, "static DfcFfiCredential* credential_alloc(")
    if "malloc(sizeof(DfcFfiCredential))" not in raw or "calloc(" in raw:
        failures.append("raw FFI credentials must use one uninitialized allocation")
    if (
        "credential_alloc_uninitialized()" not in canonical
        or "dfc_credential_clear" not in canonical
    ):
        failures.append("canonical FFI allocation must initialize exactly once")

    for name in ("parse_text", "decode", "clone"):
        body = function(ffi, f"int32_t dfc_ffi_credential_{name}(")
        if (
            "credential_alloc_uninitialized()" not in body
            or "credential_alloc()" in body
            or "dfc_credential_clear" in body
        ):
            failures.append(f"FFI {name} performs a redundant credential initialization")

    decode_contracts = (
        ("parse_text", "dfc_text_parse", "DfcTextOk"),
        ("decode", "dfc_der_decode", "DfcDerOk"),
    )
    for name, decode_call, ok_status in decode_contracts:
        body = function(ffi, f"int32_t dfc_ffi_credential_{name}(")
        call = body.find(decode_call)
        match = re.search(rf"if\s*\(\s*st\s*!=\s*{ok_status}\s*\)", body)
        if call < 0 or not match:
            failures.append(f"FFI {name} has no checked decoder result")
            continue
        failure, failure_end = braced_block(body, match.start())
        free = re.search(r"dfc_ffi_credential_free\s*\(\s*credential\s*\)\s*;", failure)
        returned = re.search(r"return\s+st\s*;", failure)
        if not free or not returned or free.start() > returned.start():
            failures.append(f"FFI {name} does not secure-free the rejected credential")
        publications = list(re.finditer(r"\*\s*out\s*=\s*credential\s*;", body))
        if len(publications) != 1 or publications[0].start() < failure_end or call > match.start():
            failures.append(f"FFI {name} publishes a credential before decode succeeds")

    clone = " ".join(function(ffi, "int32_t dfc_ffi_credential_clone(").split())
    clone_publish = re.compile(
        r"\*out\s*=\s*credential_alloc_uninitialized\(\);\s*"
        r"if\s*\(\s*!\*out\s*\)\s*return\s+DFC_FFI_OUT_OF_MEMORY;\s*"
        r"dfc_credential_copy_model\(\s*&\(\*out\)->model,\s*&credential->model\s*\);"
    )
    if not clone_publish.search(clone):
        failures.append("FFI clone must immediately copy the complete credential after allocation")

    if ffi.count("credential_alloc_uninitialized()") != 4:
        failures.append("raw FFI credential allocation escaped its reviewed callers")

    new = function(ffi, "int32_t dfc_ffi_credential_new(")
    if "credential_alloc()" not in new:
        failures.append("FFI new credential must start from canonical defaults")

    decoder = function(der, "static DfcDerStatus decode_credential(")
    if "dfc_credential_reset_application(app)" in decoder:
        failures.append("DER decode resets application slots already initialized by clear")
    return failures


def main() -> None:
    ffi = (ROOT / "ffi/dfc_ffi.c").read_text(encoding="utf-8")
    der = (ROOT / "src/dfc_der.c").read_text(encoding="utf-8")
    failures = problems(ffi, der)
    if failures:
        raise SystemExit("\n".join(failures))

    ffi_mutants = [
        ffi.replace("malloc(sizeof(DfcFfiCredential))", "calloc(1, sizeof(DfcFfiCredential))", 1),
        ffi.replace("credential_alloc_uninitialized()", "credential_alloc()", 1),
    ]
    for name in ("parse_text", "decode"):
        signature = f"int32_t dfc_ffi_credential_{name}("
        ok_status = "DfcTextOk" if name == "parse_text" else "DfcDerOk"
        ffi_mutants.append(
            replace_in_function(ffi, signature, "dfc_ffi_credential_free(credential);", "")
        )
        ffi_mutants.append(replace_in_function(ffi, signature, "*out = credential;", ""))
        ffi_mutants.append(
            move_before(
                ffi,
                signature,
                "*out = credential;",
                rf"if\s*\(\s*st\s*!=\s*{ok_status}\s*\)",
            )
        )
    ffi_mutants.append(
        replace_in_function(
            ffi,
            "int32_t dfc_ffi_credential_clone(",
            "dfc_credential_copy_model(&(*out)->model, &credential->model);",
            "(*out)->model.num_apps = credential->model.num_apps;",
        )
    )
    ffi_mutants.append(
        replace_in_function(
            ffi,
            "int32_t dfc_ffi_credential_clone(",
            "dfc_credential_copy_model(&(*out)->model, &credential->model);",
            "(*out)->model.dirty = false;\n"
            "    dfc_credential_copy_model(&(*out)->model, &credential->model);",
        )
    )
    der_mutant = der.replace(
        "DfcApplication* app = &credential->apps[credential->num_apps];",
        "DfcApplication* app = &credential->apps[credential->num_apps];\n"
        "        dfc_credential_reset_application(app);",
        1,
    )
    if any(not problems(mutant, der) for mutant in ffi_mutants) or not problems(ffi, der_mutant):
        raise SystemExit("credential-pass policy failed its mutation self-test")


if __name__ == "__main__":
    main()
