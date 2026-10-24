#!/usr/bin/env python3
"""Keep session secrets out of ordinary binding snapshots."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_FIELDS = (
    "ev2_encryption_key",
    "ev2_mac_key",
    "Ev2EncryptionKey",
    "Ev2MacKey",
)

PUBLIC_SNAPSHOTS = (
    ("bindings/python/src/dfc_core/models.py", "class ReaderState"),
    ("bindings/python/src/dfc_core/picc.py", "def _diagnostic_snapshot"),
    ("bindings/python/src/dfc_core/_native.py", "class DiagnosticSnapshot"),
    ("bindings/rust/dfc-core/src/lib.rs", "pub struct DiagnosticSnapshot"),
    (
        "bindings/rust/dfc-core-sys/src/bindings.rs",
        "pub struct DfcFfiDiagnosticSnapshot",
    ),
    ("bindings/rust/dfc-core-sys/src/target.rs", None),
    ("bindings/java/src/main/java/com/cindersocket/dfc/DfcPiccSnapshot.java", None),
    (
        "bindings/dotnet/src/Dfc/Emulation/DfcVirtualPicc.cs",
        "public sealed class DfcDiagnosticSnapshot",
    ),
    (
        "bindings/dotnet/src/Dfc/Interop/NativeStructs.cs",
        "internal unsafe struct NativeDiagnosticSnapshot",
    ),
    ("ffi/dfc_target_ffi.h", None),
)


def rust_diagnostic_is_noncopying(text: str) -> bool:
    prefix = text.split("pub struct DfcFfiDiagnosticSnapshot", 1)[0]
    declaration = prefix.rsplit("#[repr(C)]", 1)[1]
    return "derive(" not in declaration


def dotnet_marshalling_is_by_reference(text: str) -> bool:
    forbidden = (
        "Result<NativePicc",
        "NativeFile FromFile",
        "NativePicc FromPicc",
        "ToPicc(NativePicc ",
        "ToFile(NativeFile ",
    )
    required = (
        "FillPicc(DfcPicc picc, NativePicc* output)",
        "FillFile(int owner, DfcFile file, NativeFile* output",
        "ToPicc(NativePicc* source",
        "ToFile(NativeFile* source",
    )
    return not any(marker in text for marker in forbidden) and all(
        marker in text for marker in required
    )


def runner_avoids_secret_copies(text: str, forbidden: tuple[str, ...]) -> bool:
    return not any(marker in text for marker in forbidden)


def main() -> None:
    failures: list[str] = []
    for relative, end_marker in PUBLIC_SNAPSHOTS:
        text = (ROOT / relative).read_text()
        if end_marker:
            text = text.split(end_marker, 1)[0]
        for field in SECRET_FIELDS:
            if field in text:
                failures.append(f"{relative}: public snapshot contains {field}")

    header = (ROOT / "ffi/dfc_ffi.h").read_text()
    ordinary = header.split("} DfcFfiSnapshot;", 1)[0].rsplit("typedef struct {", 1)[1]
    for field in ("transaction_identifier", "encryption_key", "mac_key"):
        if field in ordinary:
            failures.append(f"ffi/dfc_ffi.h: ordinary snapshot contains {field}")
    required = (
        "DfcFfiDiagnosticSnapshot",
        "dfc_ffi_picc_diagnostic_snapshot",
        "dfc_ffi_secure_zero",
    )
    for marker in required:
        if marker not in header:
            failures.append(f"ffi/dfc_ffi.h: diagnostic contract lacks {marker}")

    lifetime_markers = {
        "bindings/python/src/dfc_core/picc.py": (
            "@contextmanager",
            "dfc_ffi_secure_zero",
            'value[:] = b"\\0" * len(value)',
        ),
        "bindings/rust/dfc-core/src/lib.rs": (
            "impl Drop for DiagnosticSnapshot",
            "dfc_ffi_secure_zero",
        ),
        "bindings/java/src/main/java/com/cindersocket/dfc/DfcDiagnosticSnapshot.java": (
            "implements AutoCloseable",
            "DfcCleaner.register(this, state)",
            "Arrays.fill(bytes, (byte) 0)",
        ),
        "bindings/jni/dfc_jni.c": (
            "piccDiagnosticSnapshot",
            "make_array_and_wipe",
            "dfc_ffi_secure_zero(&snapshot",
        ),
        "bindings/dotnet/src/Dfc/Emulation/DfcVirtualPicc.cs": (
            "DfcDiagnosticSnapshot : IDisposable",
            "CryptographicOperations.ZeroMemory",
            "dfc_ffi_secure_zero",
        ),
        "bindings/android/README.md": ("JNI layer clears native temporary",),
        "bindings/python/src/dfc_core/credential.py": (
            "def _wipe_native",
            "finally:",
            "_wipe_native(k)",
        ),
        "bindings/rust/dfc-core/src/credential.rs": (
            "impl Drop for CredentialKey",
            "impl Drop for CredentialPiccSettings",
            "impl Drop for CredentialFile",
            "wipe(&mut value)",
        ),
        "bindings/java/src/main/java/com/cindersocket/dfc/DfcCredential.java": (
            "implements AutoCloseable",
            "DfcCleaner.register(this, state)",
            "Arrays.fill(binary, (byte) 0)",
        ),
        "bindings/dotnet/src/Dfc/Interop/CredentialHandle.cs": (
            "sizeof(NativeKey)",
            "sizeof(NativePicc)",
        ),
        "bindings/dotnet/src/Dfc/Credentials/DfcCredentialCodec.cs": (
            "CryptographicOperations.ZeroMemory",
        ),
        "tests/java/DfcSecretLifetimeTest.java": (
            "credential was not wiped",
            "credential hash changed after close",
            "diagnostic was not wiped",
        ),
        "bindings/android/dfc/src/test/java/com/cindersocket/dfc/DfcSecretLifetimeTest.java": (
            "ownedSecretBuffersAreCleared",
            "DfcCleaner.register",
        ),
    }
    for relative, markers in lifetime_markers.items():
        text = (ROOT / relative).read_text()
        for marker in markers:
            if marker not in text:
                failures.append(f"{relative}: secret lifetime contract lacks {marker}")

    python_credential = (
        ROOT / "bindings/python/src/dfc_core/credential.py"
    ).read_text()
    for native_type in ("picc", "f"):
        start = python_credential.find(f"{native_type} = N.")
        finish = python_credential.find(f"_wipe_native({native_type})", start)
        guarded = python_credential[start:finish]
        if (
            start < 0
            or finish < 0
            or "try:" not in guarded
            or "finally:" not in guarded
        ):
            failures.append(
                f"bindings/python/src/dfc_core/credential.py: {native_type} is not exception-safe"
            )

    rust_sys = (ROOT / "bindings/rust/dfc-core-sys/src/bindings.rs").read_text()
    if not rust_diagnostic_is_noncopying(rust_sys):
        failures.append(
            "Rust diagnostic snapshot must not derive copying or debug traits"
        )

    dotnet_marshaller = (
        ROOT / "bindings/dotnet/src/Dfc/Interop/CredentialHandle.cs"
    ).read_text()
    if not dotnet_marshalling_is_by_reference(dotnet_marshaller):
        failures.append(".NET secret-bearing native marshalling is not caller-owned")

    for binding in ("python", "rust", "java", "dotnet", "android"):
        relative = f"bindings/{binding}/README.md"
        if "## Secret lifetime" not in (ROOT / relative).read_text():
            failures.append(f"{relative}: missing secret-lifetime documentation")

    conformance = ROOT.parents[1]
    jni_makefile = conformance / "tests/dfc-jni/Makefile"
    if (
        jni_makefile.exists()
        and "com.cindersocket.dfc.DfcSecretLifetimeTest" not in jni_makefile.read_text()
    ):
        failures.append("tests/dfc-jni/Makefile: Java lifetime test is not executed")
    execution_markers = {
        ".github/workflows/ci.yml": (
            "tests/java/DfcSecretLifetimeTest.java",
            "com.cindersocket.dfc.DfcSecretLifetimeTest",
            ":dfc:testDebugUnitTest",
        ),
        "scripts/check-release-artifacts.py": (
            '"tests/java/DfcSecretLifetimeTest.java"',
            '"com.cindersocket.dfc.DfcSecretLifetimeTest"',
        ),
    }
    for relative, markers in execution_markers.items():
        text = (ROOT / relative).read_text()
        for marker in markers:
            if marker not in text:
                failures.append(f"{relative}: lifetime test is not executed")
    runner_rules = {
        "tests/dfc-python/run.py": ("return bytes(diagnostic",),
        "tests/dfc-rust/src/main.rs": (
            "diagnostic_snapshot()?.encryption_key().to_vec()",
            "diagnostic_snapshot()?.mac_key().to_vec()",
        ),
        "tests/EmuConformance/Desfire/DfcBindingCorpusTests.cs": (
            "Convert.ToHexString(diagnostic.",
        ),
    }
    for relative, forbidden in runner_rules.items():
        path = conformance / relative
        if not path.exists():
            continue
        text = path.read_text()
        if not runner_avoids_secret_copies(text, forbidden):
            failures.append(f"{relative}: diagnostic assertion retains a secret copy")

    rust_mutant = rust_sys.replace(
        "#[repr(C)]\npub struct DfcFfiDiagnosticSnapshot",
        "#[repr(C)]\n#[derive(Copy, Clone)]\npub struct DfcFfiDiagnosticSnapshot",
        1,
    )
    dotnet_mutant = dotnet_marshaller.replace(
        "ToPicc(NativePicc* source", "ToPicc(NativePicc source", 1
    )
    if rust_diagnostic_is_noncopying(rust_mutant):
        failures.append("policy self-test missed the Rust Copy mutant")
    if dotnet_marshalling_is_by_reference(dotnet_mutant):
        failures.append("policy self-test missed the .NET value-copy mutant")
    if runner_avoids_secret_copies(
        "safe runner\nConvert.ToHexString(diagnostic.EncryptionKey.Span)",
        ("Convert.ToHexString(diagnostic.",),
    ):
        failures.append("policy self-test missed the runner-copy mutant")

    if failures:
        raise SystemExit("\n".join(failures))
    print("snapshot secret policy passed")


if __name__ == "__main__":
    main()
