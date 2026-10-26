"""Shared source inventory for JNI policy checks."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
JNI_DIRECTORY = ROOT / "bindings" / "jni"
JNI_SOURCES = tuple(sorted(JNI_DIRECTORY.glob("dfc_jni*.c")))


def combined_jni_source() -> str:
    """Read every JNI implementation unit in deterministic order."""

    return "\n".join(path.read_text(encoding="utf-8") for path in JNI_SOURCES)
