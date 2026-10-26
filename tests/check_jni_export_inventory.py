"""Keep Java native declarations, JNI definitions, and build sources synchronized."""

import re

from jni_sources import JNI_SOURCES, ROOT, combined_jni_source

JAVA_NATIVE = ROOT / "bindings/java/src/main/java/com/cindersocket/dfc/DfcNative.java"
CMAKE = ROOT / "CMakeLists.txt"


def declared_methods() -> set[str]:
    source = JAVA_NATIVE.read_text(encoding="utf-8")
    return set(re.findall(r"\bstatic\s+native\s+\S+\s+(\w+)\s*\(", source))


def defined_methods(source: str) -> list[str]:
    return re.findall(r"Java_com_cindersocket_dfc_DfcNative_(\w+)\s*\(", source)


def problems(source: str, cmake: str) -> list[str]:
    failures: list[str] = []
    declared = declared_methods()
    definitions = defined_methods(source)
    duplicates = sorted(name for name in set(definitions) if definitions.count(name) != 1)
    if duplicates:
        failures.append("JNI methods must have one definition: " + ", ".join(duplicates))
    missing = sorted(declared - set(definitions))
    extra = sorted(set(definitions) - declared)
    if missing:
        failures.append("Java native methods without JNI definitions: " + ", ".join(missing))
    if extra:
        failures.append("JNI definitions without Java native methods: " + ", ".join(extra))

    unbuilt = [
        str(path.relative_to(ROOT))
        for path in JNI_SOURCES
        if str(path.relative_to(ROOT)) not in cmake
    ]
    if unbuilt:
        failures.append("JNI implementation sources missing from CMake: " + ", ".join(unbuilt))
    return failures


def main() -> None:
    source = combined_jni_source()
    cmake = CMAKE.read_text(encoding="utf-8")
    failures = problems(source, cmake)
    methods = defined_methods(source)
    duplicate_mutant = (
        source
        + re.search(
            r"JNIEXPORT.*?Java_com_cindersocket_dfc_DfcNative_\w+\s*\(.*?\n}\n",
            source,
            re.DOTALL,
        ).group()
    )
    missing_mutant = source.replace(
        "Java_com_cindersocket_dfc_DfcNative_" + methods[0],
        "Java_com_cindersocket_dfc_DfcNative_removed_" + methods[0],
        1,
    )
    unbuilt_mutant = cmake.replace(str(JNI_SOURCES[-1].relative_to(ROOT)), "", 1)
    if not problems(duplicate_mutant, cmake):
        failures.append("JNI export inventory failed its duplicate-definition mutation")
    if not problems(missing_mutant, cmake):
        failures.append("JNI export inventory failed its declaration-parity mutation")
    if not problems(source, unbuilt_mutant):
        failures.append("JNI export inventory failed its build-source mutation")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
