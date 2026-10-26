#!/usr/bin/env python3
"""Generate the complete foreign-interface layout registries."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "ffi/dfc_ffi.h"
OUTPUTS = {
    ROOT / "ffi/dfc_ffi_layout.inc": "c",
    ROOT / "bindings/python/src/dfc_core/_layout.py": "python",
    ROOT / "bindings/rust/dfc-core/src/layout.rs": "rust",
    ROOT / "bindings/dotnet/src/Dfc/Interop/NativeLayout.Generated.cs": "dotnet",
    ROOT / "bindings/java/src/main/java/com/cindersocket/dfc/DfcLayout.java": "java",
}

SIGNATURE_OUTPUTS = {
    ROOT / "bindings/python/src/dfc_core/_native_signatures_generated.py": "python_signatures",
    ROOT
    / "bindings/python/src/dfc_core/_native_reader_signatures_generated.py": "python_reader_signatures",
    ROOT / "bindings/dotnet/src/Dfc/Interop/NativeSignatures.Generated.cs": "dotnet_signatures",
}

DOTNET_TYPES = {
    "DfcFfiCapabilities": "NativeCapabilities",
    "DfcFfiStructSizes": "NativeStructSizes",
    "DfcFfiError": "NativeError",
    "DfcFfiCard": "NativeCard",
    "DfcFfiPiccSettings": "NativePicc",
    "DfcFfiApplication": "NativeApplication",
    "DfcFfiFile": "NativeFile",
    "DfcFfiKey": "NativeKey",
    "DfcFfiActivation": "NativeActivation",
    "DfcFfiSnapshot": "NativeSnapshot",
    "DfcFfiDiagnosticSnapshot": "NativeDiagnosticSnapshot",
    "DfcFfiReaderState": "NativeReaderState",
}

TYPE_NAMES = {
    "DfcFfiCapabilities": "Capabilities",
    "DfcFfiStructSizes": "StructSizes",
    "DfcFfiError": "Error",
    "DfcFfiCard": "Card",
    "DfcFfiPiccSettings": "PiccSettings",
    "DfcFfiApplication": "Application",
    "DfcFfiFile": "File",
    "DfcFfiKey": "Key",
    "DfcFfiActivation": "Activation",
    "DfcFfiSnapshot": "Snapshot",
    "DfcFfiDiagnosticSnapshot": "DiagnosticSnapshot",
    "DfcFfiReaderState": "ReaderState",
}

STRUCT_SIZE_TYPES = {
    "capabilities": "Capabilities",
    "error": "Error",
    "card": "Card",
    "picc": "PiccSettings",
    "application": "Application",
    "file": "File",
    "key": "Key",
    "activation": "Activation",
    "snapshot": "Snapshot",
    "diagnostic_snapshot": "DiagnosticSnapshot",
    "reader_state": "ReaderState",
}


def _clean_header() -> str:
    """Return the public header without comments or preprocessor continuations."""

    text = HEADER.read_text()
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.DOTALL)
    text = re.sub(r"\\\n", "", text)
    return re.sub(r"^\s*#.*$", "", text, flags=re.MULTILINE)


def signatures() -> list[tuple[str, str, list[tuple[str, str]]]]:
    """Extract the exported function contract in declaration order."""

    text = _clean_header()
    declarations = re.findall(r"DFC_FFI_EXPORT\s+(.*?);", text, re.DOTALL)
    result: list[tuple[str, str, list[tuple[str, str]]]] = []
    for declaration in declarations:
        declaration = " ".join(declaration.split())
        match = re.fullmatch(r"(.+?)\s+(dfc_ffi_\w+)\s*\((.*)\)", declaration)
        if not match:
            raise SystemExit(f"unsupported public FFI declaration: {declaration}")
        return_type, name, body = match.groups()
        parameters: list[tuple[str, str]] = []
        if body != "void":
            for raw in body.split(","):
                parameter = raw.strip()
                parameter_match = re.fullmatch(r"(.+?\*?)\s+([A-Za-z_]\w*)", parameter)
                if not parameter_match:
                    raise SystemExit(f"unsupported parameter in {name}: {parameter}")
                ctype, parameter_name = parameter_match.groups()
                parameters.append((parameter_name, " ".join(ctype.split())))
        result.append((name, " ".join(return_type.split()), parameters))
    return result


def contract() -> tuple[list[tuple[str, int]], list[tuple[str, list[str]]]]:
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", HEADER.read_text(), flags=re.DOTALL)
    constants: list[tuple[str, int]] = []
    for name, expression in re.findall(
        r"^#define\s+(DFC_FFI_[A-Z0-9_]+)\s+([^\n]+)$", text, re.MULTILINE
    ):
        if name == "DFC_FFI_EXPORT":
            continue
        value = expression.strip()
        while value.startswith("(") and value.endswith(")"):
            value = value[1:-1].strip()
        value = re.sub(r"[uUlL]+$", "", value)
        try:
            constants.append((name, int(value, 0)))
        except ValueError as error:
            raise SystemExit(
                f"unsupported public FFI constant {name}: {expression.strip()}"
            ) from error

    for body in re.findall(r"\benum\s*\{(.*?)\}\s*;", text, re.DOTALL):
        next_value = 0
        for item in body.split(","):
            item = item.strip()
            if not item:
                continue
            match = re.fullmatch(r"(DFC_FFI_[A-Z0-9_]+)(?:\s*=\s*(.+))?", item)
            if not match:
                continue
            name, expression = match.groups()
            if expression is not None:
                value = expression.strip()
                value = re.sub(r"[uUlL]+$", "", value)
                try:
                    next_value = int(value, 0)
                except ValueError as error:
                    raise SystemExit(
                        f"unsupported public FFI enum value {name}: {value}"
                    ) from error
            constants.append((name, next_value))
            next_value += 1

    structs: list[tuple[str, list[str]]] = []
    for body, name in re.findall(
        r"typedef\s+struct\s*\{(.*?)\}\s*(DfcFfi\w+)\s*;", text, re.DOTALL
    ):
        fields = []
        for declaration in body.split(";"):
            match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]+\])?\s*$", declaration.strip())
            if match:
                fields.append(match.group(1))
        structs.append((name, fields))
    unknown = [name for name, _ in structs if name not in TYPE_NAMES]
    if unknown:
        raise SystemExit(f"add binding type names for: {', '.join(unknown)}")
    return constants, structs


def c_registry(constants: list[tuple[str, int]], structs: list[tuple[str, list[str]]]) -> str:
    lines = ["/* Generated by scripts/generate-ffi-layout.py. */"]
    lines.extend(f"DFC_FFI_LAYOUT_CONSTANT({name})" for name, _ in constants)
    for name, fields in structs:
        lines.append(f"DFC_FFI_LAYOUT_SIZE({name})")
        lines.extend(f"DFC_FFI_LAYOUT_FIELD({name}, {field})" for field in fields)
    return "\n".join(lines) + "\n"


def python_registry(constants: list[tuple[str, int]], structs: list[tuple[str, list[str]]]) -> str:
    constants_text = ",\n    ".join(f"({name!r}, {value})" for name, value in constants)
    structs_text = ",\n    ".join(
        f"({TYPE_NAMES[name]!r}, {tuple(fields)!r})" for name, fields in structs
    )
    size_fields = dict(structs)["DfcFfiStructSizes"]
    if set(size_fields) != set(STRUCT_SIZE_TYPES):
        raise SystemExit("update STRUCT_SIZE_TYPES for DfcFfiStructSizes")
    size_fields_text = ",\n    ".join(
        repr((field, STRUCT_SIZE_TYPES[field])) for field in size_fields
    )
    return f"""# Generated by scripts/generate-ffi-layout.py.
# fmt: off

CONSTANTS = (
    {constants_text},
)

STRUCTS = (
    {structs_text},
)

SIZE_FIELDS = (
    {size_fields_text},
)

VALUES = dict(CONSTANTS)
"""


def rust_registry(constants: list[tuple[str, int]], structs: list[tuple[str, list[str]]]) -> str:
    lines = [
        "// Generated by scripts/generate-ffi-layout.py.",
        "#![allow(dead_code)]",
    ]
    lines.extend(f"pub(crate) const {name}: i64 = {value};" for name, value in constants)
    lines.extend(
        [
            '#[cfg(not(feature = "role-target"))]',
            "use dfc_core_sys as sys;",
            '#[cfg(not(feature = "role-target"))]',
            "#[rustfmt::skip]",
            "pub(crate) fn expected_layout_fingerprint() -> u64 {",
            "    fn word(mut hash: u64, value: u64) -> u64 {",
            "        for byte in value.to_le_bytes() {",
            "            hash ^= u64::from(byte);",
            "            hash = hash.wrapping_mul(1_099_511_628_211);",
            "        }",
            "        hash",
            "    }",
            "    let mut hash = 14_695_981_039_346_656_037_u64;",
        ]
    )
    for _name, value in constants:
        lines.append(f"    hash = word(hash, {value}i64 as u64);")
    for name, fields in structs:
        lines.append(f"    hash = word(hash, core::mem::size_of::<sys::{name}>() as u64);")
        for field in fields:
            rust_field = "type_" if field == "type" else field
            lines.append(
                f"    hash = word(hash, core::mem::offset_of!(sys::{name}, {rust_field}) as u64);"
            )
    lines.extend(["    hash", "}", ""])
    return "\n".join(lines)


def dotnet_registry(constants: list[tuple[str, int]], structs: list[tuple[str, list[str]]]) -> str:
    lines = [
        "// Generated by scripts/generate-ffi-layout.py.",
        "namespace Dfc.Interop;",
        "",
        "using System.Runtime.InteropServices;",
        "",
        "internal static unsafe partial class Native",
        "{",
        "    internal static ulong ExpectedLayoutFingerprint()",
        "    {",
        "        var hash = 14_695_981_039_346_656_037UL;",
    ]
    for name, value in reversed(constants):
        lines.insert(7, f"    internal const long {name} = {value};")
    for _name, value in constants:
        lines.append(f"        hash = LayoutWord(hash, unchecked((ulong){value}L));")
    for name, fields in structs:
        dotnet_type = DOTNET_TYPES[name]
        lines.append(f"        hash = LayoutWord(hash, (ulong)sizeof({dotnet_type}));")
        for field in fields:
            managed = "".join(part[0].upper() + part[1:] for part in field.split("_"))
            managed = managed.replace("2k", "2K").replace("4k", "4K").replace("8k", "8K")
            lines.append(
                f"        hash = LayoutWord(hash, (ulong)Marshal.OffsetOf<{dotnet_type}>(nameof({dotnet_type}.{managed})));"
            )
    lines.extend(
        [
            "        return hash;",
            "    }",
            "",
            "    private static ulong LayoutWord(ulong hash, ulong value)",
            "    {",
            "        for (var shift = 0; shift < 64; shift += 8)",
            "        {",
            "            hash ^= (byte)(value >> shift);",
            "            hash = unchecked(hash * 1_099_511_628_211UL);",
            "        }",
            "        return hash;",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def java_registry(constants: list[tuple[str, int]], _structs: list[tuple[str, list[str]]]) -> str:
    lines = [
        "// Generated by scripts/generate-ffi-layout.py.",
        "package com.cindersocket.dfc;",
        "",
        "final class DfcLayout {",
        "  private DfcLayout() {}",
    ]
    lines.extend(f"  static final long {name} = {value}L;" for name, value in constants)
    lines.extend(["}", ""])
    return "\n".join(lines)


OPAQUE_TYPES = {
    "DfcFfiCredential",
    "DfcFfiPicc",
    "DfcFfiReaderSession",
    "DfcFfiReaderExchange",
    "DfcFfiTransactionMacVerifier",
}


def _python_type(ctype: str) -> str:
    base = ctype.removeprefix("const ")
    scalar = {
        "void": "None",
        "bool": "C.c_bool",
        "uint8_t": "C.c_uint8",
        "uint32_t": "C.c_uint32",
        "uint64_t": "C.c_uint64",
        "int32_t": "C.c_int32",
        "size_t": "C.c_size_t",
        "void*": "C.c_void_p",
        "char*": "C.POINTER(C.c_char)",
        "DfcFfiRandomCallback": "C.c_void_p",
    }
    if base == "char*" and ctype.startswith("const "):
        return "C.c_char_p"
    if base in ("uint8_t*",):
        return "P8"
    if base == "size_t*":
        return "C.POINTER(C.c_size_t)"
    if base == "uint32_t*":
        return "C.POINTER(C.c_uint32)"
    if base.endswith("**") and base[:-2] in OPAQUE_TYPES:
        return "C.POINTER(Handle)"
    if base.endswith("*") and base[:-1] in OPAQUE_TYPES:
        return "Handle"
    if base.endswith("*") and base[:-1] in TYPE_NAMES:
        return f'C.POINTER(types["{TYPE_NAMES[base[:-1]]}"])'
    try:
        return scalar[base]
    except KeyError as error:
        raise SystemExit(f"add Python FFI type mapping for {ctype}") from error


def python_signatures(functions: list[tuple[str, str, list[tuple[str, str]]]], reader: bool) -> str:
    selected = [item for item in functions if item[0].startswith("dfc_ffi_reader_") is reader]
    lines = [
        "# Generated by scripts/generate-ffi-layout.py.",
        "# fmt: off",
        "",
        "from __future__ import annotations",
        "",
        "import ctypes as C",
        "from collections.abc import Mapping",
        "from typing import Any",
        "",
        "Handle = C.c_void_p",
        "P8 = C.POINTER(C.c_uint8)",
        "",
        "",
        "def signatures(types: Mapping[str, Any]) -> tuple[tuple[str, Any, tuple[tuple[str, Any], ...]], ...]:",
        '    """Return named ctypes declarations generated from ``ffi/dfc_ffi.h``."""',
        "",
        "    return (",
    ]
    for name, result, parameters in selected:
        lines.append("        (")
        lines.append(f'            "{name}",')
        lines.append(f"            {_python_type(result)},")
        lines.append("            (")
        for parameter_name, parameter_type in parameters:
            lines.append(f'                ("{parameter_name}", {_python_type(parameter_type)}),')
        lines.append("            ),")
        lines.append("        ),")
    lines.extend(["    )", ""])
    return "\n".join(lines)


def _camel(name: str) -> str:
    aliases = {
        "out": "output",
        "len": "length",
        "cap": "capacity",
        "ins": "instruction",
    }
    if name in aliases:
        return aliases[name]
    head, *tail = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def _dotnet_type(ctype: str) -> str:
    base = ctype.removeprefix("const ")
    scalar = {
        "void": "void",
        "bool": "bool",
        "uint8_t": "byte",
        "uint32_t": "uint",
        "uint64_t": "ulong",
        "int32_t": "int",
        "size_t": "nuint",
        "void*": "nint",
        "char*": "byte*",
        "uint8_t*": "byte*",
        "size_t*": "nuint*",
        "uint32_t*": "uint*",
        "DfcFfiRandomCallback": "delegate* unmanaged<nint, byte*, nuint, int>",
    }
    if base.endswith("**") and base[:-2] in OPAQUE_TYPES:
        return "nint*"
    if base.endswith("*") and base[:-1] in OPAQUE_TYPES:
        return "nint"
    if base.endswith("*") and base[:-1] in DOTNET_TYPES:
        return f"{DOTNET_TYPES[base[:-1]]}*"
    try:
        return scalar[base]
    except KeyError as error:
        raise SystemExit(f"add .NET FFI type mapping for {ctype}") from error


def dotnet_signatures(functions: list[tuple[str, str, list[tuple[str, str]]]]) -> str:
    lines = [
        "// Generated by scripts/generate-ffi-layout.py.",
        "namespace Dfc.Interop;",
        "",
        "using System.Runtime.InteropServices;",
        "",
        "internal static unsafe partial class Native",
        "{",
    ]
    for name, result, parameters in functions:
        lines.append("    [LibraryImport(Library)]")
        if result == "bool":
            lines.append("    [return: MarshalAs(UnmanagedType.U1)]")
        rendered_parameters = [
            f"{'byte*' if ctype == 'void*' and parameter == 'buffer' else _dotnet_type(ctype)} {_camel(parameter)}"
            for parameter, ctype in parameters
        ]
        prefix = f"    internal static partial {_dotnet_type(result)} {name}"
        if len(rendered_parameters) <= 2 and len(prefix) + sum(map(len, rendered_parameters)) < 112:
            lines.append(prefix + "(" + ", ".join(rendered_parameters) + ");")
        else:
            lines.append(prefix + "(")
            for index, parameter in enumerate(rendered_parameters):
                suffix = "," if index + 1 < len(rendered_parameters) else ");"
                lines.append(f"        {parameter}{suffix}")
        lines.append("")
    lines.extend(["}", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    constants, structs = contract()
    functions = signatures()
    renderers = {
        "c": c_registry,
        "python": python_registry,
        "rust": rust_registry,
        "dotnet": dotnet_registry,
        "java": java_registry,
    }
    stale = []
    for path, kind in OUTPUTS.items():
        generated = renderers[kind](constants, structs)
        if args.check:
            if not path.exists() or path.read_text() != generated:
                stale.append(path.relative_to(ROOT))
        else:
            path.write_text(generated)
    signature_renderers = {
        "python_signatures": lambda value: python_signatures(value, False),
        "python_reader_signatures": lambda value: python_signatures(value, True),
        "dotnet_signatures": dotnet_signatures,
    }
    for path, kind in SIGNATURE_OUTPUTS.items():
        generated = signature_renderers[kind](functions)
        if args.check:
            if not path.exists() or path.read_text() != generated:
                stale.append(path.relative_to(ROOT))
        else:
            path.write_text(generated)
    if stale:
        print("stale FFI layout registry: " + ", ".join(map(str, stale)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
