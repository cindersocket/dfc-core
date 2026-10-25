#!/usr/bin/env python3
"""Verify that CMake enables PIC only for shared-library consumers."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_ROOT = Path(os.environ.get("DFC_CMAKE_PIC_BUILD_DIR", ROOT / "build-cmake-pic")).resolve()


@dataclass(frozen=True)
class Configuration:
    name: str
    options: tuple[str, ...]
    build_target: str
    pic_targets: tuple[str, ...] = ()
    non_pic_targets: tuple[str, ...] = ()


CONFIGURATIONS = (
    Configuration(
        "static-target",
        ("-DDFC_ROLE=target", "-DDFC_BUILD_SHARED=OFF"),
        "dfc_core",
        non_pic_targets=("dfc_objects",),
    ),
    Configuration(
        "static-ffi",
        (
            "-DDFC_ROLE=target",
            "-DDFC_BUILD_SHARED=OFF",
            "-DDFC_BUILD_STATIC_FFI=ON",
        ),
        "dfc_ffi_static",
        non_pic_targets=("dfc_objects", "dfc_ffi_static"),
    ),
    Configuration(
        "rust-target",
        (
            "-DDFC_ROLE=target",
            "-DDFC_BUILD_SHARED=OFF",
            "-DDFC_BUILD_RUST_TARGET_BRIDGE=ON",
        ),
        "dfc_rust_target",
        non_pic_targets=("dfc_objects", "dfc_rust_target"),
    ),
    Configuration(
        "static-explicit-pic",
        (
            "-DDFC_ROLE=target",
            "-DDFC_BUILD_SHARED=OFF",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        ),
        "dfc_core",
        pic_targets=("dfc_objects",),
    ),
    Configuration(
        "shared",
        ("-DDFC_BUILD_SHARED=ON",),
        "dfc",
        pic_targets=("dfc_objects", "dfc"),
    ),
    Configuration(
        "jni",
        ("-DDFC_BUILD_SHARED=OFF", "-DDFC_BUILD_JNI=ON"),
        "dfc_jni",
        pic_targets=("dfc_objects", "dfc_jni"),
    ),
)


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def target_entries(entries: list[dict[str, object]], target: str) -> list[dict[str, object]]:
    marker = f"CMakeFiles/{target}.dir/"
    return [entry for entry in entries if marker in str(entry.get("output", "")).replace("\\", "/")]


def compile_arguments(entry: dict[str, object]) -> list[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and all(isinstance(value, str) for value in arguments):
        return arguments
    command = entry.get("command")
    if not isinstance(command, str):
        raise TypeError("compile_commands.json entry has no command")
    return shlex.split(command)


def check_target(
    build_dir: Path,
    entries: list[dict[str, object]],
    target: str,
    expected_pic: bool,
) -> None:
    selected = target_entries(entries, target)
    if not selected:
        raise RuntimeError(f"{target}: no compile commands found")

    for entry in selected:
        arguments = compile_arguments(entry)
        actual_pic = any(argument.lower() in {"-fpic", "-fpie"} for argument in arguments)
        if actual_pic != expected_pic:
            source = Path(str(entry["file"])).name
            expectation = "with PIC" if expected_pic else "without PIC"
            raise RuntimeError(f"{target}/{source}: expected compilation {expectation}")

        output = Path(str(entry["output"]))
        if not output.is_absolute():
            output = build_dir / output
        if not output.is_file():
            raise RuntimeError(f"{target}: expected object was not built: {output}")

    state = "on" if expected_pic else "off"
    print(f"{target}: pic={state}, objects={len(selected)}")


def main() -> None:
    tiny_dir_value = os.environ.get("TINY_CRYPTO_DIR")
    if not tiny_dir_value:
        raise SystemExit("TINY_CRYPTO_DIR must name the pinned tiny-crypto-c checkout")
    tiny_dir = Path(tiny_dir_value).resolve()
    if not (tiny_dir / "src" / "aes.c").is_file():
        raise SystemExit(f"invalid tiny-crypto-c checkout: {tiny_dir}")

    for configuration in CONFIGURATIONS:
        print(f"[{configuration.name}]")
        build_dir = BUILD_ROOT / configuration.name
        run(
            "cmake",
            "--fresh",
            "-S",
            str(ROOT),
            "-B",
            str(build_dir),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DDFC_BUILD_TESTS=OFF",
            "-DDFC_CRYPTO=tiny",
            f"-DDFC_TINY_CRYPTO_DIR={tiny_dir}",
            *configuration.options,
        )
        run("cmake", "--build", str(build_dir), "--target", configuration.build_target)

        entries = json.loads((build_dir / "compile_commands.json").read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            raise TypeError("compile_commands.json is not an array")
        for target in configuration.pic_targets:
            check_target(build_dir, entries, target, True)
        for target in configuration.non_pic_targets:
            check_target(build_dir, entries, target, False)


if __name__ == "__main__":
    main()
