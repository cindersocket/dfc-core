#!/usr/bin/env python3
"""Validate and smoke-test the two dfc-core source release archives."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

ENTRY_POINTS = ("native", "android", "dotnet", "python", "java", "rust")
REQUIRED_FILES = (
    "CMakeLists.txt",
    "Cargo.toml",
    "bindings/android/gradlew",
    "bindings/android/dfc/build.gradle.kts",
    "bindings/dotnet/src/Dfc/Dfc.csproj",
    "bindings/java/src/main/java/com/cindersocket/dfc/DfcNative.java",
    "bindings/python/pyproject.toml",
    "bindings/rust/dfc-core/Cargo.toml",
    "examples/credentials/v6-minimal.dfcb",
    "scripts/check-release-artifacts.py",
    "tests/java/DfcJniSmokeTest.java",
    "tests/java/DfcSecretLifetimeTest.java",
)


def safe_relative(name: str, prefix: str) -> str | None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != prefix:
        raise ValueError(f"unsafe or unexpected archive member: {name}")
    relative = PurePosixPath(*path.parts[1:])
    return None if not relative.parts else relative.as_posix()


def executable(mode: int) -> bool:
    """Return the portable executable semantic carried by an archive mode."""
    return bool(mode & 0o111)


def tar_contents(path: Path, prefix: str) -> dict[str, tuple[str, bool]]:
    contents: dict[str, tuple[str, bool]] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            relative = safe_relative(member.name, prefix)
            if relative is None or member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"unsupported tar member type: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"cannot read tar member: {member.name}")
            contents[relative] = (
                hashlib.sha256(source.read()).hexdigest(),
                executable(member.mode),
            )
    return contents


def zip_contents(path: Path, prefix: str) -> dict[str, tuple[str, bool]]:
    contents: dict[str, tuple[str, bool]] = {}
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            relative = safe_relative(member.filename, prefix)
            if relative is None or member.is_dir():
                continue
            mode = member.external_attr >> 16
            contents[relative] = (
                hashlib.sha256(archive.read(member)).hexdigest(),
                executable(mode),
            )
    return contents


def inspect_archives(version: str, tar_path: Path, zip_path: Path) -> None:
    prefix = f"dfc-core-{version}"
    tar_files = tar_contents(tar_path, prefix)
    zip_files = zip_contents(zip_path, prefix)
    if tar_files != zip_files:
        only_tar = sorted(tar_files.keys() - zip_files.keys())
        only_zip = sorted(zip_files.keys() - tar_files.keys())
        changed = sorted(
            name
            for name in tar_files.keys() & zip_files.keys()
            if tar_files[name] != zip_files[name]
        )
        raise ValueError(
            f"source archives differ: tar-only={only_tar}, zip-only={only_zip}, changed={changed}"
        )
    missing = [name for name in REQUIRED_FILES if name not in tar_files]
    if missing:
        raise ValueError("source archives omit supported entry points: " + ", ".join(missing))
    if not tar_files:
        raise ValueError("source archives are empty")


def extract_archive(path: Path, destination: Path, prefix: str) -> Path:
    root = destination / prefix
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:gz") as archive:
            archive.extractall(destination, filter="data")
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                relative = safe_relative(member.filename, prefix)
                if relative is None:
                    continue
                target = root / relative
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                mode = (member.external_attr >> 16) & 0o777
                target.chmod(mode or 0o644)
    else:
        raise ValueError(f"unsupported source archive: {path}")
    if not root.is_dir():
        raise ValueError(f"archive did not extract {prefix}")
    return root


def run(command: list[str], root: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=root, env=env, check=True)


def cmake_native(root: Path, tiny: Path) -> None:
    build = root / ".release-build/native"
    run(
        [
            "cmake",
            "-S",
            ".",
            "-B",
            str(build),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DDFC_ROLE=simulator",
            "-DDFC_PROFILE=full_ev3",
            "-DDFC_CRYPTO=tiny",
            f"-DDFC_TINY_CRYPTO_DIR={tiny}",
        ],
        root,
    )
    run(["cmake", "--build", str(build), "--parallel"], root)
    run(["ctest", "--test-dir", str(build), "--output-on-failure"], root)


def smoke_android(root: Path, tiny: Path) -> None:
    del tiny
    run(
        [
            "./gradlew",
            "--no-daemon",
            ":dfc:assembleRelease",
            ":sample:assembleDebug",
            ":dfc:lintRelease",
        ],
        root / "bindings/android",
    )


def smoke_dotnet(root: Path, tiny: Path) -> None:
    cmake_native(root, tiny)
    native = root / ".release-build/native"
    run(
        [
            "dotnet",
            "test",
            "bindings/dotnet/Dfc.sln",
            "-c",
            "Release",
            f"-p:DfcNativeDirectory={native}",
        ],
        root,
    )
    run(
        [
            "dotnet",
            "run",
            "--project",
            "examples/dotnet/Dfc.TransceiveExample.csproj",
            "-c",
            "Release",
            f"-p:DfcNativeDirectory={native}",
            "--",
            "examples/credentials/v6-minimal.dfcb",
        ],
        root,
    )
    run(
        [
            "dotnet",
            "pack",
            "bindings/dotnet/src/Dfc/Dfc.csproj",
            "-c",
            "Release",
            "-o",
            str(root / ".release-build/nuget"),
        ],
        root,
    )


def smoke_python(root: Path, tiny: Path) -> None:
    output = root / ".release-build/python"
    env = os.environ.copy()
    env["CMAKE_ARGS"] = f"-DDFC_TINY_CRYPTO_DIR={tiny}"
    run(
        [
            "uv",
            "build",
            "--python",
            "3.12",
            "--wheel",
            "--out-dir",
            str(output),
            "bindings/python",
        ],
        root,
        env,
    )
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected one Python wheel, found {len(wheels)}")
    env["DFC_LIBRARY_PATH"] = ""
    run(
        [
            "uv",
            "run",
            "--python",
            "3.12",
            "--isolated",
            "--with",
            str(wheels[0]),
            "python",
            "examples/python/virtual_card.py",
        ],
        root,
        env,
    )


def smoke_java(root: Path, tiny: Path) -> None:
    del tiny
    build = root / ".release-build/java"
    run(
        [
            "cmake",
            "-S",
            ".",
            "-B",
            str(build),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DDFC_BUILD_SHARED=OFF",
            "-DDFC_BUILD_TESTS=OFF",
            "-DDFC_BUILD_JNI=ON",
            "-DDFC_ROLE=simulator",
            "-DDFC_PROFILE=full_ev3",
            "-DDFC_CRYPTO=mbedtls",
        ],
        root,
    )
    run(["cmake", "--build", str(build), "--parallel"], root)
    classes = build / "classes"
    java_sources = sorted(
        (root / "bindings/java/src/main/java/com/cindersocket/dfc").glob("*.java")
    )
    run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(classes),
            *(str(path) for path in java_sources),
            "tests/java/DfcJniSmokeTest.java",
            "tests/java/DfcSecretLifetimeTest.java",
        ],
        root,
    )
    run(
        [
            "java",
            "-cp",
            str(classes),
            "com.cindersocket.dfc.DfcSecretLifetimeTest",
        ],
        root,
    )
    run(
        [
            "java",
            f"-Djava.library.path={build}",
            "-cp",
            str(classes),
            "DfcJniSmokeTest",
            "examples/credentials/v6-minimal.dfc",
            "examples/credentials/v6-maximal.dfc",
        ],
        root,
    )


def smoke_rust(root: Path, tiny: Path) -> None:
    del tiny
    run(["cargo", "test", "--workspace"], root)
    run(
        [
            "cargo",
            "run",
            "--manifest-path",
            "examples/rust-virtual-picc/Cargo.toml",
            "--",
            "examples/credentials/v6-minimal.dfcb",
        ],
        root,
    )


SMOKE: dict[str, Callable[[Path, Path], None]] = {
    "native": cmake_native,
    "android": smoke_android,
    "dotnet": smoke_dotnet,
    "python": smoke_python,
    "java": smoke_java,
    "rust": smoke_rust,
}


def smoke_archives(
    version: str, tar_path: Path, zip_path: Path, entry_point: str, tiny: Path
) -> None:
    inspect_archives(version, tar_path, zip_path)
    prefix = f"dfc-core-{version}"
    with tempfile.TemporaryDirectory(prefix="dfc-core-release-") as temporary:
        base = Path(temporary)
        for label, archive in (("tar", tar_path), ("zip", zip_path)):
            root = extract_archive(archive, base / label, prefix)
            SMOKE[entry_point](root, tiny)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    for command in ("inspect", "smoke"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--version", required=True)
        subparser.add_argument("--tar", type=Path, required=True)
        subparser.add_argument("--zip", type=Path, required=True)
        if command == "smoke":
            subparser.add_argument("--entry-point", choices=ENTRY_POINTS, required=True)
            subparser.add_argument("--tiny-crypto-dir", type=Path, required=True)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        if args.command == "inspect":
            inspect_archives(args.version, args.tar, args.zip)
        else:
            smoke_archives(
                args.version,
                args.tar,
                args.zip,
                args.entry_point,
                args.tiny_crypto_dir.resolve(),
            )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
