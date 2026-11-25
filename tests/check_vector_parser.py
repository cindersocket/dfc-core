"""Exercise malformed vector grammar through the native runner."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HEADER = """name: parser regression
origin: synthetic
source: tests/check_vector_parser.py
uid: 04A1B2C3D4E5F6
picc-key-settings-1: 0F
picc-key-settings-2: 01
picc-auth-mode: D40
picc-key-len: 16

scan
"""

SANITIZER_MARKERS = (
    "AddressSanitizer",
    "LeakSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)


def assert_clean_diagnostics(name: str, result: subprocess.CompletedProcess[str]) -> None:
    diagnostics = result.stdout + result.stderr
    for marker in SANITIZER_MARKERS:
        if marker in diagnostics:
            raise AssertionError(f"{name}: sanitizer diagnostic: {marker}")


def run(runner: Path, directory: Path, name: str, body: str, *, succeeds: bool = False) -> None:
    path = directory / f"{name}.vec"
    path.write_text(HEADER + body + "\n", encoding="utf-8")
    result = subprocess.run([runner, path], capture_output=True, text=True, check=False)
    assert_clean_diagnostics(name, result)
    if result.returncode < 0:
        raise AssertionError(f"{name}: runner terminated by signal {-result.returncode}")
    expected = 0 if succeeds else 1
    if result.returncode != expected:
        raise AssertionError(
            f"{name}: expected exit {expected}, got {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    summary = "1 of 1 vectors passed" if succeeds else "0 of 1 vectors passed"
    if summary not in result.stdout:
        raise AssertionError(f"{name}: runner did not report {summary!r}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <vector-runner>", file=sys.stderr)
        return 2
    runner = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        false_program = shutil.which("false")
        if false_program:
            try:
                run(Path(false_program), directory, "reject-non-runner", "field-off")
            except AssertionError:
                pass
            else:
                raise AssertionError("parser harness accepted /usr/bin/false")
        diagnostic = subprocess.CompletedProcess(
            [runner], 1, "", "ERROR: AddressSanitizer: synthetic self-test"
        )
        try:
            assert_clean_diagnostics("sanitizer-self-test", diagnostic)
        except AssertionError:
            pass
        else:
            raise AssertionError("parser harness accepted a sanitizer diagnostic")
        run(
            runner,
            directory,
            "exact-end-tolerance",
            "exchange native-apdu 9060000000 => 0401010100160591AF tolerance 7+2 0",
            succeeds=True,
        )
        run(
            runner,
            directory,
            "ignored-s-block",
            "frame-exchange E080 => 0565810280\n"
            "frame-exchange 1200A4 => A2\n"
            "expect-error protocol-error frame-exchange F201\n"
            "frame-exchange 13040007D276 => A3\n"
            "frame-exchange 020000850100 => 029000",
            succeeds=True,
        )
        malformed = {
            "overflow-tolerance": (
                "exchange native-apdu 9060000000 => 0401010100160591AF "
                "tolerance 18446744073709551615+1 0"
            ),
            "overflow-tolerance-delta": (
                "exchange native-apdu 9060000000 => 0401010100160591AF "
                "tolerance 7+2 18446744073709551616"
            ),
            "unseparated-tolerances": (
                "exchange native-apdu 9060000000 => 0401010100160591AF "
                "tolerance 7+1 0tolerance 8+1 0"
            ),
            "unseparated-first-tolerance": (
                "exchange native-apdu 9060000000 => 0401010100160591AFtolerance 7+1 0"
            ),
            "past-end-tolerance": (
                "exchange native-apdu 9060000000 => 0401010100160591AF tolerance 8+2 0"
            ),
            "overlapping-tolerance": (
                "exchange native-apdu 9060000000 => 0401010100160591AF "
                "tolerance 1+2 0 tolerance 2+1 0"
            ),
            "wildcard-tolerance": (
                "exchange native-apdu 9060000000 => 04010101001605??AF tolerance 7+1 0"
            ),
            "signed-command-byte": "status -1 => 00",
            "wildcard-command-byte": "exchange native-apdu ?? => 9100",
            "wildcard-random-byte": "inject-random ??",
            "numeric-trailing-junk": "advance-time 1junk",
            "scan-extra": "scan junk",
            "field-off-extra": "field-off junk",
            "clear-dirty-extra": "clear-dirty junk",
            "advance-time-extra": "advance-time 1 junk",
            "assert-trailing-junk": "assert credential.num_apps = 0junk",
            "assert-extra": "assert credential.num_apps = 0 junk",
            "set-model-extra": "set-model credential.model_status = 0 junk",
            "indexed-path-junk": "assert apps[0junk].aid = 000000",
            "indexed-leaf-junk": "assert apps[0].keys[0]junk = 00000000000000000000000000000000",
            "roll-index-sign": "roll-model-key-set -1 0",
            "roll-index-extra": "roll-model-key-set 0 0 junk",
            "protocol-error-exchange": (
                "expect-error protocol-error exchange native-apdu 9060000000"
            ),
            "protocol-error-extra": ("expect-error protocol-error frame-exchange 1200A4 junk"),
        }
        for name, body in malformed.items():
            run(runner, directory, name, body)

        bad_header = directory / "signed-header-byte.vec"
        bad_header.write_text(
            HEADER.replace("picc-key-settings-1: 0F", "picc-key-settings-1: -1") + "field-off\n",
            encoding="utf-8",
        )
        result = subprocess.run([runner, bad_header], capture_output=True, text=True, check=False)
        assert_clean_diagnostics("signed-header-byte", result)
        if result.returncode != 1:
            raise AssertionError(f"signed header byte: expected exit 1, got {result.returncode}")

        long_path = directory / "overlong-line.vec"
        long_path.write_text(HEADER + ("A" * 4096) + "\nfield-off\n", encoding="utf-8")
        result = subprocess.run([runner, long_path], capture_output=True, text=True, check=False)
        assert_clean_diagnostics("overlong-line", result)
        if result.returncode != 1:
            raise AssertionError(f"overlong line: expected exit 1, got {result.returncode}")

        compile_input = directory / "overlong-header.vec"
        compile_input.write_text("name: " + ("A" * 4096) + "\n", encoding="utf-8")
        compiled_path = directory / "overlong-header.dfcb"
        result = subprocess.run(
            [runner, "--compile-dfcb", compile_input, compiled_path],
            capture_output=True,
            text=True,
            check=False,
        )
        assert_clean_diagnostics("overlong-compile-input", result)
        if result.returncode != 1 or compiled_path.exists():
            raise AssertionError(
                "overlong compile input: expected exit 1 without an output file, "
                f"got {result.returncode}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
