"""Regression tests for the bounded unit-test workflow."""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RUST_EXAMPLE_MANIFEST = ROOT / "examples" / "rust-virtual-picc" / "Cargo.toml"
MATRIX_KEYS = ("label", "backend", "sanitize", "cc", "release", "packages")


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow_job(name: str) -> str:
    workflow = workflow_text()
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n)", workflow
    )
    if match is None:
        raise AssertionError(f"{name} job not found")
    return match.group("body")


def unit_job() -> str:
    return workflow_job("unit")


def matrix_rows(job: str) -> list[tuple[str, ...]]:
    rows = []
    for encoded in re.findall(r"(?m)^          - \{ (?P<row>[^}]+) \}$", job):
        row = {
            key: json.loads(value) if value.startswith('"') else value
            for key, value in re.findall(r"([a-z]+): (\"(?:[^\"\\]|\\.)*\"|[^,]+)(?:, |$)", encoded)
        }
        rows.append(tuple(row[key] for key in MATRIX_KEYS))
    return rows


class UnitWorkflowTests(unittest.TestCase):
    def test_the_append_only_gate_is_wired_into_every_change(self) -> None:
        text = workflow_text()
        # Both entry points must run the gate against the real base, and neither
        # may be disabled; pointing it at HEAD would always pass.
        self.assertIn(
            'check-physical-vectors-append-only.py "origin/${{ github.base_ref }}"',
            text,
        )
        self.assertIn('check-physical-vectors-append-only.py "${{ github.event.before }}"', text)
        self.assertNotRegex(text, r"(?m)^\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*$")
        self.assertIn("fetch-depth: 0", text)

    def test_the_append_only_steps_are_exact_and_cannot_be_softened(self) -> None:
        text = workflow_text()
        start = text.index("name: Reject edits to genuine captures in a pull request")
        end = text.index("  format-docs:", start)
        steps = text[start:end]
        expected = (
            "name: Reject edits to genuine captures in a pull request\n"
            "        if: github.event_name == 'pull_request'\n"
            '        run: python3 scripts/check-physical-vectors-append-only.py "origin/${{ github.base_ref }}"\n'
            "      - name: Reject edits to genuine captures in a push\n"
            "        if: github.event_name == 'push' && github.event.before != "
            "'0000000000000000000000000000000000000000'\n"
            '        run: python3 scripts/check-physical-vectors-append-only.py "${{ github.event.before }}"\n'
        )
        self.assertEqual(steps, expected)
        # The job itself may not be made non-blocking either.
        job = steps_job = text[text.rindex("\n  ", 0, start - 1) : start]
        self.assertNotIn("continue-on-error", job + steps_job + steps)

    def test_fuzz_job_installs_the_matching_clang_runtime(self) -> None:
        workflow = workflow_text()
        fuzz = re.search(r"(?ms)^  fuzz:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n)", workflow)

        self.assertIsNotNone(fuzz)
        self.assertIn("clang libclang-rt-18-dev libmbedtls-dev", fuzz.group("body"))

    def test_pull_requests_run_once_and_superseded_runs_are_cancelled(self) -> None:
        workflow = workflow_text()

        self.assertIn("on:\n  push:\n    branches: [master]\n  pull_request:\n", workflow)
        self.assertIn(
            "concurrency:\n"
            "  group: ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}\n"
            "  # Never cancel a run on master: a later push would otherwise skip the\n"
            "  # provenance check of the earlier one. Pull requests are checked cumulatively,\n"
            "  # so cancelling superseded PR runs is safe.\n"
            "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n",
            workflow,
        )

    def test_matrix_variants_are_complete_and_uniquely_named(self) -> None:
        job = unit_job()

        self.assertIn("name: Unit suite (${{ matrix.label }})", job)
        self.assertEqual(
            matrix_rows(job),
            [
                ("mbedTLS GCC", "mbedtls", "", "gcc", "", "libmbedtls-dev"),
                (
                    "mbedTLS GCC ASan+UBSan",
                    "mbedtls",
                    "address,undefined",
                    "gcc",
                    "",
                    "libmbedtls-dev",
                ),
                ("tiny GCC", "tiny", "", "gcc", "", ""),
                ("tiny GCC ASan+UBSan", "tiny", "address,undefined", "gcc", "", ""),
                (
                    "tiny, memory",
                    "tiny",
                    "memory",
                    "clang",
                    "",
                    "clang libclang-rt-18-dev",
                ),
                ("tiny GCC Release", "tiny", "", "gcc", "1", ""),
            ],
        )

    def test_job_and_steps_have_hard_time_limits(self) -> None:
        job = unit_job()

        self.assertIn("    timeout-minutes: 30\n", job)
        self.assertEqual(job.count("timeout-minutes: 5"), 3)
        self.assertIn("timeout-minutes: 20", job)

    def test_dependency_setup_matches_each_backend(self) -> None:
        job = unit_job()

        self.assertIn("if: matrix.packages != ''", job)
        self.assertIn("install -y --no-install-recommends ${{ matrix.packages }}", job)
        self.assertRegex(
            job,
            r"(?s)- name: Fetch tiny-crypto-c\n"
            r"        if: matrix\.backend == 'tiny'\n"
            r"        uses: actions/checkout@v7",
        )

    def test_apt_waits_are_bounded(self) -> None:
        job = unit_job()

        self.assertEqual(job.count("timeout 180s"), 2)
        for option in (
            "Acquire::Retries=2",
            "Acquire::http::Timeout=20",
            "Acquire::https::Timeout=20",
            "DPkg::Lock::Timeout=60",
        ):
            self.assertEqual(job.count(option), 2)

    def test_unit_command_forwards_every_matrix_setting(self) -> None:
        job = unit_job()
        command = (
            "make -C tests test CRYPTO_BACKEND=${{ matrix.backend }} "
            "TINY_CRYPTO_DIR=../dependencies/tiny-crypto-c CC=${{ matrix.cc }} "
            "SANITIZE=${{ matrix.sanitize }} RELEASE=${{ matrix.release }}"
        )

        self.assertIn("- name: Run unit suite\n        timeout-minutes: 20", job)
        self.assertIn(f"run: {command}", job)

    def test_rust_example_command_has_an_unambiguous_default_binary(self) -> None:
        manifest = tomllib.loads(RUST_EXAMPLE_MANIFEST.read_text(encoding="utf-8"))

        self.assertEqual(manifest["package"].get("default-run"), manifest["package"]["name"])
        self.assertIn(
            "cargo run --manifest-path examples/rust-virtual-picc/Cargo.toml -- "
            "examples/credentials/v6-minimal.dfcb",
            workflow_text(),
        )

    def test_rust_jobs_use_the_pinned_arm_toolchain(self) -> None:
        workflow = workflow_text()
        pinned_toolchain = (
            "carlosperate/arm-none-eabi-gcc-action@49f4db4520f840e77ab1e99b24cfac2c540a21b1"
        )

        self.assertEqual(workflow_job("rust").count(pinned_toolchain), 1)
        self.assertEqual(workflow_job("rust-msrv").count(pinned_toolchain), 1)
        self.assertNotIn("apt-get install -y gcc-arm-none-eabi", workflow)


if __name__ == "__main__":
    unittest.main()
