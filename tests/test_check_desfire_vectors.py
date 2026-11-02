"""Regression tests for strict DESFire vector grammar validation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("check_desfire_vectors.py")
ROOT = MODULE_PATH.parent.parent
SPEC = importlib.util.spec_from_file_location("check_desfire_vectors", MODULE_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DesfireVectorGrammarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.vector_root = self.root / "vectors" / "desfire"
        self.vocabulary = json.loads(CHECKER.VOCABULARY.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_vector(
        self,
        relative_path: str,
        *,
        name: str = "Unique vector",
        case_id: str = "unique-vector",
        extra_headers: str = "",
    ) -> Path:
        path = self.vector_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(
                (
                    f"name: {name}",
                    f"case-id: {case_id}",
                    "source: generated test fixture",
                    "origin: synthetic",
                    "uid: 04112233445566",
                    extra_headers,
                    "scan",
                    "",
                )
            ),
            encoding="utf-8",
        )
        return path

    def validate_catalog(self, paths: list[Path]) -> None:
        with (
            patch.object(CHECKER, "ROOT", self.root),
            patch.object(CHECKER, "VECTOR_ROOT", self.vector_root),
        ):
            CHECKER.validate_catalog(paths, self.vocabulary)

    def test_hex_rejects_signs_and_contextual_wildcards(self) -> None:
        for text in ("-1", "+1", "GG", "0"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                CHECKER.parse_hex(text)
        with self.assertRaises(ValueError):
            CHECKER.parse_hex("??")
        self.assertEqual(CHECKER.parse_hex("00 ??", wildcards=True), 2)

    def test_unsigned_values_require_full_consumption(self) -> None:
        for text in ("-1", "+1", "1junk", " 1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                CHECKER.parse_unsigned(text, base=0)
        self.assertEqual(CHECKER.parse_unsigned("077", base=0), 0o77)
        self.assertEqual(CHECKER.parse_unsigned("0x10", base=0), 0x10)

    def test_tolerances_are_bounded_disjoint_and_literal(self) -> None:
        CHECKER.validate_expected("0011 tolerance 0+2 0")
        for text in (
            "0011 tolerance 1+2 0",
            "00?? tolerance 1+1 0",
            "0011 tolerance 0+2 0 tolerance 1+1 0",
            "0011 tolerance 18446744073709551615+1 0",
            "0011 tolerance 0+1 18446744073709551616",
            "0011 tolerance 0+1 0tolerance 1+1 0",
            "0011tolerance 0+1 0",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                CHECKER.validate_expected(text)

    def test_indexed_paths_require_exact_indexes(self) -> None:
        with self.assertRaises(ValueError):
            CHECKER.validate_step("assert apps[0junk].aid = 000000", {"native-apdu"})

    def test_fixed_arity_steps_reject_extra_tokens(self) -> None:
        for step in (
            "scan junk",
            "field-off junk",
            "clear-dirty junk",
            "advance-time 1 junk",
            "assert credential.num_apps = 0 junk",
            "set-model credential.model_status = 0 junk",
            "roll-model-key-set 0 0 junk",
        ):
            with self.subTest(step=step), self.assertRaises(ValueError):
                CHECKER.validate_step(step, {"native-apdu"})

    def test_protocol_error_is_limited_to_raw_frame_exchange(self) -> None:
        CHECKER.validate_step("expect-error protocol-error frame-exchange 1200A4", {"native-apdu"})
        for step in (
            "expect-error protocol-error scan",
            "expect-error protocol-error exchange native-apdu 9060000000",
            "expect-error protocol-error frame-exchange",
            "expect-error protocol-error frame-exchange 1200A4 junk",
            "expect-error unknown frame-exchange 1200A4",
        ):
            with self.subTest(step=step), self.assertRaises(ValueError):
                CHECKER.validate_step(step, {"native-apdu"})

    def test_catalog_rejects_duplicate_identity_and_names_both_files(self) -> None:
        first = self.write_vector("v4/emulator/first.vec", name="Repeated name", case_id="first")
        second = self.write_vector(
            "v5/synthetic/second.vec", name="Repeated name", case_id="second"
        )
        with self.assertRaisesRegex(ValueError, r"first\.vec.*second\.vec"):
            self.validate_catalog([first, second])

        second = self.write_vector("v5/synthetic/second.vec", name="Second", case_id="first")
        with self.assertRaisesRegex(ValueError, r"first\.vec.*second\.vec"):
            self.validate_catalog([first, second])

    def test_metadata_requires_explicit_stable_identity_and_source(self) -> None:
        for header, value in (("case-id", "Upper_Case"), ("source", "")):
            path = self.write_vector("v4/emulator/invalid.vec")
            text = path.read_text(encoding="utf-8")
            text = text.replace(
                f"{header}: "
                + ("unique-vector" if header == "case-id" else "generated test fixture"),
                f"{header}: {value}",
            )
            path.write_text(text, encoding="utf-8")
            with (
                self.subTest(header=header),
                self.assertRaisesRegex(ValueError, header),
            ):
                self.validate_catalog([path])

    def test_repeated_semantic_header_is_rejected(self) -> None:
        path = self.write_vector("v4/emulator/duplicate.vec", extra_headers="origin: physical-card")
        with self.assertRaisesRegex(ValueError, "duplicate header 'origin'"):
            self.validate_catalog([path])

    def test_typed_headers_require_exact_values_lengths_and_ranges(self) -> None:
        invalid = {
            "replayable": "maybe",
            "picc-generation": "EV4",
            "picc-atqa": "000102",
            "picc-random-id": "2",
            "picc-key-len": "32",
            "picc-storage": "0",
            "target-key-number": "14",
            "requires": "ev1,unknown-feature",
            "feature-version": "3",
        }
        for header, value in invalid.items():
            path = self.write_vector("v4/emulator/invalid.vec", extra_headers=f"{header}: {value}")
            with (
                self.subTest(header=header),
                self.assertRaisesRegex(ValueError, header),
            ):
                self.validate_catalog([path])

    def test_vector_discovery_is_recursive(self) -> None:
        expected = self.write_vector("v4/synthetic/nested/example.vec")
        with patch.object(CHECKER, "VECTOR_ROOT", self.vector_root):
            self.assertEqual(CHECKER.vector_paths(), [expected])

    def test_sdm_verifier_fixtures_are_bound_to_physical_captures(self) -> None:
        verifier_source = (ROOT / "tests/test_dfc_sdm_verify.c").read_text(encoding="utf-8")
        captures = (
            (
                "hardware_genuine_ev3_sdm_picc_native_iso.vec",
                "exchange native-apdu 90BD0000070200000030000000",
                "342FFCCF91C2B0730E2F4735A009A666A63259C3FD050C6E",
            ),
            (
                "hardware_genuine_ev3_sdm_encrypted_file_native_iso.vec",
                "exchange iso-apdu 00B0000044",
                "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E",
            ),
        )
        for filename, command, message in captures:
            with self.subTest(vector=filename):
                path = CHECKER.VECTOR_ROOT / "v4" / "hardware" / filename
                text = path.read_text(encoding="utf-8")
                self.assertIn("origin: physical-card", text)
                encoded = message.encode("ascii").hex().upper()
                status = "9000" if "iso-apdu" in command else "9100"
                self.assertIn(f"{command} => {encoded}{status}", text)
                self.assertIn(f"Captured response: {path.relative_to(ROOT)}", verifier_source)
                self.assertIn(f'"{message}"', verifier_source)


if __name__ == "__main__":
    unittest.main()
