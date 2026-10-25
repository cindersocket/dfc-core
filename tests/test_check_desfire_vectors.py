"""Regression tests for strict DESFire vector grammar validation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check_desfire_vectors.py")
SPEC = importlib.util.spec_from_file_location("check_desfire_vectors", MODULE_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DesfireVectorGrammarTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
