"""Regression tests for the decoder registry check."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_decoder_registry

ROOT = Path(__file__).resolve().parents[1]


class CheckDecoderRegistryTests(unittest.TestCase):
    def test_every_decoder_in_the_tree_is_registered(self):
        self.assertEqual(check_decoder_registry.unregistered(ROOT), [])

    def test_a_new_decoder_that_the_suite_does_not_name_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "ffi").mkdir()
            (root / "tests").mkdir()
            (root / "src" / "dfc_new.h").write_text(
                "DfcDerStatus dfc_credential_import(DfcCredential* credential,\n"
                "    const uint8_t* in, size_t len);\n"
                "DfcDerStatus dfc_credential_read_only_check(const DfcCredential* c);\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_dfc_decode_failure_atomicity.c").write_text(
                '{"dfc_der_decode", 0, 0, run},\n', encoding="utf-8"
            )

            self.assertEqual(check_decoder_registry.unregistered(root), ["dfc_credential_import"])


if __name__ == "__main__":
    unittest.main()
