"""Regression tests for generated binding constants and signatures."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts/generate-ffi-layout.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_ffi_layout", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FfiGeneratorTests(unittest.TestCase):
    def test_every_export_has_one_generated_signature(self) -> None:
        generator = load_generator()
        signatures = generator.signatures()
        names = [name for name, _result, _parameters in signatures]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("dfc_ffi_sdm_verify_ascii", names)
        self.assertIn("dfc_ffi_reader_step", names)

    def test_new_export_and_status_enter_the_generated_contract(self) -> None:
        generator = load_generator()
        original = generator.HEADER.read_text()
        mutation = (
            original.replace(
                "#define DFC_FFI_MESSAGE_MAX 96",
                "#define DFC_FFI_MESSAGE_MAX 96\n#define DFC_FFI_TEST_STATUS 97",
            )
            .replace(
                "DFC_FFI_RESPONSE_OK = 0,",
                "DFC_FFI_RESPONSE_OK = 0,\n    DFC_FFI_TEST_ENUM_STATUS = 98,",
            )
            .replace(
                "#ifdef __cplusplus\n}\n#endif",
                "DFC_FFI_EXPORT int32_t dfc_ffi_test_probe(uint32_t value, size_t* out);\n\n"
                "#ifdef __cplusplus\n}\n#endif",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / "dfc_ffi.h"
            header.write_text(mutation)
            generator.HEADER = header
            constants, _structs = generator.contract()
            signatures = generator.signatures()

        self.assertIn(("DFC_FFI_TEST_STATUS", 97), constants)
        self.assertIn(("DFC_FFI_TEST_ENUM_STATUS", 98), constants)
        self.assertIn(
            (
                "dfc_ffi_test_probe",
                "int32_t",
                [("value", "uint32_t"), ("out", "size_t*")],
            ),
            signatures,
        )


if __name__ == "__main__":
    unittest.main()
