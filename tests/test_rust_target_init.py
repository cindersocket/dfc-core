"""Regression tests for target credential initialization cost."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "bindings" / "rust" / "dfc-core" / "src" / "target.rs"


class RustTargetInitializationTests(unittest.TestCase):
    def test_decode_does_not_clear_zeroed_storage_twice(self) -> None:
        source = TARGET.read_text(encoding="utf-8")
        match = re.search(
            r"pub fn decode\(content: &\[u8\]\).*?\n    }\n\n    /// Revalidates",
            source,
            re.DOTALL,
        )

        self.assertIsNotNone(match)
        body = match.group(0)
        self.assertIn("alloc_zeroed(layout)", body)
        self.assertIn("dfc_target_credential_decode", body)
        self.assertNotIn("dfc_target_credential_init", body)


if __name__ == "__main__":
    unittest.main()
