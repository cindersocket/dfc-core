"""Keep Java range-command construction on one implementation path."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMAND_SOURCE = ROOT / "bindings/java/src/main/java/com/cindersocket/dfc/DfcCommand.java"


class JavaCommandStructureTests(unittest.TestCase):
    def test_write_data_uses_shared_range_builder(self) -> None:
        source = COMMAND_SOURCE.read_text(encoding="utf-8")
        method = re.search(r"public static DfcCommand writeData\([^}]+\}", source, re.DOTALL)

        self.assertIsNotNone(method)
        self.assertRegex(source, r"private static final int WRITE_DATA\s*=\s*0x3d;")
        self.assertIn("return writeRange(WRITE_DATA, fileNumber, offset, value);", method.group())
        self.assertNotRegex(method.group(), r"writeRange\(0x[0-9a-fA-F]+,")
        self.assertNotIn("System.arraycopy", method.group())


if __name__ == "__main__":
    unittest.main()
