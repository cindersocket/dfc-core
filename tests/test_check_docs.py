"""Regression tests for the repository-local Markdown link checker."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("check_docs", ROOT / "scripts" / "check-docs.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load scripts/check-docs.py")
CHECK_DOCS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_DOCS)


class CheckDocsTests(unittest.TestCase):
    def test_generated_markdown_does_not_affect_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)

            docs = repository / "docs"
            docs.mkdir()
            (docs / "target.md").write_text("# Target\n", encoding="utf-8")
            (docs / "guide.md").write_text("[target](target.md)\n", encoding="utf-8")

            generated = repository / "build-native" / "_deps" / "library"
            generated.mkdir(parents=True)
            (generated / "README.md").write_text("[missing](missing.md)\n", encoding="utf-8")

            self.assertEqual(CHECK_DOCS.broken_links(repository), [])

    def test_broken_link_fails_without_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "README.md").write_text("[missing](missing.md)\n", encoding="utf-8")

            self.assertEqual(
                CHECK_DOCS.broken_links(repository),
                ["README.md:1: missing.md"],
            )


if __name__ == "__main__":
    unittest.main()
