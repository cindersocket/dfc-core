"""Regression tests for repository documentation gates."""

from __future__ import annotations

import importlib.util
import shutil
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
    @staticmethod
    def _python_package(repository: Path, module: str) -> Path:
        package = repository / "bindings" / "python" / "src" / "dfc_core"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(
            'from .models import Public\n\n__all__ = ["Public"]\n', encoding="utf-8"
        )
        (package / "models.py").write_text(module, encoding="utf-8")
        return package

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

    def test_exported_python_members_require_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._python_package(
                repository,
                """\
class Public:
    \"\"\"Documented type.\"\"\"

    def operation(self) -> None:
        pass
""",
            )

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(len(failures), 1)
            self.assertIn("Public.operation has no public docstring", failures[0])

    def test_exported_dataclass_fields_and_enum_values_require_documentation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = self._python_package(
                repository,
                """\
from dataclasses import dataclass

@dataclass
class Public:
    \"\"\"Documented type.\"\"\"

    value: int
""",
            )
            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(len(failures), 1)
            self.assertIn("Public does not document field value", failures[0])

            (package / "models.py").write_text(
                """\
from enum import IntEnum

class Public(IntEnum):
    \"\"\"Documented enum.\"\"\"

    VALUE = 1
""",
                encoding="utf-8",
            )
            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(len(failures), 1)
            self.assertIn("Public does not document value VALUE", failures[0])

    def test_complete_exported_python_documentation_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._python_package(
                repository,
                """\
from dataclasses import dataclass

@dataclass
class Public:
    \"\"\"Documented type.

    Attributes:
        value: Documented value.
    \"\"\"

    value: int

    def operation(self) -> None:
        \"\"\"Perform the documented operation.\"\"\"
""",
            )

            self.assertEqual(CHECK_DOCS.python_public_documentation(repository), [])

    def test_exported_function_and_class_require_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = repository / "bindings" / "python" / "src" / "dfc_core"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text(
                'from .api import Public, operation\n\n__all__ = ["Public", "operation"]\n',
                encoding="utf-8",
            )
            (package / "api.py").write_text(
                "class Public:\n    pass\n\ndef operation() -> None:\n    pass\n",
                encoding="utf-8",
            )

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(len(failures), 2)
            self.assertTrue(any("Public has no public docstring" in f for f in failures))
            self.assertTrue(any("operation has no public docstring" in f for f in failures))

    def test_constructor_property_and_function_sections_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._python_package(
                repository,
                '''\
class Public:
    """Represent a documented public value."""

    def __init__(self, value: int):
        """Create the public value."""
        if value < 0:
            raise ValueError("negative")

    @property
    def value(self) -> int:
        """Return the value."""
        return 1
''',
            )

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertTrue(any("Public.__init__ has no Args section" in f for f in failures))
            self.assertTrue(any("Public.__init__ has no Raises section" in f for f in failures))
            self.assertTrue(any("Public.value has no Returns section" in f for f in failures))

    def test_args_section_must_name_each_public_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._python_package(
                repository,
                '''\
class Public:
    """Represent a documented public value."""

    def operation(self, first: int, second: int) -> None:
        """Apply two values.

        Args:
            first: First value.
        """
''',
            )

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(len(failures), 1)
            self.assertIn("does not document parameter second", failures[0])

    def test_private_members_are_not_part_of_public_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._python_package(
                repository,
                '''\
class Public:
    """Represent a documented public value."""

    def _helper(self, undocumented: int) -> int:
        return undocumented
''',
            )

            self.assertEqual(CHECK_DOCS.python_public_documentation(repository), [])

    def test_duplicate_all_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = self._python_package(repository, 'class Public:\n    """A type."""\n')
            (package / "__init__.py").write_text(
                'from .models import Public\n\n__all__ = ["Public", "Public"]\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "duplicate dfc_core exports"):
                CHECK_DOCS.python_public_documentation(repository)

    def test_unresolved_reexport_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = self._python_package(repository, 'class Public:\n    """A type."""\n')
            (package / "__init__.py").write_text(
                'from .models import Missing\n\n__all__ = ["Missing"]\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "expected one declaration for Missing"):
                CHECK_DOCS.python_public_documentation(repository)

    def test_documented_enum_values_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._python_package(
                repository,
                '''\
from enum import IntEnum

class Public(IntEnum):
    """Identify the supported modes.

    Values:
        VALUE: The documented mode.
    """

    VALUE = 1
''',
            )

            self.assertEqual(CHECK_DOCS.python_public_documentation(repository), [])

    def test_generic_class_function_and_member_summaries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = repository / "bindings" / "python" / "src" / "dfc_core"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text(
                'from .api import Public, operation\n\n__all__ = ["Public", "operation"]\n',
                encoding="utf-8",
            )
            (package / "api.py").write_text(
                '''\
class Public:
    """A type."""

    def run(self) -> None:
        """A method."""

def operation() -> None:
    """A function."""
''',
                encoding="utf-8",
            )

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(sum("vacuous docstring" in failure for failure in failures), 3)

    def test_exception_sections_follow_direct_local_and_native_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = self._python_package(
                repository,
                '''\
from . import _native as N

class Public:
    """Exercise documented exception paths."""

    def direct(self) -> None:
        """Run a direct failure path."""
        raise ValueError("failed")

    def _helper(self) -> None:
        raise ValueError("failed")

    def delegated(self) -> None:
        """Run a delegated failure path."""
        self._helper()

    def native(self) -> None:
        """Run a native failure path."""
        N.raise_status(-1)
''',
            )
            (package / "_native.py").write_text("", encoding="utf-8")

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertEqual(sum("has no Raises section" in failure for failure in failures), 3)

    def test_real_delegated_boundary_loses_coverage_without_raises(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            target = repository / "bindings" / "python" / "src" / "dfc_core"
            shutil.copytree(ROOT / "bindings" / "python" / "src" / "dfc_core", target)
            credential = target / "credential.py"
            source = credential.read_text(encoding="utf-8")
            documented = """\
        Raises:
            CredentialError: If the model violates a credential constraint.
            RuntimeError: If this credential is closed.
"""
            self.assertIn(documented, source)
            credential.write_text(source.replace(documented, "", 1), encoding="utf-8")

            failures = CHECK_DOCS.python_public_documentation(repository)
            self.assertTrue(
                any("Credential.validate has no Raises section" in failure for failure in failures)
            )


if __name__ == "__main__":
    unittest.main()
