#!/usr/bin/env python3
"""Check repository links and the exported Python API documentation.

The Python gate follows ``dfc_core.__all__``. Exported declarations and public
members need meaningful summaries; callable parameters and non-None returns
need structured sections. ``Raises`` is required for direct raises, local
helper paths, and the binding's native status/error helpers. Private members
remain outside the public documentation contract.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")
IGNORED_DIRECTORIES = {
    ".cxx",
    ".git",
    ".pytest_cache",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "target",
}


def repository_markdown(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if not any(
            part in IGNORED_DIRECTORIES or part.startswith("build-")
            for part in path.relative_to(root).parts
        )
    )


def broken_links(root: Path) -> list[str]:
    failures: list[str] = []
    for document in repository_markdown(root):
        for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            for raw in LINK.findall(line):
                destination = raw.split("#", 1)[0].strip().strip("<>")
                if not destination or "://" in destination or destination.startswith("mailto:"):
                    continue
                target = (document.parent / unquote(destination)).resolve()
                if not target.exists():
                    failures.append(f"{document.relative_to(root)}:{number}: {destination}")
    return failures


def _public_python_exports(package: Path) -> dict[str, tuple[Path, str]]:
    """Map package exports to the source declaration that defines each one."""

    init_path = package / "__init__.py"
    tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    imports: dict[str, tuple[Path, str]] = {}
    declarations = {
        node.name: (init_path, node.name)
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    exports: list[str] | None = None
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            module = package / f"{node.module}.py"
            for alias in node.names:
                imports[alias.asname or alias.name] = (module, alias.name)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
                raise ValueError("dfc_core.__all__ must be a literal list of strings")
            exports = value
    if exports is None:
        raise ValueError("dfc_core.__all__ is missing")
    duplicates = sorted({name for name in exports if exports.count(name) > 1})
    if duplicates:
        raise ValueError("duplicate dfc_core exports: " + ", ".join(duplicates))
    targets = declarations | imports
    missing = sorted(set(exports) - set(targets))
    if missing:
        raise ValueError("unresolved dfc_core exports: " + ", ".join(missing))
    return {name: targets[name] for name in exports}


def _declaration(path: Path, name: str) -> ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected one declaration for {name}, found {len(matches)}")
    return matches[0]


def _is_dataclass(node: ast.ClassDef) -> bool:
    return any(
        (isinstance(decorator, ast.Name) and decorator.id == "dataclass")
        or (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "dataclass"
        )
        for decorator in node.decorator_list
    )


def _is_enum(node: ast.ClassDef) -> bool:
    return any(isinstance(base, ast.Name) and base.id in {"Enum", "IntEnum"} for base in node.bases)


def _public_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if node.args.vararg:
        arguments.append(node.args.vararg)
    if node.args.kwarg:
        arguments.append(node.args.kwarg)
    return [
        argument.arg
        for argument in arguments
        if argument.arg not in {"self", "cls"} and not argument.arg.startswith("_")
    ]


def _returns_value(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    annotation = node.returns
    if annotation is None:
        return False
    return not (
        (isinstance(annotation, ast.Constant) and annotation.value is None)
        or (isinstance(annotation, ast.Name) and annotation.id == "None")
    )


def _exception_boundaries(path: Path) -> set[int]:
    """Find functions that can raise directly or through a local/native helper."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for declaration in tree.body:
        if isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[declaration.name] = declaration
        elif isinstance(declaration, ast.ClassDef):
            for member in declaration.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions[f"{declaration.name}.{member.name}"] = member

    native_helpers = {"raise_status", "variable_output", "unsigned", "signed"}
    direct: set[str] = set()
    calls: dict[str, set[str]] = {name: set() for name in functions}

    class BoundaryVisitor(ast.NodeVisitor):
        def __init__(self, owner: str) -> None:
            self.owner = owner
            self.class_name = owner.split(".", 1)[0] if "." in owner else None

        def visit_Raise(self, _node: ast.Raise) -> None:
            direct.add(self.owner)

        def visit_Call(self, node: ast.Call) -> None:
            function = node.func
            if isinstance(function, ast.Name):
                if function.id == "exception_for_status":
                    direct.add(self.owner)
                elif function.id in functions:
                    calls[self.owner].add(function.id)
            elif isinstance(function, ast.Attribute):
                if (
                    isinstance(function.value, ast.Name)
                    and function.value.id in {"N", "_native"}
                    and function.attr in native_helpers
                ):
                    direct.add(self.owner)
                elif (
                    self.class_name
                    and isinstance(function.value, ast.Name)
                    and function.value.id in {"self", "cls"}
                ):
                    target = f"{self.class_name}.{function.attr}"
                    if target in functions:
                        calls[self.owner].add(target)
            self.generic_visit(node)

        def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, _node: ast.ClassDef) -> None:
            return

    for name, function in functions.items():
        visitor = BoundaryVisitor(name)
        for statement in function.body:
            visitor.visit(statement)

    reachable = set(direct)
    changed = True
    while changed:
        changed = False
        for caller, callees in calls.items():
            if caller not in reachable and callees & reachable:
                reachable.add(caller)
                changed = True
    return {functions[name].lineno for name in reachable}


def _vacuous_docstring(doc: str, name: str) -> bool:
    summary = doc.split("\n\n", 1)[0].strip().rstrip(".").casefold()
    normalized_name = name.strip("_").replace("_", " ").casefold()
    words = re.findall(r"[a-z0-9]+", summary)
    generic = {
        "a class",
        "a function",
        "a method",
        "a object",
        "a type",
        "a value",
        "an object",
        "class",
        "function",
        "method",
        "object",
        "type",
        "value",
    }
    return len(words) < 2 or summary in generic or summary in {name.casefold(), normalized_name}


def _function_documentation_failures(
    relative: Path,
    display_name: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    exception_boundaries: set[int],
) -> list[str]:
    doc = ast.get_docstring(node, clean=True)
    if not doc:
        return [f"{relative}:{node.lineno}: {display_name} has no public docstring"]
    failures: list[str] = []
    if _vacuous_docstring(doc, node.name):
        failures.append(f"{relative}:{node.lineno}: {display_name} has a vacuous docstring")
    parameters = _public_parameters(node)
    if parameters and not re.search(r"(?m)^Args:\s*$", doc):
        failures.append(f"{relative}:{node.lineno}: {display_name} has no Args section")
    elif parameters:
        for parameter in parameters:
            if not re.search(rf"(?m)^\s+{re.escape(parameter)}\s*:", doc):
                failures.append(
                    f"{relative}:{node.lineno}: {display_name} does not document parameter "
                    f"{parameter}"
                )
    if _returns_value(node) and not re.search(r"(?m)^Returns:\s*$", doc):
        failures.append(f"{relative}:{node.lineno}: {display_name} has no Returns section")
    if node.lineno in exception_boundaries and not re.search(r"(?m)^Raises:\s*$", doc):
        failures.append(f"{relative}:{node.lineno}: {display_name} has no Raises section")
    return failures


def python_public_documentation(root: Path) -> list[str]:
    """Return missing documentation in the exported Python binding API."""

    package = root / "bindings" / "python" / "src" / "dfc_core"
    failures: list[str] = []
    for export, (path, source_name) in _public_python_exports(package).items():
        node = _declaration(path, source_name)
        relative = path.relative_to(root)
        exception_boundaries = _exception_boundaries(path)
        doc = ast.get_docstring(node, clean=True)
        if not doc:
            failures.append(f"{relative}:{node.lineno}: {export} has no public docstring")
            continue
        if not isinstance(node, ast.ClassDef):
            failures.extend(
                _function_documentation_failures(relative, export, node, exception_boundaries)
            )
            continue
        if _vacuous_docstring(doc, node.name):
            failures.append(f"{relative}:{node.lineno}: {export} has a vacuous docstring")
        for member in node.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if member.name.startswith("_") and member.name != "__init__":
                continue
            failures.extend(
                _function_documentation_failures(
                    relative,
                    f"{export}.{member.name}",
                    member,
                    exception_boundaries,
                )
            )
        if _is_dataclass(node):
            fields = [
                member.target.id
                for member in node.body
                if isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name)
            ]
            for field in fields:
                if not re.search(rf"(?m)^\s*{re.escape(field)}\s*:", doc):
                    failures.append(
                        f"{relative}:{node.lineno}: {export} does not document field {field}"
                    )
        if _is_enum(node):
            values = [
                target.id
                for member in node.body
                if isinstance(member, (ast.Assign, ast.AnnAssign))
                for target in (
                    member.targets if isinstance(member, ast.Assign) else [member.target]
                )
                if isinstance(target, ast.Name) and target.id.isupper()
            ]
            for value in values:
                if not re.search(rf"(?m)^\s*{re.escape(value)}\s*:", doc):
                    failures.append(
                        f"{relative}:{node.lineno}: {export} does not document value {value}"
                    )
    return failures


def main() -> None:
    failures = broken_links(ROOT) + python_public_documentation(ROOT)
    if failures:
        raise SystemExit("documentation check failed:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
