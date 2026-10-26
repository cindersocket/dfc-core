"""Keep strict binding API-documentation gates in their intended CI jobs."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

JAVA_DOCS = """javadoc -quiet -public -Xdoclint:all -Werror
          -d build-jni/javadoc
          bindings/java/src/main/java/com/cindersocket/dfc/*.java"""
ANDROID_DOCS = "./gradlew --no-daemon :dfc:androidJavadocs"
DOTNET_BUILD = "dotnet test bindings/dotnet/Dfc.sln -c Release"
PYTHON_DOCS = "python3 scripts/check-docs.py"
RUSTDOC_HOSTED = "cargo rustdoc -p dfc-core --lib -- -D warnings"
RUSTDOC_TARGET = """cargo rustdoc -p dfc-core --lib --no-default-features \\
            --features system,role-target,profile-full-ev3 -- -D warnings"""

JOB_COMMANDS = {
    "java": (JAVA_DOCS,),
    "android": (ANDROID_DOCS,),
    "dotnet": (DOTNET_BUILD,),
    "python": (PYTHON_DOCS,),
    "rust": (RUSTDOC_HOSTED, RUSTDOC_TARGET),
    "rust-msrv": (RUSTDOC_HOSTED, RUSTDOC_TARGET),
}


def normalized(value: str) -> str:
    """Collapse YAML shell layout while preserving command token order."""

    return " ".join(value.replace("\\\n", " ").split())


def job_body(workflow: str, job: str) -> str:
    """Return one top-level workflow job without neighboring job content."""

    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"missing workflow job: {job}")
    return match.group("body")


def documentation_gate_failures(workflow: str) -> list[str]:
    """Report required commands that moved out of or vanished from their job."""

    failures: list[str] = []
    for job, commands in JOB_COMMANDS.items():
        body = normalized(job_body(workflow, job))
        for command in commands:
            if normalized(command) not in body:
                failures.append(f"{job}: {normalized(command)}")
    return failures


class BindingDocumentationCiTests(unittest.TestCase):
    def test_strict_commands_run_in_their_intended_jobs(self) -> None:
        self.assertEqual(documentation_gate_failures(WORKFLOW), [])

    def test_moving_any_command_to_another_job_is_rejected(self) -> None:
        for job, commands in JOB_COMMANDS.items():
            for command in commands:
                with self.subTest(job=job, command=normalized(command)):
                    body = job_body(WORKFLOW, job)
                    self.assertIn(command, body)
                    moved_body = body.replace(command, "", 1)
                    mutated = WORKFLOW.replace(body, moved_body, 1) + "\n" + command
                    self.assertIn(
                        f"{job}: {normalized(command)}", documentation_gate_failures(mutated)
                    )

    def test_removing_any_command_is_rejected(self) -> None:
        for job, commands in JOB_COMMANDS.items():
            for command in commands:
                with self.subTest(job=job, command=normalized(command)):
                    body = job_body(WORKFLOW, job)
                    self.assertIn(command, body)
                    removed_body = body.replace(command, "", 1)
                    mutated = WORKFLOW.replace(body, removed_body, 1)
                    self.assertIn(
                        f"{job}: {normalized(command)}", documentation_gate_failures(mutated)
                    )

    def test_java_javadocs_are_strict_and_documented_locally(self) -> None:
        readme = normalized((ROOT / "bindings/java/README.md").read_text(encoding="utf-8"))
        self.assertIn(normalized(JAVA_DOCS), readme)

    def test_android_javadocs_are_strict_and_documented_locally(self) -> None:
        readme = (ROOT / "bindings/android/README.md").read_text(encoding="utf-8")
        self.assertIn(ANDROID_DOCS, readme)
        gradle = (ROOT / "bindings/android/dfc/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn('addBooleanOption("Xdoclint:all", true)', gradle)
        self.assertIn('addBooleanOption("Werror", true)', gradle)
        self.assertIn("isFailOnError = true", gradle)

    def test_rustdoc_commands_are_documented_locally(self) -> None:
        readme = normalized((ROOT / "bindings/rust/README.md").read_text(encoding="utf-8"))
        self.assertIn(normalized(RUSTDOC_HOSTED), readme)
        self.assertIn(normalized(RUSTDOC_TARGET), readme)

    def test_python_public_docs_are_checked_and_documented_locally(self) -> None:
        readme = (ROOT / "bindings/python/README.md").read_text(encoding="utf-8")
        self.assertIn(PYTHON_DOCS, readme)

    def test_dotnet_xml_docs_and_missing_comment_errors_are_enabled(self) -> None:
        project = (ROOT / "bindings/dotnet/src/Dfc/Dfc.csproj").read_text(encoding="utf-8")
        readme = (ROOT / "bindings/dotnet/README.md").read_text(encoding="utf-8")
        self.assertIn("<GenerateDocumentationFile>true</GenerateDocumentationFile>", project)
        self.assertIn("<WarningsAsErrors>$(WarningsAsErrors);CS1591</WarningsAsErrors>", project)
        self.assertIn(DOTNET_BUILD, readme)
        for source in (ROOT / "bindings/dotnet/src/Dfc").rglob("*.cs"):
            if "bin" in source.parts or "obj" in source.parts:
                continue
            self.assertNotIn("#pragma warning disable CS1591", source.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
