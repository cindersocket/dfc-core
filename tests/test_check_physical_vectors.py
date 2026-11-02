#!/usr/bin/env python3
"""Tests for scripts/check-physical-vectors-append-only.py.

Each case builds a throwaway git repository with one physical-card vector and one
synthetic vector, makes a single kind of change on a branch, and checks the guard's
verdict. The cases are the ways an earlier version of the guard was bypassed, plus
the plain edits it was always meant to catch.
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "check-physical-vectors-append-only.py"
)
spec = importlib.util.spec_from_file_location("append_only", SCRIPT)
append_only = importlib.util.module_from_spec(spec)
spec.loader.exec_module(append_only)

DIRECTORY = "tests/vectors/desfire/v6/hardware"
PHYSICAL = "# a capture\nname: x\norigin: physical-card\nframe-exchange E080 => 0565810280\n"
SYNTHETIC = "name: y\norigin: synthetic\n"


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root

    def git(self, *args: str) -> str:
        return subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def write(self, name: str, text: str) -> None:
        path = self.root / DIRECTORY / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)


class AppendOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(Path(self._tmp.name))
        self.repo.git("init", "-q", "-b", "main")
        self.repo.write("real.vec", PHYSICAL)
        self.repo.write("synthetic.vec", SYNTHETIC)
        self.repo.commit("base")
        self.repo.git("tag", "base")
        self.repo.git("checkout", "-q", "-b", "work")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def verdict(self) -> list[str]:
        return append_only.check("base", str(self.repo.root))[0]

    def test_adding_a_physical_vector_is_allowed(self) -> None:
        self.repo.write("new.vec", PHYSICAL)
        self.repo.commit("add")
        self.assertEqual(self.verdict(), [])

    def test_editing_a_synthetic_vector_is_allowed(self) -> None:
        self.repo.write("synthetic.vec", SYNTHETIC + "# more\n")
        self.repo.commit("edit")
        self.assertEqual(self.verdict(), [])

    # -- annotation: instructions for the replay that leave every genuine line alone --
    def _annotate(self, text: str) -> list[str]:
        self.repo.write("real.vec", text)
        self.repo.commit("annotate")
        return self.verdict()

    def test_comments_and_blank_lines_are_allowed_annotation(self) -> None:
        self.assertEqual(self._annotate("# why\n\n" + PHYSICAL + "\n# more\n"), [])

    def test_an_inject_random_step_is_allowed_annotation(self) -> None:
        text = PHYSICAL.replace(
            "frame-exchange E080", "inject-random 66A399FE5C4864A1\nframe-exchange E080"
        )
        self.assertEqual(self._annotate(text), [])

    def test_the_replayable_and_requires_headers_are_allowed_annotation(self) -> None:
        text = PHYSICAL.replace(
            "origin: physical-card\n", "origin: physical-card\nreplayable: true\nrequires: ev3\n"
        )
        self.assertEqual(self._annotate(text), [])

    def test_changing_a_genuine_line_is_not_annotation(self) -> None:
        for edit in (
            PHYSICAL.replace("0565810280", "0565810281"),  # response byte
            PHYSICAL.replace("E080", "E081"),  # request byte
            PHYSICAL + "frame-exchange 02FF => 02\n",  # an added exchange
            PHYSICAL.replace("name: x\n", "name: x\nuid: 04112233445566\n"),  # added setup header
            PHYSICAL.replace("frame-exchange E080 => 0565810280\n", ""),  # removed exchange
            PHYSICAL.replace("physical-card", "synthetic"),  # the origin
        ):
            with self.subTest(edit=edit):
                self.repo.git("reset", "-q", "--hard", "base")
                self.assertTrue(self._annotate(edit))

    def test_reordering_genuine_lines_is_not_annotation(self) -> None:
        self.repo.git("checkout", "-q", "main")
        two = PHYSICAL + "frame-exchange 0290 => 029100\n"
        self.repo.write("real.vec", two)
        self.repo.commit("two exchanges")
        self.repo.git("tag", "-f", "base")
        self.repo.git("checkout", "-q", "work")
        self.repo.git("reset", "-q", "--hard", "main")
        swapped = (
            PHYSICAL.replace("frame-exchange E080 => 0565810280\n", "")
            + "frame-exchange 0290 => 029100\nframe-exchange E080 => 0565810280\n"
        )
        self.assertTrue(self._annotate(swapped))

    def test_a_deletion_is_still_rejected_even_with_only_annotation_left(self) -> None:
        (self.repo.root / DIRECTORY / "real.vec").unlink()
        self.repo.commit("delete")
        self.assertTrue(self.verdict())

    def test_plain_edit_is_rejected(self) -> None:
        self.repo.write("real.vec", PHYSICAL + "frame-exchange 02FF => 02\n")
        self.repo.commit("edit")
        self.assertTrue(self.verdict())

    def _provisional_base(self) -> None:
        self.repo.write("batch.vec", PHYSICAL + "capture-status: provisional\n")
        self.repo.commit("add a provisional capture")
        self.repo.git("tag", "mid")
        self.repo.git("checkout", "-q", "-b", "retire")

    def test_a_provisional_capture_can_be_deleted(self) -> None:
        self._provisional_base()
        (self.repo.root / DIRECTORY / "batch.vec").unlink()
        self.repo.commit("retire the batch")
        self.assertEqual(append_only.check("mid", str(self.repo.root))[0], [])

    def test_a_provisional_capture_still_cannot_be_edited_or_renamed(self) -> None:
        self._provisional_base()
        self.repo.write(
            "batch.vec", PHYSICAL + "capture-status: provisional\nframe-exchange 02FF => 02\n"
        )
        self.repo.commit("edit")
        self.assertTrue(append_only.check("mid", str(self.repo.root))[0])
        self.repo.git("checkout", "-q", "mid")
        self.repo.git("checkout", "-q", "-b", "rename")
        (self.repo.root / DIRECTORY / "batch.vec").rename(self.repo.root / DIRECTORY / "other.vec")
        self.repo.commit("rename")
        self.assertTrue(append_only.check("mid", str(self.repo.root))[0])

    def test_a_genuine_capture_cannot_be_made_provisional_to_delete_it(self) -> None:
        # Adding the header is an edit, which is rejected, and so is the delete.
        self.repo.write("real.vec", PHYSICAL + "capture-status: provisional\n")
        self.repo.commit("mark provisional")
        self.assertTrue(self.verdict())
        (self.repo.root / DIRECTORY / "real.vec").unlink()
        self.repo.commit("delete")
        self.assertTrue(self.verdict())

    def test_deletion_is_rejected(self) -> None:
        (self.repo.root / DIRECTORY / "real.vec").unlink()
        self.repo.commit("delete")
        self.assertTrue(self.verdict())

    def test_rename_with_edit_is_rejected(self) -> None:
        self.repo.git("mv", f"{DIRECTORY}/real.vec", f"{DIRECTORY}/moved.vec")
        self.repo.write("moved.vec", PHYSICAL + "frame-exchange 02FF => 02\n")
        self.repo.commit("rename")
        self.assertTrue(self.verdict())

    def test_replacing_with_a_symlink_is_rejected(self) -> None:
        path = self.repo.root / DIRECTORY / "real.vec"
        path.unlink()
        path.symlink_to("synthetic.vec")
        self.repo.commit("symlink")
        self.assertTrue(self.verdict())

    def test_changing_the_origin_header_in_the_same_commit_is_rejected(self) -> None:
        self.repo.write("real.vec", PHYSICAL.replace("physical-card", "synthetic"))
        self.repo.commit("relabel")
        self.assertTrue(self.verdict())

    def test_edit_hidden_in_a_merge_is_rejected(self) -> None:
        self.repo.git("checkout", "-q", "main")
        self.repo.write("other.vec", SYNTHETIC)
        self.repo.commit("main moves")
        self.repo.git("checkout", "-q", "work")
        self.repo.git("merge", "-q", "--no-commit", "--no-ff", "main")
        self.repo.write("real.vec", PHYSICAL + "frame-exchange 02FF => 02\n")
        self.repo.commit("merge")
        self.assertTrue(self.verdict())

    def test_a_late_origin_line_still_counts(self) -> None:
        self.repo.git("checkout", "-q", "main")
        self.repo.write("late.vec", "".join(f"# line {i}\n" for i in range(80)) + PHYSICAL)
        self.repo.commit("add late")
        self.repo.git("tag", "-f", "base")
        self.repo.git("checkout", "-q", "work")
        self.repo.git("reset", "-q", "--hard", "main")
        self.repo.write(
            "late.vec",
            "".join(f"# line {i}\n" for i in range(80)) + PHYSICAL + "frame-exchange 02FF => 02\n",
        )
        self.repo.commit("edit late")
        self.assertTrue(self.verdict())

    def test_extra_spacing_in_the_header_still_counts(self) -> None:
        self.repo.git("checkout", "-q", "main")
        self.repo.write("spaced.vec", "name: s\norigin:   physical-card  \n")
        self.repo.commit("add spaced")
        self.repo.git("tag", "-f", "base")
        self.repo.git("checkout", "-q", "work")
        self.repo.git("reset", "-q", "--hard", "main")
        self.repo.write(
            "spaced.vec", "name: s\norigin:   physical-card  \nframe-exchange 02FF => 02\n"
        )
        self.repo.commit("edit spaced")
        self.assertTrue(self.verdict())

    def test_a_comment_that_mentions_the_words_is_not_a_header(self) -> None:
        self.repo.write("synthetic.vec", "# origin: physical-card is not true here\n" + SYNTHETIC)
        self.repo.commit("comment")
        self.repo.write(
            "synthetic.vec", "# origin: physical-card is not true here\n" + SYNTHETIC + "x\n"
        )
        self.repo.commit("edit")
        self.assertEqual(self.verdict(), [])

    def test_an_unusual_filename_is_still_protected(self) -> None:
        # git would quote these in its normal output and the path would no longer
        # end in .vec; the check reads names NUL-delimited instead.
        for name in ("caf\u00e9.vec", 'a"b.vec', "a\tb.vec"):
            with self.subTest(name=name):
                self.repo.git("checkout", "-q", "main")
                self.repo.write(name, PHYSICAL)
                self.repo.commit(f"add {name!r}")
                self.repo.git("tag", "-f", "base")
                self.repo.git("checkout", "-q", "work")
                self.repo.git("reset", "-q", "--hard", "main")
                self.repo.write(name, PHYSICAL + "frame-exchange 02FF => 02\n")
                self.repo.commit("edit")
                self.assertTrue(self.verdict())

    def test_unicode_whitespace_in_the_origin_line_still_counts(self) -> None:
        for header in ("origin:\u00a0physical-card", "origin:\u2003physical-card\u00a0"):
            with self.subTest(header=header):
                self.repo.git("checkout", "-q", "main")
                self.repo.write("uni.vec", f"name: u\n{header}\n")
                self.repo.commit("add uni")
                self.repo.git("tag", "-f", "base")
                self.repo.git("checkout", "-q", "work")
                self.repo.git("reset", "-q", "--hard", "main")
                self.repo.write("uni.vec", f"name: u\n{header}\nframe-exchange 02FF => 02\n")
                self.repo.commit("edit uni")
                self.assertTrue(self.verdict())


if __name__ == "__main__":
    unittest.main()
