#!/usr/bin/env python3
"""Tests for tests/check_virtual_picc_staging.py.

The lint exists to stop three bug classes from coming back, so each test below
reintroduces one of them (or a disguised form of it) into the real source and
requires the lint to object. Every case here is a bypass a reviewer actually got
past an earlier, line-based version of the lint.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_virtual_picc_staging as lint

SOURCE = (lint.SOURCE_DIR / lint.PICC).read_text()
FRAME = "dfc_virtual_picc_iso_dep_frame_exchange"


def inject(function: str, statement: str, after: str | None = None) -> str:
    """Return the real source with `statement` added inside `function`.

    By default the statement goes at the top of the function body; with `after`
    it goes right after the first occurrence of that text inside the body.
    """
    header = re.search(rf"\b{function}\s*\([^;{{]*\)\s*\{{", SOURCE)
    assert header, function
    at = header.end()
    if after is not None:
        at = SOURCE.index(after, at) + len(after)
    return SOURCE[:at] + "\n" + statement + "\n" + SOURCE[at:]


class StagingLintTests(unittest.TestCase):
    def assert_rejected(self, text: str) -> None:
        self.assertTrue(lint.lint_picc(text), "the lint accepted a forbidden change")

    def test_real_source_is_accepted(self) -> None:
        self.assertEqual(lint.lint_picc(SOURCE), [])

    # -- the card block number ------------------------------------------------
    def test_every_spelling_of_assigning_the_block_number_is_rejected(self) -> None:
        for statement in (
            "session->picc_sequence = sequence;",
            "session->picc_sequence |= sequence;",
            "session->picc_sequence &= sequence;",
            "session->picc_sequence += 1;",
            "session->picc_sequence++;",
            "--session->picc_sequence;",
            "session->picc_sequence\n    = sequence;",
            "(*session).picc_sequence = sequence;",
            "uint8_t* alias = &session->picc_sequence; *alias = sequence;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_a_transmitter_may_only_toggle_with_the_bit_constant(self) -> None:
        self.assert_rejected(
            inject(
                "build_iso_dep_i_block",
                "session->picc_sequence ^= (uint8_t)session->expected_pcd_sequence;",
            )
        )

    def test_a_reset_must_be_to_zero(self) -> None:
        self.assert_rejected(inject("clear_protocol", "session->picc_sequence = 1;"))

    # -- retry and reassembly storage ------------------------------------------
    def test_raw_writes_to_the_retry_array_are_rejected(self) -> None:
        for statement in (
            "memcpy(session->pending_command, frame, frame_len);",
            "memcpy((*session).pending_command, frame, frame_len);",
            (
                "memcpy((uint8_t*)session + offsetof(DfcVirtualPiccSession, pending_command), "
                "frame, frame_len);"
            ),
            "session->pending_command[0] = 1;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_every_spelling_of_changing_the_staged_length_is_rejected(self) -> None:
        for statement in (
            "session->pending_command_len = 9999;",
            "session->pending_command_len++;",
            "session->pending_command_len <<= 1;",
            "session->pending_command_len\n    = 9999;",
            "size_t* length = &session->pending_command_len; *length = 9999;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_reading_the_staged_length_is_allowed(self) -> None:
        text = inject(FRAME, "size_t staged = session->pending_command_len; (void)staged;")
        self.assertEqual(lint.lint_picc(text), [])

    def test_a_macro_cannot_hide_the_field_name(self) -> None:
        self.assert_rejected("#define PC pending_command\n" + SOURCE)

    def test_the_chain_buffer_may_not_be_written_from_the_frame_function(self) -> None:
        for statement in (
            "memcpy(session->emulator->command_chain, frame, frame_len);",
            "session->emulator->command_chain_len = frame_len;",
            "session->emulator->command_chain = NULL;",
            "dfc_secure_wipe(session->emulator->command_chain, 4);",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_a_function_cannot_hide_inside_the_staging_markers(self) -> None:
        evil = (
            f"{lint.BEGIN}\nstatic void evil(DfcVirtualPiccSession* s, const uint8_t* f, "
            "size_t n) { memcpy(s->pending_command, f, n); s->pending_command_len = n; }\n"
        )
        self.assert_rejected(SOURCE.replace(lint.BEGIN + "\n", evil, 1))

    def test_missing_or_repeated_markers_are_rejected(self) -> None:
        self.assert_rejected(SOURCE.replace(lint.END, "// gone", 1))
        self.assert_rejected(SOURCE + "\n" + lint.BEGIN + "\n")

    def test_other_source_files_may_not_touch_the_protected_fields(self) -> None:
        self.assertTrue(lint.lint_other("x.c", "int f(S* s) { return s->pending_command[0]; }"))
        self.assertTrue(lint.lint_other("x.c", "void f(S* s) { s->picc_sequence = 1; }"))
        self.assertEqual(lint.lint_other("x.c", "// picc_sequence in a comment\nint g(void);"), [])

    # -- command bytes after the exchange --------------------------------------
    def test_command_bytes_may_not_reach_the_sdm_boundary(self) -> None:
        self.assert_rejected(
            inject(
                FRAME,
                "finalize_standard_iso_sdm_boundary(session,\n"
                "    (SdmBoundaryFacts){.standard_iso = inf[0] == 0}, status, response, 0);",
                after="&apdu_response_len, false);",
            )
        )

    def test_inf_may_not_be_used_after_the_exchange(self) -> None:
        for statement in (
            "volatile uint8_t sink = inf[0]; (void)sink;",
            "SdmBoundaryFacts late = capture_sdm_boundary_facts(session, inf, inf_len);",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement, after="&apdu_response_len, false);"))


class StagingLintHardeningTests(unittest.TestCase):
    """Bypasses found by an independent review of the first statement-level lint."""

    def assert_rejected(self, text: str) -> None:
        self.assertTrue(lint.lint_picc(text), "the lint accepted a forbidden change")

    def test_a_line_splice_cannot_split_a_field_name(self) -> None:
        for statement in (
            "session->picc_se\\\nquence = 1;",
            "session->pending_com\\\nmand_len = 5000;",
            "session->pending_comm\\\nand[0] = 1;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_offsetof_on_any_protected_field_is_rejected(self) -> None:
        for field in ("picc_sequence", "pending_command_len", "pending_command"):
            statement = f"((uint8_t*)session)[offsetof(DfcVirtualPiccSession, {field})] = frame[0];"
            with self.subTest(field=field):
                self.assert_rejected(inject(FRAME, statement))

    def test_a_comma_expression_cannot_hide_a_mirrored_block_number(self) -> None:
        toggle = "session->picc_sequence ^= DFC_ISO_DEP_SEQUENCE_BIT;"
        self.assertIn(toggle, SOURCE)
        mirrored = (
            "session->picc_sequence = session->expected_pcd_sequence, "
            "session->picc_sequence ^= DFC_ISO_DEP_SEQUENCE_BIT;"
        )
        self.assert_rejected(SOURCE.replace(toggle, mirrored, 1))

    def test_a_copy_into_the_address_of_a_member_is_rejected(self) -> None:
        self.assert_rejected(inject(FRAME, "memcpy(&session->iso_dep_max_inf, frame, frame_len);"))

    def test_the_staging_accessor_cannot_be_cast_to_writable(self) -> None:
        self.assert_rejected(
            inject(FRAME, "memcpy((uint8_t*)pending_command_data(session), frame, frame_len);")
        )

    def test_unparseable_function_shapes_are_errors_not_skips(self) -> None:
        digraph = "\nstatic void evil_dg(DfcVirtualPiccSession* s) <% s->picc_sequence = 1; %>\n"
        kr = "\nstatic void evil_kr(s) DfcVirtualPiccSession* s; { s->picc_sequence = 1; }\n"
        for extra in (digraph, kr):
            with self.subTest(extra=extra):
                self.assert_rejected(SOURCE + extra)

    def test_dead_preprocessor_text_cannot_hide_code(self) -> None:
        # An apostrophe in an `#if 0` block, and a stray brace, used to blank or
        # swallow the live code around them.
        dead = "\n#if 0\ndon't {\n#endif\n"
        hidden = inject(FRAME, dead + "session->picc_sequence = frame[0];\n" + dead)
        self.assert_rejected(hidden)
        unbalanced = (
            "\nstatic void evil_if(DfcVirtualPiccSession* s) {\n#if 0\n{\n#endif\n"
            "s->picc_sequence = 1;\n}\n"
        )
        self.assert_rejected(SOURCE + unbalanced)

    def test_chain_buffer_aliases_and_pointer_writes_are_rejected(self) -> None:
        for statement in (
            "{ uint8_t* c = session->emulator->command_chain; if(c) memcpy(c, frame, frame_len); }",
            "++session->emulator->command_chain_len;",
            "size_t* p = &session->emulator->command_chain_len; *p = 99999;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_aliasing_the_command_bytes_is_rejected(self) -> None:
        for alias in ("const uint8_t* ia = inf;", "size_t ial = inf_len;"):
            with self.subTest(alias=alias):
                self.assert_rejected(inject(FRAME, alias, after="&apdu_response_len, false);"))

    def test_headers_may_not_define_macros_or_bodies_that_name_the_fields(self) -> None:
        header = (lint.SOURCE_DIR / lint.PICC_HEADER).read_text()
        macro = "#define DFC_SET_LEN(s, v) ((s)->pending_command_len = (v))\n"
        self.assertTrue(lint.lint_other(lint.PICC_HEADER, macro + header, header=True))
        body = "static inline void leak(S* s) { s->picc_sequence = 1; }\n"
        self.assertTrue(lint.lint_other(lint.PICC_HEADER, header + body, header=True))
        self.assertEqual(lint.lint_other(lint.PICC_HEADER, header, header=True), [])
        # Another header may not name them at all.
        self.assertTrue(lint.lint_other("other.h", "int f(S* s) { return s->picc_sequence; }"))


class StagingLintRound3Tests(unittest.TestCase):
    """Bypasses an independent review found after the second hardening."""

    def assert_rejected(self, text: str) -> None:
        self.assertTrue(lint.lint_picc(text), "the lint accepted a forbidden change")

    def test_every_cast_of_the_staging_accessor_is_rejected(self) -> None:
        for statement in (
            "memcpy((uint8_t* const)pending_command_data(session), frame, frame_len);",
            "memcpy((DfcByte*)pending_command_data(session), frame, frame_len);",
            "memcpy((uint8_t*)(uintptr_t)pending_command_data(session), frame, frame_len);",
            "uint8_t* writable = pending_command_data(session); writable[0] = 1;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_overwriting_the_whole_session_is_rejected(self) -> None:
        for statement in (
            "memset(session, 0, sizeof(*session));",
            "memcpy(session, other, sizeof(*session));",
            "*session = replacement;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_a_header_function_with_nested_braces_is_still_checked(self) -> None:
        header = (lint.SOURCE_DIR / lint.PICC_HEADER).read_text()
        body = "static inline void f(S* s, int x) { s->picc_sequence = 1; if(x) { x++; } }\n"
        self.assertTrue(lint.lint_other(lint.PICC_HEADER, header + body, header=True))

    def test_a_constant_if_is_rejected_even_when_a_comment_opens_it(self) -> None:
        # The text between a fake `#if 0` and `#endif` inside comments used to be
        # blanked as dead code, hiding the write between them.
        hidden = "/*\n#if 0\n*/\nsession->picc_sequence = frame[0];\n/*\n#endif\n*/"
        self.assert_rejected(inject(FRAME, hidden))
        for condition in ("0", "(0)", "1-1", "0L"):
            with self.subTest(condition=condition):
                self.assert_rejected(inject(FRAME, f"#if {condition}\n#endif"))

    def test_token_pasting_aliases_and_casts_of_the_session_are_rejected(self) -> None:
        for statement in (
            "#define SEQ(s) ((s)->picc_seq##uence)",
            "DfcVirtualPiccSession* z = session; memset(z, 0, sizeof(*z));",
            "uint8_t* raw = (uint8_t*)session; raw[0] = 1;",
            "DfcVirtualPiccSession* const alias = session;",
        ):
            with self.subTest(statement=statement):
                self.assert_rejected(inject(FRAME, statement))

    def test_a_paste_in_another_file_that_builds_a_protected_name_is_rejected(self) -> None:
        self.assertTrue(lint.lint_other("x.h", "#define SEQ(s) ((s)->picc_seq##uence)"))
        self.assertTrue(lint.lint_other("x.h", "#define F(s) ((s)->pending_##command)"))
        self.assertEqual(lint.lint_other("x.h", "#define CAT(a, b) a##b"), [])

    def test_the_command_buffer_may_not_be_read_after_the_dispatch(self) -> None:
        text = (lint.SOURCE_DIR / lint.COMMANDS).read_text()
        self.assertEqual(lint.lint_commands(text), [])
        marker = "dfc_emulator_command_apply_ev1_response_secure_messaging(emulator, command_byte"
        self.assertIn(marker, text)
        for spelling in (
            "buffer[0]",
            "*buffer",
            "buffer + 1",
            "buffer->x",
            "memcpy(&c, buffer, 1), c",
            "(const uint8_t*)buffer",
            "alias = buffer",
        ):
            with self.subTest(spelling=spelling):
                bad = text.replace(
                    marker,
                    f"(void)({spelling});\n    {marker}",
                    1,
                )
                self.assertTrue(lint.lint_commands(bad))

    def test_include_files_and_subdirectories_are_scanned(self) -> None:
        suffixes = {path.suffix for root in lint.SCAN_ROOTS for path in root.rglob("*")}
        self.assertIn(".inc", suffixes)
        scanned = [
            path
            for root in lint.SCAN_ROOTS
            for path in root.rglob("*")
            if path.suffix in (".c", ".h", ".inc")
        ]
        self.assertTrue(any(p.suffix == ".inc" for p in scanned))
        self.assertTrue(lint.lint_other("x.inc", "void f(S* s) { s->picc_sequence = 1; }"))


if __name__ == "__main__":
    unittest.main()
