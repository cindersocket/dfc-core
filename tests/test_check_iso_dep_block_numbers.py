#!/usr/bin/env python3
"""Tests for tests/check_iso_dep_block_numbers.py.

A guard is only worth having if it rejects what it says it rejects, so each
case below is a short vector with exactly one defect. The model must flag it,
and must accept the same vector once the defect is removed.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_iso_dep_block_numbers as model

PRELUDE = "scan\nframe-exchange E080 => 0565810280\n"


def violations(body: str) -> list[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "case.vec"
        path.write_text(PRELUDE + body)
        return model.check_vector(path, root)


class BlockNumberModelTests(unittest.TestCase):
    def assert_rejected(self, body: str, fragment: str) -> None:
        found = violations(body)
        self.assertTrue(any(fragment in item for item in found), found)

    def test_correct_exchanges_are_accepted(self) -> None:
        self.assertEqual(
            violations(
                "frame-exchange 02905A00000312345600 => 029100\n"
                "frame-exchange 03906F000000 => 030102039100\n"
            ),
            [],
        )

    def test_card_number_is_its_own_not_the_readers(self) -> None:
        # The reader sends 03 first; the card still answers with 02.
        self.assertEqual(violations("frame-exchange 03905A00000312345600 => 029100\n"), [])
        self.assert_rejected(
            "frame-exchange 03905A00000312345600 => 039100\n", "card block number must be 0"
        )

    def test_spaced_and_wildcard_responses_are_still_checked(self) -> None:
        self.assert_rejected("frame-exchange 0200 => 03 00\n", "card block number must be 0")
        self.assert_rejected("frame-exchange 0200 => 03 ??\n", "card block number must be 0")
        self.assertEqual(violations("frame-exchange 0200 => 02 ??\n"), [])

    def test_unparseable_step_is_an_error_not_a_skip(self) -> None:
        self.assert_rejected("frame-exchange 02GG => 0200\n", "could not be parsed")

    def test_a_tolerance_clause_cannot_excuse_a_wrong_block_number(self) -> None:
        self.assert_rejected(
            "frame-exchange 02905A00000312345600 => 029100 tolerance 0+1 1\n",
            "tolerance",
        )

    def test_an_uppercase_step_keyword_is_still_checked(self) -> None:
        self.assert_rejected("FRAME-EXCHANGE zz => 00\n", "could not be parsed")

    def test_chained_fragment_must_get_an_r_ack(self) -> None:
        self.assert_rejected("frame-exchange 1200 => 0200\n", "R(ACK)")
        self.assertEqual(violations("frame-exchange 1200 => A2\n"), [])

    def test_complete_command_must_get_an_i_block(self) -> None:
        self.assert_rejected("frame-exchange 0200 => A2\n", "I-block")

    def test_card_never_sends_nak(self) -> None:
        self.assert_rejected("frame-exchange 1200 => B2\n", "never sends R(NAK)")

    def test_cid_must_be_echoed(self) -> None:
        self.assert_rejected("frame-exchange 0A0000 => 0200\n", "CID")
        self.assert_rejected("frame-exchange 0A0100 => 0A0200\n", "CID byte")
        self.assertEqual(violations("frame-exchange 0A0100 => 0A0100\n"), [])

    def test_retransmission_repeats_the_last_block(self) -> None:
        # After the first answer (number 0) the card's last number is 0, so A2
        # asks for a retransmission and must get the same bytes back.
        self.assert_rejected(
            "frame-exchange 0200 => 0200\nframe-exchange A2 => 03\n", "must retransmit"
        )
        self.assertEqual(violations("frame-exchange 0200 => 0200\nframe-exchange A2 => 0200\n"), [])

    def test_repeated_rats_is_ignored(self) -> None:
        self.assert_rejected("frame-exchange E080 => 0565810280\n", "repeated RATS")

    def test_only_deselect_is_answered_among_s_blocks(self) -> None:
        self.assert_rejected("frame-exchange F201 => F201\n", "only DESELECT")
        self.assertEqual(violations("frame-exchange C2 => C2\n"), [])

    def test_a_silent_deselect_does_not_end_checking(self) -> None:
        # A DESELECT with the wrong CID is ignored, so the card is still active and
        # the numbers after it must still be right.
        body = (
            "expect-error protocol-error frame-exchange CA05\n"
            "frame-exchange 02905A00000300000000 => 029100\n"
        )
        self.assertEqual(violations(body), [])
        self.assert_rejected(
            body + "frame-exchange 03905A00000300000000 => 029100\n", "card block number must be"
        )

    def test_deselect_must_be_answered_with_an_exact_echo(self) -> None:
        self.assert_rejected("frame-exchange C2 => 00\n", "exact echo")

    def test_malformed_pcb_bits_are_rejected(self) -> None:
        self.assert_rejected("frame-exchange 0200 => 00AA\n", "malformed I-block PCB")
        self.assert_rejected("frame-exchange 0200 => 06AA\n", "malformed I-block PCB")
        self.assert_rejected("frame-exchange 1200 => 82\n", "malformed R-block PCB")


if __name__ == "__main__":
    unittest.main()
