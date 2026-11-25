#!/usr/bin/env python3
"""Replay every conformance vector against an independent ISO 14443-4 model.

The emulator and this script implement the card's block-number rule
separately, so a bug in one cannot hide behind a vector that was regenerated
from the same bug. The rule, as measured on genuine EV3 silicon:

* The card keeps one block number per activation. RATS sets it to 0.
* It is transmitted in, and then toggled by, every I-block the card sends and
  every R(ACK) the card sends in answer to a received I-block. A duplicate or
  out-of-sequence reader I-block is still a received block, so the card
  advances for it. The card's number is never copied from the reader's.
* An R(ACK) from the reader that repeats the card's last number requests a
  retransmission; the other number requests the next block of a response
  chain. An R(NAK) is answered with an R(ACK) that repeats the card's current
  (last transmitted) number and does not advance it.
* A card that stays silent (expect-error) does not advance.
* The card never checks the reader's number; every received I-block is new.
* After RATS the card behaves as if its last block were an empty I-block
  numbered 1. A repeated RATS in an active session is ignored.
* An R-block repeating the card's last number retransmits the last block,
  whether it is an ACK or a NAK. An R(ACK) with the other number advances a
  response chain, or is ignored if none is pending. An R(NAK) with the other
  number is answered by an R(ACK) with the card's last number.

Every frame-exchange step in every vector, physical or synthetic, must follow
the model. A synthetic vector that contradicts it is wrong, because the
physical traces are what pin the rule.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VECTOR_ROOT = ROOT / "vectors" / "desfire"

I_BLOCK, R_BLOCK, S_BLOCK = 0x00, 0x80, 0xC0
CHAIN = 0x10
CID_BIT = 0x08
# Any line that looks like a frame step must parse; a line that does not is an
# error, never silently skipped (a skipped step would leave the model out of
# step with the card and hide later violations).
STEP_LINE = re.compile(r"^(expect-error\s+\S+\s+)?frame-exchange\b", re.IGNORECASE)
STEP = re.compile(
    r"^(?P<silent>expect-error\s+\S+\s+)?frame-exchange\s+"
    r"(?P<req>[0-9A-Fa-f]+)(?:\s*=>\s*(?P<resp>[0-9A-Fa-f? ]*?))?"
    r"(?:\s+tolerance\b.*)?\s*$"
)


def block_type(pcb: int) -> int:
    return pcb & 0xC0


def parse_response(text: str) -> list[int | None]:
    """Hex octets, with None for each `??` wildcard (spaces allowed)."""
    compact = text.replace(" ", "")
    if len(compact) % 2:
        raise ValueError("odd number of hex digits")
    octets: list[int | None] = []
    for index in range(0, len(compact), 2):
        pair = compact[index : index + 2]
        octets.append(None if pair == "??" else int(pair, 16))
    return octets


def same(left: list[int | None], right: list[int | None]) -> bool:
    return len(left) == len(right) and all(
        a is None or b is None or a == b for a, b in zip(left, right)
    )


def check_vector(path: Path, root: Path = VECTOR_ROOT) -> list[str]:
    errors: list[str] = []
    active = False
    card_bn = 0
    last_sent: list[int | None] = []
    chain_pending = False
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        where = f"{path.relative_to(root)}:{number}"
        if line.startswith(("scan", "field-off")):
            active = False
            continue
        if not STEP_LINE.match(line):
            continue
        match = STEP.match(line)
        if match and re.search(r"\btolerance\b", line):
            # The replay runner honours a tolerance by accepting other bytes,
            # which would let a wrong block number through unnoticed. No frame
            # step needs one, so none is allowed.
            errors.append(f"{where}: a frame step may not carry a tolerance clause")
            continue
        if not match:
            errors.append(f"{where}: frame step could not be parsed: {line[:60]}")
            continue
        request = bytes.fromhex(match["req"])
        silent = match["silent"] is not None or match["resp"] is None
        try:
            response = [] if silent else parse_response(match["resp"])
        except ValueError as problem:
            errors.append(f"{where}: bad response hex ({problem})")
            continue

        if request[0] == 0xE0:
            if active:
                if response:
                    errors.append(f"{where}: a repeated RATS in an active session is ignored")
                continue
            active, card_bn, chain_pending = True, 0, False
            last_sent = [0x02 | 1]  # empty I-block, number 1
            continue
        if not active:
            continue
        kind = block_type(request[0])
        if kind == S_BLOCK:
            if request[0] & 0xF7 == 0xC2:
                # DESELECT ends the activation only if the card answered it. A
                # silent one (for example with the wrong CID) leaves it active.
                if response:
                    if not same(response, list(request)):
                        errors.append(f"{where}: DESELECT must be answered with an exact echo")
                    active = False
            elif response:
                errors.append(f"{where}: only DESELECT is answered among S-blocks")
            continue
        if response and response[0] is None:
            errors.append(f"{where}: the first response octet may not be a wildcard")
            continue
        if response:
            first = response[0]
            # The fixed bits of the card's PCB: an I-block is 000x x01x (no NAD),
            # an R(ACK) is 101x 001x. Chain, CID and number bits are checked below.
            if block_type(first) == I_BLOCK and first & 0xE6 != 0x02:
                errors.append(f"{where}: malformed I-block PCB {first:02x}")
            if block_type(first) == R_BLOCK and first & 0xE6 != 0xA2:
                errors.append(f"{where}: malformed R-block PCB {first:02x}")
            if block_type(first) == R_BLOCK and first & 0x10:
                errors.append(f"{where}: the card never sends R(NAK)")
            if block_type(first) == S_BLOCK:
                errors.append(f"{where}: the card sends an S-block only to answer DESELECT")
            echoes_cid = bool(request[0] & CID_BIT)
            if bool(first & CID_BIT) != echoes_cid:
                errors.append(f"{where}: the response must carry CID exactly when the request does")
            elif echoes_cid and len(response) > 1 and response[1] not in (None, request[1]):
                errors.append(f"{where}: the response must echo the request's CID byte")
        if kind == I_BLOCK:
            if silent:
                continue
            if chain_pending:
                errors.append(f"{where}: card answered an I-block during a response chain")
                continue
            first = response[0]
            reader_chains = bool(request[0] & CHAIN)
            if reader_chains and block_type(first) != R_BLOCK:
                errors.append(f"{where}: a chained request fragment must be answered by R(ACK)")
            if not reader_chains and block_type(first) != I_BLOCK:
                errors.append(f"{where}: a complete request must be answered by an I-block")
            if (first & 1) != card_bn:
                errors.append(
                    f"{where}: request {request[:2].hex()} -> {first:02x}, "
                    f"card block number must be {card_bn}"
                )
            card_bn ^= 1
            last_sent = response
            chain_pending = block_type(first) == I_BLOCK and bool(first & CHAIN)
        elif kind == R_BLOCK:
            nak = bool(request[0] & 0x10)
            reader_bn = request[0] & 1
            last_bn = card_bn ^ 1
            if reader_bn == last_bn:
                if response and not same(response, last_sent):
                    errors.append(f"{where}: repeating the last number must retransmit")
            elif nak:
                if response and (
                    block_type(response[0]) != R_BLOCK or (response[0] & 1) != last_bn
                ):
                    errors.append(
                        f"{where}: R(NAK) must be answered by R(ACK) with number {last_bn}"
                    )
            elif chain_pending:
                if response:
                    if block_type(response[0]) != I_BLOCK or (response[0] & 1) != card_bn:
                        errors.append(f"{where}: next chained block must use card number {card_bn}")
                    card_bn ^= 1
                    last_sent = response
                    chain_pending = bool(response[0] & CHAIN)
            elif response:
                errors.append(f"{where}: R(ACK) with the other number is ignored when idle")
    return errors


def main() -> int:
    paths = sorted(VECTOR_ROOT.rglob("*.vec"))
    failures: list[str] = []
    for path in paths:
        failures.extend(check_vector(path))
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(f"{len(failures)} block-number violation(s)", file=sys.stderr)
        return 1
    print(f"ISO-DEP block numbers conform in {len(paths)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
