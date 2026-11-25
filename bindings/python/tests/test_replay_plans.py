"""Replay every DESFire conformance vector through the Python binding.

The plans under ``tests/replay-plans`` are produced by the C conformance runner
(``make -C tests replay-plans``): the initial credential in the library's own
encoding, then explicit steps. This test only replays them, so the binding is
compared against the same expectations as the C engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from dfc_core import Credential, DfcError, RandomSourceError, VirtualPicc
from dfc_core.models import Activation

PLANS = Path(__file__).parents[3] / "tests" / "replay-plans"


@dataclass
class Plan:
    name: str
    credential: bytes = b""
    finite_random: bool = False
    skip: str | None = None
    steps: list[list[str]] = field(default_factory=list)
    final: bytes = b""


def parse_hex(text: str) -> bytes:
    return b"" if text == "-" else bytes.fromhex(text)


def parse_plan(path: Path) -> Plan:
    plan = Plan(path.stem)
    for line in path.read_text().splitlines():
        key, _, rest = line.partition(" ")
        if key == "credential":
            plan.credential = parse_hex(rest)
        elif key == "random":
            plan.finite_random = rest == "finite"
        elif key == "skip":
            plan.skip = rest
        elif key == "step":
            plan.steps.append(rest.split(" "))
        elif key == "final":
            plan.final = parse_hex(rest)
        elif key not in {"plan", "source"}:
            raise ValueError(f"{path.name}: unknown plan line {line!r}")
    return plan


def matches(actual: bytes, expected: str, tolerances: list[str]) -> bool:
    """Compare with ``??`` wildcards and ``tol=offset+length:delta`` clauses."""
    want = (
        [None] * 0 if expected == "-" else [expected[i : i + 2] for i in range(0, len(expected), 2)]
    )
    if len(actual) != len(want):
        return False
    ranges = []
    for clause in tolerances:
        span, _, delta = clause.removeprefix("tol=").partition(":")
        offset, _, length = span.partition("+")
        ranges.append((int(offset), int(length), int(delta)))
    tolerated = {i for offset, length, _ in ranges for i in range(offset, offset + length)}
    for index, token in enumerate(want):
        if index not in tolerated and token != "??" and actual[index] != int(token, 16):
            return False
    for offset, length, delta in ranges:
        got = int.from_bytes(actual[offset : offset + length], "little")
        expect = int.from_bytes(
            bytes.fromhex(expected[2 * offset : 2 * (offset + length)]), "little"
        )
        if abs(got - expect) > delta:
            return False
    return True


def attempt(picc: VirtualPicc, target: str, payload: bytes) -> DfcError | None:
    """Run one operation that the plan expects to fail and return its error."""
    try:
        if target == "scan":
            picc.activate()
        elif target == "exchange":
            picc.exchange(payload)
        else:
            picc.frame_exchange(payload)
    except DfcError as error:
        return error
    return None


def replay(plan: Plan) -> tuple[list[str], int, int]:
    """Return failures, asserts evaluated and asserts left to the final comparison."""
    queue = bytearray()

    def draw(count: int) -> bytes:
        if len(queue) < count:
            raise ValueError("replay random queue exhausted")
        out = bytes(queue[:count])
        del queue[:count]
        return out

    failures: list[str] = []
    checked = unchecked = 0
    activation: Activation | None = None
    picc = VirtualPicc(Credential.decode(plan.credential), draw if plan.finite_random else None)
    with picc:
        for number, (op, *args) in enumerate(plan.steps, 1):
            where = f"{plan.name} step {number} ({op})"
            try:
                if op == "scan":
                    activation = picc.activate()
                elif op == "field-off":
                    picc.field_off()
                    activation = None
                elif op == "clear-dirty":
                    picc.mark_persisted()
                elif op == "random-clear":
                    queue.clear()
                elif op == "random-inject":
                    queue.extend(parse_hex(args[0]))
                elif op == "advance-time":
                    picc.advance_time(int(args[0]))
                elif op in {"exchange", "frame"}:
                    send = picc.exchange if op == "exchange" else picc.frame_exchange
                    actual = send(parse_hex(args[0]))
                    if not matches(actual, args[1], args[2:]):
                        failures.append(f"{where}: expected {args[1]} got {actual.hex().upper()}")
                elif op == "error":
                    kind, target, payload = (
                        args[0],
                        args[1],
                        parse_hex(args[2]) if len(args) > 2 else b"",
                    )
                    before = len(queue)
                    raised = attempt(picc, target, payload)
                    if raised is None:
                        failures.append(f"{where}: expected an error")
                    elif isinstance(raised, RandomSourceError) != (kind == "random-source"):
                        failures.append(f"{where}: wrong error class {raised!r}")
                    if kind == "random-source" and len(queue) != before:
                        failures.append(f"{where}: failed draw consumed random bytes")
                    if kind == "random-source" and target == "scan":
                        activation = None
                elif op == "assert":
                    path, value = args
                    if path == "credential.dirty":
                        checked += 1
                        if int(picc.snapshot().dirty) != int(value):
                            failures.append(f"{where}: {path} expected {value}")
                    elif path.startswith("activation.") and activation is not None:
                        checked += 1
                        actual_value = {
                            "uid": activation.uid,
                            "uid_len": len(activation.uid),
                            "sak": activation.sak,
                            "atqa": activation.atqa,
                            "ats": activation.ats,
                        }[path.removeprefix("activation.")]
                        want = (
                            bytes.fromhex(value)
                            if isinstance(actual_value, bytes)
                            else int(value, 0)
                        )
                        if actual_value != want:
                            failures.append(
                                f"{where}: {path} expected {value} got {actual_value!r}"
                            )
                    else:
                        unchecked += 1
                else:
                    failures.append(f"{where}: unknown plan step")
            except (DfcError, ValueError) as error:
                failures.append(f"{where}: unexpected {error!r}")
        with picc.export() as exported:
            if exported.encode() != plan.final:
                failures.append(f"{plan.name}: final credential differs from the C engine")
    return failures, checked, unchecked


def test_vector_replay_plans_match_the_c_engine(capsys: pytest.CaptureFixture[str]) -> None:
    plans = [parse_plan(path) for path in sorted(PLANS.glob("*.plan"))]
    assert plans, "no replay plans found; run make -C tests replay-plans"
    failures: list[str] = []
    skipped: dict[str, list[str]] = {}
    replayed = checked = unchecked = 0
    for plan in plans:
        if plan.skip is not None:
            skipped.setdefault(plan.skip, []).append(plan.name)
            continue
        plan_failures, plan_checked, plan_unchecked = replay(plan)
        failures += plan_failures
        replayed += 1
        checked += plan_checked
        unchecked += plan_unchecked
    with capsys.disabled():
        print(
            f"\npython replay: {replayed} vectors replayed, "
            f"{sum(map(len, skipped.values()))} skipped, {len(failures)} failures; "
            f"{checked} assertions evaluated, {unchecked} left to the final credential comparison"
        )
        for reason, names in skipped.items():
            print(f"  skipped {len(names)}: {reason}: {', '.join(names)}")
    assert not failures, "\n".join(failures[:20])
    # Exactly these plans are skipped (the plan files carry the reason), and every other plan
    # is replayed: a regression that skips more would otherwise pass.
    expected_skips = {
        "v4-emulator-model_key_set_invariants",
        "v4-emulator-model_sdm_encrypted_range_overflow",
        "v4-emulator-vecb-ev1-create-file-full-pool",
    }
    assert {name for names in skipped.values() for name in names} == expected_skips
    assert replayed == len(plans) - len(expected_skips)
