from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parents[3]
EXAMPLE = ROOT / "examples" / "python" / "virtual_card.py"
CREDENTIAL = ROOT / "examples" / "credentials" / "v6-maximal.dfcb"


def _load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location("virtual_card_example", EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_virtual_card_example_transceives_and_reads_file() -> None:
    module = _load_example()
    uid, aid, data = module.inspect_card(CREDENTIAL)

    assert uid
    assert aid == "010203"
    assert data == bytes.fromhex("DE AD BE EF")
