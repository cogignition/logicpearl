from pathlib import Path

import pytest

from logicpearl.ir.loaders import dump_gate_ir, load_gate_ir
from logicpearl.ir.models import LogicPearlGateIR


V3_ROOT = Path(__file__).resolve().parents[2]
VALID_FIXTURE = V3_ROOT / "fixtures" / "ir" / "valid" / "auth-demo-v1.json"
INVALID_DUPLICATE_BIT_FIXTURE = V3_ROOT / "fixtures" / "ir" / "invalid" / "duplicate-bit.json"


def test_load_valid_fixture() -> None:
    gate = load_gate_ir(VALID_FIXTURE)

    assert isinstance(gate, LogicPearlGateIR)
    assert gate.gate_id == "auth_demo_v1"
    assert len(gate.rules) == 3
    assert [rule.bit for rule in gate.rules] == [0, 1, 2]


def test_dump_round_trip(tmp_path: Path) -> None:
    gate = load_gate_ir(VALID_FIXTURE)
    output_path = tmp_path / "gate.json"

    dump_gate_ir(gate, output_path)
    reloaded = load_gate_ir(output_path)

    assert reloaded.model_dump(mode="json", by_alias=True) == gate.model_dump(mode="json", by_alias=True)


def test_reject_duplicate_rule_bits() -> None:
    with pytest.raises(ValueError, match="duplicate rule bits"):
        load_gate_ir(INVALID_DUPLICATE_BIT_FIXTURE)
