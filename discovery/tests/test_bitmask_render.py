from __future__ import annotations

from pathlib import Path

from logicpearl.ir import load_gate_ir
from logicpearl.render import gate_rule_labels, infer_bit_count, render_bitmask_svg


V3_ROOT = Path(__file__).resolve().parents[2]
VALID_GATE_FIXTURE = V3_ROOT / "fixtures" / "ir" / "valid" / "auth-demo-v1.json"


def test_render_svg_contains_grid_and_rule_labels() -> None:
    gate = load_gate_ir(VALID_GATE_FIXTURE)
    svg = render_bitmask_svg(
        7,
        bit_count=infer_bit_count(gate, bitmask=7),
        columns=2,
        labels=gate_rule_labels(gate),
        title="auth_demo_v1 bitmask",
    )

    assert "<svg" in svg
    assert "Archived resources are read-only." in svg
    assert "hex=0x7" in svg
    assert svg.count("<rect") >= 4
