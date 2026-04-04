from __future__ import annotations

from pathlib import Path

from logicpearl.ir import load_gate_ir
from logicpearl.render import (
    gate_rule_labels,
    infer_bit_count,
    load_heatmap_cases,
    render_bitmask_html,
    render_heatmap_html,
)


V3_ROOT = Path(__file__).resolve().parents[2]
VALID_GATE_FIXTURE = V3_ROOT / "fixtures" / "ir" / "valid" / "auth-demo-v1.json"
EVAL_FIXTURE = V3_ROOT / "fixtures" / "ir" / "eval" / "auth-demo-v1-cases.json"


def test_render_bitmask_html_contains_hover_panel() -> None:
    gate = load_gate_ir(VALID_GATE_FIXTURE)
    html = render_bitmask_html(
        title="auth_demo_v1 bitmask",
        bitmask=7,
        bit_count=infer_bit_count(gate, bitmask=7),
        labels=gate_rule_labels(gate),
    )

    assert "<!doctype html>" in html
    assert "Hover a tile" in html
    assert "Archived resources are read-only." in html


def test_render_heatmap_html_contains_case_and_rule_data() -> None:
    gate, cases = load_heatmap_cases(EVAL_FIXTURE)
    html = render_heatmap_html(
        title="auth_demo_v1 heatmap",
        gate=gate,
        cases=cases,
        labels=gate_rule_labels(gate),
    )

    assert "<!doctype html>" in html
    assert "Hover a cell" in html
    assert "deny_multiple_rules" in html
    assert "Viewer role is read-only." in html
