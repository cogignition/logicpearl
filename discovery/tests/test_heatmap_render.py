from __future__ import annotations

from pathlib import Path

from logicpearl.render import load_heatmap_cases, render_bitmask_heatmap_svg


V3_ROOT = Path(__file__).resolve().parents[2]
EVAL_FIXTURE = V3_ROOT / "fixtures" / "ir" / "eval" / "auth-demo-v1-cases.json"


def test_render_heatmap_svg_contains_case_ids_and_rule_labels() -> None:
    gate, cases = load_heatmap_cases(EVAL_FIXTURE)
    svg = render_bitmask_heatmap_svg(gate, cases, title="auth_demo_v1 heatmap")

    assert "<svg" in svg
    assert "allow_read_active_editor" in svg
    assert "deny_multiple_rules" in svg
    assert "Viewer role is read-only." in svg
    assert "5 cases" in svg
