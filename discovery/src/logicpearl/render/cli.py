from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from logicpearl.ir import evaluate_gate, load_gate_ir

from .bitmask import gate_rule_labels, infer_bit_count, render_bitmask_svg, write_svg
from .heatmap import load_heatmap_cases, render_bitmask_heatmap_svg
from .html import render_bitmask_html, render_heatmap_html


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a LogicPearl bitmask as an SVG tiled grid.")
    parser.add_argument("--gate", type=Path, help="Path to gate IR JSON file")
    parser.add_argument("--input", type=Path, help="Path to input feature JSON file")
    parser.add_argument("--eval-fixture", type=Path, help="Path to an eval fixture JSON file for heatmap rendering")
    parser.add_argument("--bitmask", type=int, help="Bitmask integer to render directly")
    parser.add_argument("--bits", type=int, default=0, help="Explicit bit width")
    parser.add_argument("--columns", type=int, default=8, help="Grid column count")
    parser.add_argument("--output", type=Path, required=True, help="Output SVG path")
    parser.add_argument("--title", type=str, default=None, help="Optional title")
    args = parser.parse_args()
    output_is_html = args.output.suffix.lower() == ".html"

    if args.eval_fixture:
        gate, cases = load_heatmap_cases(args.eval_fixture)
        title = args.title or f"{gate.gate_id} bitmask heatmap"
        if output_is_html:
            content = render_heatmap_html(
                title=title,
                gate=gate,
                cases=cases,
                labels=gate_rule_labels(gate),
            )
        else:
            content = render_bitmask_heatmap_svg(
                gate,
                cases,
                title=title,
            )
    elif args.gate and args.input:
        gate = load_gate_ir(args.gate)
        payload = _load_json_object(args.input)
        bitmask = evaluate_gate(gate, payload)
        bit_count = args.bits or infer_bit_count(gate, bitmask=bitmask)
        labels = gate_rule_labels(gate)
        title = args.title or f"{gate.gate_id} bitmask"
        if output_is_html:
            content = render_bitmask_html(
                title=title,
                bitmask=bitmask,
                bit_count=bit_count,
                labels=labels,
            )
        else:
            content = render_bitmask_svg(
                bitmask,
                bit_count=bit_count,
                columns=args.columns,
                labels=labels,
                title=title,
            )
    elif args.bitmask is not None:
        bitmask = args.bitmask
        bit_count = args.bits or infer_bit_count(bitmask=bitmask)
        labels = None
        title = args.title or "LogicPearl bitmask"
        if output_is_html:
            content = render_bitmask_html(
                title=title,
                bitmask=bitmask,
                bit_count=bit_count,
                labels=labels,
            )
        else:
            content = render_bitmask_svg(
                bitmask,
                bit_count=bit_count,
                columns=args.columns,
                labels=labels,
                title=title,
            )
    else:
        raise ValueError("provide either --eval-fixture, --gate and --input, or --bitmask")

    write_svg(content, args.output)
    print(str(args.output))
    return 0


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("input JSON must be an object")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
