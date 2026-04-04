from __future__ import annotations

import json
from dataclasses import dataclass
from html import escape
from pathlib import Path

from logicpearl.ir import LogicPearlGateIR, evaluate_gate, load_gate_ir

from .bitmask import gate_rule_labels


@dataclass(frozen=True)
class HeatmapCase:
    case_id: str
    bitmask: int


def load_heatmap_cases(path: str | Path) -> tuple[LogicPearlGateIR, list[HeatmapCase]]:
    eval_path = Path(path)
    v3_root = eval_path.resolve().parents[3]
    payload = json.loads(eval_path.read_text(encoding="utf-8"))
    gate = load_gate_ir(v3_root / "fixtures" / payload["gate_fixture"])
    cases = [
        HeatmapCase(
            case_id=case["id"],
            bitmask=evaluate_gate(gate, case["input"]),
        )
        for case in payload["cases"]
    ]
    return gate, cases


def render_bitmask_heatmap_svg(
    gate: LogicPearlGateIR,
    cases: list[HeatmapCase],
    *,
    title: str | None = None,
    cell_size: int = 22,
    gap: int = 4,
    left_label_width: int = 0,
    header_height: int = 72,
    top_margin: int = 24,
    on_color: str = "#0f766e",
    off_color: str = "#e2e8f0",
    text_color: str = "#0f172a",
    background_color: str = "#fcfcfd",
) -> str:
    labels = gate_rule_labels(gate)
    bit_count = max((rule.bit for rule in gate.rules), default=-1) + 1
    if left_label_width <= 0:
        longest_case = max((len(case.case_id) for case in cases), default=12)
        left_label_width = max(220, min(420, longest_case * 7 + 70))
    grid_width = bit_count * cell_size + max(0, bit_count - 1) * gap
    grid_height = len(cases) * cell_size + max(0, len(cases) - 1) * gap
    legend_height = 28 + len(labels) * 18 if labels else 0
    width = 24 + left_label_width + grid_width + 24
    height = top_margin + header_height + grid_height + legend_height + 24
    title = title or f"{gate.gate_id} bitmask heatmap"

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
        f'<rect width="{width}" height="{height}" fill="{background_color}" rx="16" ry="16"/>',
        f'<text x="16" y="30" font-family="Menlo, Consolas, monospace" font-size="18" fill="{text_color}">{escape(title)}</text>',
        f'<text x="16" y="48" font-family="Menlo, Consolas, monospace" font-size="12" fill="{text_color}" opacity="0.7">{len(cases)} cases · {bit_count} rule bits</text>',
    ]

    header_y = top_margin + 48
    grid_x = 16 + left_label_width
    grid_y = top_margin + header_height

    for bit_index in range(bit_count):
        x = grid_x + bit_index * (cell_size + gap)
        parts.append(
            f'<text x="{x + cell_size / 2}" y="{header_y}" text-anchor="middle" '
            f'font-family="Menlo, Consolas, monospace" font-size="10" fill="{text_color}">{bit_index}</text>'
        )

    for row_index, case in enumerate(cases):
        y = grid_y + row_index * (cell_size + gap)
        parts.append(
            f'<text x="16" y="{y + 15}" font-family="Menlo, Consolas, monospace" font-size="11" fill="{text_color}">{escape(case.case_id)}</text>'
        )
        parts.append(
            f'<text x="{left_label_width - 18}" y="{y + 15}" text-anchor="end" font-family="Menlo, Consolas, monospace" font-size="10" fill="{text_color}" opacity="0.7">0x{case.bitmask:X}</text>'
        )

        for bit_index in range(bit_count):
            x = grid_x + bit_index * (cell_size + gap)
            bit_is_set = bool(case.bitmask & (1 << bit_index))
            fill = on_color if bit_is_set else off_color
            stroke = "#0f172a" if bit_is_set else "#94a3b8"
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_size}" height="{cell_size}" rx="6" ry="6" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="1.25"/>'
            )
            label = labels.get(bit_index, f"bit_{bit_index}")
            parts.append(
                f"<title>{escape(case.case_id)} | bit {bit_index}: {escape(label)} | {'on' if bit_is_set else 'off'}</title>"
            )

    if labels:
        legend_y = grid_y + grid_height + 26
        parts.append(
            f'<text x="16" y="{legend_y}" font-family="Menlo, Consolas, monospace" font-size="12" fill="{text_color}">Legend</text>'
        )
        for offset, bit_index in enumerate(sorted(labels), start=1):
            line_y = legend_y + offset * 18
            parts.append(
                f'<text x="16" y="{line_y}" font-family="Menlo, Consolas, monospace" font-size="11" fill="{text_color}">'
                f'bit {bit_index}: {escape(labels[bit_index])}</text>'
            )

    parts.append("</svg>")
    return "".join(parts)
