from __future__ import annotations

from html import escape
from math import ceil
from pathlib import Path

from logicpearl.ir import LogicPearlGateIR


def infer_bit_count(gate: LogicPearlGateIR | None = None, *, bitmask: int | None = None, minimum: int = 1) -> int:
    counts = [minimum]
    if gate is not None and gate.rules:
        counts.append(max(rule.bit for rule in gate.rules) + 1)
    if bitmask is not None:
        counts.append(max(minimum, bitmask.bit_length()))
    return max(counts)


def render_bitmask_svg(
    bitmask: int,
    *,
    bit_count: int,
    columns: int = 8,
    cell_size: int = 28,
    gap: int = 6,
    title: str | None = None,
    labels: dict[int, str] | None = None,
    on_color: str = "#0f766e",
    off_color: str = "#e2e8f0",
    text_color: str = "#0f172a",
    background_color: str = "#fcfcfd",
) -> str:
    columns = max(1, columns)
    rows = ceil(bit_count / columns)
    labels = labels or {}
    legend_items = [(bit_index, labels[bit_index]) for bit_index in sorted(labels)]

    title_height = 48 if title else 0
    grid_width = columns * cell_size + max(0, columns - 1) * gap
    content_height = rows * cell_size + max(0, rows - 1) * gap
    legend_height = 0
    if legend_items:
        legend_height = 24 + len(legend_items) * 18
    width = max(32 + grid_width, 360)
    height = 32 + title_height + content_height + legend_height
    x0 = 16
    y0 = 16 + title_height

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
        f'<rect width="{width}" height="{height}" fill="{background_color}" rx="16" ry="16"/>',
    ]

    if title:
        parts.append(
            f'<text x="16" y="28" font-family="Menlo, Consolas, monospace" font-size="16" fill="{text_color}">{escape(title)}</text>'
        )
        parts.append(
            f'<text x="16" y="44" font-family="Menlo, Consolas, monospace" font-size="12" fill="{text_color}" opacity="0.7">'
            f'int={bitmask} hex=0x{bitmask:0{max(1, ceil(bit_count / 4))}X} bin={bitmask:0{bit_count}b}</text>'
        )

    for bit_index in range(bit_count):
        row = bit_index // columns
        col = bit_index % columns
        x = x0 + col * (cell_size + gap)
        y = y0 + row * (cell_size + gap)
        bit_is_set = bool(bitmask & (1 << bit_index))
        fill = on_color if bit_is_set else off_color
        stroke = "#0f172a" if bit_is_set else "#94a3b8"
        bit_text = str(bit_index)
        label = labels.get(bit_index, "")

        parts.append(
            f'<rect x="{x}" y="{y}" width="{cell_size}" height="{cell_size}" rx="8" ry="8" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
        )
        if label:
            parts.append(f"<title>bit {bit_index}: {escape(label)} ({'on' if bit_is_set else 'off'})</title>")
        parts.append(
            f'<text x="{x + cell_size / 2}" y="{y + 12}" text-anchor="middle" '
            f'font-family="Menlo, Consolas, monospace" font-size="10" fill="{text_color}">{bit_text}</text>'
        )
        parts.append(
            f'<text x="{x + cell_size / 2}" y="{y + 23}" text-anchor="middle" '
            f'font-family="Menlo, Consolas, monospace" font-size="11" fill="{text_color}">{1 if bit_is_set else 0}</text>'
        )

    if legend_items:
        legend_y = y0 + content_height + 24
        parts.append(
            f'<text x="16" y="{legend_y}" font-family="Menlo, Consolas, monospace" font-size="12" fill="{text_color}">Legend</text>'
        )
        for offset, (bit_index, label) in enumerate(legend_items, start=1):
            line_y = legend_y + offset * 18
            parts.append(
                f'<text x="16" y="{line_y}" font-family="Menlo, Consolas, monospace" font-size="11" fill="{text_color}">'
                f'bit {bit_index}: {escape(label)}</text>'
            )

    parts.append("</svg>")
    return "".join(parts)


def gate_rule_labels(gate: LogicPearlGateIR) -> dict[int, str]:
    labels: dict[int, str] = {}
    for rule in gate.rules:
        labels[rule.bit] = rule.label or rule.message or rule.id
    return labels


def write_svg(svg: str, path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(svg + "\n", encoding="utf-8")
