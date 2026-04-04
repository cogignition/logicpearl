from __future__ import annotations

import json
from html import escape

from logicpearl.ir import LogicPearlGateIR

from .heatmap import HeatmapCase


def render_bitmask_html(
    *,
    title: str,
    bitmask: int,
    bit_count: int,
    labels: dict[int, str] | None = None,
) -> str:
    labels = labels or {}
    tiles = []
    legend_items = []
    for bit_index in range(bit_count):
        bit_is_set = bool(bitmask & (1 << bit_index))
        label = labels.get(bit_index, f"bit_{bit_index}")
        tiles.append(
            f'<button class="tile {"on" if bit_is_set else "off"}" '
            f'data-bit="{bit_index}" data-label="{escape(label)}" '
            f'data-state="{"on" if bit_is_set else "off"}" type="button">'
            f'<span class="bit">{bit_index}</span><span class="value">{1 if bit_is_set else 0}</span></button>'
        )
        legend_items.append(f"<li><strong>bit {bit_index}</strong> {escape(label)}</li>")

    body = (
        f'<div class="summary"><div>int={bitmask}</div><div>hex=0x{bitmask:0{max(1, (bit_count + 3) // 4)}X}</div>'
        f'<div>bin={bitmask:0{bit_count}b}</div></div>'
        f'<div class="layout"><section><div class="tile-grid">{"".join(tiles)}</div>'
        f'<ol class="legend">{"".join(legend_items)}</ol></section>'
        f'<aside id="detail" class="detail"><h2>Hover a tile</h2><p>Bit details appear here.</p></aside></div>'
    )
    script = """
const detail = document.getElementById('detail');
for (const tile of document.querySelectorAll('.tile')) {
  tile.addEventListener('mouseenter', () => {
    detail.innerHTML = `<h2>bit ${tile.dataset.bit}</h2><p><strong>${tile.dataset.label}</strong></p><p>state: ${tile.dataset.state}</p>`;
  });
}
"""
    return _wrap_html(title, body, script)


def render_heatmap_html(
    *,
    title: str,
    gate: LogicPearlGateIR,
    cases: list[HeatmapCase],
    labels: dict[int, str],
) -> str:
    max_bit = max((rule.bit for rule in gate.rules), default=-1)
    bit_indices = list(range(max_bit + 1))
    header_cells = "".join(
        f'<div class="header-cell" title="{escape(labels.get(bit_index, f"bit_{bit_index}"))}">{bit_index}</div>'
        for bit_index in bit_indices
    )

    rows = []
    for case in cases:
        cells = []
        for bit_index in bit_indices:
            bit_is_set = bool(case.bitmask & (1 << bit_index))
            label = labels.get(bit_index, f"bit_{bit_index}")
            cells.append(
                f'<button class="heat-cell {"on" if bit_is_set else "off"}" '
                f'data-case="{escape(case.case_id)}" data-bit="{bit_index}" '
                f'data-label="{escape(label)}" data-state="{"on" if bit_is_set else "off"}" '
                f'data-bitmask="0x{case.bitmask:X}" type="button"></button>'
            )
        rows.append(
            f'<div class="heat-row"><div class="case-id">{escape(case.case_id)}</div>'
            f'<div class="case-mask">0x{case.bitmask:X}</div><div class="case-cells">{"".join(cells)}</div></div>'
        )

    legend_items = "".join(
        f"<li><strong>bit {bit_index}</strong> {escape(labels[bit_index])}</li>"
        for bit_index in sorted(labels)
    )
    body = (
        f'<div class="summary"><div>{len(cases)} cases</div><div>{len(bit_indices)} rule bits</div></div>'
        f'<div class="layout"><section><div class="heat-header"><div class="case-id head">case</div>'
        f'<div class="case-mask head">mask</div><div class="header-cells">{header_cells}</div></div>'
        f'{"".join(rows)}<ol class="legend">{legend_items}</ol></section>'
        f'<aside id="detail" class="detail"><h2>Hover a cell</h2><p>Case and rule details appear here.</p></aside></div>'
    )
    script = """
const detail = document.getElementById('detail');
for (const cell of document.querySelectorAll('.heat-cell')) {
  cell.addEventListener('mouseenter', () => {
    detail.innerHTML = `<h2>${cell.dataset.case}</h2><p><strong>bit ${cell.dataset.bit}</strong> ${cell.dataset.label}</p><p>state: ${cell.dataset.state}</p><p>row bitmask: ${cell.dataset.bitmask}</p>`;
  });
}
"""
    return _wrap_html(title, body, script)


def _wrap_html(title: str, body: str, script: str) -> str:
    styles = """
body{margin:0;padding:24px;font-family:Menlo,Consolas,monospace;background:#f5f7fb;color:#0f172a}
.frame{max-width:1200px;margin:0 auto;background:#fcfcfd;border:1px solid #dbe4ee;border-radius:20px;padding:24px 24px 20px;box-shadow:0 12px 40px rgba(15,23,42,.08)}
h1{margin:0 0 8px;font-size:22px}
.summary{display:flex;gap:18px;font-size:12px;opacity:.75;margin-bottom:18px}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:24px;align-items:start}
.detail{position:sticky;top:24px;background:#f8fafc;border:1px solid #dbe4ee;border-radius:16px;padding:16px;min-height:120px}
.detail h2{margin:0 0 10px;font-size:16px}
.tile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(64px,64px));gap:10px;margin-bottom:18px}
.tile,.heat-cell{border:1.5px solid #94a3b8;background:#e2e8f0;border-radius:12px;cursor:pointer}
.tile.on,.heat-cell.on{background:#0f766e;border-color:#0f172a;color:#fff}
.tile{height:64px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px}
.tile .bit{font-size:11px}.tile .value{font-size:16px;font-weight:700}
.legend{margin:0;padding-left:18px;font-size:12px;line-height:1.6}
.heat-header,.heat-row{display:grid;grid-template-columns:minmax(180px,280px) 72px minmax(0,1fr);gap:12px;align-items:center}
.heat-header{margin-bottom:8px}
.case-id,.case-mask{font-size:11px}
.case-id.head,.case-mask.head{opacity:.65;text-transform:uppercase}
.header-cells,.case-cells{display:grid;grid-auto-flow:column;grid-auto-columns:22px;gap:6px}
.header-cell{height:22px;display:flex;align-items:center;justify-content:center;font-size:10px;border-radius:6px;background:#f1f5f9;border:1px solid #dbe4ee}
.heat-row{margin-bottom:8px}
.heat-cell{width:22px;height:22px;padding:0}
@media (max-width: 900px){.layout{grid-template-columns:1fr}.detail{position:static}}
"""
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{escape(title)}</title><style>{styles}</style></head>"
        f"<body><div class=\"frame\"><h1>{escape(title)}</h1>{body}</div><script>{script}</script></body></html>"
    )
