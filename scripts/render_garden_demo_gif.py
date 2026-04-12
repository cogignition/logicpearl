#!/usr/bin/env python3
"""Render the README garden-actions walkthrough GIF.

The animation is intentionally generated from the checked-in demo files and,
when cargo is available, the current LogicPearl CLI output. That keeps the
README visual close to the thing a developer can run locally.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
from fractions import Fraction
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demos" / "garden_actions"
GIF_OUT = ROOT / "docs" / "assets" / "garden-actions-demo.gif"
APNG_OUT = ROOT / "docs" / "assets" / "garden-actions-demo.png"
W, H = 1100, 620
FRAME_COUNT = 74
FRAME_MS = 800
FINAL_HOLD_MS = 1600

BG = (239, 250, 242)
PANEL = (255, 255, 255)
PANEL_SOFT = (247, 252, 248)
INK = (31, 61, 46)
MUTED = (83, 112, 92)
LINE = (154, 203, 164)
GREEN = (47, 141, 84)
GREEN_DARK = (23, 56, 42)
BLUE = (84, 169, 207)
YELLOW = (247, 195, 73)
CORAL = (231, 111, 81)
RED_SOFT = (255, 226, 218)
BLUE_SOFT = (216, 241, 255)
YELLOW_SOFT = (255, 242, 174)
CORAL_SOFT = (255, 216, 203)
GRAY_SOFT = (238, 242, 237)
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def load_font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    if mono:
        names = [
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/Supplemental/Courier New.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ]
    else:
        names = [
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    for name in names:
        path = Path(name)
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


TITLE = load_font(36, True)
H2 = load_font(22, True)
BODY = load_font(18)
BODY_BOLD = load_font(18, True)
SMALL = load_font(14)
SMALL_BOLD = load_font(14, True)
MONO = load_font(17, mono=True)
MONO_SMALL = load_font(14, mono=True)
MONO_TINY = load_font(12, mono=True)
MONO_TERM = load_font(15, mono=True)


def ease(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) * (1 - t)


def smoothstep(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)


def mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return tuple(int(a[i] * (1 - t) + b[i] * t) for i in range(3))


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def read_demo_data() -> tuple[list[str], list[dict[str, str]], dict[str, object]]:
    log_lines = []
    for line in (DEMO / "garden_log.md").read_text().splitlines():
        if line.strip().lower() == "dot, pothos":
            break
        if line.strip() and not line.startswith("#"):
            log_lines.append(line)
        if len(log_lines) >= 10:
            break

    with (DEMO / "traces.csv").open(newline="") as file:
        rows = list(csv.DictReader(file))[:5]

    today = json.loads((DEMO / "today.json").read_text())
    return log_lines, rows, today


def command_base() -> list[str]:
    override = os.environ.get("LOGICPEARL_BIN")
    if override:
        return [override]
    return ["cargo", "run", "--manifest-path", str(ROOT / "Cargo.toml"), "-q", "-p", "logicpearl", "--"]


def clean_terminal_line(line: str) -> str:
    line = ANSI_RE.sub("", line)
    line = CONTROL_RE.sub("", line)
    return "".join(char if char == "\t" or 32 <= ord(char) <= 126 else " " for char in line).rstrip()


def clean_terminal_lines(lines: Iterable[str]) -> list[str]:
    return [clean_terminal_line(line) for line in lines]


def compact_rule_text(line: str) -> str:
    return (
        line.replace(" at or below ", " <= ")
        .replace(" at or above ", " >= ")
        .replace(" in the last ", " last ")
    )


def compact_rule_lines(lines: Iterable[str]) -> list[str]:
    return [compact_rule_text(line) if " at or " in line else line for line in lines]


def run_cli_output() -> tuple[list[str], list[str], list[str]]:
    fallback_build = [
        "$ logicpearl build",
        "Built action artifact garden_actions",
        "  Rows 16",
        "  Actions water, do_nothing, fertilize, repot",
        "  Default action do_nothing",
        "  Training parity 100.0%",
    ]
    fallback_inspect = [
        "$ logicpearl inspect",
        "Rules:",
        "  water",
        "    bit 0: Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2",
        "  fertilize",
        "    bit 0: Growth in the last 14 days at or above 2.2 and Leaf Paleness at or above 4.0",
        "  repot",
        "    bit 0: Pot Crack above 0.0",
        "    bit 1: Root Crowding above 2.0",
    ]
    fallback_run = [
        "$ logicpearl run today.json --explain",
        "action: water",
        "reason:",
        "  - Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2",
    ]

    base = command_base()
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "CLICOLOR": "0", "TERM": "dumb"})
    try:
        shutil.rmtree("/tmp/garden-actions", ignore_errors=True)
        build = subprocess.run(
            base + ["build"],
            cwd=DEMO,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
            check=True,
        ).stdout.splitlines()
        inspect = subprocess.run(
            base + ["inspect"],
            cwd=DEMO,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
            check=True,
        ).stdout.splitlines()
        run = subprocess.run(
            base + ["run", "today.json", "--explain"],
            cwd=DEMO,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
            check=True,
        ).stdout.splitlines()
        build = clean_terminal_lines(build)
        inspect = clean_terminal_lines(inspect)
        run = clean_terminal_lines(run)
        return (
            ["$ logicpearl build"] + build[:5],
            ["$ logicpearl inspect"] + compact_inspect(inspect),
            ["$ logicpearl run today.json --explain"] + compact_rule_lines(run),
        )
    except Exception:
        return fallback_build, fallback_inspect, fallback_run


def compact_inspect(lines: Iterable[str]) -> list[str]:
    keep: list[str] = []
    in_action = False
    for line in lines:
        stripped = line.strip()
        if stripped in {"Routes:", "Rules:"}:
            keep.append("Rules:")
            in_action = False
            continue
        route = stripped.split(maxsplit=1)[0] if stripped else ""
        if route in {"water", "fertilize", "repot"}:
            keep.append(f"  {route}")
            in_action = True
            continue
        if in_action and "bit" in stripped:
            keep.append("    " + compact_rule_text(stripped))
    return keep[:9]


def rounded(draw: ImageDraw.ImageDraw, xy, fill, outline=LINE, width=2, radius=8) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def draw_text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    fill=INK,
    font_obj=BODY,
    spacing: int = 4,
) -> None:
    draw.multiline_text(xy, value, fill=fill, font=font_obj, spacing=spacing)


def crop_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 1] + "..."


def panel(draw: ImageDraw.ImageDraw, xy, fill=PANEL, outline=LINE) -> None:
    x0, y0, x1, y1 = xy
    draw.rounded_rectangle((x0 + 7, y0 + 9, x1 + 7, y1 + 9), radius=8, fill=(207, 232, 211), outline=None)
    rounded(draw, xy, fill, outline, radius=8)


TAB_LAYOUT = [
    ("garden_log.md", 42, 144),
    ("traces.csv", 204, 132),
    ("shell", 354, 92),
]

TAB_CENTERS = {
    label: (x + width / 2, 114)
    for label, x, width in TAB_LAYOUT
}


def tab_click_pulse(progress: float, center: float) -> float:
    distance = abs(progress - center)
    if distance > 0.024:
        return 0.0
    return 1 - distance / 0.024


def cursor_state(progress: float) -> tuple[float, float, str | None, float, list[tuple[float, float]], bool]:
    garden = TAB_CENTERS["garden_log.md"]
    traces = TAB_CENTERS["traces.csv"]
    shell = TAB_CENTERS["shell"]

    if progress < 0.18:
        return garden[0], garden[1] + 9, "garden_log.md", 0.0, [], True
    if progress < 0.24:
        t = smoothstep((progress - 0.18) / 0.06)
        x = lerp(garden[0], traces[0], t)
        y = lerp(garden[1] + 9, traces[1] + 9, t)
        trail = [(lerp(garden[0], x, step), lerp(garden[1] + 9, y, step)) for step in (0.35, 0.62, 0.82)]
        return x, y, "traces.csv", tab_click_pulse(progress, 0.235), trail, True
    if progress < 0.40:
        return traces[0], traces[1] + 9, "traces.csv", tab_click_pulse(progress, 0.245), [], True
    if progress < 0.46:
        t = smoothstep((progress - 0.40) / 0.06)
        x = lerp(traces[0], shell[0], t)
        y = lerp(traces[1] + 9, shell[1] + 9, t)
        trail = [(lerp(traces[0], x, step), lerp(traces[1] + 9, y, step)) for step in (0.35, 0.62, 0.82)]
        return x, y, "shell", tab_click_pulse(progress, 0.455), trail, True
    if progress < 0.54:
        return shell[0], shell[1] + 9, "shell", tab_click_pulse(progress, 0.465), [], True
    return shell[0], shell[1] + 9, None, 0.0, [], False


def draw_cursor(draw: ImageDraw.ImageDraw, x: float, y: float, trail: list[tuple[float, float]], visible: bool) -> None:
    if not visible:
        return
    for index, (tx, ty) in enumerate(trail):
        radius = 4 + index
        color = mix(BG, GREEN, 0.22 + index * 0.1)
        draw.ellipse((tx - radius, ty - radius, tx + radius, ty + radius), fill=color)

    points = [
        (x, y),
        (x + 2, y + 25),
        (x + 9, y + 19),
        (x + 15, y + 31),
        (x + 21, y + 28),
        (x + 15, y + 17),
        (x + 27, y + 17),
    ]
    shadow = [(px + 2, py + 3) for px, py in points]
    draw.polygon(shadow, fill=(196, 218, 201))
    draw.polygon(points, fill=PANEL, outline=GREEN_DARK)
    draw.line((x, y, x + 2, y + 25), fill=GREEN_DARK, width=2)


def draw_tabs(draw: ImageDraw.ImageDraw, active: str, hover: str | None, click: float) -> None:
    for label, x, width in TAB_LAYOUT:
        is_active = label == active
        is_hover = label == hover
        click_amount = click if is_hover else 0.0
        if is_hover:
            draw.rounded_rectangle((x + 3, 100, x + width + 3, 136), radius=8, fill=(207, 232, 211))
        if click_amount > 0:
            spread = int(7 + 12 * click_amount)
            ripple = mix(GREEN, BG, click_amount)
            draw.rounded_rectangle(
                (x - spread, 96 - spread, x + width + spread, 132 + spread),
                radius=8 + spread,
                outline=ripple,
                width=2,
            )
        fill = PANEL if is_active else (223, 241, 227)
        if is_hover:
            fill = mix(fill, PANEL, 0.72)
        if click_amount > 0:
            fill = mix(fill, (224, 246, 229), 0.7)
        outline = GREEN if is_active or click_amount > 0 else (188, 221, 195)
        rounded(draw, (x, 96, x + width, 132), fill, outline, width=2, radius=8)
        draw_text(draw, (x + 14, 106), label, GREEN_DARK if is_active or is_hover else MUTED, SMALL_BOLD)


def draw_step_badge(draw: ImageDraw.ImageDraw, step: str) -> None:
    current = int(step.split(".", 1)[0])
    rounded(draw, (808, 30, 1038, 84), PANEL, LINE, width=2, radius=8)
    draw_text(draw, (830, 42), step, GREEN_DARK, BODY_BOLD)
    for index in range(5):
        cx = 832 + index * 18
        fill = GREEN if index + 1 <= current else (210, 231, 215)
        draw.ellipse((cx, 68, cx + 8, 76), fill=fill, outline=(139, 188, 149))


def draw_title(draw: ImageDraw.ImageDraw, subtitle: str, active: str, step: str, progress: float) -> None:
    draw_text(draw, (42, 28), "Garden actions, running locally", INK, TITLE)
    draw_text(draw, (44, 70), subtitle, MUTED, BODY)
    cursor_x, cursor_y, hover, click, trail, cursor_visible = cursor_state(progress)
    draw_step_badge(draw, step)
    draw_tabs(draw, active, hover, click)
    draw_cursor(draw, cursor_x, cursor_y, trail, cursor_visible)


def draw_plant(draw: ImageDraw.ImageDraw, x: int, y: int, scale: float = 1.0) -> None:
    s = scale
    draw.rounded_rectangle((x + int(52 * s), y + int(74 * s), x + int(58 * s), y + int(158 * s)), radius=3, fill=GREEN)
    leaves = [
        (x + int(8 * s), y + int(42 * s), x + int(82 * s), y + int(76 * s), (82, 173, 97)),
        (x + int(48 * s), y + int(24 * s), x + int(126 * s), y + int(60 * s), (101, 190, 112)),
        (x + int(20 * s), y + int(82 * s), x + int(88 * s), y + int(116 * s), (47, 141, 84)),
        (x + int(66 * s), y + int(84 * s), x + int(136 * s), y + int(120 * s), (122, 203, 115)),
    ]
    for box in leaves:
        draw.ellipse(box[:4], fill=box[4], outline=(39, 114, 73), width=2)
    draw.rounded_rectangle((x + int(20 * s), y + int(158 * s), x + int(124 * s), y + int(178 * s)), radius=6, fill=CORAL, outline=(154, 61, 51), width=2)
    draw.rounded_rectangle((x + int(32 * s), y + int(174 * s), x + int(112 * s), y + int(232 * s)), radius=8, fill=(217, 84, 69), outline=(154, 61, 51), width=2)
    draw.rounded_rectangle((x + int(43 * s), y + int(196 * s), x + int(101 * s), y + int(204 * s)), radius=4, fill=YELLOW)


def draw_journal(draw: ImageDraw.ImageDraw, log_lines: list[str], reveal: float) -> None:
    panel(draw, (44, 154, 452, 548))
    draw.rectangle((44, 154, 452, 204), fill=(227, 246, 231), outline=LINE, width=2)
    draw_text(draw, (68, 170), "garden_log.md", INK, H2)
    visible = max(1, int(len(log_lines) * reveal))
    y = 228
    for index, line in enumerate(log_lines[:visible]):
        color = INK if not line.startswith("-") else MUTED
        prefix = "- " if line.startswith("-") else ""
        text = prefix + line.replace("- ", "")
        draw_text(draw, (72, y), crop_text(text, 38), color, BODY if not line.startswith("-") else SMALL_BOLD)
        y += 28 if line.startswith("-") else 34
    if reveal > 0.55:
        chip(draw, (310, 270), "helped", (224, 245, 214), (113, 170, 98), GREEN_DARK)
    if reveal > 0.72:
        chip(draw, (318, 370), "hurt", RED_SOFT, CORAL, GREEN_DARK)


def chip(draw: ImageDraw.ImageDraw, xy: tuple[int, int], label: str, fill, outline, ink=INK) -> None:
    x, y = xy
    rounded(draw, (x, y, x + 104, y + 34), fill, outline, width=2, radius=8)
    draw_text(draw, (x + 16, y + 8), label, ink, SMALL_BOLD)


def draw_csv(draw: ImageDraw.ImageDraw, rows: list[dict[str, str]], reveal: float, x=492, y=154, w=558, h=394) -> None:
    panel(draw, (x, y, x + w, y + h))
    draw.rectangle((x, y, x + w, y + 50), fill=(215, 240, 231), outline=LINE, width=2)
    draw_text(draw, (x + 22, y + 16), "traces.csv", INK, H2)
    headers = (
        [
            ("moisture", 120),
            ("water gal", 112),
            ("paleness", 108),
            ("next action", 112),
        ]
        if w <= 520
        else [
            ("moisture", 126),
            ("water gal", 132),
            ("paleness", 128),
            ("next action", 132),
        ]
    )
    cx = x + 22
    for label, width in headers:
        rounded(draw, (cx, y + 76, cx + width - 10, y + 108), PANEL_SOFT, (189, 220, 195), width=1, radius=6)
        draw_text(draw, (cx + 8, y + 86), crop_text(label, 15), MUTED, MONO_TINY)
        cx += width

    visible = max(0, min(len(rows), int(len(rows) * reveal + 0.7)))
    colors = {
        "water": BLUE_SOFT,
        "do_nothing": GRAY_SOFT,
        "fertilize": YELLOW_SOFT,
        "repot": CORAL_SOFT,
    }
    for index, row in enumerate(rows[:visible]):
        row_y = y + 124 + index * 50
        draw.rounded_rectangle((x + 20, row_y, x + w - 20, row_y + 38), radius=6, fill=PANEL if index % 2 == 0 else PANEL_SOFT)
        values = [
            row["soil_moisture_pct"],
            row["water_last_7_days_gallons"],
            row["leaf_paleness_score"],
            row["next_action"],
        ]
        cx = x + 30
        for col, value in enumerate(values):
            if col == 3:
                rounded(draw, (cx - 6, row_y + 6, cx + 104, row_y + 32), colors.get(value, GRAY_SOFT), (168, 188, 175), width=1, radius=6)
                draw_text(draw, (cx + 4, row_y + 12), value, INK, MONO_TINY)
            else:
                draw_text(draw, (cx, row_y + 10), value, INK, MONO_SMALL)
            cx += headers[col][1]

    if reveal > 0.85:
        draw_text(draw, (x + 22, y + h - 42), "percent signs and gallons stay in the example data", MUTED, SMALL_BOLD)


def draw_terminal(
    draw: ImageDraw.ImageDraw,
    lines: list[str],
    reveal: float,
    x: int,
    y: int,
    w: int,
    h: int,
    title: str = "local shell",
    highlight: str | None = None,
) -> None:
    panel(draw, (x, y, x + w, y + h), fill=GREEN_DARK, outline=(11, 33, 24))
    draw.rectangle((x, y, x + w, y + 40), fill=(34, 81, 61), outline=(11, 33, 24), width=2)
    for offset, color in [(18, CORAL), (36, YELLOW), (54, (98, 195, 112))]:
        draw.ellipse((x + offset, y + 15, x + offset + 10, y + 25), fill=color)
    draw_text(draw, (x + 80, y + 12), title, (218, 246, 230), SMALL)

    if reveal <= 0:
        drawn_lines = []
    elif reveal > 0.9:
        drawn_lines = lines
    else:
        visible_count = max(1, int(len(lines) * reveal + 0.75))
        drawn_lines = lines[: min(visible_count, len(lines))]

    cy = y + 62
    max_line_chars = max(28, int((w - 48) / 9.2))
    for raw_line in drawn_lines:
        wrapped = textwrap.wrap(raw_line, width=max_line_chars, subsequent_indent="  ") or [""]
        for line in wrapped:
            line_color = (235, 255, 240)
            if line.startswith("$"):
                line_color = (201, 245, 218)
            if highlight and highlight in line:
                line_color = YELLOW
            if line.startswith("action:"):
                line_color = (122, 221, 153)
            draw_text(draw, (x + 24, cy), line, line_color, MONO_TERM)
            cy += 24
            if cy > y + h - 28:
                return


def draw_run_result(draw: ImageDraw.ImageDraw, run_lines: list[str], reveal: float) -> None:
    draw_terminal(draw, run_lines, reveal, 520, 186, 516, 202, "run today.json", highlight="Soil Moisture")
    if reveal > 0.62:
        panel(draw, (584, 424, 972, 548))
        draw_text(draw, (612, 450), "action: water", GREEN, load_font(26, True))
        draw_text(draw, (614, 490), "Soil Moisture <= 18%\nWater used last 7 days <= 0.2", MUTED, BODY_BOLD, spacing=6)


def draw_frame(
    progress: float,
    log_lines: list[str],
    rows: list[dict[str, str]],
    build_lines: list[str],
    inspect_lines: list[str],
    run_lines: list[str],
) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    if progress < 0.24:
        local = ease(progress / 0.24)
        draw_title(draw, "Open the notes someone kept while caring for the plants.", "garden_log.md", "1. Journal", progress)
        draw_journal(draw, log_lines, local)
        panel(draw, (620, 170, 1006, 444))
        draw_text(draw, (650, 200), "what the notes capture", GREEN_DARK, H2)
        for index, label in enumerate(["measurements", "what was tried", "outcome"]):
            y = 252 + index * 42
            rounded(draw, (650, y, 850, y + 30), PANEL_SOFT, LINE, width=1, radius=8)
            draw_text(draw, (668, y + 7), label, GREEN_DARK, SMALL_BOLD)
        draw_text(draw, (650, 394), "Reviewed examples become rows.", GREEN, BODY_BOLD)
        draw_plant(draw, 874, 260, 0.44)
    elif progress < 0.46:
        local = ease((progress - 0.24) / 0.22)
        draw_title(draw, "Load the reviewed rows that LogicPearl will build from.", "traces.csv", "2. CSV", progress)
        draw_journal(draw, log_lines, 1.0)
        draw_csv(draw, rows, local)
        draw.line((462, 352, 486, 352), fill=GREEN, width=4)
        draw.polygon([(486, 352), (476, 344), (476, 360)], fill=GREEN)
    elif progress < 0.68:
        local = ease((progress - 0.46) / 0.22)
        draw_title(draw, "Run the build. No feature dictionary step, no pile of flags.", "shell", "3. Build", progress)
        draw_csv(draw, rows, 1.0, x=44, y=154, w=500, h=394)
        draw_terminal(draw, build_lines, local, 590, 154, 460, 318, "logicpearl build", highlight="Training parity")
        if local > 0.65:
            panel(draw, (604, 494, 1022, 558))
            draw_text(draw, (630, 512), "readable labels generated by default", GREEN_DARK, BODY_BOLD)
            draw_text(draw, (630, 538), "before rule text is created", MUTED, SMALL_BOLD)
    elif progress < 0.84:
        local = ease((progress - 0.68) / 0.16)
        draw_title(draw, "Inspect the learned rules before wiring anything into an app.", "shell", "4. Inspect", progress)
        draw_terminal(draw, inspect_lines, local, 64, 154, 972, 394, "logicpearl inspect", highlight="18%")
    else:
        local = ease((progress - 0.84) / 0.16)
        draw_title(draw, "Run today.json and watch the local answer come back.", "shell", "5. Run", progress)
        panel(draw, (66, 172, 454, 548))
        draw_text(draw, (92, 198), "today.json", INK, H2)
        today_lines = [
            '{',
            '  \"soil_moisture_pct\": \"14%\",',
            '  \"days_since_watered\": 6,',
            '  \"water_last_7_days_gallons\":',
            '    0.12,',
            '  \"leaf_paleness_score\": 1,',
            '  \"root_crowding_score\": 1',
            '}',
        ]
        draw_text(draw, (92, 244), "\n".join(today_lines), MUTED, MONO_TINY, spacing=8)
        draw_run_result(draw, run_lines, local)

    draw_text(draw, (64, 574), "examples/demos/garden_actions", MUTED, SMALL_BOLD)
    draw_text(draw, (802, 574), "same input -> same local output", GREEN_DARK, SMALL_BOLD)
    return img


def quantize_with_global_palette(frames: list[Image.Image]) -> list[Image.Image]:
    if not frames:
        return []
    try:
        resample = Image.Resampling.BILINEAR
    except AttributeError:
        resample = Image.BILINEAR

    thumb_w, thumb_h = 220, 124
    columns = 10
    rows = (len(frames) + columns - 1) // columns
    palette_source = Image.new("RGB", (thumb_w * columns, thumb_h * rows), BG)
    for index, frame in enumerate(frames):
        thumb = frame.resize((thumb_w, thumb_h), resample)
        palette_source.paste(thumb, ((index % columns) * thumb_w, (index // columns) * thumb_h))

    try:
        method = Image.Quantize.MEDIANCUT
        dither = Image.Dither.NONE
    except AttributeError:
        method = Image.MEDIANCUT
        dither = Image.NONE
    palette = palette_source.quantize(colors=160, method=method)
    return [frame.quantize(palette=palette, dither=dither) for frame in frames]


def write_high_quality_apng(frames: list[Image.Image], durations: list[int]) -> None:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        frames[0].save(
            APNG_OUT,
            format="PNG",
            save_all=True,
            append_images=frames[1:],
            duration=durations,
            loop=0,
            disposal=2,
            optimize=False,
        )
        return

    base_ms = min(durations)
    fps = Fraction(1000, base_ms)
    with tempfile.TemporaryDirectory(prefix="garden-demo-apng-") as tmp:
        tmp_dir = Path(tmp)
        frame_index = 0
        for frame, duration in zip(frames, durations):
            repeats = max(1, round(duration / base_ms))
            for _ in range(repeats):
                frame.save(tmp_dir / f"frame-{frame_index:04d}.png")
                frame_index += 1
        subprocess.run(
            [
                ffmpeg,
                "-y",
                "-v",
                "error",
                "-framerate",
                f"{fps.numerator}/{fps.denominator}",
                "-i",
                str(tmp_dir / "frame-%04d.png"),
                "-plays",
                "0",
                "-f",
                "apng",
                str(APNG_OUT),
            ],
            check=True,
        )


def main() -> None:
    log_lines, rows, _today = read_demo_data()
    build_lines, inspect_lines, run_lines = run_cli_output()

    rgb_frames = []
    durations = []
    count = FRAME_COUNT
    for index in range(count):
        progress = index / (count - 1)
        rgb_frames.append(draw_frame(progress, log_lines, rows, build_lines, inspect_lines, run_lines))
        durations.append(FRAME_MS)
    durations[-1] = FINAL_HOLD_MS
    GIF_OUT.parent.mkdir(parents=True, exist_ok=True)

    gif_frames = quantize_with_global_palette(rgb_frames)
    gif_frames[0].save(
        GIF_OUT,
        save_all=True,
        append_images=gif_frames[1:],
        duration=durations,
        loop=0,
        optimize=False,
        disposal=2,
    )

    write_high_quality_apng(rgb_frames, durations)

    print(GIF_OUT)
    print(APNG_OUT)


if __name__ == "__main__":
    main()
