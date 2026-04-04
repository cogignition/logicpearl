from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .gate import CompiledGate
from .rules import Condition


@dataclass(frozen=True)
class WasmCompilationResult:
    rust_source: str
    wasm_path: Path | None = None
    wasm_size_bytes: int | None = None


def _sanitize_param_name(feature_name: str) -> str:
    name = feature_name.replace(".", "_").replace("__", "_")
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if name and name[0].isdigit():
        name = f"f_{name}"
    return name


def _threshold_to_int(threshold: float) -> str:
    if abs(threshold - round(threshold)) < 0.001:
        return str(int(round(threshold)))
    return str(int(round(threshold * 1000)))


def _condition_to_rust(condition: Condition, param_map: dict[str, str]) -> str:
    param = param_map[condition.feature]
    threshold = _threshold_to_int(condition.threshold)
    if condition.operator == ">":
        return f"{param} > {threshold}"
    if condition.operator == "<=":
        return f"{param} <= {threshold}"
    return "true"


def generate_rust(gate: CompiledGate) -> str:
    all_features: set[str] = set()
    for rule in gate.rules:
        for condition in rule.conditions:
            all_features.add(condition.feature)

    sorted_features = sorted(all_features)
    param_map = {feature: _sanitize_param_name(feature) for feature in sorted_features}
    params = ",\n    ".join(f"{param_map[feature]}: i32" for feature in sorted_features)

    checks: list[str] = []
    for index, rule in enumerate(gate.rules):
        condition_exprs = [_condition_to_rust(condition, param_map) for condition in rule.conditions]
        check_expr = " && ".join(condition_exprs) if condition_exprs else "true"
        invariant_name = gate.invariant_names[index] if index < len(gate.invariant_names) else "unknown"
        checks.append(f"    // Rule {index}: {invariant_name}")
        checks.append(f"    if {check_expr} {{")
        checks.append(f"        failed |= 1 << {index};")
        checks.append("    }")

    checks_str = "\n".join(checks)

    return f"""#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {{ loop {{}} }}

#[no_mangle]
pub extern "C" fn evaluate(
    {params}
) -> i32 {{
    let mut failed: i32 = 0;
{checks_str}
    failed
}}
"""


def compile_gate_to_wasm(
    gate: CompiledGate,
    *,
    output_dir: str | Path | None = None,
    name: str = "gate",
) -> WasmCompilationResult:
    rust_source = generate_rust(gate)

    if output_dir is None:
        return WasmCompilationResult(rust_source=rust_source)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    rust_path = output_path / f"{name}.rs"
    wasm_path = output_path / f"{name}.wasm"
    rust_path.write_text(rust_source)

    try:
        result = subprocess.run(
            [
                "rustc",
                "--target",
                "wasm32-unknown-unknown",
                "-O",
                "--crate-type",
                "cdylib",
                "-o",
                str(wasm_path),
                str(rust_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and wasm_path.exists():
            return WasmCompilationResult(
                rust_source=rust_source,
                wasm_path=wasm_path,
                wasm_size_bytes=wasm_path.stat().st_size,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return WasmCompilationResult(rust_source=rust_source)
