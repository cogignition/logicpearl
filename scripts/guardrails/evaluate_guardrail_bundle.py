#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
TRACE_PROJECTION_CONFIG = REPO_ROOT / "benchmarks" / "guardrails" / "prep" / "trace_projection.guardrails_v1.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a frozen pre-PINT guardrail bundle against a raw benchmark file such as PINT."
    )
    parser.add_argument("--bundle-dir", required=True, help="Frozen bundle directory created by build_pre_pint_guardrail_bundle.py")
    parser.add_argument("--raw-benchmark", required=True, help="Raw benchmark input file, for example a PINT YAML export.")
    parser.add_argument(
        "--profile",
        default="pint",
        help="Benchmark adapter profile for the raw benchmark input. Defaults to `pint`.",
    )
    parser.add_argument(
        "--input-format",
        choices=("raw", "cases-jsonl"),
        default="raw",
        help="Interpret the benchmark input as raw corpus data or as already-adapted benchmark-case JSONL.",
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write evaluation outputs into.")
    parser.add_argument(
        "--use-installed-cli",
        action="store_true",
        help="Use `logicpearl` from PATH instead of `cargo run -p logicpearl-cli --`.",
    )
    return parser.parse_args()


def logicpearl_base_command(use_installed_cli: bool) -> list[str]:
    if use_installed_cli:
        return ["logicpearl"]
    return [
        "cargo",
        "run",
        "--manifest-path",
        str(REPO_ROOT / "Cargo.toml"),
        "-p",
        "logicpearl-cli",
        "--",
    ]


def run_json(cmd: list[str]) -> dict[str, Any]:
    print("+", " ".join(cmd), flush=True)
    completed = subprocess.run(cmd, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError(f"command returned no stdout: {' '.join(cmd)}")
    return json.loads(payload)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def values_equal(left: Any, right: Any) -> bool:
    try:
        left_number = float(left)
        right_number = float(right)
    except (TypeError, ValueError):
        return left == right
    return abs(left_number - right_number) < 1e-12


def evaluate_expression(expression: dict[str, Any], features: dict[str, Any]) -> bool:
    if "feature" in expression:
        feature_value = features[expression["feature"]]
        op = expression["op"]
        right = expression["value"]
        if op == "==":
            return values_equal(feature_value, right)
        if op == "!=":
            return not values_equal(feature_value, right)
        if op == ">":
            return float(feature_value) > float(right)
        if op == ">=":
            return float(feature_value) >= float(right)
        if op == "<":
            return float(feature_value) < float(right)
        if op == "<=":
            return float(feature_value) <= float(right)
        if op == "in":
            return any(values_equal(feature_value, item) for item in right)
        if op == "not_in":
            return not any(values_equal(feature_value, item) for item in right)
        raise ValueError(f"unsupported comparison operator: {op}")
    if "all" in expression:
        return all(evaluate_expression(child, features) for child in expression["all"])
    if "any" in expression:
        return any(evaluate_expression(child, features) for child in expression["any"])
    if "not" in expression:
        return not evaluate_expression(expression["not"], features)
    raise ValueError(f"unsupported expression shape: {expression}")


def evaluate_gate(gate: dict[str, Any], features: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    bitmask = 0
    fired_rules: list[dict[str, Any]] = []
    for rule in gate["rules"]:
        if evaluate_expression(rule["deny_when"], features):
            bitmask |= 1 << int(rule["bit"])
            fired_rules.append(rule)
    return bitmask, fired_rules


def derive_route(route_policy: dict[str, Any], fired_rules: list[dict[str, Any]]) -> str:
    labels = {rule.get("label") for rule in fired_rules}
    for route_rule in route_policy["rules"]:
        if route_rule["label"] in labels:
            return route_rule["route_status"]
    return route_policy["default_route"]


def ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def main() -> int:
    args = parse_args()
    bundle_dir = Path(args.bundle_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cli = logicpearl_base_command(args.use_installed_cli)

    observer_artifact = bundle_dir / "freeze" / "guardrails_v1.observer.json"
    combined_pearl = read_json(bundle_dir / "freeze" / "guardrails_pre_pint_combined.pearl.ir.json")
    route_policy = read_json(bundle_dir / "freeze" / "route_policy.json")

    cases_path = output_dir / "cases.jsonl"
    benchmark_input = str(Path(args.raw_benchmark).resolve())
    if args.input_format == "raw":
        adapt_report = run_json(
            [
                *cli,
                "benchmark",
                "adapt",
                benchmark_input,
                "--profile",
                args.profile,
                "--output",
                str(cases_path),
                "--json",
            ]
        )
    else:
        Path(cases_path).write_text(Path(benchmark_input).read_text())
        adapt_report = {
            "mode": "pass_through_cases_jsonl",
            "input": benchmark_input,
            "output": str(cases_path),
        }

    observed_path = output_dir / "observed.jsonl"
    observe_report = run_json(
        [
            *cli,
            "benchmark",
            "observe",
            str(cases_path),
            "--observer-artifact",
            str(observer_artifact),
            "--output",
            str(observed_path),
            "--json",
        ]
    )

    traces_dir = output_dir / "traces"
    emit_report = run_json(
        [
            *cli,
            "benchmark",
            "emit-traces",
            str(observed_path),
            "--config",
            str(TRACE_PROJECTION_CONFIG),
            "--output-dir",
            str(traces_dir),
            "--json",
        ]
    )

    cases = {row["id"]: row for row in read_jsonl(cases_path)}
    observed_cases = read_jsonl(observed_path)

    total_cases = 0
    matched_cases = 0
    attack_cases = 0
    benign_cases = 0
    caught_attacks = 0
    benign_passes = 0
    false_positives = 0
    route_distribution: Counter[str] = Counter()
    case_results: list[dict[str, Any]] = []

    for observed in observed_cases:
        case = cases[observed["id"]]
        features = observed["features"]
        bitmask, fired_rules = evaluate_gate(combined_pearl, features)
        route_status = derive_route(route_policy, fired_rules)
        actual_route = "allow" if route_status == "allow" else route_policy["collapse_non_allow_to"]
        expected_route = case["expected_route"]
        matched = actual_route == expected_route

        total_cases += 1
        matched_cases += int(matched)
        route_distribution[route_status] += 1
        if expected_route == "deny":
            attack_cases += 1
            caught_attacks += int(actual_route == "deny")
        else:
            benign_cases += 1
            benign_passes += int(actual_route == "allow")
            false_positives += int(actual_route != "allow")

        case_results.append(
            {
                "id": observed["id"],
                "category": case.get("category"),
                "expected_route": expected_route,
                "actual_route": actual_route,
                "route_status": route_status,
                "matched": matched,
                "bitmask": bitmask,
                "fired_rules": [
                    {
                        "id": rule["id"],
                        "label": rule.get("label"),
                        "message": rule.get("message"),
                        "counterfactual_hint": rule.get("counterfactual_hint"),
                    }
                    for rule in fired_rules
                ],
            }
        )

    report = {
        "bundle_id": read_json(bundle_dir / "bundle_manifest.json")["bundle_id"],
        "benchmark_profile": args.profile,
        "input_format": args.input_format,
        "raw_benchmark": benchmark_input,
        "adapt_report": adapt_report,
        "observe_report": observe_report,
        "emit_report": emit_report,
        "summary": {
            "total_cases": total_cases,
            "matched_cases": matched_cases,
            "exact_match_rate": ratio(matched_cases, total_cases),
            "attack_cases": attack_cases,
            "benign_cases": benign_cases,
            "attack_catch_rate": ratio(caught_attacks, attack_cases),
            "benign_pass_rate": ratio(benign_passes, benign_cases),
            "false_positive_rate": ratio(false_positives, benign_cases),
            "route_distribution": dict(sorted(route_distribution.items())),
        },
        "cases": case_results,
    }
    write_json(output_dir / "evaluation_report.json", report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
