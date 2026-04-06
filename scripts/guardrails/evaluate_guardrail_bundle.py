#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
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
        help="Use `logicpearl` from PATH instead of `cargo run -p logicpearl --`.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=0,
        help="Deterministically evaluate only up to this many benchmark cases, stratified by expected route. Defaults to all cases.",
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
        "logicpearl",
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


def deterministic_bucket(key: str) -> int:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return int(digest[:16], 16)


def sample_cases(cases: list[dict[str, Any]], sample_size: int) -> list[dict[str, Any]]:
    if sample_size <= 0 or len(cases) <= sample_size:
        return cases

    by_route: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        by_route.setdefault(case["expected_route"], []).append(case)

    selected: list[dict[str, Any]] = []
    route_items = sorted(by_route.items())
    remaining_budget = sample_size
    remaining_groups = len(route_items)
    for route, route_cases in route_items:
        route_cases = sorted(route_cases, key=lambda case: deterministic_bucket(case["id"]))
        quota = max(1, remaining_budget // remaining_groups)
        quota = min(quota, len(route_cases))
        selected.extend(route_cases[:quota])
        remaining_budget -= quota
        remaining_groups -= 1

    if len(selected) < sample_size:
        selected_ids = {case["id"] for case in selected}
        leftovers = [
            case
            for case in sorted(cases, key=lambda case: deterministic_bucket(case["id"]))
            if case["id"] not in selected_ids
        ]
        selected.extend(leftovers[: sample_size - len(selected)])

    return sorted(selected, key=lambda case: deterministic_bucket(case["id"]))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def normalize_features_for_gate(gate: dict[str, Any], features: dict[str, Any]) -> dict[str, Any]:
    feature_types = {
        feature["id"]: feature["type"]
        for feature in gate["input_schema"]["features"]
    }
    normalized = dict(features)
    for feature_id, feature_type in feature_types.items():
        if feature_id not in normalized:
            continue
        value = normalized[feature_id]
        if isinstance(value, bool):
            if feature_type == "int":
                normalized[feature_id] = 1 if value else 0
            elif feature_type == "float":
                normalized[feature_id] = 1.0 if value else 0.0
    return normalized


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


def fired_rules_from_bitmask(gate: dict[str, Any], bitmask: int) -> list[dict[str, Any]]:
    fired: list[dict[str, Any]] = []
    for rule in gate["rules"]:
        if bitmask & (1 << int(rule["bit"])):
            fired.append(rule)
    return fired


def evaluate_with_compiled_pearl(compiled_pearl: Path, feature_rows: list[dict[str, Any]]) -> list[int]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(feature_rows, handle)
        handle.write("\n")
        payload_path = Path(handle.name)
    try:
        completed = subprocess.run(
            [str(compiled_pearl), str(payload_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        payload_path.unlink(missing_ok=True)

    stdout = completed.stdout.strip()
    if not stdout:
        raise RuntimeError(f"compiled pearl produced no stdout: {compiled_pearl}")
    parsed = json.loads(stdout)
    if isinstance(parsed, int):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(item, int) for item in parsed):
        return parsed
    raise RuntimeError(f"compiled pearl returned unexpected payload: {stdout}")


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
    compiled_pearl = bundle_dir / "freeze" / "guardrails_pre_pint_combined.pearl"
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

    original_cases = read_jsonl(cases_path)
    sampled_cases = sample_cases(original_cases, args.sample_size)
    sampled = len(sampled_cases) != len(original_cases)
    if sampled:
        sampled_path = output_dir / "cases.sampled.jsonl"
        write_jsonl(sampled_path, sampled_cases)
        cases_path = sampled_path

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
    feature_rows = [normalize_features_for_gate(combined_pearl, row["features"]) for row in observed_cases]
    compiled_used = compiled_pearl.exists()
    if compiled_used:
        bitmasks = evaluate_with_compiled_pearl(compiled_pearl, feature_rows)
    else:
        bitmasks = [evaluate_gate(combined_pearl, features)[0] for features in feature_rows]

    total_cases = 0
    matched_cases = 0
    attack_cases = 0
    benign_cases = 0
    caught_attacks = 0
    benign_passes = 0
    false_positives = 0
    route_distribution: Counter[str] = Counter()
    case_results: list[dict[str, Any]] = []

    for observed, bitmask in zip(observed_cases, bitmasks):
        case = cases[observed["id"]]
        fired_rules = fired_rules_from_bitmask(combined_pearl, bitmask)
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
        "compiled_pearl": {
            "path": str(compiled_pearl),
            "used": compiled_used,
        },
        "summary": {
            "total_cases": total_cases,
            "sampled": sampled,
            "sample_size": args.sample_size if sampled else total_cases,
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
