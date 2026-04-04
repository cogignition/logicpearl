#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from common import OUTPUT_DIR, POLICY_PATH, build_demo_rules, condition_count, generate_raw_requests, observe_authz_request
from logicpearl.domains.opa import evaluate_rego_query, infer_rego_policy_metadata
from logicpearl.engine import compile_gate, compile_gate_to_wasm, serialize_rules_to_gate_ir
from logicpearl.ir import dump_gate_ir


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    raw_requests = generate_raw_requests(1000, seed=42)
    features = [observe_authz_request(item) for item in raw_requests]
    rules = build_demo_rules()
    pearl = compile_gate(rules)

    print("=" * 72)
    print("LogicPearl OPA/Rego Benchmark")
    print("=" * 72)
    metadata = infer_rego_policy_metadata(POLICY_PATH)
    print(f"  Policy: {POLICY_PATH}")
    print(f"  Package: {metadata.package}")
    print(f"  Requests: {len(raw_requests)}")
    print(f"  Pearl rules: {len(pearl.rules)}")
    print(f"  Pearl conditions: {condition_count(rules)}")

    opa_allow = [
        bool(evaluate_rego_query(POLICY_PATH, query=f"data.{metadata.package}.allow", input_data=item))
        for item in raw_requests
    ]
    pearl_allow = [pearl.is_allowed(item) for item in features]

    agreement = sum(1 for left, right in zip(opa_allow, pearl_allow) if left == right)
    accuracy = agreement / len(raw_requests) * 100
    print(f"  Parity: {agreement:,}/{len(raw_requests):,} = {accuracy:.1f}%")

    opa_bench = benchmark_opa(POLICY_PATH, raw_requests[0], metadata.package)
    pearl_latency = benchmark_pearl(pearl, features[0])
    print(f"  OPA median latency: {opa_bench['median_ns']:,} ns")
    print(f"  Pearl median latency: {pearl_latency['median_ns']:,} ns")

    pearl_json = {
        "generated_at": datetime.now(UTC).isoformat(),
        "policy_path": str(POLICY_PATH),
        "n_rules": len(pearl.rules),
        "n_conditions": condition_count(rules),
        "rules": [
            {
                "rule_id": rule.rule_id,
                "source": rule.source.value,
                "verification_status": rule.verification_status.value,
                "conditions": [
                    {
                        "feature": condition.feature,
                        "operator": condition.operator,
                        "threshold": condition.threshold,
                    }
                    for condition in rule.conditions
                ],
            }
            for rule in rules
        ],
        "parity_accuracy": accuracy,
    }
    (OUTPUT_DIR / "pearl.json").write_text(json.dumps(pearl_json, indent=2))

    gate_ir = serialize_rules_to_gate_ir(
        rules,
        gate_id="opa_rbac_demo",
        feature_sample=features[0],
        generator="logicpearl.benchmarks.opa_rego",
        generator_version="0.1.0",
        correctness_scope=f"OPA parity benchmark against {metadata.package}.allow",
        verification_summary={"heuristic_unverified": len(rules)},
    )
    pearl_ir_path = OUTPUT_DIR / "pearl.ir.json"
    dump_gate_ir(gate_ir, pearl_ir_path)

    runtime_accuracy = evaluate_runtime_accuracy(pearl_ir_path, features, opa_allow)
    print(f"  Runtime parity: {runtime_accuracy:.1f}%")

    wasm_result = compile_gate_to_wasm(pearl, output_dir=OUTPUT_DIR, name="opa_rbac_pearl")
    wasm_size = wasm_result.wasm_size_bytes
    if wasm_result.wasm_path:
        print(f"  WASM: {wasm_result.wasm_path.name} ({wasm_size} bytes)")

    audit = {
        "generated_at": datetime.now(UTC).isoformat(),
        "policy": {
            "path": str(POLICY_PATH),
            "package": metadata.package,
            "rule_names": metadata.rule_names,
        },
        "dataset": {
            "n_requests": len(raw_requests),
            "seed": 42,
        },
        "parity_accuracy": accuracy,
        "runtime_accuracy": runtime_accuracy,
        "pearl": {
            "n_rules": len(pearl.rules),
            "n_conditions": condition_count(rules),
            "wasm_size_bytes": wasm_size,
        },
        "opa_benchmark": opa_bench,
        "pearl_benchmark": pearl_latency,
    }
    (OUTPUT_DIR / "pearl_audit.json").write_text(json.dumps(audit, indent=2))
    print(f"  Outputs: {OUTPUT_DIR}")


def benchmark_opa(policy_path: Path, sample_input: dict, package: str) -> dict[str, int]:
    input_path = OUTPUT_DIR / "sample_input.json"
    input_path.write_text(json.dumps(sample_input, indent=2))
    try:
        result = subprocess.run(
            [
                "opa",
                "bench",
                "-d",
                str(policy_path),
                "-i",
                str(input_path),
                f"data.{package}.allow",
                "--count",
                "5",
                "--benchmem",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=policy_path.parent,
        )
    finally:
        input_path.unlink(missing_ok=True)

    samples = {
        "ns_op": [],
        "bytes_op": [],
        "allocs_op": [],
        "median_ns": [],
        "p95_ns": [],
        "p99_ns": [],
    }
    for line in result.stdout.strip().splitlines():
        if "|" not in line:
            continue
        parts = [part.strip() for part in line.split("|") if part.strip()]
        if len(parts) != 2:
            continue
        label, raw_value = parts
        try:
            value = int(raw_value)
        except ValueError:
            continue
        if label == "ns/op":
            samples["ns_op"].append(value)
        elif label == "B/op":
            samples["bytes_op"].append(value)
        elif label == "allocs/op":
            samples["allocs_op"].append(value)
        elif label == "histogram_timer_rego_query_eval_ns_median":
            samples["median_ns"].append(value)
        elif label == "histogram_timer_rego_query_eval_ns_95%":
            samples["p95_ns"].append(value)
        elif label == "histogram_timer_rego_query_eval_ns_99%":
            samples["p99_ns"].append(value)
    return {key: _median_int(values) for key, values in samples.items()}


def _median_int(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def benchmark_pearl(pearl, feature_sample: dict[str, float]) -> dict[str, int]:
    timings = []
    for _ in range(100000):
        started = time.perf_counter()
        pearl.evaluate(feature_sample)
        timings.append((time.perf_counter() - started) * 1e9)
    timings.sort()
    return {
        "mean_ns": round(sum(timings) / len(timings)),
        "median_ns": round(timings[len(timings) // 2]),
        "p95_ns": round(timings[int(len(timings) * 0.95)]),
        "p99_ns": round(timings[int(len(timings) * 0.99)]),
        "bytes_op": 0,
        "allocs_op": 0,
    }


def evaluate_runtime_accuracy(pearl_ir_path: Path, features: list[dict[str, float]], opa_allow: list[bool]) -> float:
    runtime_binary = ensure_runtime_binary()
    inputs_path = OUTPUT_DIR / "runtime_inputs.json"
    inputs_path.write_text(json.dumps(features, indent=2))
    try:
        proc = subprocess.run(
            [str(runtime_binary), str(pearl_ir_path), str(inputs_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        inputs_path.unlink(missing_ok=True)
    bitmasks = json.loads(proc.stdout.strip().splitlines()[-1])
    agreement = 0
    for bitmask, allowed in zip(bitmasks, opa_allow):
        if (int(bitmask) == 0) == allowed:
            agreement += 1
    return agreement / len(opa_allow) * 100


def ensure_runtime_binary() -> Path:
    runtime_dir = Path(__file__).resolve().parents[2] / "runtime"
    binary_path = runtime_dir / "target" / "debug" / "pearl-runtime"
    if binary_path.exists():
        return binary_path
    subprocess.run(["cargo", "build"], cwd=runtime_dir, check=True, capture_output=True, text=True)
    return binary_path


if __name__ == "__main__":
    main()
