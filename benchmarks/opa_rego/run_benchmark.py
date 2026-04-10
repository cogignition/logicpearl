#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from common import (
    BENCHMARK_DIR,
    OPA_ALLOW_QUERY,
    OUTPUT_DIR,
    POLICY_PATH,
    generate_raw_requests,
    observe_authz_request,
    write_decision_traces_csv,
)

REQUEST_COUNT = 1000
SEED = 42


def main() -> None:
    ensure_opa_available()
    reset_output_dir()

    raw_requests = generate_raw_requests(REQUEST_COUNT, seed=SEED)
    features = [observe_authz_request(item) for item in raw_requests]
    allowed_rows = [evaluate_opa_allow(item) for item in raw_requests]

    traces_csv = OUTPUT_DIR / "decision_traces.csv"
    write_decision_traces_csv(features, allowed_rows, traces_csv)

    sample_raw_path = OUTPUT_DIR / "sample_raw_input.json"
    sample_feature_path = OUTPUT_DIR / "sample_feature_input.json"
    sample_raw_path.write_text(json.dumps(raw_requests[0], indent=2))
    sample_feature_path.write_text(json.dumps(features[0], indent=2))

    artifact_dir = OUTPUT_DIR / "artifact_bundle"
    build_result = run_logicpearl(
        "build",
        str(traces_csv),
        "--output-dir",
        str(artifact_dir),
        "--json",
    )
    inspect_result = run_logicpearl("inspect", str(artifact_dir), "--json")
    parity_result = run_logicpearl(
        "conformance",
        "runtime-parity",
        str(artifact_dir),
        str(traces_csv),
        "--label-column",
        "allowed",
        "--json",
    )
    sample_bitmask = run_logicpearl("run", str(artifact_dir), str(sample_feature_path), capture_json=False)
    sample_allow = sample_bitmask == "0"

    inspect_path = OUTPUT_DIR / "inspect.json"
    inspect_path.write_text(json.dumps(inspect_result, indent=2))
    parity_path = OUTPUT_DIR / "runtime_parity.json"
    parity_path.write_text(json.dumps(parity_result, indent=2))
    sample_run_path = OUTPUT_DIR / "sample_run.json"
    sample_run_path.write_text(
        json.dumps(
            {
                "raw_input_path": str(sample_raw_path),
                "feature_input_path": str(sample_feature_path),
                "opa_allow": allowed_rows[0],
                "pearl_allow": sample_allow,
                "bitmask": sample_bitmask,
            },
            indent=2,
        )
    )

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "policy_path": str(POLICY_PATH),
        "opa_query": OPA_ALLOW_QUERY,
        "request_count": REQUEST_COUNT,
        "seed": SEED,
        "demo_kind": "opa_rego_parity_example",
        "decision_traces_csv": str(traces_csv),
        "artifact_dir": str(artifact_dir),
        "build": build_result,
        "inspect": inspect_result,
        "runtime_parity": parity_result,
        "sample_run": {
            "raw_input_path": str(sample_raw_path),
            "feature_input_path": str(sample_feature_path),
            "opa_allow": allowed_rows[0],
            "pearl_allow": sample_allow,
            "bitmask": sample_bitmask,
        },
    }
    summary_path = OUTPUT_DIR / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    print("=" * 72)
    print("LogicPearl OPA/Rego Parity Example")
    print("=" * 72)
    print(f"  Policy: {POLICY_PATH}")
    print(f"  Requests: {len(raw_requests)}")
    print(f"  Decision traces: {traces_csv}")
    print(f"  Artifact bundle: {artifact_dir}")
    print(
        "  Training parity: "
        f"{build_result['training_parity'] * 100.0:.1f}%"
    )
    print(
        "  Runtime parity: "
        f"{parity_result['parity'] * 100.0:.1f}%"
    )
    print(f"  Sample OPA allow: {allowed_rows[0]}")
    print(f"  Sample pearl allow: {sample_allow} (bitmask {sample_bitmask})")
    print(f"  Summary: {summary_path}")


def reset_output_dir() -> None:
    shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def ensure_opa_available() -> None:
    try:
        subprocess.run(
            ["opa", "version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            "opa CLI is required for benchmarks/opa_rego/run_benchmark.py.\n"
            "Install OPA and ensure `opa` is available on PATH."
        ) from exc


def evaluate_opa_allow(raw_input: dict) -> bool:
    with NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(raw_input, handle)
        input_path = Path(handle.name)
    try:
        result = subprocess.run(
            [
                "opa",
                "eval",
                "--format=json",
                "-d",
                str(POLICY_PATH),
                "-i",
                str(input_path),
                OPA_ALLOW_QUERY,
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=BENCHMARK_DIR,
        )
    finally:
        input_path.unlink(missing_ok=True)

    payload = json.loads(result.stdout)
    return bool(payload["result"][0]["expressions"][0]["value"])


def run_logicpearl(*args: str, capture_json: bool = True):
    repo_root = BENCHMARK_DIR.parent.parent
    command = [
        "cargo",
        "run",
        "--manifest-path",
        str(repo_root / "Cargo.toml"),
        "-p",
        "logicpearl",
        "--",
        *args,
    ]
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    stdout = result.stdout.strip()
    if capture_json:
        return json.loads(stdout)
    return stdout


if __name__ == "__main__":
    main()
