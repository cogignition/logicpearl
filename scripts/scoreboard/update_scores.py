#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "SCORES.json"
DEFAULT_GUARDRAIL_BUNDLE = Path(
    os.environ.get(
        "LOGICPEARL_GUARDRAIL_BUNDLE_DIR",
        "/private/tmp/guardrails_bundle",
    )
)

GETTING_STARTED_CSV = REPO_ROOT / "examples" / "getting_started" / "decision_traces.csv"
GETTING_STARTED_INPUT = REPO_ROOT / "examples" / "getting_started" / "new_input.json"
DEMO_CASES: tuple[tuple[str, Path], ...] = (
    ("access_control", REPO_ROOT / "examples" / "demos" / "access_control" / "traces.csv"),
    ("content_moderation", REPO_ROOT / "examples" / "demos" / "content_moderation" / "traces.csv"),
    ("loan_approval", REPO_ROOT / "examples" / "demos" / "loan_approval" / "traces.csv"),
)
GUARDRAIL_BASELINE = REPO_ROOT / "scripts" / "guardrails" / "open_guardrail_regression_baseline.sample200.json"
GUARDRAIL_BASELINE_DIR = GUARDRAIL_BASELINE.parent


def parse_args() -> tuple[Path, bool]:
    output = DEFAULT_OUTPUT
    pretty = False
    args = sys.argv[1:]
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--output":
            index += 1
            output = Path(args[index]).resolve()
        elif arg == "--pretty":
            pretty = True
        else:
            raise SystemExit(f"unknown argument: {arg}")
        index += 1
    return output, pretty


def run(cmd: list[str], cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode == 0:
        return completed

    def tail(text: str, limit: int = 12_000) -> str:
        if len(text) <= limit:
            return text
        return f"<truncated {len(text) - limit} bytes>\n{text[-limit:]}"

    details = [
        f"command failed with exit code {completed.returncode}: {shlex.join(cmd)}"
    ]
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if stdout:
        details.extend(["", "stdout:", tail(stdout)])
    if stderr:
        details.extend(["", "stderr:", tail(stderr)])
    raise RuntimeError("\n".join(details))


def run_json(cmd: list[str], cwd: Path = REPO_ROOT) -> Any:
    completed = run(cmd, cwd=cwd)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError(f"command returned no stdout: {' '.join(cmd)}")
    return json.loads(payload)


def logicpearl_cmd(*args: str) -> list[str]:
    return [
        "cargo",
        "run",
        "--manifest-path",
        str(REPO_ROOT / "Cargo.toml"),
        "-p",
        "logicpearl",
        "--",
        *args,
    ]


def git_output(*args: str) -> str:
    return run(["git", "-C", str(REPO_ROOT), *args]).stdout.strip()


def author_identity() -> dict[str, str]:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "var", "GIT_AUTHOR_IDENT"],
        check=False,
        capture_output=True,
        text=True,
    )
    raw = completed.stdout.strip() if completed.returncode == 0 else ""
    if "<" in raw and ">" in raw:
        name = raw.split("<", 1)[0].strip()
        email = raw.split("<", 1)[1].split(">", 1)[0].strip()
        return {"name": name, "email": email}

    github_actor = os.environ.get("GITHUB_ACTOR", "").strip()
    if github_actor:
        return {
            "name": github_actor,
            "email": f"{github_actor}@users.noreply.github.com",
        }

    name = git_output("config", "--get", "user.name") or "unknown"
    email = git_output("config", "--get", "user.email") or "unknown@local"
    return {"name": name, "email": email}


def get_revision() -> dict[str, Any]:
    head = git_output("rev-parse", "HEAD")
    return {
        "head": head,
        "dirty": git_output("status", "--short") != "",
    }


def metric(
    value: float,
    goal: str,
    weight: float,
    suite: str,
    *,
    target_goal: str | None = None,
) -> dict[str, Any]:
    payload = {
        "value": value,
        "goal": goal,
        "weight": weight,
        "suite": suite,
    }
    if target_goal:
        payload["target_goal"] = target_goal
    return payload


def stable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        if str(resolved).startswith(("/tmp/", "/private/tmp/")):
            return f"<tmp>/{resolved.name}"
        return resolved.name or str(resolved)


def canonical_target_goal(goal: str) -> str:
    return goal.strip().lower().replace("_", "-")


def read_bundle_manifest(bundle_dir: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / "bundle_manifest.json"
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def guardrail_target_goal(bundle_dir: Path) -> str:
    manifest = read_bundle_manifest(bundle_dir)
    return canonical_target_goal(str(manifest.get("observer_target_goal", "parity-first"))) or "parity-first"


def guardrail_baseline_for_goal(sample_size: int, target_goal: str) -> Path:
    lane_path = GUARDRAIL_BASELINE_DIR / (
        f"open_guardrail_regression_baseline.sample{sample_size}.{canonical_target_goal(target_goal)}.json"
    )
    if lane_path.exists():
        return lane_path
    return GUARDRAIL_BASELINE


def summarize_build(build: dict[str, Any]) -> dict[str, Any]:
    return {
        "gate_id": build["gate_id"],
        "rows": build["rows"],
        "label_column": build["label_column"],
        "rules_discovered": build["rules_discovered"],
        "residual_rules_discovered": build["residual_rules_discovered"],
        "refined_rules_applied": build["refined_rules_applied"],
        "pinned_rules_applied": build["pinned_rules_applied"],
        "selected_features": build["selected_features"],
        "training_parity": build["training_parity"],
        "native_binary_emitted": bool(build["output_files"]["native_binary"]),
        "wasm_emitted": bool(build["output_files"]["wasm_module"]),
    }


def build_case(csv_path: Path, output_dir: Path) -> dict[str, Any]:
    return run_json(
        logicpearl_cmd(
            "build",
            str(csv_path),
            "--output-dir",
            str(output_dir),
            "--compile",
            "--json",
        )
    )


def run_binary(binary_path: str, input_path: Path) -> str:
    completed = run([binary_path, str(input_path)])
    return completed.stdout.strip()


def measure_getting_started() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="logicpearl_scores_getting_started_") as temp_dir:
        output_dir = Path(temp_dir) / "artifact"
        build = build_case(GETTING_STARTED_CSV, output_dir)
        actual_bitmask = run_binary(build["output_files"]["native_binary"], GETTING_STARTED_INPUT)
        suite = {
            "status": "ok",
            "csv": stable_path(GETTING_STARTED_CSV),
            "input": stable_path(GETTING_STARTED_INPUT),
            "build": summarize_build(build),
            "expected_bitmask": "0",
            "actual_bitmask": actual_bitmask,
            "artifact_emitted": True,
            "run_passed": actual_bitmask == "0",
        }
        metrics = {
            "getting_started.training_parity": metric(
                float(build["training_parity"]), "max", 100.0, "getting_started"
            ),
            "getting_started.run_passed": metric(
                1.0 if suite["run_passed"] else 0.0, "max", 25.0, "getting_started"
            ),
        }
        return suite, metrics


def measure_demos() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    cases: dict[str, Any] = {}
    metrics: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="logicpearl_scores_demos_") as temp_dir:
        base_dir = Path(temp_dir)
        for demo_id, csv_path in DEMO_CASES:
            build = build_case(csv_path, base_dir / demo_id)
            cases[demo_id] = {
                "status": "ok",
                "csv": stable_path(csv_path),
                "build": summarize_build(build),
            }
            metrics[f"demos.{demo_id}.training_parity"] = metric(
                float(build["training_parity"]), "max", 100.0, "demos"
            )
            metrics[f"demos.{demo_id}.rules_discovered"] = metric(
                float(build["rules_discovered"]), "max", 5.0, "demos"
            )
    return {"status": "ok", "cases": cases}, metrics


def measure_guardrails() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not DEFAULT_GUARDRAIL_BUNDLE.exists():
        return {
            "status": "unavailable",
            "reason": f"guardrail bundle not found: {DEFAULT_GUARDRAIL_BUNDLE}",
            "bundle_dir": str(DEFAULT_GUARDRAIL_BUNDLE),
        }, {}

    target_goal = guardrail_target_goal(DEFAULT_GUARDRAIL_BUNDLE)
    baseline_path = guardrail_baseline_for_goal(200, target_goal)

    with tempfile.TemporaryDirectory(prefix="logicpearl_scores_guardrails_") as temp_dir:
        output_dir = Path(temp_dir) / "guardrails"
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "guardrails" / "run_open_guardrail_benchmarks.py"),
            "--bundle-dir",
            str(DEFAULT_GUARDRAIL_BUNDLE),
            "--input-split",
            "final_holdout",
            "--sample-size",
            "200",
            "--target-goal",
            target_goal,
            "--baseline",
            "",
            "--output-dir",
            str(output_dir),
        ]
        completed = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        summary_path = output_dir / "summary.json"
        if completed.returncode != 0 and not summary_path.exists():
            reason = completed.stderr.strip() or completed.stdout.strip() or (
                f"guardrail sampled benchmark failed with exit code {completed.returncode}"
            )
            return {
                "status": "unavailable",
                "reason": reason,
                "bundle_dir": stable_path(DEFAULT_GUARDRAIL_BUNDLE),
                "baseline": stable_path(baseline_path),
                "target_goal": target_goal,
            }, {}
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        benchmarks = {
            item["benchmark"]: item["summary"] for item in summary["benchmarks"]
        }
        metrics: dict[str, dict[str, Any]] = {}
        for benchmark_id, benchmark_summary in benchmarks.items():
            prefix = f"guardrails.{benchmark_id}"
            metrics[f"{prefix}.exact_match_rate"] = metric(
                float(benchmark_summary["exact_match_rate"]),
                "max",
                100.0,
                "guardrails",
                target_goal=target_goal,
            )
            metrics[f"{prefix}.attack_catch_rate"] = metric(
                float(benchmark_summary["attack_catch_rate"]),
                "max",
                125.0,
                "guardrails",
                target_goal=target_goal,
            )
            metrics[f"{prefix}.benign_pass_rate"] = metric(
                float(benchmark_summary["benign_pass_rate"]),
                "max",
                60.0,
                "guardrails",
                target_goal=target_goal,
            )
            metrics[f"{prefix}.false_positive_rate"] = metric(
                float(benchmark_summary["false_positive_rate"]),
                "min",
                80.0,
                "guardrails",
                target_goal=target_goal,
            )
        lane = {
            "status": "ok",
            "bundle_dir": stable_path(DEFAULT_GUARDRAIL_BUNDLE),
            "baseline": stable_path(baseline_path),
            "input_split": summary["input_split"],
            "sample_size": summary["sample_size"],
            "target_goal": target_goal,
            "benchmarks": benchmarks,
        }
        suite = {
            **lane,
            "default_target_goal": target_goal,
            "by_target_goal": {target_goal: lane},
        }
        return suite, metrics


def main() -> int:
    output_path, pretty = parse_args()

    suites: dict[str, Any] = {}
    metrics: dict[str, dict[str, Any]] = {}

    getting_started_suite, getting_started_metrics = measure_getting_started()
    suites["getting_started"] = getting_started_suite
    metrics.update(getting_started_metrics)

    demos_suite, demos_metrics = measure_demos()
    suites["demos"] = demos_suite
    metrics.update(demos_metrics)

    guardrails_suite, guardrails_metrics = measure_guardrails()
    suites["guardrails_open_sample200"] = guardrails_suite
    metrics.update(guardrails_metrics)

    payload = {
        "schema_version": "1.0",
        "generated_by": "scripts/scoreboard/update_scores.py",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": author_identity(),
        "revision": get_revision(),
        "suites": suites,
        "metrics": metrics,
        "summary": {
            "suite_count": len(suites),
            "metric_count": len(metrics),
            "available_suites": sorted(
                suite_id
                for suite_id, suite in suites.items()
                if suite.get("status") == "ok"
            ),
        },
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
