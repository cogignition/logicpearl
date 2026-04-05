#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_BUNDLE_DIR = Path("/tmp/guardrails_pre_pint_bundle")
DEFAULT_BASELINE_PATH = REPO_ROOT / "scripts" / "guardrails" / "open_guardrail_regression_baseline.sample200.json"

BENCHMARKS = [
    {
        "id": "jailbreakbench",
        "profile": "jailbreakbench",
        "path": Path("/Users/missingno/Documents/LogicPearl/datasets/public/jailbreakbench/jbb_behaviors.json"),
        "splits_dir": Path("/Users/missingno/Documents/LogicPearl/datasets/public/jailbreakbench/logicpearl_splits/jailbreakbench"),
    },
    {
        "id": "promptshield",
        "profile": "promptshield",
        "path": Path("/Users/missingno/Documents/LogicPearl/datasets/public/promptshield/promptshield.json"),
        "splits_dir": Path("/Users/missingno/Documents/LogicPearl/datasets/public/promptshield/logicpearl_splits/promptshield"),
    },
    {
        "id": "rogue-security-prompt-injections",
        "profile": "rogue-security-prompt-injections",
        "path": Path("/Users/missingno/Documents/LogicPearl/datasets/public/rogue_security/prompt_injections_benchmark.json"),
        "splits_dir": Path("/Users/missingno/Documents/LogicPearl/datasets/public/rogue_security/logicpearl_splits/rogue_security_prompt_injections"),
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the frozen pre-PINT guardrail bundle against open post-freeze evaluation benchmarks."
    )
    parser.add_argument(
        "--bundle-dir",
        default=str(DEFAULT_BUNDLE_DIR),
        help="Frozen bundle directory created by build_pre_pint_guardrail_bundle.py.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write per-benchmark and aggregate outputs into.",
    )
    parser.add_argument(
        "--benchmarks",
        nargs="*",
        default=[item["id"] for item in BENCHMARKS],
        help="Subset of benchmark ids to run. Defaults to all known open benchmarks.",
    )
    parser.add_argument(
        "--use-installed-cli",
        action="store_true",
        help="Forward --use-installed-cli to evaluate_guardrail_bundle.py.",
    )
    parser.add_argument(
        "--fail-on-missing",
        action="store_true",
        help="Fail instead of skipping when a benchmark dataset file is missing.",
    )
    parser.add_argument(
        "--input-split",
        choices=("dev", "final_holdout", "raw"),
        default="dev",
        help="Which frozen external split to evaluate. Defaults to the dev split; use raw only for legacy full-dataset runs.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=0,
        help="Deterministically evaluate only up to this many cases per benchmark. Defaults to the full selected split.",
    )
    parser.add_argument(
        "--baseline",
        default="",
        help="Optional JSON file with minimum acceptable benchmark metrics for regression checks.",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.0,
        help="Allowed metric slack when comparing against a regression baseline.",
    )
    return parser.parse_args()


def benchmark_input_for_split(benchmark: dict[str, Any], input_split: str) -> tuple[Path, str]:
    if input_split == "raw":
        return Path(benchmark["path"]), "raw"
    split_filename = "dev.jsonl" if input_split == "dev" else "final_holdout.jsonl"
    return Path(benchmark["splits_dir"]) / split_filename, "cases-jsonl"


def run_benchmark(
    bundle_dir: Path,
    benchmark: dict[str, Any],
    output_dir: Path,
    use_installed_cli: bool,
    input_split: str,
    sample_size: int,
) -> dict[str, Any]:
    benchmark_output_dir = output_dir / benchmark["id"]
    benchmark_input, input_format = benchmark_input_for_split(benchmark, input_split)
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "guardrails" / "evaluate_guardrail_bundle.py"),
        "--bundle-dir",
        str(bundle_dir),
        "--raw-benchmark",
        str(benchmark_input),
        "--profile",
        benchmark["profile"],
        "--input-format",
        input_format,
        "--output-dir",
        str(benchmark_output_dir),
    ]
    if sample_size > 0:
        cmd.extend(["--sample-size", str(sample_size)])
    if use_installed_cli:
        cmd.append("--use-installed-cli")
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    report_path = benchmark_output_dir / "evaluation_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "benchmark": benchmark["id"],
        "profile": benchmark["profile"],
        "path": str(benchmark_input),
        "input_split": input_split,
        "report_path": str(report_path),
        "summary": report["summary"],
    }


def load_baseline(path_text: str) -> dict[str, Any]:
    if not path_text:
        return {}
    path = Path(path_text).resolve()
    if not path.exists():
        raise SystemExit(f"baseline file does not exist: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def compare_against_baseline(
    aggregate: list[dict[str, Any]],
    baseline: dict[str, Any],
    tolerance: float,
) -> list[str]:
    failures: list[str] = []
    expected = baseline.get("benchmarks", {})
    for item in aggregate:
        benchmark_id = item["benchmark"]
        if benchmark_id not in expected:
            continue
        summary = item["summary"]
        baseline_summary = expected[benchmark_id]
        for metric in ("exact_match_rate", "attack_catch_rate", "benign_pass_rate"):
            if summary[metric] + tolerance < baseline_summary[metric]:
                failures.append(
                    f"{benchmark_id} {metric} regressed: {summary[metric]:.6f} < {baseline_summary[metric]:.6f}"
                )
        if summary["false_positive_rate"] - tolerance > baseline_summary["false_positive_rate"]:
            failures.append(
                f"{benchmark_id} false_positive_rate regressed: {summary['false_positive_rate']:.6f} > {baseline_summary['false_positive_rate']:.6f}"
            )
    return failures


def main() -> int:
    args = parse_args()
    bundle_dir = Path(args.bundle_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    selected = {item["id"]: item for item in BENCHMARKS if item["id"] in set(args.benchmarks)}
    if not selected:
        raise SystemExit("no matching benchmarks selected")

    aggregate: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for benchmark_id in args.benchmarks:
        benchmark = selected.get(benchmark_id)
        if benchmark is None:
            continue
        path, _ = benchmark_input_for_split(benchmark, args.input_split)
        if not path.exists():
            entry = {
                "benchmark": benchmark["id"],
                "path": str(path),
                "status": "missing",
            }
            if args.fail_on_missing:
                raise SystemExit(json.dumps(entry))
            skipped.append(entry)
            continue
        aggregate.append(
            run_benchmark(
                bundle_dir,
                benchmark,
                output_dir,
                args.use_installed_cli,
                args.input_split,
                args.sample_size,
            )
        )

    payload = {
        "input_split": args.input_split,
        "sample_size": args.sample_size,
        "benchmarks": aggregate,
        "skipped": skipped,
    }
    (output_dir / "summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))

    default_baseline = (
        str(DEFAULT_BASELINE_PATH)
        if args.sample_size > 0 and DEFAULT_BASELINE_PATH.exists()
        else ""
    )
    baseline_path = args.baseline or default_baseline
    baseline = load_baseline(baseline_path) if baseline_path else {}
    failures = compare_against_baseline(aggregate, baseline, args.tolerance) if baseline else []
    if failures:
        raise SystemExit("\n".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
