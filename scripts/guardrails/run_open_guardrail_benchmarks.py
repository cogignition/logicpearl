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

BENCHMARKS = [
    {
        "id": "jailbreakbench",
        "profile": "jailbreakbench",
        "path": Path("/Users/missingno/Documents/LogicPearl/datasets/public/jailbreakbench/jbb_behaviors.json"),
    },
    {
        "id": "promptshield",
        "profile": "promptshield",
        "path": Path("/Users/missingno/Documents/LogicPearl/datasets/public/promptshield/promptshield.json"),
    },
    {
        "id": "rogue-security-prompt-injections",
        "profile": "rogue-security-prompt-injections",
        "path": Path("/Users/missingno/Documents/LogicPearl/datasets/public/rogue_security/prompt_injections_benchmark.json"),
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
    return parser.parse_args()


def run_benchmark(bundle_dir: Path, benchmark: dict[str, Any], output_dir: Path, use_installed_cli: bool) -> dict[str, Any]:
    benchmark_output_dir = output_dir / benchmark["id"]
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "guardrails" / "evaluate_guardrail_bundle.py"),
        "--bundle-dir",
        str(bundle_dir),
        "--raw-benchmark",
        str(benchmark["path"]),
        "--profile",
        benchmark["profile"],
        "--output-dir",
        str(benchmark_output_dir),
    ]
    if use_installed_cli:
        cmd.append("--use-installed-cli")
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    report_path = benchmark_output_dir / "evaluation_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "benchmark": benchmark["id"],
        "profile": benchmark["profile"],
        "path": str(benchmark["path"]),
        "report_path": str(report_path),
        "summary": report["summary"],
    }


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
        path = benchmark["path"]
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
            run_benchmark(bundle_dir, benchmark, output_dir, args.use_installed_cli)
        )

    payload = {"benchmarks": aggregate, "skipped": skipped}
    (output_dir / "summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
