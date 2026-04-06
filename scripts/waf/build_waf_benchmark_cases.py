#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = ["cargo", "run", "--manifest-path", str(REPO_ROOT / "Cargo.toml"), "-p", "logicpearl", "--"]


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)


def default_datasets_root() -> Path:
    env = os.environ.get("LOGICPEARL_DATASETS")
    if env:
        return Path(env)
    return (REPO_ROOT.parent / "datasets" / "public").resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build mixed WAF benchmark cases from staged public datasets.")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--datasets-root", type=Path, default=default_datasets_root())
    parser.add_argument("--csic-root", type=Path)
    parser.add_argument("--modsecurity-root", type=Path)
    parser.add_argument("--dev-fraction", type=float, default=0.8)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    adapted_dir = output_dir / "adapted"
    adapted_dir.mkdir(parents=True, exist_ok=True)

    datasets_root = args.datasets_root.resolve()
    csic_root = (args.csic_root or datasets_root / "waf" / "csic-http-2010").resolve()
    modsecurity_root = (args.modsecurity_root or datasets_root / "waf" / "modsecurity-owasp-2025").resolve()

    csic_jsonl = adapted_dir / "csic_http_2010.jsonl"
    modsecurity_jsonl = adapted_dir / "modsecurity_owasp_2025.jsonl"
    merged_jsonl = output_dir / "waf_full.jsonl"
    dev_jsonl = output_dir / "dev.jsonl"
    final_holdout_jsonl = output_dir / "final_holdout.jsonl"

    run(CLI + [
        "benchmark", "adapt", str(csic_root),
        "--profile", "csic-http-2010",
        "--requested-tool", "http",
        "--requested-action", "allow_or_block",
        "--scope", "edge",
        "--output", str(csic_jsonl),
        "--json",
    ])
    run(CLI + [
        "benchmark", "adapt", str(modsecurity_root),
        "--profile", "modsecurity-owasp-2025",
        "--requested-tool", "http",
        "--requested-action", "allow_or_block",
        "--scope", "edge",
        "--output", str(modsecurity_jsonl),
        "--json",
    ])
    run(CLI + [
        "benchmark", "merge-cases",
        str(csic_jsonl),
        str(modsecurity_jsonl),
        "--output", str(merged_jsonl),
        "--json",
    ])
    run(CLI + [
        "benchmark", "split-cases",
        str(merged_jsonl),
        "--train-output", str(dev_jsonl),
        "--dev-output", str(final_holdout_jsonl),
        "--train-fraction", str(args.dev_fraction),
        "--json",
    ])

    summary = {
        "datasets_root": str(datasets_root),
        "csic_root": str(csic_root),
        "modsecurity_root": str(modsecurity_root),
        "outputs": {
            "csic": str(csic_jsonl),
            "modsecurity": str(modsecurity_jsonl),
            "merged": str(merged_jsonl),
            "dev": str(dev_jsonl),
            "final_holdout": str(final_holdout_jsonl),
        },
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
