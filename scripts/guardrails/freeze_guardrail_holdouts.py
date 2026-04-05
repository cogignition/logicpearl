#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
WORKSPACE_ROOT = REPO_ROOT.parent
DEFAULT_DATASETS_ROOT = WORKSPACE_ROOT / "datasets" / "public"


@dataclass(frozen=True)
class DatasetSpec:
    dataset_id: str
    profile: str
    raw_path: Path


DATASETS: tuple[DatasetSpec, ...] = (
    DatasetSpec("squad_train", "squad", DEFAULT_DATASETS_ROOT / "squad" / "train-v2.0.json"),
    DatasetSpec("alert", "alert", DEFAULT_DATASETS_ROOT / "alert" / "ALERT.jsonl"),
    DatasetSpec("alert_adv", "alert", DEFAULT_DATASETS_ROOT / "alert" / "ALERT_Adv.jsonl"),
    DatasetSpec("salad_base_set", "salad-base-set", DEFAULT_DATASETS_ROOT / "salad" / "base_set.json"),
    DatasetSpec(
        "salad_attack_enhanced_set",
        "salad-attack-enhanced-set",
        DEFAULT_DATASETS_ROOT / "salad" / "attack_enhanced_set.json",
    ),
    DatasetSpec(
        "chatgpt_jailbreak_prompts",
        "chatgpt-jailbreak-prompts",
        DEFAULT_DATASETS_ROOT / "chatgpt_jailbreak" / "chatgpt_jailbreak_prompts.json",
    ),
    DatasetSpec("vigil", "vigil", DEFAULT_DATASETS_ROOT / "vigil" / "vigil.json"),
    DatasetSpec("noeti_toxicqa", "noeti-toxicqa", DEFAULT_DATASETS_ROOT / "noeti_toxicqa" / "noeti_toxicqa.json"),
    DatasetSpec(
        "openagentsafety_s26",
        "openagentsafety-s26",
        DEFAULT_DATASETS_ROOT / "openagentsafety" / "openagentsafety_s26.json",
    ),
    DatasetSpec("mcpmark", "mcpmark", DEFAULT_DATASETS_ROOT / "mcpmark" / "mcpmark_tasks.json"),
    DatasetSpec("safearena_safe", "safearena-safe", DEFAULT_DATASETS_ROOT / "safearena" / "safe.json"),
    DatasetSpec("safearena_harm", "safearena-harm", DEFAULT_DATASETS_ROOT / "safearena" / "harm.json"),
    DatasetSpec("jailbreakbench", "jailbreakbench", DEFAULT_DATASETS_ROOT / "jailbreakbench" / "jbb_behaviors.json"),
    DatasetSpec("promptshield", "promptshield", DEFAULT_DATASETS_ROOT / "promptshield" / "promptshield.json"),
    DatasetSpec(
        "rogue_security_prompt_injections",
        "rogue-security-prompt-injections",
        DEFAULT_DATASETS_ROOT / "rogue_security" / "prompt_injections_benchmark.json",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Freeze deterministic dev and final holdout splits for all staged LogicPearl guardrail datasets."
    )
    parser.add_argument(
        "--datasets",
        nargs="*",
        default=[spec.dataset_id for spec in DATASETS],
        help="Subset of dataset ids to split. Defaults to all known guardrail datasets.",
    )
    parser.add_argument(
        "--dev-fraction",
        type=float,
        default=0.9,
        help="Fraction of rows to place in the development split. Final holdout receives the remainder.",
    )
    parser.add_argument(
        "--datasets-root",
        default=str(DEFAULT_DATASETS_ROOT),
        help="Root directory containing the staged public datasets.",
    )
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
    print("+", " ".join(cmd), file=sys.stderr, flush=True)
    completed = subprocess.run(cmd, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError(f"command returned no stdout: {' '.join(cmd)}")
    return json.loads(payload)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def split_dir_for(datasets_root: Path, spec: DatasetSpec) -> Path:
    dataset_parent = (datasets_root / spec.raw_path.relative_to(DEFAULT_DATASETS_ROOT)).parent
    return dataset_parent / "logicpearl_splits" / spec.dataset_id


def main() -> int:
    args = parse_args()
    datasets_root = Path(args.datasets_root).expanduser().resolve()
    cli = logicpearl_base_command(args.use_installed_cli)
    selected_ids = set(args.datasets)
    if not any(spec.dataset_id in selected_ids for spec in DATASETS):
        raise SystemExit("no matching datasets selected")

    manifests: list[dict[str, Any]] = []
    for spec in DATASETS:
        if spec.dataset_id not in selected_ids:
            continue

        raw_path = (datasets_root / spec.raw_path.relative_to(DEFAULT_DATASETS_ROOT)).resolve()
        if not raw_path.exists():
            raise SystemExit(f"missing raw dataset input: {raw_path}")

        splits_dir = split_dir_for(datasets_root, spec)
        splits_dir.mkdir(parents=True, exist_ok=True)
        all_cases = splits_dir / "all_cases.jsonl"
        dev_cases = splits_dir / "dev.jsonl"
        final_holdout_cases = splits_dir / "final_holdout.jsonl"

        adapt_report = run_json(
            [
                *cli,
                "benchmark",
                "adapt",
                str(raw_path),
                "--profile",
                spec.profile,
                "--output",
                str(all_cases),
                "--json",
            ]
        )
        split_report = run_json(
            [
                *cli,
                "benchmark",
                "split-cases",
                str(all_cases),
                "--train-output",
                str(dev_cases),
                "--dev-output",
                str(final_holdout_cases),
                "--train-fraction",
                str(args.dev_fraction),
                "--json",
            ]
        )

        manifest = {
            "dataset_id": spec.dataset_id,
            "profile": spec.profile,
            "raw_path": str(raw_path),
            "all_cases": str(all_cases),
            "dev_cases": str(dev_cases),
            "final_holdout_cases": str(final_holdout_cases),
            "adapt_report": adapt_report,
            "split_report": split_report,
        }
        write_json(splits_dir / "split_manifest.json", manifest)
        manifests.append(manifest)

    payload = {"dev_fraction": args.dev_fraction, "datasets": manifests}
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
