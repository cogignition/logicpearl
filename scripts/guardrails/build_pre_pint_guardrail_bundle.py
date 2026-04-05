#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
WORKSPACE_ROOT = REPO_ROOT.parent
DEFAULT_DATASETS_ROOT = WORKSPACE_ROOT / "datasets" / "public"
TRACE_PROJECTION_CONFIG = REPO_ROOT / "benchmarks" / "guardrails" / "prep" / "trace_projection.guardrails_v1.json"


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


ROUTE_RULES: tuple[dict[str, str], ...] = (
    {
        "target": "target_tool_use",
        "route_status": "deny_tool_use",
        "label": "deny_tool_use",
        "message": "Blocked potentially unsafe or unauthorized tool use.",
        "counterfactual_hint": "Remove the requested tool action or constrain it to an explicitly allowed scope.",
    },
    {
        "target": "target_instruction_boundary",
        "route_status": "deny_untrusted_instruction",
        "label": "deny_untrusted_instruction",
        "message": "Blocked prompt-injection or instruction override behavior.",
        "counterfactual_hint": "Remove the override or system-prompt targeting language and keep the request inside the trusted task.",
    },
    {
        "target": "target_exfiltration",
        "route_status": "deny_exfiltration_risk",
        "label": "deny_exfiltration_risk",
        "message": "Blocked secret or sensitive data exfiltration behavior.",
        "counterfactual_hint": "Remove requests for passwords, credentials, secrets, or out-of-scope sensitive data.",
    },
)

SYNTHESIS_SIGNALS: tuple[str, ...] = (
    "instruction-override",
    "secret-exfiltration",
    "tool-misuse",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a frozen pre-PINT guardrail bundle from the staged public development corpora."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write the frozen bundle into.")
    parser.add_argument(
        "--datasets-root",
        default=str(DEFAULT_DATASETS_ROOT),
        help="Root directory containing the staged public datasets.",
    )
    parser.add_argument(
        "--dev-fraction",
        type=float,
        default=0.9,
        help="Deterministic development fraction for per-dataset dev/final_holdout split generation.",
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
    print("+", " ".join(cmd), flush=True)
    completed = subprocess.run(cmd, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError(f"command returned no stdout: {' '.join(cmd)}")
    return json.loads(payload)


def run_plain(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)


def ensure_exists(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"required dataset input is missing: {path}")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def build_combined_pearl(
    artifact_set_path: Path,
    output_path: Path,
    route_policy_path: Path,
) -> dict[str, Any]:
    artifact_set = read_json(artifact_set_path)
    artifact_dir = artifact_set_path.parent
    feature_ids = artifact_set["features"]
    target_rules = {rule["target"]: rule for rule in ROUTE_RULES}

    combined_features: OrderedDict[str, dict[str, Any]] = OrderedDict()
    combined_rules: list[dict[str, Any]] = []

    for descriptor in artifact_set["binary_targets"]:
        target = descriptor["name"]
        if target not in target_rules:
            continue
        gate = read_json(artifact_dir / descriptor["artifact"])
        for feature in gate["input_schema"]["features"]:
            combined_features.setdefault(feature["id"], feature)
        for gate_rule in gate["rules"]:
            enriched_rule = dict(gate_rule)
            enriched_rule["id"] = f"{target}__{gate_rule['id']}"
            enriched_rule["bit"] = len(combined_rules)
            enriched_rule["label"] = target_rules[target]["label"]
            enriched_rule["message"] = target_rules[target]["message"]
            enriched_rule["counterfactual_hint"] = target_rules[target]["counterfactual_hint"]
            combined_rules.append(enriched_rule)

    ordered_features: list[dict[str, Any]] = []
    for feature_id in feature_ids:
        if feature_id in combined_features:
            ordered_features.append(combined_features[feature_id])
    for feature_id, feature in combined_features.items():
        if feature_id not in feature_ids:
            ordered_features.append(feature)

    combined_gate = {
        "ir_version": "1.0",
        "gate_id": "guardrails_pre_pint_combined",
        "gate_type": "bitmask_gate",
        "input_schema": {"features": ordered_features},
        "rules": combined_rules,
        "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
        "verification": {
            "domain_constraints": None,
            "correctness_scope": "derived by merging frozen pre-PINT target pearls",
            "verification_summary": {"pipeline_unverified": len(combined_rules)},
        },
        "provenance": {
            "generator": "scripts/guardrails/build_pre_pint_guardrail_bundle.py",
            "generator_version": "0.1.0",
            "source_commit": git_output("rev-parse", "HEAD"),
            "created_at": None,
        },
    }
    write_json(output_path, combined_gate)

    route_policy = {
        "route_policy_version": "1.0",
        "policy_id": "guardrails_pre_pint_route_policy_v1",
        "default_route": "allow",
        "rules": list(ROUTE_RULES),
        "collapse_non_allow_to": "deny",
    }
    write_json(route_policy_path, route_policy)
    return combined_gate


def build_artifact_hashes(bundle_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(bundle_dir.rglob("*")):
        if path.is_file():
            hashes[str(path.relative_to(bundle_dir))] = sha256_file(path)
    return hashes


def split_dir_for(datasets_root: Path, spec: DatasetSpec) -> Path:
    dataset_parent = (datasets_root / spec.raw_path.relative_to(DEFAULT_DATASETS_ROOT)).parent
    return dataset_parent / "logicpearl_splits" / spec.dataset_id


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    datasets_root = Path(args.datasets_root).expanduser().resolve()
    cli = logicpearl_base_command(args.use_installed_cli)

    freeze_dir = output_dir / "freeze"
    train_prep_dir = output_dir / "train_prep"
    final_holdout_eval_dir = output_dir / "final_holdout_eval"
    output_dir.mkdir(parents=True, exist_ok=True)
    freeze_dir.mkdir(parents=True, exist_ok=True)
    final_holdout_eval_dir.mkdir(parents=True, exist_ok=True)

    run_json(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "guardrails" / "freeze_guardrail_holdouts.py"),
            "--datasets-root",
            str(datasets_root),
            "--dev-fraction",
            str(args.dev_fraction),
            *(["--use-installed-cli"] if args.use_installed_cli else []),
        ]
    )

    split_manifests: list[dict[str, Any]] = []
    dev_case_paths: list[Path] = []
    final_holdout_paths: list[Path] = []
    for spec in DATASETS:
        raw_path = datasets_root / spec.raw_path.relative_to(DEFAULT_DATASETS_ROOT)
        ensure_exists(raw_path)
        manifest_path = split_dir_for(datasets_root, spec) / "split_manifest.json"
        ensure_exists(manifest_path)
        manifest = read_json(manifest_path)
        split_manifests.append(manifest)
        dev_case_paths.append(Path(manifest["dev_cases"]).resolve())
        final_holdout_paths.append(Path(manifest["final_holdout_cases"]).resolve())

    merged_dev_path = output_dir / "guardrail_dev_full.jsonl"
    merge_report = run_json(
        [
            *cli,
            "benchmark",
            "merge-cases",
            *[str(path) for path in dev_case_paths],
            "--output",
            str(merged_dev_path),
            "--json",
        ]
    )

    merged_final_holdout_path = output_dir / "guardrail_final_holdout_full.jsonl"
    final_holdout_merge_report = run_json(
        [
            *cli,
            "benchmark",
            "merge-cases",
            *[str(path) for path in final_holdout_paths],
            "--output",
            str(merged_final_holdout_path),
            "--json",
        ]
    )

    observer_scaffold_path = freeze_dir / "guardrails_v1.observer.scaffold.json"
    observer_scaffold = run_json(
        [
            *cli,
            "observer",
            "scaffold",
            "--profile",
            "guardrails-v1",
            "--output",
            str(observer_scaffold_path),
            "--json",
        ]
    )

    synthesized_dir = freeze_dir / "observer_synthesis"
    synthesized_dir.mkdir(parents=True, exist_ok=True)
    current_observer_path = observer_scaffold_path
    synthesis_reports: list[dict[str, Any]] = []
    for index, signal in enumerate(SYNTHESIS_SIGNALS, start=1):
        output_path = synthesized_dir / f"{index:02d}_{signal}.observer.json"
        report = run_json(
            [
                *cli,
                "observer",
                "synthesize",
                "--artifact",
                str(current_observer_path),
                "--benchmark-cases",
                str(merged_dev_path),
                "--signal",
                signal,
                "--output",
                str(output_path),
                "--json",
            ]
        )
        report["input_artifact"] = str(current_observer_path)
        synthesis_reports.append(report)
        current_observer_path = output_path

    observer_artifact_path = freeze_dir / "guardrails_v1.observer.json"
    shutil.copyfile(current_observer_path, observer_artifact_path)

    prepare_report = run_json(
        [
            *cli,
            "benchmark",
            "prepare",
            str(merged_dev_path),
            "--observer-artifact",
            str(observer_artifact_path),
            "--config",
            str(TRACE_PROJECTION_CONFIG),
            "--output-dir",
            str(train_prep_dir),
            "--json",
        ]
    )

    final_holdout_observed_path = final_holdout_eval_dir / "observed.jsonl"
    observe_report = run_json(
        [
            *cli,
            "benchmark",
            "observe",
            str(merged_final_holdout_path),
            "--observer-artifact",
            str(observer_artifact_path),
            "--output",
            str(final_holdout_observed_path),
            "--json",
        ]
    )

    final_holdout_traces_dir = final_holdout_eval_dir / "traces"
    emit_report = run_json(
        [
            *cli,
            "benchmark",
            "emit-traces",
            str(final_holdout_observed_path),
            "--config",
            str(TRACE_PROJECTION_CONFIG),
            "--output-dir",
            str(final_holdout_traces_dir),
            "--json",
        ]
    )

    score_report_path = final_holdout_eval_dir / "artifact_score.json"
    score_report = run_json(
        [
            *cli,
            "benchmark",
            "score-artifacts",
            str(train_prep_dir / "discovered" / "artifact_set.json"),
            str(final_holdout_traces_dir / "multi_target.csv"),
            "--output",
            str(score_report_path),
            "--json",
        ]
    )

    artifact_set_src = train_prep_dir / "discovered" / "artifact_set.json"
    frozen_artifact_set_dir = freeze_dir / "artifact_set"
    if frozen_artifact_set_dir.exists():
        shutil.rmtree(frozen_artifact_set_dir)
    shutil.copytree(train_prep_dir / "discovered", frozen_artifact_set_dir)

    combined_pearl_path = freeze_dir / "guardrails_pre_pint_combined.pearl.ir.json"
    route_policy_path = freeze_dir / "route_policy.json"
    build_combined_pearl(frozen_artifact_set_dir / "artifact_set.json", combined_pearl_path, route_policy_path)

    native_output = freeze_dir / "guardrails_pre_pint_combined.pearl"
    run_plain(
        [
            *cli,
            "compile",
            str(combined_pearl_path),
            "--name",
            "guardrails_pre_pint_combined",
            "--output",
            str(native_output),
        ]
    )

    wasm_output = freeze_dir / "guardrails_pre_pint_combined.pearl.wasm"
    wasm_compiled = True
    try:
        run_plain(
            [
                *cli,
                "compile",
                str(combined_pearl_path),
                "--name",
                "guardrails_pre_pint_combined",
                "--target",
                "wasm32-unknown-unknown",
                "--output",
                str(wasm_output),
            ]
        )
    except subprocess.CalledProcessError:
        wasm_compiled = False

    bundle_manifest = {
        "bundle_version": "1.0",
        "bundle_id": "guardrails_pre_pint_bundle_v1",
        "created_from_commit": git_output("rev-parse", "HEAD"),
        "git_clean": git_output("status", "--short") == "",
        "trace_projection_config": str(TRACE_PROJECTION_CONFIG),
        "observer_artifact": str(observer_artifact_path),
        "observer_scaffold_artifact": str(observer_scaffold_path),
        "artifact_set": str(frozen_artifact_set_dir / "artifact_set.json"),
        "combined_pearl_ir": str(combined_pearl_path),
        "combined_native_binary": str(native_output),
        "combined_wasm_module": str(wasm_output) if wasm_compiled else None,
        "route_policy": str(route_policy_path),
        "datasets": split_manifests,
        "merge_report": merge_report,
        "final_holdout_merge_report": final_holdout_merge_report,
        "observer_scaffold": observer_scaffold,
        "observer_synthesis": synthesis_reports,
        "prepare_report": prepare_report,
        "final_holdout_observe_report": observe_report,
        "final_holdout_emit_report": emit_report,
        "final_holdout_artifact_score": score_report,
    }
    write_json(output_dir / "bundle_manifest.json", bundle_manifest)
    write_json(output_dir / "artifact_hashes.json", build_artifact_hashes(freeze_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
