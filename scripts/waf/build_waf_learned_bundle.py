#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
WORKSPACE_ROOT = REPO_ROOT.parent
DEFAULT_DATASETS_ROOT = Path(
    os.environ.get("LOGICPEARL_DATASETS", str(WORKSPACE_ROOT / "datasets" / "public"))
).expanduser()
TRACE_PROJECTION_CONFIG = REPO_ROOT / "benchmarks" / "waf" / "prep" / "trace_projection.waf_v1.json"
OBSERVER_MANIFEST = REPO_ROOT / "examples" / "waf_edge" / "plugins" / "observer" / "manifest.json"
ROUTE_AUDIT_MANIFEST = REPO_ROOT / "examples" / "waf_edge" / "plugins" / "route_audit" / "manifest.json"
TARGETS = [
    "target_injection_payload",
    "target_sensitive_surface",
    "target_suspicious_request",
]
TARGET_TRACE_FILES = {
    "target_injection_payload": "target_injection_payload_traces.csv",
    "target_sensitive_surface": "target_sensitive_surface_traces.csv",
    "target_suspicious_request": "target_suspicious_request_traces.csv",
}
PLUGIN_BATCH_SIZE = 256


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a learned WAF bundle from real staged datasets using LogicPearl discovery."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--datasets-root", type=Path, default=DEFAULT_DATASETS_ROOT)
    parser.add_argument("--dev-fraction", type=float, default=0.8)
    parser.add_argument("--benchmark-dir", type=Path, default=None)
    parser.add_argument("--use-installed-cli", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--residual-pass", action="store_true", default=True)
    parser.add_argument("--refine", action="store_true", default=True)
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
    started = time.monotonic()
    print("+", " ".join(cmd), flush=True)
    completed = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    elapsed = time.monotonic() - started
    print(f"  completed in {elapsed:.1f}s", flush=True)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError(f"command returned no stdout: {' '.join(cmd)}")
    return json.loads(payload)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def copy_plugin_bundle(source_manifest: Path, dest_dir: Path) -> Path:
    source_dir = source_manifest.parent
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.copytree(source_dir, dest_dir)
    return dest_dir / "manifest.json"


def build_learned_pipeline(
    artifact_set_path: Path,
    observer_manifest_path: Path,
    route_audit_manifest_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    artifact_set = json.loads(artifact_set_path.read_text())
    artifacts = {item["name"]: item["artifact"] for item in artifact_set["binary_targets"]}
    for target in TARGETS:
        if target not in artifacts:
            raise RuntimeError(f"learned artifact set is missing target {target}")

    pipeline = {
        "pipeline_version": "1.0",
        "pipeline_id": "waf_edge_learned_v1",
        "entrypoint": "input",
        "stages": [
            {
                "id": "observer",
                "kind": "observer_plugin",
                "plugin_manifest": str(observer_manifest_path),
                "input": {
                    "method": "$.method",
                    "path": "$.path",
                    "source_zone": "$.source_zone",
                    "headers": "$.headers",
                    "query": "$.query",
                    "body": "$.body",
                    "raw_request": "$.raw_request",
                    "modsecurity_meta": "$.modsecurity_meta",
                },
                "export": {
                    "contains_sqli_signature": "$.features.contains_sqli_signature",
                    "contains_xss_signature": "$.features.contains_xss_signature",
                    "contains_path_traversal": "$.features.contains_path_traversal",
                    "contains_server_include": "$.features.contains_server_include",
                    "contains_php_injection": "$.features.contains_php_injection",
                    "sqli_marker_count": "$.features.sqli_marker_count",
                    "xss_marker_count": "$.features.xss_marker_count",
                    "traversal_marker_count": "$.features.traversal_marker_count",
                    "php_injection_marker_count": "$.features.php_injection_marker_count",
                    "contains_waitfor_delay": "$.features.contains_waitfor_delay",
                    "contains_union_select": "$.features.contains_union_select",
                    "contains_quote": "$.features.contains_quote",
                    "contains_comment_sequence": "$.features.contains_comment_sequence",
                    "contains_script_tag": "$.features.contains_script_tag",
                    "contains_event_handler": "$.features.contains_event_handler",
                    "contains_dotdot": "$.features.contains_dotdot",
                    "targets_sensitive_route": "$.features.targets_sensitive_route",
                    "sensitive_route_marker_count": "$.features.sensitive_route_marker_count",
                    "path_targets_admin": "$.features.path_targets_admin",
                    "path_targets_hidden": "$.features.path_targets_hidden",
                    "contains_restricted_extension": "$.features.contains_restricted_extension",
                    "origin_outside_trust_zone": "$.features.origin_outside_trust_zone",
                    "has_scanner_fingerprint": "$.features.has_scanner_fingerprint",
                    "scanner_marker_count": "$.features.scanner_marker_count",
                    "has_malformed_encoding": "$.features.has_malformed_encoding",
                    "meta_reports_sqli": "$.features.meta_reports_sqli",
                    "meta_reports_xss": "$.features.meta_reports_xss",
                    "meta_reports_restricted_resource": "$.features.meta_reports_restricted_resource",
                    "meta_reports_bad_bot": "$.features.meta_reports_bad_bot",
                    "meta_reports_protocol_violation": "$.features.meta_reports_protocol_violation",
                    "meta_reports_command_injection": "$.features.meta_reports_command_injection",
                    "meta_reports_php_injection": "$.features.meta_reports_php_injection",
                    "request_has_query": "$.features.request_has_query",
                    "request_has_body": "$.features.request_has_body",
                    "path_depth": "$.features.path_depth",
                    "query_key_count": "$.features.query_key_count",
                    "body_key_count": "$.features.body_key_count",
                    "percent_encoding_count": "$.features.percent_encoding_count",
                    "suspicious_token_count": "$.features.suspicious_token_count",
                    "likely_benign_request": "$.features.likely_benign_request",
                    "risk_score": "$.features.risk_score",
                },
            },
            {
                "id": "target_injection_payload",
                "kind": "pearl",
                "artifact": artifacts["target_injection_payload"],
                "input": {
                    "contains_sqli_signature": "@observer.contains_sqli_signature",
                    "contains_xss_signature": "@observer.contains_xss_signature",
                    "contains_path_traversal": "@observer.contains_path_traversal",
                    "contains_server_include": "@observer.contains_server_include",
                    "contains_php_injection": "@observer.contains_php_injection",
                    "sqli_marker_count": "@observer.sqli_marker_count",
                    "xss_marker_count": "@observer.xss_marker_count",
                    "traversal_marker_count": "@observer.traversal_marker_count",
                    "php_injection_marker_count": "@observer.php_injection_marker_count",
                    "contains_waitfor_delay": "@observer.contains_waitfor_delay",
                    "contains_union_select": "@observer.contains_union_select",
                    "contains_quote": "@observer.contains_quote",
                    "contains_comment_sequence": "@observer.contains_comment_sequence",
                    "contains_script_tag": "@observer.contains_script_tag",
                    "contains_event_handler": "@observer.contains_event_handler",
                    "contains_dotdot": "@observer.contains_dotdot",
                    "meta_reports_sqli": "@observer.meta_reports_sqli",
                    "meta_reports_xss": "@observer.meta_reports_xss",
                    "meta_reports_command_injection": "@observer.meta_reports_command_injection",
                    "meta_reports_php_injection": "@observer.meta_reports_php_injection",
                    "percent_encoding_count": "@observer.percent_encoding_count",
                    "suspicious_token_count": "@observer.suspicious_token_count",
                    "risk_score": "@observer.risk_score",
                },
                "export": {
                    "bitmask": "$.bitmask",
                    "allow": "$.allow",
                },
            },
            {
                "id": "target_sensitive_surface",
                "kind": "pearl",
                "artifact": artifacts["target_sensitive_surface"],
                "input": {
                    "targets_sensitive_route": "@observer.targets_sensitive_route",
                    "sensitive_route_marker_count": "@observer.sensitive_route_marker_count",
                    "path_targets_admin": "@observer.path_targets_admin",
                    "path_targets_hidden": "@observer.path_targets_hidden",
                    "contains_restricted_extension": "@observer.contains_restricted_extension",
                    "origin_outside_trust_zone": "@observer.origin_outside_trust_zone",
                    "meta_reports_restricted_resource": "@observer.meta_reports_restricted_resource",
                    "path_depth": "@observer.path_depth",
                    "query_key_count": "@observer.query_key_count",
                    "body_key_count": "@observer.body_key_count",
                    "percent_encoding_count": "@observer.percent_encoding_count",
                    "suspicious_token_count": "@observer.suspicious_token_count",
                    "risk_score": "@observer.risk_score",
                },
                "export": {
                    "bitmask": "$.bitmask",
                    "allow": "$.allow",
                },
            },
            {
                "id": "target_suspicious_request",
                "kind": "pearl",
                "artifact": artifacts["target_suspicious_request"],
                "input": {
                    "has_scanner_fingerprint": "@observer.has_scanner_fingerprint",
                    "scanner_marker_count": "@observer.scanner_marker_count",
                    "has_malformed_encoding": "@observer.has_malformed_encoding",
                    "meta_reports_bad_bot": "@observer.meta_reports_bad_bot",
                    "meta_reports_protocol_violation": "@observer.meta_reports_protocol_violation",
                    "request_has_query": "@observer.request_has_query",
                    "request_has_body": "@observer.request_has_body",
                    "path_depth": "@observer.path_depth",
                    "query_key_count": "@observer.query_key_count",
                    "body_key_count": "@observer.body_key_count",
                    "percent_encoding_count": "@observer.percent_encoding_count",
                    "suspicious_token_count": "@observer.suspicious_token_count",
                    "likely_benign_request": "@observer.likely_benign_request",
                    "risk_score": "@observer.risk_score",
                },
                "export": {
                    "bitmask": "$.bitmask",
                    "allow": "$.allow",
                },
            },
            {
                "id": "audit",
                "kind": "verify_plugin",
                "plugin_manifest": str(route_audit_manifest_path),
                "input": {
                    "target_injection_payload_bitmask": "@target_injection_payload.bitmask",
                    "target_sensitive_surface_bitmask": "@target_sensitive_surface.bitmask",
                    "target_suspicious_request_bitmask": "@target_suspicious_request.bitmask",
                    "has_scanner_fingerprint": "@observer.has_scanner_fingerprint",
                    "has_malformed_encoding": "@observer.has_malformed_encoding",
                    "risk_score": "@observer.risk_score",
                    "likely_benign_request": "@observer.likely_benign_request"
                },
                "export": {
                    "route_status": "$.route_status",
                    "decision_basis": "$.decision_basis",
                    "explanation": "$.explanation",
                    "counterfactual": "$.counterfactual",
                    "allow": "$.summary.allow",
                    "consistent": "$.summary.consistent"
                }
            }
        ],
        "output": {
            "route_status": "@audit.route_status",
            "decision_basis": "@audit.decision_basis",
            "explanation": "@audit.explanation",
            "counterfactual": "@audit.counterfactual",
            "allow": "@audit.allow",
            "consistent": "@audit.consistent",
            "risk_score": "@observer.risk_score",
            "target_injection_payload_bitmask": "@target_injection_payload.bitmask",
            "target_sensitive_surface_bitmask": "@target_sensitive_surface.bitmask",
            "target_suspicious_request_bitmask": "@target_suspicious_request.bitmask"
        }
    }
    write_json(output_path, pipeline)
    return pipeline


def build_target_artifact_set(
    cli: list[str],
    train_traces_dir: Path,
    discovered_dir: Path,
    residual_pass: bool,
    refine: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    artifacts_dir = discovered_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    build_reports: list[dict[str, Any]] = []
    descriptors: list[dict[str, str]] = []
    for target in TARGETS:
        trace_file = train_traces_dir / TARGET_TRACE_FILES[target]
        target_output_dir = artifacts_dir / target
        build_cmd = [
            *cli,
            "build",
            str(trace_file),
            "--gate-id",
            target,
            "--label-column",
            "allowed",
            "--output-dir",
            str(target_output_dir),
            "--json",
        ]
        if residual_pass:
            build_cmd.append("--residual-pass")
        if refine:
            build_cmd.append("--refine")
        build_report = run_json(build_cmd)
        build_reports.append(build_report)
        descriptors.append(
            {
                "name": target,
                "artifact": str(Path("artifacts") / target / "pearl.ir.json"),
            }
        )

    artifact_set = {
        "artifact_set_version": "1.0",
        "artifact_set_id": "waf_learned_artifact_set",
        "features": json.loads(TRACE_PROJECTION_CONFIG.read_text())["feature_columns"],
        "binary_targets": descriptors,
    }
    discover_report = {
        "source_csv": str(train_traces_dir / "multi_target.csv"),
        "artifact_set_id": artifact_set["artifact_set_id"],
        "rows": sum(report["rows"] for report in build_reports) // max(len(build_reports), 1),
        "features": artifact_set["features"],
        "targets": TARGETS,
        "cached_artifacts": sum(1 for report in build_reports if report.get("cache_hit")),
        "cache_hit": all(report.get("cache_hit") for report in build_reports),
        "artifacts": build_reports,
        "skipped_targets": [],
        "output_files": {
            "artifact_set": str(discovered_dir / "artifact_set.json"),
            "discover_report": str(discovered_dir / "discover_report.json"),
        },
    }
    write_json(discovered_dir / "artifact_set.json", artifact_set)
    write_json(discovered_dir / "discover_report.json", discover_report)
    return artifact_set, discover_report


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cli = logicpearl_base_command(args.use_installed_cli)

    benchmark_dir = (
        args.benchmark_dir.resolve()
        if args.benchmark_dir
        else output_dir / "benchmark_cases"
    )
    train_dir = output_dir / "train"
    holdout_dir = output_dir / "final_holdout"
    freeze_dir = output_dir / "freeze"
    for path in (train_dir, holdout_dir, freeze_dir):
        path.mkdir(parents=True, exist_ok=True)

    if not args.resume or not (benchmark_dir / "final_holdout.jsonl").exists():
        run_json(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "waf" / "build_waf_benchmark_cases.py"),
                "--output-dir",
                str(benchmark_dir),
                "--datasets-root",
                str(args.datasets_root),
                "--dev-fraction",
                str(args.dev_fraction),
            ]
        )

    dev_cases = benchmark_dir / "dev.jsonl"
    final_holdout_cases = benchmark_dir / "final_holdout.jsonl"

    train_observed = train_dir / "observed.jsonl"
    run_json(
        [
            *cli,
            "benchmark",
            "observe",
            str(dev_cases),
            "--plugin-manifest",
            str(OBSERVER_MANIFEST),
            "--output",
            str(train_observed),
            "--json",
        ]
    )
    run_json(
        [
            *cli,
            "benchmark",
            "emit-traces",
            str(train_observed),
            "--config",
            str(TRACE_PROJECTION_CONFIG),
            "--output-dir",
            str(train_dir / "traces"),
            "--json",
        ]
    )
    discovered_dir = train_dir / "discovered"
    discovered_dir.mkdir(parents=True, exist_ok=True)
    artifact_set, _discover_report = build_target_artifact_set(
        cli,
        train_dir / "traces",
        discovered_dir,
        args.residual_pass,
        args.refine,
    )
    artifact_set_path = discovered_dir / "artifact_set.json"

    copied_artifacts_dir = freeze_dir / "artifacts"
    copied_artifacts_dir.mkdir(parents=True, exist_ok=True)
    for descriptor in artifact_set["binary_targets"]:
        destination = freeze_dir / descriptor["artifact"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(discovered_dir / descriptor["artifact"], destination)

    copied_observer_manifest = copy_plugin_bundle(OBSERVER_MANIFEST, freeze_dir / "plugins" / "observer")
    copied_route_manifest = copy_plugin_bundle(ROUTE_AUDIT_MANIFEST, freeze_dir / "plugins" / "route_audit")

    rewritten_artifact_set_path = freeze_dir / "artifact_set.json"
    write_json(rewritten_artifact_set_path, artifact_set)

    learned_pipeline_path = freeze_dir / "waf_edge.learned.pipeline.json"
    build_learned_pipeline(
        rewritten_artifact_set_path,
        Path("plugins/observer/manifest.json"),
        Path("plugins/route_audit/manifest.json"),
        learned_pipeline_path,
    )

    holdout_observed = holdout_dir / "observed.jsonl"
    run_json(
        [
            *cli,
            "benchmark",
            "observe",
            str(final_holdout_cases),
            "--plugin-manifest",
            str(OBSERVER_MANIFEST),
            "--output",
            str(holdout_observed),
            "--json",
        ]
    )
    run_json(
        [
            *cli,
            "benchmark",
            "emit-traces",
            str(holdout_observed),
            "--config",
            str(TRACE_PROJECTION_CONFIG),
            "--output-dir",
            str(holdout_dir / "traces"),
            "--json",
        ]
    )
    artifact_score = run_json(
        [
            *cli,
            "benchmark",
            "score-artifacts",
            str(rewritten_artifact_set_path),
            str(holdout_dir / "traces" / "multi_target.csv"),
            "--output",
            str(holdout_dir / "artifact_score.json"),
            "--json",
        ]
    )
    exact = run_json(
        [
            *cli,
            "benchmark",
            "run",
            str(learned_pipeline_path),
            str(final_holdout_cases),
            "--output",
            str(holdout_dir / "exact_routes.json"),
            "--json",
        ]
    )
    collapsed = run_json(
        [
            *cli,
            "benchmark",
            "run",
            str(learned_pipeline_path),
            str(final_holdout_cases),
            "--collapse-non-allow-to-deny",
            "--output",
            str(holdout_dir / "collapsed_allow_deny.json"),
            "--json",
        ]
    )

    summary = {
        "benchmark_dir": str(benchmark_dir),
        "trace_projection_config": str(TRACE_PROJECTION_CONFIG),
        "artifact_set": str(rewritten_artifact_set_path),
        "learned_pipeline": str(learned_pipeline_path),
        "artifact_score": artifact_score["summary"],
        "exact_routes": exact["summary"],
        "collapsed_allow_deny": collapsed["summary"],
    }
    write_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
