from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dataset import build_claim_traces, load_claim_audit_dataset, summarize_rule_coverage


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect or validate claims-audit datasets for LogicPearl V3.")
    parser.add_argument("dataset", help="Path to adjudicated_claims-style JSON dataset")
    parser.add_argument(
        "--observer-mode",
        choices=["strict", "assisted"],
        help="If set, also build claim traces with the V3 claims observer in this mode.",
    )
    parser.add_argument(
        "--rules-json",
        help="Optional JSON file containing either a rule-id array or an object keyed by rule id.",
    )
    args = parser.parse_args()

    records = load_claim_audit_dataset(args.dataset)
    rule_manifest = None
    if args.rules_json:
        payload = json.loads(Path(args.rules_json).read_text(encoding="utf-8"))
        rule_manifest = payload

    summary = summarize_rule_coverage(records, rule_manifest=rule_manifest)
    print(f"Items: {summary.item_count:,}")
    print()
    print("Rule coverage:")
    for item in summary.rule_coverage:
        print(
            f"{item.rule_id:24s} primary={item.primary_count:6d} "
            f"latent={item.latent_count:6d} shadowed={item.shadowed_count:6d}"
        )
    print()
    print(f"Never primary: {summary.never_primary_rules}")
    print(f"Never observed: {summary.never_observed_rules}")

    if args.observer_mode:
        traces = build_claim_traces(records, mode=args.observer_mode)
        print()
        print(f"Built {len(traces):,} traces with observer mode={args.observer_mode}")

