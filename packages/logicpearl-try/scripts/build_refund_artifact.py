#!/usr/bin/env python3
"""Generate the refund-eligibility trace + feature dictionary, then compile the artifact.

Run from the repo root or from packages/logicpearl-try/.
Produces packages/logicpearl-try/artifacts/refund-eligibility-v1/ with the full bundle.
"""
from __future__ import annotations

import csv
import itertools
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = PACKAGE_ROOT / "artifacts" / "refund-eligibility-v1"
LOGICPEARL_BIN = REPO_ROOT / "target" / "release" / "logicpearl"

REASON_CATEGORIES = [
    "defective",
    "changed_mind",
    "wrong_item",
    "duplicate_charge",
    "billing_error",
]

# Sample values chosen so the compiler learns the thresholds we want.
# Numeric features are sampled at multiple values bracketing each threshold.
DAYS_SAMPLES = [5, 29, 31, 100, 360, 366]          # crosses 30 and 365
AMOUNT_SAMPLES = [50.0, 499.0, 501.0, 2500.0]      # crosses 500
TENURE_SAMPLES = [1, 24]                           # not gating any rule in v1; present for realism
PREV_REFUNDS_SAMPLES = [0, 3, 4]                   # crosses 3


def decide(
    days: int,
    amount: float,
    tenure: int,
    prev_refunds: int,
    reason: str,
    is_digital: bool,
    used: bool,
    enterprise: bool,
) -> str:
    """Business logic that labels each row. Rules match the design doc exactly."""
    # Terminal decisions by reason first (rules 4, 5, 6).
    if reason == "billing_error":
        return "route_to_finance"
    if reason == "wrong_item":
        return "approve"
    if reason == "duplicate_charge":
        return "approve"

    # defective: 1-year coverage (rule 1).
    if reason == "defective" and days > 365:
        return "deny"

    # changed_mind: 30-day window (rule 2).
    if reason == "changed_mind" and days > 30:
        return "deny"

    # changed_mind on used digital (rule 3).
    if reason == "changed_mind" and is_digital and used:
        return "deny"

    # Refund abuse pattern (rule 7).
    if prev_refunds > 3:
        return "route_to_review"

    # Large non-enterprise refund (rule 8).
    if amount > 500 and not enterprise:
        return "route_to_review"

    return "approve"


def build_trace_rows() -> list[dict]:
    rows = []
    # Cartesian product of all discrete / bracketing values. Large but well within SMT comfort.
    combinations = itertools.product(
        DAYS_SAMPLES,
        AMOUNT_SAMPLES,
        TENURE_SAMPLES,
        PREV_REFUNDS_SAMPLES,
        REASON_CATEGORIES,
        [False, True],       # is_digital
        [False, True],       # used
        [False, True],       # enterprise
    )
    for (days, amount, tenure, prev, reason, digital, used, enterprise) in combinations:
        row = {
            "days_since_purchase": days,
            "order_amount_usd": amount,
            "customer_tenure_months": tenure,
            "previous_refunds_90d": prev,
            "reason_category": reason,
            "item_is_digital": 1 if digital else 0,
            "item_used": 1 if used else 0,
            "is_enterprise_customer": 1 if enterprise else 0,
            "next_action": decide(days, amount, tenure, prev, reason, digital, used, enterprise),
        }
        rows.append(row)
    return rows


FEATURE_DICTIONARY = {
    "feature_dictionary_version": "1.0",
    "features": {
        "days_since_purchase": {
            "label": "Days since purchase",
            "kind": "numeric",
        },
        "order_amount_usd": {
            "label": "Order amount (USD)",
            "kind": "numeric",
        },
        "customer_tenure_months": {
            "label": "Customer tenure (months)",
            "kind": "numeric",
        },
        "previous_refunds_90d": {
            "label": "Previous refunds in last 90 days",
            "kind": "numeric",
        },
        "reason_category": {
            "label": "Refund reason category",
            "kind": "categorical",
        },
        "item_is_digital": {
            "label": "Item is digital",
            "kind": "boolean",
        },
        "item_used": {
            "label": "Item has been used / consumed",
            "kind": "boolean",
        },
        "is_enterprise_customer": {
            "label": "Enterprise customer",
            "kind": "boolean",
        },
    },
    "feature_extraction_prompt_template": (
        "You are extracting features for a refund-eligibility decision.\n"
        "Given free-form user text describing a refund request, extract these fields:\n\n"
        "- days_since_purchase (int): days between the user's purchase and today.\n"
        "- order_amount_usd (float): amount paid in USD. Default 0 if not stated.\n"
        "- customer_tenure_months (int): how long the customer has been a customer.\n"
        "  Default 0 if not stated.\n"
        "- previous_refunds_90d (int): refunds this customer got in the last 90 days.\n"
        "  Default 0 if not stated.\n"
        "- reason_category (string): one of 'defective', 'changed_mind', 'wrong_item',\n"
        "  'duplicate_charge', 'billing_error'. Pick the closest match.\n"
        "- item_is_digital (bool): true for digital goods (downloads, subscriptions,\n"
        "  streaming). False for physical items.\n"
        "- item_used (bool): true if the customer has used, consumed, or opened the item.\n"
        "- is_enterprise_customer (bool): true only if explicitly mentioned; otherwise false.\n\n"
        "Return a JSON object with exactly these 8 fields. Do not add commentary."
    ),
}


def write_trace(rows: list[dict], path: Path) -> None:
    fieldnames = list(rows[0].keys())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def run_build() -> None:
    if not LOGICPEARL_BIN.exists():
        print(f"logicpearl binary not found at {LOGICPEARL_BIN}", file=sys.stderr)
        sys.exit(1)
    trace_path = PACKAGE_ROOT / "scripts" / "refund-traces.csv"
    feature_dict_path = PACKAGE_ROOT / "scripts" / "refund-feature-dictionary.json"
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    rows = build_trace_rows()
    write_trace(rows, trace_path)
    feature_dict_path.write_text(json.dumps(FEATURE_DICTIONARY, indent=2), encoding="utf-8")

    if ARTIFACT_DIR.exists():
        shutil.rmtree(ARTIFACT_DIR)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Trace rows: {len(rows)}")
    print(f"Compiling to {ARTIFACT_DIR} ...")

    subprocess.run(
        [
            str(LOGICPEARL_BIN),
            "build",
            str(trace_path),
            "--feature-dictionary",
            str(feature_dict_path),
            "--action-column",
            "next_action",
            "--default-action",
            "approve",
            "--output-dir",
            str(ARTIFACT_DIR),
            "--gate-id",
            "refund_eligibility_v1",
            "--compile",
        ],
        check=True,
    )

    # Normalize output filenames: the build emits <gate_id>.pearl.wasm etc;
    # standardize to pearl.wasm / pearl.wasm.meta.json for consistency with the
    # @logicpearl/browser loader's default lookup.
    for orig_name, target_name in [
        ("refund_eligibility_v1.pearl.wasm", "pearl.wasm"),
        ("refund_eligibility_v1.pearl.wasm.meta.json", "pearl.wasm.meta.json"),
        ("refund_eligibility_v1.pearl", "refund_eligibility_v1.pearl"),
    ]:
        src = ARTIFACT_DIR / orig_name
        dst = ARTIFACT_DIR / target_name
        if src.exists() and src != dst:
            shutil.move(str(src), str(dst))

    print("\n=== artifact files ===")
    for p in sorted(ARTIFACT_DIR.iterdir()):
        print(f"  {p.name:<50} {p.stat().st_size:>8} bytes")


if __name__ == "__main__":
    run_build()
