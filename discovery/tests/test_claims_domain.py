from __future__ import annotations

from pathlib import Path

import pytest

from logicpearl.domains.claims import (
    build_claim_traces,
    load_claim_audit_dataset,
    observe_claim,
    summarize_rule_coverage,
    validate_claim_audit_record,
)


V3_ROOT = Path(__file__).resolve().parents[2]
CLAIMS_FIXTURE = V3_ROOT / "fixtures" / "domains" / "claims" / "claims-audit-mini.json"


def test_claims_observer_extracts_expected_features() -> None:
    records = load_claim_audit_dataset(CLAIMS_FIXTURE)
    features = observe_claim(records[1]["input"], mode="assisted")

    assert features["line_role_assistant"] == 1
    assert features["assistant_surgery_missing_modifier"] == 1
    assert features["observer_mode_assisted"] == 1
    assert features["observer_mode_strict"] == 0


def test_build_claim_traces_and_shadowing_summary() -> None:
    records = load_claim_audit_dataset(CLAIMS_FIXTURE)
    traces = build_claim_traces(records, mode="strict")
    summary = summarize_rule_coverage(
        records,
        rule_manifest=["R03_duplicate", "R19_assistant_surgeon", "R20_global_surgery"],
    )

    assert len(traces) == 3
    assert traces[2][1] == "denied"
    assert any(item.rule_id == "R19_assistant_surgeon" and item.shadowed_count == 1 for item in summary.rule_coverage)
    assert summary.never_primary_rules == ["R20_global_surgery"]
    assert summary.never_observed_rules == ["R20_global_surgery"]


def test_reject_incompatible_claim_record() -> None:
    with pytest.raises(ValueError, match="missing required keys"):
        validate_claim_audit_record(
            {
                "input": {"hcpcs_code": "93000"},
                "label": "allowed",
                "metadata": {"primary_rule_id": "PAID", "all_rule_ids": [], "all_carcs": [], "noise_type": ""},
            }
        )

