from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .observer import ClaimsObserverMode, observe_claim


CLAIMS_ALLOWED_LABELS = {"allowed", "denied"}
CLAIMS_REQUIRED_INPUT_KEYS = {
    "hcpcs_code",
    "all_codes_on_claim",
    "line_role",
    "in_global_surgery_period",
}
CLAIMS_REQUIRED_METADATA_KEYS = {"primary_rule_id", "all_rule_ids", "all_carcs", "noise_type"}


@dataclass(frozen=True)
class ClaimsRuleCoverage:
    rule_id: str
    primary_count: int
    latent_count: int
    shadowed_count: int


@dataclass(frozen=True)
class ClaimsRuleCoverageSummary:
    item_count: int
    rule_coverage: list[ClaimsRuleCoverage]
    never_primary_rules: list[str]
    never_observed_rules: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_count": self.item_count,
            "rule_coverage": [
                {
                    "rule_id": item.rule_id,
                    "primary_count": item.primary_count,
                    "latent_count": item.latent_count,
                    "shadowed_count": item.shadowed_count,
                }
                for item in self.rule_coverage
            ],
            "never_primary_rules": self.never_primary_rules,
            "never_observed_rules": self.never_observed_rules,
        }


def load_claim_audit_dataset(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("claims audit dataset must be a list of records")
    for index, record in enumerate(payload):
        validate_claim_audit_record(record, context=f"record[{index}]")
    return payload


def validate_claim_audit_record(record: dict[str, Any], *, context: str = "record") -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{context} must be an object")

    raw_input = record.get("input")
    if not isinstance(raw_input, dict):
        raise ValueError(f"{context}.input must be an object")

    missing_inputs = sorted(CLAIMS_REQUIRED_INPUT_KEYS - set(raw_input))
    if missing_inputs:
        raise ValueError(f"{context}.input missing required keys: {', '.join(missing_inputs)}")

    label = record.get("label")
    if label not in CLAIMS_ALLOWED_LABELS:
        raise ValueError(f"{context}.label must be one of: {', '.join(sorted(CLAIMS_ALLOWED_LABELS))}")

    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"{context}.metadata must be an object")

    missing_metadata = sorted(CLAIMS_REQUIRED_METADATA_KEYS - set(metadata))
    if missing_metadata:
        raise ValueError(f"{context}.metadata missing required keys: {', '.join(missing_metadata)}")

    all_rule_ids = metadata.get("all_rule_ids")
    if not isinstance(all_rule_ids, list):
        raise ValueError(f"{context}.metadata.all_rule_ids must be a list")

    all_carcs = metadata.get("all_carcs")
    if not isinstance(all_carcs, list):
        raise ValueError(f"{context}.metadata.all_carcs must be a list")


def build_claim_traces(
    records: list[dict[str, Any]],
    *,
    mode: ClaimsObserverMode = "strict",
) -> list[tuple[dict[str, float], str, dict[str, Any]]]:
    traces: list[tuple[dict[str, float], str, dict[str, Any]]] = []
    for index, record in enumerate(records):
        validate_claim_audit_record(record, context=f"record[{index}]")
        features = observe_claim(record["input"], mode=mode)
        metadata = dict(record["metadata"])
        claim_id = metadata.get("claim_id", "unknown-claim")
        line_number = record["input"].get("line_number", 0)
        metadata.setdefault("trace_id", f"{claim_id}:{line_number}")
        metadata.setdefault("trace_source", "claims_audit_oracle")
        traces.append((features, record["label"], metadata))
    return traces


def infer_rule_ids(records: list[dict[str, Any]]) -> list[str]:
    discovered = {
        rule_id
        for record in records
        for rule_id in record["metadata"].get("all_rule_ids", [])
        if rule_id != "PAID"
    }
    discovered.update(
        record["metadata"].get("primary_rule_id")
        for record in records
        if record["metadata"].get("primary_rule_id") not in (None, "PAID")
    )
    return sorted(discovered)


def summarize_rule_coverage(
    records: list[dict[str, Any]],
    *,
    rule_manifest: Mapping[str, Any] | Iterable[str] | None = None,
) -> ClaimsRuleCoverageSummary:
    for index, record in enumerate(records):
        validate_claim_audit_record(record, context=f"record[{index}]")

    primary_counts = Counter(
        record["metadata"].get("primary_rule_id", record["metadata"].get("rule_id", "PAID"))
        for record in records
    )
    latent_counts = Counter(
        rule_id
        for record in records
        for rule_id in record["metadata"].get("all_rule_ids", [])
        if rule_id != "PAID"
    )

    if rule_manifest is None:
        rule_ids = infer_rule_ids(records)
    elif isinstance(rule_manifest, Mapping):
        rule_ids = sorted(rule_manifest.keys())
    else:
        rule_ids = sorted(rule_manifest)

    coverage = []
    for rule_id in rule_ids:
        primary_count = primary_counts.get(rule_id, 0)
        latent_count = latent_counts.get(rule_id, 0)
        coverage.append(
            ClaimsRuleCoverage(
                rule_id=rule_id,
                primary_count=primary_count,
                latent_count=latent_count,
                shadowed_count=latent_count - primary_count,
            )
        )

    never_primary = [item.rule_id for item in coverage if item.primary_count == 0]
    never_observed = [item.rule_id for item in coverage if item.latent_count == 0]

    return ClaimsRuleCoverageSummary(
        item_count=len(records),
        rule_coverage=coverage,
        never_primary_rules=never_primary,
        never_observed_rules=never_observed,
    )
