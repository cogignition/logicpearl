from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .rules import Condition, Rule, RuleSource, VerificationStatus, coerce_rules


def load_pinned_rules(path: Path) -> list[Rule]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text())
    rules = []
    for item in payload.get("rules", []):
        rules.append(
            Rule(
                rule_id=item.get("rule_id"),
                source=RuleSource.PINNED,
                verification_status=VerificationStatus.PIPELINE_UNVERIFIED,
                soundness_score=float(item.get("soundness_score", 1.0)),
                denied_coverage=int(item.get("denied_coverage", 0)),
                conditions=[
                    Condition(
                        feature=condition["feature"],
                        operator=condition["operator"],
                        threshold=float(condition["threshold"]),
                    )
                    for condition in item["conditions"]
                ],
            )
        )
    return rules


def merge_rule_layers(
    *,
    discovered_rules: list[Any],
    pinned_rules: list[Any] | None = None,
    override_rules: list[Any] | None = None,
) -> list[Rule]:
    merged: list[Rule] = []
    signatures: dict[tuple[tuple[str, str, float], ...], int] = {}

    for source_rules in (override_rules or [], pinned_rules or [], discovered_rules):
        for rule in coerce_rules(list(source_rules)):
            signature = rule_signature(rule)
            existing_index = signatures.get(signature)
            if existing_index is None:
                signatures[signature] = len(merged)
                merged.append(rule)
                continue
            if _source_rank(rule) > _source_rank(merged[existing_index]):
                merged[existing_index] = rule
    return merged


def rule_signature(rule: Rule) -> tuple[tuple[str, str, float], ...]:
    return tuple(
        sorted((condition.feature, condition.operator, float(condition.threshold)) for condition in rule.conditions)
    )


def _source_rank(rule: Rule) -> int:
    if rule.source == RuleSource.OVERRIDE:
        return 3
    if rule.source == RuleSource.PINNED:
        return 2
    return 1
