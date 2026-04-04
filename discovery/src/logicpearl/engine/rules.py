from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class VerificationStatus(str, Enum):
    Z3_VERIFIED = "z3_verified"
    PIPELINE_UNVERIFIED = "pipeline_unverified"
    HEURISTIC_UNVERIFIED = "heuristic_unverified"
    REFINED_UNVERIFIED = "refined_unverified"


class RuleSource(str, Enum):
    DISCOVERED = "discovered"
    PINNED = "pinned"
    OVERRIDE = "override"


@dataclass(frozen=True)
class Condition:
    feature: str
    operator: str
    threshold: float

    def evaluate(self, features: dict[str, float]) -> bool:
        value = features.get(self.feature, 0.0)
        if self.operator == "<=":
            return value <= self.threshold
        if self.operator == ">":
            return value > self.threshold
        return False


@dataclass
class Rule:
    conditions: list[Condition]
    label: int = 0
    soundness_score: float = 1.0
    denied_coverage: int = 0
    rule_id: str | None = None
    source: RuleSource = RuleSource.DISCOVERED
    verification_status: VerificationStatus = VerificationStatus.PIPELINE_UNVERIFIED

    def matches(self, features: dict[str, float]) -> bool:
        return all(condition.evaluate(features) for condition in self.conditions)

    def coverage(self, feature_list: list[dict[str, float]]) -> int:
        return sum(1 for feature_dict in feature_list if self.matches(feature_dict))


def coerce_condition(condition: Any) -> Condition:
    if isinstance(condition, Condition):
        return condition
    return Condition(
        feature=condition.feature,
        operator=condition.operator,
        threshold=float(condition.threshold),
    )


def coerce_rule(rule: Any) -> Rule:
    if isinstance(rule, Rule):
        return rule
    return Rule(
        conditions=[coerce_condition(condition) for condition in rule.conditions],
        label=getattr(rule, "label", 0),
        soundness_score=float(getattr(rule, "soundness_score", 1.0)),
        denied_coverage=int(getattr(rule, "denied_coverage", 0)),
        rule_id=getattr(rule, "rule_id", None),
        source=RuleSource(getattr(rule, "source", RuleSource.DISCOVERED)),
        verification_status=VerificationStatus(
            getattr(rule, "verification_status", VerificationStatus.PIPELINE_UNVERIFIED)
        ),
    )


def coerce_rules(rules: list[Any]) -> list[Rule]:
    return [coerce_rule(rule) for rule in rules]
