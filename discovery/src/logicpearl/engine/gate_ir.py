from __future__ import annotations

from typing import Any

from logicpearl.ir import (
    LogicPearlGateIR,
    ComparisonExpression,
    EvaluationConfig,
    FeatureDefinition,
    FeatureType,
    InputSchema,
    LogicalAllExpression,
    Provenance,
    RuleDefinition,
    RuleKind,
    RuleVerificationStatus,
    VerificationConfig,
)

from .rules import Condition, Rule, VerificationStatus, coerce_rules


def infer_feature_type(value: Any) -> FeatureType:
    if isinstance(value, bool):
        return FeatureType.BOOL
    if isinstance(value, int) and not isinstance(value, bool):
        return FeatureType.INT
    if isinstance(value, float):
        return FeatureType.FLOAT
    if isinstance(value, str):
        return FeatureType.STRING
    raise TypeError(f"unsupported feature value type for Gate IR inference: {type(value)!r}")


def build_input_schema_from_feature_sample(feature_sample: dict[str, Any]) -> InputSchema:
    features = []
    for feature_name in sorted(feature_sample):
        features.append(
            FeatureDefinition(
                id=feature_name,
                type=infer_feature_type(feature_sample[feature_name]),
            )
        )
    return InputSchema(features=features)


def serialize_rules_to_gate_ir(
    rules: list[Rule],
    *,
    gate_id: str,
    feature_sample: dict[str, Any],
    generator: str = "logicpearl.engine",
    generator_version: str = "0.1.0",
    source_commit: str | None = None,
    correctness_scope: str | None = None,
    verification_summary: dict[str, int] | None = None,
) -> LogicPearlGateIR:
    coerced_rules = coerce_rules(rules)
    input_schema = build_input_schema_from_feature_sample(feature_sample)

    rule_definitions = []
    for bit, rule in enumerate(coerced_rules):
        rule_id = getattr(rule, "rule_id", None) or f"rule_{bit:03d}"
        rule_definitions.append(
            RuleDefinition(
                id=rule_id,
                kind=_infer_rule_kind(rule),
                bit=bit,
                deny_when=_rule_to_expression(rule),
                verification_status=_rule_verification_status(rule),
            )
        )

    verification = None
    if correctness_scope or verification_summary:
        verification = VerificationConfig(
            correctness_scope=correctness_scope,
            verification_summary=verification_summary,
        )

    provenance = Provenance(
        generator=generator,
        generator_version=generator_version,
        source_commit=source_commit,
    )

    return LogicPearlGateIR(
        ir_version="1.0",
        gate_id=gate_id,
        gate_type="bitmask_gate",
        input_schema=input_schema,
        rules=rule_definitions,
        evaluation=EvaluationConfig(combine="bitwise_or", allow_when_bitmask=0),
        verification=verification,
        provenance=provenance,
    )


def _infer_rule_kind(rule: Rule) -> RuleKind:
    return RuleKind.PREDICATE if len(rule.conditions) <= 1 else RuleKind.THRESHOLD


def _rule_to_expression(rule: Rule) -> ComparisonExpression | LogicalAllExpression:
    comparisons = [_condition_to_expression(condition) for condition in rule.conditions]
    if len(comparisons) == 1:
        return comparisons[0]
    return LogicalAllExpression(all=comparisons)


def _condition_to_expression(condition: Condition) -> ComparisonExpression:
    return ComparisonExpression(
        feature=condition.feature,
        op=condition.operator,
        value=condition.threshold,
    )


def _rule_verification_status(rule: Rule) -> RuleVerificationStatus:
    status = getattr(rule, "verification_status", VerificationStatus.PIPELINE_UNVERIFIED)
    return RuleVerificationStatus(getattr(status, "value", status))
