from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FeatureType(str, Enum):
    BOOL = "bool"
    INT = "int"
    FLOAT = "float"
    STRING = "string"
    ENUM = "enum"


class RuleKind(str, Enum):
    PREDICATE = "predicate"
    THRESHOLD = "threshold"
    WEIGHTED_SUM = "weighted_sum"


class RuleVerificationStatus(str, Enum):
    Z3_VERIFIED = "z3_verified"
    PIPELINE_UNVERIFIED = "pipeline_unverified"
    HEURISTIC_UNVERIFIED = "heuristic_unverified"
    REFINED_UNVERIFIED = "refined_unverified"


class ComparisonOperator(str, Enum):
    EQ = "=="
    NE = "!="
    GT = ">"
    GTE = ">="
    LT = "<"
    LTE = "<="
    IN = "in"
    NOT_IN = "not_in"


class LogicPearlModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class FeatureDefinition(LogicPearlModel):
    id: str
    type: FeatureType
    description: str | None = None
    values: list[str | int | float | bool] | None = None
    min: int | float | None = None
    max: int | float | None = None
    editable: bool | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not value:
            raise ValueError("feature id must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_feature_constraints(self) -> "FeatureDefinition":
        if self.type == FeatureType.ENUM and not self.values:
            raise ValueError("enum features must define values")
        if self.type != FeatureType.ENUM and self.values is not None:
            raise ValueError("only enum features may define values")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("feature min cannot exceed max")
        return self


class ComparisonExpression(LogicPearlModel):
    feature: str
    op: ComparisonOperator
    value: Any

    @field_validator("feature")
    @classmethod
    def validate_feature(cls, value: str) -> str:
        if not value:
            raise ValueError("comparison feature must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_comparison(self) -> "ComparisonExpression":
        if self.op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            if not isinstance(self.value, list):
                raise ValueError(f"operator {self.op.value} requires an array value")
        return self


class LogicalAllExpression(LogicPearlModel):
    all: list["Expression"]

    @field_validator("all")
    @classmethod
    def validate_all(cls, value: list["Expression"]) -> list["Expression"]:
        if not value:
            raise ValueError("all expressions must contain at least one child")
        return value


class LogicalAnyExpression(LogicPearlModel):
    any: list["Expression"]

    @field_validator("any")
    @classmethod
    def validate_any(cls, value: list["Expression"]) -> list["Expression"]:
        if not value:
            raise ValueError("any expressions must contain at least one child")
        return value


class LogicalNotExpression(LogicPearlModel):
    not_: "Expression" = Field(alias="not")


Expression = Annotated[
    ComparisonExpression | LogicalAllExpression | LogicalAnyExpression | LogicalNotExpression,
    Field(discriminator=None),
]


class RuleDefinition(LogicPearlModel):
    id: str
    kind: RuleKind
    bit: int
    deny_when: Expression
    label: str | None = None
    message: str | None = None
    severity: str | None = None
    counterfactual_hint: str | None = None
    verification_status: RuleVerificationStatus | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not value:
            raise ValueError("rule id must be non-empty")
        return value

    @field_validator("bit")
    @classmethod
    def validate_bit(cls, value: int) -> int:
        if value < 0:
            raise ValueError("rule bit must be non-negative")
        return value


class InputSchema(LogicPearlModel):
    features: list[FeatureDefinition]

    @field_validator("features")
    @classmethod
    def validate_features_not_empty(cls, value: list[FeatureDefinition]) -> list[FeatureDefinition]:
        if not value:
            raise ValueError("input schema must define at least one feature")
        return value

    @model_validator(mode="after")
    def validate_unique_feature_ids(self) -> "InputSchema":
        feature_ids = [feature.id for feature in self.features]
        duplicates = sorted({feature_id for feature_id in feature_ids if feature_ids.count(feature_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate feature ids: {', '.join(duplicates)}")
        return self


class EvaluationConfig(LogicPearlModel):
    combine: Literal["bitwise_or"]
    allow_when_bitmask: Literal[0]


class VerificationConfig(LogicPearlModel):
    domain_constraints: list[ComparisonExpression] | None = None
    correctness_scope: str | None = None
    verification_summary: dict[str, int] | None = None


class Provenance(LogicPearlModel):
    generator: str | None = None
    generator_version: str | None = None
    source_commit: str | None = None
    created_at: str | None = None


class LogicPearlGateIR(LogicPearlModel):
    ir_version: Literal["1.0"]
    gate_id: str
    gate_type: Literal["bitmask_gate"]
    input_schema: InputSchema
    rules: list[RuleDefinition]
    evaluation: EvaluationConfig
    verification: VerificationConfig | None = None
    provenance: Provenance | None = None

    @field_validator("gate_id")
    @classmethod
    def validate_gate_id(cls, value: str) -> str:
        if not value:
            raise ValueError("gate id must be non-empty")
        return value

    @field_validator("rules")
    @classmethod
    def validate_rules_not_empty(cls, value: list[RuleDefinition]) -> list[RuleDefinition]:
        if not value:
            raise ValueError("gate must define at least one rule")
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> "LogicPearlGateIR":
        rule_ids = [rule.id for rule in self.rules]
        duplicate_rule_ids = sorted({rule_id for rule_id in rule_ids if rule_ids.count(rule_id) > 1})
        if duplicate_rule_ids:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicate_rule_ids)}")

        bits = [rule.bit for rule in self.rules]
        duplicate_bits = sorted({str(bit) for bit in bits if bits.count(bit) > 1})
        if duplicate_bits:
            raise ValueError(f"duplicate rule bits: {', '.join(duplicate_bits)}")

        known_features = {feature.id: feature for feature in self.input_schema.features}
        referenced_features = set()
        for rule in self.rules:
            referenced_features.update(_collect_feature_refs(rule.deny_when))
        if self.verification and self.verification.domain_constraints:
            referenced_features.update(
                constraint.feature for constraint in self.verification.domain_constraints
            )

        unknown_features = sorted(referenced_features - set(known_features))
        if unknown_features:
            raise ValueError(f"unknown features referenced: {', '.join(unknown_features)}")

        for rule in self.rules:
            _validate_expression_values(rule.deny_when, known_features, context=f"rule {rule.id}")

        if self.verification and self.verification.domain_constraints:
            for constraint in self.verification.domain_constraints:
                _validate_comparison_value(
                    constraint,
                    known_features[constraint.feature],
                    context="verification.domain_constraints",
                )

        return self


def _collect_feature_refs(expression: Expression) -> set[str]:
    if isinstance(expression, ComparisonExpression):
        return {expression.feature}
    if isinstance(expression, LogicalAllExpression):
        refs: set[str] = set()
        for child in expression.all:
            refs.update(_collect_feature_refs(child))
        return refs
    if isinstance(expression, LogicalAnyExpression):
        refs = set()
        for child in expression.any:
            refs.update(_collect_feature_refs(child))
        return refs
    if isinstance(expression, LogicalNotExpression):
        return _collect_feature_refs(expression.not_)
    raise TypeError(f"unsupported expression type: {type(expression)!r}")


def _validate_expression_values(
    expression: Expression,
    known_features: dict[str, FeatureDefinition],
    *,
    context: str,
) -> None:
    if isinstance(expression, ComparisonExpression):
        _validate_comparison_value(expression, known_features[expression.feature], context=context)
        return
    if isinstance(expression, LogicalAllExpression):
        for child in expression.all:
            _validate_expression_values(child, known_features, context=context)
        return
    if isinstance(expression, LogicalAnyExpression):
        for child in expression.any:
            _validate_expression_values(child, known_features, context=context)
        return
    if isinstance(expression, LogicalNotExpression):
        _validate_expression_values(expression.not_, known_features, context=context)
        return
    raise TypeError(f"unsupported expression type: {type(expression)!r}")


def _validate_comparison_value(
    expression: ComparisonExpression,
    feature: FeatureDefinition,
    *,
    context: str,
) -> None:
    value = expression.value

    if feature.type == FeatureType.BOOL:
        _validate_bool_operator(expression, context=context)
        _validate_scalar_type(value, bool, context=context, feature_id=feature.id)
        return

    if feature.type == FeatureType.ENUM:
        allowed_values = set(feature.values or [])
        if expression.op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            for item in value:
                if item not in allowed_values:
                    raise ValueError(
                        f"{context} references enum feature {feature.id} with unsupported value {item!r}"
                    )
        else:
            if value not in allowed_values:
                raise ValueError(
                    f"{context} references enum feature {feature.id} with unsupported value {value!r}"
                )
        return

    if feature.type == FeatureType.STRING:
        _validate_string_operator(expression, context=context)
        if expression.op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            if not all(isinstance(item, str) for item in value):
                raise ValueError(f"{context} requires string array values for feature {feature.id}")
        elif not isinstance(value, str):
            raise ValueError(f"{context} requires string value for feature {feature.id}")
        return

    if feature.type in (FeatureType.INT, FeatureType.FLOAT):
        _validate_numeric_operator(expression, context=context)
        if expression.op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            if not all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in value):
                raise ValueError(f"{context} requires numeric array values for feature {feature.id}")
        elif not (isinstance(value, (int, float)) and not isinstance(value, bool)):
            raise ValueError(f"{context} requires numeric value for feature {feature.id}")
        return

    raise ValueError(f"{context} uses unsupported feature type {feature.type}")


def _validate_scalar_type(value: Any, expected_type: type, *, context: str, feature_id: str) -> None:
    if not isinstance(value, expected_type):
        raise ValueError(f"{context} requires {expected_type.__name__} value for feature {feature_id}")


def _validate_bool_operator(expression: ComparisonExpression, *, context: str) -> None:
    if expression.op not in (ComparisonOperator.EQ, ComparisonOperator.NE):
        raise ValueError(f"{context} uses unsupported operator {expression.op.value} for bool feature")


def _validate_string_operator(expression: ComparisonExpression, *, context: str) -> None:
    if expression.op not in (
        ComparisonOperator.EQ,
        ComparisonOperator.NE,
        ComparisonOperator.IN,
        ComparisonOperator.NOT_IN,
    ):
        raise ValueError(f"{context} uses unsupported operator {expression.op.value} for string feature")


def _validate_numeric_operator(expression: ComparisonExpression, *, context: str) -> None:
    if expression.op not in (
        ComparisonOperator.EQ,
        ComparisonOperator.NE,
        ComparisonOperator.GT,
        ComparisonOperator.GTE,
        ComparisonOperator.LT,
        ComparisonOperator.LTE,
        ComparisonOperator.IN,
        ComparisonOperator.NOT_IN,
    ):
        raise ValueError(f"{context} uses unsupported operator {expression.op.value} for numeric feature")


LogicalAllExpression.model_rebuild()
LogicalAnyExpression.model_rebuild()
LogicalNotExpression.model_rebuild()
LogicPearlGateIR.model_rebuild()
