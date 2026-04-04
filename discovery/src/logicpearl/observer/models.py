from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from logicpearl.ir.models import LogicPearlModel, LogicPearlGateIR, FeatureDefinition, FeatureType, InputSchema


class MappingKind(str, Enum):
    FIELD_COPY = "field_copy"
    FIELD_EQUALS = "field_equals"
    FIELD_IN_SET = "field_in_set"
    FEATURE_ALL_TRUE = "feature_all_true"
    FEATURE_ANY_TRUE = "feature_any_true"


class RawFieldDefinition(LogicPearlModel):
    id: str
    type: FeatureType
    description: str | None = None
    values: list[str | int | float | bool] | None = None
    min: int | float | None = None
    max: int | float | None = None
    required: bool = True

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not value:
            raise ValueError("raw field id must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_constraints(self) -> "RawFieldDefinition":
        if self.type == FeatureType.ENUM and not self.values:
            raise ValueError("enum raw fields must define values")
        if self.type != FeatureType.ENUM and self.values is not None:
            raise ValueError("only enum raw fields may define values")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("raw field min cannot exceed max")
        return self


class RawSchema(LogicPearlModel):
    fields: list[RawFieldDefinition]

    @field_validator("fields")
    @classmethod
    def validate_fields_not_empty(cls, value: list[RawFieldDefinition]) -> list[RawFieldDefinition]:
        if not value:
            raise ValueError("raw schema must define at least one field")
        return value

    @model_validator(mode="after")
    def validate_unique_field_ids(self) -> "RawSchema":
        field_ids = [field.id for field in self.fields]
        duplicates = sorted({field_id for field_id in field_ids if field_ids.count(field_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate raw field ids: {', '.join(duplicates)}")
        return self


class FeatureContract(LogicPearlModel):
    contract_version: Literal["1.0"]
    contract_id: str
    observer_id: str
    features: list[FeatureDefinition]

    @field_validator("contract_id", "observer_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        if not value:
            raise ValueError("feature contract ids must be non-empty")
        return value

    @field_validator("features")
    @classmethod
    def validate_features_not_empty(cls, value: list[FeatureDefinition]) -> list[FeatureDefinition]:
        if not value:
            raise ValueError("feature contract must define at least one feature")
        return value

    def to_input_schema(self) -> InputSchema:
        return InputSchema(features=self.features)


class ObserverMapping(LogicPearlModel):
    feature_id: str
    kind: MappingKind
    raw_field: str | None = None
    source_features: list[str] | None = None
    value: Any | None = None
    values: list[Any] | None = None
    description: str | None = None

    @field_validator("feature_id")
    @classmethod
    def validate_feature_id(cls, value: str) -> str:
        if not value:
            raise ValueError("mapping feature_id must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> "ObserverMapping":
        raw_kinds = {
            MappingKind.FIELD_COPY,
            MappingKind.FIELD_EQUALS,
            MappingKind.FIELD_IN_SET,
        }
        feature_kinds = {
            MappingKind.FEATURE_ALL_TRUE,
            MappingKind.FEATURE_ANY_TRUE,
        }

        if self.kind in raw_kinds and not self.raw_field:
            raise ValueError(f"mapping kind {self.kind.value} requires raw_field")
        if self.kind in raw_kinds and self.source_features is not None:
            raise ValueError(f"mapping kind {self.kind.value} does not accept source_features")
        if self.kind in feature_kinds and not self.source_features:
            raise ValueError(f"mapping kind {self.kind.value} requires source_features")
        if self.kind in feature_kinds and self.raw_field is not None:
            raise ValueError(f"mapping kind {self.kind.value} does not accept raw_field")

        if self.kind == MappingKind.FIELD_COPY:
            if self.value is not None or self.values is not None:
                raise ValueError("field_copy does not accept value or values")
        elif self.kind == MappingKind.FIELD_EQUALS:
            if self.value is None or self.values is not None:
                raise ValueError("field_equals requires value and does not accept values")
        elif self.kind == MappingKind.FIELD_IN_SET:
            if not self.values or self.value is not None:
                raise ValueError("field_in_set requires values and does not accept value")
        elif self.kind in feature_kinds:
            if self.value is not None or self.values is not None:
                raise ValueError(f"mapping kind {self.kind.value} does not accept value or values")

        return self


class Provenance(LogicPearlModel):
    generator: str | None = None
    generator_version: str | None = None
    source_commit: str | None = None
    created_at: str | None = None


class ObserverSpec(LogicPearlModel):
    observer_version: Literal["1.0"]
    observer_id: str
    raw_schema: RawSchema
    feature_contract: FeatureContract
    mappings: list[ObserverMapping]
    provenance: Provenance | None = None

    @field_validator("observer_id")
    @classmethod
    def validate_observer_id(cls, value: str) -> str:
        if not value:
            raise ValueError("observer id must be non-empty")
        return value

    @field_validator("mappings")
    @classmethod
    def validate_mappings_not_empty(cls, value: list[ObserverMapping]) -> list[ObserverMapping]:
        if not value:
            raise ValueError("observer must define at least one mapping")
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> "ObserverSpec":
        if self.feature_contract.observer_id != self.observer_id:
            raise ValueError("feature_contract.observer_id must match observer_id")

        raw_fields = {field.id: field for field in self.raw_schema.fields}
        contract_features = {feature.id: feature for feature in self.feature_contract.features}

        mapping_ids = [mapping.feature_id for mapping in self.mappings]
        duplicate_mappings = sorted(
            {feature_id for feature_id in mapping_ids if mapping_ids.count(feature_id) > 1}
        )
        if duplicate_mappings:
            raise ValueError(f"duplicate mapping feature ids: {', '.join(duplicate_mappings)}")

        missing_mappings = sorted(set(contract_features) - set(mapping_ids))
        if missing_mappings:
            raise ValueError(f"feature contract is missing mappings for: {', '.join(missing_mappings)}")

        unknown_contract_targets = sorted(set(mapping_ids) - set(contract_features))
        if unknown_contract_targets:
            raise ValueError(
                "mappings reference unknown contract features: "
                + ", ".join(unknown_contract_targets)
            )

        available_features: dict[str, FeatureDefinition] = {}
        for mapping in self.mappings:
            feature = contract_features[mapping.feature_id]
            if mapping.kind == MappingKind.FIELD_COPY:
                raw_field = raw_fields.get(mapping.raw_field or "")
                if raw_field is None:
                    raise ValueError(f"mapping {mapping.feature_id} references unknown raw field")
                _validate_field_copy(feature, raw_field, context=mapping.feature_id)
            elif mapping.kind == MappingKind.FIELD_EQUALS:
                raw_field = raw_fields.get(mapping.raw_field or "")
                if raw_field is None:
                    raise ValueError(f"mapping {mapping.feature_id} references unknown raw field")
                if feature.type != FeatureType.BOOL:
                    raise ValueError(f"mapping {mapping.feature_id} must output bool for field_equals")
                _validate_scalar_against_definition(
                    mapping.value,
                    raw_field,
                    context=f"mapping {mapping.feature_id}",
                )
            elif mapping.kind == MappingKind.FIELD_IN_SET:
                raw_field = raw_fields.get(mapping.raw_field or "")
                if raw_field is None:
                    raise ValueError(f"mapping {mapping.feature_id} references unknown raw field")
                if feature.type != FeatureType.BOOL:
                    raise ValueError(f"mapping {mapping.feature_id} must output bool for field_in_set")
                assert mapping.values is not None
                for value in mapping.values:
                    _validate_scalar_against_definition(
                        value,
                        raw_field,
                        context=f"mapping {mapping.feature_id}",
                    )
            elif mapping.kind in (MappingKind.FEATURE_ALL_TRUE, MappingKind.FEATURE_ANY_TRUE):
                if feature.type != FeatureType.BOOL:
                    raise ValueError(
                        f"mapping {mapping.feature_id} must output bool for {mapping.kind.value}"
                    )
                assert mapping.source_features is not None
                for source_feature_id in mapping.source_features:
                    source_feature = available_features.get(source_feature_id)
                    if source_feature is None:
                        raise ValueError(
                            f"mapping {mapping.feature_id} references unknown or later feature "
                            f"{source_feature_id}"
                        )
                    if source_feature.type != FeatureType.BOOL:
                        raise ValueError(
                            f"mapping {mapping.feature_id} requires bool source feature "
                            f"{source_feature_id}"
                        )
            available_features[mapping.feature_id] = feature

        return self

    def to_feature_contract(self) -> FeatureContract:
        return self.feature_contract


def validate_gate_against_contract(gate: LogicPearlGateIR, contract: FeatureContract) -> None:
    contract_features = {feature.id: feature for feature in contract.features}
    gate_features = {feature.id: feature for feature in gate.input_schema.features}

    missing_features = sorted(set(gate_features) - set(contract_features))
    if missing_features:
        raise ValueError(
            "gate input schema references features absent from feature contract: "
            + ", ".join(missing_features)
        )

    for feature_id, gate_feature in gate_features.items():
        contract_feature = contract_features[feature_id]
        if gate_feature.type != contract_feature.type:
            raise ValueError(
                f"gate feature {feature_id} type {gate_feature.type} does not match "
                f"contract type {contract_feature.type}"
            )
        if gate_feature.values != contract_feature.values:
            raise ValueError(f"gate feature {feature_id} enum domain does not match feature contract")
        if gate_feature.min != contract_feature.min or gate_feature.max != contract_feature.max:
            raise ValueError(f"gate feature {feature_id} numeric bounds do not match feature contract")


def _validate_field_copy(
    feature: FeatureDefinition,
    raw_field: RawFieldDefinition,
    *,
    context: str,
) -> None:
    if feature.type != raw_field.type:
        raise ValueError(
            f"mapping {context} field_copy type mismatch: feature {feature.type} vs raw field {raw_field.type}"
        )
    if feature.values != raw_field.values:
        raise ValueError(f"mapping {context} enum domain does not match raw field")
    if feature.min != raw_field.min or feature.max != raw_field.max:
        raise ValueError(f"mapping {context} numeric bounds do not match raw field")


def _validate_scalar_against_definition(value: Any, definition: RawFieldDefinition, *, context: str) -> None:
    if definition.type == FeatureType.BOOL:
        if not isinstance(value, bool):
            raise ValueError(f"{context} requires bool value for raw field {definition.id}")
        return

    if definition.type == FeatureType.STRING:
        if not isinstance(value, str):
            raise ValueError(f"{context} requires string value for raw field {definition.id}")
        return

    if definition.type == FeatureType.ENUM:
        if value not in set(definition.values or []):
            raise ValueError(f"{context} uses unsupported enum value {value!r} for raw field {definition.id}")
        return

    if definition.type in (FeatureType.INT, FeatureType.FLOAT):
        if not (isinstance(value, (int, float)) and not isinstance(value, bool)):
            raise ValueError(f"{context} requires numeric value for raw field {definition.id}")
        return

    raise ValueError(f"{context} uses unsupported raw field type {definition.type}")
