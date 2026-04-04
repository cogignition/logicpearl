from __future__ import annotations

from typing import Any

from logicpearl.ir.models import FeatureDefinition, FeatureType

from .models import (
    FeatureContract,
    MappingKind,
    ObserverSpec,
    RawFieldDefinition,
)


def execute_observer(spec: ObserverSpec, raw_input: dict[str, Any]) -> dict[str, Any]:
    _validate_raw_input(raw_input, spec)

    raw_fields = {field.id: field for field in spec.raw_schema.fields}
    contract_features = {feature.id: feature for feature in spec.feature_contract.features}
    features: dict[str, Any] = {}

    for mapping in spec.mappings:
        feature = contract_features[mapping.feature_id]

        if mapping.kind == MappingKind.FIELD_COPY:
            assert mapping.raw_field is not None
            value = raw_input[mapping.raw_field]
        elif mapping.kind == MappingKind.FIELD_EQUALS:
            assert mapping.raw_field is not None
            value = raw_input[mapping.raw_field] == mapping.value
        elif mapping.kind == MappingKind.FIELD_IN_SET:
            assert mapping.raw_field is not None
            assert mapping.values is not None
            value = raw_input[mapping.raw_field] in set(mapping.values)
        elif mapping.kind == MappingKind.FEATURE_ALL_TRUE:
            assert mapping.source_features is not None
            value = all(bool(features[source]) for source in mapping.source_features)
        elif mapping.kind == MappingKind.FEATURE_ANY_TRUE:
            assert mapping.source_features is not None
            value = any(bool(features[source]) for source in mapping.source_features)
        else:
            raise ValueError(f"unsupported mapping kind: {mapping.kind}")

        _validate_feature_output(value, feature, context=mapping.feature_id)
        if mapping.kind == MappingKind.FIELD_COPY:
            assert mapping.raw_field is not None
            _validate_copy_domain_alignment(
                value,
                raw_fields[mapping.raw_field],
                feature,
                context=mapping.feature_id,
            )
        features[mapping.feature_id] = value

    return features


def validate_feature_payload(features: dict[str, Any], contract: FeatureContract) -> None:
    known_features = {feature.id: feature for feature in contract.features}

    missing_features = sorted(set(known_features) - set(features))
    if missing_features:
        raise ValueError(f"feature payload is missing features: {', '.join(missing_features)}")

    unknown_features = sorted(set(features) - set(known_features))
    if unknown_features:
        raise ValueError(f"feature payload contains unknown features: {', '.join(unknown_features)}")

    for feature_id, feature in known_features.items():
        _validate_feature_output(features[feature_id], feature, context=feature_id)


def _validate_raw_input(raw_input: dict[str, Any], spec: ObserverSpec) -> None:
    raw_fields = {field.id: field for field in spec.raw_schema.fields}

    missing_required = sorted(
        field_id
        for field_id, field in raw_fields.items()
        if field.required and field_id not in raw_input
    )
    if missing_required:
        raise ValueError(f"raw input is missing required fields: {', '.join(missing_required)}")

    unknown_fields = sorted(set(raw_input) - set(raw_fields))
    if unknown_fields:
        raise ValueError(f"raw input contains unknown fields: {', '.join(unknown_fields)}")

    for field_id, value in raw_input.items():
        _validate_raw_value(value, raw_fields[field_id], context=field_id)


def _validate_raw_value(value: Any, field: RawFieldDefinition, *, context: str) -> None:
    if field.type == FeatureType.BOOL:
        if not isinstance(value, bool):
            raise ValueError(f"raw field {context} requires bool value")
        return

    if field.type == FeatureType.STRING:
        if not isinstance(value, str):
            raise ValueError(f"raw field {context} requires string value")
        return

    if field.type == FeatureType.ENUM:
        allowed_values = set(field.values or [])
        if value not in allowed_values:
            raise ValueError(f"raw field {context} uses unsupported enum value {value!r}")
        return

    if field.type in (FeatureType.INT, FeatureType.FLOAT):
        if not (isinstance(value, (int, float)) and not isinstance(value, bool)):
            raise ValueError(f"raw field {context} requires numeric value")
        if field.type == FeatureType.INT and not isinstance(value, int):
            raise ValueError(f"raw field {context} requires int value")
        if field.min is not None and value < field.min:
            raise ValueError(f"raw field {context} is below minimum {field.min}")
        if field.max is not None and value > field.max:
            raise ValueError(f"raw field {context} exceeds maximum {field.max}")
        return

    raise ValueError(f"raw field {context} uses unsupported type {field.type}")


def _validate_feature_output(value: Any, feature: FeatureDefinition, *, context: str) -> None:
    if feature.type == FeatureType.BOOL:
        if not isinstance(value, bool):
            raise ValueError(f"feature {context} requires bool value")
        return

    if feature.type == FeatureType.STRING:
        if not isinstance(value, str):
            raise ValueError(f"feature {context} requires string value")
        return

    if feature.type == FeatureType.ENUM:
        allowed_values = set(feature.values or [])
        if value not in allowed_values:
            raise ValueError(f"feature {context} uses unsupported enum value {value!r}")
        return

    if feature.type in (FeatureType.INT, FeatureType.FLOAT):
        if not (isinstance(value, (int, float)) and not isinstance(value, bool)):
            raise ValueError(f"feature {context} requires numeric value")
        if feature.type == FeatureType.INT and not isinstance(value, int):
            raise ValueError(f"feature {context} requires int value")
        if feature.min is not None and value < feature.min:
            raise ValueError(f"feature {context} is below minimum {feature.min}")
        if feature.max is not None and value > feature.max:
            raise ValueError(f"feature {context} exceeds maximum {feature.max}")
        return

    raise ValueError(f"feature {context} uses unsupported type {feature.type}")


def _validate_copy_domain_alignment(
    value: Any,
    raw_field: RawFieldDefinition,
    feature: FeatureDefinition,
    *,
    context: str,
) -> None:
    if raw_field.type != feature.type:
        raise ValueError(f"mapping {context} field_copy type mismatch at execution time")
    if raw_field.type == FeatureType.ENUM and value not in set(feature.values or []):
        raise ValueError(f"mapping {context} produced enum value outside feature domain")
