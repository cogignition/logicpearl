from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TraceTrustTier(str, Enum):
    TRUSTED = "trusted"
    QUARANTINED = "quarantined"
    EXCLUDED = "excluded"


class TraceIssueCode(str, Enum):
    INVALID_LABEL = "invalid_label"
    MISSING_FEATURE = "missing_feature"
    MISSING_METADATA = "missing_metadata"
    NON_NUMERIC_FEATURE = "non_numeric_feature"
    NAN_FEATURE = "nan_feature"
    INVALID_BINARY_VALUE = "invalid_binary_value"
    DUPLICATE_TRACE_ID = "duplicate_trace_id"
    QUARANTINED_SOURCE = "quarantined_source"
    EXCLUDED_SOURCE = "excluded_source"


@dataclass(frozen=True)
class TraceQualityIssue:
    code: TraceIssueCode
    detail: str
    severity: TraceTrustTier


@dataclass(frozen=True)
class TraceQualityConfig:
    allowed_labels: frozenset[str] = frozenset({"allowed", "denied"})
    required_feature_keys: frozenset[str] = frozenset()
    required_metadata_keys: frozenset[str] = frozenset()
    binary_feature_keys: frozenset[str] = frozenset()
    trace_id_key: str | None = None
    source_key: str | None = "trace_source"
    trusted_sources: frozenset[str] = frozenset()
    quarantined_sources: frozenset[str] = frozenset()
    excluded_sources: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TraceQualityReport:
    trust_tier: TraceTrustTier
    score: float
    issues: tuple[TraceQualityIssue, ...]


@dataclass(frozen=True)
class TracePartition:
    trusted: tuple[tuple[dict[str, float], str, dict[str, Any]], ...]
    quarantined: tuple[tuple[dict[str, float], str, dict[str, Any]], ...]
    excluded: tuple[tuple[dict[str, float], str, dict[str, Any]], ...]
    reports: tuple[TraceQualityReport, ...]
    duplicate_ids: tuple[str, ...] = field(default_factory=tuple)


def assess_trace_quality(
    features: dict[str, Any],
    label: str,
    metadata: dict[str, Any],
    config: TraceQualityConfig | None = None,
    *,
    duplicate_trace_ids: set[str] | None = None,
) -> TraceQualityReport:
    if config is None:
        config = TraceQualityConfig()

    issues: list[TraceQualityIssue] = []

    if label not in config.allowed_labels:
        issues.append(
            TraceQualityIssue(
                code=TraceIssueCode.INVALID_LABEL,
                detail=f"unexpected label: {label}",
                severity=TraceTrustTier.EXCLUDED,
            )
        )

    for key in sorted(config.required_feature_keys):
        if key not in features:
            issues.append(
                TraceQualityIssue(
                    code=TraceIssueCode.MISSING_FEATURE,
                    detail=key,
                    severity=TraceTrustTier.EXCLUDED,
                )
            )

    for key in sorted(config.required_metadata_keys):
        if key not in metadata:
            issues.append(
                TraceQualityIssue(
                    code=TraceIssueCode.MISSING_METADATA,
                    detail=key,
                    severity=TraceTrustTier.EXCLUDED,
                )
            )

    for key, value in features.items():
        if not isinstance(value, (int, float)):
            issues.append(
                TraceQualityIssue(
                    code=TraceIssueCode.NON_NUMERIC_FEATURE,
                    detail=key,
                    severity=TraceTrustTier.EXCLUDED,
                )
            )
            continue
        if math.isnan(float(value)):
            issues.append(
                TraceQualityIssue(
                    code=TraceIssueCode.NAN_FEATURE,
                    detail=key,
                    severity=TraceTrustTier.EXCLUDED,
                )
            )
            continue
        if key in config.binary_feature_keys and float(value) not in (0.0, 1.0):
            issues.append(
                TraceQualityIssue(
                    code=TraceIssueCode.INVALID_BINARY_VALUE,
                    detail=f"{key}={value}",
                    severity=TraceTrustTier.QUARANTINED,
                )
            )

    if config.trace_id_key:
        trace_id = metadata.get(config.trace_id_key)
        if trace_id is not None and duplicate_trace_ids and str(trace_id) in duplicate_trace_ids:
            issues.append(
                TraceQualityIssue(
                    code=TraceIssueCode.DUPLICATE_TRACE_ID,
                    detail=str(trace_id),
                    severity=TraceTrustTier.QUARANTINED,
                )
            )

    if config.source_key:
        source = metadata.get(config.source_key)
        if source is not None:
            source_str = str(source)
            if source_str in config.excluded_sources:
                issues.append(
                    TraceQualityIssue(
                        code=TraceIssueCode.EXCLUDED_SOURCE,
                        detail=source_str,
                        severity=TraceTrustTier.EXCLUDED,
                    )
                )
            elif source_str in config.quarantined_sources:
                issues.append(
                    TraceQualityIssue(
                        code=TraceIssueCode.QUARANTINED_SOURCE,
                        detail=source_str,
                        severity=TraceTrustTier.QUARANTINED,
                    )
                )

    trust_tier = _worst_severity(issues)
    score = _quality_score(issues)
    return TraceQualityReport(
        trust_tier=trust_tier,
        score=score,
        issues=tuple(issues),
    )


def partition_traces_by_quality(
    traces: list[tuple[dict[str, Any], str, dict[str, Any]]],
    config: TraceQualityConfig | None = None,
) -> TracePartition:
    if config is None:
        config = TraceQualityConfig()

    duplicate_ids = _find_duplicate_trace_ids(traces, config.trace_id_key)
    seen_trace_ids: set[str] = set()
    trusted: list[tuple[dict[str, float], str, dict[str, Any]]] = []
    quarantined: list[tuple[dict[str, float], str, dict[str, Any]]] = []
    excluded: list[tuple[dict[str, float], str, dict[str, Any]]] = []
    reports: list[TraceQualityReport] = []

    for features, label, metadata in traces:
        report = assess_trace_quality(
            features,
            label,
            metadata,
            config,
            duplicate_trace_ids=_current_duplicate_ids(metadata, config.trace_id_key, duplicate_ids, seen_trace_ids),
        )
        reports.append(report)
        coerced = ({key: float(value) for key, value in features.items() if isinstance(value, (int, float))}, label, metadata)
        if report.trust_tier == TraceTrustTier.TRUSTED:
            trusted.append(coerced)
        elif report.trust_tier == TraceTrustTier.QUARANTINED:
            quarantined.append(coerced)
        else:
            excluded.append(coerced)
        _mark_trace_id_seen(metadata, config.trace_id_key, seen_trace_ids)

    return TracePartition(
        trusted=tuple(trusted),
        quarantined=tuple(quarantined),
        excluded=tuple(excluded),
        reports=tuple(reports),
        duplicate_ids=tuple(sorted(duplicate_ids)),
    )


def summarize_trace_partition(partition: TracePartition) -> dict[str, Any]:
    return {
        "trusted": len(partition.trusted),
        "quarantined": len(partition.quarantined),
        "excluded": len(partition.excluded),
        "duplicate_ids": list(partition.duplicate_ids),
    }


def _find_duplicate_trace_ids(
    traces: list[tuple[dict[str, Any], str, dict[str, Any]]],
    trace_id_key: str | None,
) -> set[str]:
    if not trace_id_key:
        return set()

    seen: set[str] = set()
    duplicates: set[str] = set()
    for _features, _label, metadata in traces:
        trace_id = metadata.get(trace_id_key)
        if trace_id is None:
            continue
        trace_id_str = str(trace_id)
        if trace_id_str in seen:
            duplicates.add(trace_id_str)
        else:
            seen.add(trace_id_str)
    return duplicates


def _current_duplicate_ids(
    metadata: dict[str, Any],
    trace_id_key: str | None,
    duplicate_ids: set[str],
    seen_trace_ids: set[str],
) -> set[str]:
    if not trace_id_key:
        return set()
    trace_id = metadata.get(trace_id_key)
    if trace_id is None:
        return set()
    trace_id_str = str(trace_id)
    if trace_id_str in duplicate_ids and trace_id_str in seen_trace_ids:
        return {trace_id_str}
    return set()


def _mark_trace_id_seen(
    metadata: dict[str, Any],
    trace_id_key: str | None,
    seen_trace_ids: set[str],
) -> None:
    if not trace_id_key:
        return
    trace_id = metadata.get(trace_id_key)
    if trace_id is None:
        return
    seen_trace_ids.add(str(trace_id))


def _worst_severity(issues: list[TraceQualityIssue]) -> TraceTrustTier:
    if any(issue.severity == TraceTrustTier.EXCLUDED for issue in issues):
        return TraceTrustTier.EXCLUDED
    if any(issue.severity == TraceTrustTier.QUARANTINED for issue in issues):
        return TraceTrustTier.QUARANTINED
    return TraceTrustTier.TRUSTED


def _quality_score(issues: list[TraceQualityIssue]) -> float:
    score = 1.0
    for issue in issues:
        if issue.severity == TraceTrustTier.EXCLUDED:
            score -= 0.5
        elif issue.severity == TraceTrustTier.QUARANTINED:
            score -= 0.2
    return max(0.0, round(score, 3))
