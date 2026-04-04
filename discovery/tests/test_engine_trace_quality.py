from logicpearl.engine import (
    TraceIssueCode,
    TraceQualityConfig,
    TraceTrustTier,
    assess_trace_quality,
    partition_traces_by_quality,
    summarize_trace_partition,
)


def test_assess_trace_quality_flags_invalid_label_and_missing_keys() -> None:
    report = assess_trace_quality(
        features={"a": 1.0},
        label="maybe",
        metadata={},
        config=TraceQualityConfig(
            required_feature_keys=frozenset({"a", "b"}),
            required_metadata_keys=frozenset({"trace_id"}),
        ),
    )

    assert report.trust_tier == TraceTrustTier.EXCLUDED
    assert {issue.code for issue in report.issues} == {
        TraceIssueCode.INVALID_LABEL,
        TraceIssueCode.MISSING_FEATURE,
        TraceIssueCode.MISSING_METADATA,
    }


def test_assess_trace_quality_quarantines_invalid_binary_and_source() -> None:
    report = assess_trace_quality(
        features={"flag": 0.5},
        label="allowed",
        metadata={"trace_source": "manual_override"},
        config=TraceQualityConfig(
            binary_feature_keys=frozenset({"flag"}),
            quarantined_sources=frozenset({"manual_override"}),
        ),
    )

    assert report.trust_tier == TraceTrustTier.QUARANTINED
    assert {issue.code for issue in report.issues} == {
        TraceIssueCode.INVALID_BINARY_VALUE,
        TraceIssueCode.QUARANTINED_SOURCE,
    }


def test_partition_traces_by_quality_separates_duplicate_and_excluded() -> None:
    traces = [
        ({"flag": 1.0}, "denied", {"trace_id": "A", "trace_source": "trusted"}),
        ({"flag": 1.0}, "denied", {"trace_id": "A", "trace_source": "trusted"}),
        ({"flag": 2.0}, "allowed", {"trace_id": "B", "trace_source": "trusted"}),
        ({"flag": 1.0}, "allowed", {"trace_id": "C", "trace_source": "bad_feed"}),
    ]

    partition = partition_traces_by_quality(
        traces,
        TraceQualityConfig(
            trace_id_key="trace_id",
            source_key="trace_source",
            binary_feature_keys=frozenset({"flag"}),
            excluded_sources=frozenset({"bad_feed"}),
        ),
    )

    summary = summarize_trace_partition(partition)

    assert summary == {
        "trusted": 1,
        "quarantined": 2,
        "excluded": 1,
        "duplicate_ids": ["A"],
    }
