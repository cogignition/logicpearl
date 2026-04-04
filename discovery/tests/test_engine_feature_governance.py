from logicpearl.engine import (
    FeatureTier,
    classify_feature_tier,
    compute_feature_governance_report,
    should_scan_feature,
)


def test_classify_feature_tier_detects_interactions() -> None:
    assert classify_feature_tier("duplicate_no_bypass_mod") == FeatureTier.BASE
    assert classify_feature_tier("x_is_em_x_line_ge_6") == FeatureTier.INTERACTION


def test_compute_feature_governance_report_keeps_informative_interactions() -> None:
    features = []
    labels = []

    for _ in range(30):
        features.append({"a": 1.0, "b": 1.0, "x_a_x_b": 1.0})
        labels.append(0)
    for _ in range(30):
        features.append({"a": 1.0, "b": 0.0, "x_a_x_b": 0.0})
        labels.append(1)
    for _ in range(20):
        features.append({"a": 0.0, "b": 1.0, "x_a_x_b": 0.0})
        labels.append(1)

    report = compute_feature_governance_report(
        features,
        labels,
    )

    assert "x_a_x_b" in report.selected_interactions
    assert report.feature_tiers["x_a_x_b"] == FeatureTier.INTERACTION


def test_high_precision_scan_is_stricter_for_interactions() -> None:
    assert should_scan_feature("high_cost_no_auth", denied_hits=50, precision=0.96)
    assert not should_scan_feature("x_is_em_x_line_ge_6", denied_hits=400, precision=0.98)
    assert should_scan_feature("x_duplicate_code_on_claim_x_line_ge_6", denied_hits=800, precision=0.999)
    assert should_scan_feature("is_new_patient_em", denied_hits=20, precision=1.0, allowed_hits=0)
