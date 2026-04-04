from logicpearl.domains.healthcare_policy.mapping_validation import (
    build_mapping_validation_fixtures,
    validate_cluster_mappings,
)

from test_healthcare_policy_request_eval import _final_spec


def test_mapping_validation_builds_positive_and_negative_controls() -> None:
    policy = _final_spec()
    fixtures = build_mapping_validation_fixtures(policy)

    assert len(fixtures) == 6
    fixture_kinds = {str(fixture.kind) for fixture in fixtures}
    assert fixture_kinds == {
        "positive_clear",
        "positive_code_only",
        "positive_alias_only",
        "negative_boilerplate",
        "negative_future_plan",
        "ambiguous_weak_evidence",
    }


def test_mapping_validation_suite_passes_for_simple_policy() -> None:
    policy = _final_spec()
    fixtures = build_mapping_validation_fixtures(policy)
    suite = validate_cluster_mappings(policy, fixtures)

    assert suite.fixture_count == 6
    assert suite.failed_count == 0
    assert suite.passed_count == 6
