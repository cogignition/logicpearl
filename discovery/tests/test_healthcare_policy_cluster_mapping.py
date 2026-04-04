from logicpearl.domains.healthcare_policy.cluster_mapping import (
    build_cluster_mapping_records,
    summarize_cluster_mapping_status,
)


def test_build_cluster_mapping_records_groups_requirements() -> None:
    records = [
        {
            "requirement_id": "req-1",
            "cluster_placeholder_id": "physical_therapy_prereq__prior_physical_therapy",
            "normalized_statement": "The member must complete physical therapy before surgery.",
        },
        {
            "requirement_id": "req-2",
            "cluster_placeholder_id": "physical_therapy_prereq__prior_physical_therapy",
            "normalized_statement": "The member has documented failure of physical therapy.",
        },
    ]

    mappings = build_cluster_mapping_records(records)

    assert len(mappings) == 1
    assert mappings[0].cluster_id == "physical_therapy_prereq__prior_physical_therapy"
    assert mappings[0].source_requirement_count == 2
    assert mappings[0].alias_candidates[0].alias == "physical therapy"


def test_build_cluster_mapping_records_extracts_clean_diagnosis_aliases() -> None:
    records = [
        {
            "requirement_id": "req-1",
            "cluster_placeholder_id": "diagnosis_requirement__qualifying_diagnosis",
            "normalized_statement": "Cosentyx • Ankylosing Spondylitis • Enthesitis-Related Arthritis: Requires diagnosis only.",
        }
    ]

    mappings = build_cluster_mapping_records(records)

    aliases = [candidate.alias for candidate in mappings[0].alias_candidates]
    assert "Enthesitis-Related Arthritis" in aliases


def test_summarize_cluster_mapping_status_counts_candidates() -> None:
    mappings = build_cluster_mapping_records(
        [
            {
                "requirement_id": "req-1",
                "cluster_placeholder_id": "step_therapy__trial_of_formulary_alternatives",
                "normalized_statement": "Step therapy criteria has been met with formulary alternatives.",
            }
        ]
    )
    summary = summarize_cluster_mapping_status(mappings)

    assert summary["candidate"] == 1
