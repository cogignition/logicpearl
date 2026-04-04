from logicpearl.domains.healthcare_policy.assembly import assemble_draft_logic_specs
from logicpearl.domains.healthcare_policy.review import (
    build_requirement_selection_records,
    review_cluster_mapping_records,
)


def test_review_cluster_mapping_records_materializes_codes() -> None:
    reviewed = review_cluster_mapping_records(
        [
            {
                "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
                "family": "diagnosis_requirement",
                "evidence_hint": "qualifying_diagnosis",
                "label": "Diagnosis Requirement: qualifying diagnosis",
                "source_requirement_count": 1,
                "source_requirement_ids": ["req-1"],
                "alias_candidates": [{"alias": "Enthesitis-Related Arthritis", "count": 1}],
            }
        ]
    )

    assert reviewed[0].kind == "diagnosis"
    assert reviewed[0].aliases == ["Enthesitis-Related Arthritis"]
    assert reviewed[0].codes == [
        "DIAGNOSIS__DIAGNOSIS_REQUIREMENT_QUALIFYING_DIAGNOSIS__ENTHESITIS_RELATED_ARTHRITIS"
    ]


def test_build_requirement_selection_records_chooses_best_requirement_per_cluster() -> None:
    specs = assemble_draft_logic_specs(
        documents=[
            {
                "document_id": "041-diabetes-step-therapy-prn",
                "filename": "041.pdf",
                "title_guess": "041 Diabetes Step Therapy prn",
                "document_kind": "medication_policy",
                "source_url": "https://example.com/041.pdf",
            }
        ],
        requirement_records=[
            {
                "requirement_id": "req-1",
                "document_id": "041-diabetes-step-therapy-prn",
                "requirement_family": "step_therapy",
                "cluster_placeholder_id": "step_therapy__prior_trial_of_step_therapy_medication",
                "status": "normalized",
                "source_snippet": "Step therapy requirement in policy section.",
                "source_section_heading": "Policy",
                "page_number": 1,
                "evidence_hint": "prior_trial_of_step_therapy_medication",
            },
            {
                "requirement_id": "req-2",
                "document_id": "041-diabetes-step-therapy-prn",
                "requirement_family": "step_therapy",
                "cluster_placeholder_id": "step_therapy__prior_trial_of_step_therapy_medication",
                "status": "normalized",
                "source_snippet": "Step therapy summary wording.",
                "source_section_heading": "Summary",
                "page_number": 2,
                "evidence_hint": "prior_trial_of_step_therapy_medication",
            },
        ],
        cluster_mappings=[
            {
                "cluster_id": "step_therapy__prior_trial_of_step_therapy_medication",
                "label": "Step Therapy: prior trial of step therapy medication",
                "alias_candidates": [{"alias": "step therapy", "count": 2}],
            }
        ],
        ranked_examples={"step_therapy": {"document_id": "041-diabetes-step-therapy-prn"}},
    )

    selections = build_requirement_selection_records(
        specs[0],
        requirement_records=[
            {"requirement_id": "req-1", "confidence": 0.9, "source_section_heading": "Policy"},
            {"requirement_id": "req-2", "confidence": 0.7, "source_section_heading": "Summary"},
        ],
    )

    assert len(selections) == 1
    assert selections[0].selected_requirement_id == "req-1"
    assert selections[0].rejected_requirement_ids == ["req-2"]
