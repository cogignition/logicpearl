from logicpearl.domains.healthcare_policy.assembly import assemble_draft_logic_specs
from logicpearl.domains.healthcare_policy.curation import curate_healthcare_policy_slice


def test_curate_healthcare_policy_slice_collapses_duplicate_cluster_requirements() -> None:
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

    curated = curate_healthcare_policy_slice(
        specs[0],
        requirement_records=[
            {"requirement_id": "req-1", "confidence": 0.9, "source_section_heading": "Policy"},
            {"requirement_id": "req-2", "confidence": 0.7, "source_section_heading": "Summary"},
        ],
    )

    assert len(curated.requirements) == 1
    assert curated.requirements[0].requirement_id == "req-1"
