from logicpearl.domains.healthcare_policy.assembly import assemble_draft_logic_specs
from logicpearl.domains.healthcare_policy.finalization import assemble_final_logic_spec


def test_assemble_final_logic_spec_uses_reviewed_mappings_and_selection() -> None:
    specs = assemble_draft_logic_specs(
        documents=[
            {
                "document_id": "004-immune-modulating-drugs-prn",
                "filename": "004.pdf",
                "title_guess": "004 Immune Modulating Drugs prn",
                "document_kind": "medication_policy",
                "source_url": "https://example.com/004.pdf",
            }
        ],
        requirement_records=[
            {
                "requirement_id": "req-1",
                "document_id": "004-immune-modulating-drugs-prn",
                "requirement_family": "diagnosis_requirement",
                "cluster_placeholder_id": "diagnosis_requirement__qualifying_diagnosis",
                "status": "normalized",
                "source_snippet": "Enthesitis-Related Arthritis: Requires diagnosis only.",
                "source_section_heading": "Policy",
                "page_number": 2,
                "evidence_hint": "qualifying_diagnosis",
            }
        ],
        cluster_mappings=[
            {
                "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
                "label": "Diagnosis Requirement: qualifying diagnosis",
                "alias_candidates": [{"alias": "Enthesitis-Related Arthritis", "count": 1}],
            }
        ],
        ranked_examples={"diagnosis_requirement": {"document_id": "004-immune-modulating-drugs-prn"}},
    )

    final_spec = assemble_final_logic_spec(
        specs[0],
        reviewed_cluster_mappings=[
            {
                "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
                "label": "Diagnosis Requirement: qualifying diagnosis",
                "kind": "diagnosis",
                "aliases": ["Enthesitis-Related Arthritis"],
                "codes": ["DIAGNOSIS__DIAGNOSIS_REQUIREMENT_QUALIFYING_DIAGNOSIS__ENTHESITIS_RELATED_ARTHRITIS"],
            }
        ],
        requirement_selections=[
            {
                "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
                "selected_requirement_id": "req-1",
            }
        ],
    )

    assert final_spec.provenance.review_status == "approved"
    assert final_spec.clusters[0].codes == [
        "DIAGNOSIS__DIAGNOSIS_REQUIREMENT_QUALIFYING_DIAGNOSIS__ENTHESITIS_RELATED_ARTHRITIS"
    ]
    assert final_spec.requirements[0].review_status == "approved"
