from logicpearl.domains.healthcare_policy.assembly import assemble_draft_logic_specs


def test_assemble_draft_logic_specs_builds_slice_from_ranked_example() -> None:
    documents = [
        {
            "document_id": "004-immune-modulating-drugs-prn",
            "filename": "004.pdf",
            "title_guess": "004 Immune Modulating Drugs prn",
            "document_kind": "medication_policy",
            "source_url": "https://example.com/004.pdf",
        }
    ]
    requirement_records = [
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
    ]
    cluster_mappings = [
        {
            "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
            "label": "Diagnosis Requirement: qualifying diagnosis",
            "alias_candidates": [{"alias": "Enthesitis-Related Arthritis", "count": 1}],
        }
    ]
    ranked_examples = {
        "diagnosis_requirement": {
            "document_id": "004-immune-modulating-drugs-prn",
        }
    }

    specs = assemble_draft_logic_specs(
        documents=documents,
        requirement_records=requirement_records,
        cluster_mappings=cluster_mappings,
        ranked_examples=ranked_examples,
    )

    assert len(specs) == 1
    assert specs[0].requirements[0].cluster_id == "diagnosis_requirement__qualifying_diagnosis"
    assert specs[0].clusters[0].aliases == ["Enthesitis-Related Arthritis"]
    assert specs[0].adapted_for_demo is False


def test_assemble_draft_logic_specs_builds_all_document_family_specs_when_not_ranked() -> None:
    documents = [
        {
            "document_id": "004-immune-modulating-drugs-prn",
            "filename": "004.pdf",
            "title_guess": "004 Immune Modulating Drugs prn",
            "document_kind": "medication_policy",
            "source_url": "https://example.com/004.pdf",
        },
        {
            "document_id": "120-example-policy-prn",
            "filename": "120.pdf",
            "title_guess": "120 Example Policy prn",
            "document_kind": "medical_policy",
            "source_url": "https://example.com/120.pdf",
        },
    ]
    requirement_records = [
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
        },
        {
            "requirement_id": "req-2",
            "document_id": "120-example-policy-prn",
            "requirement_family": "physical_therapy_prereq",
            "cluster_placeholder_id": "physical_therapy_prereq__prior_physical_therapy",
            "status": "normalized",
            "source_snippet": "Member must complete prior physical therapy.",
            "source_section_heading": "Policy",
            "page_number": 1,
            "evidence_hint": "prior_physical_therapy",
        },
    ]
    cluster_mappings = [
        {
            "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
            "label": "Diagnosis Requirement: qualifying diagnosis",
            "alias_candidates": [{"alias": "Enthesitis-Related Arthritis", "count": 1}],
        },
        {
            "cluster_id": "physical_therapy_prereq__prior_physical_therapy",
            "label": "Physical Therapy: prior physical therapy",
            "alias_candidates": [{"alias": "physical therapy", "count": 1}],
        },
    ]

    specs = assemble_draft_logic_specs(
        documents=documents,
        requirement_records=requirement_records,
        cluster_mappings=cluster_mappings,
    )

    assert [spec.policy_id for spec in specs] == [
        "bcbsma_diagnosis_requirement_004_immune_modulating_drugs_prn",
        "bcbsma_physical_therapy_prereq_120_example_policy_prn",
    ]
