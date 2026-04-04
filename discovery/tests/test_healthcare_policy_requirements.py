from logicpearl.domains.healthcare_policy.requirements import (
    RequirementStatus,
    normalize_requirement_candidate,
)


def test_normalize_requirement_candidate_builds_stable_record() -> None:
    candidate = {
        "candidate_id": "doc-p1-001",
        "document_id": "doc",
        "filename": "004.pdf",
        "title": "004 Immune Modulating Drugs",
        "document_kind": "medication_policy",
        "page_number": 2,
        "source_section_kind": "policy",
        "source_section_heading": "Policy",
        "candidate_kind": "diagnosis_requirement",
        "snippet": "Enthesitis-Related Arthritis: Requires diagnosis only",
    }

    record = normalize_requirement_candidate(candidate)

    assert record.requirement_id == "req-doc-p1-001"
    assert record.evidence_hint == "qualifying_diagnosis"
    assert record.cluster_placeholder_id == "diagnosis_requirement__qualifying_diagnosis"
    assert record.status == RequirementStatus.NORMALIZED


def test_normalize_requirement_candidate_marks_lower_confidence_items_for_review() -> None:
    candidate = {
        "candidate_id": "doc-p1-002",
        "document_id": "doc",
        "filename": "003.pdf",
        "title": "003 Policy",
        "document_kind": "medical_policy",
        "page_number": 1,
        "source_section_kind": "summary",
        "source_section_heading": "Summary",
        "candidate_kind": "prior_auth",
        "snippet": "Prior Authorization may apply in some circumstances",
    }

    record = normalize_requirement_candidate(candidate)

    assert record.confidence < 0.75
    assert record.status == RequirementStatus.NEEDS_REVIEW
