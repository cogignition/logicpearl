from logicpearl.domains.healthcare_policy.slice_candidates import (
    SliceCandidateKind,
    classify_candidate_paragraph,
    extract_slice_candidates,
    extract_slice_candidates_from_sections,
    split_extracted_text_by_page,
)


def test_split_extracted_text_by_page_preserves_page_numbers() -> None:
    payload = """=== Page 1 ===
Medical Policy
Some text here.

=== Page 2 ===
Prior Authorization Information
More text here.
"""

    assert split_extracted_text_by_page(payload) == [
        (1, "Medical Policy\nSome text here."),
        (2, "Prior Authorization Information\nMore text here."),
    ]


def test_classify_candidate_paragraph_identifies_step_therapy() -> None:
    kind, pattern = classify_candidate_paragraph(
        "041 Diabetes Step Therapy",
        "Step therapy requires trial of a first-line agent before coverage of the requested medication.",
    )

    assert kind is SliceCandidateKind.STEP_THERAPY
    assert "step therapy" in pattern


def test_classify_candidate_paragraph_identifies_diagnosis_requirement() -> None:
    kind, pattern = classify_candidate_paragraph(
        "Immune Modulating Drugs",
        "Enthesitis-Related Arthritis: Requires diagnosis only.",
    )

    assert kind is SliceCandidateKind.DIAGNOSIS_REQUIREMENT
    assert "requires diagnosis" in pattern


def test_extract_slice_candidates_returns_typed_candidates() -> None:
    payload = """=== Page 1 ===
Medical Policy

The member must complete physical therapy before the requested procedure.

Documentation should include prior treatment dates and the ordering physician.
"""

    candidates = extract_slice_candidates(
        document_id="demo-doc",
        filename="demo.pdf",
        title="Demo Policy",
        document_kind="medical_policy",
        extracted_text=payload,
    )

    assert len(candidates) == 2
    assert candidates[0].candidate_kind == SliceCandidateKind.PHYSICAL_THERAPY_PREREQ
    assert candidates[1].candidate_kind == SliceCandidateKind.DOCUMENTATION_REQUIREMENT
    assert all(candidate.page_number == 1 for candidate in candidates)
    assert all(candidate.source_section_kind == "full_document" for candidate in candidates)


def test_extract_slice_candidates_from_sections_ignores_non_decision_sections() -> None:
    sections = [
        {
            "section_kind": "policy_history",
            "page_start": 2,
            "text": "Policy History Step therapy language in history should not be used.",
        },
        {
            "section_kind": "policy",
            "page_start": 1,
            "text": "Step therapy requires a first-line trial before the requested medication.",
        },
    ]

    candidates = extract_slice_candidates_from_sections(
        document_id="demo-doc",
        filename="demo.pdf",
        title="Demo Policy",
        document_kind="medical_policy",
        sections=sections,
    )

    assert len(candidates) == 1
    assert candidates[0].candidate_kind == SliceCandidateKind.STEP_THERAPY
    assert candidates[0].source_section_kind == "policy"
    assert candidates[0].source_section_heading == "policy"


def test_classify_candidate_paragraph_identifies_workflow_admin() -> None:
    kind, pattern = classify_candidate_paragraph(
        "Carelon Oncology Medication Management Program",
        "This program uses a prior authorization request form and services management workflow for operational routing.",
    )

    assert kind is SliceCandidateKind.WORKFLOW_ADMIN
    assert "request form" in pattern or "services management" in pattern
