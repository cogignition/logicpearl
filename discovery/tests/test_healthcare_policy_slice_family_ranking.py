from logicpearl.domains.healthcare_policy.slice_family_ranking import rank_slice_family_documents


def test_rank_slice_family_documents_prefers_step_therapy_medication_policy() -> None:
    documents = [
        {
            "document_id": "doc-step",
            "filename": "041.pdf",
            "title_guess": "041 Diabetes Step Therapy",
            "document_kind": "medication_policy",
        },
        {
            "document_id": "doc-other",
            "filename": "003.pdf",
            "title_guess": "003 Some Other Policy",
            "document_kind": "medical_policy",
        },
    ]
    candidates = [
        {
            "document_id": "doc-step",
            "title": "041 Diabetes Step Therapy",
            "page_number": 1,
            "snippet": "Step therapy requires a first-line trial.",
            "candidate_kind": "step_therapy",
        },
        {
            "document_id": "doc-step",
            "title": "041 Diabetes Step Therapy",
            "page_number": 2,
            "snippet": "Prior authorization is also required.",
            "candidate_kind": "prior_auth",
        },
        {
            "document_id": "doc-other",
            "title": "003 Some Other Policy",
            "page_number": 1,
            "snippet": "Step therapy language appears once.",
            "candidate_kind": "step_therapy",
        },
    ]

    rankings = rank_slice_family_documents(documents=documents, candidates=candidates, top_n=2)

    assert rankings["step_therapy"][0].document_id == "doc-step"


def test_rank_slice_family_documents_prefers_diagnosis_docs_with_explicit_requires_diagnosis() -> None:
    documents = [
        {
            "document_id": "doc-a",
            "filename": "004.pdf",
            "title_guess": "004 Immune Modulating Drugs",
            "document_kind": "medication_policy",
        },
        {
            "document_id": "doc-b",
            "filename": "050.pdf",
            "title_guess": "050 Another Policy",
            "document_kind": "medical_policy",
        },
    ]
    candidates = [
        {
            "document_id": "doc-a",
            "title": "004 Immune Modulating Drugs",
            "page_number": 5,
            "snippet": "Enthesitis-Related Arthritis: Requires diagnosis only",
            "candidate_kind": "diagnosis_requirement",
        },
        {
            "document_id": "doc-b",
            "title": "050 Another Policy",
            "page_number": 3,
            "snippet": "Must have documented genetic test confirming diagnosis.",
            "candidate_kind": "diagnosis_requirement",
        },
    ]

    rankings = rank_slice_family_documents(documents=documents, candidates=candidates, top_n=2)

    assert rankings["diagnosis_requirement"][0].document_id == "doc-a"
