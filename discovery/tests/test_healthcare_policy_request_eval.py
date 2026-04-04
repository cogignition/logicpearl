from logicpearl.domains.healthcare_policy.assembly import assemble_draft_logic_specs
from logicpearl.domains.healthcare_policy.compiler import compile_healthcare_policy_to_gate_ir
from logicpearl.domains.healthcare_policy.finalization import assemble_final_logic_spec
from logicpearl.domains.healthcare_policy.models import ClinicalEvent, ClinicalEventType
from logicpearl.domains.healthcare_policy.request_eval import (
    CandidateAssertion,
    DocumentationStatus,
    EvidenceDocument,
    HealthcarePolicyRequest,
    MemberEvidence,
    PolicyContext,
    PolicySourceRef,
    RequestContext,
    RequestedService,
    RoutingStatus,
    evaluate_request_against_policy,
    extract_candidate_assertions,
    prepare_request_evidence,
    review_candidate_assertions,
)


def _final_spec():
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
    return assemble_final_logic_spec(
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


def test_extract_candidate_assertions_finds_alias_in_freeform_note() -> None:
    policy = _final_spec()
    candidates = extract_candidate_assertions(
        policy,
        [
            EvidenceDocument(
                document_id="note-1",
                kind="clinical_note",
                text="Clinical history shows enthesitis-related arthritis documented by rheumatology.",
                source="ehr",
                citation="note-1#line-1",
            )
        ],
    )

    assert len(candidates) == 1
    assert candidates[0].cluster_id == "diagnosis_requirement__qualifying_diagnosis"
    assert candidates[0].citation == "note-1#line-1"


def test_extract_candidate_assertions_ignores_policy_title_without_evidence_context() -> None:
    policy = _final_spec()
    candidates = extract_candidate_assertions(
        policy,
        [
            EvidenceDocument(
                document_id="note-blank",
                kind="fax_packet",
                text="Faxed packet summary for Requested Drug. Member record includes no clinical detail.",
                source="fax_gateway",
                citation="fax#line-1",
            )
        ],
    )

    assert candidates == []


def test_review_candidate_assertions_uses_trust_signals() -> None:
    policy = _final_spec()
    reviewed = review_candidate_assertions(
        policy,
        [
            CandidateAssertion(
                assertion_id="a1",
                cluster_id="diagnosis_requirement__qualifying_diagnosis",
                value="present",
                confidence=0.78,
                source_document_id="doc-1",
                source_snippet="Diagnosis documented.",
                citation="doc-1#line-1",
                extractor="llm_observer_v1",
            ),
            CandidateAssertion(
                assertion_id="a2",
                cluster_id="diagnosis_requirement__qualifying_diagnosis",
                value="present",
                confidence=0.72,
                source_document_id="doc-2",
                source_snippet="Diagnosis documented in another note.",
                citation="doc-2#line-1",
                extractor="llm_observer_v1",
            ),
            CandidateAssertion(
                assertion_id="a3",
                cluster_id="diagnosis_requirement__qualifying_diagnosis",
                value="present",
                confidence=0.55,
                source_document_id="doc-1",
                source_snippet="Possible diagnosis documented.",
                extractor="llm_observer_v1",
            ),
        ],
    )

    assert reviewed[0].status == "accepted"
    assert "has_citation" in reviewed[0].trust_signals
    assert "multi_document_corroboration" in reviewed[0].trust_signals
    assert reviewed[1].status == "accepted"
    assert reviewed[2].status == "ambiguous"


def test_evaluate_request_against_policy_uses_reviewed_assertion_when_no_structured_event() -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)
    reviewed = review_candidate_assertions(
        policy,
        [
            CandidateAssertion(
                assertion_id="a1",
                cluster_id="diagnosis_requirement__qualifying_diagnosis",
                value="present",
                confidence=0.95,
                source_document_id="note-1",
                source_snippet="Patient has enthesitis-related arthritis.",
                extractor="llm_observer_v1",
            )
        ]
    )
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-123",
            payer="BCBSMA",
            member_id="member-1",
            requested_service=RequestedService(kind="drug", code="NDC-1", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[],
            unstructured_documents=[
                EvidenceDocument(
                    document_id="note-1",
                    kind="clinical_note",
                    text="Patient has enthesitis-related arthritis.",
                    source="ehr",
                )
            ],
            candidate_assertions=[],
            reviewed_assertions=reviewed,
        ),
    )

    response = evaluate_request_against_policy(policy, request, gate=gate)

    assert response.questions[0].status == "found"
    assert response.summary.bitmask == 0


def test_evaluate_request_against_policy_marks_ambiguous_when_only_ambiguous_assertion_exists() -> None:
    policy = _final_spec()
    reviewed = review_candidate_assertions(
        policy,
        [
            CandidateAssertion(
                assertion_id="a1",
                cluster_id="diagnosis_requirement__qualifying_diagnosis",
                value="present",
                confidence=0.6,
                source_document_id="note-1",
                source_snippet="Possible diagnosis documented.",
                citation="note-1#line-1",
                extractor="llm_observer_v1",
            )
        ]
    )
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-124",
            payer="BCBSMA",
            member_id="member-2",
            requested_service=RequestedService(kind="drug", code="NDC-2", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[],
            unstructured_documents=[],
            candidate_assertions=[],
            reviewed_assertions=reviewed,
        ),
    )

    response = evaluate_request_against_policy(policy, request)

    assert response.questions[0].status == "ambiguous"
    assert response.summary.ambiguous_question_ids == ["q1"]


def test_prepare_request_evidence_auto_extracts_and_reviews_from_docs() -> None:
    policy = _final_spec()
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-124a",
            payer="BCBSMA",
            member_id="member-2",
            requested_service=RequestedService(kind="drug", code="NDC-2", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[],
            unstructured_documents=[
                EvidenceDocument(
                    document_id="note-1",
                    kind="clinical_note",
                    text="Patient is diagnosed with Enthesitis-Related Arthritis.",
                    source="ehr",
                    citation="note-1#line-1",
                )
            ],
            candidate_assertions=[],
            reviewed_assertions=[],
        ),
    )

    prepared = prepare_request_evidence(policy, request)

    assert len(prepared.member_evidence.candidate_assertions) == 1
    assert len(prepared.member_evidence.reviewed_assertions) == 1
    assert prepared.member_evidence.reviewed_assertions[0].status == "accepted"


def test_evaluate_request_against_policy_prefers_structured_event() -> None:
    policy = _final_spec()
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-125",
            payer="BCBSMA",
            member_id="member-3",
            requested_service=RequestedService(kind="drug", code="NDC-3", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[
                ClinicalEvent(
                    event_id="claim-1",
                    event_type=ClinicalEventType.DIAGNOSIS,
                    code="DIAGNOSIS__DIAGNOSIS_REQUIREMENT_QUALIFYING_DIAGNOSIS__ENTHESITIS_RELATED_ARTHRITIS",
                    label="Enthesitis-related arthritis",
                    source="claims",
                )
            ],
            unstructured_documents=[],
            candidate_assertions=[],
            reviewed_assertions=[],
        ),
    )

    response = evaluate_request_against_policy(policy, request)

    assert response.questions[0].status == "found"
    assert response.questions[0].matched_evidence[0].source == "claims"


def test_evaluate_request_against_policy_marks_missing_required_documentation() -> None:
    policy = _final_spec()
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-126",
            payer="BCBSMA",
            member_id="member-4",
            requested_service=RequestedService(kind="drug", code="NDC-4", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[],
            unstructured_documents=[],
            candidate_assertions=[],
            reviewed_assertions=[],
        ),
    )

    response = evaluate_request_against_policy(policy, request)

    assert response.questions[0].documentation_status == DocumentationStatus.MISSING_REQUIRED_DOCUMENTATION
    assert response.summary.route_status == RoutingStatus.MISSING_REQUIRED_DOCUMENTATION
    assert response.summary.documentation_complete is False
    assert response.review_packet.missing_documentation[0].required_document_kinds


def test_healthcare_request_harmonizes_top_level_bundle_shape() -> None:
    policy = _final_spec()
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-127",
            payer="BCBSMA",
            member_id="member-5",
            requested_service=RequestedService(kind="drug", code="NDC-5", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        clinical_documents=[
            EvidenceDocument(
                document_id="portal-form-1",
                kind="prior_auth_form",
                text="Structured portal submission.",
                source="provider_portal",
            ),
            EvidenceDocument(
                document_id="note-5",
                kind="office_note",
                text="Clinical history shows enthesitis-related arthritis documented by rheumatology.",
                source="ehr",
                citation="note-5#line-1",
            ),
        ],
    )

    response = evaluate_request_against_policy(policy, request)

    assert request.member_evidence.unstructured_documents[0].document_id == "portal-form-1"
    assert response.review_packet.organized_documents[0].kind == "prior_auth_form"
    assert response.case_summary.clinical_document_count == 2
