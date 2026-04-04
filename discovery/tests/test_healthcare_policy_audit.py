from logicpearl.domains.healthcare_policy.audit import build_request_assertion_audit
from logicpearl.domains.healthcare_policy.compiler import compile_healthcare_policy_to_gate_ir
from logicpearl.domains.healthcare_policy.request_eval import (
    CandidateAssertion,
    EvidenceDocument,
    HealthcarePolicyRequest,
    MemberEvidence,
    PolicyContext,
    PolicySourceRef,
    RequestContext,
    RequestedService,
    evaluate_request_against_policy,
    review_candidate_assertions,
)

from test_healthcare_policy_request_eval import _final_spec


def test_build_request_assertion_audit_contains_candidate_reviewed_and_structured_layers() -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)
    candidate = CandidateAssertion(
        assertion_id="a1",
        cluster_id="diagnosis_requirement__qualifying_diagnosis",
        value="present",
        confidence=0.95,
        source_document_id="note-1",
        source_snippet="Clinical note documents enthesitis-related arthritis.",
        citation="note-1#line-1",
        extractor="llm_observer_v1",
        matched_terms=["Enthesitis-Related Arthritis"],
    )
    reviewed = review_candidate_assertions(policy, [candidate])
    request = HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-audit",
            payer="BCBSMA",
            member_id="member-audit",
            requested_service=RequestedService(kind="drug", code="NDC-A", label="Requested Drug"),
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
            unstructured_documents=[
                EvidenceDocument(
                    document_id="note-1",
                    kind="clinical_note",
                    text="Clinical note documents enthesitis-related arthritis.",
                    source="ehr",
                    citation="note-1#line-1",
                )
            ],
            candidate_assertions=[candidate],
            reviewed_assertions=reviewed,
        ),
    )

    response = evaluate_request_against_policy(policy, request, gate=gate)
    audit = build_request_assertion_audit(policy, request, response)

    layers = {str(record.layer) for record in audit.records}
    assert "candidate" in layers
    assert "reviewed" in layers
    reviewed_record = next(record for record in audit.records if str(record.layer) == "reviewed")
    assert reviewed_record.matched is True
    assert reviewed_record.linked_question_ids == ["q1"]
