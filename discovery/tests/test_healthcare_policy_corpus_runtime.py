from logicpearl.domains.healthcare_policy.corpus_runtime import evaluate_request_against_corpus
from logicpearl.domains.healthcare_policy.models import (
    ArtifactProvenance,
    ClinicalEvent,
    ClinicalEventType,
    CodeCluster,
    EvidenceRequirement,
    EvidenceRequirementKind,
    HealthcarePolicySlice,
    PolicySource,
)
from logicpearl.domains.healthcare_policy.request_eval import (
    EvidenceDocument,
    HealthcarePolicyRequest,
    MemberEvidence,
    PolicyContext,
    PolicySourceRef,
    RequestContext,
    RequestedService,
    SubmissionChannel,
    SubmissionMetadata,
)


def _policy(
    policy_id: str,
    title: str,
    requirement_id: str,
    cluster_id: str,
    kind: EvidenceRequirementKind,
    cluster_kind: str,
    code: str,
) -> HealthcarePolicySlice:
    return HealthcarePolicySlice(
        policy_id=policy_id,
        title=title,
        source_url=f"https://example.com/{policy_id}.pdf",
        source_note="Synthetic corpus runtime test policy.",
        adapted_for_demo=False,
        provenance=ArtifactProvenance(
            artifact_version="1.0.0",
            generated_by="test",
            generated_at="2026-04-03T00:00:00Z",
            review_status="approved",
            adapted_for_demo=False,
        ),
        sources=[
            PolicySource(
                source_id="source-1",
                title=title,
                document_type="medical_policy",
                publisher="BCBSMA",
                url=f"https://example.com/{policy_id}.pdf",
            )
        ],
        requirements=[
            EvidenceRequirement(
                requirement_id=requirement_id,
                label=f"{title} requirement",
                question_text=f"Did we find evidence for {title}?",
                kind=kind,
                cluster_id=cluster_id,
                evidence_needed=f"Evidence supporting {title}",
                source_excerpt=f"{title} requires evidence.",
                source_id="source-1",
                source_section="Policy",
                review_status="approved",
            )
        ],
        clusters=[
            CodeCluster(
                cluster_id=cluster_id,
                label=f"{title} cluster",
                kind=cluster_kind,
                codes=[code],
                aliases=[title],
            )
        ],
    )


def _request() -> HealthcarePolicyRequest:
    return HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-tmj-corpus-1",
            payer="BCBSMA",
            member_id="member-1",
            requested_service=RequestedService(
                kind="procedure",
                code="TMJ-001",
                label="Temporomandibular Joint Disorder treatment",
            ),
        ),
        submission=SubmissionMetadata(
            submission_id="sub-1",
            channel=SubmissionChannel.PROVIDER_PORTAL,
            review_type="prior_authorization",
            submitted_at="2026-04-03T12:00:00Z",
            source_system="provider_portal",
            attachment_count=1,
        ),
        policy_context=PolicyContext(
            policy_id="selector_pending",
            policy_sources=[PolicySourceRef(source_id="selector", title="selector", url="selector://pending")],
        ),
        member_evidence=MemberEvidence(
            structured_events=[
                ClinicalEvent(
                    event_id="event-1",
                    event_type=ClinicalEventType.DIAGNOSIS,
                    code="DX-TMJ",
                    label="Temporomandibular Joint Disorder",
                    source="claims",
                ),
                ClinicalEvent(
                    event_id="event-2",
                    event_type=ClinicalEventType.PROCEDURE,
                    code="PROC-TMJ",
                    label="Prior physical therapy completed",
                    source="claims",
                ),
            ],
            unstructured_documents=[
                EvidenceDocument(
                    document_id="cover",
                    kind="cover_sheet",
                    title="Cover Sheet",
                    text="Clinical attachments pending.",
                    source="provider_portal",
                )
            ],
        ),
    )


def test_evaluate_request_against_corpus_combines_logic_and_documentation_bits() -> None:
    policies = [
        _policy(
            "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-pt",
            "physical_therapy_prereq__prior_physical_therapy",
            EvidenceRequirementKind.PROCEDURE_COMPLETED,
            "procedure",
            "PROC-TMJ",
        ),
        _policy(
            "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-doc",
            "documentation_requirement__supporting_clinical_documentation",
            EvidenceRequirementKind.DIAGNOSIS_PRESENT,
            "diagnosis",
            "DX-TMJ",
        ),
    ]

    result = evaluate_request_against_corpus(_request(), policies)

    assert result.selected_policy_ids == [
        "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
        "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
    ]
    assert result.logic_bitmask == 0
    assert result.documentation_bitmask != 0
    assert result.bitmask == result.documentation_bitmask
    assert result.response.summary.route_status == "missing_required_documentation"
    assert any(mapping.bit_kind == "documentation" for mapping in result.bit_mappings)
