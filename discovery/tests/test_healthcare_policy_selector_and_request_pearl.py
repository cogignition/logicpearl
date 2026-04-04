from logicpearl.domains.healthcare_policy.compiler import compile_healthcare_policy_to_gate_ir
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
    HealthcarePolicyRequest,
    MemberEvidence,
    PolicyContext,
    PolicySourceRef,
    RequestContext,
    RequestedService,
    evaluate_request_against_policy,
)
from logicpearl.domains.healthcare_policy.request_pearl import assemble_request_pearl
from logicpearl.domains.healthcare_policy.selector import select_applicable_policies


def _policy(
    policy_id: str,
    title: str,
    requirement_id: str,
    cluster_id: str,
    cluster_kind: str,
    cluster_code: str,
) -> HealthcarePolicySlice:
    return HealthcarePolicySlice(
        policy_id=policy_id,
        title=title,
        source_url=f"https://example.com/{policy_id}.pdf",
        source_note="Synthetic policy for selector and request-pearl tests.",
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
                kind=EvidenceRequirementKind.DIAGNOSIS_PRESENT,
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
                codes=[cluster_code],
                aliases=[title],
            )
        ],
    )


def _request() -> HealthcarePolicyRequest:
    return HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-tmj-1",
            payer="BCBSMA",
            member_id="member-1",
            requested_service=RequestedService(
                kind="procedure",
                code="TMJ-001",
                label="Temporomandibular Joint Disorder treatment",
            ),
            product="HMO",
            line_of_business="commercial",
        ),
        policy_context=PolicyContext(
            policy_id="selector_pending",
            policy_sources=[
                PolicySourceRef(
                    source_id="selector",
                    title="selector pending",
                    url="selector://pending",
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[
                ClinicalEvent(
                    event_id="dx-1",
                    event_type=ClinicalEventType.DIAGNOSIS,
                    code="DX-TMJ",
                    label="Temporomandibular Joint Disorder",
                    source="claims",
                ),
                ClinicalEvent(
                    event_id="proc-1",
                    event_type=ClinicalEventType.PROCEDURE,
                    code="PROC-TMJ",
                    label="Jaw physical therapy completed",
                    source="claims",
                ),
            ]
        ),
    )


def test_selector_picks_related_tmj_policies() -> None:
    request = _request()
    policies = [
        _policy(
            "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-pt",
            "physical_therapy_prereq__prior_physical_therapy",
            "procedure",
            "PROC-TMJ",
        ),
        _policy(
            "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-doc",
            "documentation_requirement__required_documentation",
            "diagnosis",
            "DX-TMJ",
        ),
        _policy(
            "bcbsma_conservative_therapy_prereq_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-conservative",
            "conservative_therapy_prereq__failed_conservative_therapy",
            "diagnosis",
            "DX-TMJ",
        ),
        _policy(
            "bcbsma_step_therapy_021_anti_migraine_policy",
            "021 Anti-Migraine Policy",
            "req-migraine",
            "step_therapy__trial_of_formulary_alternatives",
            "medication",
            "NDC-MIGRAINE",
        ),
    ]

    result = select_applicable_policies(request, policies)

    assert result.selected_policy_ids == [
        "bcbsma_conservative_therapy_prereq_035_temporomandibular_joint_disorder_prn",
        "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
        "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
    ]
    assert "bcbsma_step_therapy_021_anti_migraine_policy" not in result.selected_policy_ids


def test_assemble_request_pearl_prefixes_ids_and_preserves_provenance() -> None:
    request = _request()
    policies = [
        _policy(
            "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-doc",
            "documentation_requirement__required_documentation",
            "diagnosis",
            "DX-TMJ",
        ),
        _policy(
            "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-pt",
            "physical_therapy_prereq__prior_physical_therapy",
            "procedure",
            "PROC-TMJ",
        ),
    ]
    selector_result = select_applicable_policies(request, policies)

    artifact = assemble_request_pearl(request, policies, selector_result)

    assert artifact.composed_policy.policy_id == "request_pearl__req-tmj-1"
    assert len(artifact.components) == 2
    assert {
        requirement.requirement_id for requirement in artifact.composed_policy.requirements
    } == {
        "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn__req-doc",
        "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn__req-pt",
    }
    assert {
        reference.source_policy_id for reference in artifact.requirement_references
    } == {
        "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
        "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
    }


def test_request_pearl_compiles_and_evaluates_across_multiple_selected_policies() -> None:
    request = _request()
    policies = [
        _policy(
            "bcbsma_documentation_requirement_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-doc",
            "documentation_requirement__required_documentation",
            "diagnosis",
            "DX-TMJ",
        ),
        _policy(
            "bcbsma_physical_therapy_prereq_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-pt",
            "physical_therapy_prereq__prior_physical_therapy",
            "procedure",
            "PROC-TMJ",
        ),
        _policy(
            "bcbsma_conservative_therapy_prereq_035_temporomandibular_joint_disorder_prn",
            "035 Temporomandibular Joint Disorder prn",
            "req-conservative",
            "conservative_therapy_prereq__failed_conservative_therapy",
            "diagnosis",
            "DX-MISSING",
        ),
    ]
    selector_result = select_applicable_policies(request, policies)
    artifact = assemble_request_pearl(request, policies, selector_result)
    gate = compile_healthcare_policy_to_gate_ir(artifact.composed_policy)
    composed_request = request.model_copy(
        update={
            "policy_context": PolicyContext(
                policy_id=artifact.composed_policy.policy_id,
                policy_sources=[
                    PolicySourceRef(
                        source_id=source.source_id,
                        title=source.title,
                        url=source.url,
                    )
                    for source in artifact.composed_policy.sources
                ],
            )
        }
    )

    response = evaluate_request_against_policy(artifact.composed_policy, composed_request, gate=gate)

    assert response.summary.bitmask == 4
    assert response.summary.missing_question_ids == ["q3"]
    assert response.questions[0].status == "found"
    assert response.questions[1].status == "found"
    assert response.questions[2].status == "not_found"
