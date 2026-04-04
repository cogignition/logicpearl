from __future__ import annotations

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel

from .models import ArtifactProvenance, CodeCluster, EvidenceRequirement, HealthcarePolicySlice, PolicySource
from .presentation import question_text_for_requirement
from .request_eval import HealthcarePolicyRequest
from .selector import PolicySelectionResult


class RequestPearlComponent(LogicPearlModel):
    policy_id: str
    title: str
    requirement_count: int
    cluster_count: int

    @field_validator("policy_id", "title")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("request pearl component fields must be non-empty")
        return value


class RequestPearlRequirementReference(LogicPearlModel):
    request_requirement_id: str
    source_policy_id: str
    source_requirement_id: str
    source_cluster_id: str
    source_question_text: str

    @field_validator(
        "request_requirement_id",
        "source_policy_id",
        "source_requirement_id",
        "source_cluster_id",
        "source_question_text",
    )
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("request pearl requirement reference fields must be non-empty")
        return value


class RequestPearlArtifact(LogicPearlModel):
    request_id: str
    selector_result: PolicySelectionResult
    composed_policy: HealthcarePolicySlice
    components: list[RequestPearlComponent] = Field(default_factory=list)
    requirement_references: list[RequestPearlRequirementReference] = Field(default_factory=list)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if not value:
            raise ValueError("request_id must be non-empty")
        return value


def assemble_request_pearl(
    request: HealthcarePolicyRequest,
    selected_policies: list[HealthcarePolicySlice],
    selector_result: PolicySelectionResult,
) -> RequestPearlArtifact:
    composed_sources: list[PolicySource] = []
    composed_clusters: list[CodeCluster] = []
    composed_requirements: list[EvidenceRequirement] = []
    components: list[RequestPearlComponent] = []
    references: list[RequestPearlRequirementReference] = []

    generated_at = "1970-01-01T00:00:00Z"
    effective_date = None
    source_commit = None
    if selected_policies:
        generated_at = selected_policies[0].provenance.generated_at
        effective_date = selected_policies[0].provenance.effective_date
        source_commit = selected_policies[0].provenance.source_commit

    for policy in selected_policies:
        cluster_by_id = {cluster.cluster_id: cluster for cluster in policy.clusters}
        components.append(
            RequestPearlComponent(
                policy_id=policy.policy_id,
                title=policy.title,
                requirement_count=len(policy.requirements),
                cluster_count=len(policy.clusters),
            )
        )
        for source in policy.sources:
            composed_sources.append(
                source.model_copy(
                    update={
                        "source_id": _prefixed(policy.policy_id, source.source_id),
                    }
                )
            )
        for cluster in policy.clusters:
            composed_clusters.append(
                cluster.model_copy(
                    update={
                        "cluster_id": _prefixed(policy.policy_id, cluster.cluster_id),
                        "label": f"{policy.title}: {cluster.label}",
                    }
                )
            )
        for requirement in policy.requirements:
            request_requirement_id = _prefixed(policy.policy_id, requirement.requirement_id)
            question_text = question_text_for_requirement(
                requirement,
                cluster=cluster_by_id.get(requirement.cluster_id),
                policy_title=policy.title,
            )
            composed_requirements.append(
                requirement.model_copy(
                    update={
                        "requirement_id": request_requirement_id,
                        "label": f"{policy.title}: {requirement.label}",
                        "question_text": question_text,
                        "cluster_id": _prefixed(policy.policy_id, requirement.cluster_id),
                        "source_id": _prefixed(policy.policy_id, requirement.source_id),
                    }
                )
            )
            references.append(
                RequestPearlRequirementReference(
                    request_requirement_id=request_requirement_id,
                    source_policy_id=policy.policy_id,
                    source_requirement_id=requirement.requirement_id,
                    source_cluster_id=requirement.cluster_id,
                    source_question_text=requirement.question_text,
                )
            )

    request_id = request.request.request_id
    composed_policy = HealthcarePolicySlice(
        policy_id=f"request_pearl__{request_id}",
        title=f"Request Pearl for {request.request.requested_service.label}",
        source_url=f"request-pearl://{request_id}",
        source_note=(
            "Request-scoped pearl assembled from selector-approved BCBSMA policy pearls. "
            "Only selected policies are included; non-selected policies remain not_applicable."
        ),
        adapted_for_demo=False,
        provenance=ArtifactProvenance(
            artifact_version="1.0.0",
            generated_by="logicpearl.healthcare_policy_request_pearl_assembler",
            generated_at=generated_at,
            review_status="approved",
            adapted_for_demo=False,
            effective_date=effective_date,
            source_commit=source_commit,
        ),
        sources=composed_sources,
        requirements=composed_requirements,
        clusters=composed_clusters,
    )
    return RequestPearlArtifact(
        request_id=request_id,
        selector_result=selector_result,
        composed_policy=composed_policy,
        components=components,
        requirement_references=references,
    )


def _prefixed(policy_id: str, value: str) -> str:
    return f"{policy_id}__{value}"
