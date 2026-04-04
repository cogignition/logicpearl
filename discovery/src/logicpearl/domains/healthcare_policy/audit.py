from __future__ import annotations

from enum import Enum

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel

from .models import HealthcarePolicySlice
from .request_eval import (
    HealthcarePolicyRequest,
    HealthcarePolicyResponse,
    ReviewedAssertionStatus,
)


class AssertionEvidenceLayer(str, Enum):
    CANDIDATE = "candidate"
    REVIEWED = "reviewed"
    STRUCTURED = "structured"


class AssertionAuditRecord(LogicPearlModel):
    assertion_id: str
    layer: AssertionEvidenceLayer
    cluster_id: str
    linked_question_ids: list[str] = Field(default_factory=list)
    source_document_id: str | None = None
    source_citation: str | None = None
    source_snippet: str
    value: str
    confidence: float | None = None
    status: str
    trust_score: float | None = None
    trust_signals: list[str] = Field(default_factory=list)
    derived_from: str
    review_method: str | None = None
    matched: bool
    audit_note: str

    @field_validator("assertion_id", "cluster_id", "source_snippet", "value", "status", "derived_from", "audit_note")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("assertion audit fields must be non-empty")
        return value


class RequestAssertionAudit(LogicPearlModel):
    request_id: str
    policy_id: str
    question_statuses: dict[str, str]
    records: list[AssertionAuditRecord]

    @field_validator("request_id", "policy_id")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("request assertion audit fields must be non-empty")
        return value


def build_request_assertion_audit(
    policy: HealthcarePolicySlice,
    request: HealthcarePolicyRequest,
    response: HealthcarePolicyResponse,
) -> RequestAssertionAudit:
    linked_question_ids_by_cluster: dict[str, list[str]] = {}
    question_statuses = {}
    for question in response.questions:
        linked_question_ids_by_cluster.setdefault(question.cluster_id, []).append(question.question_id)
        question_statuses[question.question_id] = question.status.value if hasattr(question.status, "value") else str(question.status)

    records: list[AssertionAuditRecord] = []
    accepted_assertion_ids = {
        evidence.evidence_id
        for question in response.questions
        for evidence in question.matched_evidence
        if evidence.kind in {"reviewed_assertion", "candidate_assertion"}
    }

    for candidate in request.member_evidence.candidate_assertions:
        records.append(
            AssertionAuditRecord(
                assertion_id=candidate.assertion_id,
                layer=AssertionEvidenceLayer.CANDIDATE,
                cluster_id=candidate.cluster_id,
                linked_question_ids=linked_question_ids_by_cluster.get(candidate.cluster_id, []),
                source_document_id=candidate.source_document_id,
                source_citation=candidate.citation,
                source_snippet=candidate.source_snippet,
                value=candidate.value,
                confidence=candidate.confidence,
                status="candidate",
                trust_score=None,
                trust_signals=[],
                derived_from=candidate.extractor,
                review_method=None,
                matched=candidate.assertion_id in accepted_assertion_ids,
                audit_note="Observer-generated candidate assertion; not trusted until reviewed.",
            )
        )

    for reviewed in request.member_evidence.reviewed_assertions:
        status_value = reviewed.status.value if isinstance(reviewed.status, ReviewedAssertionStatus) else str(reviewed.status)
        records.append(
            AssertionAuditRecord(
                assertion_id=reviewed.assertion_id,
                layer=AssertionEvidenceLayer.REVIEWED,
                cluster_id=reviewed.cluster_id,
                linked_question_ids=linked_question_ids_by_cluster.get(reviewed.cluster_id, []),
                source_document_id=reviewed.source_document_id,
                source_citation=reviewed.citation,
                source_snippet=reviewed.source_snippet,
                value=reviewed.value,
                confidence=None,
                status=status_value,
                trust_score=reviewed.trust_score,
                trust_signals=reviewed.trust_signals,
                derived_from=reviewed.derived_from,
                review_method=reviewed.review_method,
                matched=reviewed.assertion_id in accepted_assertion_ids,
                audit_note=_reviewed_assertion_note(status_value),
            )
        )

    structured_by_cluster = {
        requirement.cluster_id: []
        for requirement in policy.requirements
    }
    for event in request.member_evidence.structured_events:
        for cluster in policy.clusters:
            accepted_codes = {code.strip().upper() for code in cluster.codes}
            if event.code.strip().upper() in accepted_codes:
                structured_by_cluster.setdefault(cluster.cluster_id, []).append(event)
    for cluster_id, events in structured_by_cluster.items():
        for event in events:
            records.append(
                AssertionAuditRecord(
                    assertion_id=event.event_id,
                    layer=AssertionEvidenceLayer.STRUCTURED,
                    cluster_id=cluster_id,
                    linked_question_ids=linked_question_ids_by_cluster.get(cluster_id, []),
                    source_document_id=None,
                    source_citation=None,
                    source_snippet=event.label,
                    value="present",
                    confidence=1.0,
                    status="structured_match",
                    trust_score=1.0,
                    trust_signals=["structured_event"],
                    derived_from=event.source,
                    review_method="structured_history_lookup",
                    matched=True,
                    audit_note="Structured clinical/admin history matched a reviewed cluster code directly.",
                )
            )

    records.sort(key=lambda row: (row.cluster_id, _layer_value(row.layer), row.assertion_id))
    return RequestAssertionAudit(
        request_id=request.request.request_id,
        policy_id=policy.policy_id,
        question_statuses=question_statuses,
        records=records,
    )


def _reviewed_assertion_note(status: str) -> str:
    if status == "accepted":
        return "Assertion crossed the deterministic trust threshold and may feed the pearl."
    if status == "ambiguous":
        return "Assertion is grounded but not strong enough for silent acceptance."
    if status == "needs_human_review":
        return "Assertion requires manual review before it can be treated as trusted evidence."
    if status == "rejected":
        return "Assertion did not survive deterministic review."
    return "Reviewed assertion record."


def _layer_value(layer: AssertionEvidenceLayer | str) -> str:
    if isinstance(layer, Enum):
        return str(layer.value)
    return str(layer)
