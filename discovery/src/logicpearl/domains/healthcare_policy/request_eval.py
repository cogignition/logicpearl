from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from logicpearl.ir import LogicPearlGateIR, evaluate_gate
from logicpearl.ir.models import LogicPearlModel

from .evaluator import requirement_feature_id
from .models import ClinicalEvent, HealthcarePolicySlice
from .presentation import question_text_for_requirement


class RequestedService(LogicPearlModel):
    kind: Literal["drug", "procedure", "other"]
    code: str
    label: str

    @field_validator("code", "label")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("requested service fields must be non-empty")
        return value


class RequestUrgency(str, Enum):
    STANDARD = "standard"
    EXPEDITED = "expedited"
    URGENT = "urgent"


class SubmissionChannel(str, Enum):
    PROVIDER_PORTAL = "provider_portal"
    FAX_ATTACHMENT = "fax_attachment"
    FHIR_EPA = "fhir_epa"


class ReviewType(str, Enum):
    PRIOR_AUTHORIZATION = "prior_authorization"
    CONCURRENT_REVIEW = "concurrent_review"
    POST_SERVICE_REVIEW = "post_service_review"
    MEDICAL_NECESSITY_REVIEW = "medical_necessity_review"


class ProviderReference(LogicPearlModel):
    provider_name: str
    npi: str | None = None
    specialty: str | None = None

    @field_validator("provider_name")
    @classmethod
    def validate_provider_name(cls, value: str) -> str:
        if not value:
            raise ValueError("provider_name must be non-empty")
        return value


class RequestContext(LogicPearlModel):
    request_id: str
    payer: str
    member_id: str
    requested_service: RequestedService
    product: str | None = None
    line_of_business: str | None = None
    urgency: RequestUrgency = RequestUrgency.STANDARD
    requesting_provider: ProviderReference | None = None
    servicing_provider: ProviderReference | None = None

    @field_validator("request_id", "payer", "member_id")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("request context fields must be non-empty")
        return value


class SubmissionMetadata(LogicPearlModel):
    submission_id: str
    channel: SubmissionChannel
    review_type: ReviewType
    submitted_at: str
    source_system: str
    attachment_count: int = 0

    @field_validator("submission_id", "submitted_at", "source_system")
    @classmethod
    def validate_submission_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("submission metadata fields must be non-empty")
        return value


class PolicySourceRef(LogicPearlModel):
    source_id: str
    title: str
    url: str
    excerpt: str | None = None

    @field_validator("source_id", "title", "url")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("policy source ref fields must be non-empty")
        return value


class PolicyContext(LogicPearlModel):
    policy_id: str
    policy_sources: list[PolicySourceRef]
    guideline_sources: list[PolicySourceRef] = Field(default_factory=list)

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        if not value:
            raise ValueError("policy_id must be non-empty")
        return value


class EvidenceDocument(LogicPearlModel):
    document_id: str
    kind: str
    text: str
    source: str
    citation: str | None = None
    title: str | None = None
    mime_type: str | None = None
    received_via: SubmissionChannel | None = None

    @field_validator("document_id", "kind", "text", "source")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("evidence document fields must be non-empty")
        return value


class CandidateAssertion(LogicPearlModel):
    assertion_id: str
    cluster_id: str
    value: Literal["present", "absent", "unknown"]
    confidence: float
    source_document_id: str
    source_snippet: str
    citation: str | None = None
    extractor: str
    matched_terms: list[str] = Field(default_factory=list)

    @field_validator("assertion_id", "cluster_id", "source_document_id", "source_snippet", "extractor")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("candidate assertion fields must be non-empty")
        return value


class GuidedQuestion(LogicPearlModel):
    question_id: str
    question_text: str
    requirement_id: str
    cluster_id: str
    required_document_kinds: list[str] = Field(default_factory=list)
    documentation_hint: str | None = None
    template: Literal["dtr_guided_question"] = "dtr_guided_question"

    @field_validator("question_id", "question_text", "requirement_id", "cluster_id")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("guided question fields must be non-empty")
        return value

    @field_validator("required_document_kinds")
    @classmethod
    def normalize_required_document_kinds(cls, values: list[str]) -> list[str]:
        return [value.strip() for value in values if value and value.strip()]


class ReviewedAssertionStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class ReviewedAssertion(LogicPearlModel):
    assertion_id: str
    cluster_id: str
    value: Literal["present", "absent", "unknown"]
    status: ReviewedAssertionStatus
    trust_score: float
    trust_signals: list[str] = Field(default_factory=list)
    source_document_id: str
    source_snippet: str
    citation: str | None = None
    derived_from: str
    review_method: str

    @field_validator(
        "assertion_id",
        "cluster_id",
        "source_document_id",
        "source_snippet",
        "derived_from",
        "review_method",
    )
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("reviewed assertion fields must be non-empty")
        return value


class MemberEvidence(LogicPearlModel):
    structured_events: list[ClinicalEvent] = Field(default_factory=list)
    unstructured_documents: list[EvidenceDocument] = Field(default_factory=list)
    candidate_assertions: list[CandidateAssertion] = Field(default_factory=list)
    reviewed_assertions: list[ReviewedAssertion] = Field(default_factory=list)


class StructuredHistory(LogicPearlModel):
    diagnoses: list[ClinicalEvent] = Field(default_factory=list)
    procedures: list[ClinicalEvent] = Field(default_factory=list)
    medications: list[ClinicalEvent] = Field(default_factory=list)
    note_assertions: list[ClinicalEvent] = Field(default_factory=list)

    def to_events(self) -> list[ClinicalEvent]:
        return [
            *self.diagnoses,
            *self.procedures,
            *self.medications,
            *self.note_assertions,
        ]


class HealthcarePolicyRequest(LogicPearlModel):
    request: RequestContext
    submission: SubmissionMetadata | None = None
    policy_context: PolicyContext
    guided_questions: list[GuidedQuestion] = Field(default_factory=list)
    structured_history: StructuredHistory | None = None
    clinical_documents: list[EvidenceDocument] = Field(default_factory=list)
    member_evidence: MemberEvidence = Field(default_factory=MemberEvidence)

    @model_validator(mode="after")
    def harmonize_evidence(self) -> "HealthcarePolicyRequest":
        structured_events = self.member_evidence.structured_events or (
            self.structured_history.to_events() if self.structured_history else []
        )
        unstructured_documents = self.member_evidence.unstructured_documents or self.clinical_documents
        self.member_evidence = self.member_evidence.model_copy(
            update={
                "structured_events": structured_events,
                "unstructured_documents": unstructured_documents,
            }
        )
        if self.structured_history is None and structured_events:
            self.structured_history = StructuredHistory(
                diagnoses=[event for event in structured_events if event.event_type == "diagnosis"],
                procedures=[event for event in structured_events if event.event_type == "procedure"],
                medications=[event for event in structured_events if event.event_type == "medication"],
                note_assertions=[event for event in structured_events if event.event_type == "note_assertion"],
            )
        if not self.clinical_documents:
            self.clinical_documents = list(unstructured_documents)
        return self


class QuestionStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"


class DocumentationStatus(str, Enum):
    PRESENT = "present"
    MISSING_REQUIRED_DOCUMENTATION = "missing_required_documentation"
    AMBIGUOUS = "ambiguous"


class RoutingStatus(str, Enum):
    READY_FOR_CLINICAL_REVIEW = "ready_for_clinical_review"
    MISSING_REQUIRED_DOCUMENTATION = "missing_required_documentation"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class MatchedEvidence(LogicPearlModel):
    evidence_id: str
    kind: str
    source: str
    snippet: str


class MissingDocumentationItem(LogicPearlModel):
    question_id: str
    requirement_id: str
    cluster_id: str
    required_document_kinds: list[str] = Field(default_factory=list)
    note: str


class QuestionEvaluationResult(LogicPearlModel):
    question_id: str
    question_text: str
    status: QuestionStatus
    documentation_status: DocumentationStatus
    requirement_id: str
    cluster_id: str
    guided_question_id: str | None = None
    required_document_kinds: list[str] = Field(default_factory=list)
    missing_document_kinds: list[str] = Field(default_factory=list)
    matched_document_ids: list[str] = Field(default_factory=list)
    matched_evidence: list[MatchedEvidence] = Field(default_factory=list)
    policy_source_id: str
    policy_excerpt: str
    policy_citation: str | None = None
    reason: str


class CaseSummary(LogicPearlModel):
    request_id: str
    submission_id: str | None = None
    channel: str
    review_type: str
    payer: str
    requested_service: str
    product: str | None = None
    line_of_business: str | None = None
    structured_event_count: int
    clinical_document_count: int
    accepted_assertion_count: int
    ambiguous_assertion_count: int
    organized_case_summary: str


class OrganizedDocument(LogicPearlModel):
    document_id: str
    kind: str
    source: str
    title: str | None = None
    matched_question_ids: list[str] = Field(default_factory=list)


class ReviewPacket(LogicPearlModel):
    route_status: RoutingStatus
    review_summary: str
    organized_documents: list[OrganizedDocument] = Field(default_factory=list)
    missing_documentation: list[MissingDocumentationItem] = Field(default_factory=list)
    audit_notes: list[str] = Field(default_factory=list)


class EvaluationSummary(LogicPearlModel):
    ready_for_review: bool
    route_status: RoutingStatus
    documentation_complete: bool
    needs_human_review: bool
    missing_question_ids: list[str] = Field(default_factory=list)
    ambiguous_question_ids: list[str] = Field(default_factory=list)
    missing_documentation: list[MissingDocumentationItem] = Field(default_factory=list)
    bitmask: int | None = None


class HealthcarePolicyResponse(LogicPearlModel):
    request_id: str
    policy_id: str
    submission_id: str | None = None
    case_summary: CaseSummary
    questions: list[QuestionEvaluationResult]
    review_packet: ReviewPacket
    summary: EvaluationSummary


def prepare_request_evidence(policy: HealthcarePolicySlice, request: HealthcarePolicyRequest) -> HealthcarePolicyRequest:
    candidate_assertions = request.member_evidence.candidate_assertions
    if not candidate_assertions:
        candidate_assertions = extract_candidate_assertions(policy, request.member_evidence.unstructured_documents)

    reviewed_assertions = request.member_evidence.reviewed_assertions
    if not reviewed_assertions:
        reviewed_assertions = review_candidate_assertions(
            policy,
            candidate_assertions,
            structured_events=request.member_evidence.structured_events,
        )

    return request.model_copy(
        update={
            "guided_questions": request.guided_questions or build_guided_questions(policy),
            "member_evidence": request.member_evidence.model_copy(
                update={
                    "candidate_assertions": candidate_assertions,
                    "reviewed_assertions": reviewed_assertions,
                }
            )
        }
    )


def extract_candidate_assertions(
    policy: HealthcarePolicySlice,
    documents: list[EvidenceDocument],
) -> list[CandidateAssertion]:
    candidates: list[CandidateAssertion] = []
    for cluster in policy.clusters:
        alias_terms = _filter_alias_terms(cluster.aliases)
        code_terms = [code for code in cluster.codes if code]
        for document in documents:
            match = _find_cluster_match(document.text, alias_terms=alias_terms, code_terms=code_terms)
            if match is None:
                continue
            matched_terms, snippet, confidence = match
            candidates.append(
                CandidateAssertion(
                    assertion_id=f"{document.document_id}__{cluster.cluster_id}",
                    cluster_id=cluster.cluster_id,
                    value="present",
                    confidence=confidence,
                    source_document_id=document.document_id,
                    source_snippet=snippet,
                    citation=document.citation,
                    extractor="deterministic_freeform_observer_v1",
                    matched_terms=matched_terms,
                )
            )
    return candidates


def review_candidate_assertions(
    policy: HealthcarePolicySlice,
    candidate_assertions: list[CandidateAssertion],
    *,
    structured_events: list[ClinicalEvent] | None = None,
    min_accept_score: float = 0.85,
    min_ambiguous_score: float = 0.65,
) -> list[ReviewedAssertion]:
    structured_event_set = {
        event.code.strip().upper()
        for event in (structured_events or [])
    }
    cluster_by_id = {cluster.cluster_id: cluster for cluster in policy.clusters}
    counts_by_cluster: dict[str, int] = {}
    for assertion in candidate_assertions:
        counts_by_cluster[assertion.cluster_id] = counts_by_cluster.get(assertion.cluster_id, 0) + 1

    reviewed: list[ReviewedAssertion] = []
    for assertion in candidate_assertions:
        cluster = cluster_by_id.get(assertion.cluster_id)
        trust_score = assertion.confidence
        signals: list[str] = []

        if assertion.citation:
            trust_score += 0.1
            signals.append("has_citation")
        if counts_by_cluster.get(assertion.cluster_id, 0) > 1:
            trust_score += 0.15
            signals.append("multi_document_corroboration")
        if cluster and any(code.strip().upper() in structured_event_set for code in cluster.codes):
            trust_score += 0.2
            signals.append("structured_event_corroboration")
        if any(term.upper() in assertion.source_snippet.upper() for term in cluster.codes[:2] if cluster):
            trust_score += 0.1
            signals.append("exact_code_mention")
        if len(assertion.matched_terms) > 1:
            trust_score += 0.05
            signals.append("multiple_term_match")

        trust_score = min(trust_score, 0.99)

        if assertion.value != "present":
            status = ReviewedAssertionStatus.REJECTED
        elif trust_score >= min_accept_score:
            status = ReviewedAssertionStatus.ACCEPTED
        elif trust_score >= min_ambiguous_score:
            status = ReviewedAssertionStatus.AMBIGUOUS
        else:
            status = ReviewedAssertionStatus.NEEDS_HUMAN_REVIEW

        reviewed.append(
            ReviewedAssertion(
                assertion_id=assertion.assertion_id,
                cluster_id=assertion.cluster_id,
                value=assertion.value,
                status=status,
                trust_score=trust_score,
                trust_signals=signals,
                source_document_id=assertion.source_document_id,
                source_snippet=assertion.source_snippet,
                citation=assertion.citation,
                derived_from=assertion.extractor,
                review_method="deterministic_evidence_trust_review_v1",
            )
        )
    return reviewed


def evaluate_request_against_policy(
    policy: HealthcarePolicySlice,
    request: HealthcarePolicyRequest,
    *,
    gate: LogicPearlGateIR | None = None,
) -> HealthcarePolicyResponse:
    request = prepare_request_evidence(policy, request)
    source_by_id = {source.source_id: source for source in policy.sources}
    structured_by_cluster = _structured_matches_by_cluster(policy, request.member_evidence.structured_events)
    reviewed_by_cluster = _reviewed_assertions_by_cluster(request.member_evidence.reviewed_assertions)
    document_by_id = {document.document_id: document for document in request.member_evidence.unstructured_documents}
    guided_question_by_requirement_id = {
        guided_question.requirement_id: guided_question for guided_question in request.guided_questions
    }

    features: dict[str, float] = {}
    questions: list[QuestionEvaluationResult] = []
    missing_question_ids: list[str] = []
    ambiguous_question_ids: list[str] = []
    missing_documentation: list[MissingDocumentationItem] = []

    for index, requirement in enumerate(policy.requirements, start=1):
        structured_matches = structured_by_cluster.get(requirement.cluster_id, [])
        reviewed_matches = reviewed_by_cluster.get(requirement.cluster_id, [])
        accepted = [item for item in reviewed_matches if item.status == ReviewedAssertionStatus.ACCEPTED]
        ambiguous = [
            item
            for item in reviewed_matches
            if item.status in {ReviewedAssertionStatus.AMBIGUOUS, ReviewedAssertionStatus.NEEDS_HUMAN_REVIEW}
        ]
        guided_question = guided_question_by_requirement_id.get(requirement.requirement_id)
        required_document_kinds = list(guided_question.required_document_kinds) if guided_question else []
        matched_document_ids = sorted(
            {
                item.source_document_id
                for item in accepted + ambiguous
                if item.source_document_id in document_by_id
            }
        )

        matched_evidence = [
            MatchedEvidence(
                evidence_id=event.event_id,
                kind=str(event.event_type),
                source=event.source,
                snippet=event.label,
            )
            for event in structured_matches
        ] + [
            MatchedEvidence(
                evidence_id=item.assertion_id,
                kind="reviewed_assertion",
                source=item.source_document_id,
                snippet=item.source_snippet,
            )
            for item in accepted
        ]

        documentation_status = _derive_documentation_status(
            required_document_kinds=required_document_kinds,
            available_documents=request.member_evidence.unstructured_documents,
            matched_document_ids=matched_document_ids,
            question_has_ambiguity=bool(ambiguous),
        )
        missing_document_kinds = _missing_document_kinds(
            required_document_kinds=required_document_kinds,
            available_documents=request.member_evidence.unstructured_documents,
        )

        if structured_matches or accepted:
            status = QuestionStatus.FOUND
            reason = "Mapped structured history and/or accepted reviewed assertions to the guided policy question."
            features[requirement_feature_id(requirement.requirement_id)] = 1.0
        elif ambiguous:
            status = QuestionStatus.AMBIGUOUS
            reason = "Only ambiguous or needs-review reviewed assertions were available for this guided policy question."
            features[requirement_feature_id(requirement.requirement_id)] = 0.0
            ambiguous_question_ids.append(f"q{index}")
            matched_evidence.extend(
                MatchedEvidence(
                    evidence_id=item.assertion_id,
                    kind="candidate_assertion",
                    source=item.source_document_id,
                    snippet=item.source_snippet,
                )
                for item in ambiguous
            )
        else:
            status = QuestionStatus.NOT_FOUND
            reason = "No structured history or accepted reviewed assertions matched the guided policy question."
            features[requirement_feature_id(requirement.requirement_id)] = 0.0
            missing_question_ids.append(f"q{index}")

        if documentation_status == DocumentationStatus.MISSING_REQUIRED_DOCUMENTATION:
            missing_documentation.append(
                MissingDocumentationItem(
                    question_id=f"q{index}",
                    requirement_id=requirement.requirement_id,
                    cluster_id=requirement.cluster_id,
                    required_document_kinds=required_document_kinds,
                    note=guided_question.documentation_hint
                    if guided_question and guided_question.documentation_hint
                    else "Required documentation types were not present in the intake bundle.",
                )
            )

        source = source_by_id[requirement.source_id]
        questions.append(
            QuestionEvaluationResult(
                question_id=f"q{index}",
                question_text=guided_question.question_text if guided_question else requirement.question_text,
                status=status,
                documentation_status=documentation_status,
                requirement_id=requirement.requirement_id,
                cluster_id=requirement.cluster_id,
                guided_question_id=guided_question.question_id if guided_question else None,
                required_document_kinds=required_document_kinds,
                missing_document_kinds=missing_document_kinds,
                matched_document_ids=matched_document_ids,
                matched_evidence=matched_evidence,
                policy_source_id=source.source_id,
                policy_excerpt=requirement.source_excerpt,
                policy_citation=requirement.source_anchor,
                reason=reason,
            )
        )

    bitmask = evaluate_gate(gate, features) if gate is not None else None
    route_status = _derive_route_status(
        questions,
        reviewed_assertions=request.member_evidence.reviewed_assertions,
        missing_documentation=missing_documentation,
    )
    case_summary = _build_case_summary(request, route_status)
    review_packet = _build_review_packet(
        request,
        questions,
        route_status=route_status,
        missing_documentation=missing_documentation,
    )
    return HealthcarePolicyResponse(
        request_id=request.request.request_id,
        policy_id=policy.policy_id,
        submission_id=request.submission.submission_id if request.submission else None,
        case_summary=case_summary,
        questions=questions,
        review_packet=review_packet,
        summary=EvaluationSummary(
            ready_for_review=True,
            route_status=route_status,
            documentation_complete=not missing_documentation,
            needs_human_review=route_status == RoutingStatus.NEEDS_HUMAN_REVIEW,
            missing_question_ids=missing_question_ids,
            ambiguous_question_ids=ambiguous_question_ids,
            missing_documentation=missing_documentation,
            bitmask=bitmask,
        ),
    )


def build_guided_questions(policy: HealthcarePolicySlice) -> list[GuidedQuestion]:
    guided_questions: list[GuidedQuestion] = []
    cluster_by_id = {cluster.cluster_id: cluster for cluster in policy.clusters}
    for index, requirement in enumerate(policy.requirements, start=1):
        guided_questions.append(
            GuidedQuestion(
                question_id=f"gq{index}",
                question_text=question_text_for_requirement(
                    requirement,
                    cluster=cluster_by_id.get(requirement.cluster_id),
                ),
                requirement_id=requirement.requirement_id,
                cluster_id=requirement.cluster_id,
                required_document_kinds=_default_document_kinds_for_requirement(requirement.kind),
                documentation_hint=requirement.evidence_needed,
            )
        )
    return guided_questions


def _structured_matches_by_cluster(policy: HealthcarePolicySlice, events: list[ClinicalEvent]) -> dict[str, list[ClinicalEvent]]:
    matches: dict[str, list[ClinicalEvent]] = {}
    for cluster in policy.clusters:
        accepted_codes = {code.strip().upper() for code in cluster.codes}
        matched = [
            event
            for event in events
            if event.code.strip().upper() in accepted_codes
        ]
        if matched:
            matches[cluster.cluster_id] = matched
    return matches


def _reviewed_assertions_by_cluster(
    reviewed_assertions: list[ReviewedAssertion],
) -> dict[str, list[ReviewedAssertion]]:
    grouped: dict[str, list[ReviewedAssertion]] = {}
    for assertion in reviewed_assertions:
        grouped.setdefault(assertion.cluster_id, []).append(assertion)
    return grouped


def _default_document_kinds_for_requirement(kind: str) -> list[str]:
    if kind == "diagnosis_present":
        return ["prior_auth_form", "office_note", "problem_list"]
    if kind == "procedure_completed":
        return ["procedure_history", "office_note", "therapy_report"]
    if kind == "medication_trial":
        return ["medication_history", "office_note", "pharmacy_history"]
    if kind == "note_assertion_present":
        return ["office_note", "clinical_attachment"]
    return ["office_note"]


def _missing_document_kinds(
    *,
    required_document_kinds: list[str],
    available_documents: list[EvidenceDocument],
) -> list[str]:
    if not required_document_kinds:
        return []
    available_kinds = {document.kind for document in available_documents}
    return [kind for kind in required_document_kinds if kind not in available_kinds]


def _derive_documentation_status(
    *,
    required_document_kinds: list[str],
    available_documents: list[EvidenceDocument],
    matched_document_ids: list[str],
    question_has_ambiguity: bool,
) -> DocumentationStatus:
    if question_has_ambiguity:
        return DocumentationStatus.AMBIGUOUS
    if not required_document_kinds:
        return DocumentationStatus.PRESENT
    available_kinds = {document.kind for document in available_documents}
    if any(kind in available_kinds for kind in required_document_kinds):
        return DocumentationStatus.PRESENT
    if matched_document_ids:
        return DocumentationStatus.PRESENT
    return DocumentationStatus.MISSING_REQUIRED_DOCUMENTATION


def _derive_route_status(
    questions: list[QuestionEvaluationResult],
    *,
    reviewed_assertions: list[ReviewedAssertion],
    missing_documentation: list[MissingDocumentationItem],
) -> RoutingStatus:
    if any(
        question.status == QuestionStatus.AMBIGUOUS or question.documentation_status == DocumentationStatus.AMBIGUOUS
        for question in questions
    ):
        return RoutingStatus.NEEDS_HUMAN_REVIEW
    if any(assertion.status == ReviewedAssertionStatus.NEEDS_HUMAN_REVIEW for assertion in reviewed_assertions):
        return RoutingStatus.NEEDS_HUMAN_REVIEW
    if missing_documentation:
        return RoutingStatus.MISSING_REQUIRED_DOCUMENTATION
    return RoutingStatus.READY_FOR_CLINICAL_REVIEW


def _build_case_summary(
    request: HealthcarePolicyRequest,
    route_status: RoutingStatus,
) -> CaseSummary:
    accepted_count = sum(
        1 for assertion in request.member_evidence.reviewed_assertions if assertion.status == ReviewedAssertionStatus.ACCEPTED
    )
    ambiguous_count = sum(
        1
        for assertion in request.member_evidence.reviewed_assertions
        if assertion.status in {ReviewedAssertionStatus.AMBIGUOUS, ReviewedAssertionStatus.NEEDS_HUMAN_REVIEW}
    )
    submission = request.submission
    channel = _enum_value(submission.channel, default="unknown") if submission else "unknown"
    review_type = _enum_value(submission.review_type, default="prior_authorization") if submission else "prior_authorization"
    summary = (
        f"{request.request.payer} {review_type.replace('_', ' ')} case for "
        f"{request.request.requested_service.label} arrived via {channel.replace('_', ' ')} "
        f"with {len(request.member_evidence.unstructured_documents)} intake documents and "
        f"{len(request.member_evidence.structured_events)} structured history events. "
        f"Current routing status: {route_status.value}."
    )
    return CaseSummary(
        request_id=request.request.request_id,
        submission_id=submission.submission_id if submission else None,
        channel=channel,
        review_type=review_type,
        payer=request.request.payer,
        requested_service=request.request.requested_service.label,
        product=request.request.product,
        line_of_business=request.request.line_of_business,
        structured_event_count=len(request.member_evidence.structured_events),
        clinical_document_count=len(request.member_evidence.unstructured_documents),
        accepted_assertion_count=accepted_count,
        ambiguous_assertion_count=ambiguous_count,
        organized_case_summary=summary,
    )


def _build_review_packet(
    request: HealthcarePolicyRequest,
    questions: list[QuestionEvaluationResult],
    *,
    route_status: RoutingStatus,
    missing_documentation: list[MissingDocumentationItem],
) -> ReviewPacket:
    question_ids_by_document_id: dict[str, list[str]] = {}
    for question in questions:
        for document_id in question.matched_document_ids:
            question_ids_by_document_id.setdefault(document_id, []).append(question.question_id)
    organized_documents = [
        OrganizedDocument(
            document_id=document.document_id,
            kind=document.kind,
            source=document.source,
            title=document.title,
            matched_question_ids=question_ids_by_document_id.get(document.document_id, []),
        )
        for document in request.member_evidence.unstructured_documents
    ]
    review_summary = (
        "Guided intake completed. "
        "The packet organizes submitted clinical documents, maps candidate evidence to policy questions, "
        "and preserves final clinical determination for the reviewer."
    )
    audit_notes = [
        f"submission_channel={_enum_value(request.submission.channel, default='unknown')}" if request.submission else "submission_channel=unknown",
        f"guided_question_count={len(request.guided_questions)}",
        f"accepted_reviewed_assertions={sum(1 for item in request.member_evidence.reviewed_assertions if item.status == ReviewedAssertionStatus.ACCEPTED)}",
    ]
    return ReviewPacket(
        route_status=route_status,
        review_summary=review_summary,
        organized_documents=organized_documents,
        missing_documentation=missing_documentation,
        audit_notes=audit_notes,
    )


def _enum_value(value: object, *, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _find_cluster_match(
    text: str,
    *,
    alias_terms: list[str],
    code_terms: list[str],
) -> tuple[list[str], str, float] | None:
    normalized_text = " ".join(text.split())
    lowered = normalized_text.lower()
    matched_terms: list[str] = []
    ambiguity_pattern = re.compile(
        r"\b("
        r"possible|possibly|suspected|suggests|unclear|unconfirmed|not confirmed|"
        r"incomplete|pending|may have|might have"
        r")\b"
    )
    evidence_context_pattern = re.compile(
        r"\b("
        r"history|trial|tried|failed|failure|contraindication|documented|diagnosed|diagnosis|"
        r"completed|received|prior|previous|claim|claims|medication|assessment|"
        r"office note|clinical note|lab|pharmacy"
        r")\b"
    )

    for term in code_terms:
        if term and term.lower() in lowered:
            matched_terms.append(term)
    for alias in alias_terms:
        if not alias:
            continue
        alias_lower = alias.lower()
        search_from = 0
        while True:
            alias_index = lowered.find(alias_lower, search_from)
            if alias_index == -1:
                break
            window_start = max(0, alias_index - 120)
            window_end = min(len(normalized_text), alias_index + len(alias) + 120)
            window = lowered[window_start:window_end]
            if ambiguity_pattern.search(window):
                search_from = alias_index + len(alias_lower)
                continue
            if evidence_context_pattern.search(window):
                matched_terms.append(alias)
                break
            search_from = alias_index + len(alias_lower)

    if not matched_terms:
        return None

    earliest_index = min(lowered.index(term.lower()) for term in matched_terms)
    start = max(0, earliest_index - 80)
    end = min(len(normalized_text), earliest_index + 180)
    snippet = normalized_text[start:end].strip()
    confidence = 0.72
    if any(term in code_terms for term in matched_terms):
        confidence += 0.15
    if len(matched_terms) > 1:
        confidence += 0.05
    if ambiguity_pattern.search(lowered):
        confidence -= 0.1
    if re.search(r"\b(completed|tried|history of|diagnosed with|documented)\b", lowered):
        confidence += 0.05
    return matched_terms, snippet, min(confidence, 0.95)


def _filter_alias_terms(alias_terms: list[str]) -> list[str]:
    blocked = {
        "step therapy",
        "managed care",
        "ppo/epo",
        "medex with rx plans",
        "medex with rx plans*",
        "indemnity",
        "ndemnity",
        "a clinician's or physician's office",
        "a clinician’s or physician’s office",
        "a home health care provider",
        "a home infusion therapy provider",
        "outpatient hospital and dialysis settings",
        "surgical day care",
        "policy does not apply to",
    }
    filtered: list[str] = []
    for alias in alias_terms:
        if not alias:
            continue
        normalized = " ".join(alias.split()).strip()
        lowered = normalized.lower()
        token_count = len(re.findall(r"[a-z0-9]+", lowered))
        if lowered in blocked:
            continue
        if token_count < 2 and not re.search(r"\d", normalized):
            continue
        if len(normalized) < 8:
            continue
        filtered.append(normalized)
    return filtered
