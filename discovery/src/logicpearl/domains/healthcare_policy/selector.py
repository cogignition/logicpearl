from __future__ import annotations

import re
from collections.abc import Iterable

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel

from .models import HealthcarePolicySlice
from .request_eval import HealthcarePolicyRequest

_STOPWORDS = {
    "a",
    "an",
    "and",
    "auth",
    "authorization",
    "benefit",
    "bluecrossma",
    "bcbsma",
    "clinical",
    "documentation",
    "for",
    "history",
    "in",
    "medical",
    "of",
    "or",
    "policy",
    "prn",
    "prereq",
    "prior",
    "required",
    "requirement",
    "review",
    "step",
    "therapy",
    "the",
    "to",
    "with",
}


class PolicySelectionCandidate(LogicPearlModel):
    policy_id: str
    title: str
    score: float
    matched_terms: list[str] = Field(default_factory=list)
    selector_reasons: list[str] = Field(default_factory=list)
    selected: bool = False

    @field_validator("policy_id", "title")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("policy selection candidate fields must be non-empty")
        return value


class PolicySelectionResult(LogicPearlModel):
    request_id: str
    requested_service: str
    selected_policy_ids: list[str] = Field(default_factory=list)
    ambiguous_policy_ids: list[str] = Field(default_factory=list)
    candidates: list[PolicySelectionCandidate] = Field(default_factory=list)
    selector_version: str = "deterministic_policy_selector_v1"

    @field_validator("request_id", "requested_service", "selector_version")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("policy selection result fields must be non-empty")
        return value


def select_applicable_policies(
    request: HealthcarePolicyRequest,
    policies: Iterable[HealthcarePolicySlice],
    *,
    max_selected: int = 6,
    min_score: float = 2.0,
) -> PolicySelectionResult:
    request_terms = _request_terms(request)
    request_phrase = request.request.requested_service.label.strip().lower()
    candidates: list[PolicySelectionCandidate] = []
    for policy in policies:
        policy_terms = _policy_terms(policy)
        matched_terms = sorted(request_terms & policy_terms)
        score = 0.0
        reasons: list[str] = []
        if request_phrase and request_phrase in policy.title.lower():
            score += 6.0
            reasons.append("requested_service_phrase_in_title")
        if matched_terms:
            score += min(6.0, float(len(matched_terms) * 2))
            reasons.append(f"title_term_overlap:{','.join(matched_terms[:6])}")
        evidence_terms = _request_evidence_terms(request)
        supporting_terms = sorted(evidence_terms & policy_terms)
        if supporting_terms:
            score += min(3.0, float(len(supporting_terms)))
            reasons.append(f"evidence_term_overlap:{','.join(supporting_terms[:6])}")
        if request.request.requested_service.kind == "drug" and (
            "medication" in policy.policy_id or "drug" in policy.policy_id
        ):
            score += 0.5
            reasons.append("service_kind_matches_medication_policy_shape")
        if request.request.requested_service.kind == "procedure" and "procedure" in policy.policy_id:
            score += 0.5
            reasons.append("service_kind_matches_procedure_policy_shape")
        if score <= 0:
            continue
        candidates.append(
            PolicySelectionCandidate(
                policy_id=policy.policy_id,
                title=policy.title,
                score=round(score, 2),
                matched_terms=matched_terms + [term for term in supporting_terms if term not in matched_terms],
                selector_reasons=reasons,
            )
        )

    candidates.sort(key=lambda row: (-row.score, row.policy_id))
    if not candidates:
        return PolicySelectionResult(
            request_id=request.request.request_id,
            requested_service=request.request.requested_service.label,
            candidates=[],
        )

    top_score = candidates[0].score
    dynamic_threshold = max(min_score, top_score - 1.0)
    selected_policy_ids: list[str] = []
    for candidate in candidates:
        if candidate.score < dynamic_threshold or len(selected_policy_ids) >= max_selected:
            break
        candidate.selected = True
        selected_policy_ids.append(candidate.policy_id)

    ambiguous_policy_ids = [
        candidate.policy_id
        for candidate in candidates
        if not candidate.selected and candidate.score >= dynamic_threshold - 0.5
    ]

    return PolicySelectionResult(
        request_id=request.request.request_id,
        requested_service=request.request.requested_service.label,
        selected_policy_ids=selected_policy_ids,
        ambiguous_policy_ids=ambiguous_policy_ids,
        candidates=candidates,
    )


def _tokenize(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 2 and token not in _STOPWORDS and not token.isdigit()
    }


def _request_terms(request: HealthcarePolicyRequest) -> set[str]:
    terms = set()
    terms.update(_tokenize(request.request.requested_service.label))
    terms.update(_tokenize(request.request.requested_service.code))
    if request.request.product:
        terms.update(_tokenize(request.request.product))
    if request.request.line_of_business:
        terms.update(_tokenize(request.request.line_of_business))
    return terms


def _request_evidence_terms(request: HealthcarePolicyRequest) -> set[str]:
    terms = set()
    for event in request.member_evidence.structured_events:
        terms.update(_tokenize(event.label))
        terms.update(_tokenize(event.code))
    return terms


def _policy_terms(policy: HealthcarePolicySlice) -> set[str]:
    terms = set()
    terms.update(_tokenize(policy.policy_id))
    terms.update(_tokenize(policy.title))
    for source in policy.sources:
        terms.update(_tokenize(source.title))
        terms.update(_tokenize(source.section_note or ""))
    return terms
