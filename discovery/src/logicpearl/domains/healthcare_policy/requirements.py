from __future__ import annotations

import re
from enum import Enum

from pydantic import field_validator

from logicpearl.ir.models import LogicPearlModel


class RequirementFamily(str, Enum):
    STEP_THERAPY = "step_therapy"
    PHYSICAL_THERAPY_PREREQ = "physical_therapy_prereq"
    DIAGNOSIS_REQUIREMENT = "diagnosis_requirement"
    CONSERVATIVE_THERAPY_PREREQ = "conservative_therapy_prereq"
    DOCUMENTATION_REQUIREMENT = "documentation_requirement"
    PRIOR_AUTH = "prior_auth"
    WORKFLOW_ADMIN = "workflow_admin"


class RequirementStatus(str, Enum):
    EXTRACTED = "extracted"
    NEEDS_REVIEW = "needs_review"
    NORMALIZED = "normalized"


class RequirementRecord(LogicPearlModel):
    requirement_id: str
    candidate_id: str
    document_id: str
    filename: str
    title: str
    document_kind: str
    page_number: int
    source_section_kind: str
    source_section_heading: str
    requirement_family: RequirementFamily
    normalized_statement: str
    evidence_hint: str
    cluster_placeholder_id: str
    mapping_status: str = "unmapped"
    confidence: float
    status: RequirementStatus
    source_snippet: str

    @field_validator(
        "requirement_id",
        "candidate_id",
        "document_id",
        "filename",
        "title",
        "document_kind",
        "source_section_kind",
        "source_section_heading",
        "normalized_statement",
        "evidence_hint",
        "cluster_placeholder_id",
        "mapping_status",
        "source_snippet",
    )
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("requirement record fields must be non-empty")
        return value


def normalize_requirement_candidate(candidate: dict) -> RequirementRecord:
    family = RequirementFamily(candidate["candidate_kind"])
    snippet = normalize_snippet(candidate["snippet"])
    evidence_hint = infer_evidence_hint(family, snippet)
    cluster_placeholder = build_cluster_placeholder_id(family, evidence_hint)
    source_section_kind = candidate.get("source_section_kind", "unknown")
    source_section_heading = candidate.get("source_section_heading", source_section_kind.replace("_", " "))
    confidence = infer_confidence(family, snippet, source_section_kind)
    status = RequirementStatus.NORMALIZED if confidence >= 0.75 else RequirementStatus.NEEDS_REVIEW

    return RequirementRecord(
        requirement_id=f"req-{candidate['candidate_id']}",
        candidate_id=candidate["candidate_id"],
        document_id=candidate["document_id"],
        filename=candidate["filename"],
        title=candidate["title"],
        document_kind=candidate["document_kind"],
        page_number=int(candidate["page_number"]),
        source_section_kind=source_section_kind,
        source_section_heading=source_section_heading,
        requirement_family=family,
        normalized_statement=snippet,
        evidence_hint=evidence_hint,
        cluster_placeholder_id=cluster_placeholder,
        confidence=confidence,
        status=status,
        source_snippet=snippet,
    )


def summarize_requirement_families(records: list[RequirementRecord]) -> dict[str, int]:
    summary = {family.value: 0 for family in RequirementFamily}
    for record in records:
        family_value = (
            record.requirement_family.value
            if isinstance(record.requirement_family, RequirementFamily)
            else str(record.requirement_family)
        )
        summary[family_value] += 1
    return summary


def normalize_snippet(snippet: str) -> str:
    text = re.sub(r"\s+", " ", snippet).strip()
    return text.rstrip(" .") + "."


def infer_evidence_hint(family: RequirementFamily, snippet: str) -> str:
    lower = snippet.lower()
    if family is RequirementFamily.STEP_THERAPY:
        if "preferred/non-preferred drug sequence" in lower:
            return "preferred_nonpreferred_drug_sequence"
        if "formulary alternatives" in lower:
            return "trial_of_formulary_alternatives"
        return "prior_trial_of_step_therapy_medication"
    if family is RequirementFamily.PHYSICAL_THERAPY_PREREQ:
        if "manual chest physical therapy" in lower or "chest physical therapy" in lower:
            return "prior_chest_physical_therapy"
        return "prior_physical_therapy"
    if family is RequirementFamily.CONSERVATIVE_THERAPY_PREREQ:
        return "failed_conservative_therapy"
    if family is RequirementFamily.DOCUMENTATION_REQUIREMENT:
        if "genetic test" in lower:
            return "supporting_genetic_test_documentation"
        return "supporting_clinical_documentation"
    if family is RequirementFamily.DIAGNOSIS_REQUIREMENT:
        if "genetic test confirming diagnosis" in lower:
            return "confirmed_diagnosis_via_genetic_test"
        return "qualifying_diagnosis"
    if family is RequirementFamily.WORKFLOW_ADMIN:
        if "request form" in lower or "coverage determination" in lower:
            return "workflow_request_form"
        if "clinical exception process" in lower:
            return "workflow_exception_process"
        if "directory of documents" in lower:
            return "workflow_document_directory"
        return "workflow_program_routing"
    return "prior_authorization_workflow"


def build_cluster_placeholder_id(family: RequirementFamily, evidence_hint: str) -> str:
    return f"{family.value}__{slugify(evidence_hint)}"


def infer_confidence(family: RequirementFamily, snippet: str, source_section_kind: str) -> float:
    lower = snippet.lower()
    confidence = 0.65

    if source_section_kind in {"policy", "coverage_criteria"}:
        confidence += 0.15
    elif source_section_kind in {"prior_authorization_information", "authorization_information"}:
        confidence += 0.05

    if family is RequirementFamily.STEP_THERAPY and "step therapy" in lower:
        confidence += 0.15
    if family is RequirementFamily.DIAGNOSIS_REQUIREMENT and (
        "requires diagnosis" in lower or "diagnosis only" in lower or "confirming diagnosis" in lower
    ):
        confidence += 0.15
    if family is RequirementFamily.PHYSICAL_THERAPY_PREREQ and "physical therapy" in lower:
        confidence += 0.1
    if family is RequirementFamily.CONSERVATIVE_THERAPY_PREREQ and "conservative therapy" in lower:
        confidence += 0.1
    if family is RequirementFamily.DOCUMENTATION_REQUIREMENT and "documentation" in lower:
        confidence += 0.1
    if family is RequirementFamily.PRIOR_AUTH and "prior authorization" in lower:
        confidence += 0.05
    if family is RequirementFamily.WORKFLOW_ADMIN:
        confidence += 0.05

    return min(confidence, 0.98)


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
