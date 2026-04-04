from __future__ import annotations

import re
from enum import Enum

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel


PAGE_MARKER_RE = re.compile(r"=== Page (?P<page>\d+) ===\n?")


class SliceCandidateKind(str, Enum):
    STEP_THERAPY = "step_therapy"
    PHYSICAL_THERAPY_PREREQ = "physical_therapy_prereq"
    DIAGNOSIS_REQUIREMENT = "diagnosis_requirement"
    CONSERVATIVE_THERAPY_PREREQ = "conservative_therapy_prereq"
    PRIOR_AUTH = "prior_auth"
    DOCUMENTATION_REQUIREMENT = "documentation_requirement"
    WORKFLOW_ADMIN = "workflow_admin"
    OTHER = "other"


class SliceCandidate(LogicPearlModel):
    candidate_id: str
    document_id: str
    filename: str
    title: str
    document_kind: str
    page_number: int
    source_section_kind: str
    source_section_heading: str
    candidate_kind: SliceCandidateKind
    matched_pattern: str
    snippet: str

    @field_validator(
        "candidate_id",
        "document_id",
        "filename",
        "title",
        "document_kind",
        "source_section_kind",
        "source_section_heading",
        "matched_pattern",
        "snippet",
    )
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("candidate fields must be non-empty")
        return value


def split_extracted_text_by_page(extracted_text: str) -> list[tuple[int, str]]:
    matches = list(PAGE_MARKER_RE.finditer(extracted_text))
    if not matches:
        stripped = extracted_text.strip()
        return [(1, stripped)] if stripped else []

    pages: list[tuple[int, str]] = []
    for index, match in enumerate(matches):
        page_number = int(match.group("page"))
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(extracted_text)
        page_text = extracted_text[start:end].strip()
        if page_text:
            pages.append((page_number, page_text))
    return pages


def extract_slice_candidates(
    *,
    document_id: str,
    filename: str,
    title: str,
    document_kind: str,
    extracted_text: str,
    max_candidates_per_document: int = 20,
) -> list[SliceCandidate]:
    candidates: list[SliceCandidate] = []

    for page_number, page_text in split_extracted_text_by_page(extracted_text):
        for paragraph in _candidate_paragraphs(page_text):
            candidate_kind, matched_pattern = classify_candidate_paragraph(title, paragraph)
            if candidate_kind is SliceCandidateKind.OTHER:
                continue
            candidate = SliceCandidate(
                candidate_id=f"{document_id}-p{page_number}-{len(candidates) + 1:03d}",
                document_id=document_id,
                filename=filename,
                title=title,
                document_kind=document_kind,
                page_number=page_number,
                source_section_kind="full_document",
                source_section_heading="Full Document",
                candidate_kind=candidate_kind,
                matched_pattern=matched_pattern,
                snippet=paragraph,
            )
            candidates.append(candidate)
            if len(candidates) >= max_candidates_per_document:
                return candidates

    return candidates


def extract_slice_candidates_from_sections(
    *,
    document_id: str,
    filename: str,
    title: str,
    document_kind: str,
    sections: list[dict] | list[LogicPearlModel],
    max_candidates_per_document: int = 20,
) -> list[SliceCandidate]:
    candidates: list[SliceCandidate] = []
    for section in sections:
        section_kind = _section_value(section, "section_kind")
        if section_kind not in DEFAULT_CANDIDATE_SECTION_KINDS:
            continue
        page_number = int(_section_value(section, "page_start"))
        section_text = str(_section_value(section, "text"))
        section_heading = str(_section_value(section, "heading"))
        for paragraph in _candidate_paragraphs(section_text):
            candidate_kind, matched_pattern = classify_candidate_paragraph(title, paragraph)
            if candidate_kind is SliceCandidateKind.OTHER:
                continue
            candidate = SliceCandidate(
                candidate_id=f"{document_id}-p{page_number}-{len(candidates) + 1:03d}",
                document_id=document_id,
                filename=filename,
                title=title,
                document_kind=document_kind,
                page_number=page_number,
                source_section_kind=section_kind,
                source_section_heading=section_heading,
                candidate_kind=candidate_kind,
                matched_pattern=matched_pattern,
                snippet=paragraph,
            )
            candidates.append(candidate)
            if len(candidates) >= max_candidates_per_document:
                return candidates
    return candidates


def classify_candidate_paragraph(title: str, paragraph: str) -> tuple[SliceCandidateKind, str]:
    haystack = paragraph.lower()

    for kind, pattern in CANDIDATE_PATTERNS:
        if re.search(pattern, haystack):
            return kind, pattern
    return SliceCandidateKind.OTHER, "fallback_other"


def summarize_candidate_kinds(candidates: list[SliceCandidate]) -> dict[str, int]:
    summary = {kind.value: 0 for kind in SliceCandidateKind}
    for candidate in candidates:
        kind_value = (
            candidate.candidate_kind.value
            if isinstance(candidate.candidate_kind, SliceCandidateKind)
            else str(candidate.candidate_kind)
        )
        summary[kind_value] += 1
    return summary


def _candidate_paragraphs(page_text: str) -> list[str]:
    page_text = page_text.replace("•", "\n• ")
    chunks = re.split(r"\n\s*\n", page_text)
    paragraphs: list[str] = []
    for chunk in chunks:
        normalized = _normalize_whitespace(chunk)
        if len(normalized) < 40:
            continue
        if any(re.search(pattern, normalized.lower()) for pattern in SKIP_PARAGRAPH_PATTERNS):
            continue
        paragraphs.append(normalized)
    return paragraphs


def _section_value(section: dict | LogicPearlModel, field: str) -> object:
    if isinstance(section, dict):
        if field == "heading":
            return section.get("heading", str(section.get("section_kind", "section")).replace("_", " "))
        return section[field]
    return getattr(section, field)


def _normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


CANDIDATE_PATTERNS: list[tuple[SliceCandidateKind, str]] = [
    (SliceCandidateKind.STEP_THERAPY, r"\bstep therapy\b|\bstep policy\b|first-step|first line"),
    (SliceCandidateKind.PHYSICAL_THERAPY_PREREQ, r"\bphysical therapy\b"),
    (SliceCandidateKind.CONSERVATIVE_THERAPY_PREREQ, r"\bconservative therapy\b|failed conservative|unresponsive to at least \d+ months"),
    (SliceCandidateKind.DIAGNOSIS_REQUIREMENT, r"requires diagnosis|qualifying diagnosis|diagnosed with|diagnosis only|must have .* diagnosis"),
    (SliceCandidateKind.DOCUMENTATION_REQUIREMENT, r"\bdocumentation\b|must include|should include"),
    (SliceCandidateKind.WORKFLOW_ADMIN, r"\brequest form\b|\bcoverage determination request form\b|\bprogram\b|\bservices management\b|\bclinical exception process\b|\bdirectory of documents\b"),
    (SliceCandidateKind.PRIOR_AUTH, r"\bprior authorization\b|authorization information"),
]

SKIP_PARAGRAPH_PATTERNS = (
    r"^table of contents\b",
    r"^policy history\b",
    r"^references\b",
    r"^coding information\b",
    r"^cpt codes / hcpcs codes / icd codes\b",
    r"^bcbsa reference number\b",
)

DEFAULT_CANDIDATE_SECTION_KINDS = {
    "policy",
    "coverage_criteria",
    "prior_authorization_information",
    "authorization_information",
    "summary",
}
