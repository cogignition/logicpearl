from __future__ import annotations

import re
from typing import Iterable

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel
from logicpearl.domains.healthcare_policy.slice_candidates import PAGE_MARKER_RE


class DocumentSection(LogicPearlModel):
    section_id: str
    section_kind: str
    heading: str
    page_start: int
    text: str

    @field_validator("section_id", "section_kind", "heading", "text")
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("section fields must be non-empty")
        return value


def extract_policy_sections(extracted_text: str) -> list[DocumentSection]:
    lines = extracted_text.splitlines()
    sections: list[DocumentSection] = []
    current_page = 1
    current_heading: str | None = None
    current_kind: str | None = None
    current_page_start = 1
    buffer: list[str] = []

    def flush() -> None:
        nonlocal buffer, current_heading, current_kind, current_page_start
        normalized = _normalize_block(buffer)
        if not normalized:
            return
        heading = current_heading or "Document Body"
        kind = current_kind or "document_body"
        sections.append(
            DocumentSection(
                section_id=f"{kind}-{len(sections) + 1:03d}",
                section_kind=kind,
                heading=heading,
                page_start=current_page_start,
                text=normalized,
            )
        )
        buffer = []

    for raw_line in lines:
        page_match = PAGE_MARKER_RE.match(raw_line.strip())
        if page_match:
            current_page = int(page_match.group("page"))
            continue

        normalized_line = _normalize_line(raw_line)
        if not normalized_line:
            buffer.append("")
            continue

        section_match = match_section_heading(normalized_line)
        if section_match:
            flush()
            current_heading = normalized_line
            current_kind = section_match
            current_page_start = current_page
            continue

        buffer.append(normalized_line)

    flush()
    return sections


def match_section_heading(line: str) -> str | None:
    normalized = line.strip().lower().rstrip(":")
    for pattern, section_kind in SECTION_HEADING_PATTERNS:
        if re.fullmatch(pattern, normalized):
            return section_kind
    return None


def summarize_section_kinds(section_documents: Iterable[list[DocumentSection]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sections in section_documents:
        for section in sections:
            counts[section.section_kind] = counts.get(section.section_kind, 0) + 1
    return dict(sorted(counts.items()))


def _normalize_line(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _normalize_block(lines: list[str]) -> str:
    paragraphs: list[str] = []
    current: list[str] = []
    for line in lines:
        if not line:
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            continue
        current.append(line)
    if current:
        paragraphs.append(" ".join(current).strip())
    return "\n\n".join(paragraphs).strip()


SECTION_HEADING_PATTERNS: list[tuple[str, str]] = [
    (r"policy", "policy"),
    (r"summary", "summary"),
    (r"coverage criteria", "coverage_criteria"),
    (r"authorization information", "authorization_information"),
    (r"prior authorization information", "prior_authorization_information"),
    (r"coding information", "coding_information"),
    (r"description", "description"),
    (r"background", "background"),
    (r"forms?", "forms"),
    (r"appendix", "appendix"),
    (r"references", "references"),
    (r"policy history", "policy_history"),
    (r"information pertaining to all policies", "all_policy_information"),
]
