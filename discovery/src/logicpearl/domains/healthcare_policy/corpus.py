from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel


HEX_ESCAPE_RE = re.compile(r"_([0-9A-Fa-f]{2})")
POLICY_NUMBER_RE = re.compile(r"^(?P<policy_number>\d{3}[A-Z]?)")


class CorpusDocumentKind(str, Enum):
    MEDICAL_POLICY = "medical_policy"
    MEDICATION_POLICY = "medication_policy"
    PRIOR_AUTH_FORM = "prior_auth_form"
    CODE_REFERENCE = "code_reference"
    ADMINISTRATIVE = "administrative"
    OTHER = "other"


class CorpusDocumentRecord(LogicPearlModel):
    document_id: str
    filename: str
    relative_pdf_path: str
    relative_text_path: str
    sha1: str
    size_bytes: int
    page_count: int
    extracted_char_count: int
    non_whitespace_char_count: int
    title_guess: str
    policy_number: str | None = None
    document_kind: CorpusDocumentKind
    decision_bearing: bool
    classification_signals: list[str] = Field(default_factory=list)
    source_url: str | None = None
    discovered_via: str | None = None
    source_page: str | None = None
    extraction_status: str = "ok"

    @field_validator(
        "document_id",
        "filename",
        "relative_pdf_path",
        "relative_text_path",
        "sha1",
        "title_guess",
        "extraction_status",
    )
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("record fields must be non-empty")
        return value


def derive_document_id(filename: str) -> str:
    stem = Path(filename).stem.lower()
    stem = HEX_ESCAPE_RE.sub(_decode_hex_escape, stem)
    stem = re.sub(r"[^a-z0-9]+", "-", stem).strip("-")
    return stem


def decode_bcbsma_filename(filename: str) -> str:
    stem = Path(filename).stem
    stem = HEX_ESCAPE_RE.sub(_decode_hex_escape, stem)
    stem = stem.replace("_", " ")
    stem = re.sub(r"\s+", " ", stem).strip()
    return stem


def guess_title_from_filename(filename: str) -> str:
    decoded = decode_bcbsma_filename(filename)
    return decoded


def extract_policy_number(filename: str) -> str | None:
    match = POLICY_NUMBER_RE.match(decode_bcbsma_filename(filename))
    if not match:
        return None
    return match.group("policy_number")


def classify_corpus_document(filename: str, extracted_text: str) -> tuple[CorpusDocumentKind, list[str]]:
    title_text = decode_bcbsma_filename(filename).lower()
    lead_text = extracted_text[:2500].lower()
    haystack = " ".join(part for part in [title_text, lead_text] if part)
    signals: list[str] = []

    if not extracted_text.strip():
        if any(phrase in title_text for phrase in PRIOR_AUTH_FORM_TITLE_PHRASES):
            signals.append("prior_auth_form_title")
            signals.append("empty_text")
            return CorpusDocumentKind.PRIOR_AUTH_FORM, signals
        if any(phrase in title_text for phrase in CODE_REFERENCE_TITLE_PHRASES):
            signals.append("code_reference_title")
            signals.append("empty_text")
            return CorpusDocumentKind.CODE_REFERENCE, signals
        if any(phrase in title_text for phrase in ADMINISTRATIVE_TITLE_PHRASES):
            signals.append("administrative_title")
            signals.append("empty_text")
            return CorpusDocumentKind.ADMINISTRATIVE, signals

    if any(phrase in title_text for phrase in PRIOR_AUTH_FORM_TITLE_PHRASES):
        signals.append("prior_auth_form_title")
        return CorpusDocumentKind.PRIOR_AUTH_FORM, signals

    if any(phrase in title_text for phrase in CODE_REFERENCE_TITLE_PHRASES):
        signals.append("code_reference_title")
        return CorpusDocumentKind.CODE_REFERENCE, signals

    if any(phrase in title_text for phrase in ADMINISTRATIVE_TITLE_PHRASES):
        signals.append("administrative_title")
        return CorpusDocumentKind.ADMINISTRATIVE, signals

    if "pharmacy medical policy" in lead_text:
        signals.append("pharmacy_medical_policy_header")
        return CorpusDocumentKind.MEDICATION_POLICY, signals

    if any(phrase in haystack for phrase in MEDICATION_POLICY_PHRASES):
        signals.append("medication_policy_phrase")
        return CorpusDocumentKind.MEDICATION_POLICY, signals

    if "medical policy" in lead_text:
        signals.append("medical_policy_header")
        return CorpusDocumentKind.MEDICAL_POLICY, signals

    if any(phrase in haystack for phrase in MEDICAL_POLICY_PHRASES):
        signals.append("medical_policy_phrase")
        return CorpusDocumentKind.MEDICAL_POLICY, signals

    signals.append("fallback_other")
    return CorpusDocumentKind.OTHER, signals


def is_decision_bearing(kind: CorpusDocumentKind) -> bool:
    return kind in {CorpusDocumentKind.MEDICAL_POLICY, CorpusDocumentKind.MEDICATION_POLICY}


def summarize_document_kinds(records: list[CorpusDocumentRecord]) -> dict[str, int]:
    summary = {kind.value: 0 for kind in CorpusDocumentKind}
    for record in records:
        kind_value = (
            record.document_kind.value
            if isinstance(record.document_kind, CorpusDocumentKind)
            else str(record.document_kind)
        )
        summary[kind_value] += 1
    return summary


def _decode_hex_escape(match: re.Match[str]) -> str:
    return bytes.fromhex(match.group(1)).decode("utf-8", errors="ignore")


PRIOR_AUTH_FORM_TITLE_PHRASES = (
    "prior authorization request form",
    "prior authorization form",
    "service request form",
    "e form",
)

CODE_REFERENCE_TITLE_PHRASES = (
    "cpt and diagnoses codes",
    "diagnoses codes",
    "drug list",
    "medication list",
    "code list",
)

ADMINISTRATIVE_TITLE_PHRASES = (
    "terms of use",
    "schedule",
    "guidelines",
    "medical technology assessment guidelines",
    "prior auth overview",
    "directory of documents",
    "what's new page",
    "whats new page",
    "clinical exception process",
    "definition of med nec",
    "agenda",
    "management program",
    "services management",
    "management",
)

MEDICATION_POLICY_PHRASES = (
    "step policy",
    "step therapy",
    "medication management",
    "drug management",
    "injectable",
    "immunomodulators",
    "policy for",
    "drugs for",
)

MEDICAL_POLICY_PHRASES = (
    "medical policy",
    "medically necessary",
    "not medically necessary",
    "clinical input",
    "policy statement",
)
