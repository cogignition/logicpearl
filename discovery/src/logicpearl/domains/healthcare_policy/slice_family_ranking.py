from __future__ import annotations

from collections import Counter, defaultdict

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel


SLICE_FAMILIES = (
    "step_therapy",
    "physical_therapy_prereq",
    "diagnosis_requirement",
)


class SliceFamilyCandidate(LogicPearlModel):
    title: str
    page_number: int
    snippet: str
    candidate_kind: str

    @field_validator("title", "snippet", "candidate_kind")
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("slice family candidate fields must be non-empty")
        return value


class SliceFamilyDocument(LogicPearlModel):
    slice_family: str
    score: float
    document_id: str
    filename: str
    title: str
    document_kind: str
    candidate_counts: dict[str, int]
    sample_candidates: list[SliceFamilyCandidate] = Field(default_factory=list)

    @field_validator("slice_family", "document_id", "filename", "title", "document_kind")
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("slice family document fields must be non-empty")
        return value


def rank_slice_family_documents(
    *,
    documents: list[dict],
    candidates: list[dict],
    top_n: int = 5,
) -> dict[str, list[SliceFamilyDocument]]:
    document_map = {document["document_id"]: document for document in documents}
    grouped_candidates: dict[str, list[dict]] = defaultdict(list)
    grouped_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for candidate in candidates:
        grouped_candidates[candidate["document_id"]].append(candidate)
        grouped_counts[candidate["document_id"]][candidate["candidate_kind"]] += 1

    rankings: dict[str, list[SliceFamilyDocument]] = {family: [] for family in SLICE_FAMILIES}

    for family in SLICE_FAMILIES:
        scored: list[SliceFamilyDocument] = []
        for document_id, counts in grouped_counts.items():
            document = document_map.get(document_id)
            if document is None:
                continue
            score = _score_document_for_family(family, document, counts, grouped_candidates[document_id])
            if score <= 0:
                continue
            sample_candidates = [
                SliceFamilyCandidate(
                    title=candidate["title"],
                    page_number=candidate["page_number"],
                    snippet=candidate["snippet"],
                    candidate_kind=candidate["candidate_kind"],
                )
                for candidate in grouped_candidates[document_id]
                if candidate["candidate_kind"] == family
            ][:3]
            scored.append(
                SliceFamilyDocument(
                    slice_family=family,
                    score=score,
                    document_id=document_id,
                    filename=document["filename"],
                    title=document["title_guess"],
                    document_kind=document["document_kind"],
                    candidate_counts=dict(counts),
                    sample_candidates=sample_candidates,
                )
            )

        scored.sort(key=lambda item: (-item.score, item.title))
        rankings[family] = scored[:top_n]

    return rankings


def _score_document_for_family(
    family: str,
    document: dict,
    counts: Counter[str],
    candidates: list[dict],
) -> float:
    title = document["title_guess"].lower()
    document_kind = document["document_kind"]
    family_count = counts[family]
    if family_count == 0:
        return 0.0

    score = float(family_count)

    if family == "step_therapy":
        if document_kind == "medication_policy":
            score += 3.0
        if "step" in title:
            score += 2.0
        score += 0.1 * counts["prior_auth"]

    elif family == "physical_therapy_prereq":
        if document_kind == "medical_policy":
            score += 2.0
        score += 0.5 * counts["conservative_therapy_prereq"]
        if "musculoskeletal" in title or "pain" in title:
            score += 1.0

    elif family == "diagnosis_requirement":
        if document_kind == "medication_policy":
            score += 2.0
        if any("requires diagnosis" in candidate["snippet"].lower() for candidate in candidates):
            score += 2.0
        if any("diagnosis only" in candidate["snippet"].lower() for candidate in candidates):
            score += 1.0

    return score
