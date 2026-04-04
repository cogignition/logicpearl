from __future__ import annotations

import re
from enum import Enum

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel


class ClusterMappingStatus(str, Enum):
    UNMAPPED = "unmapped"
    CANDIDATE = "candidate"
    REVIEWED = "reviewed"


class ClusterAliasCandidate(LogicPearlModel):
    alias: str
    count: int

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if not value:
            raise ValueError("alias must be non-empty")
        return value


class ClusterMappingRecord(LogicPearlModel):
    cluster_id: str
    family: str
    evidence_hint: str
    label: str
    status: ClusterMappingStatus
    source_requirement_count: int
    source_requirement_ids: list[str]
    alias_candidates: list[ClusterAliasCandidate] = Field(default_factory=list)
    sample_statements: list[str] = Field(default_factory=list)

    @field_validator("cluster_id", "family", "evidence_hint", "label")
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("cluster mapping fields must be non-empty")
        return value


def build_cluster_mapping_records(requirement_records: list[dict]) -> list[ClusterMappingRecord]:
    grouped: dict[str, list[dict]] = {}
    for record in requirement_records:
        grouped.setdefault(record["cluster_placeholder_id"], []).append(record)

    mappings: list[ClusterMappingRecord] = []
    for cluster_id, records in sorted(grouped.items()):
        family, evidence_hint = split_cluster_placeholder_id(cluster_id)
        alias_candidates = infer_alias_candidates(records, family)
        sample_statements = [record["normalized_statement"] for record in records[:3]]
        status = ClusterMappingStatus.CANDIDATE if alias_candidates else ClusterMappingStatus.UNMAPPED
        mappings.append(
            ClusterMappingRecord(
                cluster_id=cluster_id,
                family=family,
                evidence_hint=evidence_hint,
                label=build_cluster_label(family, evidence_hint),
                status=status,
                source_requirement_count=len(records),
                source_requirement_ids=[record["requirement_id"] for record in records],
                alias_candidates=alias_candidates,
                sample_statements=sample_statements,
            )
        )

    return mappings


def summarize_cluster_mapping_status(records: list[ClusterMappingRecord]) -> dict[str, int]:
    summary = {status.value: 0 for status in ClusterMappingStatus}
    for record in records:
        status_value = record.status.value if isinstance(record.status, ClusterMappingStatus) else str(record.status)
        summary[status_value] += 1
    return summary


def split_cluster_placeholder_id(cluster_id: str) -> tuple[str, str]:
    family, _, evidence_hint = cluster_id.partition("__")
    return family, evidence_hint


def build_cluster_label(family: str, evidence_hint: str) -> str:
    return f"{family.replace('_', ' ').title()}: {evidence_hint.replace('_', ' ')}"


def infer_alias_candidates(records: list[dict], family: str) -> list[ClusterAliasCandidate]:
    counts: dict[str, int] = {}
    for record in records:
        for alias in extract_aliases_from_statement(record["normalized_statement"], family):
            counts[alias] = counts.get(alias, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [ClusterAliasCandidate(alias=alias, count=count) for alias, count in ranked[:8]]


def extract_aliases_from_statement(statement: str, family: str) -> list[str]:
    aliases: list[str] = []
    lower = statement.lower()

    bullet_aliases = re.findall(r"•\s*([^•]{3,80})", statement)
    for alias in bullet_aliases:
        cleaned = clean_alias(alias)
        if cleaned:
            aliases.append(cleaned)

    if family == "diagnosis_requirement":
        colon_phrases = re.findall(r"([A-Za-z][A-Za-z0-9\s\-/()]{2,60}):\s*(?:requires diagnosis only|diagnosis only)", statement, flags=re.IGNORECASE)
        for phrase in colon_phrases:
            cleaned = clean_alias(phrase)
            if cleaned:
                aliases.append(cleaned)
        for match in re.findall(r"(?:diagnosed with|diagnosis of|requires diagnosis only|diagnosis only)\s+([^.;:]{3,80})", lower):
            cleaned = clean_alias(match)
            if cleaned:
                aliases.append(cleaned)

    if family == "physical_therapy_prereq":
        if "chest physical therapy" in lower:
            aliases.append("chest physical therapy")
        if "manual chest physical therapy" in lower:
            aliases.append("manual chest physical therapy")
        if "physical therapy" in lower:
            aliases.append("physical therapy")

    if family == "conservative_therapy_prereq" and "conservative therapy" in lower:
        aliases.append("conservative therapy")

    if family == "step_therapy":
        if "formulary alternatives" in lower:
            aliases.append("formulary alternatives")
        if "step therapy" in lower:
            aliases.append("step therapy")

    if family == "documentation_requirement":
        if "genetic testing" in lower or "genetic test" in lower:
            aliases.append("genetic testing")
        if "documentation" in lower:
            aliases.append("clinical documentation")

    normalized = []
    seen = set()
    for alias in aliases:
        key = alias.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(alias)
    return normalized


def clean_alias(value: str) -> str:
    value = re.sub(r"\([^)]*\)", "", value)
    value = re.sub(r"\s+", " ", value).strip(" .,:;")
    value = re.sub(r"^[0-9ivx\-\)\(]+\s*", "", value, flags=re.IGNORECASE)
    if len(value) < 3:
        return ""
    word_count = len(value.split())
    if word_count > 8:
        return ""
    if not re.search(r"[A-Za-z]", value):
        return ""
    if value.lower() in {"pa", "qcd", "spbo", "med", "rx"}:
        return ""
    lowered = value.lower()
    if lowered.startswith(("for ", "the ", "there ", "during ", "clinical ", "documentation ", "policy ")):
        return ""
    if any(token in lowered for token in ("prior authorization", "provider documentation requirements", "individual consideration")):
        return ""
    return value
