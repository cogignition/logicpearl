from __future__ import annotations

import re
from enum import Enum

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel

from .curation import requirement_priority_score


class ReviewedClusterMappingStatus(str, Enum):
    REVIEWED = "reviewed"


class ReviewedClusterMappingRecord(LogicPearlModel):
    cluster_id: str
    family: str
    evidence_hint: str
    label: str
    kind: str
    status: ReviewedClusterMappingStatus
    source_requirement_count: int
    source_requirement_ids: list[str]
    aliases: list[str] = Field(default_factory=list)
    codes: list[str] = Field(default_factory=list)
    review_method: str

    @field_validator("cluster_id", "family", "evidence_hint", "label", "kind", "review_method")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("reviewed cluster mapping fields must be non-empty")
        return value


class RequirementSelectionRecord(LogicPearlModel):
    policy_id: str
    title: str
    cluster_id: str
    selected_requirement_id: str
    source_requirement_ids: list[str]
    rejected_requirement_ids: list[str]
    selection_method: str
    selected_source_section: str

    @field_validator(
        "policy_id",
        "title",
        "cluster_id",
        "selected_requirement_id",
        "selection_method",
        "selected_source_section",
    )
    @classmethod
    def validate_non_empty_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("requirement selection fields must be non-empty")
        return value


def review_cluster_mapping_records(cluster_mappings: list[dict]) -> list[ReviewedClusterMappingRecord]:
    reviewed: list[ReviewedClusterMappingRecord] = []
    for mapping in sorted(cluster_mappings, key=lambda row: row["cluster_id"]):
        kind = _cluster_kind_for_family(mapping["family"])
        aliases = _reviewed_aliases(mapping)
        reviewed.append(
            ReviewedClusterMappingRecord(
                cluster_id=mapping["cluster_id"],
                family=mapping["family"],
                evidence_hint=mapping["evidence_hint"],
                label=mapping["label"],
                kind=kind,
                status=ReviewedClusterMappingStatus.REVIEWED,
                source_requirement_count=mapping["source_requirement_count"],
                source_requirement_ids=mapping["source_requirement_ids"],
                aliases=aliases,
                codes=[_canonical_code(alias, cluster_id=mapping["cluster_id"], kind=kind) for alias in aliases],
                review_method="deterministic_auto_review_v1",
            )
        )
    return reviewed


def build_requirement_selection_records(policy, requirement_records: list[dict]) -> list[RequirementSelectionRecord]:
    records_by_id = {record["requirement_id"]: record for record in requirement_records}
    grouped: dict[str, list] = {}
    for requirement in policy.requirements:
        grouped.setdefault(requirement.cluster_id, []).append(requirement)

    selections: list[RequirementSelectionRecord] = []
    for cluster_id, requirements in sorted(grouped.items()):
        best = max(
            requirements,
            key=lambda requirement: requirement_priority_score(
                requirement,
                records_by_id.get(requirement.requirement_id),
            ),
        )
        requirement_ids = [requirement.requirement_id for requirement in requirements]
        selections.append(
            RequirementSelectionRecord(
                policy_id=policy.policy_id,
                title=policy.title,
                cluster_id=cluster_id,
                selected_requirement_id=best.requirement_id,
                source_requirement_ids=requirement_ids,
                rejected_requirement_ids=[
                    requirement_id for requirement_id in requirement_ids if requirement_id != best.requirement_id
                ],
                selection_method="deterministic_priority_curation_v1",
                selected_source_section=best.source_section,
            )
        )
    return selections


def _reviewed_aliases(mapping: dict) -> list[str]:
    aliases = [
        alias["alias"].strip()
        for alias in mapping.get("alias_candidates", [])
        if alias.get("alias", "").strip()
    ]
    if not aliases:
        aliases = [mapping["evidence_hint"].replace("_", " ")]

    reviewed: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        cleaned = re.sub(r"\s+", " ", alias).strip(" .,:;")
        if len(cleaned) < 3:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        reviewed.append(cleaned)
    return reviewed[:8]


def _canonical_code(alias: str, *, cluster_id: str, kind: str) -> str:
    alias_slug = re.sub(r"[^a-z0-9]+", "_", alias.lower()).strip("_")
    cluster_slug = re.sub(r"[^a-z0-9]+", "_", cluster_id.lower()).strip("_")
    return f"{kind.upper()}__{cluster_slug.upper()}__{alias_slug.upper()}"


def _cluster_kind_for_family(family: str) -> str:
    if family == "diagnosis_requirement":
        return "diagnosis"
    if family == "physical_therapy_prereq":
        return "procedure"
    if family == "documentation_requirement":
        return "note_assertion"
    return "medication"
