from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from logicpearl.ir.models import LogicPearlModel


class ClinicalEventType(str, Enum):
    DIAGNOSIS = "diagnosis"
    PROCEDURE = "procedure"
    MEDICATION = "medication"
    NOTE_ASSERTION = "note_assertion"


class EvidenceRequirementKind(str, Enum):
    DIAGNOSIS_PRESENT = "diagnosis_present"
    PROCEDURE_COMPLETED = "procedure_completed"
    MEDICATION_TRIAL = "medication_trial"
    NOTE_ASSERTION_PRESENT = "note_assertion_present"


class CodeCluster(LogicPearlModel):
    cluster_id: str
    label: str
    kind: Literal["diagnosis", "procedure", "medication", "note_assertion"]
    codes: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)

    @field_validator("cluster_id", "label")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("cluster fields must be non-empty")
        return value

    @field_validator("codes", "aliases")
    @classmethod
    def normalize_entries(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            if not value:
                raise ValueError("cluster entries must be non-empty")
            normalized.append(value.strip())
        return normalized


class EvidenceRequirement(LogicPearlModel):
    requirement_id: str
    label: str
    question_text: str
    kind: EvidenceRequirementKind
    cluster_id: str
    evidence_needed: str
    source_excerpt: str
    source_id: str
    source_section: str
    source_anchor: str | None = None
    review_status: Literal["draft", "reviewed", "approved", "deprecated"] = "reviewed"
    required: bool = True

    @field_validator(
        "requirement_id",
        "label",
        "question_text",
        "cluster_id",
        "evidence_needed",
        "source_excerpt",
        "source_id",
        "source_section",
    )
    @classmethod
    def validate_required_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("requirement fields must be non-empty")
        return value


class PolicySource(LogicPearlModel):
    source_id: str
    title: str
    document_type: str
    publisher: str
    url: str
    section_note: str | None = None
    last_updated: str | None = None

    @field_validator("source_id", "title", "document_type", "publisher", "url")
    @classmethod
    def validate_source_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("policy source fields must be non-empty")
        return value


class ArtifactProvenance(LogicPearlModel):
    artifact_version: str
    generated_by: str
    generated_at: str
    review_status: Literal["draft", "reviewed", "approved"] = "reviewed"
    adapted_for_demo: bool = True
    effective_date: str | None = None
    source_commit: str | None = None

    @field_validator("artifact_version", "generated_by", "generated_at")
    @classmethod
    def validate_provenance_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("artifact provenance fields must be non-empty")
        return value


class HealthcarePolicySlice(LogicPearlModel):
    policy_id: str
    title: str
    source_url: str
    source_note: str
    adapted_for_demo: bool = True
    provenance: ArtifactProvenance
    sources: list[PolicySource]
    requirements: list[EvidenceRequirement]
    clusters: list[CodeCluster]

    @field_validator("policy_id", "title", "source_url", "source_note")
    @classmethod
    def validate_top_level_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("policy fields must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "HealthcarePolicySlice":
        requirement_ids = [requirement.requirement_id for requirement in self.requirements]
        duplicate_requirements = sorted(
            {requirement_id for requirement_id in requirement_ids if requirement_ids.count(requirement_id) > 1}
        )
        if duplicate_requirements:
            raise ValueError(f"duplicate requirement ids: {', '.join(duplicate_requirements)}")

        cluster_ids = [cluster.cluster_id for cluster in self.clusters]
        duplicate_clusters = sorted(
            {cluster_id for cluster_id in cluster_ids if cluster_ids.count(cluster_id) > 1}
        )
        if duplicate_clusters:
            raise ValueError(f"duplicate cluster ids: {', '.join(duplicate_clusters)}")

        missing_clusters = sorted(
            {requirement.cluster_id for requirement in self.requirements} - set(cluster_ids)
        )
        if missing_clusters:
            raise ValueError(f"requirements reference unknown clusters: {', '.join(missing_clusters)}")

        source_ids = [source.source_id for source in self.sources]
        duplicate_sources = sorted({source_id for source_id in source_ids if source_ids.count(source_id) > 1})
        if duplicate_sources:
            raise ValueError(f"duplicate source ids: {', '.join(duplicate_sources)}")

        missing_sources = sorted({requirement.source_id for requirement in self.requirements} - set(source_ids))
        if missing_sources:
            raise ValueError(f"requirements reference unknown sources: {', '.join(missing_sources)}")

        return self


class ClinicalEvent(LogicPearlModel):
    event_id: str
    event_type: ClinicalEventType
    code: str
    label: str
    source: str

    @field_validator("event_id", "code", "label", "source")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("clinical event fields must be non-empty")
        return value


class PatientCase(LogicPearlModel):
    case_id: str
    member_id: str
    requested_service: str
    events: list[ClinicalEvent]

    @field_validator("case_id", "member_id", "requested_service")
    @classmethod
    def validate_case_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("patient case fields must be non-empty")
        return value


class RequirementEvaluation(LogicPearlModel):
    requirement_id: str
    label: str
    question_text: str
    satisfied: bool
    evidence_status: Literal["found", "not_found"]
    source_excerpt: str
    source_id: str
    cluster_id: str
    matched_events: list[str] = Field(default_factory=list)
