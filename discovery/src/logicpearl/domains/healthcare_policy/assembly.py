from __future__ import annotations

from datetime import UTC, datetime

from .models import (
    ArtifactProvenance,
    CodeCluster,
    EvidenceRequirement,
    EvidenceRequirementKind,
    HealthcarePolicySlice,
    PolicySource,
)
from .presentation import family_question_text


def assemble_draft_logic_specs(
    *,
    documents: list[dict],
    requirement_records: list[dict],
    cluster_mappings: list[dict],
    ranked_examples: dict[str, dict | None] | None = None,
) -> list[HealthcarePolicySlice]:
    document_by_id = {document["document_id"]: document for document in documents}
    mapping_by_id = {mapping["cluster_id"]: mapping for mapping in cluster_mappings}
    targets = _target_document_families(requirement_records, ranked_examples=ranked_examples)

    specs: list[HealthcarePolicySlice] = []
    for document_id, slice_family in targets:
        document = document_by_id.get(document_id)
        if document is None:
            continue

        family_requirements = [
            record
            for record in requirement_records
            if record["document_id"] == document_id and record["requirement_family"] == slice_family
        ]
        if not family_requirements:
            continue

        source_id = f"source_{document['document_id'].replace('-', '_')}"
        sources = [
            PolicySource(
                source_id=source_id,
                title=document["title_guess"],
                document_type=document["document_kind"],
                publisher="Blue Cross Blue Shield of Massachusetts",
                url=document.get("source_url") or "https://www.bluecrossma.org/medical-policies/policy-listing-options",
                section_note=f"Draft logic spec assembled from processed BCBSMA {document['document_kind']} corpus document.",
            )
        ]

        clusters = []
        seen_clusters: set[str] = set()
        for record in family_requirements:
            cluster_id = record["cluster_placeholder_id"]
            if cluster_id in seen_clusters:
                continue
            seen_clusters.add(cluster_id)
            mapping = mapping_by_id.get(cluster_id)
            clusters.append(
                CodeCluster(
                    cluster_id=cluster_id,
                    label=(mapping["label"] if mapping else cluster_id.replace("__", ": ").replace("_", " ").title()),
                    kind=cluster_kind_for_family(record["requirement_family"]),
                    codes=[],
                    aliases=[alias["alias"] for alias in (mapping or {}).get("alias_candidates", [])[:8]],
                )
            )

        requirements = [
            EvidenceRequirement(
                requirement_id=record["requirement_id"],
                label=requirement_label(record),
                question_text=requirement_question_text(record),
                kind=requirement_kind_for_family(record["requirement_family"]),
                cluster_id=record["cluster_placeholder_id"],
                evidence_needed=evidence_needed_text(record),
                source_excerpt=record["source_snippet"],
                source_id=source_id,
                source_section=record["source_section_heading"],
                source_anchor=f"page-{record['page_number']}",
                review_status=("reviewed" if record["status"] == "normalized" else "draft"),
            )
            for record in family_requirements
        ]

        specs.append(
            HealthcarePolicySlice(
                policy_id=f"bcbsma_{slice_family}_{document_id.replace('-', '_')}",
                title=document["title_guess"],
                source_url=document.get("source_url") or "https://www.bluecrossma.org/medical-policies/policy-listing-options",
                source_note="Draft logic spec assembled automatically from the processed BCBSMA corpus, requirement records, and cluster-mapping artifacts.",
                adapted_for_demo=False,
                provenance=ArtifactProvenance(
                    artifact_version="0.1.0",
                    generated_by="logicpearl.bcbsma_draft_logic_spec_assembler",
                    generated_at=datetime.now(UTC).date().isoformat(),
                    review_status="draft",
                    adapted_for_demo=False,
                ),
                sources=sources,
                requirements=requirements,
                clusters=clusters,
            )
        )

    return sorted(specs, key=lambda spec: spec.policy_id)


def _target_document_families(
    requirement_records: list[dict],
    *,
    ranked_examples: dict[str, dict | None] | None,
) -> list[tuple[str, str]]:
    if ranked_examples:
        targets: list[tuple[str, str]] = []
        for slice_family, ranked in ranked_examples.items():
            if ranked is None:
                continue
            document_id = ranked.get("document_id")
            if document_id:
                targets.append((document_id, slice_family))
        return targets

    discovered = {
        (record["document_id"], record["requirement_family"])
        for record in requirement_records
        if record["requirement_family"] not in {"prior_auth", "workflow_admin"}
    }
    return sorted(discovered)


def cluster_kind_for_family(requirement_family: str) -> str:
    if requirement_family == "diagnosis_requirement":
        return "diagnosis"
    if requirement_family == "physical_therapy_prereq":
        return "procedure"
    return "medication"


def requirement_kind_for_family(requirement_family: str) -> EvidenceRequirementKind:
    if requirement_family == "diagnosis_requirement":
        return EvidenceRequirementKind.DIAGNOSIS_PRESENT
    if requirement_family == "physical_therapy_prereq":
        return EvidenceRequirementKind.PROCEDURE_COMPLETED
    return EvidenceRequirementKind.MEDICATION_TRIAL


def requirement_label(record: dict) -> str:
    family = record["requirement_family"]
    if family == "step_therapy":
        return "Prior step-therapy medication trial"
    if family == "physical_therapy_prereq":
        return "Prior physical therapy completed"
    if family == "diagnosis_requirement":
        return "Qualifying diagnosis present"
    if family == "conservative_therapy_prereq":
        return "Prior conservative therapy failed"
    if family == "documentation_requirement":
        return "Supporting documentation present"
    if family == "workflow_admin":
        return "Workflow or administrative requirement"
    return "Prior authorization workflow requirement"


def requirement_question_text(record: dict) -> str:
    return family_question_text(
        record["requirement_family"],
        cluster_id=record.get("cluster_placeholder_id"),
        evidence_needed=record.get("evidence_hint"),
    )


def evidence_needed_text(record: dict) -> str:
    return record["evidence_hint"].replace("_", " ")
