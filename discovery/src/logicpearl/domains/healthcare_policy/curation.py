from __future__ import annotations

from copy import deepcopy

from .models import ArtifactProvenance, HealthcarePolicySlice


SECTION_PRIORITY = {
    "coverage criteria": 5,
    "policy": 4,
    "summary": 3,
    "prior authorization information": 2,
    "authorization information": 2,
}


def curate_healthcare_policy_slice(
    policy: HealthcarePolicySlice,
    requirement_records: list[dict],
) -> HealthcarePolicySlice:
    records_by_id = {record["requirement_id"]: record for record in requirement_records}
    grouped: dict[str, list] = {}
    for requirement in policy.requirements:
        grouped.setdefault(requirement.cluster_id, []).append(requirement)

    curated_requirements = []
    for cluster_id, requirements in grouped.items():
        best = max(
            requirements,
            key=lambda requirement: requirement_priority_score(
                requirement,
                records_by_id.get(requirement.requirement_id),
            ),
        )
        curated_requirements.append(best)

    curated_requirements.sort(key=lambda requirement: requirement.requirement_id)
    curated_cluster_ids = {requirement.cluster_id for requirement in curated_requirements}
    curated_clusters = [cluster for cluster in policy.clusters if cluster.cluster_id in curated_cluster_ids]

    updated = policy.model_copy(
        update={
            "requirements": curated_requirements,
            "clusters": curated_clusters,
            "source_note": (
                policy.source_note
                + " Curated automatically to collapse duplicate requirement candidates by cluster before compilation."
            ),
            "provenance": ArtifactProvenance(
                artifact_version=policy.provenance.artifact_version,
                generated_by="logicpearl.healthcare_policy_curation",
                generated_at=policy.provenance.generated_at,
                review_status="draft",
                adapted_for_demo=policy.provenance.adapted_for_demo,
                effective_date=policy.provenance.effective_date,
                source_commit=policy.provenance.source_commit,
            ),
        }
    )
    return updated


def requirement_priority_score(requirement, record: dict | None) -> tuple[float, int, int]:
    confidence = float(record.get("confidence", 0.0)) if record else 0.0
    section = (record.get("source_section_heading", "") if record else requirement.source_section).lower()
    section_score = SECTION_PRIORITY.get(section, 0)
    snippet_length_bonus = -len(requirement.source_excerpt)
    return confidence, section_score, snippet_length_bonus
