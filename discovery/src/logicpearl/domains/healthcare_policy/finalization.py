from __future__ import annotations

from .models import ArtifactProvenance, CodeCluster, HealthcarePolicySlice


def assemble_final_logic_spec(
    policy: HealthcarePolicySlice,
    *,
    reviewed_cluster_mappings: list[dict],
    requirement_selections: list[dict],
) -> HealthcarePolicySlice:
    mapping_by_id = {mapping["cluster_id"]: mapping for mapping in reviewed_cluster_mappings}
    requirement_by_id = {requirement.requirement_id: requirement for requirement in policy.requirements}

    selected_requirements = []
    for selection in sorted(requirement_selections, key=lambda row: row["cluster_id"]):
        requirement = requirement_by_id.get(selection["selected_requirement_id"])
        if requirement is None:
            continue
        selected_requirements.append(
            requirement.model_copy(
                update={
                    "review_status": "approved",
                }
            )
        )

    final_clusters = []
    for requirement in selected_requirements:
        reviewed_mapping = mapping_by_id.get(requirement.cluster_id)
        if reviewed_mapping is None:
            continue
        final_clusters.append(
            CodeCluster(
                cluster_id=reviewed_mapping["cluster_id"],
                label=reviewed_mapping["label"],
                kind=reviewed_mapping["kind"],
                codes=reviewed_mapping["codes"],
                aliases=reviewed_mapping["aliases"],
            )
        )

    return policy.model_copy(
        update={
            "requirements": selected_requirements,
            "clusters": final_clusters,
            "source_note": (
                policy.source_note
                + " Final logic spec assembled from reviewed cluster mappings and reviewed requirement selections."
            ),
            "provenance": ArtifactProvenance(
                artifact_version=policy.provenance.artifact_version,
                generated_by="logicpearl.bcbsma_final_logic_spec_assembler",
                generated_at=policy.provenance.generated_at,
                review_status="approved",
                adapted_for_demo=False,
                effective_date=policy.provenance.effective_date,
                source_commit=policy.provenance.source_commit,
            ),
        }
    )
