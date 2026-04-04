from __future__ import annotations

from .models import CodeCluster, EvidenceRequirement


def family_question_text(requirement_family: str, *, cluster_id: str | None = None, evidence_needed: str | None = None) -> str:
    specific = specific_question_text(cluster_id=cluster_id, evidence_needed=evidence_needed)
    if specific is not None:
        return specific
    if requirement_family == "step_therapy":
        return "Did we find evidence of a prior step-therapy medication trial?"
    if requirement_family == "physical_therapy_prereq":
        return "Did we find evidence of prior physical therapy?"
    if requirement_family == "diagnosis_requirement":
        return "Did we find evidence of a qualifying diagnosis?"
    if requirement_family == "conservative_therapy_prereq":
        return "Did we find evidence of failed conservative therapy?"
    if requirement_family == "documentation_requirement":
        return "Did we find the required supporting documentation?"
    if requirement_family == "workflow_admin":
        return "Did we identify the workflow or administrative requirement?"
    return "Did we find evidence that prior authorization workflow requirements were met?"


def question_text_for_requirement(
    requirement: EvidenceRequirement,
    *,
    cluster: CodeCluster | None = None,
    policy_title: str | None = None,
) -> str:
    base = specific_question_text(
        cluster_id=requirement.cluster_id,
        cluster_label=cluster.label if cluster else None,
        evidence_needed=requirement.evidence_needed,
        fallback=requirement.question_text,
    )
    if policy_title:
        return f"[{policy_title}] {base}"
    return base


def human_requirement_counterfactual(
    *,
    question_text: str,
    requirement_id: str,
    evidence_needed: str | None = None,
) -> dict:
    base_action = specific_requirement_action(evidence_needed=evidence_needed, question_text=question_text)
    return {
        "summary": base_action,
        "recommended_action": base_action,
        "machine_action": f"Set requirement__{requirement_id}__satisfied to 1.0.",
    }


def human_documentation_counterfactual(*, missing_document_kinds: list[str]) -> dict:
    readable_kinds = [_humanize_document_kind(kind) for kind in missing_document_kinds]
    if readable_kinds:
        joined = ", ".join(readable_kinds)
        summary = f"Provide at least one of the missing document types: {joined}."
    else:
        summary = "Provide one of the required supporting document types."
    return {
        "summary": summary,
        "recommended_action": summary,
    }


def specific_question_text(
    *,
    cluster_id: str | None = None,
    cluster_label: str | None = None,
    evidence_needed: str | None = None,
    fallback: str | None = None,
) -> str | None:
    key_parts = " ".join(filter(None, [cluster_id or "", cluster_label or "", evidence_needed or ""])).lower()
    if "trial_of_formulary_alternatives" in key_parts or "formulary alternative" in key_parts:
        return "Did we find evidence of a trial of formulary alternatives?"
    if "prior_trial_of_step_therapy_medication" in key_parts or "prior step-therapy medication trial" in key_parts:
        return "Did we find evidence of a prior step-therapy medication trial?"
    if "failed_conservative_therapy" in key_parts:
        return "Did we find evidence of failed conservative therapy?"
    if "prior_physical_therapy" in key_parts or "physical therapy" in key_parts:
        return "Did we find evidence of prior physical therapy?"
    if "supporting documentation" in key_parts or "documentation present" in key_parts:
        return "Did we find the required supporting documentation?"
    if "diagnosis" in key_parts:
        return "Did we find evidence of a qualifying diagnosis?"
    if fallback:
        return fallback
    return None


def specific_requirement_action(*, evidence_needed: str | None, question_text: str) -> str:
    key_parts = " ".join(filter(None, [evidence_needed or "", question_text])).lower()
    if "formulary alternative" in key_parts:
        return "Provide evidence of a trial of formulary alternatives."
    if "step-therapy medication trial" in key_parts:
        return "Provide evidence of a prior step-therapy medication trial."
    if "failed conservative therapy" in key_parts:
        return "Provide evidence that conservative therapy was tried and failed."
    if "physical therapy" in key_parts:
        return "Provide evidence of prior physical therapy."
    if "supporting documentation" in key_parts or "documentation" in key_parts:
        return "Provide the required supporting documentation."
    if "diagnosis" in key_parts:
        return "Provide evidence of the qualifying diagnosis."
    return "Provide evidence needed to satisfy this policy question."


def _humanize_document_kind(value: str) -> str:
    return value.replace("_", " ")
