from logicpearl.domains.healthcare_policy.models import CodeCluster, EvidenceRequirement, EvidenceRequirementKind
from logicpearl.domains.healthcare_policy.presentation import (
    human_documentation_counterfactual,
    human_requirement_counterfactual,
    question_text_for_requirement,
)


def test_step_therapy_question_text_distinguishes_formulary_alternatives() -> None:
    prior_trial_requirement = EvidenceRequirement(
        requirement_id="req-1",
        label="Prior trial",
        question_text="placeholder",
        kind=EvidenceRequirementKind.MEDICATION_TRIAL,
        cluster_id="step_therapy__prior_trial_of_step_therapy_medication",
        evidence_needed="prior trial of step therapy medication",
        source_excerpt="excerpt",
        source_id="source-1",
        source_section="Policy",
    )
    prior_trial_cluster = CodeCluster(
        cluster_id="step_therapy__prior_trial_of_step_therapy_medication",
        label="prior trial of step therapy medication",
        kind="medication",
    )
    formulary_requirement = EvidenceRequirement(
        requirement_id="req-2",
        label="Formulary alternative trial",
        question_text="placeholder",
        kind=EvidenceRequirementKind.MEDICATION_TRIAL,
        cluster_id="step_therapy__trial_of_formulary_alternatives",
        evidence_needed="trial of formulary alternatives",
        source_excerpt="excerpt",
        source_id="source-1",
        source_section="Policy",
    )
    formulary_cluster = CodeCluster(
        cluster_id="step_therapy__trial_of_formulary_alternatives",
        label="trial of formulary alternatives",
        kind="medication",
    )

    assert question_text_for_requirement(prior_trial_requirement, cluster=prior_trial_cluster) == (
        "Did we find evidence of a prior step-therapy medication trial?"
    )
    assert question_text_for_requirement(formulary_requirement, cluster=formulary_cluster) == (
        "Did we find evidence of a trial of formulary alternatives?"
    )


def test_human_counterfactuals_are_readable() -> None:
    requirement_counterfactual = human_requirement_counterfactual(
        question_text="Did we find evidence of a trial of formulary alternatives?",
        requirement_id="req-2",
    )
    documentation_counterfactual = human_documentation_counterfactual(
        missing_document_kinds=["office_note", "pharmacy_history"]
    )

    assert requirement_counterfactual["summary"] == "Provide evidence of a trial of formulary alternatives."
    assert "requirement__req-2__satisfied" in requirement_counterfactual["machine_action"]
    assert documentation_counterfactual["summary"] == (
        "Provide at least one of the missing document types: office note, pharmacy history."
    )
