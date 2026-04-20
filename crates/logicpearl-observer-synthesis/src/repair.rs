// SPDX-License-Identifier: MIT
use crate::bootstrap::infer_bootstrap_examples;
use crate::selection::{count_phrase_hits, count_selected_hits, solve_phrase_subset};
use crate::{ObserverBootstrapStrategy, ObserverRepairReport};
use logicpearl_benchmark::SynthesisCase;
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_observer::{
    guardrails_signal_label, guardrails_signal_phrases, prompt_matches_phrase,
    set_guardrails_signal_phrases, GuardrailsSignal, NativeObserverArtifact,
    ObserverProfile as NativeObserverProfile,
};

pub fn repair_guardrails_artifact(
    artifact: &NativeObserverArtifact,
    signal: GuardrailsSignal,
    cases: &[SynthesisCase],
    bootstrap: ObserverBootstrapStrategy,
    positive_routes: &[String],
) -> Result<(NativeObserverArtifact, ObserverRepairReport)> {
    if artifact.profile != NativeObserverProfile::GuardrailsV1 {
        return Err(LogicPearlError::message(
            "observer repair currently supports guardrails_v1 artifacts only",
        ));
    }
    let config = artifact.guardrails.as_ref().ok_or_else(|| {
        LogicPearlError::message("guardrails_v1 artifact is missing its cue configuration")
    })?;
    let phrases_before = guardrails_signal_phrases(config, signal).to_vec();
    if phrases_before.is_empty() {
        return Err(LogicPearlError::message(format!(
            "observer artifact has no phrases for {}",
            guardrails_signal_label(signal)
        )));
    }

    let (bootstrap_mode, positive_prompts, negative_prompts) =
        infer_bootstrap_examples(cases, signal, bootstrap, positive_routes, &phrases_before)?;

    let mut positive_constraints: Vec<Vec<usize>> = Vec::new();
    let mut negative_constraints: Vec<Vec<usize>> = Vec::new();

    for prompt in &positive_prompts {
        let matched: Vec<usize> = phrases_before
            .iter()
            .enumerate()
            .filter_map(|(index, phrase)| prompt_matches_phrase(prompt, phrase).then_some(index))
            .collect();
        if !matched.is_empty() {
            positive_constraints.push(matched);
        }
    }
    for prompt in &negative_prompts {
        let matched: Vec<usize> = phrases_before
            .iter()
            .enumerate()
            .filter_map(|(index, phrase)| prompt_matches_phrase(prompt, phrase).then_some(index))
            .collect();
        if !matched.is_empty() {
            negative_constraints.push(matched);
        }
    }
    if positive_constraints.is_empty() {
        return Err(LogicPearlError::message(format!(
            "no positive benchmark cases currently match {} phrases",
            guardrails_signal_label(signal)
        )));
    }

    let selection = solve_phrase_subset(
        &phrases_before,
        &positive_constraints,
        &negative_constraints,
    )?;
    if !selection.status.is_success() {
        return Err(LogicPearlError::message(
            "solver could not find a satisfying phrase subset",
        ));
    }
    let phrases_after: Vec<String> = selection
        .selected
        .iter()
        .map(|index| phrases_before[*index].clone())
        .collect();
    if phrases_after.is_empty() {
        return Err(LogicPearlError::message(
            "solver removed every phrase for the selected signal",
        ));
    }
    let removed_phrases: Vec<String> = phrases_before
        .iter()
        .enumerate()
        .filter(|(index, _)| !selection.selected.contains(index))
        .map(|(_, phrase)| phrase.clone())
        .collect();

    let mut repaired = artifact.clone();
    let repaired_config = repaired.guardrails.as_mut().ok_or_else(|| {
        LogicPearlError::message("guardrails_v1 artifact is missing its cue configuration")
    })?;
    set_guardrails_signal_phrases(repaired_config, signal, phrases_after.clone());

    Ok((
        repaired,
        ObserverRepairReport {
            signal: guardrails_signal_label(signal).to_string(),
            bootstrap_mode,
            before_positive_hits: count_phrase_hits(&positive_constraints),
            after_positive_hits: count_selected_hits(&selection.selected, &positive_constraints),
            before_negative_hits: count_phrase_hits(&negative_constraints),
            after_negative_hits: count_selected_hits(&selection.selected, &negative_constraints),
            matched_positive_cases: positive_prompts.len(),
            matched_negative_cases: negative_prompts.len(),
            removed_phrases,
            phrases_before,
            phrases_after,
        },
    ))
}
