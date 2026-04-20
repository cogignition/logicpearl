// SPDX-License-Identifier: MIT
use crate::bootstrap::{auto_bootstrap_strategies, infer_bootstrap_examples};
use crate::candidate_generation::{build_candidate_pool, truncate_constraints, CandidatePool};
use crate::scoring::{
    evaluate_guardrails_artifact_signal, is_better_trial, primary_metric, selection_metric_name,
};
use crate::selection::{count_selected_hits, select_phrase_subset, PhraseSelectionMode};
use crate::signal_profiles::default_guardrail_signal_profile;
use crate::{
    ObserverAutoSelectionReport, ObserverAutoSynthesisOptions, ObserverBootstrapMode,
    ObserverBootstrapStrategy, ObserverSignalScoreReport, ObserverSynthesisReport,
    ObserverSynthesisTrialReport,
};
use logicpearl_benchmark::SynthesisCase;
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_observer::{
    guardrails_signal_label, guardrails_signal_phrases, set_guardrails_signal_phrases,
    GuardrailsSignal, NativeObserverArtifact, ObserverProfile as NativeObserverProfile,
};
use std::time::Instant;

fn log_synthesis_progress(message: impl AsRef<str>) {
    eprintln!("[logicpearl observer synthesize] {}", message.as_ref());
}

fn synthesize_from_candidate_pool(
    artifact: &NativeObserverArtifact,
    signal: GuardrailsSignal,
    bootstrap_mode: ObserverBootstrapMode,
    positive_prompts: &[String],
    negative_prompts: &[String],
    pool: &CandidatePool,
    candidate_cap: usize,
) -> Result<(NativeObserverArtifact, ObserverSynthesisReport)> {
    let candidate_count = pool.candidates.len().min(candidate_cap);
    if candidate_count == 0 {
        return Err(LogicPearlError::message(format!(
            "could not generate candidate phrases for {}",
            guardrails_signal_label(signal)
        )));
    }
    let candidates = &pool.candidates[..candidate_count];
    let positive_constraints = truncate_constraints(&pool.positive_constraints, candidate_count);
    let negative_constraints = truncate_constraints(&pool.negative_constraints, candidate_count);
    let selection_started = Instant::now();
    let selection = select_phrase_subset(
        candidates,
        &positive_constraints,
        &negative_constraints,
        PhraseSelectionMode::PreferCoverage,
    )?;
    let selection_duration_ms = selection_started.elapsed().as_millis() as u64;
    if !selection.status.is_success() || selection.selected.is_empty() {
        return Err(LogicPearlError::message(
            "solver could not synthesize a useful phrase subset",
        ));
    }

    let phrases_after: Vec<String> = selection
        .selected
        .iter()
        .map(|index| candidates[*index].clone())
        .collect();
    let mut synthesized = artifact.clone();
    let synthesized_config = synthesized.guardrails.as_mut().ok_or_else(|| {
        LogicPearlError::message("guardrails_v1 artifact is missing its cue configuration")
    })?;
    let phrases_before = guardrails_signal_phrases(synthesized_config, signal).to_vec();
    set_guardrails_signal_phrases(synthesized_config, signal, phrases_after.clone());

    Ok((
        synthesized,
        ObserverSynthesisReport {
            signal: guardrails_signal_label(signal).to_string(),
            bootstrap_mode,
            positive_case_count: positive_prompts.len(),
            negative_case_count: negative_prompts.len(),
            candidate_count,
            phrases_before,
            matched_positives_after: count_selected_hits(
                &selection.selected,
                &positive_constraints,
            ),
            matched_negatives_after: count_selected_hits(
                &selection.selected,
                &negative_constraints,
            ),
            phrases_after,
            selected_max_candidates: Some(candidate_cap),
            selection_backend: Some(selection.backend_used.as_str().to_string()),
            selection_status: Some(selection.status.as_str().to_string()),
            selection_duration_ms: Some(selection_duration_ms),
            auto_selection: None,
        },
    ))
}

pub fn synthesize_guardrails_artifact(
    artifact: &NativeObserverArtifact,
    signal: GuardrailsSignal,
    cases: &[SynthesisCase],
    bootstrap: ObserverBootstrapStrategy,
    positive_routes: &[String],
    max_candidates: usize,
) -> Result<(NativeObserverArtifact, ObserverSynthesisReport)> {
    let started = Instant::now();
    if artifact.profile != NativeObserverProfile::GuardrailsV1 {
        return Err(LogicPearlError::message(
            "observer synthesize currently supports guardrails_v1 artifacts only",
        ));
    }
    let config = artifact.guardrails.as_ref().ok_or_else(|| {
        LogicPearlError::message("guardrails_v1 artifact is missing its cue configuration")
    })?;
    let phrases_before = guardrails_signal_phrases(config, signal).to_vec();
    let (bootstrap_mode, positive_prompts, negative_prompts) =
        infer_bootstrap_examples(cases, signal, bootstrap, positive_routes, &phrases_before)?;
    log_synthesis_progress(format!(
        "signal={} mode={bootstrap_mode:?} positives={} negatives={} max_candidates={max_candidates}",
        guardrails_signal_label(signal),
        positive_prompts.len(),
        negative_prompts.len(),
    ));
    let profile = default_guardrail_signal_profile();
    let pool = build_candidate_pool(
        &profile,
        signal,
        &positive_prompts,
        &negative_prompts,
        max_candidates,
    );
    let (synthesized, mut report) = synthesize_from_candidate_pool(
        artifact,
        signal,
        bootstrap_mode,
        &positive_prompts,
        &negative_prompts,
        &pool,
        max_candidates,
    )?;
    report.phrases_before = phrases_before;
    log_synthesis_progress(format!(
        "signal={} complete in {:.1}s selected={} matched_pos={} matched_neg={}",
        guardrails_signal_label(signal),
        started.elapsed().as_secs_f32(),
        report.phrases_after.len(),
        report.matched_positives_after,
        report.matched_negatives_after,
    ));
    Ok((synthesized, report))
}

pub fn synthesize_guardrails_artifact_auto(
    artifact: &NativeObserverArtifact,
    signal: GuardrailsSignal,
    options: ObserverAutoSynthesisOptions<'_>,
) -> Result<(NativeObserverArtifact, ObserverSynthesisReport)> {
    let started = Instant::now();
    if options.candidate_frontier.is_empty() {
        return Err(LogicPearlError::message(
            "auto candidate search requires at least one candidate cap",
        ));
    }

    let mut trials: Vec<(
        usize,
        NativeObserverArtifact,
        ObserverSynthesisReport,
        ObserverSignalScoreReport,
    )> = Vec::new();
    let dev_eval_bootstrap = if matches!(options.bootstrap, ObserverBootstrapStrategy::Auto) {
        ObserverBootstrapStrategy::Route
    } else {
        options.bootstrap
    };
    let seed_phrases = {
        let config = artifact.guardrails.as_ref().ok_or_else(|| {
            LogicPearlError::message("guardrails_v1 artifact is missing its cue configuration")
        })?;
        guardrails_signal_phrases(config, signal).to_vec()
    };
    let profile = default_guardrail_signal_profile();

    for &bootstrap_candidate in auto_bootstrap_strategies(options.bootstrap) {
        let Ok((bootstrap_mode, positive_prompts, negative_prompts)) = infer_bootstrap_examples(
            options.train_cases,
            signal,
            bootstrap_candidate,
            options.positive_routes,
            &seed_phrases,
        ) else {
            continue;
        };
        log_synthesis_progress(format!(
            "signal={} mode={bootstrap_mode:?} train_pos={} train_neg={} frontier={:?}",
            guardrails_signal_label(signal),
            positive_prompts.len(),
            negative_prompts.len(),
            options.candidate_frontier,
        ));
        let pool = build_candidate_pool(
            &profile,
            signal,
            &positive_prompts,
            &negative_prompts,
            *options.candidate_frontier.iter().max().unwrap_or(&0),
        );
        if pool.candidates.is_empty() {
            log_synthesis_progress(format!(
                "signal={} mode={bootstrap_mode:?} produced no candidates",
                guardrails_signal_label(signal),
            ));
            continue;
        }
        log_synthesis_progress(format!(
            "signal={} mode={bootstrap_mode:?} mined {} candidates",
            guardrails_signal_label(signal),
            pool.candidates.len(),
        ));
        for &cap in options.candidate_frontier {
            let trial_started = Instant::now();
            log_synthesis_progress(format!(
                "signal={} mode={bootstrap_mode:?} trying cap={cap}",
                guardrails_signal_label(signal),
            ));
            let Ok((candidate_artifact, train_report)) = synthesize_from_candidate_pool(
                artifact,
                signal,
                bootstrap_mode,
                &positive_prompts,
                &negative_prompts,
                &pool,
                cap,
            ) else {
                continue;
            };
            let Ok(dev_score) = evaluate_guardrails_artifact_signal(
                &candidate_artifact,
                signal,
                options.dev_cases,
                dev_eval_bootstrap,
                options.positive_routes,
            ) else {
                continue;
            };
            log_synthesis_progress(format!(
                "signal={} mode={bootstrap_mode:?} cap={cap} dev_exact={:.4} dev_recall={:.4} dev_pass={:.4} elapsed={:.1}s",
                guardrails_signal_label(signal),
                dev_score.exact_match_rate,
                dev_score.positive_recall,
                dev_score.negative_pass_rate,
                trial_started.elapsed().as_secs_f32(),
            ));
            trials.push((cap, candidate_artifact, train_report, dev_score));
        }
    }

    if trials.is_empty() {
        return Err(LogicPearlError::message(
            "auto candidate search could not synthesize any observer variants",
        ));
    }

    let best_primary_metric = trials
        .iter()
        .map(|(_, _, _, score)| primary_metric(options.target_goal, score))
        .fold(f64::NEG_INFINITY, f64::max);

    let mut chosen_index = None;
    for (index, (cap, _, train_report, score)) in trials.iter().enumerate() {
        if primary_metric(options.target_goal, score) + options.tolerance < best_primary_metric {
            continue;
        }
        match chosen_index {
            None => chosen_index = Some(index),
            Some(current) => {
                let (current_cap, _, current_train_report, current_score) = &trials[current];
                let better = is_better_trial(
                    options.target_goal,
                    *cap,
                    train_report,
                    score,
                    *current_cap,
                    current_train_report,
                    current_score,
                );
                if better {
                    chosen_index = Some(index);
                }
            }
        }
    }

    let chosen_index = chosen_index.ok_or_else(|| {
        LogicPearlError::message("auto candidate search could not select a synthesized observer")
    })?;
    let (_, chosen_artifact, mut chosen_report, _) = trials.remove(chosen_index);
    log_synthesis_progress(format!(
        "signal={} selected cap={} after {:.1}s",
        guardrails_signal_label(signal),
        chosen_report
            .selected_max_candidates
            .unwrap_or(options.candidate_frontier[0]),
        started.elapsed().as_secs_f32(),
    ));
    chosen_report.auto_selection = Some(ObserverAutoSelectionReport {
        target_goal: options.target_goal,
        selection_metric: selection_metric_name(options.target_goal).to_string(),
        tolerance: options.tolerance,
        tried: trials
            .into_iter()
            .chain(std::iter::once((
                chosen_report
                    .selected_max_candidates
                    .unwrap_or(options.candidate_frontier[0]),
                chosen_artifact.clone(),
                chosen_report.clone(),
                evaluate_guardrails_artifact_signal(
                    &chosen_artifact,
                    signal,
                    options.dev_cases,
                    dev_eval_bootstrap,
                    options.positive_routes,
                )?,
            )))
            .map(
                |(cap, _, train_report, dev_score)| ObserverSynthesisTrialReport {
                    max_candidates: cap,
                    train_report,
                    dev_score,
                },
            )
            .collect(),
    });
    Ok((chosen_artifact, chosen_report))
}
