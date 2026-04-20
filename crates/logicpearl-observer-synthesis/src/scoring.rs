// SPDX-License-Identifier: MIT
use crate::bootstrap::infer_bootstrap_case_labels;
use crate::{
    ObserverBootstrapStrategy, ObserverSignalScoreReport, ObserverSynthesisReport,
    ObserverTargetGoal,
};
use logicpearl_benchmark::SynthesisCase;
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_observer::{
    guardrails_signal_feature, guardrails_signal_phrases, observe_with_artifact, GuardrailsSignal,
    NativeObserverArtifact, ObserverProfile as NativeObserverProfile,
};
use serde_json::json;

pub(crate) fn selection_metric_name(goal: ObserverTargetGoal) -> &'static str {
    match goal {
        ObserverTargetGoal::ParityFirst => {
            "lexicographic(exact_match_rate,macro_balance,negative_pass_rate,positive_recall,train_negative_hits,artifact_size)"
        }
        ObserverTargetGoal::ProtectiveGate => {
            "lexicographic(positive_recall,negative_pass_rate,exact_match_rate,train_negative_hits,artifact_size)"
        }
        ObserverTargetGoal::CustomerSafe => {
            "lexicographic(negative_pass_rate,positive_recall,exact_match_rate,train_negative_hits,artifact_size)"
        }
        ObserverTargetGoal::Balanced => {
            "lexicographic(macro_balance,exact_match_rate,negative_pass_rate,positive_recall,train_negative_hits,artifact_size)"
        }
        ObserverTargetGoal::ReviewQueue => {
            "lexicographic(positive_recall,exact_match_rate,artifact_size,negative_pass_rate,train_negative_hits)"
        }
    }
}

fn macro_balance(score: &ObserverSignalScoreReport) -> f64 {
    (score.positive_recall + score.negative_pass_rate) / 2.0
}

pub(crate) fn primary_metric(goal: ObserverTargetGoal, score: &ObserverSignalScoreReport) -> f64 {
    match goal {
        ObserverTargetGoal::ParityFirst => score.exact_match_rate,
        ObserverTargetGoal::ProtectiveGate => score.positive_recall,
        ObserverTargetGoal::CustomerSafe => score.negative_pass_rate,
        ObserverTargetGoal::Balanced => macro_balance(score),
        ObserverTargetGoal::ReviewQueue => score.positive_recall,
    }
}

pub(crate) fn is_better_trial(
    goal: ObserverTargetGoal,
    candidate_cap: usize,
    candidate_train_report: &ObserverSynthesisReport,
    candidate_score: &ObserverSignalScoreReport,
    current_cap: usize,
    current_train_report: &ObserverSynthesisReport,
    current_score: &ObserverSignalScoreReport,
) -> bool {
    match goal {
        ObserverTargetGoal::ParityFirst => {
            candidate_score.exact_match_rate > current_score.exact_match_rate
                || (candidate_score.exact_match_rate == current_score.exact_match_rate
                    && macro_balance(candidate_score) > macro_balance(current_score))
                || (candidate_score.exact_match_rate == current_score.exact_match_rate
                    && macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.negative_pass_rate > current_score.negative_pass_rate)
                || (candidate_score.exact_match_rate == current_score.exact_match_rate
                    && macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall > current_score.positive_recall)
                || (candidate_score.exact_match_rate == current_score.exact_match_rate
                    && macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_train_report.matched_negatives_after
                        < current_train_report.matched_negatives_after)
                || (candidate_score.exact_match_rate == current_score.exact_match_rate
                    && macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_train_report.matched_negatives_after
                        == current_train_report.matched_negatives_after
                    && candidate_cap < current_cap)
        }
        ObserverTargetGoal::ProtectiveGate => {
            candidate_score.positive_recall > current_score.positive_recall
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.negative_pass_rate > current_score.negative_pass_rate)
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.exact_match_rate > current_score.exact_match_rate)
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_train_report.matched_negatives_after
                        < current_train_report.matched_negatives_after)
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_train_report.matched_negatives_after
                        == current_train_report.matched_negatives_after
                    && candidate_cap < current_cap)
        }
        ObserverTargetGoal::CustomerSafe => {
            candidate_score.negative_pass_rate > current_score.negative_pass_rate
                || (candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall > current_score.positive_recall)
                || (candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate > current_score.exact_match_rate)
                || (candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_train_report.matched_negatives_after
                        < current_train_report.matched_negatives_after)
                || (candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_train_report.matched_negatives_after
                        == current_train_report.matched_negatives_after
                    && candidate_cap < current_cap)
        }
        ObserverTargetGoal::Balanced => {
            macro_balance(candidate_score) > macro_balance(current_score)
                || (macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.exact_match_rate > current_score.exact_match_rate)
                || (macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_score.negative_pass_rate > current_score.negative_pass_rate)
                || (macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall > current_score.positive_recall)
                || (macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_train_report.matched_negatives_after
                        < current_train_report.matched_negatives_after)
                || (macro_balance(candidate_score) == macro_balance(current_score)
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_score.positive_recall == current_score.positive_recall
                    && candidate_train_report.matched_negatives_after
                        == current_train_report.matched_negatives_after
                    && candidate_cap < current_cap)
        }
        ObserverTargetGoal::ReviewQueue => {
            candidate_score.positive_recall > current_score.positive_recall
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate > current_score.exact_match_rate)
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_cap < current_cap)
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_cap == current_cap
                    && candidate_score.negative_pass_rate > current_score.negative_pass_rate)
                || (candidate_score.positive_recall == current_score.positive_recall
                    && candidate_score.exact_match_rate == current_score.exact_match_rate
                    && candidate_cap == current_cap
                    && candidate_score.negative_pass_rate == current_score.negative_pass_rate
                    && candidate_train_report.matched_negatives_after
                        < current_train_report.matched_negatives_after)
        }
    }
}

pub fn evaluate_guardrails_artifact_signal(
    artifact: &NativeObserverArtifact,
    signal: GuardrailsSignal,
    cases: &[SynthesisCase],
    bootstrap: ObserverBootstrapStrategy,
    positive_routes: &[String],
) -> Result<ObserverSignalScoreReport> {
    if artifact.profile != NativeObserverProfile::GuardrailsV1 {
        return Err(LogicPearlError::message(
            "observer evaluation currently supports guardrails_v1 artifacts only",
        ));
    }
    let config = artifact.guardrails.as_ref().ok_or_else(|| {
        LogicPearlError::message("guardrails_v1 artifact is missing its cue configuration")
    })?;
    let seed_phrases = guardrails_signal_phrases(config, signal).to_vec();
    let signal_feature = guardrails_signal_feature(signal);
    let (bootstrap_mode, labels) =
        infer_bootstrap_case_labels(cases, signal, bootstrap, positive_routes, &seed_phrases)?;

    let mut tp = 0_usize;
    let mut fn_count = 0_usize;
    let mut tn = 0_usize;
    let mut fp = 0_usize;

    for (case, label) in cases.iter().zip(labels.iter()) {
        let Some(is_positive) = label else {
            continue;
        };
        let features = observe_with_artifact(
            artifact,
            &json!({
                "prompt": case.prompt,
                "requested_tool": "none",
                "requested_action": "chat_response",
                "scope": "allowed",
                "document_instructions_present": false
            }),
        )?;
        let predicted = boolish(features.get(signal_feature));
        match (*is_positive, predicted) {
            (true, true) => tp += 1,
            (true, false) => fn_count += 1,
            (false, false) => tn += 1,
            (false, true) => fp += 1,
        }
    }

    let positive_case_count = tp + fn_count;
    let negative_case_count = tn + fp;
    let total = positive_case_count + negative_case_count;
    Ok(ObserverSignalScoreReport {
        bootstrap_mode,
        positive_case_count,
        negative_case_count,
        true_positive_count: tp,
        false_negative_count: fn_count,
        true_negative_count: tn,
        false_positive_count: fp,
        exact_match_rate: ratio(tp + tn, total),
        positive_recall: ratio(tp, positive_case_count),
        negative_pass_rate: ratio(tn, negative_case_count),
    })
}

pub(crate) fn boolish(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(boolean)) => *boolean,
        Some(serde_json::Value::Number(number)) => number.as_i64().unwrap_or_default() != 0,
        Some(serde_json::Value::String(text)) => {
            matches!(
                text.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y"
            )
        }
        _ => false,
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
