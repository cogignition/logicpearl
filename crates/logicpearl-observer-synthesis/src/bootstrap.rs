// SPDX-License-Identifier: MIT
use crate::scoring::boolish;
use crate::{ObserverBootstrapMode, ObserverBootstrapStrategy};
use logicpearl_benchmark::SynthesisCase;
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_observer::{
    guardrails_signal_feature, guardrails_signal_label, prompt_matches_phrase, GuardrailsSignal,
};

const AUTO_BOOTSTRAP_STRATEGIES: [ObserverBootstrapStrategy; 3] = [
    ObserverBootstrapStrategy::ObservedFeature,
    ObserverBootstrapStrategy::Route,
    ObserverBootstrapStrategy::Seed,
];
const OBSERVED_FEATURE_BOOTSTRAP_STRATEGY: [ObserverBootstrapStrategy; 1] =
    [ObserverBootstrapStrategy::ObservedFeature];
const ROUTE_BOOTSTRAP_STRATEGY: [ObserverBootstrapStrategy; 1] = [ObserverBootstrapStrategy::Route];
const SEED_BOOTSTRAP_STRATEGY: [ObserverBootstrapStrategy; 1] = [ObserverBootstrapStrategy::Seed];

pub(crate) fn auto_bootstrap_strategies(
    bootstrap: ObserverBootstrapStrategy,
) -> &'static [ObserverBootstrapStrategy] {
    match bootstrap {
        ObserverBootstrapStrategy::Auto => &AUTO_BOOTSTRAP_STRATEGIES,
        ObserverBootstrapStrategy::ObservedFeature => &OBSERVED_FEATURE_BOOTSTRAP_STRATEGY,
        ObserverBootstrapStrategy::Route => &ROUTE_BOOTSTRAP_STRATEGY,
        ObserverBootstrapStrategy::Seed => &SEED_BOOTSTRAP_STRATEGY,
    }
}

pub fn default_positive_routes_for_signal(signal: GuardrailsSignal) -> &'static [&'static str] {
    match signal {
        GuardrailsSignal::InstructionOverride => {
            &["deny_untrusted_instruction", "deny_instruction_boundary"]
        }
        GuardrailsSignal::SystemPrompt => &["deny_untrusted_instruction", "deny_system_prompt"],
        GuardrailsSignal::SecretExfiltration => {
            &["deny_exfiltration_risk", "deny_secret_exfiltration"]
        }
        GuardrailsSignal::ToolMisuse => &["deny_tool_use", "deny_tool_misuse"],
        GuardrailsSignal::DataAccessOutsideScope => {
            &["deny_exfiltration_risk", "needs_scope_reduction"]
        }
        GuardrailsSignal::IndirectDocumentAuthority => &[
            "deny_untrusted_instruction",
            "deny_indirect_document_authority",
        ],
        GuardrailsSignal::BenignQuestion => &["allow"],
    }
}

pub fn infer_bootstrap_case_labels(
    cases: &[SynthesisCase],
    signal: GuardrailsSignal,
    bootstrap: ObserverBootstrapStrategy,
    positive_routes: &[String],
    seed_phrases: &[String],
) -> Result<(ObserverBootstrapMode, Vec<Option<bool>>)> {
    let signal_feature = guardrails_signal_feature(signal);

    if matches!(
        bootstrap,
        ObserverBootstrapStrategy::Auto | ObserverBootstrapStrategy::ObservedFeature
    ) {
        let labels: Vec<Option<bool>> = cases
            .iter()
            .map(|case| {
                case.features
                    .as_ref()
                    .map(|features| boolish(features.get(signal_feature)))
            })
            .collect();
        if labels.iter().any(|label| matches!(label, Some(true))) {
            return Ok((ObserverBootstrapMode::ObservedFeature, labels));
        }
        if matches!(bootstrap, ObserverBootstrapStrategy::ObservedFeature) {
            return Err(LogicPearlError::message(format!(
                "no observed feature rows expose {signal_feature}"
            )));
        }
    }

    if matches!(
        bootstrap,
        ObserverBootstrapStrategy::Auto | ObserverBootstrapStrategy::Route
    ) {
        let route_hints: Vec<String> = if positive_routes.is_empty() {
            default_positive_routes_for_signal(signal)
                .iter()
                .map(|route| route.to_string())
                .collect()
        } else {
            positive_routes.to_vec()
        };
        let labels: Vec<Option<bool>> = cases
            .iter()
            .map(|case| {
                if route_hints
                    .iter()
                    .any(|route| route == &case.expected_route)
                {
                    Some(true)
                } else if case.expected_route == "allow" {
                    Some(false)
                } else {
                    None
                }
            })
            .collect();
        if labels.iter().any(|label| matches!(label, Some(true))) {
            return Ok((ObserverBootstrapMode::Route, labels));
        }
        if positive_routes.is_empty() && !matches!(signal, GuardrailsSignal::BenignQuestion) {
            let coarse_labels: Vec<Option<bool>> = cases
                .iter()
                .map(|case| {
                    if case.expected_route == "allow" {
                        Some(false)
                    } else {
                        Some(true)
                    }
                })
                .collect();
            if coarse_labels
                .iter()
                .any(|label| matches!(label, Some(true)))
            {
                return Ok((ObserverBootstrapMode::Route, coarse_labels));
            }
        }
        if matches!(bootstrap, ObserverBootstrapStrategy::Route) {
            return Err(LogicPearlError::message(
                "route-based observer bootstrapping found no positive examples",
            ));
        }
    }

    let labels: Vec<Option<bool>> = cases
        .iter()
        .map(|case| {
            if case.expected_route == "allow" {
                Some(false)
            } else if seed_phrases
                .iter()
                .any(|phrase| prompt_matches_phrase(&case.prompt, phrase))
            {
                Some(true)
            } else {
                None
            }
        })
        .collect();
    if !labels.iter().any(|label| matches!(label, Some(true))) {
        return Err(LogicPearlError::message(format!(
            "could not find positive examples for {} with the current bootstrap strategy",
            guardrails_signal_label(signal)
        )));
    }
    Ok((ObserverBootstrapMode::Seed, labels))
}

pub fn infer_bootstrap_examples(
    cases: &[SynthesisCase],
    signal: GuardrailsSignal,
    bootstrap: ObserverBootstrapStrategy,
    positive_routes: &[String],
    seed_phrases: &[String],
) -> Result<(ObserverBootstrapMode, Vec<String>, Vec<String>)> {
    let (mode, labels) =
        infer_bootstrap_case_labels(cases, signal, bootstrap, positive_routes, seed_phrases)?;
    let positives = cases
        .iter()
        .zip(labels.iter())
        .filter_map(|(case, label)| (*label == Some(true)).then_some(case.prompt.clone()))
        .collect();
    let negatives = cases
        .iter()
        .zip(labels.iter())
        .filter_map(|(case, label)| (*label == Some(false)).then_some(case.prompt.clone()))
        .collect();
    Ok((mode, positives, negatives))
}
