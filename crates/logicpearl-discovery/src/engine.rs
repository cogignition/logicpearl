// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    CombineStrategy, EvaluationConfig, Expression, FeatureDefinition, FeatureGovernance, GateType,
    InputSchema, LogicPearlGateIr, Provenance, RuleDefinition, RuleEvidence, RuleSupportEvidence,
    RuleTraceEvidence, RuleVerificationStatus, VerificationConfig,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::canonicalize::{canonicalize_rules, expression_matches, prune_redundant_rules};
use super::features::{infer_feature_type, sorted_feature_names};
use super::rule_text::RuleTextContext;
mod candidates;
mod residual_recovery;
mod rule_hygiene;
mod rule_limit;
mod scoring;
mod selection;
mod validation;

use super::{
    decision_trace_row_hash, rule_trace_evidence, CandidateRule, DecisionTraceRow,
    DiscoveryDecisionMode, ExactSelectionReport, PinnedRuleSet, ResidualPassOptions,
    ResidualRecoveryReport, ResidualRecoveryState, UniqueCoverageRefinementOptions,
};
#[cfg(test)]
pub(super) use candidates::rule_from_candidate;
use candidates::{
    best_immediate_candidate_rule, candidate_rules, compare_candidate_priority, matches_candidate,
    rule_from_candidate_with_context,
};
#[cfg(test)]
use candidates::{
    candidate_allowed_for_mode, candidate_as_comparison, candidate_complexity_penalty,
    conjunction_candidate_rules,
};
pub(super) use residual_recovery::{discover_residual_rules, refine_rules_unique_coverage};
pub(super) use rule_hygiene::{dedupe_rules_by_signature, merge_discovered_and_pinned_rules};
use rule_limit::limit_rules_by_training_coverage;
#[cfg(test)]
use scoring::CandidateSetScore;
use scoring::{compare_candidate_set_score, score_candidate_set, score_candidate_subset};
pub(crate) use selection::DISCOVERY_SELECTION_BACKEND_ENV;
use selection::{current_solver_backend, exact_selection_shortlist, select_candidate_rules_exact};
use validation::discovery_validation_split;

const LOOKAHEAD_FRONTIER_LIMIT: usize = 12;
const NUMERIC_EQ_MAX_DISTINCT_VALUES: usize = 20;
const NUMERIC_EQ_MIN_SUPPORT_ABSOLUTE: usize = 3;
const NUMERIC_EQ_MIN_SUPPORT_BASIS_POINTS: usize = 10; // 0.1%
const EXACT_SELECTION_FRONTIER_LIMIT: usize = 48;
const CONJUNCTION_ATOM_FRONTIER_LIMIT: usize = 128;
const RARE_RULE_RECOVERY_FRONTIER_LIMIT: usize = 24;
const RARE_RULE_RECOVERY_MAX_PASSES: usize = 3;

#[derive(Debug, Clone, PartialEq)]
struct CandidatePlanScore {
    training_total_errors: usize,
    training_false_positives: usize,
    validation_total_errors: usize,
    validation_false_positives: usize,
    uncovered_denied: usize,
    rule_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct CandidateSelectionContext<'a> {
    rows: &'a [DecisionTraceRow],
    denied_indices: &'a [usize],
    allowed_indices: &'a [usize],
    validation_indices: Option<&'a [usize]>,
    feature_governance: &'a BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&'a ResidualPassOptions>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_gate(
    rows: &[DecisionTraceRow],
    source_rows: &[DecisionTraceRow],
    derived_features: &[FeatureDefinition],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    feature_semantics: &BTreeMap<String, logicpearl_ir::FeatureSemantics>,
    gate_id: &str,
    decision_mode: DiscoveryDecisionMode,
    max_rules: Option<usize>,
    residual_options: Option<&ResidualPassOptions>,
    refinement_options: Option<&UniqueCoverageRefinementOptions>,
    pinned_rules: Option<&PinnedRuleSet>,
) -> Result<(
    LogicPearlGateIr,
    ExactSelectionReport,
    usize,
    ResidualRecoveryReport,
    usize,
    usize,
)> {
    let (mut rules, exact_selection) = discover_rules(
        rows,
        feature_governance,
        feature_semantics,
        decision_mode,
        residual_options,
    )?;
    let mut residual_rules_discovered = 0usize;
    let primary_discovery_used_solver_recovery =
        residual_options.is_some() && rules.iter().any(rule_uses_compound_expression);
    let solver_backend = current_solver_backend()?;
    let mut residual_recovery = residual_options
        .map(|_| ResidualRecoveryReport {
            state: if primary_discovery_used_solver_recovery {
                ResidualRecoveryState::Applied
            } else {
                ResidualRecoveryState::NoMissedSlices
            },
            detail: primary_discovery_used_solver_recovery
                .then_some("applied during primary discovery".to_string()),
            backend_used: solver_backend.clone(),
        })
        .unwrap_or_default();
    if let Some(options) = residual_options {
        let first_pass_gate = gate_from_rules(
            rows,
            source_rows,
            derived_features,
            feature_governance,
            feature_semantics,
            gate_id,
            rules.clone(),
        )?;
        match discover_residual_rules(rows, &first_pass_gate, feature_semantics, options) {
            Ok(residual_rules) => {
                residual_rules_discovered = residual_rules.len();
                residual_recovery.state =
                    if residual_rules.is_empty() && !primary_discovery_used_solver_recovery {
                        ResidualRecoveryState::NoMissedSlices
                    } else {
                        ResidualRecoveryState::Applied
                    };
                residual_recovery.detail = if residual_rules.is_empty() {
                    primary_discovery_used_solver_recovery
                        .then_some("applied during primary discovery".to_string())
                } else {
                    Some(format!(
                        "applied {} residual rule{}",
                        residual_rules_discovered,
                        if residual_rules_discovered == 1 {
                            ""
                        } else {
                            "s"
                        }
                    ))
                };
                rules.extend(residual_rules);
            }
            Err(err) => {
                let message = err.to_string();
                if message.contains("failed to launch ") {
                    residual_recovery = ResidualRecoveryReport {
                        state: ResidualRecoveryState::SolverUnavailable,
                        detail: Some(message),
                        backend_used: solver_backend.clone(),
                    };
                } else if message.contains("boolean conjunction synthesis") {
                    residual_recovery = ResidualRecoveryReport {
                        state: ResidualRecoveryState::SolverError,
                        detail: Some(message),
                        backend_used: solver_backend.clone(),
                    };
                } else {
                    return Err(err);
                }
            }
        }
    }
    let mut refined_rules_applied = 0usize;
    if let Some(options) = refinement_options {
        let (refined_rules, applied) = refine_rules_unique_coverage(rows, &rules, options)?;
        rules = refined_rules;
        refined_rules_applied = applied;
    }
    let mut pinned_rules_applied = 0usize;
    if let Some(pinned_rules) = pinned_rules {
        pinned_rules_applied = pinned_rules.rules.len();
        rules = merge_discovered_and_pinned_rules(rules, pinned_rules);
    } else {
        rules = dedupe_rules_by_signature(rules);
    }
    rules = canonicalize_rules(rules);
    rules = dedupe_rules_by_signature(rules);
    rules = prune_redundant_rules(rows, rules);
    if let Some(max_rules) = max_rules {
        rules = limit_rules_by_training_coverage(rows, rules, max_rules);
    }
    if rules.is_empty() {
        return Err(LogicPearlError::message(
            "no deny rules could be discovered from decision traces",
        ));
    }

    Ok((
        gate_from_rules(
            rows,
            source_rows,
            derived_features,
            feature_governance,
            feature_semantics,
            gate_id,
            rules,
        )?,
        exact_selection,
        residual_rules_discovered,
        residual_recovery,
        refined_rules_applied,
        pinned_rules_applied,
    ))
}

fn rule_uses_compound_expression(rule: &RuleDefinition) -> bool {
    !matches!(rule.deny_when, Expression::Comparison(_))
}

pub(super) fn gate_from_rules(
    rows: &[DecisionTraceRow],
    source_rows: &[DecisionTraceRow],
    derived_features: &[FeatureDefinition],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    feature_semantics: &BTreeMap<String, logicpearl_ir::FeatureSemantics>,
    gate_id: &str,
    rules: Vec<RuleDefinition>,
) -> Result<LogicPearlGateIr> {
    let rules = attach_rule_evidence(rows, source_rows, rules);
    let feature_sample = source_rows[0].features.clone();
    let mut features = sorted_feature_names(source_rows)
        .into_iter()
        .map(|feature| FeatureDefinition {
            id: feature.clone(),
            feature_type: infer_feature_type(feature_sample.get(&feature).unwrap()),
            description: None,
            values: None,
            min: None,
            max: None,
            editable: None,
            semantics: feature_semantics.get(&feature).cloned(),
            governance: feature_governance.get(&feature).cloned(),
            derived: None,
        })
        .collect::<Vec<_>>();
    features.extend(derived_features.iter().cloned().map(|mut feature| {
        if feature.semantics.is_none() {
            feature.semantics = feature_semantics.get(&feature.id).cloned();
        }
        feature
    }));
    let verification_summary = rule_verification_summary(&rules);
    Ok(LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: gate_id.to_string(),
        gate_type: GateType::BitmaskGate,
        input_schema: InputSchema { features },
        rules,
        evaluation: EvaluationConfig {
            combine: CombineStrategy::BitwiseOr,
            allow_when_bitmask: 0,
        },
        verification: Some(VerificationConfig {
            domain_constraints: None,
            correctness_scope: Some(format!(
                "training parity against {} decision traces",
                rows.len()
            )),
            verification_summary: Some(verification_summary),
        }),
        provenance: Some(Provenance {
            generator: Some("logicpearl.build".to_string()),
            generator_version: Some("0.1.0".to_string()),
            source_commit: None,
            created_at: None,
        }),
    })
}

fn attach_rule_evidence(
    rows: &[DecisionTraceRow],
    source_rows: &[DecisionTraceRow],
    rules: Vec<RuleDefinition>,
) -> Vec<RuleDefinition> {
    rules
        .into_iter()
        .map(|mut rule| {
            rule.evidence = Some(rule_evidence(rows, source_rows, &rule.deny_when));
            rule
        })
        .collect()
}

fn rule_evidence(
    rows: &[DecisionTraceRow],
    source_rows: &[DecisionTraceRow],
    expression: &Expression,
) -> RuleEvidence {
    const MAX_EXAMPLE_HASHES: usize = 8;

    let mut denied_trace_count = 0usize;
    let mut allowed_trace_count = 0usize;
    let mut example_traces = BTreeSet::<RuleTraceEvidence>::new();

    for (index, row) in rows.iter().enumerate() {
        if !expression_matches(expression, &row.features) {
            continue;
        }
        if row.allowed {
            allowed_trace_count += 1;
            continue;
        }
        denied_trace_count += 1;
        let source_row = source_rows.get(index).unwrap_or(row);
        let trace_evidence = source_row
            .trace_provenance
            .as_ref()
            .map(rule_trace_evidence)
            .unwrap_or_else(|| RuleTraceEvidence {
                trace_row_hash: decision_trace_row_hash(&source_row.features, source_row.allowed),
                source_id: None,
                source_anchor: None,
                citation: None,
                quote_hash: None,
            });
        example_traces.insert(trace_evidence);
    }

    RuleEvidence {
        schema_version: "logicpearl.rule_evidence.v1".to_string(),
        support: RuleSupportEvidence {
            denied_trace_count,
            allowed_trace_count,
            example_traces: example_traces
                .into_iter()
                .take(MAX_EXAMPLE_HASHES)
                .collect(),
        },
    }
}

fn rule_verification_summary(rules: &[RuleDefinition]) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for rule in rules {
        let key = match rule
            .verification_status
            .as_ref()
            .unwrap_or(&RuleVerificationStatus::PipelineUnverified)
        {
            RuleVerificationStatus::SolverVerified => "solver_verified",
            RuleVerificationStatus::PipelineUnverified => "pipeline_unverified",
            RuleVerificationStatus::HeuristicUnverified => "heuristic_unverified",
            RuleVerificationStatus::RefinedUnverified => "refined_unverified",
        };
        *counts.entry(key.to_string()).or_insert(0) += 1;
    }
    counts
}

pub(super) fn load_pinned_rule_set(path: &std::path::Path) -> Result<PinnedRuleSet> {
    let payload = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&payload)?)
}

pub(super) fn discover_rules(
    rows: &[DecisionTraceRow],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    feature_semantics: &BTreeMap<String, logicpearl_ir::FeatureSemantics>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
) -> Result<(Vec<RuleDefinition>, ExactSelectionReport)> {
    let denied_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (!row.allowed).then_some(index))
        .collect();
    let allowed_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| row.allowed.then_some(index))
        .collect();

    let validation_split = discovery_validation_split(rows, &denied_indices, &allowed_indices);
    let (train_denied_indices, train_allowed_indices, validation_indices) =
        match validation_split.as_ref() {
            Some(split) => (
                split.train_denied_indices.clone(),
                split.train_allowed_indices.clone(),
                Some(split.validation_indices.as_slice()),
            ),
            None => (denied_indices.clone(), allowed_indices.clone(), None),
        };

    let all_candidates = candidate_rules(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        feature_governance,
        decision_mode,
        residual_options,
    );
    if all_candidates.is_empty() {
        return Err(LogicPearlError::message("no recoverable deny rule found"));
    }

    let greedy_plan = discover_rules_greedy(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        validation_indices,
        feature_governance,
        decision_mode,
        residual_options,
    )?;
    let shortlist = exact_selection_shortlist(
        &all_candidates,
        &greedy_plan,
        EXACT_SELECTION_FRONTIER_LIMIT,
    );
    let (exact_plan, mut exact_selection) = select_candidate_rules_exact(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        &shortlist,
    )?;
    let selected_candidates = match exact_plan {
        Some(exact_plan) if !exact_plan.is_empty() => {
            let greedy_score = score_candidate_set(rows, &greedy_plan, validation_indices);
            let exact_score = score_candidate_set(rows, &exact_plan, validation_indices);
            if compare_candidate_set_score(&exact_score, &greedy_score) == Ordering::Less {
                exact_selection.adopted = true;
                exact_plan
            } else {
                exact_selection.detail =
                    Some("kept greedy plan because exact selection was not better".to_string());
                greedy_plan
            }
        }
        _ => greedy_plan,
    };
    let selection_context = CandidateSelectionContext {
        rows,
        denied_indices: &train_denied_indices,
        allowed_indices: &train_allowed_indices,
        validation_indices,
        feature_governance,
        decision_mode,
        residual_options,
    };
    let selected_candidates = recover_rare_rules(&selection_context, selected_candidates)?;

    Ok((
        selected_candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                rule_from_candidate_with_context(
                    index as u32,
                    candidate,
                    &RuleTextContext::with_feature_semantics(feature_semantics),
                )
            })
            .collect(),
        exact_selection,
    ))
}

fn recover_rare_rules(
    selection_context: &CandidateSelectionContext<'_>,
    selected_candidates: Vec<CandidateRule>,
) -> Result<Vec<CandidateRule>> {
    let mut recovered = selected_candidates;
    for _ in 0..RARE_RULE_RECOVERY_MAX_PASSES {
        let uncovered_denied = selection_context
            .denied_indices
            .iter()
            .copied()
            .filter(|index| {
                !recovered.iter().any(|candidate| {
                    matches_candidate(&selection_context.rows[*index].features, candidate)
                })
            })
            .collect::<Vec<_>>();
        if uncovered_denied.is_empty() {
            break;
        }

        let existing_signatures = recovered
            .iter()
            .map(|c| c.signature().to_string())
            .collect::<BTreeSet<_>>();
        let rescue_shortlist = candidate_rules(
            selection_context.rows,
            &uncovered_denied,
            selection_context.allowed_indices,
            selection_context.feature_governance,
            selection_context.decision_mode,
            selection_context.residual_options,
        )
        .into_iter()
        .filter(|candidate| !existing_signatures.contains(candidate.signature()))
        .take(RARE_RULE_RECOVERY_FRONTIER_LIMIT)
        .collect::<Vec<_>>();
        if rescue_shortlist.is_empty() {
            break;
        }

        let (rescue_plan, _) = select_candidate_rules_exact(
            selection_context.rows,
            &uncovered_denied,
            selection_context.allowed_indices,
            &rescue_shortlist,
        )?;
        let Some(rescue_plan) = rescue_plan else {
            break;
        };
        if rescue_plan.is_empty() {
            break;
        }

        let mut candidate_combined = recovered.clone();
        candidate_combined.extend(rescue_plan);
        candidate_combined = dedupe_candidate_rules_by_signature(candidate_combined);

        let current_score = score_candidate_set(
            selection_context.rows,
            &recovered,
            selection_context.validation_indices,
        );
        let combined_score = score_candidate_set(
            selection_context.rows,
            &candidate_combined,
            selection_context.validation_indices,
        );
        let improved = compare_candidate_set_score(&combined_score, &current_score)
            == Ordering::Less
            || (combined_score.false_negatives < current_score.false_negatives
                && combined_score.false_positives <= current_score.false_positives);
        if !improved {
            break;
        }

        recovered = candidate_combined;
    }
    Ok(recovered)
}

fn dedupe_candidate_rules_by_signature(candidates: Vec<CandidateRule>) -> Vec<CandidateRule> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for candidate in candidates {
        if seen.insert(candidate.signature().to_string()) {
            deduped.push(candidate);
        }
    }
    deduped.sort_by(compare_candidate_priority);
    deduped
}

fn discover_rules_greedy(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    validation_indices: Option<&[usize]>,
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
) -> Result<Vec<CandidateRule>> {
    let mut remaining_denied = denied_indices.to_vec();
    let mut discovered = Vec::new();
    while !remaining_denied.is_empty() {
        let candidate = select_candidate_rule(
            rows,
            &remaining_denied,
            allowed_indices,
            validation_indices,
            feature_governance,
            decision_mode,
            residual_options,
        )
        .ok_or_else(|| LogicPearlError::message("no recoverable deny rule found"))?;
        if candidate.denied_coverage == 0 {
            break;
        }

        let has_false_positives = candidate.false_positives > 0;
        discovered.push(candidate.clone());
        remaining_denied.retain(|index| !matches_candidate(&rows[*index].features, &candidate));
        if has_false_positives {
            break;
        }
    }
    Ok(discovered)
}

fn select_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    validation_indices: Option<&[usize]>,
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
) -> Option<CandidateRule> {
    let selection_context = CandidateSelectionContext {
        rows,
        denied_indices,
        allowed_indices,
        validation_indices,
        feature_governance,
        decision_mode,
        residual_options,
    };
    let mut candidates = candidate_rules(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
        residual_options,
    );
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(compare_candidate_priority);
    candidates.truncate(LOOKAHEAD_FRONTIER_LIMIT);

    let mut best: Option<(CandidateRule, CandidatePlanScore)> = None;
    for candidate in candidates {
        let score = simulate_candidate_plan(&selection_context, &candidate);
        let better = match &best {
            None => true,
            Some((current_candidate, current_score)) => {
                compare_candidate_plan(&candidate, &score, current_candidate, current_score)
                    == Ordering::Less
            }
        };
        if better {
            best = Some((candidate, score));
        }
    }
    best.map(|(candidate, _score)| candidate)
}

fn simulate_candidate_plan(
    selection_context: &CandidateSelectionContext<'_>,
    first_candidate: &CandidateRule,
) -> CandidatePlanScore {
    let mut rules = vec![first_candidate.clone()];
    let mut remaining_denied: Vec<usize> = selection_context
        .denied_indices
        .iter()
        .copied()
        .filter(|index| {
            !matches_candidate(&selection_context.rows[*index].features, first_candidate)
        })
        .collect();

    if first_candidate.false_positives == 0 {
        while !remaining_denied.is_empty() {
            let Some(next) = best_immediate_candidate_rule(
                selection_context.rows,
                &remaining_denied,
                selection_context.allowed_indices,
                selection_context.feature_governance,
                selection_context.decision_mode,
                selection_context.residual_options,
            ) else {
                break;
            };
            if next.denied_coverage == 0 {
                break;
            }
            remaining_denied.retain(|index| {
                !matches_candidate(&selection_context.rows[*index].features, &next)
            });
            let has_false_positives = next.false_positives > 0;
            rules.push(next);
            if has_false_positives {
                break;
            }
        }
    }

    let validation_set = selection_context
        .validation_indices
        .map(|indices| indices.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let training_indices = selection_context
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| (!validation_set.contains(&index)).then_some(index))
        .collect::<Vec<_>>();
    let training_score = score_candidate_subset(selection_context.rows, &rules, &training_indices);
    let validation_score = score_candidate_subset(
        selection_context.rows,
        &rules,
        selection_context.validation_indices.unwrap_or(&[]),
    );

    CandidatePlanScore {
        training_total_errors: training_score.total_errors,
        training_false_positives: training_score.false_positives,
        validation_total_errors: validation_score.total_errors,
        validation_false_positives: validation_score.false_positives,
        uncovered_denied: remaining_denied.len(),
        rule_count: rules.len(),
    }
}

fn compare_candidate_plan(
    candidate: &CandidateRule,
    score: &CandidatePlanScore,
    current_candidate: &CandidateRule,
    current_score: &CandidatePlanScore,
) -> Ordering {
    score
        .training_total_errors
        .cmp(&current_score.training_total_errors)
        .then_with(|| {
            score
                .validation_total_errors
                .cmp(&current_score.validation_total_errors)
        })
        .then_with(|| {
            score
                .training_false_positives
                .cmp(&current_score.training_false_positives)
        })
        .then_with(|| {
            score
                .validation_false_positives
                .cmp(&current_score.validation_false_positives)
        })
        .then_with(|| score.uncovered_denied.cmp(&current_score.uncovered_denied))
        .then_with(|| score.rule_count.cmp(&current_score.rule_count))
        .then_with(|| compare_candidate_priority(candidate, current_candidate))
}

#[cfg(test)]
mod tests;
