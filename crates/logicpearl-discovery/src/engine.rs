// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    CombineStrategy, EvaluationConfig, Expression, FeatureDefinition, FeatureGovernance, GateType,
    InputSchema, LogicPearlGateIr, Provenance, RuleDefinition, RuleEvidence, RuleSupportEvidence,
    RuleTraceEvidence, RuleVerificationStatus, VerificationConfig,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

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
    decision_trace_row_hash, report_progress, rule_trace_evidence, CandidateRule, DecisionTraceRow,
    DiscoveryDecisionMode, ExactSelectionReport, PinnedRuleSet, ProgressCallback,
    ResidualPassOptions, ResidualRecoveryReport, ResidualRecoveryState, SelectionPolicy,
    UniqueCoverageRefinementOptions,
};
#[cfg(test)]
pub(super) use candidates::rule_from_candidate;
use candidates::{
    best_immediate_candidate_rule_with_cache, candidate_rules_with_cache,
    compare_candidate_priority, rule_from_candidate_with_context, CandidateMatchCache,
};
#[cfg(test)]
use candidates::{
    candidate_allowed_for_mode, candidate_as_comparison, candidate_complexity_penalty,
    candidate_rules, conjunction_candidate_rules,
};
pub(super) use residual_recovery::{discover_residual_rules, refine_rules_unique_coverage};
pub(super) use rule_hygiene::{dedupe_rules_by_signature, merge_discovered_and_pinned_rules};
use rule_limit::limit_rules_by_training_coverage;
#[cfg(test)]
use scoring::{compare_candidate_set_score, score_candidate_set, CandidateSetScore};
use scoring::{
    compare_candidate_set_score_with_policy, score_candidate_set_cached,
    score_candidate_subset_cached,
};
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

#[derive(Debug, Clone)]
struct CandidateChoice {
    candidate: CandidateRule,
    score: CandidatePlanScore,
}

#[derive(Debug, Clone)]
struct CandidateSelectionContext<'a> {
    rows: &'a [DecisionTraceRow],
    denied_indices: &'a [usize],
    allowed_indices: &'a [usize],
    training_indices: Vec<usize>,
    validation_indices: &'a [usize],
    training_denied_count: usize,
    training_allowed_count: usize,
    feature_governance: &'a BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    selection_policy: SelectionPolicy,
    residual_options: Option<&'a ResidualPassOptions>,
    match_cache: Arc<CandidateMatchCache<'a>>,
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
    selection_policy: SelectionPolicy,
    max_rules: Option<usize>,
    residual_options: Option<&ResidualPassOptions>,
    refinement_options: Option<&UniqueCoverageRefinementOptions>,
    pinned_rules: Option<&PinnedRuleSet>,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<(
    LogicPearlGateIr,
    ExactSelectionReport,
    usize,
    ResidualRecoveryReport,
    usize,
    usize,
)> {
    report_progress(
        progress,
        "discover_rules",
        format!("discover_rules: {} rows", rows.len()),
    );
    let (mut rules, exact_selection) = discover_rules(
        rows,
        feature_governance,
        feature_semantics,
        decision_mode,
        selection_policy,
        residual_options,
        progress,
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
        report_progress(
            progress,
            "residual_recovery",
            "residual_recovery: checking missed deny slices",
        );
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
        report_progress(
            progress,
            "refinement",
            format!("refinement: tightening {} discovered rules", rules.len()),
        );
        let (refined_rules, applied) = refine_rules_unique_coverage(rows, &rules, options)?;
        rules = refined_rules;
        refined_rules_applied = applied;
    }
    let mut pinned_rules_applied = 0usize;
    if let Some(pinned_rules) = pinned_rules {
        report_progress(
            progress,
            "pinned_rules",
            format!(
                "pinned_rules: merging {} pinned rules",
                pinned_rules.rules.len()
            ),
        );
        pinned_rules_applied = pinned_rules.rules.len();
        rules = merge_discovered_and_pinned_rules(rules, pinned_rules);
    } else {
        rules = dedupe_rules_by_signature(rules);
    }
    report_progress(
        progress,
        "rule_hygiene",
        format!("rule_hygiene: canonicalizing {} rules", rules.len()),
    );
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
    selection_policy: SelectionPolicy,
    residual_options: Option<&ResidualPassOptions>,
    progress: Option<&ProgressCallback<'_>>,
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
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: {} denied / {} allowed rows",
            denied_indices.len(),
            allowed_indices.len()
        ),
    );
    let (train_denied_indices, train_allowed_indices, validation_indices) =
        match validation_split.as_ref() {
            Some(split) => (
                split.train_denied_indices.clone(),
                split.train_allowed_indices.clone(),
                Some(split.validation_indices.as_slice()),
            ),
            None => (denied_indices.clone(), allowed_indices.clone(), None),
        };
    let validation_indices_slice = validation_indices.unwrap_or(&[]);
    let training_indices = training_indices(rows, validation_indices_slice);
    let match_cache = Arc::new(CandidateMatchCache::new(rows));

    let all_candidates = candidate_rules_with_cache(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        feature_governance,
        decision_mode,
        residual_options,
        progress,
        Some(match_cache.as_ref()),
    );
    if all_candidates.is_empty() {
        return Err(LogicPearlError::message("no recoverable deny rule found"));
    }
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: {} candidate rules",
            all_candidates.len()
        ),
    );

    let selection_context = CandidateSelectionContext {
        rows,
        denied_indices: &train_denied_indices,
        allowed_indices: &train_allowed_indices,
        training_indices,
        validation_indices: validation_indices_slice,
        training_denied_count: train_denied_indices.len(),
        training_allowed_count: train_allowed_indices.len(),
        feature_governance,
        decision_mode,
        selection_policy,
        residual_options,
        match_cache,
    };
    report_progress(
        progress,
        "greedy_selection",
        "greedy_selection: selecting rule plan",
    );
    let greedy_plan = discover_rules_greedy(&selection_context, progress)?;
    report_progress(
        progress,
        "greedy_selection",
        format!("greedy_selection: {} rules shortlisted", greedy_plan.len()),
    );
    let shortlist = exact_selection_shortlist(
        &all_candidates,
        &greedy_plan,
        EXACT_SELECTION_FRONTIER_LIMIT,
    );
    report_progress(
        progress,
        "exact_selection",
        format!(
            "exact_selection: evaluating {} shortlisted candidates",
            shortlist.len()
        ),
    );
    let (exact_plan, mut exact_selection) = select_candidate_rules_exact(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        &shortlist,
        selection_policy,
    )?;
    let selected_candidates = match exact_plan {
        Some(exact_plan) if !exact_plan.is_empty() => {
            let greedy_score = score_candidate_set_cached(
                &greedy_plan,
                &selection_context.training_indices,
                selection_context.validation_indices,
                &selection_context.match_cache,
            );
            let exact_score = score_candidate_set_cached(
                &exact_plan,
                &selection_context.training_indices,
                selection_context.validation_indices,
                &selection_context.match_cache,
            );
            if compare_candidate_set_score_with_policy(
                &exact_score,
                &greedy_score,
                selection_policy,
                train_denied_indices.len(),
                train_allowed_indices.len(),
            ) == Ordering::Less
            {
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
    report_progress(
        progress,
        "rare_rule_recovery",
        "rare_rule_recovery: checking uncovered deny slices",
    );
    let selected_candidates =
        recover_rare_rules(&selection_context, selected_candidates, progress)?;
    report_progress(
        progress,
        "rule_text",
        format!(
            "rule_text: rendering {} selected rules",
            selected_candidates.len()
        ),
    );

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
    progress: Option<&ProgressCallback<'_>>,
) -> Result<Vec<CandidateRule>> {
    let mut recovered = selected_candidates;
    for _ in 0..RARE_RULE_RECOVERY_MAX_PASSES {
        let uncovered_denied = selection_context
            .denied_indices
            .iter()
            .copied()
            .filter(|index| {
                !recovered.iter().any(|candidate| {
                    selection_context
                        .match_cache
                        .matches_candidate(*index, candidate)
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
        let rescue_shortlist = candidate_rules_with_cache(
            selection_context.rows,
            &uncovered_denied,
            selection_context.allowed_indices,
            selection_context.feature_governance,
            selection_context.decision_mode,
            selection_context.residual_options,
            progress,
            Some(selection_context.match_cache.as_ref()),
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
            selection_context.selection_policy,
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

        let current_score = score_candidate_set_cached(
            &recovered,
            &selection_context.training_indices,
            selection_context.validation_indices,
            &selection_context.match_cache,
        );
        let combined_score = score_candidate_set_cached(
            &candidate_combined,
            &selection_context.training_indices,
            selection_context.validation_indices,
            &selection_context.match_cache,
        );
        let improved = compare_candidate_set_score_with_policy(
            &combined_score,
            &current_score,
            selection_context.selection_policy,
            selection_context.training_denied_count,
            selection_context.training_allowed_count,
        ) == Ordering::Less
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

fn training_indices(rows: &[DecisionTraceRow], validation_indices: &[usize]) -> Vec<usize> {
    let validation_set = validation_indices.iter().copied().collect::<BTreeSet<_>>();
    rows.iter()
        .enumerate()
        .filter_map(|(index, _)| (!validation_set.contains(&index)).then_some(index))
        .collect()
}

fn current_plan_score(
    selection_context: &CandidateSelectionContext<'_>,
    rules: &[CandidateRule],
) -> CandidatePlanScore {
    let training_score = score_candidate_subset_cached(
        rules,
        &selection_context.training_indices,
        &selection_context.match_cache,
    );
    let validation_score = score_candidate_subset_cached(
        rules,
        selection_context.validation_indices,
        &selection_context.match_cache,
    );
    let uncovered_denied = selection_context
        .denied_indices
        .iter()
        .filter(|index| {
            !rules.iter().any(|candidate| {
                selection_context
                    .match_cache
                    .matches_candidate(**index, candidate)
            })
        })
        .count();
    CandidatePlanScore {
        training_total_errors: training_score.total_errors,
        training_false_positives: training_score.false_positives,
        validation_total_errors: validation_score.total_errors,
        validation_false_positives: validation_score.false_positives,
        uncovered_denied,
        rule_count: rules.len(),
    }
}

fn plan_respects_false_positive_cap(
    selection_context: &CandidateSelectionContext<'_>,
    score: &CandidatePlanScore,
) -> bool {
    score.training_false_positives
        <= selection_context
            .selection_policy
            .max_allowed_false_positives(selection_context.training_allowed_count)
}

fn plan_meets_recall_target(
    selection_context: &CandidateSelectionContext<'_>,
    score: &CandidatePlanScore,
) -> bool {
    selection_context
        .training_denied_count
        .saturating_sub(score.uncovered_denied)
        >= selection_context
            .selection_policy
            .required_denied_hits(selection_context.training_denied_count)
}

fn should_stop_greedy_selection(
    selection_context: &CandidateSelectionContext<'_>,
    discovered: &[CandidateRule],
) -> bool {
    if discovered.is_empty() {
        return false;
    }
    match selection_context.selection_policy {
        SelectionPolicy::Balanced => discovered
            .iter()
            .any(|candidate| candidate.false_positives > 0),
        SelectionPolicy::RecallBiased { .. } => {
            let score = current_plan_score(selection_context, discovered);
            plan_respects_false_positive_cap(selection_context, &score)
                && plan_meets_recall_target(selection_context, &score)
        }
    }
}

fn discover_rules_greedy(
    selection_context: &CandidateSelectionContext<'_>,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<Vec<CandidateRule>> {
    let mut remaining_denied = selection_context.denied_indices.to_vec();
    let mut discovered = Vec::new();
    let total_denied = selection_context.denied_indices.len();
    while !remaining_denied.is_empty() {
        let pass = discovered.len() + 1;
        report_progress(
            progress,
            "greedy_selection",
            format!(
                "greedy_selection: pass {pass}; remaining_denied={}/{}; selected_rules={}",
                remaining_denied.len(),
                total_denied,
                discovered.len()
            ),
        );
        if should_stop_greedy_selection(selection_context, &discovered) {
            report_progress(
                progress,
                "greedy_selection",
                format!("greedy_selection: pass {pass}; selection policy target reached"),
            );
            break;
        }
        let choice = select_candidate_rule(
            &remaining_denied,
            &discovered,
            selection_context,
            progress,
            pass,
        )
        .ok_or_else(|| LogicPearlError::message("no recoverable deny rule found"))?;
        if choice.candidate.denied_coverage == 0 {
            report_progress(
                progress,
                "greedy_selection",
                format!("greedy_selection: pass {pass}; selected candidate covered 0 rows"),
            );
            break;
        }
        if matches!(
            selection_context.selection_policy,
            SelectionPolicy::RecallBiased { .. }
        ) && !plan_respects_false_positive_cap(selection_context, &choice.score)
        {
            report_progress(
                progress,
                "greedy_selection",
                format!(
                    "greedy_selection: pass {pass}; stopping because the next plan would exceed the false-positive cap"
                ),
            );
            break;
        }

        let has_false_positives = choice.candidate.false_positives > 0;
        report_progress(
            progress,
            "greedy_selection",
            format!(
                "greedy_selection: pass {pass}; selected candidate denied_coverage={} false_positives={}",
                choice.candidate.denied_coverage,
                choice.candidate.false_positives
            ),
        );
        discovered.push(choice.candidate.clone());
        remaining_denied.retain(|index| {
            !selection_context
                .match_cache
                .matches_candidate(*index, &choice.candidate)
        });
        report_progress(
            progress,
            "greedy_selection",
            format!(
                "greedy_selection: pass {pass}; remaining_denied={}/{} after selection",
                remaining_denied.len(),
                total_denied
            ),
        );
        if matches!(
            selection_context.selection_policy,
            SelectionPolicy::Balanced
        ) && has_false_positives
        {
            report_progress(
                progress,
                "greedy_selection",
                format!("greedy_selection: pass {pass}; stopping after false-positive rule"),
            );
            break;
        }
    }
    report_progress(
        progress,
        "greedy_selection",
        format!("greedy_selection: selected {} rules", discovered.len()),
    );
    Ok(discovered)
}

fn select_candidate_rule(
    denied_indices: &[usize],
    seed_rules: &[CandidateRule],
    selection_context: &CandidateSelectionContext<'_>,
    progress: Option<&ProgressCallback<'_>>,
    pass: usize,
) -> Option<CandidateChoice> {
    report_progress(
        progress,
        "greedy_selection",
        format!("greedy_selection: pass {pass}; enumerating lookahead candidates"),
    );
    let mut candidates = candidate_rules_with_cache(
        selection_context.rows,
        denied_indices,
        selection_context.allowed_indices,
        selection_context.feature_governance,
        selection_context.decision_mode,
        selection_context.residual_options,
        progress,
        Some(selection_context.match_cache.as_ref()),
    );
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(compare_candidate_priority);
    candidates.truncate(LOOKAHEAD_FRONTIER_LIMIT);
    report_progress(
        progress,
        "greedy_selection",
        format!(
            "greedy_selection: pass {pass}; evaluating {} lookahead candidates",
            candidates.len()
        ),
    );

    let scored_candidates =
        score_lookahead_candidates(seed_rules, selection_context, candidates, progress, pass);

    let mut best: Option<CandidateChoice> = None;
    for (index, candidate, score) in scored_candidates {
        let better = match &best {
            None => true,
            Some(current) => {
                compare_candidate_plan(
                    selection_context,
                    &candidate,
                    &score,
                    &current.candidate,
                    &current.score,
                ) == Ordering::Less
            }
        };
        if better {
            report_progress(
                progress,
                "greedy_selection",
                format!(
                    "greedy_selection: pass {pass}; best lookahead={} training_errors={} validation_errors={} uncovered_denied={} projected_rules={}",
                    index + 1,
                    score.training_total_errors,
                    score.validation_total_errors,
                    score.uncovered_denied,
                    score.rule_count
                ),
            );
            best = Some(CandidateChoice { candidate, score });
        }
    }
    best
}

fn score_lookahead_candidates(
    seed_rules: &[CandidateRule],
    selection_context: &CandidateSelectionContext<'_>,
    candidates: Vec<CandidateRule>,
    progress: Option<&ProgressCallback<'_>>,
    pass: usize,
) -> Vec<(usize, CandidateRule, CandidatePlanScore)> {
    let candidate_count = candidates.len();
    if candidate_count <= 1
        || std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            <= 1
    {
        return candidates
            .into_iter()
            .enumerate()
            .map(|(index, candidate)| {
                report_progress(
                    progress,
                    "greedy_selection",
                    format!(
                        "greedy_selection: pass {pass}; evaluating lookahead {}/{}",
                        index + 1,
                        candidate_count
                    ),
                );
                let score = simulate_candidate_plan(
                    seed_rules,
                    selection_context,
                    &candidate,
                    progress,
                    pass,
                    index + 1,
                );
                (index, candidate, score)
            })
            .collect();
    }

    report_progress(
        progress,
        "greedy_selection",
        format!(
            "greedy_selection: pass {pass}; evaluating {candidate_count} lookahead candidates in parallel"
        ),
    );
    let mut scored = std::thread::scope(|scope| {
        let handles = candidates
            .into_iter()
            .enumerate()
            .map(|(index, candidate)| {
                scope.spawn(move || {
                    let score = simulate_candidate_plan(
                        seed_rules,
                        selection_context,
                        &candidate,
                        None,
                        pass,
                        index + 1,
                    );
                    (index, candidate, score)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("greedy-selection worker panicked"))
            .collect::<Vec<_>>()
    });
    scored.sort_by_key(|(index, _, _)| *index);
    scored
}

fn simulate_candidate_plan(
    seed_rules: &[CandidateRule],
    selection_context: &CandidateSelectionContext<'_>,
    first_candidate: &CandidateRule,
    progress: Option<&ProgressCallback<'_>>,
    pass: usize,
    lookahead_index: usize,
) -> CandidatePlanScore {
    let mut rules = seed_rules.to_vec();
    rules.push(first_candidate.clone());
    let mut remaining_denied: Vec<usize> = selection_context
        .denied_indices
        .iter()
        .copied()
        .filter(|index| {
            !rules.iter().any(|candidate| {
                selection_context
                    .match_cache
                    .matches_candidate(*index, candidate)
            })
        })
        .collect();

    if !matches!(
        selection_context.selection_policy,
        SelectionPolicy::Balanced
    ) || first_candidate.false_positives == 0
    {
        while !remaining_denied.is_empty() {
            let simulated_step = rules.len() + 1;
            report_progress(
                progress,
                "greedy_selection",
                format!(
                    "greedy_selection: pass {pass}; lookahead={lookahead_index}; sim_step={simulated_step}; remaining_denied={}",
                    remaining_denied.len()
                ),
            );
            let Some(next) = best_immediate_candidate_rule_with_cache(
                selection_context.rows,
                &remaining_denied,
                selection_context.allowed_indices,
                selection_context.feature_governance,
                selection_context.decision_mode,
                selection_context.residual_options,
                &selection_context.match_cache,
            ) else {
                break;
            };
            if next.denied_coverage == 0 {
                break;
            }
            remaining_denied.retain(|index| {
                !selection_context
                    .match_cache
                    .matches_candidate(*index, &next)
            });
            let has_false_positives = next.false_positives > 0;
            rules.push(next);
            if matches!(
                selection_context.selection_policy,
                SelectionPolicy::Balanced
            ) && has_false_positives
            {
                break;
            }
            if matches!(
                selection_context.selection_policy,
                SelectionPolicy::RecallBiased { .. }
            ) {
                let score = current_plan_score(selection_context, &rules);
                if !plan_respects_false_positive_cap(selection_context, &score)
                    || plan_meets_recall_target(selection_context, &score)
                {
                    break;
                }
            }
        }
    }

    let mut score = current_plan_score(selection_context, &rules);
    score.uncovered_denied = remaining_denied.len();
    score
}

fn compare_candidate_plan(
    selection_context: &CandidateSelectionContext<'_>,
    candidate: &CandidateRule,
    score: &CandidatePlanScore,
    current_candidate: &CandidateRule,
    current_score: &CandidatePlanScore,
) -> Ordering {
    match selection_context.selection_policy {
        SelectionPolicy::Balanced => score
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
            .then_with(|| compare_candidate_priority(candidate, current_candidate)),
        SelectionPolicy::RecallBiased { .. } => {
            let score_under_cap = plan_respects_false_positive_cap(selection_context, score);
            let current_under_cap =
                plan_respects_false_positive_cap(selection_context, current_score);
            current_under_cap
                .cmp(&score_under_cap)
                .then_with(|| {
                    if score_under_cap && current_under_cap {
                        let score_hits_target = plan_meets_recall_target(selection_context, score);
                        let current_hits_target =
                            plan_meets_recall_target(selection_context, current_score);
                        current_hits_target.cmp(&score_hits_target).then_with(|| {
                            if score_hits_target && current_hits_target {
                                score
                                    .training_false_positives
                                    .cmp(&current_score.training_false_positives)
                                    .then_with(|| {
                                        score
                                            .validation_false_positives
                                            .cmp(&current_score.validation_false_positives)
                                    })
                                    .then_with(|| {
                                        score
                                            .validation_total_errors
                                            .cmp(&current_score.validation_total_errors)
                                    })
                                    .then_with(|| score.rule_count.cmp(&current_score.rule_count))
                                    .then_with(|| {
                                        score.uncovered_denied.cmp(&current_score.uncovered_denied)
                                    })
                            } else {
                                score
                                    .uncovered_denied
                                    .cmp(&current_score.uncovered_denied)
                                    .then_with(|| {
                                        score
                                            .training_false_positives
                                            .cmp(&current_score.training_false_positives)
                                    })
                                    .then_with(|| {
                                        score
                                            .validation_total_errors
                                            .cmp(&current_score.validation_total_errors)
                                    })
                                    .then_with(|| score.rule_count.cmp(&current_score.rule_count))
                            }
                        })
                    } else {
                        score
                            .training_false_positives
                            .cmp(&current_score.training_false_positives)
                            .then_with(|| {
                                score.uncovered_denied.cmp(&current_score.uncovered_denied)
                            })
                            .then_with(|| {
                                score
                                    .validation_total_errors
                                    .cmp(&current_score.validation_total_errors)
                            })
                            .then_with(|| score.rule_count.cmp(&current_score.rule_count))
                    }
                })
                .then_with(|| compare_candidate_priority(candidate, current_candidate))
        }
    }
}

#[cfg(test)]
mod tests;
