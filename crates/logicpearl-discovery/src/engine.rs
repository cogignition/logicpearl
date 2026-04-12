// SPDX-License-Identifier: MIT
use good_lp::{
    constraint, microlp, variable, variables, Expression as LpExpression, ResolutionError,
    Solution, SolverModel, Variable,
};
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    BooleanEvidencePolicy, CombineStrategy, ComparisonExpression, ComparisonOperator,
    ComparisonValue, EvaluationConfig, Expression, FeatureDefinition, FeatureGovernance, GateType,
    InputSchema, LogicPearlGateIr, Provenance, RuleDefinition, RuleKind, RuleVerificationStatus,
    VerificationConfig,
};
use logicpearl_runtime::evaluate_gate;
use logicpearl_solver::{
    resolve_backend, solve_keep_bools_lexicographic, LexObjective, SatStatus, SolverSettings,
};
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionCandidate, BooleanConjunctionSearchOptions,
    BooleanSearchExample,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::time::Instant;

use super::canonicalize::{
    canonicalize_rules, comparison_matches, expression_matches, prune_redundant_rules,
};
use super::features::{
    boolean_feature_map, infer_binary_feature_names, infer_feature_type, is_derived_feature_name,
    numeric_feature_names, rule_contains_feature, rule_with_added_condition, sorted_feature_names,
};
use super::rule_text::{generate_rule_text, RuleTextContext};
use super::{
    CandidateRule, DecisionTraceRow, DiscoveryDecisionMode, ExactSelectionBackend,
    ExactSelectionReport, PinnedRuleSet, ResidualPassOptions, ResidualRecoveryReport,
    ResidualRecoveryState, UniqueCoverageRefinementOptions,
};

const LOOKAHEAD_FRONTIER_LIMIT: usize = 12;
const NUMERIC_EQ_MAX_DISTINCT_VALUES: usize = 20;
const NUMERIC_EQ_MIN_SUPPORT_ABSOLUTE: usize = 3;
const NUMERIC_EQ_MIN_SUPPORT_BASIS_POINTS: usize = 10; // 0.1%
const EXACT_SELECTION_FRONTIER_LIMIT: usize = 48;
const EXACT_SELECTION_COMPOUND_FRONTIER_LIMIT: usize = 24;
const EXACT_SELECTION_BRUTE_FORCE_LIMIT: usize = 16;
const CONJUNCTION_ATOM_FRONTIER_LIMIT: usize = 128;
const RARE_RULE_RECOVERY_FRONTIER_LIMIT: usize = 24;
const RARE_RULE_RECOVERY_MAX_PASSES: usize = 3;
const DISCOVERY_VALIDATION_MIN_CLASS_ROWS: usize = 20;
const DISCOVERY_VALIDATION_FRACTION_NUMERATOR: usize = 1;
const DISCOVERY_VALIDATION_FRACTION_DENOMINATOR: usize = 5;
pub(crate) const DISCOVERY_SELECTION_BACKEND_ENV: &str = "LOGICPEARL_DISCOVERY_SELECTION_BACKEND";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoverySelectionBackend {
    Smt,
    Mip,
}

struct DiscoverySelectionSettings {
    backend: DiscoverySelectionBackend,
}

impl DiscoverySelectionSettings {
    fn from_env() -> Result<Self> {
        let backend = env::var(DISCOVERY_SELECTION_BACKEND_ENV)
            .ok()
            .map(|raw| parse_discovery_selection_backend(&raw))
            .transpose()?
            .unwrap_or(DiscoverySelectionBackend::Smt);
        Ok(Self { backend })
    }
}

fn parse_discovery_selection_backend(raw: &str) -> Result<DiscoverySelectionBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "smt" => Ok(DiscoverySelectionBackend::Smt),
        "mip" => Ok(DiscoverySelectionBackend::Mip),
        other => Err(LogicPearlError::message(format!(
            "unsupported discovery selection backend `{other}` in {DISCOVERY_SELECTION_BACKEND_ENV}; expected `smt` or `mip`"
        ))),
    }
}

fn current_solver_backend() -> Result<Option<String>> {
    let settings = SolverSettings::from_env()?;
    Ok(Some(resolve_backend(&settings)?.as_str().to_string()))
}

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
struct DiscoveryValidationSplit {
    train_denied_indices: Vec<usize>,
    train_allowed_indices: Vec<usize>,
    validation_indices: Vec<usize>,
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

pub(super) fn merge_discovered_and_pinned_rules(
    discovered: Vec<RuleDefinition>,
    pinned: &PinnedRuleSet,
) -> Vec<RuleDefinition> {
    let mut merged = discovered;
    merged.extend(pinned.rules.clone());
    dedupe_rules_by_signature(merged)
}

pub(super) fn dedupe_rules_by_signature(rules: Vec<RuleDefinition>) -> Vec<RuleDefinition> {
    let mut by_signature: BTreeMap<String, RuleDefinition> = BTreeMap::new();
    for rule in rules {
        let signature = rule_signature(&rule);
        match by_signature.get(&signature) {
            None => {
                by_signature.insert(signature, rule);
            }
            Some(existing) => {
                if prefer_rule(&rule, existing) == Ordering::Greater {
                    by_signature.insert(signature, rule);
                }
            }
        }
    }

    by_signature
        .into_values()
        .enumerate()
        .map(|(index, mut rule)| {
            rule.bit = index as u32;
            rule.id = format!("rule_{index:03}");
            rule
        })
        .collect()
}

fn prefer_rule(left: &RuleDefinition, right: &RuleDefinition) -> Ordering {
    verification_rank(left)
        .cmp(&verification_rank(right))
        .then_with(|| {
            expression_complexity(&right.deny_when).cmp(&expression_complexity(&left.deny_when))
        })
}

fn verification_rank(rule: &RuleDefinition) -> i32 {
    match rule
        .verification_status
        .as_ref()
        .unwrap_or(&RuleVerificationStatus::PipelineUnverified)
    {
        RuleVerificationStatus::SolverVerified => 4,
        RuleVerificationStatus::RefinedUnverified => 3,
        RuleVerificationStatus::PipelineUnverified => 2,
        RuleVerificationStatus::HeuristicUnverified => 1,
    }
}

fn expression_complexity(expression: &Expression) -> usize {
    match expression {
        Expression::Comparison(_) => 1,
        Expression::All { all } => all.iter().map(expression_complexity).sum(),
        Expression::Any { any } => any.iter().map(expression_complexity).sum(),
        Expression::Not { expr } => expression_complexity(expr),
    }
}

fn rule_signature(rule: &RuleDefinition) -> String {
    let mut normalized = rule.clone();
    normalized.id = String::new();
    normalized.bit = 0;
    normalized.verification_status = None;
    serde_json::to_string(&normalized).expect("rule signature serialization")
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

fn discovery_validation_split(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Option<DiscoveryValidationSplit> {
    if denied_indices.len() < DISCOVERY_VALIDATION_MIN_CLASS_ROWS
        || allowed_indices.len() < DISCOVERY_VALIDATION_MIN_CLASS_ROWS
    {
        return None;
    }

    let (train_denied_indices, validation_denied_indices) =
        stratified_train_validation_indices(rows, denied_indices);
    let (train_allowed_indices, validation_allowed_indices) =
        stratified_train_validation_indices(rows, allowed_indices);
    if train_denied_indices.is_empty()
        || train_allowed_indices.is_empty()
        || validation_denied_indices.is_empty()
        || validation_allowed_indices.is_empty()
    {
        return None;
    }

    let mut validation_indices = validation_denied_indices;
    validation_indices.extend(validation_allowed_indices);
    validation_indices.sort_unstable();

    Some(DiscoveryValidationSplit {
        train_denied_indices,
        train_allowed_indices,
        validation_indices,
    })
}

fn stratified_train_validation_indices(
    rows: &[DecisionTraceRow],
    indices: &[usize],
) -> (Vec<usize>, Vec<usize>) {
    let mut sorted = indices.to_vec();
    sorted.sort_by_key(|index| stable_row_bucket(&rows[*index]));

    let validation_count = std::cmp::max(
        1,
        (sorted.len() * DISCOVERY_VALIDATION_FRACTION_NUMERATOR)
            / DISCOVERY_VALIDATION_FRACTION_DENOMINATOR,
    )
    .min(sorted.len().saturating_sub(1));

    let validation = sorted[..validation_count].to_vec();
    let train = sorted[validation_count..].to_vec();
    (train, validation)
}

fn stable_row_bucket(row: &DecisionTraceRow) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    row.allowed.hash(&mut hasher);
    let sorted_features = row.features.iter().collect::<BTreeMap<_, _>>();
    for (key, value) in sorted_features {
        key.hash(&mut hasher);
        hash_json_value(&mut hasher, value);
    }
    hasher.finish()
}

fn hash_json_value(hasher: &mut impl std::hash::Hasher, value: &Value) {
    use std::hash::Hash;
    match value {
        Value::Null => 0u8.hash(hasher),
        Value::Bool(b) => {
            1u8.hash(hasher);
            b.hash(hasher);
        }
        Value::Number(n) => {
            2u8.hash(hasher);
            // Use the string representation for stable hashing of numbers.
            n.to_string().hash(hasher);
        }
        Value::String(s) => {
            3u8.hash(hasher);
            s.hash(hasher);
        }
        Value::Array(arr) => {
            4u8.hash(hasher);
            arr.len().hash(hasher);
            for item in arr {
                hash_json_value(hasher, item);
            }
        }
        Value::Object(obj) => {
            5u8.hash(hasher);
            obj.len().hash(hasher);
            for (k, v) in obj {
                k.hash(hasher);
                hash_json_value(hasher, v);
            }
        }
    }
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

fn exact_selection_shortlist(
    all_candidates: &[CandidateRule],
    greedy_plan: &[CandidateRule],
    limit: usize,
) -> Vec<CandidateRule> {
    let mut shortlisted: Vec<CandidateRule> = all_candidates.iter().take(limit).cloned().collect();
    let mut signatures: BTreeSet<String> = shortlisted
        .iter()
        .map(|c| c.signature().to_string())
        .collect();
    for candidate in all_candidates
        .iter()
        .filter(|candidate| candidate_is_compound(candidate))
        .take(EXACT_SELECTION_COMPOUND_FRONTIER_LIMIT)
    {
        let signature = candidate.signature().to_string();
        if signatures.insert(signature) {
            shortlisted.push(candidate.clone());
        }
    }
    for candidate in greedy_plan {
        let signature = candidate.signature().to_string();
        if signatures.insert(signature) {
            shortlisted.push(candidate.clone());
        }
    }
    shortlisted.sort_by(compare_candidate_priority);
    shortlisted
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateSetScore {
    total_errors: usize,
    false_positives: usize,
    false_negatives: usize,
    validation_total_errors: usize,
    validation_false_positives: usize,
    validation_false_negatives: usize,
    rule_count: usize,
    complexity_penalty: usize,
}

fn compare_candidate_set_score(left: &CandidateSetScore, right: &CandidateSetScore) -> Ordering {
    left.total_errors
        .cmp(&right.total_errors)
        .then_with(|| {
            left.validation_total_errors
                .cmp(&right.validation_total_errors)
        })
        .then_with(|| left.false_positives.cmp(&right.false_positives))
        .then_with(|| {
            left.validation_false_positives
                .cmp(&right.validation_false_positives)
        })
        .then_with(|| left.rule_count.cmp(&right.rule_count))
        .then_with(|| left.complexity_penalty.cmp(&right.complexity_penalty))
        .then_with(|| left.false_negatives.cmp(&right.false_negatives))
        .then_with(|| {
            left.validation_false_negatives
                .cmp(&right.validation_false_negatives)
        })
}

fn score_candidate_set(
    rows: &[DecisionTraceRow],
    candidates: &[CandidateRule],
    validation_indices: Option<&[usize]>,
) -> CandidateSetScore {
    let validation_set = validation_indices
        .map(|indices| indices.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let training_indices = rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| (!validation_set.contains(&index)).then_some(index))
        .collect::<Vec<_>>();
    let training_score = score_candidate_subset(rows, candidates, &training_indices);
    let validation_score =
        score_candidate_subset(rows, candidates, validation_indices.unwrap_or(&[]));
    let complexity_penalty = candidates.iter().map(candidate_total_penalty).sum();
    CandidateSetScore {
        total_errors: training_score.total_errors,
        false_positives: training_score.false_positives,
        false_negatives: training_score.false_negatives,
        validation_total_errors: validation_score.total_errors,
        validation_false_positives: validation_score.false_positives,
        validation_false_negatives: validation_score.false_negatives,
        rule_count: candidates.len(),
        complexity_penalty,
    }
}

fn score_candidate_subset(
    rows: &[DecisionTraceRow],
    candidates: &[CandidateRule],
    indices: &[usize],
) -> CandidateSubsetScore {
    let false_positives = indices
        .iter()
        .filter(|index| {
            rows[**index].allowed
                && candidates
                    .iter()
                    .any(|rule| matches_candidate(&rows[**index].features, rule))
        })
        .count();
    let false_negatives = indices
        .iter()
        .filter(|index| {
            !rows[**index].allowed
                && !candidates
                    .iter()
                    .any(|rule| matches_candidate(&rows[**index].features, rule))
        })
        .count();
    CandidateSubsetScore {
        total_errors: false_positives + false_negatives,
        false_positives,
        false_negatives,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateSubsetScore {
    total_errors: usize,
    false_positives: usize,
    false_negatives: usize,
}

fn candidate_total_penalty(candidate: &CandidateRule) -> usize {
    candidate_complexity_penalty(candidate, DiscoveryDecisionMode::Standard)
        + candidate_memorization_penalty(candidate)
}

fn select_candidate_rules_exact(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    candidates: &[CandidateRule],
) -> Result<(Option<Vec<CandidateRule>>, ExactSelectionReport)> {
    let started = Instant::now();
    let mut report = ExactSelectionReport {
        shortlisted_candidates: candidates.len(),
        ..Default::default()
    };
    if candidates.is_empty() {
        report.duration_ms = Some(started.elapsed().as_millis() as u64);
        return Ok((Some(Vec::new()), report));
    }
    let denied_matches: Vec<Vec<usize>> = denied_indices
        .iter()
        .map(|index| {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(candidate_index, candidate)| {
                    matches_candidate(&rows[*index].features, candidate).then_some(candidate_index)
                })
                .collect()
        })
        .collect();
    let allowed_matches: Vec<Vec<usize>> = allowed_indices
        .iter()
        .map(|index| {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(candidate_index, candidate)| {
                    matches_candidate(&rows[*index].features, candidate).then_some(candidate_index)
                })
                .collect()
        })
        .collect();

    if candidates.len() <= EXACT_SELECTION_BRUTE_FORCE_LIMIT {
        let selected =
            select_candidate_rules_bruteforce(candidates, &denied_matches, &allowed_matches);
        report.backend = Some(ExactSelectionBackend::BruteForce);
        report.selected_candidates = selected.len();
        report.duration_ms = Some(started.elapsed().as_millis() as u64);
        return Ok((Some(selected), report));
    }

    let selection_settings = DiscoverySelectionSettings::from_env()?;
    report.backend = Some(match selection_settings.backend {
        DiscoverySelectionBackend::Smt => ExactSelectionBackend::Smt,
        DiscoverySelectionBackend::Mip => ExactSelectionBackend::Mip,
    });
    let selected_indexes = match selection_settings.backend {
        DiscoverySelectionBackend::Smt => {
            let (smt, objectives) =
                build_exact_selection_problem(candidates, &denied_matches, &allowed_matches);
            match solve_selected_rule_indexes(candidates.len(), &smt, &objectives) {
                Ok(indexes) => indexes,
                Err(err) => {
                    report.detail = Some(format!(
                        "falling back to greedy after SMT exact selection failed: {err}"
                    ));
                    report.duration_ms = Some(started.elapsed().as_millis() as u64);
                    return Ok((None, report));
                }
            }
        }
        DiscoverySelectionBackend::Mip => {
            match solve_selected_rule_indexes_mip(candidates, &denied_matches, &allowed_matches) {
                Ok(indexes) => indexes,
                Err(err) => {
                    report.detail = Some(format!(
                        "falling back to greedy after MIP exact selection failed: {err}"
                    ));
                    report.duration_ms = Some(started.elapsed().as_millis() as u64);
                    return Ok((None, report));
                }
            }
        }
    };
    report.selected_candidates = selected_indexes.len();
    report.duration_ms = Some(started.elapsed().as_millis() as u64);
    Ok((
        Some(
            selected_indexes
                .into_iter()
                .map(|index| candidates[index].clone())
                .collect(),
        ),
        report,
    ))
}

fn build_exact_selection_problem(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> (String, Vec<LexObjective>) {
    let mut smt = String::new();
    for index in 0..candidates.len() {
        smt.push_str(&format!("(declare-fun keep_{index} () Bool)\n"));
    }

    for (index, matches) in denied_matches.iter().enumerate() {
        smt.push_str(&format!("(declare-fun deny_hit_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= deny_hit_{index} {}))\n",
            match_expression_for(matches)
        ));
    }
    for (index, matches) in allowed_matches.iter().enumerate() {
        smt.push_str(&format!("(declare-fun allow_hit_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= allow_hit_{index} {}))\n",
            match_expression_for(matches)
        ));
    }

    let objectives = vec![
        LexObjective::minimize(format!(
            "(+ {} {})",
            hit_sum("deny_hit", denied_matches.len(), false),
            hit_sum("allow_hit", allowed_matches.len(), true)
        )),
        LexObjective::minimize(hit_sum("allow_hit", allowed_matches.len(), true)),
        LexObjective::minimize(keep_sum(candidates.len())),
        LexObjective::minimize(weighted_keep_sum(candidates)),
        LexObjective::minimize(keep_index_sum(candidates.len())),
    ];
    (smt, objectives)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExactSelectionScore {
    total_errors: usize,
    allowed_hits: usize,
    rule_count: usize,
    complexity_weight: usize,
    index_weight: usize,
}

struct CandidateMatchMasks {
    denied: Vec<usize>,
    allowed: Vec<usize>,
}

fn select_candidate_rules_bruteforce(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> Vec<CandidateRule> {
    let match_masks = candidate_match_masks(candidates.len(), denied_matches, allowed_matches);
    let upper_bound = 1usize << candidates.len();
    let mut best_mask = 0usize;
    let mut best_score = exact_selection_score(0, candidates, &match_masks);

    for mask in 1..upper_bound {
        let score = exact_selection_score(mask, candidates, &match_masks);
        if score < best_score {
            best_score = score;
            best_mask = mask;
        }
    }

    candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            ((best_mask & (1usize << index)) != 0).then_some(candidate.clone())
        })
        .collect()
}

fn candidate_match_masks(
    candidate_count: usize,
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> CandidateMatchMasks {
    let to_mask = |matches: &[usize]| {
        matches.iter().fold(0usize, |mask, index| {
            debug_assert!(*index < candidate_count);
            mask | (1usize << index)
        })
    };

    CandidateMatchMasks {
        denied: denied_matches
            .iter()
            .map(|matches| to_mask(matches))
            .collect(),
        allowed: allowed_matches
            .iter()
            .map(|matches| to_mask(matches))
            .collect(),
    }
}

fn exact_selection_score(
    mask: usize,
    candidates: &[CandidateRule],
    match_masks: &CandidateMatchMasks,
) -> ExactSelectionScore {
    let denied_misses = match_masks
        .denied
        .iter()
        .filter(|row_mask| (**row_mask & mask) == 0)
        .count();
    let allowed_hits = match_masks
        .allowed
        .iter()
        .filter(|row_mask| (**row_mask & mask) != 0)
        .count();
    let (rule_count, complexity_weight, index_weight) = candidates
        .iter()
        .enumerate()
        .filter(|(index, _)| (mask & (1usize << index)) != 0)
        .fold(
            (0usize, 0usize, 0usize),
            |(count, complexity, index_sum), (index, candidate)| {
                (
                    count + 1,
                    complexity + candidate_total_penalty(candidate),
                    index_sum + index + 1,
                )
            },
        );

    ExactSelectionScore {
        total_errors: denied_misses + allowed_hits,
        allowed_hits,
        rule_count,
        complexity_weight,
        index_weight,
    }
}

fn match_expression_for(matches: &[usize]) -> String {
    if matches.is_empty() {
        return "false".to_string();
    }
    if matches.len() == 1 {
        return format!("keep_{}", matches[0]);
    }
    format!(
        "(or {})",
        matches
            .iter()
            .map(|index| format!("keep_{index}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn hit_sum(prefix: &str, count: usize, when_true: bool) -> String {
    solver_sum(
        (0..count)
            .map(|index| {
                if when_true {
                    format!("(ite {prefix}_{index} 1 0)")
                } else {
                    format!("(ite {prefix}_{index} 0 1)")
                }
            })
            .collect(),
    )
}

fn keep_sum(count: usize) -> String {
    solver_sum(
        (0..count)
            .map(|index| format!("(ite keep_{index} 1 0)"))
            .collect(),
    )
}

fn keep_index_sum(count: usize) -> String {
    solver_sum(
        (0..count)
            .map(|index| format!("(ite keep_{index} {} 0)", index + 1))
            .collect(),
    )
}

fn weighted_keep_sum(candidates: &[CandidateRule]) -> String {
    solver_sum(
        candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                format!(
                    "(ite keep_{index} {} 0)",
                    candidate_total_penalty(candidate)
                )
            })
            .collect(),
    )
}

fn solver_sum(terms: Vec<String>) -> String {
    match terms.len() {
        0 => "0".to_string(),
        1 => terms.into_iter().next().expect("single term should exist"),
        _ => format!("(+ {})", terms.join(" ")),
    }
}

fn solve_selected_rule_indexes(
    candidate_count: usize,
    preamble: &str,
    objectives: &[LexObjective],
) -> Result<Vec<usize>> {
    let solver_settings = SolverSettings::from_env()?;
    let result = solve_keep_bools_lexicographic(
        preamble,
        objectives,
        "keep",
        candidate_count,
        &solver_settings,
    )
    .map_err(|err| {
        LogicPearlError::message(format!("exact rule selection solver failed: {err}"))
    })?;
    match result.status {
        SatStatus::Sat => Ok(result.selected),
        SatStatus::Unsat => Ok(Vec::new()),
        SatStatus::Unknown => Err(LogicPearlError::message(format!(
            "{} returned unknown while solving exact rule selection",
            result.report.backend_used.as_str()
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSelectionObjective {
    TotalErrors,
    AllowedHits,
    KeepCount,
    ComplexityWeight,
    KeepIndexSum,
}

fn solve_selected_rule_indexes_mip(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> Result<Vec<usize>> {
    let mut locked = Vec::new();
    let mut selected = Vec::new();
    for objective in [
        RuleSelectionObjective::TotalErrors,
        RuleSelectionObjective::AllowedHits,
        RuleSelectionObjective::KeepCount,
        RuleSelectionObjective::ComplexityWeight,
        RuleSelectionObjective::KeepIndexSum,
    ] {
        let stage = solve_selected_rule_indexes_mip_stage(
            candidates,
            denied_matches,
            allowed_matches,
            objective,
            &locked,
        )?;
        let objective_value = rule_selection_objective_value(
            objective,
            &stage,
            candidates,
            denied_matches,
            allowed_matches,
        );
        selected = stage;
        locked.push((objective, objective_value));
    }
    Ok(selected)
}

fn solve_selected_rule_indexes_mip_stage(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    objective: RuleSelectionObjective,
    locked: &[(RuleSelectionObjective, usize)],
) -> Result<Vec<usize>> {
    let mut vars = variables!();
    let keep_vars: Vec<Variable> = (0..candidates.len())
        .map(|_| vars.add(variable().binary()))
        .collect();
    let deny_hit_vars: Vec<Variable> = denied_matches
        .iter()
        .map(|_| vars.add(variable().binary()))
        .collect();
    let allow_hit_vars: Vec<Variable> = allowed_matches
        .iter()
        .map(|_| vars.add(variable().binary()))
        .collect();

    let mut model = vars
        .minimise(rule_selection_objective_expression(
            objective,
            &keep_vars,
            &deny_hit_vars,
            &allow_hit_vars,
            candidates,
            denied_matches.len(),
        ))
        .using(microlp);
    model = add_rule_selection_constraints(
        model,
        &keep_vars,
        &deny_hit_vars,
        &allow_hit_vars,
        denied_matches,
        allowed_matches,
    );

    for (locked_objective, value) in locked {
        model = model.with(constraint!(
            rule_selection_objective_expression(
                *locked_objective,
                &keep_vars,
                &deny_hit_vars,
                &allow_hit_vars,
                candidates,
                denied_matches.len(),
            ) == *value as f64
        ));
    }

    let solution = match model.solve() {
        Ok(solution) => solution,
        Err(ResolutionError::Infeasible) => return Ok(Vec::new()),
        Err(ResolutionError::Unbounded) => {
            return Err(LogicPearlError::message(
                "discovery exact rule selection MIP solve was unexpectedly unbounded",
            ));
        }
        Err(err) => {
            return Err(LogicPearlError::message(format!(
                "exact rule selection MIP solver failed: {err}"
            )));
        }
    };

    Ok(selected_keep_indexes(&solution, &keep_vars))
}

fn add_rule_selection_constraints<M: SolverModel>(
    mut model: M,
    keep_vars: &[Variable],
    deny_hit_vars: &[Variable],
    allow_hit_vars: &[Variable],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> M {
    for (index, matches) in denied_matches.iter().enumerate() {
        model = add_match_indicator_constraints(model, deny_hit_vars[index], keep_vars, matches);
    }
    for (index, matches) in allowed_matches.iter().enumerate() {
        model = add_match_indicator_constraints(model, allow_hit_vars[index], keep_vars, matches);
    }
    model
}

fn add_match_indicator_constraints<M: SolverModel>(
    mut model: M,
    indicator: Variable,
    keep_vars: &[Variable],
    matches: &[usize],
) -> M {
    if matches.is_empty() {
        return model.with(constraint!(indicator == 0.0));
    }

    model = model.with(constraint!(indicator <= sum_keep_vars(keep_vars, matches)));
    for matched in matches {
        model = model.with(constraint!(indicator >= keep_vars[*matched]));
    }
    model
}

fn rule_selection_objective_expression(
    objective: RuleSelectionObjective,
    keep_vars: &[Variable],
    deny_hit_vars: &[Variable],
    allow_hit_vars: &[Variable],
    candidates: &[CandidateRule],
    denied_count: usize,
) -> LpExpression {
    match objective {
        RuleSelectionObjective::TotalErrors => {
            (denied_count as f64) - sum_vars(deny_hit_vars) + sum_vars(allow_hit_vars)
        }
        RuleSelectionObjective::AllowedHits => sum_vars(allow_hit_vars),
        RuleSelectionObjective::KeepCount => sum_vars(keep_vars),
        RuleSelectionObjective::ComplexityWeight => keep_vars.iter().zip(candidates.iter()).fold(
            LpExpression::from(0.0),
            |expression, (variable, candidate)| {
                expression + (candidate_total_penalty(candidate) as f64) * *variable
            },
        ),
        RuleSelectionObjective::KeepIndexSum => keep_vars
            .iter()
            .enumerate()
            .fold(LpExpression::from(0.0), |expression, (index, variable)| {
                expression + ((index + 1) as f64) * *variable
            }),
    }
}

fn rule_selection_objective_value(
    objective: RuleSelectionObjective,
    selected: &[usize],
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> usize {
    match objective {
        RuleSelectionObjective::TotalErrors => {
            let denied_misses = denied_matches
                .iter()
                .filter(|matches| !matches.iter().any(|index| selected.contains(index)))
                .count();
            let allowed_hits = allowed_matches
                .iter()
                .filter(|matches| matches.iter().any(|index| selected.contains(index)))
                .count();
            denied_misses + allowed_hits
        }
        RuleSelectionObjective::AllowedHits => allowed_matches
            .iter()
            .filter(|matches| matches.iter().any(|index| selected.contains(index)))
            .count(),
        RuleSelectionObjective::KeepCount => selected.len(),
        RuleSelectionObjective::ComplexityWeight => selected
            .iter()
            .map(|index| candidate_total_penalty(&candidates[*index]))
            .sum(),
        RuleSelectionObjective::KeepIndexSum => selected.iter().map(|index| index + 1).sum(),
    }
}

fn sum_keep_vars(keep_vars: &[Variable], matches: &[usize]) -> LpExpression {
    matches
        .iter()
        .fold(LpExpression::from(0.0), |expression, matched| {
            expression + keep_vars[*matched]
        })
}

fn sum_vars(vars: &[Variable]) -> LpExpression {
    vars.iter()
        .fold(LpExpression::from(0.0), |expression, variable| {
            expression + *variable
        })
}

fn selected_keep_indexes<S: Solution>(solution: &S, keep_vars: &[Variable]) -> Vec<usize> {
    keep_vars
        .iter()
        .enumerate()
        .filter_map(|(index, variable)| (solution.value(*variable) >= 0.5).then_some(index))
        .collect()
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

pub(super) fn discover_residual_rules(
    rows: &[DecisionTraceRow],
    gate: &LogicPearlGateIr,
    feature_semantics: &BTreeMap<String, logicpearl_ir::FeatureSemantics>,
    options: &ResidualPassOptions,
) -> Result<Vec<RuleDefinition>> {
    let binary_features = infer_binary_feature_names(rows);
    if binary_features.is_empty() {
        return Ok(Vec::new());
    }

    let mut examples = Vec::new();
    for row in rows {
        let predicted_deny = !evaluate_gate(gate, &row.features)?.is_zero();
        if !row.allowed && !predicted_deny {
            examples.push(BooleanSearchExample {
                features: boolean_feature_map(&row.features, &binary_features),
                positive: true,
            });
        } else if row.allowed {
            examples.push(BooleanSearchExample {
                features: boolean_feature_map(&row.features, &binary_features),
                positive: false,
            });
        }
    }

    if examples.iter().filter(|example| example.positive).count() < options.min_positive_support {
        return Ok(Vec::new());
    }

    let candidates = synthesize_boolean_conjunctions(
        &examples,
        &BooleanConjunctionSearchOptions {
            min_conditions: 1,
            max_conditions: options.max_conditions,
            min_positive_support: options.min_positive_support,
            max_negative_hits: options.max_negative_hits,
            max_rules: options.max_rules,
        },
    )?;

    Ok(candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            residual_rule_from_candidate(
                gate.rules.len() as u32 + index as u32,
                candidate,
                &RuleTextContext::with_feature_semantics(feature_semantics),
            )
        })
        .collect())
}

pub(super) fn refine_rules_unique_coverage(
    rows: &[DecisionTraceRow],
    rules: &[RuleDefinition],
    options: &UniqueCoverageRefinementOptions,
) -> Result<(Vec<RuleDefinition>, usize)> {
    let binary_features = infer_binary_feature_names(rows);
    if binary_features.is_empty() || rules.is_empty() {
        return Ok((rules.to_vec(), 0));
    }

    let mut refined = Vec::with_capacity(rules.len());
    let mut refined_rules_applied = 0usize;

    for (rule_index, rule) in rules.iter().enumerate() {
        let mut unique_positive_rows = Vec::new();
        let mut unique_negative_rows = Vec::new();

        for row in rows {
            if !expression_matches(&rule.deny_when, &row.features) {
                continue;
            }
            let matched_by_other = rules.iter().enumerate().any(|(other_index, other)| {
                other_index != rule_index && expression_matches(&other.deny_when, &row.features)
            });
            if matched_by_other {
                continue;
            }
            if row.allowed {
                unique_negative_rows.push(row);
            } else {
                unique_positive_rows.push(row);
            }
        }

        if unique_negative_rows.len() < options.min_unique_false_positives
            || unique_positive_rows.is_empty()
        {
            refined.push(rule.clone());
            continue;
        }

        let current_negative_hits = unique_negative_rows.len();
        let current_positive_hits = unique_positive_rows.len();
        let mut best_addition: Option<(ComparisonExpression, usize, usize)> = None;

        for feature in &binary_features {
            if rule_contains_feature(rule, feature) {
                continue;
            }
            for op in [ComparisonOperator::Gt, ComparisonOperator::Lte] {
                let candidate = ComparisonExpression {
                    feature: feature.clone(),
                    op: op.clone(),
                    value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                };
                let positive_hits = unique_positive_rows
                    .iter()
                    .filter(|row| comparison_matches(&candidate, &row.features))
                    .count();
                if positive_hits == 0 {
                    continue;
                }
                let retained = positive_hits as f64 / current_positive_hits as f64;
                if retained < options.min_true_positive_retention {
                    continue;
                }
                let negative_hits = unique_negative_rows
                    .iter()
                    .filter(|row| comparison_matches(&candidate, &row.features))
                    .count();
                if negative_hits >= current_negative_hits {
                    continue;
                }

                let better = match &best_addition {
                    None => true,
                    Some((_best, best_positive_hits, best_negative_hits)) => {
                        let candidate_reduction =
                            current_negative_hits.saturating_sub(negative_hits);
                        let best_reduction =
                            current_negative_hits.saturating_sub(*best_negative_hits);
                        match candidate_reduction.cmp(&best_reduction) {
                            Ordering::Greater => true,
                            Ordering::Less => false,
                            Ordering::Equal => match positive_hits.cmp(best_positive_hits) {
                                Ordering::Greater => true,
                                Ordering::Less => false,
                                Ordering::Equal => negative_hits < *best_negative_hits,
                            },
                        }
                    }
                };
                if better {
                    best_addition = Some((candidate, positive_hits, negative_hits));
                }
            }
        }

        if let Some((addition, _positive_hits, _negative_hits)) = best_addition {
            refined.push(rule_with_added_condition(rule, addition));
            refined_rules_applied += 1;
        } else {
            refined.push(rule.clone());
        }
    }

    Ok((refined, refined_rules_applied))
}

fn candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
) -> Vec<CandidateRule> {
    let mut candidates = atomic_candidate_rules(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
    );
    candidates.retain(|candidate| candidate.denied_coverage > 0);
    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    if let Some(options) = residual_options {
        candidates.extend(conjunction_candidate_rules(
            rows,
            denied_indices,
            allowed_indices,
            &candidates,
            options,
        ));
    }

    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    candidates
}

fn atomic_candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
) -> Vec<CandidateRule> {
    let feature_names = sorted_feature_names(rows);
    let numeric_features = numeric_feature_names(rows)
        .into_iter()
        .filter(|feature| feature_has_nontrivial_numeric_range(rows, feature))
        .collect::<Vec<_>>();
    let feature_ref_numeric_features = numeric_features
        .iter()
        .filter(|feature| !is_derived_feature_name(feature))
        .cloned()
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();

    for feature in feature_names {
        let values: Vec<&Value> = rows
            .iter()
            .filter_map(|row| row.features.get(&feature))
            .collect();
        if values.iter().all(|value| value.is_number()) {
            let unique_thresholds = numeric_thresholds(rows, denied_indices, &feature);
            let allow_numeric_eq = numeric_feature_supports_exact_match(rows, &feature);
            let min_numeric_eq_support = numeric_eq_min_support(denied_indices.len());
            for threshold in unique_thresholds {
                for op in [
                    ComparisonOperator::Lt,
                    ComparisonOperator::Lte,
                    ComparisonOperator::Eq,
                    ComparisonOperator::Gte,
                    ComparisonOperator::Gt,
                ] {
                    let comparison = ComparisonExpression {
                        feature: feature.clone(),
                        op: op.clone(),
                        value: ComparisonValue::Literal(Value::Number(
                            Number::from_f64(threshold).unwrap(),
                        )),
                    };
                    let candidate = candidate_from_expression(
                        rows,
                        denied_indices,
                        allowed_indices,
                        Expression::Comparison(comparison.clone()),
                    );
                    if comparison.op == ComparisonOperator::Eq
                        && comparison.value.literal().and_then(Value::as_f64).is_some()
                        && (!allow_numeric_eq || candidate.denied_coverage < min_numeric_eq_support)
                    {
                        continue;
                    }
                    if candidate_allowed_for_mode(&candidate, decision_mode) {
                        candidates.push(candidate);
                    }
                }
            }
        } else if values.iter().all(|value| value.is_boolean()) {
            let unique_values: BTreeSet<bool> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(Value::as_bool)
                .collect();
            for boolean in unique_values {
                if !boolean_candidate_allowed(feature_governance.get(&feature), boolean) {
                    continue;
                }
                let candidate = candidate_from_expression(
                    rows,
                    denied_indices,
                    allowed_indices,
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::Bool(boolean)),
                    }),
                );
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
            }
        } else {
            let unique_values: BTreeSet<String> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect();
            for text in unique_values {
                let candidate = candidate_from_expression(
                    rows,
                    denied_indices,
                    allowed_indices,
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::String(text.clone())),
                    }),
                );
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
            }
        }
    }

    for left in &feature_ref_numeric_features {
        for right in &feature_ref_numeric_features {
            if left == right {
                continue;
            }
            for op in [
                ComparisonOperator::Lt,
                ComparisonOperator::Lte,
                ComparisonOperator::Gt,
                ComparisonOperator::Gte,
            ] {
                let candidate = candidate_from_expression(
                    rows,
                    denied_indices,
                    allowed_indices,
                    Expression::Comparison(ComparisonExpression {
                        feature: left.clone(),
                        op,
                        value: ComparisonValue::FeatureRef {
                            feature_ref: right.clone(),
                        },
                    }),
                );
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
            }
        }
    }

    candidates
}

fn conjunction_candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    atomic_candidates: &[CandidateRule],
    options: &ResidualPassOptions,
) -> Vec<CandidateRule> {
    let mut prioritized_atoms = atomic_candidates
        .iter()
        .filter(|candidate| candidate_as_comparison(candidate).is_some())
        .collect::<Vec<_>>();
    prioritized_atoms.sort_by(|left, right| compare_conjunction_atom_priority(left, right));
    let atomic_comparisons = prioritized_atoms
        .into_iter()
        .take(CONJUNCTION_ATOM_FRONTIER_LIMIT)
        .filter_map(candidate_as_comparison)
        .cloned()
        .collect::<Vec<_>>();
    if atomic_comparisons.len() < 2 {
        return Vec::new();
    }

    let atom_ids = atomic_comparisons
        .iter()
        .enumerate()
        .map(|(index, _)| format!("atom_{index:03}"))
        .collect::<Vec<_>>();
    let examples = denied_indices
        .iter()
        .map(|index| BooleanSearchExample {
            features: conjunction_example_features(
                &rows[*index].features,
                &atom_ids,
                &atomic_comparisons,
            ),
            positive: true,
        })
        .chain(allowed_indices.iter().map(|index| BooleanSearchExample {
            features: conjunction_example_features(
                &rows[*index].features,
                &atom_ids,
                &atomic_comparisons,
            ),
            positive: false,
        }))
        .collect::<Vec<_>>();

    let conjunctions = match synthesize_boolean_conjunctions(
        &examples,
        &BooleanConjunctionSearchOptions {
            min_conditions: 2,
            max_conditions: options.max_conditions,
            min_positive_support: options.min_positive_support,
            max_negative_hits: options.max_negative_hits,
            max_rules: options.max_rules,
        },
    ) {
        Ok(conjunctions) => conjunctions,
        Err(err) => {
            #[cfg(not(test))]
            let _ = &err;
            #[cfg(test)]
            eprintln!("conjunction synthesis failed: {err}");
            return Vec::new();
        }
    };

    let atom_lookup = atom_ids
        .iter()
        .cloned()
        .zip(atomic_comparisons.iter().cloned())
        .collect::<BTreeMap<_, _>>();
    conjunctions
        .into_iter()
        .filter_map(|candidate| {
            let comparisons = candidate
                .required_true_features
                .iter()
                .filter_map(|atom_id| atom_lookup.get(atom_id).cloned())
                .collect::<Vec<_>>();
            if comparisons.is_empty() {
                return None;
            }
            Some(candidate_from_expression(
                rows,
                denied_indices,
                allowed_indices,
                conjunction_expression(comparisons),
            ))
        })
        .collect()
}

fn compare_conjunction_atom_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
    left.false_positives
        .cmp(&right.false_positives)
        .then_with(|| right.denied_coverage.cmp(&left.denied_coverage))
        .then_with(|| {
            candidate_complexity_penalty(left, DiscoveryDecisionMode::Standard).cmp(
                &candidate_complexity_penalty(right, DiscoveryDecisionMode::Standard),
            )
        })
        .then_with(|| left.signature().cmp(right.signature()))
}

fn conjunction_example_features(
    row_features: &HashMap<String, Value>,
    atom_ids: &[String],
    comparisons: &[ComparisonExpression],
) -> BTreeMap<String, bool> {
    atom_ids
        .iter()
        .cloned()
        .zip(
            comparisons
                .iter()
                .map(|comparison| comparison_matches(comparison, row_features)),
        )
        .collect()
}

fn comparison_sort_key(c: &ComparisonExpression) -> (String, String, String) {
    (
        c.feature.clone(),
        format!("{:?}", c.op),
        serde_json::to_string(&c.value).unwrap_or_default(),
    )
}

fn conjunction_expression(mut comparisons: Vec<ComparisonExpression>) -> Expression {
    comparisons.sort_by_key(comparison_sort_key);
    if comparisons.len() == 1 {
        return Expression::Comparison(comparisons.pop().expect("single comparison"));
    }
    Expression::All {
        all: comparisons
            .into_iter()
            .map(Expression::Comparison)
            .collect(),
    }
}

fn candidate_from_expression(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    expression: Expression,
) -> CandidateRule {
    let denied_coverage = candidate_coverage(rows, denied_indices, &expression);
    let false_positives = candidate_coverage(rows, allowed_indices, &expression);
    CandidateRule::new(expression, denied_coverage, false_positives)
}

fn candidate_as_comparison(candidate: &CandidateRule) -> Option<&ComparisonExpression> {
    match &candidate.expression {
        Expression::Comparison(comparison) => Some(comparison),
        _ => None,
    }
}

fn candidate_is_compound(candidate: &CandidateRule) -> bool {
    !matches!(candidate.expression, Expression::Comparison(_))
}

fn boolean_candidate_allowed(governance: Option<&FeatureGovernance>, value: bool) -> bool {
    match governance.and_then(|governance| governance.deny_boolean_evidence.as_ref()) {
        None | Some(BooleanEvidencePolicy::Either) => true,
        Some(BooleanEvidencePolicy::TrueOnly) => value,
        Some(BooleanEvidencePolicy::FalseOnly) => !value,
        Some(BooleanEvidencePolicy::Never) => false,
    }
}

fn best_immediate_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
) -> Option<CandidateRule> {
    candidate_rules(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
        residual_options,
    )
    .into_iter()
    .next()
}

fn compare_candidate_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
    let left_net = left.denied_coverage as isize - left.false_positives as isize;
    let right_net = right.denied_coverage as isize - right.false_positives as isize;
    right_net
        .cmp(&left_net)
        .then_with(|| left.false_positives.cmp(&right.false_positives))
        .then_with(|| right.denied_coverage.cmp(&left.denied_coverage))
        .then_with(|| {
            candidate_complexity_penalty(left, DiscoveryDecisionMode::Standard).cmp(
                &candidate_complexity_penalty(right, DiscoveryDecisionMode::Standard),
            )
        })
        .then_with(|| {
            candidate_memorization_penalty(left).cmp(&candidate_memorization_penalty(right))
        })
        .then_with(|| left.signature().cmp(right.signature()))
}

fn candidate_complexity_penalty(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> usize {
    expression_complexity_penalty(&candidate.expression, decision_mode)
}

fn candidate_allowed_for_mode(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> bool {
    expression_allowed_for_mode(&candidate.expression, decision_mode)
}

fn candidate_memorization_penalty(candidate: &CandidateRule) -> usize {
    expression_memorization_penalty(&candidate.expression, candidate.denied_coverage)
}

fn expression_complexity_penalty(
    expression: &Expression,
    decision_mode: DiscoveryDecisionMode,
) -> usize {
    match expression {
        Expression::Comparison(comparison) => {
            if decision_mode == DiscoveryDecisionMode::Review
                && comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64).is_some()
            {
                return usize::MAX / 4;
            }
            match &comparison.value {
                ComparisonValue::Literal(value)
                    if comparison.op == ComparisonOperator::Eq && value.as_f64().is_some() =>
                {
                    3
                }
                ComparisonValue::FeatureRef { .. } => 1,
                ComparisonValue::Literal(_) if is_derived_feature_name(&comparison.feature) => 2,
                ComparisonValue::Literal(_) => 0,
            }
        }
        Expression::All { all } => {
            all.iter()
                .map(|child| expression_complexity_penalty(child, decision_mode))
                .sum::<usize>()
                + all.len().saturating_sub(1)
        }
        Expression::Any { any } => {
            any.iter()
                .map(|child| expression_complexity_penalty(child, decision_mode))
                .sum::<usize>()
                + any.len().saturating_sub(1)
        }
        Expression::Not { expr } => expression_complexity_penalty(expr, decision_mode) + 1,
    }
}

fn expression_allowed_for_mode(
    expression: &Expression,
    decision_mode: DiscoveryDecisionMode,
) -> bool {
    match expression {
        Expression::Comparison(comparison) => {
            !(decision_mode == DiscoveryDecisionMode::Review
                && comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64).is_some())
        }
        Expression::All { all } => all
            .iter()
            .all(|child| expression_allowed_for_mode(child, decision_mode)),
        Expression::Any { any } => any
            .iter()
            .all(|child| expression_allowed_for_mode(child, decision_mode)),
        Expression::Not { expr } => expression_allowed_for_mode(expr, decision_mode),
    }
}

fn expression_memorization_penalty(expression: &Expression, denied_coverage: usize) -> usize {
    match expression {
        Expression::Comparison(comparison)
            if comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64).is_some() =>
        {
            1_000_000usize.saturating_sub(denied_coverage)
        }
        Expression::Comparison(_) => 0,
        Expression::All { all } => all
            .iter()
            .map(|child| expression_memorization_penalty(child, denied_coverage))
            .sum(),
        Expression::Any { any } => any
            .iter()
            .map(|child| expression_memorization_penalty(child, denied_coverage))
            .sum(),
        Expression::Not { expr } => expression_memorization_penalty(expr, denied_coverage),
    }
}

fn numeric_thresholds(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    feature: &str,
) -> Vec<f64> {
    let mut thresholds: BTreeSet<i64> = BTreeSet::new();
    for index in denied_indices {
        if let Some(value) = rows[*index].features.get(feature).and_then(Value::as_f64) {
            thresholds.insert((value * 1000.0).round() as i64);
        }
    }
    thresholds
        .into_iter()
        .map(|scaled| scaled as f64 / 1000.0)
        .collect()
}

fn numeric_feature_supports_exact_match(rows: &[DecisionTraceRow], feature: &str) -> bool {
    numeric_feature_distinct_value_count(rows, feature) <= NUMERIC_EQ_MAX_DISTINCT_VALUES
}

fn numeric_feature_distinct_value_count(rows: &[DecisionTraceRow], feature: &str) -> usize {
    let mut distinct_values: BTreeSet<i64> = BTreeSet::new();
    for value in rows
        .iter()
        .filter_map(|row| row.features.get(feature))
        .filter_map(Value::as_f64)
    {
        distinct_values.insert((value * 1000.0).round() as i64);
    }
    distinct_values.len()
}

fn numeric_eq_min_support(denied_count: usize) -> usize {
    let proportional = denied_count
        .saturating_mul(NUMERIC_EQ_MIN_SUPPORT_BASIS_POINTS)
        .div_ceil(10_000);
    NUMERIC_EQ_MIN_SUPPORT_ABSOLUTE.max(proportional)
}

fn feature_has_nontrivial_numeric_range(rows: &[DecisionTraceRow], feature: &str) -> bool {
    numeric_feature_distinct_value_count(rows, feature) > 2
}

fn candidate_coverage(
    rows: &[DecisionTraceRow],
    indices: &[usize],
    expression: &Expression,
) -> usize {
    indices
        .iter()
        .filter(|index| expression_matches(expression, &rows[**index].features))
        .count()
}

#[cfg(test)]
pub(super) fn rule_from_candidate(bit: u32, candidate: &CandidateRule) -> RuleDefinition {
    rule_from_candidate_with_context(bit, candidate, &RuleTextContext::empty())
}

fn rule_from_candidate_with_context(
    bit: u32,
    candidate: &CandidateRule,
    context: &RuleTextContext<'_>,
) -> RuleDefinition {
    let deny_when = candidate.expression.clone();
    let generated = generate_rule_text(&deny_when, context);
    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: generated.label,
        message: generated.message,
        severity: None,
        counterfactual_hint: generated.counterfactual_hint,
        verification_status: Some(RuleVerificationStatus::PipelineUnverified),
    }
}

fn residual_rule_from_candidate(
    bit: u32,
    candidate: BooleanConjunctionCandidate,
    context: &RuleTextContext<'_>,
) -> RuleDefinition {
    let deny_when = if candidate.required_true_features.len() == 1 {
        Expression::Comparison(ComparisonExpression {
            feature: candidate.required_true_features[0].clone(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
        })
    } else {
        Expression::All {
            all: candidate
                .required_true_features
                .iter()
                .map(|feature| {
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Gt,
                        value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    })
                })
                .collect(),
        }
    };

    let generated = generate_rule_text(&deny_when, context);
    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: generated.label,
        message: generated.message,
        severity: None,
        counterfactual_hint: generated.counterfactual_hint,
        verification_status: Some(RuleVerificationStatus::RefinedUnverified),
    }
}

fn matches_candidate(features: &HashMap<String, Value>, candidate: &CandidateRule) -> bool {
    expression_matches(&candidate.expression, features)
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_allowed_for_mode, candidate_as_comparison, candidate_complexity_penalty,
        candidate_rules, compare_candidate_set_score, conjunction_candidate_rules,
        recover_rare_rules, rule_from_candidate, score_candidate_set, select_candidate_rules_exact,
        CandidateRule, CandidateSelectionContext, CandidateSetScore,
        DISCOVERY_SELECTION_BACKEND_ENV,
    };
    use crate::{
        discovery_selection_env_lock, DecisionTraceRow, DiscoveryDecisionMode, ResidualPassOptions,
    };
    use logicpearl_ir::{ComparisonExpression, ComparisonOperator, ComparisonValue, Expression};
    use logicpearl_solver::{check_sat, SolverSettings};
    use serde_json::{Number, Value};
    use std::collections::{BTreeMap, HashMap};

    fn solver_available() -> bool {
        check_sat("(check-sat)\n", &SolverSettings::default()).is_ok()
    }

    fn with_discovery_selection_backend<T>(backend: &str, test: impl FnOnce() -> T) -> T {
        let _guard = discovery_selection_env_lock()
            .lock()
            .expect("env lock should be available");
        let saved = std::env::var(DISCOVERY_SELECTION_BACKEND_ENV).ok();
        std::env::set_var(DISCOVERY_SELECTION_BACKEND_ENV, backend);
        let result = test();
        match saved {
            Some(value) => std::env::set_var(DISCOVERY_SELECTION_BACKEND_ENV, value),
            None => std::env::remove_var(DISCOVERY_SELECTION_BACKEND_ENV),
        }
        result
    }

    #[test]
    fn exact_selection_prefers_minimal_general_rule_over_equal_singletons() {
        if !solver_available() {
            return;
        }

        let rows = vec![
            row(1.0, false),
            row(2.0, false),
            row(3.0, true),
            row(4.0, true),
        ];
        let denied_indices = vec![0usize, 1usize];
        let allowed_indices = vec![2usize, 3usize];
        let candidates = vec![
            numeric_candidate("score", ComparisonOperator::Eq, 1.0),
            numeric_candidate("score", ComparisonOperator::Eq, 2.0),
            numeric_candidate("score", ComparisonOperator::Lte, 2.0),
        ];

        let selected =
            select_candidate_rules_exact(&rows, &denied_indices, &allowed_indices, &candidates)
                .unwrap()
                .0
                .unwrap();
        assert_eq!(selected.len(), 1);
        let comparison = candidate_as_comparison(&selected[0]).unwrap();
        assert_eq!(comparison.op, ComparisonOperator::Lte);
        assert_eq!(
            comparison.value.literal().and_then(Value::as_f64),
            Some(2.0)
        );
    }

    #[test]
    fn mip_exact_selection_matches_smt_choice_beyond_bruteforce_limit() {
        if !solver_available() {
            return;
        }

        let rows = (1..=18)
            .map(|value| row(value as f64, value == 18))
            .collect::<Vec<_>>();
        let denied_indices = (0..17).collect::<Vec<_>>();
        let allowed_indices = vec![17usize];
        let mut candidates = (1..=17)
            .map(|value| numeric_candidate("score", ComparisonOperator::Eq, value as f64))
            .collect::<Vec<_>>();
        candidates.push(numeric_candidate("score", ComparisonOperator::Lte, 17.0));

        let smt_selection = with_discovery_selection_backend("smt", || {
            select_candidate_rules_exact(&rows, &denied_indices, &allowed_indices, &candidates)
                .expect("smt exact selection should find a solution")
                .0
                .expect("smt exact selection should return a rule set")
        });
        let mip_selection = with_discovery_selection_backend("mip", || {
            select_candidate_rules_exact(&rows, &denied_indices, &allowed_indices, &candidates)
                .expect("mip exact selection should find a solution")
                .0
                .expect("mip exact selection should return a rule set")
        });

        assert_eq!(smt_selection.len(), 1);
        let smt_comparison = candidate_as_comparison(&smt_selection[0]).unwrap();
        assert_eq!(smt_comparison.op, ComparisonOperator::Lte);
        assert_eq!(
            smt_comparison.value.literal().and_then(Value::as_f64),
            Some(17.0)
        );

        assert_eq!(mip_selection.len(), smt_selection.len());
        let mip_comparison = candidate_as_comparison(&mip_selection[0]).unwrap();
        assert_eq!(mip_comparison.op, smt_comparison.op);
        assert_eq!(
            mip_comparison.value.literal().and_then(Value::as_f64),
            smt_comparison.value.literal().and_then(Value::as_f64)
        );
    }

    #[test]
    fn invalid_discovery_selection_backend_is_rejected() {
        let rows = (1..=18)
            .map(|value| row(value as f64, value == 18))
            .collect::<Vec<_>>();
        let denied_indices = (0..17).collect::<Vec<_>>();
        let allowed_indices = vec![17usize];
        let mut candidates = (1..=17)
            .map(|value| numeric_candidate("score", ComparisonOperator::Eq, value as f64))
            .collect::<Vec<_>>();
        candidates.push(numeric_candidate("score", ComparisonOperator::Lte, 17.0));

        let err = with_discovery_selection_backend("not-a-backend", || {
            select_candidate_rules_exact(&rows, &denied_indices, &allowed_indices, &candidates)
                .expect_err("invalid discovery selection backend should fail loudly")
        });

        assert!(
            err.to_string()
                .contains("unsupported discovery selection backend"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn candidate_set_score_prefers_fewer_false_positives_after_equal_total_error() {
        let better = CandidateSetScore {
            total_errors: 2,
            false_positives: 0,
            false_negatives: 2,
            validation_total_errors: 0,
            validation_false_positives: 0,
            validation_false_negatives: 0,
            rule_count: 2,
            complexity_penalty: 0,
        };
        let worse = CandidateSetScore {
            total_errors: 2,
            false_positives: 1,
            false_negatives: 1,
            validation_total_errors: 0,
            validation_false_positives: 0,
            validation_false_negatives: 0,
            rule_count: 1,
            complexity_penalty: 0,
        };
        assert_eq!(
            compare_candidate_set_score(&better, &worse),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn candidate_set_score_counts_selected_set_union_errors() {
        let rows = vec![
            row(1.0, false),
            row(2.0, false),
            row(3.0, true),
            row(4.0, true),
        ];
        let candidate_a = numeric_candidate("score", ComparisonOperator::Eq, 1.0);
        let candidate_b = numeric_candidate("score", ComparisonOperator::Gte, 3.0);
        let score = score_candidate_set(&rows, &[candidate_a, candidate_b], None);
        assert_eq!(score.false_negatives, 1);
        assert_eq!(score.false_positives, 2);
        assert_eq!(score.total_errors, 3);
    }

    #[test]
    fn candidate_rules_skip_feature_refs_for_binary_numeric_features() {
        let rows = vec![
            binary_pair_row(1.0, 0.0, false),
            binary_pair_row(0.0, 1.0, false),
            binary_pair_row(0.0, 0.0, true),
            binary_pair_row(1.0, 1.0, true),
        ];
        let denied_indices = vec![0usize, 1usize];
        let allowed_indices = vec![2usize, 3usize];
        let candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );
        assert!(
            !candidates.iter().any(|candidate| matches!(
                candidate_as_comparison(candidate).map(|comparison| &comparison.value),
                Some(ComparisonValue::FeatureRef { .. })
            )),
            "binary numeric features should not produce feature-ref candidates"
        );
    }

    #[test]
    fn candidate_rules_limit_feature_refs_to_ordered_numeric_comparisons() {
        let rows = vec![
            binary_pair_row(0.0, 2.0, false),
            binary_pair_row(1.0, 3.0, false),
            binary_pair_row(2.0, 1.0, true),
            binary_pair_row(3.0, 0.0, true),
        ];
        let denied_indices = vec![0usize, 1usize];
        let allowed_indices = vec![2usize, 3usize];
        let candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );
        assert!(
            candidates
                .iter()
                .filter(|candidate| matches!(
                    candidate_as_comparison(candidate).map(|comparison| &comparison.value),
                    Some(ComparisonValue::FeatureRef { .. })
                ))
                .all(|candidate| matches!(
                    candidate_as_comparison(candidate).unwrap().op,
                    ComparisonOperator::Lt
                        | ComparisonOperator::Lte
                        | ComparisonOperator::Gt
                        | ComparisonOperator::Gte
                )),
            "feature-ref candidates should stay ordered comparisons"
        );
    }

    #[test]
    fn high_cardinality_numeric_features_skip_exact_match_candidates() {
        let rows = (0..24)
            .map(|value| row(value as f64, value >= 12))
            .collect::<Vec<_>>();
        let denied_indices = (0usize..12usize).collect::<Vec<_>>();
        let allowed_indices = (12usize..24usize).collect::<Vec<_>>();

        let candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );

        assert!(
            !candidates.iter().any(|candidate| {
                let Some(comparison) = candidate_as_comparison(candidate) else {
                    return false;
                };
                comparison.feature == "score" && comparison.op == ComparisonOperator::Eq
            }),
            "continuous/high-cardinality numeric features should not emit exact-match candidates"
        );
    }

    #[test]
    fn low_cardinality_numeric_features_can_still_emit_exact_match_candidates() {
        let rows = vec![
            row(0.0, false),
            row(0.0, false),
            row(0.0, false),
            row(1.0, true),
            row(1.0, true),
            row(1.0, true),
        ];
        let denied_indices = vec![0usize, 1usize, 2usize];
        let allowed_indices = vec![3usize, 4usize, 5usize];

        let candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );

        assert!(
            candidates.iter().any(|candidate| {
                let Some(comparison) = candidate_as_comparison(candidate) else {
                    return false;
                };
                comparison.feature == "score"
                    && comparison.op == ComparisonOperator::Eq
                    && comparison.value.literal().and_then(Value::as_f64) == Some(0.0)
            }),
            "binary/low-cardinality numeric features should still support exact matches"
        );
    }

    #[test]
    fn numeric_exact_match_candidates_require_minimum_support() {
        let rows = vec![
            row(0.0, false),
            row(1.0, false),
            row(2.0, false),
            row(9.0, true),
            row(9.0, true),
            row(9.0, true),
        ];
        let denied_indices = vec![0usize, 1usize, 2usize];
        let allowed_indices = vec![3usize, 4usize, 5usize];

        let candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );

        assert!(
            !candidates.iter().any(|candidate| {
                let Some(comparison) = candidate_as_comparison(candidate) else {
                    return false;
                };
                comparison.feature == "score" && comparison.op == ComparisonOperator::Eq
            }),
            "singleton numeric exact-match candidates should be filtered by support floor"
        );
        assert!(
            candidates.iter().any(|candidate| {
                let Some(comparison) = candidate_as_comparison(candidate) else {
                    return false;
                };
                comparison.feature == "score" && comparison.op == ComparisonOperator::Lte
            }),
            "threshold candidates should remain available"
        );
    }

    #[test]
    fn rare_rule_recovery_adds_uncovered_zero_fp_rule() {
        let rows = vec![
            triad_row(1.0, 0.0, 0.0, false),
            triad_row(2.0, 0.0, 0.0, false),
            triad_row(3.0, 0.0, 0.0, false),
            triad_row(9.0, 1.0, 0.0, false),
            triad_row(3.0, 0.0, 0.0, true),
            triad_row(7.0, 0.0, 0.0, true),
            triad_row(8.0, 0.0, 0.0, true),
        ];
        let denied_indices = vec![0usize, 1usize, 2usize, 3usize];
        let allowed_indices = vec![4usize, 5usize, 6usize];
        let selected = vec![candidate_with_metrics(
            "score",
            ComparisonOperator::Lte,
            ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
            3,
            1,
        )];

        let feature_governance = BTreeMap::new();
        let selection_context = CandidateSelectionContext {
            rows: &rows,
            denied_indices: &denied_indices,
            allowed_indices: &allowed_indices,
            validation_indices: None,
            feature_governance: &feature_governance,
            decision_mode: DiscoveryDecisionMode::Standard,
            residual_options: None,
        };
        let recovered = recover_rare_rules(&selection_context, selected).unwrap();
        assert_eq!(recovered.len(), 2);
        let score = score_candidate_set(&rows, &recovered, None);
        assert_eq!(score.false_negatives, 0);
        assert_eq!(score.false_positives, 1);
    }

    #[test]
    fn rare_rule_recovery_skips_rules_that_only_add_false_positives() {
        let rows = vec![
            triad_row(1.0, 0.0, 0.0, false),
            triad_row(2.0, 0.0, 0.0, false),
            triad_row(3.0, 0.0, 0.0, false),
            triad_row(8.0, 1.0, 1.0, false),
            triad_row(3.0, 0.0, 0.0, true),
            triad_row(8.0, 1.0, 1.0, true),
            triad_row(8.0, 0.0, 0.0, true),
        ];
        let denied_indices = vec![0usize, 1usize, 2usize, 3usize];
        let allowed_indices = vec![4usize, 5usize, 6usize];
        let selected = vec![candidate_with_metrics(
            "score",
            ComparisonOperator::Lte,
            ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
            3,
            1,
        )];

        let feature_governance = BTreeMap::new();
        let selection_context = CandidateSelectionContext {
            rows: &rows,
            denied_indices: &denied_indices,
            allowed_indices: &allowed_indices,
            validation_indices: None,
            feature_governance: &feature_governance,
            decision_mode: DiscoveryDecisionMode::Standard,
            residual_options: None,
        };
        let recovered = recover_rare_rules(&selection_context, selected).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            candidate_as_comparison(&recovered[0]).unwrap().feature,
            "score"
        );
        let score = score_candidate_set(&rows, &recovered, None);
        assert_eq!(score.false_negatives, 1);
        assert_eq!(score.false_positives, 1);
    }

    #[test]
    fn conjunction_candidate_rules_emit_real_multi_condition_rules() {
        if !solver_available() {
            return;
        }

        let rows = vec![
            authz_row(0.0, 1.0, 0.0, 0.0, 1.0, 0.0, true),
            authz_row(0.0, 1.0, 0.0, 0.0, 1.0, 1.0, true),
            authz_row(1.0, 1.0, 0.0, 0.0, 1.0, 0.0, false),
            authz_row(0.0, 0.0, 1.0, 0.0, 1.0, 0.0, false),
            authz_row(0.0, 0.0, 1.0, 0.0, 0.0, 0.0, false),
        ];
        let denied_indices = vec![0usize, 1usize];
        let allowed_indices = vec![2usize, 3usize, 4usize];
        let atomic_candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );

        let compounds = conjunction_candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &atomic_candidates,
            &ResidualPassOptions {
                max_conditions: 3,
                min_positive_support: 2,
                max_negative_hits: 0,
                max_rules: 4,
            },
        );

        assert!(compounds.iter().any(|candidate| {
            matches!(
                &candidate.expression,
                Expression::All { all }
                    if all.iter().any(|expr| matches!(
                        expr,
                        Expression::Comparison(ComparisonExpression { feature, .. })
                            if feature == "action_delete"
                    )) && all.iter().any(|expr| matches!(
                        expr,
                        Expression::Comparison(ComparisonExpression { feature, .. })
                            if feature == "is_admin"
                    ))
            )
        }));
    }

    #[test]
    fn conjunction_candidate_rules_cover_policy_style_dataset() {
        if !solver_available() {
            return;
        }

        let rows = vec![
            policy_style_row(PolicyStyleRowSpec {
                action_delete: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_delete: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                archived: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                archived: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                is_authenticated: 1.0,
                team_match: 1.0,
                is_contractor: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                is_authenticated: 1.0,
                team_match: 1.0,
                is_contractor: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                is_authenticated: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                is_authenticated: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                sensitivity: 2.0,
                team_match: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                sensitivity: 1.0,
                team_match: 1.0,
                denied: true,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: false,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                is_contractor: 1.0,
                denied: false,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                is_admin: 1.0,
                action_delete: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: false,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                is_admin: 1.0,
                action_read: 1.0,
                archived: 1.0,
                is_authenticated: 1.0,
                team_match: 1.0,
                denied: false,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                is_authenticated: 1.0,
                is_public: 1.0,
                denied: false,
                ..Default::default()
            }),
            policy_style_row(PolicyStyleRowSpec {
                action_read: 1.0,
                team_match: 1.0,
                denied: false,
                ..Default::default()
            }),
        ];
        let denied_indices = (0usize..10usize).collect::<Vec<_>>();
        let allowed_indices = (10usize..16usize).collect::<Vec<_>>();
        let atomic_candidates = candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
            None,
        );

        let compounds = conjunction_candidate_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            &atomic_candidates,
            &ResidualPassOptions {
                max_conditions: 3,
                min_positive_support: 2,
                max_negative_hits: 0,
                max_rules: 8,
            },
        );

        let score = score_candidate_set(&rows, &compounds, None);
        assert_eq!(score.total_errors, 0);
    }

    #[test]
    fn candidate_set_score_prefers_better_validation_when_training_is_equal() {
        let better = CandidateSetScore {
            total_errors: 1,
            false_positives: 0,
            false_negatives: 1,
            validation_total_errors: 0,
            validation_false_positives: 0,
            validation_false_negatives: 0,
            rule_count: 2,
            complexity_penalty: 0,
        };
        let worse = CandidateSetScore {
            total_errors: 1,
            false_positives: 0,
            false_negatives: 1,
            validation_total_errors: 1,
            validation_false_positives: 1,
            validation_false_negatives: 0,
            rule_count: 1,
            complexity_penalty: 0,
        };
        assert_eq!(
            compare_candidate_set_score(&better, &worse),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn discovered_rule_gets_generated_label_and_counterfactual() {
        let rule = rule_from_candidate(
            0,
            &candidate_with_metrics(
                "contains_xss_signature",
                ComparisonOperator::Eq,
                ComparisonValue::Literal(Value::Bool(true)),
                3,
                0,
            ),
        );

        assert_eq!(rule.label.as_deref(), Some("XSS Signature Detected"));
        assert_eq!(
            rule.counterfactual_hint.as_deref(),
            Some("Remove XSS Signature")
        );
    }

    #[test]
    fn numeric_exact_match_rules_get_extra_complexity_penalty() {
        let exact = candidate_with_metrics(
            "suspicious_token_count",
            ComparisonOperator::Eq,
            ComparisonValue::Literal(Value::Number(Number::from(1))),
            5,
            0,
        );
        let threshold = candidate_with_metrics(
            "suspicious_token_count",
            ComparisonOperator::Gte,
            ComparisonValue::Literal(Value::Number(Number::from(1))),
            5,
            0,
        );

        assert!(
            candidate_complexity_penalty(&exact, DiscoveryDecisionMode::Standard)
                > candidate_complexity_penalty(&threshold, DiscoveryDecisionMode::Standard)
        );
    }

    #[test]
    fn review_mode_rejects_numeric_exact_matches() {
        let exact = candidate_with_metrics(
            "suspicious_token_count",
            ComparisonOperator::Eq,
            ComparisonValue::Literal(Value::Number(Number::from(13))),
            5,
            0,
        );
        let threshold = candidate_with_metrics(
            "suspicious_token_count",
            ComparisonOperator::Gte,
            ComparisonValue::Literal(Value::Number(Number::from(13))),
            5,
            0,
        );

        assert!(!candidate_allowed_for_mode(
            &exact,
            DiscoveryDecisionMode::Review
        ));
        assert!(candidate_allowed_for_mode(
            &threshold,
            DiscoveryDecisionMode::Review
        ));
    }

    #[test]
    fn review_mode_still_allows_derived_numeric_thresholds() {
        let candidate = candidate_with_metrics(
            "derived__query_key_count__minus__suspicious_token_count",
            ComparisonOperator::Gte,
            ComparisonValue::Literal(Value::Number(Number::from(13))),
            5,
            0,
        );

        assert!(candidate_allowed_for_mode(
            &candidate,
            DiscoveryDecisionMode::Review
        ));
    }

    fn row(score: f64, allowed: bool) -> DecisionTraceRow {
        let mut features = HashMap::new();
        features.insert(
            "score".to_string(),
            Value::Number(Number::from_f64(score).unwrap()),
        );
        DecisionTraceRow { features, allowed }
    }

    fn numeric_candidate(feature: &str, op: ComparisonOperator, value: f64) -> CandidateRule {
        CandidateRule::new(
            Expression::Comparison(ComparisonExpression {
                feature: feature.to_string(),
                op,
                value: ComparisonValue::Literal(Value::Number(Number::from_f64(value).unwrap())),
            }),
            0,
            0,
        )
    }

    fn candidate_with_metrics(
        feature: &str,
        op: ComparisonOperator,
        value: ComparisonValue,
        denied_coverage: usize,
        false_positives: usize,
    ) -> CandidateRule {
        CandidateRule::new(
            Expression::Comparison(ComparisonExpression {
                feature: feature.to_string(),
                op,
                value,
            }),
            denied_coverage,
            false_positives,
        )
    }

    fn binary_pair_row(left: f64, right: f64, allowed: bool) -> DecisionTraceRow {
        let mut features = HashMap::new();
        features.insert(
            "left".to_string(),
            Value::Number(Number::from_f64(left).unwrap()),
        );
        features.insert(
            "right".to_string(),
            Value::Number(Number::from_f64(right).unwrap()),
        );
        DecisionTraceRow { features, allowed }
    }

    fn triad_row(score: f64, rare_flag: f64, noisy_flag: f64, allowed: bool) -> DecisionTraceRow {
        let mut features = HashMap::new();
        features.insert(
            "score".to_string(),
            Value::Number(Number::from_f64(score).unwrap()),
        );
        features.insert(
            "rare_flag".to_string(),
            Value::Number(Number::from_f64(rare_flag).unwrap()),
        );
        features.insert(
            "noisy_flag".to_string(),
            Value::Number(Number::from_f64(noisy_flag).unwrap()),
        );
        DecisionTraceRow { features, allowed }
    }

    fn authz_row(
        is_admin: f64,
        action_delete: f64,
        action_read: f64,
        is_contractor: f64,
        is_authenticated: f64,
        sensitivity: f64,
        denied: bool,
    ) -> DecisionTraceRow {
        let mut features = HashMap::new();
        features.insert("is_admin".to_string(), Value::from(is_admin));
        features.insert("action_delete".to_string(), Value::from(action_delete));
        features.insert("action_read".to_string(), Value::from(action_read));
        features.insert("is_contractor".to_string(), Value::from(is_contractor));
        features.insert(
            "is_authenticated".to_string(),
            Value::from(is_authenticated),
        );
        features.insert("sensitivity".to_string(), Value::from(sensitivity));
        DecisionTraceRow {
            features,
            allowed: !denied,
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct PolicyStyleRowSpec {
        is_admin: f64,
        action_delete: f64,
        action_read: f64,
        archived: f64,
        is_authenticated: f64,
        sensitivity: f64,
        team_match: f64,
        is_public: f64,
        is_contractor: f64,
        denied: bool,
    }

    fn policy_style_row(spec: PolicyStyleRowSpec) -> DecisionTraceRow {
        let mut features = HashMap::new();
        features.insert("is_admin".to_string(), Value::from(spec.is_admin));
        features.insert("action_delete".to_string(), Value::from(spec.action_delete));
        features.insert("action_read".to_string(), Value::from(spec.action_read));
        features.insert("archived".to_string(), Value::from(spec.archived));
        features.insert(
            "is_authenticated".to_string(),
            Value::from(spec.is_authenticated),
        );
        features.insert("sensitivity".to_string(), Value::from(spec.sensitivity));
        features.insert("team_match".to_string(), Value::from(spec.team_match));
        features.insert("is_public".to_string(), Value::from(spec.is_public));
        features.insert("is_contractor".to_string(), Value::from(spec.is_contractor));
        DecisionTraceRow {
            features,
            allowed: !spec.denied,
        }
    }
}
