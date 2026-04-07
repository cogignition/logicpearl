use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    BooleanEvidencePolicy, ComparisonExpression, ComparisonOperator, ComparisonValue,
    EvaluationConfig, Expression, FeatureDefinition, FeatureGovernance, InputSchema,
    LogicPearlGateIr, Provenance, RuleDefinition, RuleKind, RuleVerificationStatus,
    VerificationConfig,
};
use logicpearl_runtime::evaluate_gate;
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionCandidate, BooleanConjunctionSearchOptions,
    BooleanSearchExample,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::process::Command;

use super::canonicalize::{
    canonicalize_rules, comparison_matches, expression_matches, prune_redundant_rules,
};
use super::features::{
    boolean_feature_map, infer_binary_feature_names, infer_feature_type, is_derived_feature_name,
    numeric_feature_names, rule_contains_feature, rule_with_added_condition, sorted_feature_names,
};
use super::rule_text::generate_rule_text;
use super::{
    CandidateRule, DecisionTraceRow, DiscoveryDecisionMode, PinnedRuleSet, ResidualPassOptions,
    UniqueCoverageRefinementOptions,
};

const LOOKAHEAD_FRONTIER_LIMIT: usize = 12;
const EXACT_SELECTION_FRONTIER_LIMIT: usize = 48;
const RARE_RULE_RECOVERY_FRONTIER_LIMIT: usize = 24;
const RARE_RULE_RECOVERY_MAX_PASSES: usize = 3;
const DISCOVERY_VALIDATION_MIN_CLASS_ROWS: usize = 20;
const DISCOVERY_VALIDATION_FRACTION_NUMERATOR: usize = 1;
const DISCOVERY_VALIDATION_FRACTION_DENOMINATOR: usize = 5;

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

#[allow(clippy::too_many_arguments)]
pub(super) fn build_gate(
    rows: &[DecisionTraceRow],
    source_rows: &[DecisionTraceRow],
    derived_features: &[FeatureDefinition],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    gate_id: &str,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
    refinement_options: Option<&UniqueCoverageRefinementOptions>,
    pinned_rules: Option<&PinnedRuleSet>,
) -> Result<(LogicPearlGateIr, usize, usize, usize)> {
    let mut rules = discover_rules(rows, feature_governance, decision_mode)?;
    let mut residual_rules_discovered = 0usize;
    if let Some(options) = residual_options {
        let first_pass_gate = gate_from_rules(
            rows,
            source_rows,
            derived_features,
            feature_governance,
            gate_id,
            rules.clone(),
        )?;
        match discover_residual_rules(rows, &first_pass_gate, options) {
            Ok(residual_rules) => {
                residual_rules_discovered = residual_rules.len();
                rules.extend(residual_rules);
            }
            Err(err) => {
                let message = err.to_string();
                if !message.contains("boolean conjunction synthesis")
                    && !message.contains("failed to launch z3")
                {
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
            gate_id,
            rules,
        )?,
        residual_rules_discovered,
        refined_rules_applied,
        pinned_rules_applied,
    ))
}

pub(super) fn gate_from_rules(
    rows: &[DecisionTraceRow],
    source_rows: &[DecisionTraceRow],
    derived_features: &[FeatureDefinition],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
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
            governance: feature_governance.get(&feature).cloned(),
            derived: None,
        })
        .collect::<Vec<_>>();
    features.extend(derived_features.iter().cloned());
    let verification_summary = rule_verification_summary(&rules);
    Ok(LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: gate_id.to_string(),
        gate_type: "bitmask_gate".to_string(),
        input_schema: InputSchema { features },
        rules,
        evaluation: EvaluationConfig {
            combine: "bitwise_or".to_string(),
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
            RuleVerificationStatus::Z3Verified => "z3_verified",
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
        RuleVerificationStatus::Z3Verified => 4,
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
    decision_mode: DiscoveryDecisionMode,
) -> Result<Vec<RuleDefinition>> {
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
    )?;
    let shortlist = exact_selection_shortlist(
        &all_candidates,
        &greedy_plan,
        EXACT_SELECTION_FRONTIER_LIMIT,
    );
    let selected_candidates = match select_candidate_rules_exact(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        &shortlist,
    ) {
        Some(exact_plan) if !exact_plan.is_empty() => {
            let greedy_score = score_candidate_set(rows, &greedy_plan, validation_indices);
            let exact_score = score_candidate_set(rows, &exact_plan, validation_indices);
            if compare_candidate_set_score(&exact_score, &greedy_score) == Ordering::Less {
                exact_plan
            } else {
                greedy_plan
            }
        }
        _ => greedy_plan,
    };
    let selected_candidates = recover_rare_rules(
        rows,
        &train_denied_indices,
        &train_allowed_indices,
        validation_indices,
        selected_candidates,
        feature_governance,
        decision_mode,
    );

    Ok(selected_candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| rule_from_candidate(index as u32, candidate))
        .collect())
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
        serde_json::to_string(value)
            .expect("stable row bucket serialization")
            .hash(&mut hasher);
    }
    hasher.finish()
}

fn recover_rare_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    validation_indices: Option<&[usize]>,
    selected_candidates: Vec<CandidateRule>,
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
) -> Vec<CandidateRule> {
    let mut recovered = selected_candidates;
    for _ in 0..RARE_RULE_RECOVERY_MAX_PASSES {
        let uncovered_denied = denied_indices
            .iter()
            .copied()
            .filter(|index| {
                !recovered
                    .iter()
                    .any(|candidate| matches_candidate(&rows[*index].features, candidate))
            })
            .collect::<Vec<_>>();
        if uncovered_denied.is_empty() {
            break;
        }

        let existing_signatures = recovered
            .iter()
            .map(CandidateRule::signature)
            .collect::<BTreeSet<_>>();
        let rescue_shortlist = candidate_rules(
            rows,
            &uncovered_denied,
            allowed_indices,
            feature_governance,
            decision_mode,
        )
        .into_iter()
        .filter(|candidate| !existing_signatures.contains(&candidate.signature()))
        .take(RARE_RULE_RECOVERY_FRONTIER_LIMIT)
        .collect::<Vec<_>>();
        if rescue_shortlist.is_empty() {
            break;
        }

        let Some(rescue_plan) = select_candidate_rules_exact(
            rows,
            &uncovered_denied,
            allowed_indices,
            &rescue_shortlist,
        ) else {
            break;
        };
        if rescue_plan.is_empty() {
            break;
        }

        let mut candidate_combined = recovered.clone();
        candidate_combined.extend(rescue_plan);
        candidate_combined = dedupe_candidate_rules_by_signature(candidate_combined);

        let current_score = score_candidate_set(rows, &recovered, validation_indices);
        let combined_score = score_candidate_set(rows, &candidate_combined, validation_indices);
        let improved = compare_candidate_set_score(&combined_score, &current_score)
            == Ordering::Less
            || (combined_score.false_negatives < current_score.false_negatives
                && combined_score.false_positives <= current_score.false_positives);
        if !improved {
            break;
        }

        recovered = candidate_combined;
    }
    recovered
}

fn dedupe_candidate_rules_by_signature(candidates: Vec<CandidateRule>) -> Vec<CandidateRule> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for candidate in candidates {
        if seen.insert(candidate.signature()) {
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
    let mut signatures: BTreeSet<String> =
        shortlisted.iter().map(CandidateRule::signature).collect();
    for candidate in greedy_plan {
        let signature = candidate.signature();
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
) -> Option<Vec<CandidateRule>> {
    if candidates.is_empty() {
        return Some(Vec::new());
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

    let smt = build_exact_selection_smt(candidates, &denied_matches, &allowed_matches);
    let selected_indexes = solve_selected_rule_indexes_with_z3(candidates.len(), &smt).ok()?;
    Some(
        selected_indexes
            .into_iter()
            .map(|index| candidates[index].clone())
            .collect(),
    )
}

fn build_exact_selection_smt(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> String {
    let mut smt = String::from("(set-option :opt.priority lex)\n");
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

    smt.push_str(&format!(
        "(minimize (+ {} {}))\n",
        hit_sum("deny_hit", denied_matches.len(), false),
        hit_sum("allow_hit", allowed_matches.len(), true)
    ));
    smt.push_str(&format!(
        "(minimize {})\n",
        hit_sum("allow_hit", allowed_matches.len(), true)
    ));
    smt.push_str(&format!("(minimize {})\n", keep_sum(candidates.len())));
    smt.push_str(&format!("(minimize {})\n", weighted_keep_sum(candidates)));
    smt.push_str("(check-sat)\n(get-model)\n");
    smt
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
    if count == 0 {
        return "0".to_string();
    }
    format!(
        "(+ {})",
        (0..count)
            .map(|index| {
                if when_true {
                    format!("(ite {prefix}_{index} 1 0)")
                } else {
                    format!("(ite {prefix}_{index} 0 1)")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn keep_sum(count: usize) -> String {
    if count == 0 {
        return "0".to_string();
    }
    format!(
        "(+ {})",
        (0..count)
            .map(|index| format!("(ite keep_{index} 1 0)"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn weighted_keep_sum(candidates: &[CandidateRule]) -> String {
    if candidates.is_empty() {
        return "0".to_string();
    }
    format!(
        "(+ {})",
        candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                format!(
                    "(ite keep_{index} {} 0)",
                    candidate_total_penalty(candidate)
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn solve_selected_rule_indexes_with_z3(candidate_count: usize, smt: &str) -> Result<Vec<usize>> {
    let smt_path = std::env::temp_dir().join(format!(
        "logicpearl-discovery-{}-{}.smt2",
        std::process::id(),
        unique_suffix()
    ));
    fs::write(&smt_path, smt)?;

    let output = Command::new("z3")
        .arg("-smt2")
        .arg(&smt_path)
        .output()
        .map_err(|err| {
            LogicPearlError::message(format!(
                "failed to launch z3; make sure Z3 is installed and on PATH: {err}"
            ))
        })?;
    let _ = fs::remove_file(&smt_path);

    if !output.status.success() {
        return Err(LogicPearlError::message(format!(
            "z3 failed while solving exact rule selection: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| LogicPearlError::message(format!("z3 output was not valid UTF-8: {err}")))?;
    if !stdout.lines().next().unwrap_or_default().contains("sat") {
        return Ok(Vec::new());
    }

    let mut selected = Vec::new();
    for index in 0..candidate_count {
        let needle = format!("(define-fun keep_{index} () Bool");
        if let Some(position) = stdout.find(&needle) {
            let remainder = &stdout[position + needle.len()..];
            if remainder.trim_start().starts_with("true") {
                selected.push(index);
            }
        }
    }
    Ok(selected)
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn select_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    validation_indices: Option<&[usize]>,
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
) -> Option<CandidateRule> {
    let mut candidates = candidate_rules(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
    );
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(compare_candidate_priority);
    candidates.truncate(LOOKAHEAD_FRONTIER_LIMIT);

    let mut best: Option<(CandidateRule, CandidatePlanScore)> = None;
    for candidate in candidates {
        let score = simulate_candidate_plan(
            rows,
            denied_indices,
            allowed_indices,
            validation_indices,
            &candidate,
            feature_governance,
            decision_mode,
        );
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
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    validation_indices: Option<&[usize]>,
    first_candidate: &CandidateRule,
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
) -> CandidatePlanScore {
    let mut rules = vec![first_candidate.clone()];
    let mut remaining_denied: Vec<usize> = denied_indices
        .iter()
        .copied()
        .filter(|index| !matches_candidate(&rows[*index].features, first_candidate))
        .collect();

    if first_candidate.false_positives == 0 {
        while !remaining_denied.is_empty() {
            let Some(next) = best_immediate_candidate_rule(
                rows,
                &remaining_denied,
                allowed_indices,
                feature_governance,
                decision_mode,
            ) else {
                break;
            };
            if next.denied_coverage == 0 {
                break;
            }
            remaining_denied.retain(|index| !matches_candidate(&rows[*index].features, &next));
            let has_false_positives = next.false_positives > 0;
            rules.push(next);
            if has_false_positives {
                break;
            }
        }
    }

    let validation_set = validation_indices
        .map(|indices| indices.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let training_indices = rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| (!validation_set.contains(&index)).then_some(index))
        .collect::<Vec<_>>();
    let training_score = score_candidate_subset(rows, &rules, &training_indices);
    let validation_score = score_candidate_subset(rows, &rules, validation_indices.unwrap_or(&[]));

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
            residual_rule_from_candidate(gate.rules.len() as u32 + index as u32, candidate)
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
            for threshold in unique_thresholds {
                for op in [
                    ComparisonOperator::Lt,
                    ComparisonOperator::Lte,
                    ComparisonOperator::Eq,
                    ComparisonOperator::Gte,
                    ComparisonOperator::Gt,
                ] {
                    let candidate = CandidateRule {
                        feature: feature.clone(),
                        op: op.clone(),
                        value: ComparisonValue::Literal(Value::Number(
                            Number::from_f64(threshold).unwrap(),
                        )),
                        denied_coverage: 0,
                        false_positives: 0,
                    };
                    let candidate = CandidateRule {
                        denied_coverage: candidate_coverage(rows, denied_indices, &candidate),
                        false_positives: candidate_coverage(rows, allowed_indices, &candidate),
                        ..candidate
                    };
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
                let candidate = CandidateRule {
                    feature: feature.clone(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Bool(boolean)),
                    denied_coverage: candidate_coverage(
                        rows,
                        denied_indices,
                        &CandidateRule {
                            feature: feature.clone(),
                            op: ComparisonOperator::Eq,
                            value: ComparisonValue::Literal(Value::Bool(boolean)),
                            denied_coverage: 0,
                            false_positives: 0,
                        },
                    ),
                    false_positives: candidate_coverage(
                        rows,
                        allowed_indices,
                        &CandidateRule {
                            feature: feature.clone(),
                            op: ComparisonOperator::Eq,
                            value: ComparisonValue::Literal(Value::Bool(boolean)),
                            denied_coverage: 0,
                            false_positives: 0,
                        },
                    ),
                };
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
                let candidate = CandidateRule {
                    feature: feature.clone(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String(text.clone())),
                    denied_coverage: string_coverage_for(rows, denied_indices, &feature, &text),
                    false_positives: string_coverage_for(rows, allowed_indices, &feature, &text),
                };
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
                let candidate = CandidateRule {
                    feature: left.clone(),
                    op,
                    value: ComparisonValue::FeatureRef {
                        feature_ref: right.clone(),
                    },
                    denied_coverage: 0,
                    false_positives: 0,
                };
                let candidate = CandidateRule {
                    denied_coverage: candidate_coverage(rows, denied_indices, &candidate),
                    false_positives: candidate_coverage(rows, allowed_indices, &candidate),
                    ..candidate
                };
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
            }
        }
    }

    candidates.retain(|candidate| candidate.denied_coverage > 0);
    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    candidates
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
) -> Option<CandidateRule> {
    candidate_rules(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
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
        .then_with(|| left.signature().cmp(&right.signature()))
}

fn candidate_complexity_penalty(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> usize {
    if decision_mode == DiscoveryDecisionMode::Review
        && candidate.op == ComparisonOperator::Eq
        && candidate.value.literal().and_then(Value::as_f64).is_some()
    {
        return usize::MAX / 4;
    }
    match candidate.value {
        ComparisonValue::Literal(ref value)
            if candidate.op == ComparisonOperator::Eq && value.as_f64().is_some() =>
        {
            3
        }
        ComparisonValue::FeatureRef { .. } => 1,
        ComparisonValue::Literal(_) if is_derived_feature_name(&candidate.feature) => 2,
        ComparisonValue::Literal(_) => 0,
    }
}

fn candidate_allowed_for_mode(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> bool {
    !(decision_mode == DiscoveryDecisionMode::Review
        && candidate.op == ComparisonOperator::Eq
        && candidate.value.literal().and_then(Value::as_f64).is_some())
}

fn candidate_memorization_penalty(candidate: &CandidateRule) -> usize {
    if candidate.op == ComparisonOperator::Eq
        && candidate.value.literal().and_then(Value::as_f64).is_some()
    {
        1_000_000usize.saturating_sub(candidate.denied_coverage)
    } else {
        0
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

fn feature_has_nontrivial_numeric_range(rows: &[DecisionTraceRow], feature: &str) -> bool {
    let mut distinct_values: BTreeSet<i64> = BTreeSet::new();
    for value in rows
        .iter()
        .filter_map(|row| row.features.get(feature))
        .filter_map(Value::as_f64)
    {
        distinct_values.insert((value * 1000.0).round() as i64);
        if distinct_values.len() > 2 {
            return true;
        }
    }
    false
}

fn candidate_coverage(
    rows: &[DecisionTraceRow],
    indices: &[usize],
    candidate: &CandidateRule,
) -> usize {
    indices
        .iter()
        .filter(|index| matches_candidate(&rows[**index].features, candidate))
        .count()
}

fn string_coverage_for(
    rows: &[DecisionTraceRow],
    indices: &[usize],
    feature: &str,
    expected: &str,
) -> usize {
    indices
        .iter()
        .filter(|index| {
            rows[**index]
                .features
                .get(feature)
                .and_then(Value::as_str)
                .map(|value| value == expected)
                .unwrap_or(false)
        })
        .count()
}

pub(super) fn rule_from_candidate(bit: u32, candidate: &CandidateRule) -> RuleDefinition {
    let deny_when = Expression::Comparison(ComparisonExpression {
        feature: candidate.feature.clone(),
        op: candidate.op.clone(),
        value: candidate.value.clone(),
    });
    let generated = generate_rule_text(&deny_when);
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

    let generated = generate_rule_text(&deny_when);
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
    comparison_matches(
        &ComparisonExpression {
            feature: candidate.feature.clone(),
            op: candidate.op.clone(),
            value: candidate.value.clone(),
        },
        features,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_allowed_for_mode, candidate_complexity_penalty, candidate_rules,
        compare_candidate_set_score, recover_rare_rules, rule_from_candidate, score_candidate_set,
        select_candidate_rules_exact, CandidateRule, CandidateSetScore,
    };
    use crate::{DecisionTraceRow, DiscoveryDecisionMode};
    use logicpearl_ir::{ComparisonOperator, ComparisonValue};
    use serde_json::{Number, Value};
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn exact_selection_prefers_minimal_general_rule_over_equal_singletons() {
        if std::process::Command::new("z3")
            .arg("-version")
            .output()
            .is_err()
        {
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
                .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].op, ComparisonOperator::Lte);
        assert_eq!(
            selected[0].value.literal().and_then(Value::as_f64),
            Some(2.0)
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
        );
        assert!(
            !candidates
                .iter()
                .any(|candidate| matches!(candidate.value, ComparisonValue::FeatureRef { .. })),
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
        );
        assert!(
            candidates
                .iter()
                .filter(|candidate| matches!(candidate.value, ComparisonValue::FeatureRef { .. }))
                .all(|candidate| matches!(
                    candidate.op,
                    ComparisonOperator::Lt
                        | ComparisonOperator::Lte
                        | ComparisonOperator::Gt
                        | ComparisonOperator::Gte
                )),
            "feature-ref candidates should stay ordered comparisons"
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
        let selected = vec![CandidateRule {
            feature: "score".to_string(),
            op: ComparisonOperator::Lte,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
            denied_coverage: 3,
            false_positives: 1,
        }];

        let recovered = recover_rare_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            None,
            selected,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
        );
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
        let selected = vec![CandidateRule {
            feature: "score".to_string(),
            op: ComparisonOperator::Lte,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
            denied_coverage: 3,
            false_positives: 1,
        }];

        let recovered = recover_rare_rules(
            &rows,
            &denied_indices,
            &allowed_indices,
            None,
            selected,
            &BTreeMap::new(),
            DiscoveryDecisionMode::Standard,
        );
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].feature, "score");
        let score = score_candidate_set(&rows, &recovered, None);
        assert_eq!(score.false_negatives, 1);
        assert_eq!(score.false_positives, 1);
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
            &CandidateRule {
                feature: "contains_xss_signature".to_string(),
                op: ComparisonOperator::Eq,
                value: ComparisonValue::Literal(Value::Bool(true)),
                denied_coverage: 3,
                false_positives: 0,
            },
        );

        assert_eq!(rule.label.as_deref(), Some("XSS Signature Detected"));
        assert_eq!(
            rule.counterfactual_hint.as_deref(),
            Some("Remove XSS Signature")
        );
    }

    #[test]
    fn numeric_exact_match_rules_get_extra_complexity_penalty() {
        let exact = CandidateRule {
            feature: "suspicious_token_count".to_string(),
            op: ComparisonOperator::Eq,
            value: ComparisonValue::Literal(Value::Number(Number::from(1))),
            denied_coverage: 5,
            false_positives: 0,
        };
        let threshold = CandidateRule {
            feature: "suspicious_token_count".to_string(),
            op: ComparisonOperator::Gte,
            value: ComparisonValue::Literal(Value::Number(Number::from(1))),
            denied_coverage: 5,
            false_positives: 0,
        };

        assert!(
            candidate_complexity_penalty(&exact, DiscoveryDecisionMode::Standard)
                > candidate_complexity_penalty(&threshold, DiscoveryDecisionMode::Standard)
        );
    }

    #[test]
    fn review_mode_rejects_numeric_exact_matches() {
        let exact = CandidateRule {
            feature: "suspicious_token_count".to_string(),
            op: ComparisonOperator::Eq,
            value: ComparisonValue::Literal(Value::Number(Number::from(13))),
            denied_coverage: 5,
            false_positives: 0,
        };
        let threshold = CandidateRule {
            feature: "suspicious_token_count".to_string(),
            op: ComparisonOperator::Gte,
            value: ComparisonValue::Literal(Value::Number(Number::from(13))),
            denied_coverage: 5,
            false_positives: 0,
        };

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
        let candidate = CandidateRule {
            feature: "derived__query_key_count__minus__suspicious_token_count".to_string(),
            op: ComparisonOperator::Gte,
            value: ComparisonValue::Literal(Value::Number(Number::from(13))),
            denied_coverage: 5,
            false_positives: 0,
        };

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
        CandidateRule {
            feature: feature.to_string(),
            op,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(value).unwrap())),
            denied_coverage: 0,
            false_positives: 0,
        }
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
}
