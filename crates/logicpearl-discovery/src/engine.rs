use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig, Expression,
    FeatureDefinition, InputSchema, LogicPearlGateIr, Provenance, RuleDefinition, RuleKind,
    RuleVerificationStatus, VerificationConfig,
};
use logicpearl_runtime::evaluate_gate;
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionCandidate, BooleanConjunctionSearchOptions,
    BooleanSearchExample,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::canonicalize::{
    canonicalize_rules, comparison_matches, expression_matches, prune_redundant_rules,
};
use super::features::{
    boolean_feature_map, infer_binary_feature_names, infer_feature_type, numeric_feature_names,
    rule_contains_feature, rule_with_added_condition, sorted_feature_names,
};
use super::{
    CandidateRule, DecisionTraceRow, PinnedRuleSet, ResidualPassOptions,
    UniqueCoverageRefinementOptions,
};

const LOOKAHEAD_FRONTIER_LIMIT: usize = 12;

#[derive(Debug, Clone, PartialEq)]
struct CandidatePlanScore {
    training_parity: f64,
    total_false_positives: usize,
    uncovered_denied: usize,
    rule_count: usize,
}

pub(super) fn build_gate(
    rows: &[DecisionTraceRow],
    gate_id: &str,
    residual_options: Option<&ResidualPassOptions>,
    refinement_options: Option<&UniqueCoverageRefinementOptions>,
    pinned_rules: Option<&PinnedRuleSet>,
) -> Result<(LogicPearlGateIr, usize, usize, usize)> {
    let mut rules = discover_rules(rows)?;
    let mut residual_rules_discovered = 0usize;
    if let Some(options) = residual_options {
        let first_pass_gate = gate_from_rules(rows, gate_id, rules.clone())?;
        let residual_rules = discover_residual_rules(rows, &first_pass_gate, options)?;
        residual_rules_discovered = residual_rules.len();
        rules.extend(residual_rules);
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
        gate_from_rules(rows, gate_id, rules)?,
        residual_rules_discovered,
        refined_rules_applied,
        pinned_rules_applied,
    ))
}

pub(super) fn gate_from_rules(
    rows: &[DecisionTraceRow],
    gate_id: &str,
    rules: Vec<RuleDefinition>,
) -> Result<LogicPearlGateIr> {
    let feature_sample = rows[0].features.clone();
    let verification_summary = rule_verification_summary(&rules);
    Ok(LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: gate_id.to_string(),
        gate_type: "bitmask_gate".to_string(),
        input_schema: InputSchema {
            features: sorted_feature_names(rows)
                .into_iter()
                .map(|feature| FeatureDefinition {
                    id: feature.clone(),
                    feature_type: infer_feature_type(feature_sample.get(&feature).unwrap()),
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                })
                .collect(),
        },
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

pub(super) fn discover_rules(rows: &[DecisionTraceRow]) -> Result<Vec<RuleDefinition>> {
    let mut remaining_denied: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (!row.allowed).then_some(index))
        .collect();
    let allowed_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| row.allowed.then_some(index))
        .collect();

    let mut discovered = Vec::new();
    while !remaining_denied.is_empty() {
        let candidate = select_candidate_rule(rows, &remaining_denied, &allowed_indices)
            .ok_or_else(|| LogicPearlError::message("no recoverable deny rule found"))?;
        if candidate.denied_coverage == 0 {
            break;
        }

        let bit = discovered.len() as u32;
        let has_false_positives = candidate.false_positives > 0;
        discovered.push(rule_from_candidate(bit, &candidate));
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
) -> Option<CandidateRule> {
    let mut candidates = candidate_rules(rows, denied_indices, allowed_indices);
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(compare_candidate_priority);
    candidates.truncate(LOOKAHEAD_FRONTIER_LIMIT);

    let mut best: Option<(CandidateRule, CandidatePlanScore)> = None;
    for candidate in candidates {
        let score = simulate_candidate_plan(rows, denied_indices, allowed_indices, &candidate);
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
    first_candidate: &CandidateRule,
) -> CandidatePlanScore {
    let mut rules = vec![first_candidate.clone()];
    let mut remaining_denied: Vec<usize> = denied_indices
        .iter()
        .copied()
        .filter(|index| !matches_candidate(&rows[*index].features, first_candidate))
        .collect();

    if first_candidate.false_positives == 0 {
        while !remaining_denied.is_empty() {
            let Some(next) =
                best_immediate_candidate_rule(rows, &remaining_denied, allowed_indices)
            else {
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

    let total_false_positives = allowed_indices
        .iter()
        .filter(|index| {
            rules
                .iter()
                .any(|rule| matches_candidate(&rows[**index].features, rule))
        })
        .count();
    let correct = rows
        .iter()
        .filter(|row| {
            let predicted_deny = rules
                .iter()
                .any(|rule| matches_candidate(&row.features, rule));
            predicted_deny != row.allowed
        })
        .count();

    CandidatePlanScore {
        training_parity: correct as f64 / rows.len() as f64,
        total_false_positives,
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
    current_score
        .training_parity
        .total_cmp(&score.training_parity)
        .then_with(|| {
            score
                .total_false_positives
                .cmp(&current_score.total_false_positives)
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
        let predicted_deny = evaluate_gate(gate, &row.features)? != 0;
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
) -> Vec<CandidateRule> {
    let feature_names = sorted_feature_names(rows);
    let numeric_features = numeric_feature_names(rows);
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
                    candidates.push(candidate);
                }
            }
        } else if values.iter().all(|value| value.is_boolean()) {
            let unique_values: BTreeSet<bool> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(Value::as_bool)
                .collect();
            for boolean in unique_values {
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
                candidates.push(candidate);
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
                candidates.push(candidate);
            }
        }
    }

    for left in &numeric_features {
        for right in &numeric_features {
            if left == right {
                continue;
            }
            for op in [
                ComparisonOperator::Lt,
                ComparisonOperator::Lte,
                ComparisonOperator::Gt,
                ComparisonOperator::Gte,
                ComparisonOperator::Eq,
                ComparisonOperator::Ne,
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
                candidates.push(candidate);
            }
        }
    }

    candidates.retain(|candidate| candidate.denied_coverage > 0);
    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    candidates
}

fn best_immediate_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Option<CandidateRule> {
    candidate_rules(rows, denied_indices, allowed_indices)
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
        .then_with(|| candidate_complexity_penalty(left).cmp(&candidate_complexity_penalty(right)))
        .then_with(|| {
            candidate_memorization_penalty(left).cmp(&candidate_memorization_penalty(right))
        })
        .then_with(|| left.signature().cmp(&right.signature()))
}

fn candidate_complexity_penalty(candidate: &CandidateRule) -> usize {
    match candidate.value {
        ComparisonValue::FeatureRef { .. } => 1,
        ComparisonValue::Literal(_) => 0,
    }
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
    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: candidate.feature.clone(),
            op: candidate.op.clone(),
            value: candidate.value.clone(),
        }),
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
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

    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
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
