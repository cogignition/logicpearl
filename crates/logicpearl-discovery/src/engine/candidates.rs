// SPDX-License-Identifier: MIT
use super::super::canonicalize::{comparison_matches, expression_matches};
use super::super::features::{
    is_derived_feature_name, numeric_feature_names, sorted_feature_names,
};
use super::super::rule_text::{generate_rule_text, RuleTextContext};
use super::super::{CandidateRule, DecisionTraceRow, DiscoveryDecisionMode, ResidualPassOptions};
use super::{
    CONJUNCTION_ATOM_FRONTIER_LIMIT, NUMERIC_EQ_MAX_DISTINCT_VALUES,
    NUMERIC_EQ_MIN_SUPPORT_ABSOLUTE, NUMERIC_EQ_MIN_SUPPORT_BASIS_POINTS,
};
use logicpearl_ir::{
    BooleanEvidencePolicy, ComparisonExpression, ComparisonOperator, ComparisonValue, Expression,
    FeatureGovernance, RuleDefinition, RuleKind, RuleVerificationStatus,
};
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionCandidate, BooleanConjunctionSearchOptions,
    BooleanSearchExample,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub(super) fn candidate_rules(
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

pub(super) fn conjunction_candidate_rules(
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

pub(super) fn candidate_as_comparison(candidate: &CandidateRule) -> Option<&ComparisonExpression> {
    match &candidate.expression {
        Expression::Comparison(comparison) => Some(comparison),
        _ => None,
    }
}

pub(super) fn candidate_is_compound(candidate: &CandidateRule) -> bool {
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

pub(super) fn best_immediate_candidate_rule(
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

pub(super) fn compare_candidate_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
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

pub(super) fn candidate_complexity_penalty(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> usize {
    expression_complexity_penalty(&candidate.expression, decision_mode)
}

pub(super) fn candidate_allowed_for_mode(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> bool {
    expression_allowed_for_mode(&candidate.expression, decision_mode)
}

pub(super) fn candidate_memorization_penalty(candidate: &CandidateRule) -> usize {
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
pub(crate) fn rule_from_candidate(bit: u32, candidate: &CandidateRule) -> RuleDefinition {
    rule_from_candidate_with_context(bit, candidate, &RuleTextContext::empty())
}

pub(super) fn rule_from_candidate_with_context(
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
        evidence: None,
    }
}

pub(super) fn residual_rule_from_candidate(
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
        evidence: None,
    }
}

pub(super) fn matches_candidate(
    features: &HashMap<String, Value>,
    candidate: &CandidateRule,
) -> bool {
    expression_matches(&candidate.expression, features)
}
