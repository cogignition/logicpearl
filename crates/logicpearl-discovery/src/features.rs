// SPDX-License-Identifier: MIT
use logicpearl_ir::{
    ComparisonExpression, DerivedFeatureDefinition, DerivedFeatureOperator, Expression,
    FeatureDefinition, FeatureType, RuleDefinition,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::collections::HashMap;

use logicpearl_core::{LogicPearlError, Result};

use super::rule_text::{generate_rule_text, RuleTextContext};
use super::DecisionTraceRow;

const DERIVED_FEATURE_PREFIX: &str = "derived__";
const INTERACTION_SOURCE_FEATURE_LIMIT: usize = 6;
const MAX_INTERACTION_FEATURES: usize = 8;

pub(super) fn rule_contains_feature(rule: &RuleDefinition, feature: &str) -> bool {
    expression_features(&rule.deny_when)
        .iter()
        .any(|existing| existing == feature)
}

pub(super) fn expression_features(expression: &Expression) -> Vec<String> {
    match expression {
        Expression::Comparison(comparison) => {
            let mut features = vec![comparison.feature.clone()];
            if let Some(feature_ref) = comparison.value.feature_ref() {
                features.push(feature_ref.to_string());
            }
            features
        }
        Expression::All { all } => all.iter().flat_map(expression_features).collect(),
        Expression::Any { any } => any.iter().flat_map(expression_features).collect(),
        Expression::Not { expr } => expression_features(expr),
    }
}

pub(super) fn numeric_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    sorted_feature_names(rows)
        .into_iter()
        .filter(|feature| {
            rows.iter()
                .filter_map(|row| row.features.get(feature))
                .all(Value::is_number)
        })
        .collect()
}

pub(super) fn augment_rows_with_numeric_interactions(
    rows: &[DecisionTraceRow],
) -> Result<(Vec<DecisionTraceRow>, Vec<FeatureDefinition>)> {
    if rows.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let numeric_features = numeric_feature_names(rows)
        .into_iter()
        .filter(|feature| !is_binary_numeric_feature(rows, feature))
        .collect::<Vec<_>>();
    if numeric_features.len() < 2 {
        return Ok((rows.to_vec(), Vec::new()));
    }

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

    let mut ranked = numeric_features
        .iter()
        .map(|feature| {
            (
                feature.clone(),
                best_numeric_feature_score(rows, &denied_indices, &allowed_indices, feature),
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_name, left_score), (right_name, right_score)| {
        compare_numeric_feature_score(right_score, left_score)
            .then_with(|| left_name.cmp(right_name))
    });
    let top_sources = ranked
        .into_iter()
        .take(INTERACTION_SOURCE_FEATURE_LIMIT)
        .collect::<Vec<_>>();

    let mut candidates = Vec::new();
    for (left_feature, left_score) in &top_sources {
        for (right_feature, right_score) in &top_sources {
            if left_feature == right_feature {
                continue;
            }
            let base_score = std::cmp::max(*left_score, *right_score);
            for op in [
                DerivedFeatureOperator::Difference,
                DerivedFeatureOperator::Ratio,
            ] {
                let id = derived_feature_id(op.clone(), left_feature, right_feature);
                let values = rows
                    .iter()
                    .map(|row| {
                        derive_numeric_interaction(
                            row.features.get(left_feature),
                            row.features.get(right_feature),
                            &op,
                        )
                    })
                    .collect::<Vec<_>>();
                if !has_nontrivial_numeric_range(&values) {
                    continue;
                }
                let score = best_numeric_values_score(&values, &denied_indices, &allowed_indices);
                if compare_numeric_feature_score(&score, &base_score) != Ordering::Greater {
                    continue;
                }
                candidates.push((
                    score,
                    FeatureDefinition {
                        id,
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: Some(false),
                        semantics: None,
                        governance: None,
                        derived: Some(DerivedFeatureDefinition {
                            op,
                            left_feature: left_feature.clone(),
                            right_feature: right_feature.clone(),
                        }),
                    },
                    values,
                ));
            }
        }
    }

    candidates.sort_by(|(left_score, left_def, _), (right_score, right_def, _)| {
        compare_numeric_feature_score(right_score, left_score)
            .then_with(|| left_def.id.cmp(&right_def.id))
    });
    candidates.truncate(MAX_INTERACTION_FEATURES);

    if candidates.is_empty() {
        return Ok((rows.to_vec(), Vec::new()));
    }

    let mut augmented = Vec::with_capacity(rows.len());
    for (row_index, row) in rows.iter().enumerate() {
        let mut features = row.features.clone();
        for (_, derived, values) in &candidates {
            features.insert(
                derived.id.clone(),
                Value::Number(Number::from_f64(values[row_index]).ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "derived feature produced non-finite value at row {row_index}"
                    ))
                })?),
            );
        }
        augmented.push(DecisionTraceRow {
            features,
            allowed: row.allowed,
        });
    }

    let derived_features = candidates
        .into_iter()
        .map(|(_, derived, _)| derived)
        .collect();
    Ok((augmented, derived_features))
}

pub(super) fn infer_binary_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| {
            let mut names: Vec<String> = row
                .features
                .keys()
                .filter(|feature| {
                    rows.iter()
                        .all(|row| is_binary_value(row.features.get(*feature)))
                })
                .cloned()
                .collect();
            names.sort();
            names
        })
        .unwrap_or_default()
}

pub(super) fn is_derived_feature_name(feature: &str) -> bool {
    feature.starts_with(DERIVED_FEATURE_PREFIX)
}

pub(super) fn is_binary_value(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(_)) => true,
        Some(Value::Number(number)) => number
            .as_f64()
            .map(|value| (value - 0.0).abs() < 1e-9 || (value - 1.0).abs() < 1e-9)
            .unwrap_or(false),
        _ => false,
    }
}

pub(super) fn boolean_feature_map(
    features: &HashMap<String, Value>,
    binary_features: &[String],
) -> std::collections::BTreeMap<String, bool> {
    binary_features
        .iter()
        .map(|feature| {
            let value = match features.get(feature) {
                Some(Value::Bool(value)) => *value,
                Some(Value::Number(number)) => number.as_f64().unwrap_or_default() > 0.5,
                _ => false,
            };
            (feature.clone(), value)
        })
        .collect()
}

pub(super) fn sorted_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| {
            let mut keys: Vec<String> = row.features.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default()
}

pub(super) fn infer_feature_type(value: &Value) -> FeatureType {
    if value.is_boolean() {
        FeatureType::Bool
    } else if value.as_i64().is_some() {
        FeatureType::Int
    } else if value.as_f64().is_some() {
        FeatureType::Float
    } else {
        FeatureType::String
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NumericFeatureScore {
    net_coverage: isize,
    false_positives: usize,
    denied_coverage: usize,
}

fn compare_numeric_feature_score(
    left: &NumericFeatureScore,
    right: &NumericFeatureScore,
) -> Ordering {
    left.net_coverage
        .cmp(&right.net_coverage)
        .then_with(|| right.false_positives.cmp(&left.false_positives))
        .then_with(|| left.denied_coverage.cmp(&right.denied_coverage))
}

fn best_numeric_feature_score(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature: &str,
) -> NumericFeatureScore {
    let values = rows
        .iter()
        .map(|row| {
            row.features
                .get(feature)
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
        })
        .collect::<Vec<_>>();
    best_numeric_values_score(&values, denied_indices, allowed_indices)
}

fn best_numeric_values_score(
    values: &[f64],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> NumericFeatureScore {
    let mut thresholds = BTreeSet::new();
    for index in denied_indices {
        thresholds.insert((values[*index] * 1000.0).round() as i64);
    }
    let mut best = NumericFeatureScore {
        net_coverage: isize::MIN,
        false_positives: usize::MAX,
        denied_coverage: 0,
    };
    for threshold in thresholds {
        let threshold = threshold as f64 / 1000.0;
        for predicate in [
            |value: f64, rhs: f64| value < rhs,
            |value: f64, rhs: f64| value <= rhs,
            |value: f64, rhs: f64| value > rhs,
            |value: f64, rhs: f64| value >= rhs,
        ] {
            let denied_coverage = denied_indices
                .iter()
                .filter(|index| predicate(values[**index], threshold))
                .count();
            if denied_coverage == 0 {
                continue;
            }
            let false_positives = allowed_indices
                .iter()
                .filter(|index| predicate(values[**index], threshold))
                .count();
            let score = NumericFeatureScore {
                net_coverage: denied_coverage as isize - false_positives as isize,
                false_positives,
                denied_coverage,
            };
            if compare_numeric_feature_score(&score, &best) == Ordering::Greater {
                best = score;
            }
        }
    }
    best
}

fn derived_feature_id(
    op: DerivedFeatureOperator,
    left_feature: &str,
    right_feature: &str,
) -> String {
    let suffix = match op {
        DerivedFeatureOperator::Difference => "minus",
        DerivedFeatureOperator::Ratio => "over",
    };
    format!(
        "{DERIVED_FEATURE_PREFIX}{}__{suffix}__{}",
        sanitize_feature_id(left_feature),
        sanitize_feature_id(right_feature)
    )
}

fn sanitize_feature_id(feature: &str) -> String {
    feature
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn derive_numeric_interaction(
    left: Option<&Value>,
    right: Option<&Value>,
    op: &DerivedFeatureOperator,
) -> f64 {
    let left = left.and_then(Value::as_f64).unwrap_or(0.0);
    let right = right.and_then(Value::as_f64).unwrap_or(0.0);
    let value = match op {
        DerivedFeatureOperator::Difference => left - right,
        DerivedFeatureOperator::Ratio => {
            if right.abs() < f64::EPSILON {
                0.0
            } else {
                left / right
            }
        }
    };
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn has_nontrivial_numeric_range(values: &[f64]) -> bool {
    let mut distinct_values: BTreeSet<i64> = BTreeSet::new();
    for value in values {
        distinct_values.insert((value * 1000.0).round() as i64);
        if distinct_values.len() > 2 {
            return true;
        }
    }
    false
}

fn is_binary_numeric_feature(rows: &[DecisionTraceRow], feature: &str) -> bool {
    rows.iter()
        .filter_map(|row| row.features.get(feature))
        .all(|value| is_binary_value(Some(value)))
}

pub(super) fn rule_with_added_condition(
    rule: &RuleDefinition,
    addition: ComparisonExpression,
) -> RuleDefinition {
    let deny_when = match &rule.deny_when {
        Expression::Comparison(existing) => Expression::All {
            all: vec![
                Expression::Comparison(existing.clone()),
                Expression::Comparison(addition),
            ],
        },
        Expression::All { all } => {
            let mut next = all.clone();
            next.push(Expression::Comparison(addition));
            Expression::All { all: next }
        }
        _ => rule.deny_when.clone(),
    };

    let generated = generate_rule_text(&deny_when, &RuleTextContext::empty());

    RuleDefinition {
        id: rule.id.clone(),
        kind: rule.kind.clone(),
        bit: rule.bit,
        deny_when,
        label: generated.label,
        message: generated.message,
        severity: rule.severity.clone(),
        counterfactual_hint: generated.counterfactual_hint,
        verification_status: Some(logicpearl_ir::RuleVerificationStatus::RefinedUnverified),
    }
}
