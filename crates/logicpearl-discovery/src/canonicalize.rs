// SPDX-License-Identifier: MIT
use super::{
    verification_status, verification_status_rank, DecisionTraceRow, NumericBound, NumericInterval,
};
use logicpearl_ir::{
    canonicalize_expression, ComparisonExpression, ComparisonOperator, ComparisonValue, Expression,
    RuleDefinition, RuleVerificationStatus,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

pub(super) fn prune_redundant_rules(
    rows: &[DecisionTraceRow],
    rules: Vec<RuleDefinition>,
) -> Vec<RuleDefinition> {
    let mut pruned = rules;
    let mut index = 0usize;
    while index < pruned.len() {
        let mut candidate = pruned.clone();
        candidate.remove(index);
        let predictions_changed = rows.iter().any(|row| {
            let with_rule = pruned
                .iter()
                .any(|rule| expression_matches(&rule.deny_when, &row.features));
            let without_rule = candidate
                .iter()
                .any(|rule| expression_matches(&rule.deny_when, &row.features));
            with_rule != without_rule
        });
        if predictions_changed {
            index += 1;
        } else {
            pruned = candidate;
        }
    }
    for (index, rule) in pruned.iter_mut().enumerate() {
        rule.bit = index as u32;
        rule.id = format!("rule_{index:03}");
    }
    pruned
}

pub(super) fn canonicalize_rules(rules: Vec<RuleDefinition>) -> Vec<RuleDefinition> {
    let mut passthrough = Vec::new();
    let mut grouped: BTreeMap<String, Vec<RuleDefinition>> = BTreeMap::new();

    for mut rule in rules {
        rule.deny_when = canonicalize_expression(&rule.deny_when);
        if let Some(key) = rule_canonicalization_key(&rule) {
            grouped.entry(key).or_default().push(rule);
        } else {
            passthrough.push(rule);
        }
    }

    let mut canonicalized = passthrough;
    for group in grouped.into_values() {
        canonicalized.extend(canonicalize_numeric_rule_group(group));
    }

    canonicalized
        .into_iter()
        .enumerate()
        .map(|(index, mut rule)| {
            rule.bit = index as u32;
            rule.id = format!("rule_{index:03}");
            rule
        })
        .collect()
}

fn rule_canonicalization_key(rule: &RuleDefinition) -> Option<String> {
    let Expression::Comparison(comparison) = &rule.deny_when else {
        return None;
    };
    comparison.value.literal().and_then(Value::as_f64)?;
    if !matches!(
        comparison.op,
        ComparisonOperator::Eq
            | ComparisonOperator::Gt
            | ComparisonOperator::Gte
            | ComparisonOperator::Lt
            | ComparisonOperator::Lte
    ) {
        return None;
    }

    let payload = serde_json::json!({
        "kind": &rule.kind,
        "feature": &comparison.feature,
        "label": &rule.label,
        "message": &rule.message,
        "severity": &rule.severity,
        "counterfactual_hint": &rule.counterfactual_hint,
    });
    Some(serde_json::to_string(&payload).expect("rule canonicalization key serialization"))
}

fn canonicalize_numeric_rule_group(group: Vec<RuleDefinition>) -> Vec<RuleDefinition> {
    if group.len() <= 1 {
        return group;
    }

    let mut intervals = Vec::new();
    let mut strongest_status = RuleVerificationStatus::HeuristicUnverified;
    for rule in &group {
        strongest_status =
            strongest_verification_status(strongest_status, verification_status(rule));
        let Expression::Comparison(comparison) = &rule.deny_when else {
            continue;
        };
        if let Some(interval) = comparison_interval(comparison) {
            intervals.push(interval);
        }
    }

    if intervals.len() <= 1 {
        return group;
    }

    intervals.sort_by(compare_intervals);
    let mut merged = Vec::new();
    for interval in intervals {
        match merged.last_mut() {
            Some(current) if intervals_can_merge(current, &interval) => {
                merge_interval_into(current, &interval);
            }
            _ => merged.push(interval),
        }
    }

    let prototype = &group[0];
    merged
        .into_iter()
        .enumerate()
        .map(|(index, interval)| {
            let mut rule = prototype.clone();
            rule.bit = index as u32;
            rule.id = format!("rule_{index:03}");
            rule.deny_when = canonicalize_expression(&interval_expression(prototype, interval));
            rule.verification_status = Some(strongest_status.clone());
            rule
        })
        .collect()
}

fn interval_expression(prototype: &RuleDefinition, interval: NumericInterval) -> Expression {
    let Expression::Comparison(base) = &prototype.deny_when else {
        return prototype.deny_when.clone();
    };
    let lower = interval.lower.as_ref().map(|bound| ComparisonExpression {
        feature: base.feature.clone(),
        op: if bound.inclusive {
            ComparisonOperator::Gte
        } else {
            ComparisonOperator::Gt
        },
        value: ComparisonValue::Literal(number_value(bound.value)),
    });
    let upper = interval.upper.as_ref().map(|bound| ComparisonExpression {
        feature: base.feature.clone(),
        op: if bound.inclusive {
            ComparisonOperator::Lte
        } else {
            ComparisonOperator::Lt
        },
        value: ComparisonValue::Literal(number_value(bound.value)),
    });

    match (lower, upper) {
        (Some(lower), Some(upper))
            if approx_eq(
                lower.value.literal().and_then(Value::as_f64).unwrap(),
                upper.value.literal().and_then(Value::as_f64).unwrap(),
            ) && lower.op == ComparisonOperator::Gte
                && upper.op == ComparisonOperator::Lte =>
        {
            Expression::Comparison(ComparisonExpression {
                feature: base.feature.clone(),
                op: ComparisonOperator::Eq,
                value: lower.value,
            })
        }
        (Some(lower), Some(upper)) => Expression::All {
            all: vec![Expression::Comparison(lower), Expression::Comparison(upper)],
        },
        (Some(lower), None) => Expression::Comparison(lower),
        (None, Some(upper)) => Expression::Comparison(upper),
        (None, None) => prototype.deny_when.clone(),
    }
}

fn comparison_interval(comparison: &ComparisonExpression) -> Option<NumericInterval> {
    let value = comparison.value.literal().and_then(Value::as_f64)?;
    let bound = NumericBound {
        value,
        inclusive: matches!(
            comparison.op,
            ComparisonOperator::Eq | ComparisonOperator::Gte | ComparisonOperator::Lte
        ),
    };
    match comparison.op {
        ComparisonOperator::Eq => Some(NumericInterval {
            lower: Some(bound.clone()),
            upper: Some(bound),
        }),
        ComparisonOperator::Gt | ComparisonOperator::Gte => Some(NumericInterval {
            lower: Some(bound),
            upper: None,
        }),
        ComparisonOperator::Lt | ComparisonOperator::Lte => Some(NumericInterval {
            lower: None,
            upper: Some(bound),
        }),
        _ => None,
    }
}

fn compare_intervals(left: &NumericInterval, right: &NumericInterval) -> Ordering {
    compare_lower_bounds(&left.lower, &right.lower)
        .then_with(|| compare_upper_bounds(&left.upper, &right.upper))
}

fn compare_lower_bounds(left: &Option<NumericBound>, right: &Option<NumericBound>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left
            .value
            .total_cmp(&right.value)
            .then_with(|| right.inclusive.cmp(&left.inclusive)),
    }
}

fn compare_upper_bounds(left: &Option<NumericBound>, right: &Option<NumericBound>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => left
            .value
            .total_cmp(&right.value)
            .then_with(|| left.inclusive.cmp(&right.inclusive)),
    }
}

fn intervals_can_merge(left: &NumericInterval, right: &NumericInterval) -> bool {
    match (&left.upper, &right.lower) {
        (None, _) | (_, None) => true,
        (Some(upper), Some(lower)) => match upper.value.total_cmp(&lower.value) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => upper.inclusive || lower.inclusive,
        },
    }
}

fn merge_interval_into(left: &mut NumericInterval, right: &NumericInterval) {
    if compare_upper_bounds(&left.upper, &right.upper) == Ordering::Less {
        left.upper = right.upper.clone();
    }
}

fn strongest_verification_status(
    left: RuleVerificationStatus,
    right: RuleVerificationStatus,
) -> RuleVerificationStatus {
    if verification_status_rank(&left) >= verification_status_rank(&right) {
        left
    } else {
        right
    }
}

pub(super) fn expression_matches(
    expression: &Expression,
    features: &HashMap<String, Value>,
) -> bool {
    match expression {
        Expression::Comparison(comparison) => comparison_matches(comparison, features),
        Expression::All { all } => all.iter().all(|expr| expression_matches(expr, features)),
        Expression::Any { any } => any.iter().any(|expr| expression_matches(expr, features)),
        Expression::Not { expr } => !expression_matches(expr, features),
    }
}

pub(super) fn comparison_matches(
    comparison: &ComparisonExpression,
    features: &HashMap<String, Value>,
) -> bool {
    let Some(value) = features.get(&comparison.feature) else {
        return false;
    };
    let Some(right) = resolve_comparison_value(features, &comparison.value) else {
        return false;
    };
    match (&comparison.op, value, right) {
        (ComparisonOperator::Eq, left, right) => values_equal(left, right),
        (ComparisonOperator::Ne, left, right) => !values_equal(left, right),
        (ComparisonOperator::Lte, Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .map(|(l, r)| l <= r)
            .unwrap_or(false),
        (ComparisonOperator::Lt, Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .map(|(l, r)| l < r)
            .unwrap_or(false),
        (ComparisonOperator::Gt, Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .map(|(l, r)| l > r)
            .unwrap_or(false),
        (ComparisonOperator::Gte, Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .map(|(l, r)| l >= r)
            .unwrap_or(false),
        (ComparisonOperator::In, left, Value::Array(items)) => {
            items.iter().any(|item| values_equal(left, item))
        }
        (ComparisonOperator::NotIn, left, Value::Array(items)) => {
            !items.iter().any(|item| values_equal(left, item))
        }
        _ => false,
    }
}

fn resolve_comparison_value<'a>(
    features: &'a HashMap<String, Value>,
    value: &'a ComparisonValue,
) -> Option<&'a Value> {
    match value {
        ComparisonValue::Literal(value) => Some(value),
        ComparisonValue::FeatureRef { feature_ref } => features.get(feature_ref),
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(l), Some(r)) => approx_eq(l, r),
        _ => left == right,
    }
}

fn number_value(value: f64) -> Value {
    Value::Number(Number::from_f64(value).expect("finite canonicalized numeric boundary"))
}

fn approx_eq(left: f64, right: f64) -> bool {
    (left - right).abs() < 1e-9
}
