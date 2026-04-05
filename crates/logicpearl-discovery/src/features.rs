use logicpearl_ir::{ComparisonExpression, Expression, FeatureType, RuleDefinition};
use serde_json::Value;
use std::collections::HashMap;

use super::DecisionTraceRow;

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

pub(super) fn infer_binary_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| {
            let mut names: Vec<String> = row
                .features
                .keys()
                .filter(|feature| rows.iter().all(|row| is_binary_value(row.features.get(*feature))))
                .cloned()
                .collect();
            names.sort();
            names
        })
        .unwrap_or_default()
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

    RuleDefinition {
        id: rule.id.clone(),
        kind: rule.kind.clone(),
        bit: rule.bit,
        deny_when,
        label: rule.label.clone(),
        message: rule.message.clone(),
        severity: rule.severity.clone(),
        counterfactual_hint: rule.counterfactual_hint.clone(),
        verification_status: Some(logicpearl_ir::RuleVerificationStatus::RefinedUnverified),
    }
}
