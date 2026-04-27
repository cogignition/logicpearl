// SPDX-License-Identifier: MIT
use super::model::{
    FeatureChanges, FeatureDictionaryChanges, FeatureSemanticsChange, FeatureSemanticsSnapshot,
    FeatureStateSnapshot, RuleFeatureSemanticsSnapshot,
};
use logicpearl_ir::{
    ActionRuleDefinition, ComparisonValue, Expression, FeatureSemantics, InputSchema,
    LogicPearlActionIr, LogicPearlGateIr, RuleDefinition,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn diff_feature_dictionaries(
    old_gate: &LogicPearlGateIr,
    new_gate: &LogicPearlGateIr,
) -> FeatureDictionaryChanges {
    diff_feature_dictionaries_for_schemas(&old_gate.input_schema, &new_gate.input_schema)
}

pub(super) fn diff_feature_sets(
    old_schema: &InputSchema,
    new_schema: &InputSchema,
) -> FeatureChanges {
    let old_features = old_schema
        .features
        .iter()
        .map(|feature| feature.id.clone())
        .collect::<BTreeSet<_>>();
    let new_features = new_schema
        .features
        .iter()
        .map(|feature| feature.id.clone())
        .collect::<BTreeSet<_>>();

    FeatureChanges {
        added: new_features.difference(&old_features).cloned().collect(),
        removed: old_features.difference(&new_features).cloned().collect(),
    }
}

pub(super) fn diff_feature_dictionaries_for_schemas(
    old_schema: &InputSchema,
    new_schema: &InputSchema,
) -> FeatureDictionaryChanges {
    let old_semantics = feature_semantics_by_schema(old_schema);
    let new_semantics = feature_semantics_by_schema(new_schema);
    let old_ids = old_semantics.keys().cloned().collect::<BTreeSet<_>>();
    let new_ids = new_semantics.keys().cloned().collect::<BTreeSet<_>>();
    let added = new_ids
        .difference(&old_ids)
        .map(|id| feature_semantics_snapshot(id, new_semantics[id]))
        .collect::<Vec<_>>();
    let removed = old_ids
        .difference(&new_ids)
        .map(|id| feature_semantics_snapshot(id, old_semantics[id]))
        .collect::<Vec<_>>();
    let changed = old_ids
        .intersection(&new_ids)
        .filter_map(|id| {
            let old = old_semantics[id];
            let new = new_semantics[id];
            (old != new).then(|| FeatureSemanticsChange {
                id: id.clone(),
                source_changed: feature_source_signature(old) != feature_source_signature(new),
                explanation_changed: feature_explanation_signature(old)
                    != feature_explanation_signature(new),
                old: feature_semantics_snapshot(id, old),
                new: feature_semantics_snapshot(id, new),
            })
        })
        .collect::<Vec<_>>();
    FeatureDictionaryChanges {
        added,
        removed,
        changed,
    }
}

fn feature_semantics_by_id(gate: &LogicPearlGateIr) -> BTreeMap<String, &FeatureSemantics> {
    feature_semantics_by_schema(&gate.input_schema)
}

fn feature_semantics_by_schema(input_schema: &InputSchema) -> BTreeMap<String, &FeatureSemantics> {
    input_schema
        .features
        .iter()
        .filter_map(|feature| {
            feature
                .semantics
                .as_ref()
                .map(|semantics| (feature.id.clone(), semantics))
        })
        .collect()
}

fn feature_semantics_snapshot(id: &str, semantics: &FeatureSemantics) -> FeatureSemanticsSnapshot {
    FeatureSemanticsSnapshot {
        id: id.to_string(),
        label: semantics.label.clone(),
        kind: semantics.kind.clone(),
        unit: semantics.unit.clone(),
        higher_is_better: semantics.higher_is_better,
        source_id: semantics.source_id.clone(),
        source_anchor: semantics.source_anchor.clone(),
        states: semantics
            .states
            .iter()
            .map(|(state_id, state)| FeatureStateSnapshot {
                id: state_id.clone(),
                op: serde_json::to_string(&state.predicate.op)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                value: match &state.predicate.value {
                    ComparisonValue::Literal(value) => value.clone(),
                    ComparisonValue::FeatureRef { feature_ref } => {
                        serde_json::json!({ "feature_ref": feature_ref })
                    }
                },
                label: state.label.clone(),
                message: state.message.clone(),
                counterfactual_hint: state.counterfactual_hint.clone(),
            })
            .collect(),
    }
}

fn feature_source_signature(semantics: &FeatureSemantics) -> String {
    serde_json::to_string(&serde_json::json!({
        "source_id": semantics.source_id,
        "source_anchor": semantics.source_anchor,
    }))
    .unwrap_or_default()
}

fn feature_explanation_signature(semantics: &FeatureSemantics) -> String {
    serde_json::to_string(&serde_json::json!({
        "label": semantics.label,
        "kind": semantics.kind,
        "unit": semantics.unit,
        "higher_is_better": semantics.higher_is_better,
        "states": semantics.states,
    }))
    .unwrap_or_default()
}

pub(super) fn rule_feature_semantics(
    rule: &RuleDefinition,
    gate: &LogicPearlGateIr,
) -> Vec<RuleFeatureSemanticsSnapshot> {
    let semantics = feature_semantics_by_id(gate);
    expression_feature_ids(&rule.deny_when)
        .into_iter()
        .filter_map(|feature_id| {
            let feature_semantics = semantics.get(&feature_id)?;
            Some(RuleFeatureSemanticsSnapshot {
                id: feature_id,
                label: feature_semantics.label.clone(),
                source_id: feature_semantics.source_id.clone(),
                source_anchor: feature_semantics.source_anchor.clone(),
            })
        })
        .collect()
}

pub(super) fn action_rule_feature_semantics(
    rule: &ActionRuleDefinition,
    policy: &LogicPearlActionIr,
) -> Vec<RuleFeatureSemanticsSnapshot> {
    let semantics = feature_semantics_by_schema(&policy.input_schema);
    expression_feature_ids(&rule.predicate)
        .into_iter()
        .filter_map(|feature_id| {
            let feature_semantics = semantics.get(&feature_id)?;
            Some(RuleFeatureSemanticsSnapshot {
                id: feature_id,
                label: feature_semantics.label.clone(),
                source_id: feature_semantics.source_id.clone(),
                source_anchor: feature_semantics.source_anchor.clone(),
            })
        })
        .collect()
}

pub(super) fn rule_primary_feature(
    rule: &RuleDefinition,
    gate: &LogicPearlGateIr,
) -> Option<RuleFeatureSemanticsSnapshot> {
    let comparison = simple_comparison(&rule.deny_when)?;
    let semantics = feature_semantics_by_id(gate);
    let feature_semantics = semantics.get(&comparison.feature);
    Some(RuleFeatureSemanticsSnapshot {
        id: comparison.feature.clone(),
        label: feature_semantics.and_then(|semantics| semantics.label.clone()),
        source_id: feature_semantics.and_then(|semantics| semantics.source_id.clone()),
        source_anchor: feature_semantics.and_then(|semantics| semantics.source_anchor.clone()),
    })
}

pub(super) fn action_rule_primary_feature(
    rule: &ActionRuleDefinition,
    policy: &LogicPearlActionIr,
) -> Option<RuleFeatureSemanticsSnapshot> {
    let comparison = simple_comparison(&rule.predicate)?;
    let semantics = feature_semantics_by_schema(&policy.input_schema);
    let feature_semantics = semantics.get(&comparison.feature);
    Some(RuleFeatureSemanticsSnapshot {
        id: comparison.feature.clone(),
        label: feature_semantics.and_then(|semantics| semantics.label.clone()),
        source_id: feature_semantics.and_then(|semantics| semantics.source_id.clone()),
        source_anchor: feature_semantics.and_then(|semantics| semantics.source_anchor.clone()),
    })
}

pub(super) fn rule_meaning(rule: &RuleDefinition, gate: &LogicPearlGateIr) -> Option<String> {
    let comparison = simple_comparison(&rule.deny_when)?;
    let semantics = feature_semantics_by_id(gate);
    if let Some(feature_semantics) = semantics.get(&comparison.feature) {
        if let Some(state_label) = feature_semantics
            .states
            .values()
            .find(|state| state_matches_comparison(&state.predicate, comparison))
            .and_then(|state| non_empty_string(state.label.clone()))
        {
            return Some(state_label);
        }
    }
    non_empty_string(rule.label.clone())
}

pub(super) fn action_rule_meaning(
    rule: &ActionRuleDefinition,
    policy: &LogicPearlActionIr,
) -> Option<String> {
    let comparison = simple_comparison(&rule.predicate)?;
    let semantics = feature_semantics_by_schema(&policy.input_schema);
    if let Some(feature_semantics) = semantics.get(&comparison.feature) {
        if let Some(state_label) = feature_semantics
            .states
            .values()
            .find(|state| state_matches_comparison(&state.predicate, comparison))
            .and_then(|state| non_empty_string(state.label.clone()))
        {
            return Some(state_label);
        }
    }
    non_empty_string(rule.label.clone())
}

fn simple_comparison(expression: &Expression) -> Option<&logicpearl_ir::ComparisonExpression> {
    match expression {
        Expression::Comparison(comparison) => Some(comparison),
        Expression::All { .. } | Expression::Any { .. } | Expression::Not { .. } => None,
    }
}

fn state_matches_comparison(
    predicate: &logicpearl_ir::FeatureStatePredicate,
    comparison: &logicpearl_ir::ComparisonExpression,
) -> bool {
    predicate.op == comparison.op && same_comparison_value(&predicate.value, &comparison.value)
}

fn same_comparison_value(left: &ComparisonValue, right: &ComparisonValue) -> bool {
    match (left, right) {
        (
            ComparisonValue::FeatureRef {
                feature_ref: left_ref,
            },
            ComparisonValue::FeatureRef {
                feature_ref: right_ref,
            },
        ) => left_ref == right_ref,
        (ComparisonValue::Literal(left), ComparisonValue::Literal(right)) => {
            same_json_value(left, right)
        }
        _ => false,
    }
}

fn same_json_value(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => (left - right).abs() < f64::EPSILON,
        _ => left == right,
    }
}

fn non_empty_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn expression_feature_ids(expression: &Expression) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    collect_expression_feature_ids(expression, &mut features);
    features
}

fn collect_expression_feature_ids(expression: &Expression, features: &mut BTreeSet<String>) {
    match expression {
        Expression::Comparison(comparison) => {
            features.insert(comparison.feature.clone());
            if let ComparisonValue::FeatureRef { feature_ref } = &comparison.value {
                features.insert(feature_ref.clone());
            }
        }
        Expression::All { all } => {
            for child in all {
                collect_expression_feature_ids(child, features);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_expression_feature_ids(child, features);
            }
        }
        Expression::Not { expr } => collect_expression_feature_ids(expr, features),
    }
}
