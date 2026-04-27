// SPDX-License-Identifier: MIT
use super::model::{IndexedActionRule, IndexedRule, RuleSnapshot};
use super::semantics::{
    action_rule_feature_semantics, action_rule_meaning, action_rule_primary_feature,
    rule_feature_semantics, rule_meaning, rule_primary_feature,
};
use super::signatures::{semantic_action_rule_signature, semantic_rule_signature};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use serde_json::Value;

pub(super) fn index_rules(gate: &LogicPearlGateIr) -> Vec<IndexedRule<'_>> {
    gate.rules
        .iter()
        .enumerate()
        .map(|(index, rule)| IndexedRule {
            index,
            rule,
            semantic_signature: semantic_rule_signature(rule),
        })
        .collect()
}

pub(super) fn index_action_rules(policy: &LogicPearlActionIr) -> Vec<IndexedActionRule<'_>> {
    policy
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| IndexedActionRule {
            index,
            rule,
            semantic_signature: semantic_action_rule_signature(rule),
        })
        .collect()
}

pub(super) fn snapshot_rule(rule: &IndexedRule<'_>, gate: &LogicPearlGateIr) -> RuleSnapshot {
    snapshot_rule_inner(rule, gate, None)
}

pub(super) fn snapshot_rule_with_change_kind(
    rule: &IndexedRule<'_>,
    gate: &LogicPearlGateIr,
    change_kind: &str,
) -> RuleSnapshot {
    snapshot_rule_inner(rule, gate, Some(change_kind))
}

pub(super) fn snapshot_rule_inner(
    rule: &IndexedRule<'_>,
    gate: &LogicPearlGateIr,
    change_kind: Option<&str>,
) -> RuleSnapshot {
    let raw_expression = serde_json::to_value(&rule.rule.deny_when).unwrap_or(Value::Null);
    RuleSnapshot {
        id: rule.rule.id.clone(),
        bit: rule.rule.bit,
        action: None,
        priority: None,
        change_kind: change_kind.map(ToOwned::to_owned),
        feature: rule_primary_feature(rule.rule, gate),
        meaning: rule_meaning(rule.rule, gate),
        label: rule.rule.label.clone(),
        message: rule.rule.message.clone(),
        severity: rule.rule.severity.clone(),
        counterfactual_hint: rule.rule.counterfactual_hint.clone(),
        verification_status: rule.rule.verification_status.as_ref().map(|status| {
            serde_json::to_string(status)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string()
        }),
        evidence: rule.rule.evidence.clone(),
        semantic_signature: rule.semantic_signature.clone(),
        raw_expression: raw_expression.clone(),
        expression: raw_expression,
        feature_dictionary: rule_feature_semantics(rule.rule, gate),
    }
}

pub(super) fn snapshot_action_rule(
    rule: &IndexedActionRule<'_>,
    policy: &LogicPearlActionIr,
) -> RuleSnapshot {
    snapshot_action_rule_inner(rule, policy, None)
}

pub(super) fn snapshot_action_rule_with_change_kind(
    rule: &IndexedActionRule<'_>,
    policy: &LogicPearlActionIr,
    change_kind: &str,
) -> RuleSnapshot {
    snapshot_action_rule_inner(rule, policy, Some(change_kind))
}

pub(super) fn snapshot_action_rule_inner(
    rule: &IndexedActionRule<'_>,
    policy: &LogicPearlActionIr,
    change_kind: Option<&str>,
) -> RuleSnapshot {
    let raw_expression = serde_json::to_value(&rule.rule.predicate).unwrap_or(Value::Null);
    RuleSnapshot {
        id: rule.rule.id.clone(),
        bit: rule.rule.bit,
        action: Some(rule.rule.action.clone()),
        priority: Some(rule.rule.priority),
        change_kind: change_kind.map(ToOwned::to_owned),
        feature: action_rule_primary_feature(rule.rule, policy),
        meaning: action_rule_meaning(rule.rule, policy),
        label: rule.rule.label.clone(),
        message: rule.rule.message.clone(),
        severity: rule.rule.severity.clone(),
        counterfactual_hint: rule.rule.counterfactual_hint.clone(),
        verification_status: rule.rule.verification_status.as_ref().map(|status| {
            serde_json::to_string(status)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string()
        }),
        evidence: rule.rule.evidence.clone(),
        semantic_signature: rule.semantic_signature.clone(),
        raw_expression: raw_expression.clone(),
        expression: raw_expression,
        feature_dictionary: action_rule_feature_semantics(rule.rule, policy),
    }
}
