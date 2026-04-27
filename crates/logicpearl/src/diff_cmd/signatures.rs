// SPDX-License-Identifier: MIT
use logicpearl_ir::{canonical_expression_key, ActionRuleDefinition, RuleDefinition, RuleEvidence};

pub(super) fn metadata_signature(rule: &RuleDefinition) -> String {
    serde_json::to_string(&serde_json::json!({
        "label": rule.label,
        "message": rule.message,
        "severity": rule.severity,
        "counterfactual_hint": rule.counterfactual_hint,
        "verification_status": rule.verification_status,
    }))
    .unwrap_or_default()
}

pub(super) fn evidence_signature(evidence: Option<&RuleEvidence>) -> String {
    serde_json::to_string(&evidence).unwrap_or_default()
}

pub(super) fn action_metadata_signature(rule: &ActionRuleDefinition) -> String {
    serde_json::to_string(&serde_json::json!({
        "label": rule.label,
        "message": rule.message,
        "severity": rule.severity,
        "counterfactual_hint": rule.counterfactual_hint,
        "verification_status": rule.verification_status,
    }))
    .unwrap_or_default()
}

pub(super) fn semantic_rule_signature(rule: &RuleDefinition) -> String {
    format!(
        "{}|{}",
        serde_json::to_string(&rule.kind).unwrap_or_default(),
        canonical_expression_key(&rule.deny_when)
    )
}

pub(super) fn semantic_action_rule_signature(rule: &ActionRuleDefinition) -> String {
    format!(
        "{}|{}",
        rule.action,
        canonical_expression_key(&rule.predicate)
    )
}
