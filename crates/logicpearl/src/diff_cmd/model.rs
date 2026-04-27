// SPDX-License-Identifier: MIT
use logicpearl_ir::{
    ActionRuleDefinition, LogicPearlActionIr, LogicPearlGateIr, RuleDefinition, RuleEvidence,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub(super) struct ArtifactDiffReport {
    pub(super) old_artifact: String,
    pub(super) new_artifact: String,
    pub(super) old_gate_id: String,
    pub(super) new_gate_id: String,
    pub(super) feature_changes: FeatureChanges,
    pub(super) feature_dictionary_changes: FeatureDictionaryChanges,
    pub(super) summary: DiffSummary,
    pub(super) changed_rules: Vec<RuleChange>,
    pub(super) reordered_rules: Vec<RulePairChange>,
    pub(super) evidence_changed_rules: Vec<RuleChange>,
    pub(super) added_rules: Vec<RuleSnapshot>,
    pub(super) removed_rules: Vec<RuleSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ActionPolicyDiffReport {
    pub(super) old_artifact: String,
    pub(super) new_artifact: String,
    pub(super) old_action_policy_id: String,
    pub(super) new_action_policy_id: String,
    pub(super) old_default_action: String,
    pub(super) new_default_action: String,
    pub(super) old_no_match_action: Option<String>,
    pub(super) new_no_match_action: Option<String>,
    pub(super) action_changes: ActionChanges,
    pub(super) feature_changes: FeatureChanges,
    pub(super) feature_dictionary_changes: FeatureDictionaryChanges,
    pub(super) summary: ActionDiffSummary,
    pub(super) changed_rules: Vec<RuleChange>,
    pub(super) reordered_rules: Vec<RulePairChange>,
    pub(super) evidence_changed_rules: Vec<RuleChange>,
    pub(super) added_rules: Vec<RuleSnapshot>,
    pub(super) removed_rules: Vec<RuleSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ActionChanges {
    pub(super) added: Vec<String>,
    pub(super) removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FeatureChanges {
    pub(super) added: Vec<String>,
    pub(super) removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FeatureDictionaryChanges {
    pub(super) added: Vec<FeatureSemanticsSnapshot>,
    pub(super) removed: Vec<FeatureSemanticsSnapshot>,
    pub(super) changed: Vec<FeatureSemanticsChange>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FeatureSemanticsChange {
    pub(super) id: String,
    pub(super) source_changed: bool,
    pub(super) explanation_changed: bool,
    pub(super) old: FeatureSemanticsSnapshot,
    pub(super) new: FeatureSemanticsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FeatureSemanticsSnapshot {
    pub(super) id: String,
    pub(super) label: Option<String>,
    pub(super) kind: Option<String>,
    pub(super) unit: Option<String>,
    pub(super) higher_is_better: Option<bool>,
    pub(super) source_id: Option<String>,
    pub(super) source_anchor: Option<String>,
    pub(super) states: Vec<FeatureStateSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FeatureStateSnapshot {
    pub(super) id: String,
    pub(super) op: String,
    pub(super) value: Value,
    pub(super) label: Option<String>,
    pub(super) message: Option<String>,
    pub(super) counterfactual_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DiffSummary {
    pub(super) source_schema_changed: bool,
    pub(super) learned_rule_changed: bool,
    pub(super) rule_explanation_changed: bool,
    pub(super) rule_evidence_changed: bool,
    pub(super) changed_rules: usize,
    pub(super) reordered_rules: usize,
    pub(super) evidence_changed_rules: usize,
    pub(super) added_rules: usize,
    pub(super) removed_rules: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ActionDiffSummary {
    pub(super) source_schema_changed: bool,
    pub(super) action_set_changed: bool,
    pub(super) default_action_changed: bool,
    pub(super) no_match_action_changed: bool,
    pub(super) rule_predicate_changed: bool,
    pub(super) rule_priority_changed: bool,
    pub(super) learned_rule_changed: bool,
    pub(super) rule_explanation_changed: bool,
    pub(super) rule_evidence_changed: bool,
    pub(super) changed_rules: usize,
    pub(super) reordered_rules: usize,
    pub(super) evidence_changed_rules: usize,
    pub(super) added_rules: usize,
    pub(super) removed_rules: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RuleSnapshot {
    pub(super) id: String,
    pub(super) bit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) change_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) feature: Option<RuleFeatureSemanticsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) meaning: Option<String>,
    pub(super) label: Option<String>,
    pub(super) message: Option<String>,
    pub(super) severity: Option<String>,
    pub(super) counterfactual_hint: Option<String>,
    pub(super) verification_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) evidence: Option<RuleEvidence>,
    pub(super) semantic_signature: String,
    pub(super) raw_expression: Value,
    pub(super) expression: Value,
    pub(super) feature_dictionary: Vec<RuleFeatureSemanticsSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RuleFeatureSemanticsSnapshot {
    pub(super) id: String,
    pub(super) label: Option<String>,
    pub(super) source_id: Option<String>,
    pub(super) source_anchor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RuleChange {
    pub(super) rule_id: String,
    pub(super) change_kind: String,
    pub(super) old_rule: RuleSnapshot,
    pub(super) new_rule: RuleSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RulePairChange {
    pub(super) old_rule: RuleSnapshot,
    pub(super) new_rule: RuleSnapshot,
    pub(super) change_kind: String,
}

#[derive(Debug, Clone)]
pub(super) struct IndexedRule<'a> {
    pub(super) index: usize,
    pub(super) rule: &'a RuleDefinition,
    pub(super) semantic_signature: String,
}

#[derive(Debug, Clone)]
pub(super) struct IndexedActionRule<'a> {
    pub(super) index: usize,
    pub(super) rule: &'a ActionRuleDefinition,
    pub(super) semantic_signature: String,
}

pub(super) enum DiffPearl {
    Gate(LogicPearlGateIr),
    Action(LogicPearlActionIr),
}
