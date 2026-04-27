// SPDX-License-Identifier: MIT
use super::model::*;
use super::semantics::{
    diff_feature_dictionaries, diff_feature_dictionaries_for_schemas, diff_feature_sets,
};
use super::signatures::{action_metadata_signature, evidence_signature, metadata_signature};
use super::snapshots::{
    index_action_rules, index_rules, snapshot_action_rule, snapshot_action_rule_with_change_kind,
    snapshot_rule, snapshot_rule_with_change_kind,
};
use crate::{artifact_cmd, Result};
use logicpearl_ir::{canonical_expression_key, LogicPearlActionIr, LogicPearlGateIr};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn diff_gates(
    old_gate: &LogicPearlGateIr,
    new_gate: &LogicPearlGateIr,
    old_resolved: &artifact_cmd::ResolvedArtifactInput,
    new_resolved: &artifact_cmd::ResolvedArtifactInput,
) -> Result<ArtifactDiffReport> {
    let old_features = old_gate
        .input_schema
        .features
        .iter()
        .map(|feature| feature.id.clone())
        .collect::<BTreeSet<_>>();
    let new_features = new_gate
        .input_schema
        .features
        .iter()
        .map(|feature| feature.id.clone())
        .collect::<BTreeSet<_>>();

    let feature_changes = FeatureChanges {
        added: new_features.difference(&old_features).cloned().collect(),
        removed: old_features.difference(&new_features).cloned().collect(),
    };
    let feature_dictionary_changes = diff_feature_dictionaries(old_gate, new_gate);

    let old_indexed = index_rules(old_gate);
    let new_indexed = index_rules(new_gate);

    let mut old_remaining = old_indexed
        .iter()
        .map(|rule| rule.index)
        .collect::<BTreeSet<_>>();
    let mut new_remaining = new_indexed
        .iter()
        .map(|rule| rule.index)
        .collect::<BTreeSet<_>>();

    let mut changed_rules = Vec::new();
    let mut reordered_rules = Vec::new();
    let mut evidence_changed_rules = Vec::new();

    let old_by_id = old_indexed
        .iter()
        .map(|rule| (rule.rule.id.clone(), rule.index))
        .collect::<BTreeMap<_, _>>();
    let new_by_id = new_indexed
        .iter()
        .map(|rule| (rule.rule.id.clone(), rule.index))
        .collect::<BTreeMap<_, _>>();

    for rule_id in old_by_id
        .keys()
        .filter(|rule_id| new_by_id.contains_key(*rule_id))
    {
        let old_idx = old_by_id[rule_id];
        let new_idx = new_by_id[rule_id];
        let old_rule = &old_indexed[old_idx];
        let new_rule = &new_indexed[new_idx];
        old_remaining.remove(&old_idx);
        new_remaining.remove(&new_idx);

        if old_rule.semantic_signature != new_rule.semantic_signature {
            changed_rules.push(RuleChange {
                rule_id: rule_id.clone(),
                change_kind: "semantic_change".to_string(),
                old_rule: snapshot_rule(old_rule, old_gate),
                new_rule: snapshot_rule(new_rule, new_gate),
            });
        } else if old_rule.rule.bit != new_rule.rule.bit
            || metadata_signature(old_rule.rule) != metadata_signature(new_rule.rule)
        {
            reordered_rules.push(RulePairChange {
                old_rule: snapshot_rule(old_rule, old_gate),
                new_rule: snapshot_rule(new_rule, new_gate),
                change_kind: if old_rule.rule.bit != new_rule.rule.bit {
                    "bit_reordered".to_string()
                } else {
                    "metadata_changed".to_string()
                },
            });
        } else if evidence_signature(old_rule.rule.evidence.as_ref())
            != evidence_signature(new_rule.rule.evidence.as_ref())
        {
            evidence_changed_rules.push(RuleChange {
                rule_id: rule_id.clone(),
                change_kind: "evidence_changed".to_string(),
                old_rule: snapshot_rule(old_rule, old_gate),
                new_rule: snapshot_rule(new_rule, new_gate),
            });
        }
    }

    let mut old_by_sig = BTreeMap::<String, Vec<usize>>::new();
    for idx in &old_remaining {
        old_by_sig
            .entry(old_indexed[*idx].semantic_signature.clone())
            .or_default()
            .push(*idx);
    }
    let mut new_by_sig = BTreeMap::<String, Vec<usize>>::new();
    for idx in &new_remaining {
        new_by_sig
            .entry(new_indexed[*idx].semantic_signature.clone())
            .or_default()
            .push(*idx);
    }

    for signature in old_by_sig
        .keys()
        .filter(|signature| new_by_sig.contains_key(*signature))
        .cloned()
        .collect::<Vec<_>>()
    {
        let old_list = old_by_sig
            .get_mut(&signature)
            .expect("old signature exists");
        let new_list = new_by_sig
            .get_mut(&signature)
            .expect("new signature exists");
        old_list.sort_by_key(|idx| old_indexed[*idx].rule.bit);
        new_list.sort_by_key(|idx| new_indexed[*idx].rule.bit);
        let pair_count = old_list.len().min(new_list.len());
        for _ in 0..pair_count {
            let old_idx = old_list.remove(0);
            let new_idx = new_list.remove(0);
            old_remaining.remove(&old_idx);
            new_remaining.remove(&new_idx);
            reordered_rules.push(RulePairChange {
                old_rule: snapshot_rule(&old_indexed[old_idx], old_gate),
                new_rule: snapshot_rule(&new_indexed[new_idx], new_gate),
                change_kind: "reordered_or_renamed".to_string(),
            });
        }
    }

    let added_rules = new_remaining
        .iter()
        .map(|idx| snapshot_rule_with_change_kind(&new_indexed[*idx], new_gate, "added_rule"))
        .collect::<Vec<_>>();
    let removed_rules = old_remaining
        .iter()
        .map(|idx| snapshot_rule_with_change_kind(&old_indexed[*idx], old_gate, "removed_rule"))
        .collect::<Vec<_>>();

    let learned_rule_changed =
        !changed_rules.is_empty() || !added_rules.is_empty() || !removed_rules.is_empty();
    let rule_explanation_changed = reordered_rules
        .iter()
        .any(|change| change.change_kind == "metadata_changed")
        || feature_dictionary_changes
            .changed
            .iter()
            .any(|change| change.explanation_changed)
        || !feature_dictionary_changes.added.is_empty()
        || !feature_dictionary_changes.removed.is_empty();
    let source_schema_changed = !feature_changes.added.is_empty()
        || !feature_changes.removed.is_empty()
        || feature_dictionary_changes
            .changed
            .iter()
            .any(|change| change.source_changed);
    let summary = DiffSummary {
        source_schema_changed,
        learned_rule_changed,
        rule_explanation_changed,
        rule_evidence_changed: !evidence_changed_rules.is_empty(),
        changed_rules: changed_rules.len(),
        reordered_rules: reordered_rules.len(),
        evidence_changed_rules: evidence_changed_rules.len(),
        added_rules: added_rules.len(),
        removed_rules: removed_rules.len(),
    };

    Ok(ArtifactDiffReport {
        old_artifact: old_resolved.artifact_dir.display().to_string(),
        new_artifact: new_resolved.artifact_dir.display().to_string(),
        old_gate_id: old_gate.gate_id.clone(),
        new_gate_id: new_gate.gate_id.clone(),
        feature_changes,
        feature_dictionary_changes,
        summary,
        changed_rules,
        reordered_rules,
        evidence_changed_rules,
        added_rules,
        removed_rules,
    })
}

pub(super) fn diff_action_policies(
    old_policy: &LogicPearlActionIr,
    new_policy: &LogicPearlActionIr,
    old_resolved: &artifact_cmd::ResolvedArtifactInput,
    new_resolved: &artifact_cmd::ResolvedArtifactInput,
) -> Result<ActionPolicyDiffReport> {
    let feature_changes = diff_feature_sets(&old_policy.input_schema, &new_policy.input_schema);
    let feature_dictionary_changes =
        diff_feature_dictionaries_for_schemas(&old_policy.input_schema, &new_policy.input_schema);
    let old_actions = old_policy.actions.iter().cloned().collect::<BTreeSet<_>>();
    let new_actions = new_policy.actions.iter().cloned().collect::<BTreeSet<_>>();
    let action_changes = ActionChanges {
        added: new_actions.difference(&old_actions).cloned().collect(),
        removed: old_actions.difference(&new_actions).cloned().collect(),
    };

    let old_indexed = index_action_rules(old_policy);
    let new_indexed = index_action_rules(new_policy);
    let mut old_remaining = old_indexed
        .iter()
        .map(|rule| rule.index)
        .collect::<BTreeSet<_>>();
    let mut new_remaining = new_indexed
        .iter()
        .map(|rule| rule.index)
        .collect::<BTreeSet<_>>();

    let mut changed_rules = Vec::new();
    let mut reordered_rules = Vec::new();
    let mut evidence_changed_rules = Vec::new();

    let old_by_id = old_indexed
        .iter()
        .map(|rule| (rule.rule.id.clone(), rule.index))
        .collect::<BTreeMap<_, _>>();
    let new_by_id = new_indexed
        .iter()
        .map(|rule| (rule.rule.id.clone(), rule.index))
        .collect::<BTreeMap<_, _>>();

    for rule_id in old_by_id
        .keys()
        .filter(|rule_id| new_by_id.contains_key(*rule_id))
    {
        let old_idx = old_by_id[rule_id];
        let new_idx = new_by_id[rule_id];
        let old_rule = &old_indexed[old_idx];
        let new_rule = &new_indexed[new_idx];
        old_remaining.remove(&old_idx);
        new_remaining.remove(&new_idx);

        if canonical_expression_key(&old_rule.rule.predicate)
            != canonical_expression_key(&new_rule.rule.predicate)
        {
            changed_rules.push(RuleChange {
                rule_id: rule_id.clone(),
                change_kind: "rule_predicate_changed".to_string(),
                old_rule: snapshot_action_rule(old_rule, old_policy),
                new_rule: snapshot_action_rule(new_rule, new_policy),
            });
        } else if old_rule.rule.action != new_rule.rule.action {
            changed_rules.push(RuleChange {
                rule_id: rule_id.clone(),
                change_kind: "rule_action_changed".to_string(),
                old_rule: snapshot_action_rule(old_rule, old_policy),
                new_rule: snapshot_action_rule(new_rule, new_policy),
            });
        } else if old_rule.rule.priority != new_rule.rule.priority
            || old_rule.rule.bit != new_rule.rule.bit
            || action_metadata_signature(old_rule.rule) != action_metadata_signature(new_rule.rule)
        {
            reordered_rules.push(RulePairChange {
                old_rule: snapshot_action_rule(old_rule, old_policy),
                new_rule: snapshot_action_rule(new_rule, new_policy),
                change_kind: if old_rule.rule.priority != new_rule.rule.priority {
                    "rule_priority_changed".to_string()
                } else if old_rule.rule.bit != new_rule.rule.bit {
                    "bit_reordered".to_string()
                } else {
                    "metadata_changed".to_string()
                },
            });
        } else if evidence_signature(old_rule.rule.evidence.as_ref())
            != evidence_signature(new_rule.rule.evidence.as_ref())
        {
            evidence_changed_rules.push(RuleChange {
                rule_id: rule_id.clone(),
                change_kind: "evidence_changed".to_string(),
                old_rule: snapshot_action_rule(old_rule, old_policy),
                new_rule: snapshot_action_rule(new_rule, new_policy),
            });
        }
    }

    let mut old_by_sig = BTreeMap::<String, Vec<usize>>::new();
    for idx in &old_remaining {
        old_by_sig
            .entry(old_indexed[*idx].semantic_signature.clone())
            .or_default()
            .push(*idx);
    }
    let mut new_by_sig = BTreeMap::<String, Vec<usize>>::new();
    for idx in &new_remaining {
        new_by_sig
            .entry(new_indexed[*idx].semantic_signature.clone())
            .or_default()
            .push(*idx);
    }

    for signature in old_by_sig
        .keys()
        .filter(|signature| new_by_sig.contains_key(*signature))
        .cloned()
        .collect::<Vec<_>>()
    {
        let old_list = old_by_sig
            .get_mut(&signature)
            .expect("old signature exists");
        let new_list = new_by_sig
            .get_mut(&signature)
            .expect("new signature exists");
        old_list.sort_by_key(|idx| old_indexed[*idx].rule.bit);
        new_list.sort_by_key(|idx| new_indexed[*idx].rule.bit);
        let pair_count = old_list.len().min(new_list.len());
        for _ in 0..pair_count {
            let old_idx = old_list.remove(0);
            let new_idx = new_list.remove(0);
            old_remaining.remove(&old_idx);
            new_remaining.remove(&new_idx);
            reordered_rules.push(RulePairChange {
                old_rule: snapshot_action_rule(&old_indexed[old_idx], old_policy),
                new_rule: snapshot_action_rule(&new_indexed[new_idx], new_policy),
                change_kind: if old_indexed[old_idx].rule.priority
                    != new_indexed[new_idx].rule.priority
                {
                    "rule_priority_changed".to_string()
                } else if old_indexed[old_idx].rule.bit != new_indexed[new_idx].rule.bit {
                    "bit_reordered".to_string()
                } else {
                    "reordered_or_renamed".to_string()
                },
            });
        }
    }

    let added_rules = new_remaining
        .iter()
        .map(|idx| {
            snapshot_action_rule_with_change_kind(&new_indexed[*idx], new_policy, "added_rule")
        })
        .collect::<Vec<_>>();
    let removed_rules = old_remaining
        .iter()
        .map(|idx| {
            snapshot_action_rule_with_change_kind(&old_indexed[*idx], old_policy, "removed_rule")
        })
        .collect::<Vec<_>>();

    let action_set_changed = !action_changes.added.is_empty() || !action_changes.removed.is_empty();
    let default_action_changed = old_policy.default_action != new_policy.default_action;
    let no_match_action_changed = old_policy.no_match_action != new_policy.no_match_action;
    let rule_predicate_changed = changed_rules
        .iter()
        .any(|change| change.change_kind == "rule_predicate_changed");
    let rule_action_changed = changed_rules
        .iter()
        .any(|change| change.change_kind == "rule_action_changed");
    let rule_priority_changed = reordered_rules
        .iter()
        .any(|change| change.change_kind == "rule_priority_changed");
    let learned_rule_changed = rule_predicate_changed
        || rule_action_changed
        || !added_rules.is_empty()
        || !removed_rules.is_empty();
    let rule_explanation_changed = reordered_rules
        .iter()
        .any(|change| change.change_kind == "metadata_changed")
        || feature_dictionary_changes
            .changed
            .iter()
            .any(|change| change.explanation_changed)
        || !feature_dictionary_changes.added.is_empty()
        || !feature_dictionary_changes.removed.is_empty();
    let source_schema_changed = !feature_changes.added.is_empty()
        || !feature_changes.removed.is_empty()
        || feature_dictionary_changes
            .changed
            .iter()
            .any(|change| change.source_changed);
    let summary = ActionDiffSummary {
        source_schema_changed,
        action_set_changed,
        default_action_changed,
        no_match_action_changed,
        rule_predicate_changed,
        rule_priority_changed,
        learned_rule_changed,
        rule_explanation_changed,
        rule_evidence_changed: !evidence_changed_rules.is_empty(),
        changed_rules: changed_rules.len(),
        reordered_rules: reordered_rules.len(),
        evidence_changed_rules: evidence_changed_rules.len(),
        added_rules: added_rules.len(),
        removed_rules: removed_rules.len(),
    };

    Ok(ActionPolicyDiffReport {
        old_artifact: old_resolved.artifact_dir.display().to_string(),
        new_artifact: new_resolved.artifact_dir.display().to_string(),
        old_action_policy_id: old_policy.action_policy_id.clone(),
        new_action_policy_id: new_policy.action_policy_id.clone(),
        old_default_action: old_policy.default_action.clone(),
        new_default_action: new_policy.default_action.clone(),
        old_no_match_action: old_policy.no_match_action.clone(),
        new_no_match_action: new_policy.no_match_action.clone(),
        action_changes,
        feature_changes,
        feature_dictionary_changes,
        summary,
        changed_rules,
        reordered_rules,
        evidence_changed_rules,
        added_rules,
        removed_rules,
    })
}
