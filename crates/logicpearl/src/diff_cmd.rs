use super::*;
use logicpearl_ir::{
    canonical_expression_key, ActionRuleDefinition, ComparisonValue, Expression, FeatureSemantics,
    InputSchema, LogicPearlActionIr, LogicPearlGateIr, RuleDefinition,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
struct ArtifactDiffReport {
    old_artifact: String,
    new_artifact: String,
    old_gate_id: String,
    new_gate_id: String,
    feature_changes: FeatureChanges,
    feature_dictionary_changes: FeatureDictionaryChanges,
    summary: DiffSummary,
    changed_rules: Vec<RuleChange>,
    reordered_rules: Vec<RulePairChange>,
    added_rules: Vec<RuleSnapshot>,
    removed_rules: Vec<RuleSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct ActionPolicyDiffReport {
    old_artifact: String,
    new_artifact: String,
    old_action_policy_id: String,
    new_action_policy_id: String,
    old_default_action: String,
    new_default_action: String,
    action_changes: ActionChanges,
    feature_changes: FeatureChanges,
    feature_dictionary_changes: FeatureDictionaryChanges,
    summary: ActionDiffSummary,
    changed_rules: Vec<RuleChange>,
    reordered_rules: Vec<RulePairChange>,
    added_rules: Vec<RuleSnapshot>,
    removed_rules: Vec<RuleSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct ActionChanges {
    added: Vec<String>,
    removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureChanges {
    added: Vec<String>,
    removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureDictionaryChanges {
    added: Vec<FeatureSemanticsSnapshot>,
    removed: Vec<FeatureSemanticsSnapshot>,
    changed: Vec<FeatureSemanticsChange>,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureSemanticsChange {
    id: String,
    source_changed: bool,
    explanation_changed: bool,
    old: FeatureSemanticsSnapshot,
    new: FeatureSemanticsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureSemanticsSnapshot {
    id: String,
    label: Option<String>,
    kind: Option<String>,
    unit: Option<String>,
    higher_is_better: Option<bool>,
    source_id: Option<String>,
    source_anchor: Option<String>,
    states: Vec<FeatureStateSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureStateSnapshot {
    id: String,
    op: String,
    value: Value,
    label: Option<String>,
    message: Option<String>,
    counterfactual_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DiffSummary {
    source_schema_changed: bool,
    learned_rule_changed: bool,
    rule_explanation_changed: bool,
    changed_rules: usize,
    reordered_rules: usize,
    added_rules: usize,
    removed_rules: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ActionDiffSummary {
    source_schema_changed: bool,
    action_set_changed: bool,
    default_action_changed: bool,
    rule_predicate_changed: bool,
    rule_priority_changed: bool,
    learned_rule_changed: bool,
    rule_explanation_changed: bool,
    changed_rules: usize,
    reordered_rules: usize,
    added_rules: usize,
    removed_rules: usize,
}

#[derive(Debug, Clone, Serialize)]
struct RuleSnapshot {
    id: String,
    bit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    feature: Option<RuleFeatureSemanticsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meaning: Option<String>,
    label: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    counterfactual_hint: Option<String>,
    verification_status: Option<String>,
    semantic_signature: String,
    raw_expression: Value,
    expression: Value,
    feature_dictionary: Vec<RuleFeatureSemanticsSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct RuleFeatureSemanticsSnapshot {
    id: String,
    label: Option<String>,
    source_id: Option<String>,
    source_anchor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RuleChange {
    rule_id: String,
    change_kind: String,
    old_rule: RuleSnapshot,
    new_rule: RuleSnapshot,
}

#[derive(Debug, Clone, Serialize)]
struct RulePairChange {
    old_rule: RuleSnapshot,
    new_rule: RuleSnapshot,
    change_kind: String,
}

#[derive(Debug, Clone)]
struct IndexedRule<'a> {
    index: usize,
    rule: &'a RuleDefinition,
    semantic_signature: String,
}

#[derive(Debug, Clone)]
struct IndexedActionRule<'a> {
    index: usize,
    rule: &'a ActionRuleDefinition,
    semantic_signature: String,
}

enum DiffPearl {
    Gate(LogicPearlGateIr),
    Action(LogicPearlActionIr),
}

pub(crate) fn run_diff(args: DiffArgs) -> Result<()> {
    let old_resolved = resolve_artifact_input(&args.old_artifact)?;
    let new_resolved = resolve_artifact_input(&args.new_artifact)?;
    let old_pearl = load_diff_pearl(&old_resolved.pearl_ir).wrap_err("failed to load old pearl")?;
    let new_pearl = load_diff_pearl(&new_resolved.pearl_ir).wrap_err("failed to load new pearl")?;

    match (old_pearl, new_pearl) {
        (DiffPearl::Gate(old_gate), DiffPearl::Gate(new_gate)) => {
            let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
                .wrap_err("failed to diff artifacts")?;
            render_gate_diff_report(&report, args.json)
        }
        (DiffPearl::Action(old_policy), DiffPearl::Action(new_policy)) => {
            let report =
                diff_action_policies(&old_policy, &new_policy, &old_resolved, &new_resolved)
                    .wrap_err("failed to diff action policies")?;
            render_action_diff_report(&report, args.json)
        }
        _ => Err(guidance(
            "cannot diff different decision artifact kinds",
            "Diff two gate artifacts or two action-policy artifacts.",
        )),
    }
}

fn load_diff_pearl(path: &PathBuf) -> Result<DiffPearl> {
    let payload = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err("failed to read pearl IR")?;
    let value: Value = serde_json::from_str(&payload)
        .into_diagnostic()
        .wrap_err("pearl IR is not valid JSON")?;
    if value.get("action_policy_id").is_some() {
        return LogicPearlActionIr::from_json_str(&payload)
            .into_diagnostic()
            .map(DiffPearl::Action)
            .wrap_err("pearl IR is not a valid action policy");
    }
    LogicPearlGateIr::from_json_str(&payload)
        .into_diagnostic()
        .map(DiffPearl::Gate)
        .wrap_err("pearl IR is not a valid gate")
}

fn render_gate_diff_report(report: &ArtifactDiffReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", "LogicPearl Diff".bold().bright_blue());
        println!("  {} {}", "Old".bright_black(), report.old_artifact);
        println!("  {} {}", "New".bright_black(), report.new_artifact);
        if report.old_gate_id != report.new_gate_id {
            println!(
                "  {} {} -> {}",
                "Gate IDs".bright_black(),
                report.old_gate_id,
                report.new_gate_id
            );
        } else {
            println!("  {} {}", "Gate ID".bright_black(), report.old_gate_id);
        }
        println!(
            "  {} +{} / -{}",
            "Features".bright_black(),
            report.feature_changes.added.len(),
            report.feature_changes.removed.len()
        );
        println!(
            "  {} changed={} reordered={} added={} removed={}",
            "Rules".bright_black(),
            report.summary.changed_rules,
            report.summary.reordered_rules,
            report.summary.added_rules,
            report.summary.removed_rules
        );
        println!(
            "  {} source_schema={} learned_rule={} rule_explanation={}",
            "Change classes".bright_black(),
            report.summary.source_schema_changed,
            report.summary.learned_rule_changed,
            report.summary.rule_explanation_changed
        );

        render_changed_rules("Changed Rules", &report.changed_rules);
        render_reordered_rules("Reordered Or Renamed Rules", &report.reordered_rules);
        render_rule_snapshots("Added Rules", &report.added_rules, "Added");
        render_rule_snapshots("Removed Rules", &report.removed_rules, "Removed");
    }
    Ok(())
}

fn render_action_diff_report(report: &ActionPolicyDiffReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", "LogicPearl Action Diff".bold().bright_blue());
        println!("  {} {}", "Old".bright_black(), report.old_artifact);
        println!("  {} {}", "New".bright_black(), report.new_artifact);
        if report.old_action_policy_id != report.new_action_policy_id {
            println!(
                "  {} {} -> {}",
                "Action policy IDs".bright_black(),
                report.old_action_policy_id,
                report.new_action_policy_id
            );
        } else {
            println!(
                "  {} {}",
                "Action policy ID".bright_black(),
                report.old_action_policy_id
            );
        }
        if report.old_default_action != report.new_default_action {
            println!(
                "  {} {} -> {}",
                "Default action".bright_black(),
                report.old_default_action,
                report.new_default_action
            );
        } else {
            println!(
                "  {} {}",
                "Default action".bright_black(),
                report.old_default_action
            );
        }
        println!(
            "  {} +{} / -{}",
            "Actions".bright_black(),
            report.action_changes.added.len(),
            report.action_changes.removed.len()
        );
        println!(
            "  {} +{} / -{}",
            "Features".bright_black(),
            report.feature_changes.added.len(),
            report.feature_changes.removed.len()
        );
        println!(
            "  {} changed={} reordered={} added={} removed={}",
            "Rules".bright_black(),
            report.summary.changed_rules,
            report.summary.reordered_rules,
            report.summary.added_rules,
            report.summary.removed_rules
        );
        println!(
            "  {} source_schema={} action_set={} default_action={} rule_predicate={} rule_priority={} learned_rule={} rule_explanation={}",
            "Change classes".bright_black(),
            report.summary.source_schema_changed,
            report.summary.action_set_changed,
            report.summary.default_action_changed,
            report.summary.rule_predicate_changed,
            report.summary.rule_priority_changed,
            report.summary.learned_rule_changed,
            report.summary.rule_explanation_changed
        );

        render_changed_rules("Changed Rules", &report.changed_rules);
        render_reordered_rules("Reordered Or Renamed Rules", &report.reordered_rules);
        render_rule_snapshots("Added Rules", &report.added_rules, "Added");
        render_rule_snapshots("Removed Rules", &report.removed_rules, "Removed");
    }
    Ok(())
}

fn render_changed_rules(header: &str, changes: &[RuleChange]) {
    if changes.is_empty() {
        return;
    }
    println!();
    println!("{}", header.bold());
    for change in changes {
        println!(
            "  {} {} (bit {} -> {})",
            change.change_kind.bold(),
            change.rule_id,
            change.old_rule.bit,
            change.new_rule.bit
        );
        println!(
            "    {} {}",
            "Old".bright_black(),
            rule_display_meaning(&change.old_rule)
        );
        render_rule_feature(&change.old_rule);
        println!(
            "    {} {}",
            "New".bright_black(),
            rule_display_meaning(&change.new_rule)
        );
        render_rule_feature(&change.new_rule);
    }
}

fn render_reordered_rules(header: &str, changes: &[RulePairChange]) {
    if changes.is_empty() {
        return;
    }
    println!();
    println!("{}", header.bold());
    for change in changes {
        println!(
            "  {} {}:{} -> {}:{}",
            change.change_kind.bold(),
            change.old_rule.id,
            change.old_rule.bit,
            change.new_rule.id,
            change.new_rule.bit
        );
        println!(
            "    {} {}",
            "Semantics".bright_black(),
            rule_display_meaning(&change.new_rule)
        );
        render_rule_feature(&change.new_rule);
    }
}

fn render_rule_snapshots(header: &str, rules: &[RuleSnapshot], prefix: &str) {
    if rules.is_empty() {
        return;
    }
    println!();
    println!("{}", header.bold());
    for rule in rules {
        println!("  {} {}:{}", prefix.bold(), rule.id, rule.bit);
        println!(
            "    {} {}",
            "Semantics".bright_black(),
            rule_display_meaning(rule)
        );
        render_rule_feature(rule);
    }
}

fn rule_display_meaning(rule: &RuleSnapshot) -> &str {
    rule.meaning
        .as_deref()
        .or(rule.label.as_deref())
        .unwrap_or(&rule.semantic_signature)
}

fn render_rule_feature(rule: &RuleSnapshot) {
    match (&rule.action, rule.priority) {
        (Some(action), Some(priority)) => println!(
            "    {} {} (priority {})",
            "Action".bright_black(),
            action,
            priority
        ),
        (Some(action), None) => println!("    {} {}", "Action".bright_black(), action),
        _ => {}
    }
    let Some(feature) = &rule.feature else {
        return;
    };
    let feature_label = feature.label.as_deref().unwrap_or(&feature.id);
    match (&feature.source_id, &feature.source_anchor) {
        (Some(source_id), Some(source_anchor)) => println!(
            "    {} {} ({}, {})",
            "Feature".bright_black(),
            feature_label,
            source_id,
            source_anchor
        ),
        (Some(source_id), None) => println!(
            "    {} {} ({})",
            "Feature".bright_black(),
            feature_label,
            source_id
        ),
        _ => println!("    {} {}", "Feature".bright_black(), feature_label),
    }
}

fn diff_gates(
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
        changed_rules: changed_rules.len(),
        reordered_rules: reordered_rules.len(),
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
        added_rules,
        removed_rules,
    })
}

fn diff_action_policies(
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
        rule_predicate_changed,
        rule_priority_changed,
        learned_rule_changed,
        rule_explanation_changed,
        changed_rules: changed_rules.len(),
        reordered_rules: reordered_rules.len(),
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
        action_changes,
        feature_changes,
        feature_dictionary_changes,
        summary,
        changed_rules,
        reordered_rules,
        added_rules,
        removed_rules,
    })
}

fn index_rules(gate: &LogicPearlGateIr) -> Vec<IndexedRule<'_>> {
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

fn index_action_rules(policy: &LogicPearlActionIr) -> Vec<IndexedActionRule<'_>> {
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

fn snapshot_rule(rule: &IndexedRule<'_>, gate: &LogicPearlGateIr) -> RuleSnapshot {
    snapshot_rule_inner(rule, gate, None)
}

fn snapshot_rule_with_change_kind(
    rule: &IndexedRule<'_>,
    gate: &LogicPearlGateIr,
    change_kind: &str,
) -> RuleSnapshot {
    snapshot_rule_inner(rule, gate, Some(change_kind))
}

fn snapshot_rule_inner(
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
        semantic_signature: rule.semantic_signature.clone(),
        raw_expression: raw_expression.clone(),
        expression: raw_expression,
        feature_dictionary: rule_feature_semantics(rule.rule, gate),
    }
}

fn snapshot_action_rule(rule: &IndexedActionRule<'_>, policy: &LogicPearlActionIr) -> RuleSnapshot {
    snapshot_action_rule_inner(rule, policy, None)
}

fn snapshot_action_rule_with_change_kind(
    rule: &IndexedActionRule<'_>,
    policy: &LogicPearlActionIr,
    change_kind: &str,
) -> RuleSnapshot {
    snapshot_action_rule_inner(rule, policy, Some(change_kind))
}

fn snapshot_action_rule_inner(
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
        semantic_signature: rule.semantic_signature.clone(),
        raw_expression: raw_expression.clone(),
        expression: raw_expression,
        feature_dictionary: action_rule_feature_semantics(rule.rule, policy),
    }
}

fn diff_feature_dictionaries(
    old_gate: &LogicPearlGateIr,
    new_gate: &LogicPearlGateIr,
) -> FeatureDictionaryChanges {
    diff_feature_dictionaries_for_schemas(&old_gate.input_schema, &new_gate.input_schema)
}

fn diff_feature_sets(old_schema: &InputSchema, new_schema: &InputSchema) -> FeatureChanges {
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

fn diff_feature_dictionaries_for_schemas(
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

fn rule_feature_semantics(
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

fn action_rule_feature_semantics(
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

fn rule_primary_feature(
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

fn action_rule_primary_feature(
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

fn rule_meaning(rule: &RuleDefinition, gate: &LogicPearlGateIr) -> Option<String> {
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

fn action_rule_meaning(rule: &ActionRuleDefinition, policy: &LogicPearlActionIr) -> Option<String> {
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

fn metadata_signature(rule: &RuleDefinition) -> String {
    serde_json::to_string(&serde_json::json!({
        "label": rule.label,
        "message": rule.message,
        "severity": rule.severity,
        "counterfactual_hint": rule.counterfactual_hint,
        "verification_status": rule.verification_status,
    }))
    .unwrap_or_default()
}

fn action_metadata_signature(rule: &ActionRuleDefinition) -> String {
    serde_json::to_string(&serde_json::json!({
        "label": rule.label,
        "message": rule.message,
        "severity": rule.severity,
        "counterfactual_hint": rule.counterfactual_hint,
        "verification_status": rule.verification_status,
    }))
    .unwrap_or_default()
}

fn semantic_rule_signature(rule: &RuleDefinition) -> String {
    format!(
        "{}|{}",
        serde_json::to_string(&rule.kind).unwrap_or_default(),
        canonical_expression_key(&rule.deny_when)
    )
}

fn semantic_action_rule_signature(rule: &ActionRuleDefinition) -> String {
    format!(
        "{}|{}",
        rule.action,
        canonical_expression_key(&rule.predicate)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use logicpearl_ir::{
        ActionEvaluationConfig, ActionSelectionStrategy, ComparisonExpression, ComparisonOperator,
        ComparisonValue, EvaluationConfig, Expression, FeatureDefinition, FeatureType, InputSchema,
        LogicPearlGateIr, RuleKind,
    };
    use serde_json::{json, Value};
    use std::path::PathBuf;

    fn gate_with_rules(rules: Vec<RuleDefinition>) -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "demo".to_string(),
            gate_type: "bitmask_gate".to_string(),
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "age".to_string(),
                    feature_type: FeatureType::Int,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                }],
            },
            rules,
            evaluation: EvaluationConfig {
                combine: "bitwise_or".to_string(),
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        }
    }

    fn predicate_rule(id: &str, bit: u32, op: ComparisonOperator, value: Value) -> RuleDefinition {
        RuleDefinition {
            id: id.to_string(),
            kind: RuleKind::Predicate,
            bit,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "age".to_string(),
                op,
                value: ComparisonValue::Literal(value),
            }),
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: None,
        }
    }

    fn expression_rule(id: &str, bit: u32, deny_when: Expression) -> RuleDefinition {
        RuleDefinition {
            id: id.to_string(),
            kind: RuleKind::Predicate,
            bit,
            deny_when,
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: None,
        }
    }

    fn action_policy_with_rules(
        default_action: &str,
        actions: Vec<&str>,
        rules: Vec<ActionRuleDefinition>,
    ) -> LogicPearlActionIr {
        LogicPearlActionIr {
            ir_version: "1.0".to_string(),
            action_policy_id: "demo_actions".to_string(),
            action_policy_type: "priority_rules".to_string(),
            action_column: "next_action".to_string(),
            default_action: default_action.to_string(),
            actions: actions.into_iter().map(ToOwned::to_owned).collect(),
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "age".to_string(),
                    feature_type: FeatureType::Int,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                }],
            },
            rules,
            evaluation: ActionEvaluationConfig {
                selection: ActionSelectionStrategy::FirstMatch,
            },
            verification: None,
            provenance: None,
        }
    }

    fn action_rule(
        id: &str,
        bit: u32,
        action: &str,
        priority: u32,
        op: ComparisonOperator,
        value: Value,
    ) -> ActionRuleDefinition {
        ActionRuleDefinition {
            id: id.to_string(),
            bit,
            action: action.to_string(),
            priority,
            predicate: Expression::Comparison(ComparisonExpression {
                feature: "age".to_string(),
                op,
                value: ComparisonValue::Literal(value),
            }),
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: None,
        }
    }

    fn resolved_inputs() -> (
        artifact_cmd::ResolvedArtifactInput,
        artifact_cmd::ResolvedArtifactInput,
    ) {
        (
            artifact_cmd::ResolvedArtifactInput {
                artifact_dir: PathBuf::from("/tmp/old"),
                pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
            },
            artifact_cmd::ResolvedArtifactInput {
                artifact_dir: PathBuf::from("/tmp/new"),
                pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
            },
        )
    }

    fn feature_semantics(
        label: &str,
        source_anchor: &str,
        state_label: &str,
    ) -> logicpearl_ir::FeatureSemantics {
        serde_json::from_value(json!({
            "label": label,
            "source_id": "policy-1",
            "source_anchor": source_anchor,
            "states": {
                "minor": {
                    "when": {"op": "<", "value": 18},
                    "label": state_label,
                    "message": format!("This rule fires when {state_label}."),
                    "counterfactual_hint": "Raise applicant age."
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn diff_treats_same_semantics_with_new_bits_as_reordered() {
        let old_gate = gate_with_rules(vec![
            predicate_rule("rule_a", 0, ComparisonOperator::Lt, json!(18)),
            predicate_rule("rule_b", 1, ComparisonOperator::Gte, json!(65)),
        ]);
        let new_gate = gate_with_rules(vec![
            predicate_rule("rule_b2", 0, ComparisonOperator::Gte, json!(65)),
            predicate_rule("rule_a2", 1, ComparisonOperator::Lt, json!(18)),
        ]);
        let old_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/old"),
            pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
        };
        let new_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/new"),
            pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
        };

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert_eq!(report.summary.changed_rules, 0);
        assert_eq!(report.summary.reordered_rules, 2);
        assert_eq!(report.summary.added_rules, 0);
        assert_eq!(report.summary.removed_rules, 0);
        assert!(!report.summary.learned_rule_changed);
    }

    #[test]
    fn diff_treats_same_id_with_new_threshold_as_changed() {
        let old_gate = gate_with_rules(vec![predicate_rule(
            "missing_docs",
            0,
            ComparisonOperator::Lt,
            json!(18),
        )]);
        let new_gate = gate_with_rules(vec![predicate_rule(
            "missing_docs",
            0,
            ComparisonOperator::Lt,
            json!(21),
        )]);
        let old_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/old"),
            pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
        };
        let new_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/new"),
            pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
        };

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert_eq!(report.summary.changed_rules, 1);
        assert_eq!(report.changed_rules[0].rule_id, "missing_docs");
        assert!(report.summary.learned_rule_changed);
        assert!(!report.summary.source_schema_changed);
        assert!(!report.summary.rule_explanation_changed);
    }

    #[test]
    fn diff_action_policies_reports_action_specific_changes() {
        let old_policy = action_policy_with_rules(
            "do_nothing",
            vec!["do_nothing", "water"],
            vec![
                action_rule(
                    "rule_water",
                    0,
                    "water",
                    0,
                    ComparisonOperator::Lt,
                    json!(18),
                ),
                action_rule("rule_old", 1, "water", 1, ComparisonOperator::Gt, json!(70)),
                action_rule(
                    "rule_priority",
                    2,
                    "water",
                    2,
                    ComparisonOperator::Gte,
                    json!(40),
                ),
            ],
        );
        let mut new_priority_rule = action_rule(
            "rule_priority",
            2,
            "water",
            5,
            ComparisonOperator::Gte,
            json!(40),
        );
        new_priority_rule.label = Some("Priority changed only".to_string());
        let new_policy = action_policy_with_rules(
            "wait",
            vec!["wait", "water", "fertilize"],
            vec![
                action_rule(
                    "rule_water",
                    0,
                    "water",
                    0,
                    ComparisonOperator::Lt,
                    json!(21),
                ),
                new_priority_rule,
                action_rule(
                    "rule_new",
                    3,
                    "fertilize",
                    3,
                    ComparisonOperator::Gte,
                    json!(80),
                ),
            ],
        );
        let (old_resolved, new_resolved) = resolved_inputs();

        let report = diff_action_policies(&old_policy, &new_policy, &old_resolved, &new_resolved)
            .expect("action diff should succeed");

        assert!(report.summary.action_set_changed);
        assert!(report.summary.default_action_changed);
        assert!(report.summary.rule_predicate_changed);
        assert!(report.summary.rule_priority_changed);
        assert!(report.summary.learned_rule_changed);
        assert_eq!(report.action_changes.added, vec!["fertilize", "wait"]);
        assert_eq!(report.action_changes.removed, vec!["do_nothing"]);
        assert_eq!(report.summary.changed_rules, 1);
        assert_eq!(
            report.changed_rules[0].change_kind,
            "rule_predicate_changed"
        );
        assert_eq!(report.summary.reordered_rules, 1);
        assert_eq!(
            report.reordered_rules[0].change_kind,
            "rule_priority_changed"
        );
        assert_eq!(report.summary.added_rules, 1);
        assert_eq!(report.summary.removed_rules, 1);
        assert_eq!(report.added_rules[0].action.as_deref(), Some("fertilize"));
    }

    #[test]
    fn diff_reports_added_and_removed_rules() {
        let old_gate = gate_with_rules(vec![predicate_rule(
            "rule_a",
            0,
            ComparisonOperator::Lt,
            json!(18),
        )]);
        let new_gate = gate_with_rules(vec![predicate_rule(
            "rule_b",
            0,
            ComparisonOperator::Gte,
            json!(65),
        )]);
        let old_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/old"),
            pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
        };
        let new_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/new"),
            pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
        };

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert_eq!(report.summary.added_rules, 1);
        assert_eq!(report.summary.removed_rules, 1);
    }

    #[test]
    fn diff_rule_snapshots_include_readable_artifact_semantics() {
        let mut old_gate = gate_with_rules(vec![predicate_rule(
            "minor_guard",
            0,
            ComparisonOperator::Lt,
            json!(18.0),
        )]);
        old_gate.rules[0].label = Some("Applicant age below 18".to_string());
        old_gate.input_schema.features[0].semantics = Some(feature_semantics(
            "Applicant age",
            "page-1",
            "Applicant is a minor",
        ));
        let new_gate = gate_with_rules(vec![]);
        let (old_resolved, new_resolved) = resolved_inputs();

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");

        assert_eq!(report.summary.removed_rules, 1);
        let snapshot = &report.removed_rules[0];
        assert_eq!(snapshot.change_kind.as_deref(), Some("removed_rule"));
        assert_eq!(snapshot.meaning.as_deref(), Some("Applicant is a minor"));
        assert_eq!(snapshot.raw_expression, snapshot.expression);
        assert_eq!(snapshot.raw_expression["feature"].as_str(), Some("age"));
        assert_eq!(snapshot.raw_expression["op"].as_str(), Some("<"));
        assert_eq!(snapshot.raw_expression["value"].as_f64(), Some(18.0));
        let feature = snapshot.feature.as_ref().expect("primary feature");
        assert_eq!(feature.id, "age");
        assert_eq!(feature.label.as_deref(), Some("Applicant age"));
        assert_eq!(feature.source_id.as_deref(), Some("policy-1"));
        assert_eq!(feature.source_anchor.as_deref(), Some("page-1"));
    }

    #[test]
    fn diff_normalizes_semantically_equivalent_boolean_expressions() {
        let old_gate = gate_with_rules(vec![expression_rule(
            "age_guard",
            0,
            Expression::Not {
                expr: Box::new(Expression::Not {
                    expr: Box::new(Expression::Comparison(ComparisonExpression {
                        feature: "age".to_string(),
                        op: ComparisonOperator::In,
                        value: ComparisonValue::Literal(json!([18, 21, 18])),
                    })),
                }),
            },
        )]);
        let new_gate = gate_with_rules(vec![expression_rule(
            "age_guard",
            0,
            Expression::Comparison(ComparisonExpression {
                feature: "age".to_string(),
                op: ComparisonOperator::In,
                value: ComparisonValue::Literal(json!([21, 18])),
            }),
        )]);
        let old_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/old"),
            pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
        };
        let new_resolved = artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/new"),
            pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
        };

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert_eq!(report.summary.changed_rules, 0);
        assert_eq!(report.summary.reordered_rules, 0);
        assert!(report.changed_rules.is_empty());
        assert!(report.reordered_rules.is_empty());
    }

    #[test]
    fn diff_separates_explanation_only_changes() {
        let mut old_gate = gate_with_rules(vec![predicate_rule(
            "age_guard",
            0,
            ComparisonOperator::Lt,
            json!(18),
        )]);
        let mut new_gate = old_gate.clone();
        old_gate.rules[0].label = Some("Applicant age below 18".to_string());
        new_gate.rules[0].label = Some("Applicant is a minor".to_string());
        old_gate.input_schema.features[0].semantics = Some(feature_semantics(
            "Applicant age",
            "page-1",
            "Applicant age below 18",
        ));
        new_gate.input_schema.features[0].semantics = Some(feature_semantics(
            "Applicant age",
            "page-1",
            "Applicant is a minor",
        ));
        let (old_resolved, new_resolved) = resolved_inputs();

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert!(!report.summary.source_schema_changed);
        assert!(!report.summary.learned_rule_changed);
        assert!(report.summary.rule_explanation_changed);
        assert_eq!(report.feature_dictionary_changes.changed.len(), 1);
        assert!(report.feature_dictionary_changes.changed[0].explanation_changed);
    }

    #[test]
    fn diff_separates_source_schema_changes() {
        let mut old_gate = gate_with_rules(vec![predicate_rule(
            "age_guard",
            0,
            ComparisonOperator::Lt,
            json!(18),
        )]);
        let mut new_gate = old_gate.clone();
        old_gate.input_schema.features[0].semantics = Some(feature_semantics(
            "Applicant age",
            "page-1",
            "Applicant age below 18",
        ));
        new_gate.input_schema.features[0].semantics = Some(feature_semantics(
            "Applicant age",
            "page-2",
            "Applicant age below 18",
        ));
        let (old_resolved, new_resolved) = resolved_inputs();

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert!(report.summary.source_schema_changed);
        assert!(!report.summary.learned_rule_changed);
        assert!(!report.summary.rule_explanation_changed);
        assert!(report.feature_dictionary_changes.changed[0].source_changed);
    }

    #[test]
    fn diff_treats_dictionary_addition_as_explanation_only() {
        let old_gate = gate_with_rules(vec![predicate_rule(
            "age_guard",
            0,
            ComparisonOperator::Lt,
            json!(18),
        )]);
        let mut new_gate = old_gate.clone();
        new_gate.input_schema.features[0].semantics = Some(feature_semantics(
            "Applicant age",
            "page-1",
            "Applicant age below 18",
        ));
        let (old_resolved, new_resolved) = resolved_inputs();

        let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
            .expect("diff should succeed");
        assert!(!report.summary.source_schema_changed);
        assert!(!report.summary.learned_rule_changed);
        assert!(report.summary.rule_explanation_changed);
        assert_eq!(report.feature_dictionary_changes.added.len(), 1);
    }
}
