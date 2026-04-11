use super::*;
use logicpearl_ir::{
    canonical_expression_key, ComparisonValue, Expression, FeatureSemantics, LogicPearlGateIr,
    RuleDefinition,
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
struct RuleSnapshot {
    id: String,
    bit: u32,
    label: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    counterfactual_hint: Option<String>,
    verification_status: Option<String>,
    semantic_signature: String,
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

pub(crate) fn run_diff(args: DiffArgs) -> Result<()> {
    let old_resolved = resolve_artifact_input(&args.old_artifact)?;
    let new_resolved = resolve_artifact_input(&args.new_artifact)?;
    let old_gate = LogicPearlGateIr::from_path(&old_resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load old pearl IR")?;
    let new_gate = LogicPearlGateIr::from_path(&new_resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load new pearl IR")?;

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .wrap_err("failed to diff artifacts")?;

    if args.json {
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
            change.old_rule.semantic_signature
        );
        println!(
            "    {} {}",
            "New".bright_black(),
            change.new_rule.semantic_signature
        );
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
            change.new_rule.semantic_signature
        );
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
            rule.semantic_signature
        );
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
        .map(|idx| snapshot_rule(&new_indexed[*idx], new_gate))
        .collect::<Vec<_>>();
    let removed_rules = old_remaining
        .iter()
        .map(|idx| snapshot_rule(&old_indexed[*idx], old_gate))
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

fn snapshot_rule(rule: &IndexedRule<'_>, gate: &LogicPearlGateIr) -> RuleSnapshot {
    RuleSnapshot {
        id: rule.rule.id.clone(),
        bit: rule.rule.bit,
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
        expression: serde_json::to_value(&rule.rule.deny_when).unwrap_or(Value::Null),
        feature_dictionary: rule_feature_semantics(rule.rule, gate),
    }
}

fn diff_feature_dictionaries(
    old_gate: &LogicPearlGateIr,
    new_gate: &LogicPearlGateIr,
) -> FeatureDictionaryChanges {
    let old_semantics = feature_semantics_by_id(old_gate);
    let new_semantics = feature_semantics_by_id(new_gate);
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
    gate.input_schema
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

fn semantic_rule_signature(rule: &RuleDefinition) -> String {
    format!(
        "{}|{}",
        serde_json::to_string(&rule.kind).unwrap_or_default(),
        canonical_expression_key(&rule.deny_when)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use logicpearl_ir::{
        ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig, Expression,
        FeatureDefinition, FeatureType, InputSchema, LogicPearlGateIr, RuleKind,
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
