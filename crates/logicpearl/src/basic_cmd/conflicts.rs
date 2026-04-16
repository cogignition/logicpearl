// SPDX-License-Identifier: MIT
use logicpearl_build::PreparedActionTraces;
use logicpearl_core::{artifact_hash, RuleMask};
use logicpearl_discovery::{action_trace_row_hash, decision_trace_row_hash, DecisionTraceRow};
use logicpearl_ir::{
    ActionRuleDefinition, ComparisonExpression, Expression, LogicPearlActionIr, LogicPearlGateIr,
    RuleDefinition,
};
use logicpearl_runtime::{
    evaluate_action_policy, evaluate_expression, resolve_action_features, resolve_gate_features,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

const CONFLICT_REPORT_SCHEMA_VERSION: &str = "logicpearl.build_conflicts.v1";
const MAX_NEAR_MISS_RULES: usize = 3;
const MAX_UNMET_PREDICATES: usize = 8;

#[derive(Debug, Clone)]
pub(super) struct ConflictReportSummary {
    pub display_path: String,
    pub conflict_count: usize,
    pub row_indexes: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct BuildConflictReport {
    schema_version: String,
    decision_kind: String,
    artifact_id: String,
    artifact_hash: String,
    training_parity: f64,
    rows: usize,
    conflict_count: usize,
    conflicts: Vec<TraceConflict>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceConflict {
    row_index: usize,
    trace_row_hash: String,
    expected: Value,
    predicted: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    selected_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    candidate_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    referenced_features: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    near_miss_rules: Vec<NearMissRule>,
    explanation: String,
}

#[derive(Debug, Clone, Serialize)]
struct NearMissRule {
    rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unmet_predicates: Vec<UnmetPredicate>,
}

#[derive(Debug, Clone, Serialize)]
struct UnmetPredicate {
    feature: String,
    op: String,
    comparison_value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actual: Option<Value>,
}

pub(super) fn requested_conflict_report_path(
    output_dir: &Path,
    explicit_path: Option<&PathBuf>,
) -> PathBuf {
    explicit_path
        .cloned()
        .unwrap_or_else(|| output_dir.join("conflict_report.json"))
}

pub(super) fn write_gate_conflict_report(
    path: PathBuf,
    output_dir: &Path,
    gate: &LogicPearlGateIr,
    rows: &[DecisionTraceRow],
    training_parity: f64,
    write_empty: bool,
) -> Result<Option<ConflictReportSummary>> {
    let report = gate_conflict_report(gate, rows, training_parity)?;
    write_conflict_report(path, output_dir, report, write_empty)
}

pub(super) fn write_action_conflict_report(
    path: PathBuf,
    output_dir: &Path,
    policy: &LogicPearlActionIr,
    traces: &PreparedActionTraces,
    training_parity: f64,
    write_empty: bool,
) -> Result<Option<ConflictReportSummary>> {
    let report = action_conflict_report(policy, traces, training_parity)?;
    write_conflict_report(path, output_dir, report, write_empty)
}

pub(super) fn add_conflict_summary_to_json(
    report: &mut Value,
    conflicts_requested: bool,
    summary: Option<&ConflictReportSummary>,
) {
    if !conflicts_requested {
        return;
    }
    report["conflict_count"] = json!(summary.map(|summary| summary.conflict_count).unwrap_or(0));
    if let Some(summary) = summary {
        report["conflict_report"] = json!(summary.display_path);
    }
}

pub(super) fn print_conflict_summary(
    summary: Option<&ConflictReportSummary>,
    conflicts_requested: bool,
) {
    if !conflicts_requested {
        return;
    }
    let Some(summary) = summary else {
        anstream::println!("  {} none", "Conflicts".bright_black());
        return;
    };
    let preview = summary
        .row_indexes
        .iter()
        .take(8)
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if preview.is_empty() {
        anstream::println!(
            "  {} {} ({})",
            "Conflicts".bright_black(),
            summary.conflict_count,
            summary.display_path
        );
    } else {
        anstream::println!(
            "  {} {} rows [{}] ({})",
            "Conflicts".bright_black(),
            summary.conflict_count,
            preview,
            summary.display_path
        );
    }
}

fn write_conflict_report(
    path: PathBuf,
    output_dir: &Path,
    report: BuildConflictReport,
    write_empty: bool,
) -> Result<Option<ConflictReportSummary>> {
    if report.conflict_count == 0 && !write_empty {
        return Ok(None);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create conflict report directory")?;
    }
    fs::write(
        &path,
        serde_json::to_string_pretty(&report).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write conflict report")?;
    Ok(Some(ConflictReportSummary {
        display_path: report_display_path(&path, output_dir),
        conflict_count: report.conflict_count,
        row_indexes: report
            .conflicts
            .iter()
            .map(|conflict| conflict.row_index)
            .collect(),
    }))
}

fn report_display_path(path: &Path, output_dir: &Path) -> String {
    path.strip_prefix(output_dir)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn gate_conflict_report(
    gate: &LogicPearlGateIr,
    rows: &[DecisionTraceRow],
    training_parity: f64,
) -> Result<BuildConflictReport> {
    let mut conflicts = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let resolved_features = resolve_gate_features(gate, &row.features)
            .into_diagnostic()
            .wrap_err("failed to resolve derived features for conflict report")?;
        let bitmask = gate_bitmask(gate, &resolved_features)
            .wrap_err("failed to evaluate gate for conflict report")?;
        let predicted_allowed = bitmask.is_zero();
        if predicted_allowed == row.allowed {
            continue;
        }

        let matched_rules = gate
            .rules
            .iter()
            .filter(|rule| bitmask.test_bit(rule.bit))
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();
        let near_miss_rules = if row.allowed {
            Vec::new()
        } else {
            gate_near_miss_rules(gate, &resolved_features)?
        };
        let referenced_features = referenced_features_for_gate_conflict(
            gate,
            &matched_rules,
            &near_miss_rules,
            &resolved_features,
        );
        let explanation = if !matched_rules.is_empty() {
            format!("matched deny rule(s): {}", matched_rules.join(", "))
        } else {
            "no deny rules matched".to_string()
        };

        conflicts.push(TraceConflict {
            row_index: index,
            trace_row_hash: row
                .trace_provenance
                .as_ref()
                .map(|provenance| provenance.trace_row_hash.clone())
                .unwrap_or_else(|| decision_trace_row_hash(&row.features, row.allowed)),
            expected: json!({ "allowed": row.allowed }),
            predicted: json!({
                "allowed": predicted_allowed,
                "bitmask": bitmask.to_json_value(),
            }),
            matched_rules,
            selected_rules: Vec::new(),
            candidate_actions: Vec::new(),
            referenced_features,
            near_miss_rules,
            explanation,
        });
    }

    Ok(BuildConflictReport {
        schema_version: CONFLICT_REPORT_SCHEMA_VERSION.to_string(),
        decision_kind: "gate".to_string(),
        artifact_id: gate.gate_id.clone(),
        artifact_hash: artifact_hash(gate),
        training_parity,
        rows: rows.len(),
        conflict_count: conflicts.len(),
        conflicts,
    })
}

fn action_conflict_report(
    policy: &LogicPearlActionIr,
    traces: &PreparedActionTraces,
    training_parity: f64,
) -> Result<BuildConflictReport> {
    let mut conflicts = Vec::new();
    for (index, (features, expected_action)) in traces
        .features_by_row
        .iter()
        .zip(traces.action_by_row.iter())
        .enumerate()
    {
        let result = evaluate_action_policy(policy, features)
            .into_diagnostic()
            .wrap_err("failed to evaluate action policy for conflict report")?;
        if &result.action == expected_action {
            continue;
        }
        let resolved_features = resolve_action_features(policy, features)
            .into_diagnostic()
            .wrap_err("failed to resolve action features for conflict report")?;
        let matched_rules = result
            .matched_rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();
        let selected_rules = result
            .selected_rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();
        let near_miss_rules = action_near_miss_rules(policy, &resolved_features, expected_action)?;
        let referenced_features = referenced_features_for_action_conflict(
            policy,
            &matched_rules,
            &near_miss_rules,
            &resolved_features,
        );
        let explanation = if result.no_match {
            format!("no action rules matched; selected {:?}", result.action)
        } else if selected_rules.is_empty() {
            format!("selected action {:?}", result.action)
        } else {
            format!(
                "selected action {:?} from rule(s): {}",
                result.action,
                selected_rules.join(", ")
            )
        };

        conflicts.push(TraceConflict {
            row_index: index,
            trace_row_hash: traces
                .trace_provenance_by_row
                .get(index)
                .map(|provenance| provenance.trace_row_hash.clone())
                .unwrap_or_else(|| action_trace_row_hash(features, expected_action)),
            expected: json!({ "action": expected_action }),
            predicted: json!({
                "action": result.action,
                "bitmask": result.bitmask.to_json_value(),
                "defaulted": result.defaulted,
            }),
            matched_rules,
            selected_rules,
            candidate_actions: result.candidate_actions,
            referenced_features,
            near_miss_rules,
            explanation,
        });
    }

    Ok(BuildConflictReport {
        schema_version: CONFLICT_REPORT_SCHEMA_VERSION.to_string(),
        decision_kind: "action".to_string(),
        artifact_id: policy.action_policy_id.clone(),
        artifact_hash: artifact_hash(policy),
        training_parity,
        rows: traces.action_by_row.len(),
        conflict_count: conflicts.len(),
        conflicts,
    })
}

fn gate_bitmask(gate: &LogicPearlGateIr, features: &HashMap<String, Value>) -> Result<RuleMask> {
    let mut bitmask = RuleMask::zero();
    for rule in &gate.rules {
        if evaluate_expression(&rule.deny_when, features).into_diagnostic()? {
            bitmask.set_bit(rule.bit);
        }
    }
    Ok(bitmask)
}

fn gate_near_miss_rules(
    gate: &LogicPearlGateIr,
    features: &HashMap<String, Value>,
) -> Result<Vec<NearMissRule>> {
    let mut candidates = Vec::new();
    for rule in &gate.rules {
        if evaluate_expression(&rule.deny_when, features).into_diagnostic()? {
            continue;
        }
        if let Some(near_miss) = near_miss_for_gate_rule(rule, features)? {
            candidates.push((near_miss.unmet_predicates.len(), rule.bit, near_miss));
        }
    }
    candidates.sort_by_key(|(unmet_count, bit, _)| (*unmet_count, *bit));
    Ok(candidates
        .into_iter()
        .map(|(_, _, near_miss)| near_miss)
        .take(MAX_NEAR_MISS_RULES)
        .collect())
}

fn action_near_miss_rules(
    policy: &LogicPearlActionIr,
    features: &HashMap<String, Value>,
    expected_action: &str,
) -> Result<Vec<NearMissRule>> {
    let mut candidates = Vec::new();
    for rule in policy
        .rules
        .iter()
        .filter(|rule| rule.action == expected_action)
    {
        if evaluate_expression(&rule.predicate, features).into_diagnostic()? {
            continue;
        }
        if let Some(near_miss) = near_miss_for_action_rule(rule, features)? {
            candidates.push((near_miss.unmet_predicates.len(), rule.priority, near_miss));
        }
    }
    candidates.sort_by_key(|(unmet_count, priority, _)| (*unmet_count, *priority));
    Ok(candidates
        .into_iter()
        .map(|(_, _, near_miss)| near_miss)
        .take(MAX_NEAR_MISS_RULES)
        .collect())
}

fn near_miss_for_gate_rule(
    rule: &RuleDefinition,
    features: &HashMap<String, Value>,
) -> Result<Option<NearMissRule>> {
    let unmet_predicates = unmet_predicates(&rule.deny_when, features)?;
    if unmet_predicates.is_empty() {
        return Ok(None);
    }
    Ok(Some(NearMissRule {
        rule_id: rule.id.clone(),
        action: None,
        unmet_predicates,
    }))
}

fn near_miss_for_action_rule(
    rule: &ActionRuleDefinition,
    features: &HashMap<String, Value>,
) -> Result<Option<NearMissRule>> {
    let unmet_predicates = unmet_predicates(&rule.predicate, features)?;
    if unmet_predicates.is_empty() {
        return Ok(None);
    }
    Ok(Some(NearMissRule {
        rule_id: rule.id.clone(),
        action: Some(rule.action.clone()),
        unmet_predicates,
    }))
}

fn unmet_predicates(
    expression: &Expression,
    features: &HashMap<String, Value>,
) -> Result<Vec<UnmetPredicate>> {
    let mut out = Vec::new();
    collect_unmet_predicates(expression, features, &mut out)?;
    out.truncate(MAX_UNMET_PREDICATES);
    Ok(out)
}

fn collect_unmet_predicates(
    expression: &Expression,
    features: &HashMap<String, Value>,
    out: &mut Vec<UnmetPredicate>,
) -> Result<()> {
    if out.len() >= MAX_UNMET_PREDICATES {
        return Ok(());
    }
    match expression {
        Expression::Comparison(comparison) => {
            if !evaluate_expression(expression, features).into_diagnostic()? {
                out.push(unmet_predicate(comparison, features));
            }
        }
        Expression::All { all } => {
            for child in all {
                if !evaluate_expression(child, features).into_diagnostic()? {
                    collect_unmet_predicates(child, features, out)?;
                }
            }
        }
        Expression::Any { any } => {
            for child in any {
                if evaluate_expression(child, features).into_diagnostic()? {
                    return Ok(());
                }
            }
            for child in any {
                collect_unmet_predicates(child, features, out)?;
            }
        }
        Expression::Not { .. } => {}
    }
    Ok(())
}

fn unmet_predicate(
    comparison: &ComparisonExpression,
    features: &HashMap<String, Value>,
) -> UnmetPredicate {
    UnmetPredicate {
        feature: comparison.feature.clone(),
        op: comparison.op.as_str().to_string(),
        comparison_value: serde_json::to_value(&comparison.value).unwrap_or(Value::Null),
        actual: features.get(&comparison.feature).cloned(),
    }
}

fn referenced_features_for_gate_conflict(
    gate: &LogicPearlGateIr,
    matched_rules: &[String],
    near_miss_rules: &[NearMissRule],
    features: &HashMap<String, Value>,
) -> BTreeMap<String, Value> {
    let mut feature_ids = BTreeSet::new();
    for rule in &gate.rules {
        if matched_rules.iter().any(|id| id == &rule.id) {
            collect_expression_feature_ids(&rule.deny_when, &mut feature_ids);
        }
    }
    collect_near_miss_feature_ids(near_miss_rules, &mut feature_ids);
    selected_feature_values(features, feature_ids)
}

fn referenced_features_for_action_conflict(
    policy: &LogicPearlActionIr,
    matched_rules: &[String],
    near_miss_rules: &[NearMissRule],
    features: &HashMap<String, Value>,
) -> BTreeMap<String, Value> {
    let mut feature_ids = BTreeSet::new();
    for rule in &policy.rules {
        if matched_rules.iter().any(|id| id == &rule.id) {
            collect_expression_feature_ids(&rule.predicate, &mut feature_ids);
        }
    }
    collect_near_miss_feature_ids(near_miss_rules, &mut feature_ids);
    selected_feature_values(features, feature_ids)
}

fn collect_near_miss_feature_ids(near_miss_rules: &[NearMissRule], out: &mut BTreeSet<String>) {
    for near_miss in near_miss_rules {
        for predicate in &near_miss.unmet_predicates {
            out.insert(predicate.feature.clone());
        }
    }
}

fn collect_expression_feature_ids(expression: &Expression, out: &mut BTreeSet<String>) {
    match expression {
        Expression::Comparison(comparison) => {
            out.insert(comparison.feature.clone());
            if let Some(feature_ref) = comparison.value.feature_ref() {
                out.insert(feature_ref.to_string());
            }
        }
        Expression::All { all } => {
            for child in all {
                collect_expression_feature_ids(child, out);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_expression_feature_ids(child, out);
            }
        }
        Expression::Not { expr } => collect_expression_feature_ids(expr, out),
    }
}

fn selected_feature_values(
    features: &HashMap<String, Value>,
    feature_ids: BTreeSet<String>,
) -> BTreeMap<String, Value> {
    feature_ids
        .into_iter()
        .filter_map(|feature_id| {
            features
                .get(&feature_id)
                .cloned()
                .map(|value| (feature_id, value))
        })
        .collect()
}
