// SPDX-License-Identifier: MIT

use super::{default_gate_id_from_path, DoctorArgs};
use anstream::println;
use logicpearl_discovery::load_flat_records;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    source: String,
    rows: usize,
    columns: Vec<ColumnReport>,
    warnings: Vec<String>,
    recommendation: DoctorRecommendation,
}

#[derive(Debug, Clone, Serialize)]
struct ColumnReport {
    name: String,
    distinct_values: usize,
    dominant_value_fraction: f64,
    inferred_type: String,
    examples: Vec<String>,
    signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorRecommendation {
    mode: String,
    confidence: String,
    target_column: Option<String>,
    feature_columns: Vec<String>,
    exclude_columns: Vec<String>,
    command: Option<String>,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetInferenceMode {
    Gate,
    Action,
    Fanout,
}

impl TargetInferenceMode {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Gate => "gate",
            Self::Action => "action",
            Self::Fanout => "fanout",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct TargetInference {
    pub(super) mode: TargetInferenceMode,
    pub(super) target_column: String,
    pub(super) confidence: String,
    pub(super) feature_columns: Vec<String>,
    pub(super) exclude_columns: Vec<String>,
    pub(super) actions: Vec<String>,
    pub(super) default_action: Option<String>,
    pub(super) reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct ColumnStats {
    name: String,
    distinct: BTreeMap<String, usize>,
    inferred_type: String,
    examples: Vec<String>,
    signals: Vec<String>,
    fanout_tokens: BTreeSet<String>,
    multi_value_rows: usize,
    binary_like: bool,
    suspicious_feature: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    mode: TargetInferenceMode,
    column: String,
    score: i32,
    reasons: Vec<String>,
    actions: Vec<String>,
    default_action: Option<String>,
}

pub(crate) fn run_doctor(args: DoctorArgs) -> Result<()> {
    let loaded = load_flat_records(&args.traces)
        .into_diagnostic()
        .wrap_err("failed to load traces for doctor")?;
    let stats = loaded
        .field_names
        .iter()
        .map(|field| column_stats(field, &loaded.records))
        .collect::<Vec<_>>();
    let warnings = trace_warnings(&args.traces, loaded.records.len(), &stats);
    let recommendation = recommend(&args.traces, args.output_dir.as_deref(), &stats);
    let report = DoctorReport {
        source: args.traces.display().to_string(),
        rows: loaded.records.len(),
        columns: stats.iter().map(column_report).collect(),
        warnings,
        recommendation,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        print_human_report(&report);
    }
    Ok(())
}

pub(super) fn infer_target_for_build(
    traces: &Path,
    target_column: &str,
) -> Result<TargetInference> {
    let stats = stats_for_target_inference(traces)?;
    infer_target_from_stats(&stats, target_column).ok_or_else(|| {
        let known_columns = stats
            .iter()
            .map(|stat| stat.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        super::guidance(
            format!("could not infer a build mode for --target {target_column:?}"),
            format!(
                "Use a binary gate target, scalar action target, or multi-label action list. Columns found: {known_columns}"
            ),
        )
    })
}

pub(super) fn infer_recommended_target_for_build(traces: &Path) -> Result<Option<TargetInference>> {
    let stats = stats_for_target_inference(traces)?;
    Ok(best_target_inference_from_stats(&stats))
}

fn stats_for_target_inference(traces: &Path) -> Result<Vec<ColumnStats>> {
    let loaded = load_flat_records(traces)
        .into_diagnostic()
        .wrap_err("failed to load traces for target inference")?;
    Ok(loaded
        .field_names
        .iter()
        .map(|field| column_stats(field, &loaded.records))
        .collect())
}

fn column_stats(name: &str, records: &[BTreeMap<String, Value>]) -> ColumnStats {
    let mut distinct = BTreeMap::<String, usize>::new();
    let mut examples = Vec::<String>::new();
    let mut type_counts = BTreeMap::<&'static str, usize>::new();
    let mut fanout_tokens = BTreeSet::new();
    let mut multi_value_rows = 0usize;
    for record in records {
        let Some(value) = record.get(name) else {
            continue;
        };
        let rendered = render_value(value);
        *distinct.entry(rendered.clone()).or_insert(0) += 1;
        if examples.len() < 3 && !examples.iter().any(|example| example == &rendered) {
            examples.push(rendered);
        }
        *type_counts.entry(value_kind(value)).or_insert(0) += 1;
        let tokens = fanout_tokens_for_value(value);
        if tokens.len() > 1 {
            multi_value_rows += 1;
            fanout_tokens.extend(tokens);
        }
    }
    let lowered = leaf_name(name);
    let mut signals = Vec::new();
    let binary_like = is_binary_like(&distinct);
    if binary_like {
        signals.push("binary values".to_string());
    }
    if is_labelish_name(&lowered) {
        signals.push("label-like name".to_string());
    }
    if is_actionish_name(&lowered) {
        signals.push("action-like name".to_string());
    }
    if is_fanoutish_name(&lowered) || multi_value_rows > 0 {
        signals.push("multi-action list".to_string());
    }
    let suspicious_feature = is_suspicious_feature_name(&lowered);
    if suspicious_feature {
        signals.push("likely metadata/provenance".to_string());
    }
    ColumnStats {
        name: name.to_string(),
        inferred_type: dominant_type(&type_counts).to_string(),
        distinct,
        examples,
        signals,
        fanout_tokens,
        multi_value_rows,
        binary_like,
        suspicious_feature,
    }
}

fn recommend(
    traces: &Path,
    output_dir: Option<&Path>,
    stats: &[ColumnStats],
) -> DoctorRecommendation {
    let Some(inference) = best_target_inference_from_stats(stats) else {
        return DoctorRecommendation {
            mode: "manual".to_string(),
            confidence: "low".to_string(),
            target_column: None,
            feature_columns: stats.iter().map(|stat| stat.name.clone()).collect(),
            exclude_columns: Vec::new(),
            command: None,
            reasons: vec![
                "No likely label, action, or fan-out column was detected.".to_string(),
                "Pick the reviewed outcome column and pass --label-column, --action-column, or --fanout-column explicitly.".to_string(),
            ],
        };
    };

    let output_dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_output_dir(traces, inference.mode.as_str()));
    let command = build_command(
        traces,
        &output_dir,
        &inference.target_column,
        &inference.exclude_columns,
    );
    DoctorRecommendation {
        mode: inference.mode.as_str().to_string(),
        confidence: inference.confidence,
        target_column: Some(inference.target_column),
        feature_columns: inference.feature_columns,
        exclude_columns: inference.exclude_columns,
        command: Some(command),
        reasons: inference.reasons,
    }
}

fn infer_target_from_stats(stats: &[ColumnStats], target_column: &str) -> Option<TargetInference> {
    let stat = stats.iter().find(|stat| stat.name == target_column)?;
    let best = column_candidates(stat)
        .into_iter()
        .max_by_key(|candidate| candidate.score)?;
    Some(target_inference_from_candidate(stats, best))
}

fn best_target_inference_from_stats(stats: &[ColumnStats]) -> Option<TargetInference> {
    let best = stats
        .iter()
        .flat_map(column_candidates)
        .max_by_key(|candidate| candidate.score)?;
    Some(target_inference_from_candidate(stats, best))
}

fn target_inference_from_candidate(stats: &[ColumnStats], best: Candidate) -> TargetInference {
    let exclude_columns = stats
        .iter()
        .filter(|stat| stat.name != best.column && stat.suspicious_feature)
        .map(|stat| stat.name.clone())
        .collect::<Vec<_>>();
    let feature_columns = stats
        .iter()
        .filter(|stat| {
            stat.name != best.column && !exclude_columns.iter().any(|col| col == &stat.name)
        })
        .map(|stat| stat.name.clone())
        .collect::<Vec<_>>();
    let confidence = if best.score >= 90 {
        "high"
    } else if best.score >= 55 {
        "medium"
    } else {
        "low"
    };
    TargetInference {
        mode: best.mode,
        target_column: best.column,
        confidence: confidence.to_string(),
        feature_columns,
        exclude_columns,
        actions: best.actions,
        default_action: best.default_action,
        reasons: best.reasons,
    }
}

fn column_candidates(stat: &ColumnStats) -> Vec<Candidate> {
    let lowered = leaf_name(&stat.name);
    let mut candidates = Vec::new();
    if stat.binary_like {
        let mut score = 35;
        let mut reasons = vec![format!(
            "{} has one or two binary-compatible values",
            stat.name
        )];
        if is_labelish_name(&lowered) {
            score += 35;
            reasons.push("the column name looks like a reviewed outcome".to_string());
        }
        if !stat.suspicious_feature {
            score += 10;
        }
        candidates.push(Candidate {
            mode: TargetInferenceMode::Gate,
            column: stat.name.clone(),
            score,
            reasons,
            actions: Vec::new(),
            default_action: None,
        });
    }
    if stat.multi_value_rows > 0 || is_fanoutish_name(&lowered) {
        let mut score = 25;
        let mut reasons = Vec::new();
        if stat.multi_value_rows > 0 {
            score += 45;
            reasons.push(format!(
                "{} rows contain multiple action tokens",
                stat.multi_value_rows
            ));
        }
        if is_fanoutish_name(&lowered) {
            score += 35;
            reasons.push("the column name looks like an applicable-action list".to_string());
        }
        let actions = stat.fanout_tokens.iter().cloned().collect::<Vec<_>>();
        if actions.len() >= 2 {
            score += 10;
        }
        candidates.push(Candidate {
            mode: TargetInferenceMode::Fanout,
            column: stat.name.clone(),
            score,
            reasons,
            actions,
            default_action: None,
        });
    }
    if !stat.binary_like && stat.distinct.len() >= 2 && stat.distinct.len() <= 30 {
        let unique_ratio =
            stat.distinct.len() as f64 / stat.distinct.values().sum::<usize>() as f64;
        if unique_ratio < 0.85 || is_actionish_name(&lowered) {
            let mut score = 20;
            let mut reasons = vec![format!(
                "{} has {} reusable action values",
                stat.name,
                stat.distinct.len()
            )];
            if is_actionish_name(&lowered) {
                score += 45;
                reasons.push("the column name looks like an action route".to_string());
            }
            let default_action = stat
                .distinct
                .keys()
                .find(|value| is_default_action_token(value))
                .cloned();
            if default_action.is_some() {
                score += 10;
                reasons.push("a default/no-op action value was detected".to_string());
            }
            candidates.push(Candidate {
                mode: TargetInferenceMode::Action,
                column: stat.name.clone(),
                score,
                reasons,
                actions: stat.distinct.keys().cloned().collect(),
                default_action,
            });
        }
    }
    candidates
}

fn build_command(
    traces: &Path,
    output_dir: &Path,
    target_column: &str,
    exclude_columns: &[String],
) -> String {
    let mut parts = vec![
        "logicpearl".to_string(),
        "build".to_string(),
        shell_arg(&traces.display().to_string()),
    ];
    parts.push("--target".to_string());
    parts.push(shell_arg(target_column));
    if !exclude_columns.is_empty() {
        parts.push("--exclude-columns".to_string());
        parts.push(shell_arg(&exclude_columns.join(",")));
    }
    parts.push("--output-dir".to_string());
    parts.push(shell_arg(&output_dir.display().to_string()));
    parts.join(" ")
}

fn trace_warnings(path: &Path, rows: usize, stats: &[ColumnStats]) -> Vec<String> {
    let mut warnings = Vec::new();
    if rows == 0 {
        warnings.push(format!("{} contains no trace rows.", path.display()));
    }
    if stats.len() < 2 {
        warnings
            .push("A build needs at least one target column and one feature column.".to_string());
    }
    for stat in stats {
        if stat.distinct.len() == rows && rows > 20 && !stat.suspicious_feature {
            warnings.push(format!(
                "{} is unique in every row; it may be an identifier rather than a useful feature.",
                stat.name
            ));
        }
        if stat.distinct.len() == 1 && rows > 1 {
            warnings.push(format!(
                "{} has one value in all rows; it will not help discovery.",
                stat.name
            ));
        }
    }
    warnings
}

fn column_report(stat: &ColumnStats) -> ColumnReport {
    let total = stat.distinct.values().sum::<usize>().max(1);
    let dominant = stat.distinct.values().copied().max().unwrap_or(0);
    ColumnReport {
        name: stat.name.clone(),
        distinct_values: stat.distinct.len(),
        dominant_value_fraction: dominant as f64 / total as f64,
        inferred_type: stat.inferred_type.clone(),
        examples: stat.examples.clone(),
        signals: stat.signals.clone(),
    }
}

fn print_human_report(report: &DoctorReport) {
    println!(
        "{} {}",
        "Trace doctor".bold().bright_green(),
        report.source.bold()
    );
    println!("  {} {}", "Rows".bright_black(), report.rows);
    println!("  {} {}", "Columns".bright_black(), report.columns.len());
    println!(
        "  {} {} ({})",
        "Recommendation".bright_black(),
        report.recommendation.mode.bold(),
        report.recommendation.confidence
    );
    if let Some(target) = &report.recommendation.target_column {
        println!("  {} {}", "Target".bright_black(), target);
    }
    if !report.recommendation.reasons.is_empty() {
        println!("\n{}", "Why".bold());
        for reason in &report.recommendation.reasons {
            println!("  - {reason}");
        }
    }
    println!("\n{}", "Columns".bold());
    for column in &report.columns {
        let signals = if column.signals.is_empty() {
            "no special signals".to_string()
        } else {
            column.signals.join(", ")
        };
        println!(
            "  - {}: {} distinct, {}, examples [{}]",
            column.name,
            column.distinct_values,
            signals,
            column.examples.join(", ")
        );
    }
    if !report.warnings.is_empty() {
        println!("\n{}", "Warnings".bold().yellow());
        for warning in &report.warnings {
            println!("  - {warning}");
        }
    }
    if let Some(command) = &report.recommendation.command {
        println!("\n{}", "Recommended Command".bold());
        println!("  {command}");
    }
}

fn fanout_tokens_for_value(value: &Value) -> BTreeSet<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| scalar_token(item).filter(|token| !is_empty_action_token(token)))
            .collect(),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.starts_with('[') {
                if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(trimmed) {
                    return fanout_tokens_for_value(&Value::Array(items));
                }
            }
            if trimmed.contains(',') || trimmed.contains(';') || trimmed.contains('|') {
                return trimmed
                    .split([',', ';', '|'])
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .filter(|token| !is_empty_action_token(token))
                    .map(ToOwned::to_owned)
                    .collect();
            }
            BTreeSet::new()
        }
        _ => BTreeSet::new(),
    }
}

fn scalar_token(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => value.to_string(),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_i64() || number.is_u64() => "int",
        Value::Number(_) => "float",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Null => "null",
    }
}

fn dominant_type(type_counts: &BTreeMap<&'static str, usize>) -> &'static str {
    type_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(kind, _)| *kind)
        .unwrap_or("unknown")
}

fn is_binary_like(distinct: &BTreeMap<String, usize>) -> bool {
    if distinct.is_empty() || distinct.len() > 2 {
        return false;
    }
    distinct.keys().all(|value| {
        let token = normalize_token(value);
        is_positive_label_token(&token) || is_negative_label_token(&token)
    }) || distinct.len() == 2
}

fn is_positive_label_token(token: &str) -> bool {
    matches!(
        token,
        "true" | "yes" | "y" | "1" | "allow" | "allowed" | "approved" | "pass" | "passed" | "ok"
    )
}

fn is_negative_label_token(token: &str) -> bool {
    matches!(
        token,
        "false" | "no" | "n" | "0" | "deny" | "denied" | "rejected" | "fail" | "failed" | "block"
    )
}

fn is_default_action_token(token: &str) -> bool {
    matches!(
        normalize_token(token).as_str(),
        "none" | "noop" | "no_op" | "do_nothing" | "default" | "allow" | "pass" | "ok"
    )
}

fn is_empty_action_token(token: &str) -> bool {
    matches!(
        normalize_token(token).as_str(),
        "" | "none" | "null" | "[]" | "n/a" | "na"
    )
}

fn is_labelish_name(name: &str) -> bool {
    matches!(
        name,
        "allowed" | "approved" | "label" | "target" | "decision" | "outcome" | "verdict" | "result"
    ) || name.ends_with("_label")
        || name.ends_with("_target")
        || name.ends_with("_decision")
        || name.ends_with("_outcome")
        || name.ends_with("_verdict")
        || name.ends_with("_result")
}

fn is_actionish_name(name: &str) -> bool {
    matches!(
        name,
        "action" | "next_action" | "route" | "decision_action" | "recommendation"
    ) || name.ends_with("_action")
        || name.ends_with("_route")
}

fn is_fanoutish_name(name: &str) -> bool {
    matches!(
        name,
        "applicable" | "applicable_actions" | "actions" | "labels" | "tags"
    ) || name.ends_with("_actions")
        || name.ends_with("_labels")
        || name.ends_with("_tags")
        || name.contains("applicable")
}

fn is_suspicious_feature_name(name: &str) -> bool {
    matches!(
        name,
        "id" | "row_id"
            | "trace_id"
            | "source"
            | "source_id"
            | "note"
            | "notes"
            | "rationale"
            | "reason"
            | "explanation"
            | "timestamp"
            | "created_at"
            | "updated_at"
    ) || name.ends_with("_id")
        || name.ends_with("_note")
        || name.ends_with("_notes")
        || name.ends_with("_rationale")
        || name.ends_with("_explanation")
}

fn leaf_name(name: &str) -> String {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase()
}

fn normalize_token(token: &str) -> String {
    token.trim().to_ascii_lowercase()
}

fn default_output_dir(traces: &Path, mode: &str) -> PathBuf {
    let stem = default_gate_id_from_path(traces);
    traces
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}_{mode}"))
}

fn shell_arg(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | ','))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
