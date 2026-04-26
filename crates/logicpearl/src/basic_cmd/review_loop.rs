// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_build::prepare_action_traces;
use logicpearl_core::{artifact_hash, load_artifact_bundle, ArtifactKind};
use logicpearl_discovery::{load_decision_traces_auto, load_flat_records};
use logicpearl_ir::{
    ActionRuleDefinition, ComparisonExpression, Expression, LogicPearlActionIr, LogicPearlGateIr,
    RuleDefinition,
};
use logicpearl_runtime::{
    evaluate_action_policy, evaluate_expression, evaluate_gate, parse_input_payload,
    resolve_action_features, resolve_gate_features,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{guidance, RefineArgs, ReviewArgs, TraceArgs};
use crate::{read_json_input_argument, resolve_manifest_member_path};

const MAX_NEAR_MISS_RULES: usize = 3;
const MAX_UNMET_PREDICATES: usize = 8;

pub(crate) fn run_review(args: ReviewArgs) -> Result<()> {
    let bundle = load_artifact_bundle(&args.artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", args.artifact.display()))?;
    let pearl_ir = bundle.ir_path().into_diagnostic()?;
    match bundle.manifest.artifact_kind {
        ArtifactKind::Gate => {
            let gate = LogicPearlGateIr::from_path(&pearl_ir)
                .into_diagnostic()
                .wrap_err("could not load pearl IR")?;
            let payload = read_json_input_argument(Some(&args.input_json), "input")?;
            let parsed = parse_input_payload(payload)
                .into_diagnostic()
                .wrap_err("runtime input shape is invalid")?;
            let reviews = parsed
                .iter()
                .map(|input| review_gate_input(&gate, input))
                .collect::<Result<Vec<_>>>()?;
            emit_review_output("gate", reviews, args.json)
        }
        ArtifactKind::Action => {
            let policy = LogicPearlActionIr::from_path(&pearl_ir)
                .into_diagnostic()
                .wrap_err("could not load action policy IR")?;
            let payload = read_json_input_argument(Some(&args.input_json), "input")?;
            let parsed = parse_input_payload(payload)
                .into_diagnostic()
                .wrap_err("runtime input shape is invalid")?;
            let reviews = parsed
                .iter()
                .map(|input| review_action_input(&policy, input))
                .collect::<Result<Vec<_>>>()?;
            emit_review_output("action", reviews, args.json)
        }
        ArtifactKind::Pipeline => Err(guidance(
            "review received a pipeline artifact",
            "Use `logicpearl pipeline trace` for pipeline artifacts.",
        )),
    }
}

pub(crate) fn run_trace(args: TraceArgs) -> Result<()> {
    let bundle = load_artifact_bundle(&args.artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", args.artifact.display()))?;
    let pearl_ir = bundle.ir_path().into_diagnostic()?;
    match bundle.manifest.artifact_kind {
        ArtifactKind::Gate => {
            let gate = LogicPearlGateIr::from_path(&pearl_ir)
                .into_diagnostic()
                .wrap_err("could not load pearl IR")?;
            let rows = load_decision_traces_auto(&args.traces, None, None, None)
                .into_diagnostic()
                .wrap_err("failed to load reviewed traces")?;
            let mut traced = Vec::with_capacity(rows.rows.len());
            for (index, row) in rows.rows.iter().enumerate() {
                let resolved = resolve_gate_features(&gate, &row.features)
                    .into_diagnostic()
                    .wrap_err("failed to resolve gate features")?;
                let bitmask = evaluate_gate(&gate, &row.features)
                    .into_diagnostic()
                    .wrap_err("failed to evaluate gate")?;
                let predicted_allowed = bitmask.is_zero();
                let matched_rules = gate
                    .rules
                    .iter()
                    .filter(|rule| bitmask.test_bit(rule.bit))
                    .map(|rule| rule.id.clone())
                    .collect::<Vec<_>>();
                let near_misses = if args.show_near_misses && !row.allowed {
                    gate_near_miss_rules(&gate, &resolved)?
                } else {
                    Vec::new()
                };
                traced.push(TraceRowReview {
                    row_index: index,
                    expected: json!({ "allow": row.allowed }),
                    predicted: json!({
                        "allow": predicted_allowed,
                        "bitmask": bitmask.to_json_value(),
                    }),
                    matched_rules,
                    selected_rules: Vec::new(),
                    near_miss_rules: near_misses,
                    correct: predicted_allowed == row.allowed,
                });
            }
            emit_trace_output(
                "gate",
                &gate.gate_id,
                artifact_hash(&gate),
                traced,
                args.json,
            )
        }
        ArtifactKind::Action => {
            let policy = LogicPearlActionIr::from_path(&pearl_ir)
                .into_diagnostic()
                .wrap_err("could not load action policy IR")?;
            let loaded = load_flat_records(&args.traces)
                .into_diagnostic()
                .wrap_err("failed to load reviewed traces")?;
            let traces = prepare_action_traces(&loaded, &policy.action_column)
                .into_diagnostic()
                .wrap_err("failed to prepare action traces")?;
            let mut traced = Vec::with_capacity(traces.action_by_row.len());
            for (index, (features, expected_action)) in traces
                .features_by_row
                .iter()
                .zip(traces.action_by_row.iter())
                .enumerate()
            {
                let result = evaluate_action_policy(&policy, features)
                    .into_diagnostic()
                    .wrap_err("failed to evaluate action policy")?;
                let resolved = resolve_action_features(&policy, features)
                    .into_diagnostic()
                    .wrap_err("failed to resolve action features")?;
                let near_misses = if args.show_near_misses {
                    action_near_miss_rules(&policy, &resolved, expected_action)?
                } else {
                    Vec::new()
                };
                traced.push(TraceRowReview {
                    row_index: index,
                    expected: json!({ "action": expected_action }),
                    predicted: json!({
                        "action": result.action,
                        "bitmask": result.bitmask.to_json_value(),
                        "defaulted": result.defaulted,
                    }),
                    matched_rules: result
                        .matched_rules
                        .iter()
                        .map(|rule| rule.id.clone())
                        .collect(),
                    selected_rules: result
                        .selected_rules
                        .iter()
                        .map(|rule| rule.id.clone())
                        .collect(),
                    near_miss_rules: near_misses,
                    correct: &result.action == expected_action,
                });
            }
            emit_trace_output(
                "action",
                &policy.action_policy_id,
                artifact_hash(&policy),
                traced,
                args.json,
            )
        }
        ArtifactKind::Pipeline => Err(guidance(
            "trace received a pipeline artifact",
            "Use `logicpearl pipeline trace` for pipeline artifacts.",
        )),
    }
}

pub(crate) fn run_refine(args: RefineArgs) -> Result<()> {
    let bundle = load_artifact_bundle(&args.artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", args.artifact.display()))?;
    let report_path = bundle
        .manifest
        .files
        .build_report
        .as_deref()
        .map(|file| resolve_manifest_member_path(&bundle.base_dir, file))
        .transpose()?
        .ok_or_else(|| {
            guidance(
                "refine needs an artifact build report",
                "Rebuild the source artifact with a current LogicPearl build so provenance is available.",
            )
        })?;
    let report: Value = serde_json::from_str(
        &fs::read_to_string(&report_path)
            .into_diagnostic()
            .wrap_err("failed to read build report")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse build report")?;
    let traces = report["provenance"]["input_traces"]
        .as_array()
        .and_then(|inputs| inputs.first())
        .and_then(|input| input["path"].as_str())
        .ok_or_else(|| {
            guidance(
                "refine could not find the original trace path",
                "Pass the original trace file to `logicpearl build ... --pinned-rules` directly.",
            )
        })?;
    if traces.starts_with('<') {
        return Err(guidance(
            "refine cannot replay a redacted trace path",
            "Run `logicpearl build <traces> --pinned-rules <rules>` directly, or rebuild the source artifact from a relative trace path.",
        ));
    }
    let traces_path = resolve_refine_trace_path(&bundle.base_dir, traces);
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| default_refined_output_dir(&bundle.base_dir));

    let mut command = Command::new(std::env::current_exe().into_diagnostic()?);
    command
        .arg("build")
        .arg(&traces_path)
        .arg("--output-dir")
        .arg(&output_dir);
    append_refine_target_args(&mut command, &bundle, &report)?;
    if let Some(feature_dictionary) = bundle.manifest.files.feature_dictionary.as_deref() {
        command
            .arg("--feature-dictionary")
            .arg(resolve_manifest_member_path(
                &bundle.base_dir,
                feature_dictionary,
            )?);
    }
    command
        .arg("--pinned-rules")
        .arg(&args.pinned_rules)
        .arg("--refine");
    if args.json {
        command.arg("--json");
    }

    if !args.json {
        println!(
            "{}",
            "Refining policy from reviewed evidence"
                .bold()
                .bright_blue()
        );
        println!(
            "  {} {}",
            "Source artifact".bright_black(),
            bundle.base_dir.display()
        );
        println!(
            "  {} {}",
            "Reviewed traces".bright_black(),
            traces_path.display()
        );
        println!(
            "  {} {}",
            "Pinned rules".bright_black(),
            args.pinned_rules.display()
        );
        println!("  {} {}", "Output".bright_black(), output_dir.display());
        println!();
    }
    let status = command
        .status()
        .into_diagnostic()
        .wrap_err("failed to run refinement build")?;
    if !status.success() {
        return Err(guidance(
            "refinement build failed",
            "Review the build output above, fix the pinned rules or trace source, then rerun `logicpearl refine`.",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct InputReview {
    decision_kind: String,
    artifact_id: String,
    artifact_hash: String,
    outcome: Value,
    matched_rules: Vec<RuleReview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    selected_rules: Vec<RuleReview>,
}

#[derive(Debug, Clone, Serialize)]
struct RuleReview {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence: Option<logicpearl_ir::RuleEvidence>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceReplayReport {
    schema_version: String,
    decision_kind: String,
    artifact_id: String,
    artifact_hash: String,
    rows: usize,
    correct: usize,
    parity: f64,
    rows_detail: Vec<TraceRowReview>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceRowReview {
    row_index: usize,
    expected: Value,
    predicted: Value,
    matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    selected_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    near_miss_rules: Vec<NearMissRule>,
    correct: bool,
}

#[derive(Debug, Clone, Serialize)]
struct NearMissRule {
    rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
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

fn review_gate_input(
    gate: &LogicPearlGateIr,
    input: &HashMap<String, Value>,
) -> Result<InputReview> {
    let bitmask = evaluate_gate(gate, input)
        .into_diagnostic()
        .wrap_err("failed to evaluate gate")?;
    let matched_rules = gate
        .rules
        .iter()
        .filter(|rule| bitmask.test_bit(rule.bit))
        .map(|rule| RuleReview {
            id: rule.id.clone(),
            action: None,
            label: rule.label.clone(),
            message: rule.message.clone(),
            evidence: rule.evidence.clone(),
        })
        .collect::<Vec<_>>();
    Ok(InputReview {
        decision_kind: "gate".to_string(),
        artifact_id: gate.gate_id.clone(),
        artifact_hash: artifact_hash(gate),
        outcome: json!({
            "allow": bitmask.is_zero(),
            "bitmask": bitmask.to_json_value(),
        }),
        matched_rules,
        selected_rules: Vec::new(),
    })
}

fn review_action_input(
    policy: &LogicPearlActionIr,
    input: &HashMap<String, Value>,
) -> Result<InputReview> {
    let result = evaluate_action_policy(policy, input)
        .into_diagnostic()
        .wrap_err("failed to evaluate action policy")?;
    Ok(InputReview {
        decision_kind: "action".to_string(),
        artifact_id: policy.action_policy_id.clone(),
        artifact_hash: artifact_hash(policy),
        outcome: json!({
            "action": result.action,
            "bitmask": result.bitmask.to_json_value(),
            "defaulted": result.defaulted,
        }),
        matched_rules: result
            .matched_rules
            .iter()
            .map(|rule| RuleReview {
                id: rule.id.clone(),
                action: Some(rule.action.clone()),
                label: rule.label.clone(),
                message: rule.message.clone(),
                evidence: action_rule_evidence(policy, &rule.id),
            })
            .collect(),
        selected_rules: result
            .selected_rules
            .iter()
            .map(|rule| RuleReview {
                id: rule.id.clone(),
                action: Some(rule.action.clone()),
                label: rule.label.clone(),
                message: rule.message.clone(),
                evidence: action_rule_evidence(policy, &rule.id),
            })
            .collect(),
    })
}

fn action_rule_evidence(
    policy: &LogicPearlActionIr,
    rule_id: &str,
) -> Option<logicpearl_ir::RuleEvidence> {
    policy
        .rules
        .iter()
        .find(|rule| rule.id == rule_id)
        .and_then(|rule| rule.evidence.clone())
}

fn emit_review_output(kind: &str, reviews: Vec<InputReview>, json: bool) -> Result<()> {
    if json {
        let value = if reviews.len() == 1 {
            serde_json::to_value(&reviews[0]).into_diagnostic()?
        } else {
            serde_json::to_value(&reviews).into_diagnostic()?
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&value).into_diagnostic()?
        );
        return Ok(());
    }
    println!("{}", "Policy review".bold().bright_blue());
    for (index, review) in reviews.iter().enumerate() {
        if reviews.len() > 1 {
            println!("  {} {}", "Input".bright_black(), index);
        }
        match kind {
            "gate" => println!(
                "  {} {}",
                "Decision".bright_black(),
                if review.outcome["allow"].as_bool() == Some(true) {
                    "allow"
                } else {
                    "deny"
                }
                .bold()
            ),
            "action" => println!(
                "  {} {}",
                "Action".bright_black(),
                review.outcome["action"]
                    .as_str()
                    .unwrap_or("unknown")
                    .bold()
            ),
            _ => {}
        }
        let rules = if review.selected_rules.is_empty() {
            &review.matched_rules
        } else {
            &review.selected_rules
        };
        if rules.is_empty() {
            println!(
                "  {} no rule matched; default behavior applied",
                "Evidence".bright_black()
            );
        } else {
            println!("  {}", "Evidence".bright_black());
            for rule in rules {
                println!(
                    "    - {}",
                    rule.label
                        .as_deref()
                        .or(rule.message.as_deref())
                        .unwrap_or(&rule.id)
                );
            }
        }
    }
    Ok(())
}

fn emit_trace_output(
    decision_kind: &str,
    artifact_id: &str,
    artifact_hash_value: String,
    rows: Vec<TraceRowReview>,
    json: bool,
) -> Result<()> {
    let correct = rows.iter().filter(|row| row.correct).count();
    let report = TraceReplayReport {
        schema_version: "logicpearl.trace_replay.v1".to_string(),
        decision_kind: decision_kind.to_string(),
        artifact_id: artifact_id.to_string(),
        artifact_hash: artifact_hash_value,
        rows: rows.len(),
        correct,
        parity: if rows.is_empty() {
            1.0
        } else {
            correct as f64 / rows.len() as f64
        },
        rows_detail: rows,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
        return Ok(());
    }
    println!("{}", "Trace replay".bold().bright_blue());
    println!("  {} {}", "Artifact".bright_black(), report.artifact_id);
    println!(
        "  {} {:.1}% ({}/{})",
        "Parity".bright_black(),
        report.parity * 100.0,
        report.correct,
        report.rows
    );
    for row in report.rows_detail.iter().filter(|row| !row.correct).take(8) {
        println!(
            "  {} {} expected={} predicted={}",
            "Mismatch row".bright_black(),
            row.row_index,
            row.expected,
            row.predicted
        );
        for near_miss in &row.near_miss_rules {
            println!("    near miss: {}", near_miss.rule_id);
            for predicate in &near_miss.unmet_predicates {
                println!(
                    "      {} {} {} (actual {})",
                    predicate.feature,
                    predicate.op,
                    predicate.comparison_value,
                    predicate.actual.as_ref().unwrap_or(&Value::Null)
                );
            }
        }
    }
    Ok(())
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

fn append_refine_target_args(
    command: &mut Command,
    bundle: &logicpearl_core::LoadedArtifactBundle,
    report: &Value,
) -> Result<()> {
    match bundle.manifest.artifact_kind {
        ArtifactKind::Gate => {
            let label_column = report["label_column"].as_str().ok_or_else(|| {
                guidance(
                    "refine could not find the gate target column",
                    "Run `logicpearl build <traces> --target <column> --pinned-rules <rules>` directly.",
                )
            })?;
            command.arg("--target").arg(label_column);
        }
        ArtifactKind::Action => {
            let policy = LogicPearlActionIr::from_path(bundle.ir_path().into_diagnostic()?)
                .into_diagnostic()
                .wrap_err("could not load action policy IR")?;
            command
                .arg("--target")
                .arg(&policy.action_column)
                .arg("--default-action")
                .arg(&policy.default_action);
            if let Some(no_match_action) = &policy.no_match_action {
                command.arg("--no-match-action").arg(no_match_action);
            }
        }
        ArtifactKind::Pipeline => {
            return Err(guidance(
                "refine received a pipeline artifact",
                "Refine the gate or action artifacts inside the pipeline, then update the pipeline bundle.",
            ));
        }
    }
    Ok(())
}

fn default_refined_output_dir(artifact_dir: &Path) -> PathBuf {
    let mut value = artifact_dir.as_os_str().to_owned();
    value.push(".refined");
    PathBuf::from(value)
}

fn resolve_refine_trace_path(artifact_dir: &Path, raw_path: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    if path.is_absolute() || path.exists() {
        return path;
    }
    let artifact_relative = artifact_dir.join(&path);
    if artifact_relative.exists() {
        return artifact_relative;
    }
    if let Some(parent) = artifact_dir.parent() {
        let sibling_relative = parent.join(&path);
        if sibling_relative.exists() {
            return sibling_relative;
        }
    }
    path
}
