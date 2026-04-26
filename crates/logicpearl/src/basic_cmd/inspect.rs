// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_core::{load_artifact_bundle, ArtifactKind, ArtifactRenderer, LoadedArtifactBundle};
use logicpearl_ir::{InputSchema, LogicPearlActionIr, LogicPearlGateIr};
use logicpearl_render::TextInspector;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::config::{configured_inspect_artifact, ConfiguredInspectArtifact};
use super::feature_dictionary::write_feature_dictionary_from_schema;
use super::{
    artifact_bundle_descriptor_from_manifest, guidance, resolve_manifest_member_path, InspectArgs,
};

pub(crate) fn run_inspect(args: InspectArgs) -> Result<()> {
    let artifact = resolve_inspect_artifact(args.pearl_ir.as_ref())?;
    let bundle = load_artifact_bundle(&artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", artifact.display()))?;
    let pearl_ir = bundle.ir_path().into_diagnostic()?;
    match bundle.manifest.artifact_kind {
        ArtifactKind::Action => {
            return run_action_inspect(
                &bundle,
                args.json,
                args.show_provenance,
                args.write_feature_dictionary.as_deref(),
            );
        }
        ArtifactKind::Pipeline => {
            return Err(guidance(
                "inspect received a pipeline artifact",
                "Use `logicpearl pipeline inspect` for pipeline artifacts.",
            ));
        }
        ArtifactKind::Gate => {}
    }
    let gate = LogicPearlGateIr::from_path(&pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    if let Some(path) = args.write_feature_dictionary.as_ref() {
        write_feature_dictionary_from_schema(path, &gate.input_schema)?;
    }
    let review_advice = inspect_review_advice_for_gate(&gate, &bundle.base_dir);
    let descriptor = artifact_bundle_descriptor_from_manifest(&bundle.manifest)
        .wrap_err("could not load artifact bundle metadata")?;
    if args.json {
        let summary = serde_json::json!({
            "artifact_dir": bundle.base_dir,
            "pearl_ir": pearl_ir,
            "gate_id": gate.gate_id,
            "ir_version": gate.ir_version,
            "features": gate.input_schema.features.len(),
            "rules": gate.rules.len(),
            "feature_dictionary": inspect_feature_dictionary(&gate),
            "review_advice": review_advice,
            "written_feature_dictionary": args.write_feature_dictionary.as_ref(),
            "rule_details": inspect_rule_details(&gate, args.show_provenance),
            "correctness_scope": gate.verification.as_ref().and_then(|verification| verification.correctness_scope.clone()),
            "verification_summary": gate.verification.as_ref().and_then(|verification| verification.verification_summary.clone()),
            "bundle": descriptor,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        let inspector = TextInspector;
        println!("{}", "LogicPearl Artifact".bold().bright_blue());
        println!(
            "  {} {}",
            "Bundle".bright_black(),
            bundle.base_dir.display()
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            bundle.base_dir.join(&descriptor.cli_entrypoint).display()
        );
        if let Some(primary_runtime) = &descriptor.primary_runtime {
            println!("  {} {}", "Primary runtime".bright_black(), primary_runtime);
        }
        for deployable in &descriptor.deployables {
            println!(
                "  {} {}",
                "Deployable".bright_black(),
                bundle.base_dir.join(&deployable.path).display()
            );
        }
        for metadata_file in &descriptor.metadata_files {
            println!(
                "  {} {}",
                "Wasm metadata".bright_black(),
                bundle.base_dir.join(&metadata_file.path).display()
            );
        }
        println!();
        println!("{}", inspector.render(&gate).into_diagnostic()?);
        render_review_advice(review_advice.as_ref());
        if let Some(path) = args.write_feature_dictionary.as_ref() {
            println!();
            println!(
                "{} {}",
                "Wrote starter feature dictionary:".bright_black(),
                path.display()
            );
        }
        if args.show_provenance {
            render_gate_rule_provenance(&gate);
        }
    }
    Ok(())
}

fn resolve_inspect_artifact(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.clone());
    }
    match configured_inspect_artifact()? {
        ConfiguredInspectArtifact::Found(artifact) => Ok(artifact),
        ConfiguredInspectArtifact::MissingConfig => Err(guidance(
            "inspect is missing an artifact",
            "Pass an artifact path, or set run.artifact or build.output_dir in logicpearl.yaml.",
        )),
        ConfiguredInspectArtifact::MissingArtifact => Err(guidance(
            "inspect could not find an artifact in logicpearl.yaml",
            "Set run.artifact or build.output_dir.",
        )),
    }
}

fn run_action_inspect(
    bundle: &LoadedArtifactBundle,
    json: bool,
    show_provenance: bool,
    write_feature_dictionary: Option<&Path>,
) -> Result<()> {
    let action_policy_path = bundle.ir_path().into_diagnostic()?;
    let action_policy = LogicPearlActionIr::from_path(&action_policy_path)
        .into_diagnostic()
        .wrap_err("could not load action policy IR")?;
    if let Some(path) = write_feature_dictionary {
        write_feature_dictionary_from_schema(path, &action_policy.input_schema)?;
    }
    let report_path = bundle
        .manifest
        .files
        .build_report
        .as_deref()
        .map(|file| resolve_manifest_member_path(&bundle.base_dir, file))
        .transpose()?;
    let report: Option<Value> = if report_path.as_ref().is_some_and(|path| path.exists()) {
        let report_path = report_path.as_ref().expect("report path should exist");
        Some(
            serde_json::from_str(
                &fs::read_to_string(report_path)
                    .into_diagnostic()
                    .wrap_err("failed to read action report")?,
            )
            .into_diagnostic()
            .wrap_err("failed to parse action report")?,
        )
    } else {
        None
    };
    run_action_policy_inspect(
        bundle,
        &action_policy_path,
        &action_policy,
        report,
        json,
        show_provenance,
        write_feature_dictionary,
    )
}

fn run_action_policy_inspect(
    bundle: &LoadedArtifactBundle,
    action_policy_path: &Path,
    action_policy: &LogicPearlActionIr,
    report: Option<Value>,
    json: bool,
    show_provenance: bool,
    written_feature_dictionary: Option<&Path>,
) -> Result<()> {
    let review_advice = inspect_review_advice_for_action(action_policy, &bundle.base_dir);
    if json {
        let summary = serde_json::json!({
            "artifact_dir": bundle.base_dir,
            "artifact_kind": "action",
            "artifact_name": bundle.manifest.artifact_id,
            "action_policy_id": action_policy.action_policy_id,
            "ir_version": action_policy.ir_version,
            "action_column": action_policy.action_column,
            "default_action": action_policy.default_action,
            "no_match_action": action_policy.no_match_action,
            "actions": action_policy.actions,
            "features": action_policy.input_schema.features.len(),
            "feature_dictionary": inspect_action_feature_dictionary(action_policy),
            "review_advice": review_advice,
            "written_feature_dictionary": written_feature_dictionary,
            "action_report": report,
            "pearl_ir": action_policy_path,
            "rules": action_policy.rules.iter().map(|rule| {
                let mut value = serde_json::json!({
                    "id": rule.id,
                    "bit": rule.bit,
                    "action": rule.action,
                    "priority": rule.priority,
                    "when": rule.predicate,
                    "label": rule.label,
                    "message": rule.message,
                    "counterfactual_hint": rule.counterfactual_hint,
                    "verification_status": rule.verification_status,
                });
                if show_provenance {
                    value["evidence"] = serde_json::to_value(&rule.evidence).unwrap_or(Value::Null);
                }
                value
            }).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
        return Ok(());
    }

    println!("{}", "LogicPearl Action Artifact".bold().bright_blue());
    println!(
        "  {} {}",
        "Bundle".bright_black(),
        bundle.base_dir.display()
    );
    println!(
        "  {} {}",
        "Action policy".bright_black(),
        action_policy.action_policy_id
    );
    println!(
        "  {} {}",
        "Action column".bright_black(),
        action_policy.action_column
    );
    println!(
        "  {} {}",
        "Default action".bright_black(),
        action_policy.default_action
    );
    if let Some(no_match_action) = &action_policy.no_match_action {
        println!("  {} {}", "No-match action".bright_black(), no_match_action);
    }
    println!("Action rules:");
    for (index, rule) in action_policy.rules.iter().enumerate() {
        println!("  {}. {}", index + 1, rule.action.bold());
        println!(
            "     {}",
            rule.label
                .as_deref()
                .or(rule.message.as_deref())
                .unwrap_or(&rule.id)
        );
        if show_provenance {
            render_rule_evidence(rule.evidence.as_ref(), 5);
        }
    }
    render_review_advice(review_advice.as_ref());
    if let Some(path) = written_feature_dictionary {
        println!();
        println!(
            "{} {}",
            "Wrote starter feature dictionary:".bright_black(),
            path.display()
        );
    }
    if let Some(report) = report {
        if let Some(training_parity) = report.get("training_parity").and_then(Value::as_f64) {
            println!(
                "  {} {:.1}%",
                "Training parity".bright_black(),
                training_parity * 100.0
            );
        }
    }
    Ok(())
}

fn inspect_feature_dictionary(gate: &LogicPearlGateIr) -> Value {
    inspect_schema_feature_dictionary(&gate.input_schema)
}

fn inspect_action_feature_dictionary(action_policy: &LogicPearlActionIr) -> Value {
    inspect_schema_feature_dictionary(&action_policy.input_schema)
}

fn inspect_schema_feature_dictionary(input_schema: &InputSchema) -> Value {
    let features = input_schema
        .features
        .iter()
        .filter_map(|feature| {
            let semantics = feature.semantics.as_ref()?;
            Some(serde_json::json!({
                "id": feature.id,
                "label": semantics.label,
                "kind": semantics.kind,
                "unit": semantics.unit,
                "higher_is_better": semantics.higher_is_better,
                "source_id": semantics.source_id,
                "source_anchor": semantics.source_anchor,
                "states": semantics.states,
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "features": features,
        "feature_count": features.len(),
    })
}

fn inspect_review_advice_for_gate(gate: &LogicPearlGateIr, artifact_dir: &Path) -> Option<Value> {
    let referenced_features = gate
        .rules
        .iter()
        .flat_map(|rule| expression_feature_ids(&rule.deny_when))
        .collect::<BTreeSet<_>>();
    inspect_review_advice(&gate.input_schema, referenced_features, artifact_dir)
}

fn inspect_review_advice_for_action(
    action_policy: &LogicPearlActionIr,
    artifact_dir: &Path,
) -> Option<Value> {
    let referenced_features = action_policy
        .rules
        .iter()
        .flat_map(|rule| expression_feature_ids(&rule.predicate))
        .collect::<BTreeSet<_>>();
    inspect_review_advice(
        &action_policy.input_schema,
        referenced_features,
        artifact_dir,
    )
}

fn inspect_review_advice(
    input_schema: &InputSchema,
    referenced_features: BTreeSet<String>,
    artifact_dir: &Path,
) -> Option<Value> {
    let raw_features = referenced_features
        .into_iter()
        .filter(|feature_id| feature_uses_raw_id(input_schema, feature_id))
        .collect::<Vec<_>>();
    if raw_features.is_empty() {
        return None;
    }
    let starter_dictionary = artifact_dir.join("feature_dictionary.starter.json");
    Some(serde_json::json!({
        "kind": "raw_feature_ids",
        "message": "These rules use raw feature ids. Generate a starter feature dictionary?",
        "raw_feature_count": raw_features.len(),
        "raw_features": raw_features,
        "write_command": format!(
            "logicpearl inspect {} --write-feature-dictionary {}",
            shell_arg(artifact_dir),
            shell_arg(&starter_dictionary)
        ),
        "next_step": "Review the labels, then rebuild with --feature-dictionary so rule labels, messages, inspect, run, and diff use reviewer-facing text.",
    }))
}

fn feature_uses_raw_id(input_schema: &InputSchema, feature_id: &str) -> bool {
    input_schema
        .features
        .iter()
        .find(|feature| feature.id == feature_id)
        .is_some_and(|feature| {
            feature
                .semantics
                .as_ref()
                .and_then(|semantics| semantics.label.as_deref())
                .map(str::trim)
                .is_none_or(str::is_empty)
        })
}

fn render_review_advice(advice: Option<&Value>) {
    let Some(advice) = advice else {
        return;
    };
    println!();
    println!("{}", "Review note".bold().bright_blue());
    if let Some(message) = advice.get("message").and_then(Value::as_str) {
        println!("  {message}");
    }
    if let Some(raw_features) = advice.get("raw_features").and_then(Value::as_array) {
        let preview = raw_features
            .iter()
            .filter_map(Value::as_str)
            .take(5)
            .collect::<Vec<_>>()
            .join(", ");
        if !preview.is_empty() {
            let suffix = if raw_features.len() > 5 { ", ..." } else { "" };
            println!("  {} {}{}", "Raw features".bright_black(), preview, suffix);
        }
    }
    if let Some(command) = advice.get("write_command").and_then(Value::as_str) {
        println!("  {} {}", "Generate".bright_black(), command);
    }
}

fn inspect_rule_details(gate: &LogicPearlGateIr, show_provenance: bool) -> Vec<Value> {
    gate.rules
        .iter()
        .map(|rule| {
            let referenced_features = expression_feature_ids(&rule.deny_when)
                .into_iter()
                .filter_map(|feature_id| inspect_rule_feature(gate, &feature_id))
                .collect::<Vec<_>>();
            let mut value = serde_json::json!({
                "id": rule.id,
                "bit": rule.bit,
                "deny_when": rule.deny_when,
                "label": rule.label,
                "message": rule.message,
                "severity": rule.severity,
                "counterfactual_hint": rule.counterfactual_hint,
                "verification_status": rule.verification_status,
                "feature_dictionary": referenced_features,
            });
            if show_provenance {
                value["evidence"] = serde_json::to_value(&rule.evidence).unwrap_or(Value::Null);
            }
            value
        })
        .collect()
}

fn render_gate_rule_provenance(gate: &LogicPearlGateIr) {
    println!();
    println!("{}", "Rule provenance".bold().bright_blue());
    for rule in &gate.rules {
        println!("  {} {}", "-".bright_black(), rule.id.bold());
        render_rule_evidence(rule.evidence.as_ref(), 4);
    }
}

fn render_rule_evidence(evidence: Option<&logicpearl_ir::RuleEvidence>, indent: usize) {
    let prefix = " ".repeat(indent);
    let Some(evidence) = evidence else {
        println!("{prefix}{} none", "Evidence".bright_black());
        return;
    };
    println!(
        "{prefix}{} denied={} allowed={}",
        "Support".bright_black(),
        evidence.support.denied_trace_count,
        evidence.support.allowed_trace_count
    );
    for example in &evidence.support.example_traces {
        let source = match (&example.source_id, &example.source_anchor) {
            (Some(source_id), Some(anchor)) => format!("{source_id}#{anchor}"),
            (Some(source_id), None) => source_id.clone(),
            (None, Some(anchor)) => anchor.clone(),
            (None, None) => "source".to_string(),
        };
        let citation = example
            .citation
            .as_deref()
            .map(|value| format!(" citation={value}"))
            .unwrap_or_default();
        let quote_hash = example
            .quote_hash
            .as_deref()
            .map(|value| format!(" quote_hash={value}"))
            .unwrap_or_default();
        println!(
            "{prefix}{} {} source={}{}{}",
            "Trace".bright_black(),
            example.trace_row_hash,
            source,
            citation,
            quote_hash
        );
    }
}

fn inspect_rule_feature(gate: &LogicPearlGateIr, feature_id: &str) -> Option<Value> {
    let feature = gate
        .input_schema
        .features
        .iter()
        .find(|feature| feature.id == feature_id)?;
    let semantics = feature.semantics.as_ref()?;
    Some(serde_json::json!({
        "id": feature.id,
        "label": semantics.label,
        "source_id": semantics.source_id,
        "source_anchor": semantics.source_anchor,
    }))
}

fn expression_feature_ids(expression: &logicpearl_ir::Expression) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    collect_expression_feature_ids(expression, &mut features);
    features
}

fn collect_expression_feature_ids(
    expression: &logicpearl_ir::Expression,
    features: &mut BTreeSet<String>,
) {
    match expression {
        logicpearl_ir::Expression::Comparison(comparison) => {
            features.insert(comparison.feature.clone());
            if let logicpearl_ir::ComparisonValue::FeatureRef { feature_ref } = &comparison.value {
                features.insert(feature_ref.clone());
            }
        }
        logicpearl_ir::Expression::All { all } => {
            for child in all {
                collect_expression_feature_ids(child, features);
            }
        }
        logicpearl_ir::Expression::Any { any } => {
            for child in any {
                collect_expression_feature_ids(child, features);
            }
        }
        logicpearl_ir::Expression::Not { expr } => collect_expression_feature_ids(expr, features),
    }
}

fn shell_arg(path: &Path) -> String {
    let value = path.display().to_string();
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':'))
    {
        return value;
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}
