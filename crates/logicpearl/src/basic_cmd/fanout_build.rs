// SPDX-License-Identifier: MIT

use anstream::println;
use logicpearl_benchmark::sanitize_identifier;
use logicpearl_build::{
    learn_fanout_policy_with_progress, prepare_fanout_traces_with_feature_selection,
    FanoutLearningOptions, FanoutLearningResult,
};
use logicpearl_core::ArtifactKind;
use logicpearl_discovery::load_flat_records;
use logicpearl_pipeline::build_fanout_pipeline;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use super::post_build_summary::{percent, top_rule_lines, PostBuildSummary};
use super::{
    default_gate_id_from_path, feature_column_selection, finish_progress,
    generated_feature_dictionary_for_output, generated_feature_dictionary_path, progress_callback,
    progress_enabled, selection_policy_from_args, set_progress_message,
    should_generate_feature_dictionary, start_progress, to_discovery_decision_mode,
    write_feature_dictionary_from_columns, BuildArgs, CommandCoaching,
};
use crate::{
    artifact_cmd::{ArtifactDeployable, ArtifactSidecar},
    build_options_hash, compile_native_fanout_runner, compile_wasm_fanout_module,
    is_rust_target_installed, native_artifact_output_path, wasm_artifact_output_path,
    write_artifact_manifest_v1, ArtifactBundleDescriptor, ArtifactManifestWriteOptions,
};

#[derive(Debug, Clone, Serialize)]
struct FanoutBuildReport {
    source: String,
    artifact_name: String,
    fanout_column: String,
    rows: usize,
    actions: Vec<FanoutActionReport>,
    selection_policy: logicpearl_discovery::SelectionPolicy,
    training_exact_set_match: f64,
    pipeline: String,
}

#[derive(Debug, Clone, Serialize)]
struct FanoutActionReport {
    action: String,
    gate_id: String,
    support: usize,
    positive_recall: f64,
    precision: f64,
    training_parity: f64,
    artifact: String,
}

pub(super) fn run_fanout_build(mut args: BuildArgs) -> Result<()> {
    if args.trace_plugin_manifest.is_some()
        || args.trace_plugin_input.is_some()
        || !args.trace_plugin_options.is_empty()
        || args.enricher_plugin_manifest.is_some()
    {
        return Err(CommandCoaching::simple(
            "fan-out builds currently require normalized trace files",
            "Run the trace-source plugin separately, then build fan-out from the emitted CSV/JSON/JSONL records.",
        ));
    }
    let fanout_column = args.fanout_column.clone().ok_or_else(|| {
        CommandCoaching::simple(
            "fan-out build is missing --fanout-column",
            "Pass --fanout-column <column> with a scalar or list of applicable actions.",
        )
    })?;
    let traces = args.decision_traces.clone().ok_or_else(|| {
        CommandCoaching::simple(
            "fan-out build is missing traces",
            "Pass a trace dataset path containing the --fanout-column values.",
        )
    })?;
    let feature_selection = feature_column_selection(&args.feature_columns, &args.exclude_columns)?;
    let selection_policy = selection_policy_from_args(
        args.selection_policy,
        args.deny_recall_target,
        args.max_false_positive_rate,
    )
    .map_err(|message| {
        CommandCoaching::simple(
            message,
            "Use balanced or provide both recall-biased targets.",
        )
    })?;
    let output_dir = args.output_dir.clone().unwrap_or_else(|| {
        traces
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("fanout_output")
    });
    fs::create_dir_all(&output_dir)
        .into_diagnostic()
        .wrap_err("failed to create fan-out artifact directory")?;
    let artifact_name = args
        .gate_id
        .clone()
        .unwrap_or_else(|| default_gate_id_from_path(&traces));
    let spinner = start_progress(
        progress_enabled(args.json, args.progress),
        "fanout_build: preparing input",
    );
    let progress = progress_callback(spinner.as_ref());

    set_progress_message(
        spinner.as_ref(),
        format!("load_traces: {}", traces.display()),
    );
    let loaded = load_flat_records(&traces)
        .into_diagnostic()
        .wrap_err("failed to load fan-out traces")?;
    let explicit_actions = (!args.fanout_actions.is_empty()).then_some(args.fanout_actions.clone());
    let fanout_traces = prepare_fanout_traces_with_feature_selection(
        &loaded,
        &fanout_column,
        &feature_selection,
        explicit_actions.as_deref(),
    )
    .into_diagnostic()
    .wrap_err("failed to prepare fan-out traces")?;

    if should_generate_feature_dictionary(&args) {
        set_progress_message(
            spinner.as_ref(),
            "feature_dictionary: generating starter metadata",
        );
        let dictionary_path = generated_feature_dictionary_path(&output_dir);
        write_feature_dictionary_from_columns(
            &dictionary_path,
            fanout_traces.feature_columns.clone(),
        )?;
        args.feature_dictionary = Some(dictionary_path);
    }

    let actions_dir = output_dir.join("actions");
    if actions_dir.exists() {
        fs::remove_dir_all(&actions_dir)
            .into_diagnostic()
            .wrap_err("failed to remove stale fan-out action artifacts")?;
    }
    fs::create_dir_all(&actions_dir)
        .into_diagnostic()
        .wrap_err("failed to create fan-out actions directory")?;

    set_progress_message(spinner.as_ref(), "fanout_build: learning action gates");
    let learned = learn_fanout_policy_with_progress(
        &fanout_traces,
        &FanoutLearningOptions {
            artifact_name: artifact_name.clone(),
            fanout_column: fanout_column.clone(),
            actions: explicit_actions,
            max_rules_per_action: args.max_rules,
            max_conditions: args.max_conditions,
            output_dir: output_dir.clone(),
            refine: args.refine,
            pinned_rules: args.pinned_rules.clone(),
            feature_dictionary: args.feature_dictionary.clone(),
            feature_governance: args.feature_governance.clone(),
            decision_mode: to_discovery_decision_mode(args.discovery_mode),
            selection_policy,
        },
        progress.as_deref(),
    )
    .into_diagnostic()
    .wrap_err("failed to learn fan-out gates")?;

    let mut action_artifacts = Vec::<(String, PathBuf)>::new();
    let mut action_reports = Vec::<FanoutActionReport>::new();
    for gate in &learned.gates {
        let action_dir = actions_dir.join(sanitize_identifier(&gate.action));
        fs::create_dir_all(&action_dir)
            .into_diagnostic()
            .wrap_err("failed to create fan-out action artifact directory")?;
        let gate_path = action_dir.join("pearl.ir.json");
        gate.gate
            .write_pretty(&gate_path)
            .into_diagnostic()
            .wrap_err("failed to write fan-out action gate IR")?;
        let build_options_digest = build_options_hash(&serde_json::json!({
            "artifact_name": &artifact_name,
            "fanout_column": &fanout_column,
            "action": gate.action,
            "max_rules": args.max_rules,
            "max_conditions": args.max_conditions,
            "selection_policy": selection_policy,
            "refine": args.refine,
        }));
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "fanout_action".to_string(),
            Value::String(gate.action.clone()),
        );
        write_artifact_manifest_v1(
            &action_dir,
            ArtifactManifestWriteOptions {
                artifact_kind: ArtifactKind::Gate,
                artifact_id: gate.gate.gate_id.clone(),
                ir_path: gate_path.clone(),
                build_report_path: None,
                feature_dictionary_path: None,
                native_path: None,
                wasm_path: None,
                wasm_metadata_path: None,
                build_options_hash: Some(build_options_digest),
                bundle: ArtifactBundleDescriptor {
                    bundle_kind: "gate_bundle".to_string(),
                    cli_entrypoint: "artifact.json".to_string(),
                    primary_runtime: None,
                    deployables: Vec::new(),
                    metadata_files: Vec::new(),
                },
                extensions,
                file_extensions: BTreeMap::new(),
            },
        )
        .wrap_err("failed to write fan-out action gate manifest")?;
        action_artifacts.push((gate.action.clone(), action_dir.join("artifact.json")));
        action_reports.push(FanoutActionReport {
            action: gate.action.clone(),
            gate_id: gate.gate.gate_id.clone(),
            support: gate.support,
            positive_recall: gate.positive_recall,
            precision: gate.precision,
            training_parity: gate.training_parity,
            artifact: action_dir.join("artifact.json").display().to_string(),
        });
    }

    let pipeline_input = fanout_traces
        .feature_columns
        .iter()
        .map(|feature| (feature.clone(), Value::String(format!("$.{feature}"))))
        .collect::<HashMap<_, _>>();
    let pipeline = build_fanout_pipeline(
        artifact_name.clone(),
        &action_artifacts,
        &output_dir,
        pipeline_input,
    )
    .into_diagnostic()
    .wrap_err("failed to assemble fan-out pipeline")?;
    let pipeline_path = output_dir.join("pipeline.json");
    pipeline
        .write_pretty(&pipeline_path)
        .into_diagnostic()
        .wrap_err("failed to write fan-out pipeline")?;
    let report = FanoutBuildReport {
        source: traces.display().to_string(),
        artifact_name: artifact_name.clone(),
        fanout_column: fanout_column.clone(),
        rows: loaded.records.len(),
        actions: action_reports,
        selection_policy,
        training_exact_set_match: learned.training_exact_set_match,
        pipeline: pipeline_path.display().to_string(),
    };
    let report_path = output_dir.join("fanout_report.json");
    fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write fan-out report")?;

    let native_binary_path = if args.compile {
        set_progress_message(spinner.as_ref(), "compile: native fan-out runner");
        Some(compile_native_fanout_runner(
            &pipeline_path,
            &output_dir,
            &artifact_name,
            Some(artifact_name.clone()),
            None,
            Some(native_artifact_output_path(
                &output_dir,
                &artifact_name,
                None,
            )),
        )?)
    } else {
        None
    };
    let wasm_output = if args.compile && is_rust_target_installed("wasm32-unknown-unknown") {
        set_progress_message(spinner.as_ref(), "compile: wasm fan-out runner");
        Some(compile_wasm_fanout_module(
            &pipeline_path,
            &output_dir,
            &artifact_name,
            Some(artifact_name.clone()),
            Some(wasm_artifact_output_path(&output_dir, &artifact_name)),
        )?)
    } else {
        if args.compile && !args.json {
            println!(
                "  {} wasm32-unknown-unknown target not installed; skipping Wasm output",
                "Wasm".bright_black()
            );
        }
        None
    };
    let wasm_module_path = wasm_output
        .as_ref()
        .map(|output| output.module_path.clone());
    let wasm_metadata_path = wasm_output
        .as_ref()
        .map(|output| output.metadata_path.clone());

    let mut extensions = BTreeMap::new();
    extensions.insert(
        "pipeline_type".to_string(),
        Value::String("fanout".to_string()),
    );
    extensions.insert(
        "actions".to_string(),
        serde_json::to_value(&learned.actions).into_diagnostic()?,
    );
    write_artifact_manifest_v1(
        &output_dir,
        ArtifactManifestWriteOptions {
            artifact_kind: ArtifactKind::Pipeline,
            artifact_id: artifact_name.clone(),
            ir_path: pipeline_path.clone(),
            build_report_path: Some(report_path.clone()),
            feature_dictionary_path: generated_feature_dictionary_for_output(&args, &output_dir)
                .map(|path| path.as_path().to_path_buf()),
            native_path: native_binary_path.clone(),
            wasm_path: wasm_module_path.clone(),
            wasm_metadata_path: wasm_metadata_path.clone(),
            build_options_hash: Some(build_options_hash(&serde_json::json!({
                "artifact_name": &artifact_name,
                "fanout_column": &fanout_column,
                "actions": &learned.actions,
                "max_rules": args.max_rules,
                "max_conditions": args.max_conditions,
                "selection_policy": selection_policy,
                "refine": args.refine,
            }))),
            bundle: ArtifactBundleDescriptor {
                bundle_kind: "fanout_pipeline_bundle".to_string(),
                cli_entrypoint: "artifact.json".to_string(),
                primary_runtime: native_binary_path
                    .as_ref()
                    .map(|_| "native_binary".to_string())
                    .or_else(|| wasm_module_path.as_ref().map(|_| "wasm_module".to_string()))
                    .or_else(|| Some("pipeline.json".to_string())),
                deployables: fanout_deployables(
                    native_binary_path.as_deref(),
                    wasm_module_path.as_deref(),
                ),
                metadata_files: fanout_metadata_files(
                    wasm_module_path.as_deref(),
                    wasm_metadata_path.as_deref(),
                )
                .into_iter()
                .chain([ArtifactSidecar {
                    kind: "fanout_report".to_string(),
                    path: "fanout_report.json".to_string(),
                    companion_to: Some("pipeline.json".to_string()),
                }])
                .collect(),
            },
            extensions,
            file_extensions: BTreeMap::new(),
        },
    )
    .wrap_err("failed to write fan-out artifact manifest")?;
    finish_progress(spinner);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        render_fanout_build_summary(
            &report,
            &learned,
            &output_dir,
            &pipeline_path,
            &report_path,
            generated_feature_dictionary_for_output(&args, &output_dir).map(|path| path.as_path()),
            native_binary_path.as_deref(),
            wasm_module_path.as_deref(),
            wasm_metadata_path.as_deref(),
            args.compile,
            fanout_traces.feature_columns.len(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_fanout_build_summary(
    report: &FanoutBuildReport,
    learned: &FanoutLearningResult,
    output_dir: &Path,
    pipeline_path: &Path,
    report_path: &Path,
    feature_dictionary_path: Option<&Path>,
    native_binary_path: Option<&Path>,
    wasm_module_path: Option<&Path>,
    wasm_metadata_path: Option<&Path>,
    compile_requested: bool,
    feature_count: usize,
) {
    let actions = report
        .actions
        .iter()
        .map(|action| action.action.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let learned_lines = vec![
        format!(
            "Fan-out pipeline learned from `{}` over {feature_count} features.",
            report.fanout_column
        ),
        format!("Built one applicability gate for each action: {actions}."),
    ];
    let metrics = vec![
        ("Rows".to_string(), report.rows.to_string()),
        (
            "Exact set match".to_string(),
            percent(report.training_exact_set_match),
        ),
    ];
    let top_rules = top_rule_lines(
        learned.gates.iter().map(|gate| {
            let rule = gate
                .gate
                .rules
                .first()
                .and_then(|rule| rule.label.as_deref().or(rule.message.as_deref()))
                .unwrap_or("default gate");
            format!("{}: {rule}", gate.action)
        }),
        3,
    );
    let mut extra_files = Vec::new();
    if let Some(feature_dictionary_path) = feature_dictionary_path {
        extra_files.push((
            "Feature dictionary".to_string(),
            feature_dictionary_path.to_path_buf(),
        ));
    }
    if let Some(native_binary_path) = native_binary_path {
        extra_files.push((
            "Native runner".to_string(),
            native_binary_path.to_path_buf(),
        ));
    }
    if let Some(wasm_module_path) = wasm_module_path {
        extra_files.push(("Wasm module".to_string(), wasm_module_path.to_path_buf()));
    }
    if let Some(wasm_metadata_path) = wasm_metadata_path {
        extra_files.push((
            "Wasm metadata".to_string(),
            wasm_metadata_path.to_path_buf(),
        ));
    }
    PostBuildSummary {
        artifact_kind: "fan-out pipeline",
        artifact_name: report.artifact_name.clone(),
        learned: learned_lines,
        metrics,
        top_rules,
        bundle_path: output_dir.to_path_buf(),
        entrypoint_path: output_dir.join("artifact.json"),
        ir_path: Some(pipeline_path.to_path_buf()),
        report_path: Some(report_path.to_path_buf()),
        extra_files,
        compile_requested,
        wasm_skipped: compile_requested && wasm_module_path.is_none(),
    }
    .render();
}

fn fanout_deployables(
    native_path: Option<&Path>,
    wasm_path: Option<&Path>,
) -> Vec<ArtifactDeployable> {
    native_path
        .map(|path| ArtifactDeployable {
            kind: "native_binary".to_string(),
            path: manifest_file_name(path),
        })
        .into_iter()
        .chain(wasm_path.map(|path| ArtifactDeployable {
            kind: "wasm_module".to_string(),
            path: manifest_file_name(path),
        }))
        .collect()
}

fn fanout_metadata_files(
    wasm_path: Option<&Path>,
    wasm_metadata_path: Option<&Path>,
) -> Vec<ArtifactSidecar> {
    wasm_metadata_path
        .map(|path| ArtifactSidecar {
            kind: "wasm_metadata".to_string(),
            path: manifest_file_name(path),
            companion_to: wasm_path.map(manifest_file_name),
        })
        .into_iter()
        .collect()
}

fn manifest_file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
