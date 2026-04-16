// SPDX-License-Identifier: MIT
use anstream::println;
use indicatif::{ProgressBar, ProgressStyle};
use logicpearl_build::{
    attach_generated_file_hashes, build_gate_artifact_from_rows,
    load_source_manifest_for_provenance, plugin_provenance_from_execution, source_input_provenance,
    trace_input_provenance, BuildProvenanceInputs,
};
use logicpearl_discovery::{
    build_result_for_report, load_decision_traces_auto_with_feature_selection, BuildOptions,
    DecisionTraceRow, ExactSelectionBackend, FeatureColumnSelection, ResidualRecoveryState,
};
use logicpearl_plugin::{
    run_plugin_with_policy_and_metadata, PluginManifest, PluginRequest, PluginStage,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::config::apply_build_config;
use super::{
    build_trace_plugin_options, default_gate_id_from_path, feature_column_selection,
    feature_columns_from_decision_rows, generated_feature_dictionary_for_output,
    generated_feature_dictionary_path, guidance, parse_key_value_entries, run_action_build,
    should_generate_feature_dictionary, to_discovery_decision_mode,
    write_feature_dictionary_from_columns, BuildArgs,
};
use crate::{
    build_options_hash, compile_native_runner, compile_wasm_module, is_rust_target_installed,
    native_artifact_output_path, persist_build_report, plugin_execution_policy,
    wasm_artifact_output_path, write_named_artifact_manifest,
};

pub(crate) fn run_build(mut args: BuildArgs) -> Result<()> {
    apply_build_config(&mut args)?;
    if args.action_column.is_some() {
        return run_action_build(args);
    }
    if args.trace_plugin_manifest.is_none()
        && (!args.trace_plugin_options.is_empty() || args.trace_plugin_input.is_some())
    {
        return Err(guidance(
            "trace plugin input/options were provided without a trace plugin manifest",
            "Pass --trace-plugin-manifest before using --trace-plugin-input or --trace-plugin-option.",
        ));
    }
    let plugin_policy = plugin_execution_policy(&args.plugin_execution);
    let feature_selection = feature_column_selection(&args.feature_columns, &args.exclude_columns)?;

    let output_dir = args.output_dir.clone().unwrap_or_else(|| {
        args.decision_traces
            .as_deref()
            .and_then(|path| path.parent())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("output")
    });
    let gate_id = args.gate_id.clone().unwrap_or_else(|| {
        args.decision_traces
            .as_deref()
            .map(default_gate_id_from_path)
            .unwrap_or_else(|| "decision_traces".to_string())
    });

    let mut input_traces = Vec::new();
    let mut trace_plugin_provenance = None;
    let mut enricher_plugin_provenance = None;
    let (mut rows, resolved_label_column) = match (
        &args.trace_plugin_manifest,
        &args.decision_traces,
    ) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            let mut trace_plugin_options = build_trace_plugin_options(&args)?;
            let plugin_label_column = trace_plugin_options
                .get("label_column")
                .cloned()
                .unwrap_or_else(|| "allowed".to_string());
            trace_plugin_options
                .entry("label_column".to_string())
                .or_insert_with(|| plugin_label_column.clone());
            let source = args.trace_plugin_input.clone().ok_or_else(|| {
                guidance(
                    "--trace-plugin-manifest was provided without --trace-plugin-input",
                    "Pass the raw source string or path with --trace-plugin-input when using a trace_source plugin.",
                )
            })?;
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::TraceSource,
                payload: logicpearl_plugin::build_canonical_payload(
                    &PluginStage::TraceSource,
                    Value::String(source.clone()),
                    Some(serde_json::to_value(&trace_plugin_options).into_diagnostic()?),
                ),
            };
            let execution =
                run_plugin_with_policy_and_metadata(&manifest, &request, &plugin_policy)
                    .into_diagnostic()
                    .wrap_err("trace plugin execution failed")?;
            trace_plugin_provenance = Some(
                plugin_provenance_from_execution(
                    "trace_source",
                    manifest_path,
                    &manifest,
                    &execution,
                    Some(source_input_provenance(&source)),
                    trace_plugin_options.clone(),
                )
                .into_diagnostic()?,
            );
            let traces_value = execution
                .response
                .extra
                .get("decision_traces")
                .cloned()
                .ok_or_else(|| {
                    guidance(
                        "trace plugin response is missing `decision_traces`",
                        "A trace_source plugin must return a top-level decision_traces array.",
                    )
                })?;
            let rows: Vec<DecisionTraceRow> = serde_json::from_value(traces_value)
                .into_diagnostic()
                .wrap_err("trace plugin decision_traces payload was invalid")?;
            (rows, plugin_label_column)
        }
        (None, Some(decision_traces)) => {
            let loaded = load_decision_traces_auto_with_feature_selection(
                decision_traces,
                args.label_column.as_deref(),
                args.default_label.as_deref(),
                args.rule_label.as_deref(),
                &feature_selection,
            )
            .into_diagnostic()
            .wrap_err("failed to load decision traces")?;
            input_traces.push(
                trace_input_provenance(decision_traces, loaded.rows.len()).into_diagnostic()?,
            );
            (loaded.rows, loaded.label_column)
        }
        (Some(_), Some(_)) => {
            return Err(guidance(
                "build received both a CSV path and a trace plugin",
                "Use either the positional decision trace dataset input or --trace-plugin-manifest, not both.",
            ));
        }
        (None, None) => {
            return Err(guidance(
                "build is missing an input source",
                "Provide a decision trace dataset path (.csv, .jsonl, or .json) or use --trace-plugin-manifest with --trace-plugin-input.",
            ));
        }
    };

    if args.trace_plugin_manifest.is_some() {
        apply_feature_selection_to_decision_rows(
            &mut rows,
            &feature_selection,
            "trace plugin decision_traces",
        )?;
    }

    if should_generate_feature_dictionary(&args) {
        let dictionary_path = generated_feature_dictionary_path(&output_dir);
        write_feature_dictionary_from_columns(
            &dictionary_path,
            feature_columns_from_decision_rows(&rows),
        )?;
        args.feature_dictionary = Some(dictionary_path);
    }

    let build_options = BuildOptions {
        output_dir,
        gate_id,
        label_column: resolved_label_column.clone(),
        positive_label: args.default_label.clone(),
        negative_label: args.rule_label.clone(),
        residual_pass: true,
        refine: args.refine,
        pinned_rules: args.pinned_rules.clone(),
        feature_dictionary: args.feature_dictionary.clone(),
        feature_governance: args.feature_governance.clone(),
        decision_mode: to_discovery_decision_mode(args.discovery_mode),
        max_rules: None,
        feature_selection: feature_selection.clone(),
    };
    let build_options_value = serde_json::json!({
        "gate_id": &build_options.gate_id,
        "label_column": &build_options.label_column,
        "positive_label": &build_options.positive_label,
        "negative_label": &build_options.negative_label,
        "residual_pass": build_options.residual_pass,
        "refine": build_options.refine,
        "pinned_rules": build_options
            .pinned_rules
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_dictionary": build_options
            .feature_dictionary
            .as_ref()
            .map(|path| path.display().to_string()),
        "source_manifest": args
            .source_manifest
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_governance": build_options
            .feature_governance
            .as_ref()
            .map(|path| path.display().to_string()),
        "decision_mode": build_options.decision_mode,
        "max_rules": build_options.max_rules,
        "feature_columns": &build_options.feature_selection.feature_columns,
        "exclude_columns": &build_options.feature_selection.exclude_columns,
    });
    let build_options_digest = build_options_hash(&build_options_value);

    if let Some(manifest_path) = &args.enricher_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to load enricher plugin manifest")?;
        if manifest.stage != PluginStage::Enricher {
            return Err(guidance(
                format!(
                    "plugin manifest stage mismatch: expected enricher, got {:?}",
                    manifest.stage
                ),
                "Use an enricher-stage manifest with --enricher-plugin-manifest.",
            ));
        }
        let request = PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Enricher,
            payload: logicpearl_plugin::build_canonical_payload(
                &PluginStage::Enricher,
                serde_json::to_value(&rows).into_diagnostic()?,
                None,
            ),
        };
        let execution = run_plugin_with_policy_and_metadata(&manifest, &request, &plugin_policy)
            .into_diagnostic()
            .wrap_err("enricher plugin execution failed")?;
        enricher_plugin_provenance = Some(
            plugin_provenance_from_execution(
                "enricher",
                manifest_path,
                &manifest,
                &execution,
                None,
                BTreeMap::new(),
            )
            .into_diagnostic()?,
        );
        let records_value = execution
            .response
            .extra
            .get("records")
            .cloned()
            .ok_or_else(|| {
            guidance(
                "enricher plugin response is missing `records`",
                "An enricher plugin must return a top-level records array compatible with decision traces.",
            )
        })?;
        rows = serde_json::from_value(records_value)
            .into_diagnostic()
            .wrap_err("enricher plugin records payload was invalid")?;
    }

    let source_name = if let Some(manifest) = &args.trace_plugin_manifest {
        format!(
            "plugin:{}",
            PluginManifest::from_path(manifest)
                .into_diagnostic()
                .wrap_err("failed to reload trace plugin manifest")?
                .name
        )
    } else {
        args.decision_traces
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "decision_traces".to_string())
    };

    let provenance_inputs = BuildProvenanceInputs {
        artifact_dir: Some(build_options.output_dir.clone()),
        source_references: parse_key_value_entries(&args.source_references, "source-ref")?,
        decision_traces_path: args.decision_traces.clone(),
        trace_plugin_manifest_path: args.trace_plugin_manifest.clone(),
        input_traces,
        trace_plugin: trace_plugin_provenance,
        enricher_plugin: enricher_plugin_provenance,
        feature_dictionary_path: args.feature_dictionary.clone(),
        source_manifest: load_source_manifest_for_provenance(args.source_manifest.as_deref())
            .into_diagnostic()?,
        build_options: build_options_value,
        build_options_hash: build_options_digest.clone(),
    };

    let spinner = if !args.json {
        let sp = ProgressBar::new_spinner();
        sp.set_style(ProgressStyle::with_template("{spinner:.green} {msg} ({elapsed})").unwrap());
        sp.enable_steady_tick(std::time::Duration::from_millis(80));
        sp.set_message(format!(
            "{} pearl from {} rows",
            "Building".bold().bright_green(),
            rows.len()
        ));
        Some(sp)
    } else {
        None
    };
    let mut result =
        build_gate_artifact_from_rows(&rows, source_name, &build_options, provenance_inputs)
            .into_diagnostic()
            .wrap_err("failed to build pearl from decision traces")?;
    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    let artifact_dir = PathBuf::from(&result.output_files.artifact_dir);
    let pearl_ir_path = PathBuf::from(&result.output_files.pearl_ir);
    let artifact_name = result.gate_id.clone();
    if args.compile {
        let native_binary_path = result
            .output_files
            .native_binary
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| native_artifact_output_path(&artifact_dir, &artifact_name, None));
        let native_binary = compile_native_runner(
            &pearl_ir_path,
            &artifact_dir,
            &result.gate_id,
            Some(artifact_name.clone()),
            None,
            Some(native_binary_path),
        )?;
        result.output_files.native_binary = Some(native_binary.display().to_string());

        let wasm_output = if is_rust_target_installed("wasm32-unknown-unknown") {
            let wasm_output_path = result
                .output_files
                .wasm_module
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| wasm_artifact_output_path(&artifact_dir, &artifact_name));
            Some(compile_wasm_module(
                &pearl_ir_path,
                &artifact_dir,
                &result.gate_id,
                Some(artifact_name.clone()),
                Some(wasm_output_path),
            )?)
        } else {
            None
        };
        result.output_files.wasm_module = wasm_output
            .as_ref()
            .map(|output| output.module_path.display().to_string());
        result.output_files.wasm_metadata = wasm_output
            .as_ref()
            .map(|output| output.metadata_path.display().to_string());
    } else {
        result.output_files.native_binary = None;
        result.output_files.wasm_module = None;
        result.output_files.wasm_metadata = None;
    }
    attach_generated_file_hashes(
        &mut result.provenance,
        &artifact_dir,
        [
            Some(pearl_ir_path.clone()),
            generated_feature_dictionary_for_output(&args, &artifact_dir).cloned(),
            result
                .output_files
                .native_binary
                .as_ref()
                .map(PathBuf::from),
            result.output_files.wasm_module.as_ref().map(PathBuf::from),
            result
                .output_files
                .wasm_metadata
                .as_ref()
                .map(PathBuf::from),
        ]
        .into_iter()
        .flatten(),
    )
    .into_diagnostic()?;
    persist_build_report(&result)?;
    write_named_artifact_manifest(
        &artifact_dir,
        &result.gate_id,
        &result.output_files,
        generated_feature_dictionary_for_output(&args, &artifact_dir).map(|path| path.as_path()),
        Some(build_options_digest),
    )?;

    if args.json {
        let report = build_result_for_report(&result);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Built".bold().bright_green(),
            result.gate_id.bold()
        );
        if result.cache_hit {
            println!(
                "  {} {}",
                "Cache".bright_black(),
                "reused prior build output".bold()
            );
        }
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!("  {} {}", "Rules".bright_black(), result.rules_discovered);
        if let Some(backend) = &result.exact_selection.backend {
            let backend_label = match backend {
                ExactSelectionBackend::BruteForce => "brute force",
                ExactSelectionBackend::Smt => "smt",
                ExactSelectionBackend::Mip => "mip",
            };
            let selection_summary = if result.exact_selection.adopted {
                format!(
                    "{backend_label} exact selection adopted on {} candidates",
                    result.exact_selection.shortlisted_candidates
                )
            } else {
                format!(
                    "{backend_label} exact selection kept greedy plan on {} candidates",
                    result.exact_selection.shortlisted_candidates
                )
            };
            println!(
                "  {} {}",
                "Exact selection".bright_black(),
                selection_summary
            );
            if let Some(detail) = &result.exact_selection.detail {
                println!("  {} {}", "Selection detail".bright_black(), detail);
            }
        }
        match result.residual_recovery.state {
            ResidualRecoveryState::Applied => {
                println!(
                    "  {} {}",
                    "Solver recovery".bright_black(),
                    result
                        .residual_recovery
                        .detail
                        .clone()
                        .unwrap_or_else(|| "applied".to_string())
                );
            }
            ResidualRecoveryState::NoMissedSlices => {
                println!(
                    "  {} no missed deny slices found",
                    "Solver recovery".bright_black(),
                );
            }
            ResidualRecoveryState::SolverUnavailable => {
                println!(
                    "  {} {}",
                    "Solver recovery".bright_black(),
                    result
                        .residual_recovery
                        .detail
                        .as_deref()
                        .unwrap_or("unavailable")
                );
            }
            ResidualRecoveryState::SolverError => {
                println!(
                    "  {} {}",
                    "Solver recovery".bright_black(),
                    result
                        .residual_recovery
                        .detail
                        .as_deref()
                        .unwrap_or("skipped after a solver error")
                );
            }
            ResidualRecoveryState::Disabled => {}
        }
        if result.refined_rules_applied > 0 {
            println!(
                "  {} {}",
                "Refined rules".bright_black(),
                result.refined_rules_applied
            );
        }
        if result.pinned_rules_applied > 0 {
            println!(
                "  {} {}",
                "Pinned rules".bright_black(),
                result.pinned_rules_applied
            );
        }
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", result.training_parity * 100.0).bold()
        );
        println!(
            "  {} {}",
            "Artifact bundle".bright_black(),
            result.output_files.artifact_dir
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            result.output_files.artifact_manifest
        );
        println!(
            "  {} {}",
            "Pearl IR".bright_black(),
            result.output_files.pearl_ir
        );
        println!(
            "  {} {}",
            "Build report".bright_black(),
            result.output_files.build_report
        );
        if let Some(feature_dictionary) =
            generated_feature_dictionary_for_output(&args, &artifact_dir)
        {
            println!(
                "  {} {}",
                "Feature dictionary".bright_black(),
                feature_dictionary.display()
            );
        }
        if let Some(native_binary) = &result.output_files.native_binary {
            println!("  {} {}", "Deployable".bright_black(), native_binary);
        }
        if let Some(wasm_module) = &result.output_files.wasm_module {
            println!("  {} {}", "Deployable".bright_black(), wasm_module);
            if let Some(wasm_metadata) = &result.output_files.wasm_metadata {
                println!("  {} {}", "Wasm metadata".bright_black(), wasm_metadata);
            }
        } else if args.compile {
            println!(
                "  {} {}",
                "Wasm module".bright_black(),
                "skipped (install wasm32-unknown-unknown to emit it)".bright_black()
            );
        } else {
            println!(
                "  {} {}",
                "Deployables".bright_black(),
                "not compiled by default; run `logicpearl compile <artifact>` when needed"
                    .bright_black()
            );
        }
    }
    Ok(())
}

fn apply_feature_selection_to_decision_rows(
    rows: &mut [DecisionTraceRow],
    feature_selection: &FeatureColumnSelection,
    source_name: &str,
) -> Result<()> {
    if feature_selection.feature_columns.is_none() && feature_selection.exclude_columns.is_empty() {
        return Ok(());
    }

    let Some(first) = rows.first() else {
        return Ok(());
    };
    let mut field_names = first.features.keys().cloned().collect::<Vec<_>>();
    field_names.sort();
    let selected_columns = feature_selection
        .selected_feature_columns(Path::new(source_name), &field_names, &[])
        .into_diagnostic()?;
    let selected_set = selected_columns.into_iter().collect::<BTreeSet<_>>();

    for (index, row) in rows.iter_mut().enumerate() {
        for column in &selected_set {
            if !row.features.contains_key(column) {
                return Err(guidance(
                    format!(
                        "row {} is missing selected feature column {column:?}",
                        index + 1
                    ),
                    "Trace plugins must emit rectangular feature maps before discovery.",
                ));
            }
        }
        row.features
            .retain(|column, _| selected_set.contains(column));
    }
    Ok(())
}
