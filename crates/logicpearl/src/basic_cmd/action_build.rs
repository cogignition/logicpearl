// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_benchmark::sanitize_identifier;
use logicpearl_build::{
    action_rule_report, attach_generated_file_hashes, build_provenance,
    learn_action_policy_with_progress, load_source_manifest_for_provenance,
    plugin_provenance_from_execution, prepare_action_traces_with_feature_selection,
    source_input_provenance, trace_input_provenance, ActionLearningOptions, ActionRuleBudgetReport,
    ActionRuleBuildReport, BuildProvenanceInputs,
};
use logicpearl_core::{provenance_safe_path_string, ArtifactKind};
use logicpearl_discovery::{
    load_flat_records, BuildProvenance, LoadedFlatRecords, PluginBuildProvenance,
};
use logicpearl_plugin::{
    run_plugin_with_policy_and_metadata, PluginManifest, PluginRequest, PluginResponse, PluginStage,
};
use logicpearl_runtime::sha256_prefixed;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::conflicts::{
    add_conflict_summary_to_json, print_conflict_summary, requested_conflict_report_path,
    write_action_conflict_report,
};
use super::{
    build_trace_plugin_options, default_gate_id_from_path, feature_column_selection,
    finish_progress, generated_feature_dictionary_for_output, generated_feature_dictionary_path,
    guidance, parse_key_value_entries, progress_callback, progress_enabled,
    selection_policy_from_args, set_progress_message, should_generate_feature_dictionary,
    start_progress, to_discovery_decision_mode, write_feature_dictionary_from_columns, BuildArgs,
};
use crate::{
    build_deployable_bundle_descriptor, build_options_hash, compile_native_runner,
    compile_wasm_module, is_rust_target_installed, native_artifact_output_path,
    plugin_execution_policy, write_artifact_manifest_v1, ArtifactManifestWriteOptions,
};

#[derive(Debug, Clone, Serialize)]
struct ActionBuildReport {
    source: String,
    artifact_name: String,
    action_column: String,
    default_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    no_match_action: Option<String>,
    rows: usize,
    actions: Vec<String>,
    rule_budget: ActionRuleBudgetReport,
    rules: Vec<ActionRuleBuildReport>,
    training_parity: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provenance: Option<BuildProvenance>,
}

fn action_build_report_for_report(report: &ActionBuildReport) -> ActionBuildReport {
    let mut sanitized = report.clone();
    sanitized.source = provenance_safe_path_string(&sanitized.source);
    sanitized
}

struct LoadedActionTraceRecords {
    loaded: LoadedFlatRecords,
    source_name: String,
    default_output_base: PathBuf,
    default_artifact_name: String,
    trace_plugin: Option<PluginBuildProvenance>,
}

pub(super) fn run_action_build(mut args: BuildArgs) -> Result<()> {
    let selection_policy = selection_policy_from_args(
        args.selection_policy,
        args.deny_recall_target,
        args.max_false_positive_rate,
    )
    .map_err(|message| {
        guidance(
            message,
            "Action builds only support the default balanced selection policy.",
        )
    })?;
    if !matches!(
        selection_policy,
        logicpearl_discovery::SelectionPolicy::Balanced
    ) {
        return Err(guidance(
            "action-column builds do not support recall-biased selection yet",
            "Remove the recall-biased selection flags for multi-action builds.",
        ));
    }
    if args.enricher_plugin_manifest.is_some() {
        return Err(guidance(
            "action-column builds do not support enricher plugins yet",
            "Use a trace-source plugin or normalized trace file that already includes the action column.",
        ));
    }
    let action_column = args.action_column.clone().ok_or_else(|| {
        guidance(
            "action build is missing --action-column",
            "Pass --action-column <column> or set build.action_column in logicpearl.yaml.",
        )
    })?;
    let feature_selection = feature_column_selection(&args.feature_columns, &args.exclude_columns)?;
    let spinner = start_progress(
        progress_enabled(args.json, args.progress),
        "action_build: preparing input",
    );
    let progress = progress_callback(spinner.as_ref());
    if let Some(manifest_path) = &args.trace_plugin_manifest {
        set_progress_message(
            spinner.as_ref(),
            format!("trace_plugin: {}", manifest_path.display()),
        );
    } else if let Some(traces) = &args.decision_traces {
        set_progress_message(
            spinner.as_ref(),
            format!("load_traces: {}", traces.display()),
        );
    }
    let LoadedActionTraceRecords {
        loaded,
        source_name,
        default_output_base,
        default_artifact_name,
        trace_plugin: trace_plugin_provenance,
    } = load_action_trace_records(&args, &action_column)?;
    set_progress_message(
        spinner.as_ref(),
        format!("action_build: prepared {} rows", loaded.records.len()),
    );
    let input_traces = if let Some(path) = &args.decision_traces {
        vec![trace_input_provenance(path, loaded.records.len()).into_diagnostic()?]
    } else {
        Vec::new()
    };
    let action_traces =
        prepare_action_traces_with_feature_selection(&loaded, &action_column, &feature_selection)
            .into_diagnostic()
            .wrap_err("failed to prepare action traces")?;
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| default_output_base.join("output"));
    fs::create_dir_all(&output_dir)
        .into_diagnostic()
        .wrap_err("failed to create action artifact directory")?;
    let artifact_name = args.gate_id.clone().unwrap_or(default_artifact_name);

    if should_generate_feature_dictionary(&args) {
        set_progress_message(
            spinner.as_ref(),
            "feature_dictionary: generating starter metadata",
        );
        let dictionary_path = generated_feature_dictionary_path(&output_dir);
        write_feature_dictionary_from_columns(
            &dictionary_path,
            action_traces.feature_columns.clone(),
        )?;
        args.feature_dictionary = Some(dictionary_path);
    }
    let source_manifest_provenance =
        load_source_manifest_for_provenance(args.source_manifest.as_deref()).into_diagnostic()?;

    let stale_actions_dir = output_dir.join("actions");
    if stale_actions_dir.exists() {
        fs::remove_dir_all(&stale_actions_dir)
            .into_diagnostic()
            .wrap_err("failed to remove stale action route artifacts")?;
    }
    for stale_file in [
        "pearl.ir.json",
        "pearl.wasm",
        "pearl.wasm.meta.json",
        "action_policy.ir.json",
        "build_report.json",
        "conflict_report.json",
        ".logicpearl-cache.json",
    ] {
        let path = output_dir.join(stale_file);
        if path.exists() {
            fs::remove_file(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove stale artifact file {stale_file}"))?;
        }
    }

    set_progress_message(
        spinner.as_ref(),
        "learn_action_policy: selecting action routes",
    );
    let learned_action = learn_action_policy_with_progress(
        &action_traces,
        &ActionLearningOptions {
            artifact_name: artifact_name.clone(),
            action_column: action_column.clone(),
            default_action: args.default_action.clone(),
            no_match_action: args.no_match_action.clone(),
            action_priority: args.action_priority.clone(),
            action_max_rules: args.action_max_rules,
            max_conditions: args.max_conditions,
            action_selection: args.action_selection.map(Into::into),
            output_dir: output_dir.clone(),
            refine: args.refine,
            pinned_rules: args.pinned_rules.clone(),
            feature_dictionary: args.feature_dictionary.clone(),
            feature_governance: args.feature_governance.clone(),
            decision_mode: to_discovery_decision_mode(args.discovery_mode),
        },
        progress.as_deref(),
    )
    .into_diagnostic()
    .wrap_err("failed to learn action policy")?;
    let action_policy = learned_action.action_policy;
    let default_action = learned_action.default_action;
    let no_match_action = learned_action.no_match_action;
    let priority_order = learned_action.priority_order;
    let rule_budget = learned_action.rule_budget;
    let training_parity = learned_action.training_parity;
    let action_policy_path = output_dir.join("pearl.ir.json");
    set_progress_message(spinner.as_ref(), "write_ir: pearl.ir.json");
    action_policy
        .write_pretty(&action_policy_path)
        .into_diagnostic()
        .wrap_err("failed to write action policy IR")?;

    let build_options_value = serde_json::json!({
        "artifact_name": &artifact_name,
        "action_column": &action_column,
        "default_action": &default_action,
        "no_match_action": &no_match_action,
        "actions": &action_policy.actions,
        "action_priority": &args.action_priority,
        "priority_order": &priority_order,
        "action_max_rules": args.action_max_rules,
        "max_conditions": args.max_conditions,
        "action_selection": args.action_selection,
        "rule_budget": &rule_budget,
        "refine": args.refine,
        "pinned_rules": args
            .pinned_rules
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_dictionary": args
            .feature_dictionary
            .as_ref()
            .map(|path| path.display().to_string()),
        "source_manifest": args
            .source_manifest
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_governance": args
            .feature_governance
            .as_ref()
            .map(|path| path.display().to_string()),
        "decision_mode": to_discovery_decision_mode(args.discovery_mode),
        "feature_columns": &feature_selection.feature_columns,
        "exclude_columns": &feature_selection.exclude_columns,
    });
    let build_options_digest = build_options_hash(&build_options_value);

    let mut action_report = ActionBuildReport {
        source: source_name,
        artifact_name: artifact_name.clone(),
        action_column: action_column.clone(),
        default_action: default_action.clone(),
        no_match_action: no_match_action.clone(),
        rows: loaded.records.len(),
        actions: action_policy.actions.clone(),
        rule_budget: rule_budget.clone(),
        rules: action_rule_report(&action_policy),
        training_parity,
        provenance: Some(
            build_provenance(BuildProvenanceInputs {
                artifact_dir: Some(output_dir.clone()),
                source_references: parse_key_value_entries(&args.source_references, "source-ref")?,
                decision_traces_path: args.decision_traces.clone(),
                trace_plugin_manifest_path: args.trace_plugin_manifest.clone(),
                input_traces,
                trace_plugin: trace_plugin_provenance,
                enricher_plugin: None,
                observation_runs: Vec::new(),
                feature_dictionary_path: args.feature_dictionary.clone(),
                source_manifest: source_manifest_provenance,
                build_options: build_options_value,
                build_options_hash: build_options_digest.clone(),
            })
            .into_diagnostic()?,
        ),
    };
    let action_report_path = output_dir.join("action_report.json");

    let mut native_binary_file = None;
    let mut wasm_module_file = None;
    let mut wasm_metadata_file = None;
    if args.compile {
        set_progress_message(spinner.as_ref(), "compile: native runner");
        let native_binary_path = native_artifact_output_path(&output_dir, &artifact_name, None);
        let native_binary = compile_native_runner(
            &action_policy_path,
            &output_dir,
            &artifact_name,
            Some(artifact_name.clone()),
            None,
            Some(native_binary_path),
        )?;
        native_binary_file = native_binary
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());

        if is_rust_target_installed("wasm32-unknown-unknown") {
            set_progress_message(spinner.as_ref(), "compile: wasm module");
            let wasm_output = compile_wasm_module(
                &action_policy_path,
                &output_dir,
                &artifact_name,
                Some(artifact_name.clone()),
                Some(output_dir.join("pearl.wasm")),
            )?;
            wasm_module_file = wasm_output
                .module_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            wasm_metadata_file = wasm_output
                .metadata_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
        }
    }

    set_progress_message(spinner.as_ref(), "write_outputs: manifest and reports");
    attach_generated_file_hashes(
        &mut action_report.provenance,
        &output_dir,
        [
            Some(action_policy_path.clone()),
            generated_feature_dictionary_for_output(&args, &output_dir).cloned(),
            native_binary_file
                .as_ref()
                .map(|file| output_dir.join(file)),
            wasm_module_file.as_ref().map(|file| output_dir.join(file)),
            wasm_metadata_file
                .as_ref()
                .map(|file| output_dir.join(file)),
        ]
        .into_iter()
        .flatten(),
    )
    .into_diagnostic()?;
    let conflicts_requested = args.show_conflicts || args.conflict_report.is_some();
    let conflict_summary = if conflicts_requested {
        write_action_conflict_report(
            requested_conflict_report_path(&output_dir, args.conflict_report.as_ref()),
            &output_dir,
            &action_policy,
            &action_traces,
            training_parity,
            args.conflict_report.is_some(),
        )?
    } else {
        None
    };
    let public_action_report = action_build_report_for_report(&action_report);
    fs::write(
        &action_report_path,
        serde_json::to_string_pretty(&public_action_report).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write action report")?;

    let mut extensions = BTreeMap::new();
    extensions.insert(
        "action_column".to_string(),
        serde_json::json!(action_column),
    );
    extensions.insert(
        "default_action".to_string(),
        serde_json::json!(default_action),
    );
    if let Some(no_match_action) = &no_match_action {
        extensions.insert(
            "no_match_action".to_string(),
            serde_json::json!(no_match_action),
        );
    }
    extensions.insert(
        "actions".to_string(),
        serde_json::json!(&action_policy.actions),
    );
    extensions.insert(
        "action_priority".to_string(),
        serde_json::json!(priority_order),
    );
    extensions.insert(
        "action_rule_budget".to_string(),
        serde_json::json!(rule_budget),
    );
    write_artifact_manifest_v1(
        &output_dir,
        ArtifactManifestWriteOptions {
            artifact_kind: ArtifactKind::Action,
            artifact_id: artifact_name.clone(),
            ir_path: action_policy_path.clone(),
            build_report_path: Some(action_report_path.clone()),
            feature_dictionary_path: generated_feature_dictionary_for_output(&args, &output_dir)
                .map(|path| path.as_path().to_path_buf()),
            native_path: native_binary_file
                .as_ref()
                .map(|file| output_dir.join(file)),
            wasm_path: wasm_module_file.as_ref().map(|file| output_dir.join(file)),
            wasm_metadata_path: wasm_metadata_file
                .as_ref()
                .map(|file| output_dir.join(file)),
            build_options_hash: Some(build_options_digest),
            bundle: build_deployable_bundle_descriptor(
                native_binary_file.clone(),
                wasm_module_file.clone(),
                wasm_metadata_file.clone(),
            ),
            extensions,
            file_extensions: BTreeMap::new(),
        },
    )
    .wrap_err("failed to write action artifact manifest")?;
    finish_progress(spinner);

    if args.json {
        let mut report = serde_json::to_value(&public_action_report)
            .into_diagnostic()
            .wrap_err("failed to serialize action build report")?;
        add_conflict_summary_to_json(&mut report, conflicts_requested, conflict_summary.as_ref());
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Built action artifact".bold().bright_green(),
            artifact_name.bold()
        );
        println!("  {} {}", "Rows".bright_black(), action_report.rows);
        println!(
            "  {} {}",
            "Actions".bright_black(),
            action_report.actions.join(", ")
        );
        println!(
            "  {} {}",
            "Default action".bright_black(),
            action_report.default_action
        );
        if let Some(no_match_action) = &action_report.no_match_action {
            println!("  {} {}", "No-match action".bright_black(), no_match_action);
        }
        println!(
            "  {} {}",
            "Action priority".bright_black(),
            action_report.rule_budget.priority_order.join(", ")
        );
        println!(
            "  {} {} ({})",
            "Rule budget".bright_black(),
            action_report.rule_budget.total_budget,
            action_report.rule_budget.mode
        );
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", action_report.training_parity * 100.0).bold()
        );
        print_conflict_summary(conflict_summary.as_ref(), conflicts_requested);
        println!(
            "  {} {}",
            "Artifact bundle".bright_black(),
            output_dir.display()
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            output_dir.join("artifact.json").display()
        );
        println!(
            "  {} {}",
            "Pearl IR".bright_black(),
            action_policy_path.display()
        );
        if let Some(feature_dictionary) =
            generated_feature_dictionary_for_output(&args, &output_dir)
        {
            println!(
                "  {} {}",
                "Feature dictionary".bright_black(),
                feature_dictionary.display()
            );
        }
        if let Some(native_binary) = &native_binary_file {
            println!(
                "  {} {}",
                "Deployable".bright_black(),
                output_dir.join(native_binary).display()
            );
        }
        if let Some(wasm_module) = &wasm_module_file {
            println!(
                "  {} {}",
                "Deployable".bright_black(),
                output_dir.join(wasm_module).display()
            );
            if let Some(wasm_metadata) = &wasm_metadata_file {
                println!(
                    "  {} {}",
                    "Wasm metadata".bright_black(),
                    output_dir.join(wasm_metadata).display()
                );
            }
        } else if args.compile {
            println!(
                "  {} {}",
                "Wasm module".bright_black(),
                "skipped (install wasm32-unknown-unknown to emit it)".bright_black()
            );
        }
    }
    Ok(())
}

fn load_action_trace_records(
    args: &BuildArgs,
    action_column: &str,
) -> Result<LoadedActionTraceRecords> {
    if args.trace_plugin_manifest.is_none()
        && (!args.trace_plugin_options.is_empty() || args.trace_plugin_input.is_some())
    {
        return Err(guidance(
            "trace plugin input/options were provided without a trace plugin manifest",
            "Pass --trace-plugin-manifest before using --trace-plugin-input or --trace-plugin-option.",
        ));
    }

    match (&args.trace_plugin_manifest, &args.decision_traces) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            if manifest.stage != PluginStage::TraceSource {
                return Err(guidance(
                    format!(
                        "plugin manifest stage mismatch: expected trace_source, got {:?}",
                        manifest.stage
                    ),
                    "Use a trace_source-stage manifest with --trace-plugin-manifest.",
                ));
            }
            let mut options = build_trace_plugin_options(args)?;
            options
                .entry("action_column".to_string())
                .or_insert_with(|| action_column.to_string());
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
                    Some(serde_json::to_value(&options).into_diagnostic()?),
                ),
            };
            let policy = plugin_execution_policy(&args.plugin_execution);
            let execution = run_plugin_with_policy_and_metadata(&manifest, &request, &policy)
                .into_diagnostic()
                .wrap_err("trace plugin execution failed")?;
            let provenance = plugin_provenance_from_execution(
                "trace_source",
                manifest_path,
                &manifest,
                &execution,
                Some(source_input_provenance(&source)),
                options.clone(),
            )
            .into_diagnostic()?;
            let loaded = action_records_from_plugin_response(&execution.response, action_column)?;
            let source_name = format!(
                "plugin:{}:{}",
                manifest.name,
                redacted_source_display(&source)
            );
            let default_artifact_name = default_action_artifact_name_from_plugin_input(&source);
            Ok(LoadedActionTraceRecords {
                loaded,
                source_name,
                default_output_base: PathBuf::from("."),
                default_artifact_name: if default_artifact_name.is_empty() {
                    "action_policy".to_string()
                } else {
                    default_artifact_name
                },
                trace_plugin: Some(provenance),
            })
        }
        (None, Some(traces)) => {
            let loaded = load_flat_records(traces)
                .into_diagnostic()
                .wrap_err("failed to load action traces")?;
            Ok(LoadedActionTraceRecords {
                loaded,
                source_name: traces.display().to_string(),
                default_output_base: traces
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
                default_artifact_name: default_gate_id_from_path(traces),
                trace_plugin: None,
            })
        }
        (Some(_), Some(_)) => Err(guidance(
            "action build received both a trace file and a trace plugin",
            "Use either the positional trace dataset input or --trace-plugin-manifest, not both.",
        )),
        (None, None) => Err(guidance(
            "action build is missing traces",
            "Pass a trace dataset path or use --trace-plugin-manifest with --trace-plugin-input.",
        )),
    }
}

fn default_action_artifact_name_from_plugin_input(source: &str) -> String {
    let path = Path::new(source);
    if path.exists() {
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            let name = sanitize_identifier(stem);
            if !name.is_empty() {
                return name;
            }
        }
    }
    let hash = sha256_prefixed(source.as_bytes());
    format!(
        "action_policy_{}",
        &hash["sha256:".len().."sha256:".len() + 12]
    )
}

fn redacted_source_display(source: &str) -> String {
    if Path::new(source).exists() {
        provenance_safe_path_string(source)
    } else {
        format!("<inline:{}>", sha256_prefixed(source.as_bytes()))
    }
}

fn action_records_from_plugin_response(
    response: &PluginResponse,
    action_column: &str,
) -> Result<LoadedFlatRecords> {
    let records_value = response
        .extra
        .get("records")
        .or_else(|| response.extra.get("decision_traces"))
        .cloned()
        .ok_or_else(|| {
            guidance(
                "trace plugin response is missing action records",
                "For action builds, return a top-level `records` array of flat trace rows, or `decision_traces` rows with features plus the action column.",
            )
        })?;
    let rows = records_value.as_array().ok_or_else(|| {
        guidance(
            "trace plugin action records must be an array",
            "Return `records: [...]` or `decision_traces: [...]` from the trace_source plugin.",
        )
    })?;

    let mut records = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        records.push(flatten_plugin_action_record(index + 1, row, action_column)?);
    }
    let field_names = action_record_field_names(&records)?;
    Ok(LoadedFlatRecords {
        field_names,
        records,
    })
}

fn flatten_plugin_action_record(
    row_number: usize,
    row: &Value,
    action_column: &str,
) -> Result<BTreeMap<String, Value>> {
    let object = row.as_object().ok_or_else(|| {
        guidance(
            format!("trace plugin action row {row_number} is not an object"),
            "Each action trace row must be a flat object, or an object with `features` plus the action column.",
        )
    })?;
    let mut out = BTreeMap::new();
    if let Some(features) = object.get("features") {
        let features = features.as_object().ok_or_else(|| {
            guidance(
                format!("trace plugin action row {row_number} has non-object features"),
                "`features` must be an object of scalar feature values.",
            )
        })?;
        for (key, value) in features {
            insert_plugin_scalar(&mut out, key, value, row_number)?;
        }
        let action = object
            .get(action_column)
            .or_else(|| object.get("action"))
            .ok_or_else(|| {
                guidance(
                    format!("trace plugin action row {row_number} is missing {action_column:?}"),
                    "Put the action label at the top level beside `features`, or return flat records.",
                )
            })?;
        insert_plugin_scalar(&mut out, action_column, action, row_number)?;
        return Ok(out);
    }

    for (key, value) in object {
        insert_plugin_scalar(&mut out, key, value, row_number)?;
    }
    Ok(out)
}

fn insert_plugin_scalar(
    out: &mut BTreeMap<String, Value>,
    key: &str,
    value: &Value,
    row_number: usize,
) -> Result<()> {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => Err(guidance(
            format!("trace plugin action row {row_number} has a non-scalar value for {key:?}"),
            "Action trace plugins must emit normalized scalar fields before discovery.",
        )),
        scalar => {
            out.insert(key.to_string(), scalar.clone());
            Ok(())
        }
    }
}

fn action_record_field_names(records: &[BTreeMap<String, Value>]) -> Result<Vec<String>> {
    let Some(first) = records.first() else {
        return Ok(Vec::new());
    };
    let field_names = first.keys().cloned().collect::<Vec<_>>();
    for (index, record) in records.iter().enumerate().skip(1) {
        let names = record.keys().cloned().collect::<Vec<_>>();
        if names != field_names {
            return Err(guidance(
                format!("trace plugin action row {} has a different schema", index + 1),
                "Action trace plugins must emit rectangular records with the same fields in every row.",
            ));
        }
    }
    Ok(field_names)
}
