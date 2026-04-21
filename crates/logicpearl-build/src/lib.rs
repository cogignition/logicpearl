// SPDX-License-Identifier: MIT
//! Shared build orchestration and provenance assembly.
//!
//! This crate keeps shared build behavior available to library
//! consumers instead of hiding it inside the CLI. It coordinates gate builds,
//! prepares and learns action policies, assembles build/source/plugin
//! provenance, validates source manifests, and records generated file hashes.
//! The CLI remains responsible for argument parsing and terminal rendering.

use logicpearl_core::{provenance_safe_path, provenance_safe_path_string, LogicPearlError, Result};
use logicpearl_discovery::{
    action_trace_provenance_from_record, build_pearl_from_rows_with_progress,
    learn_gate_from_rows_without_numeric_interactions_with_progress, report_progress,
    BuildCommandProvenance, BuildInputProvenance, BuildOptions, BuildProvenance, BuildResult,
    DecisionTraceProvenance, DecisionTraceRow, DiscoveryDecisionMode, FeatureColumnSelection,
    FileProvenance, LoadedFlatRecords, ObservationFeatureType, ObservationRunProvenance,
    ObservationSchema, ObservedFeature, PluginBuildProvenance, ProgressCallback, ProposalPolicy,
    SourceManifest, SourceManifestProvenance, TraceInputProvenance,
};
use logicpearl_ir::{
    ActionEvaluationConfig, ActionRuleDefinition, ActionSelectionStrategy, LogicPearlActionIr,
    VerificationConfig,
};
use logicpearl_plugin::{
    PluginEntrypointMetadata, PluginExecutionResult, PluginManifest, PluginResponse,
};
use logicpearl_runtime::{
    artifact_hash, evaluate_action_policy, evaluate_gate, sha256_prefixed,
    LOGICPEARL_ENGINE_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PreparedActionTraces {
    pub feature_columns: Vec<String>,
    pub actions: Vec<String>,
    pub action_by_row: Vec<String>,
    pub features_by_row: Vec<HashMap<String, Value>>,
    pub trace_provenance_by_row: Vec<DecisionTraceProvenance>,
}

#[derive(Debug, Clone)]
pub struct ActionLearningOptions {
    pub artifact_name: String,
    pub action_column: String,
    pub default_action: Option<String>,
    pub no_match_action: Option<String>,
    pub action_priority: Option<String>,
    pub action_max_rules: Option<usize>,
    pub output_dir: PathBuf,
    pub refine: bool,
    pub pinned_rules: Option<PathBuf>,
    pub feature_dictionary: Option<PathBuf>,
    pub feature_governance: Option<PathBuf>,
    pub decision_mode: DiscoveryDecisionMode,
}

#[derive(Debug, Clone)]
pub struct ActionLearningResult {
    pub action_policy: LogicPearlActionIr,
    pub default_action: String,
    pub no_match_action: Option<String>,
    pub priority_order: Vec<String>,
    pub rule_budget: ActionRuleBudgetReport,
    pub training_parity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRuleBudgetReport {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_max_rules: Option<usize>,
    pub total_budget: usize,
    pub priority_order: Vec<String>,
    pub per_action: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionRuleBuildReport {
    pub id: String,
    pub bit: u32,
    pub action: String,
    pub priority: u32,
    pub label: Option<String>,
}

pub struct BuildProvenanceInputs {
    pub artifact_dir: Option<PathBuf>,
    pub source_references: BTreeMap<String, String>,
    pub decision_traces_path: Option<PathBuf>,
    pub trace_plugin_manifest_path: Option<PathBuf>,
    pub input_traces: Vec<TraceInputProvenance>,
    pub trace_plugin: Option<PluginBuildProvenance>,
    pub enricher_plugin: Option<PluginBuildProvenance>,
    pub observation_runs: Vec<ObservationRunProvenance>,
    pub feature_dictionary_path: Option<PathBuf>,
    pub source_manifest: Option<SourceManifestProvenance>,
    pub build_options: Value,
    pub build_options_hash: String,
}

pub fn build_gate_artifact_from_rows(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
    provenance_inputs: BuildProvenanceInputs,
) -> Result<BuildResult> {
    build_gate_artifact_from_rows_with_progress(rows, source_name, options, provenance_inputs, None)
}

pub fn build_gate_artifact_from_rows_with_progress(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
    provenance_inputs: BuildProvenanceInputs,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<BuildResult> {
    let provenance = build_provenance(provenance_inputs)?;
    let mut result = build_pearl_from_rows_with_progress(rows, source_name, options, progress)?;
    result.provenance = Some(provenance);
    Ok(result)
}

pub fn prepare_action_traces(
    loaded: &LoadedFlatRecords,
    action_column: &str,
) -> Result<PreparedActionTraces> {
    prepare_action_traces_with_feature_selection(
        loaded,
        action_column,
        &FeatureColumnSelection::default(),
    )
}

pub fn prepare_action_traces_with_feature_selection(
    loaded: &LoadedFlatRecords,
    action_column: &str,
    feature_selection: &FeatureColumnSelection,
) -> Result<PreparedActionTraces> {
    if !loaded.field_names.iter().any(|name| name == action_column) {
        return Err(LogicPearlError::message(format!(
            "action trace input is missing action column {action_column:?}"
        )));
    }
    let feature_columns = feature_selection.selected_feature_columns(
        Path::new("action traces"),
        &loaded.field_names,
        &[action_column.to_string()],
    )?;

    let mut actions = Vec::<String>::new();
    let mut action_by_row = Vec::<String>::new();
    let mut features_by_row = Vec::<HashMap<String, Value>>::new();
    let mut trace_provenance_by_row = Vec::<DecisionTraceProvenance>::new();
    for (index, record) in loaded.records.iter().enumerate() {
        let raw_action = record.get(action_column).ok_or_else(|| {
            LogicPearlError::message(format!(
                "row {} is missing action column {action_column:?}",
                index + 1
            ))
        })?;
        let action = action_value_to_string(raw_action)?;
        if action.is_empty() {
            return Err(LogicPearlError::message(format!(
                "row {} has an empty action",
                index + 1
            )));
        }
        if !actions.iter().any(|known| known == &action) {
            actions.push(action.clone());
        }
        let mut features = HashMap::new();
        for feature in &feature_columns {
            let value = record.get(feature).ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {} is missing feature {feature:?}",
                    index + 1
                ))
            })?;
            features.insert(feature.clone(), value.clone());
        }
        let trace_provenance = action_trace_provenance_from_record(record, &features, &action);
        action_by_row.push(action);
        features_by_row.push(features);
        trace_provenance_by_row.push(trace_provenance);
    }
    if actions.len() < 2 {
        return Err(LogicPearlError::message(
            "action traces need at least two distinct actions",
        ));
    }

    Ok(PreparedActionTraces {
        feature_columns,
        actions,
        action_by_row,
        features_by_row,
        trace_provenance_by_row,
    })
}

pub fn learn_action_policy(
    traces: &PreparedActionTraces,
    options: &ActionLearningOptions,
) -> Result<ActionLearningResult> {
    learn_action_policy_with_progress(traces, options, None)
}

pub fn learn_action_policy_with_progress(
    traces: &PreparedActionTraces,
    options: &ActionLearningOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<ActionLearningResult> {
    let default_action =
        resolve_default_action(options.default_action.as_deref(), &traces.actions)?;
    let no_match_action = resolve_no_match_action(options.no_match_action.as_deref())?;
    let support_counts = action_support_counts(&traces.action_by_row);
    report_progress(
        progress,
        "action_priority",
        format!(
            "action_priority: {} rows across {} actions",
            traces.action_by_row.len(),
            traces.actions.len()
        ),
    );
    let priority_order = resolve_action_priority_order(
        &traces.actions,
        &default_action,
        options.action_priority.as_deref(),
        &support_counts,
    )?;
    let rule_budget =
        allocate_action_rule_budget(&priority_order, &support_counts, options.action_max_rules)?;

    let mut input_schema = None;
    let mut action_rules = Vec::new();
    let mut covered_by_priority = vec![false; traces.action_by_row.len()];
    for action in &priority_order {
        report_progress(
            progress,
            "action_route",
            format!("action_route: learning {action}"),
        );
        let action_rule_budget = rule_budget.per_action.get(action).copied().unwrap_or(0);
        if action_rule_budget == 0 {
            continue;
        }
        let mut target_rows = 0usize;
        let route_rows = traces
            .action_by_row
            .iter()
            .zip(traces.features_by_row.iter())
            .enumerate()
            .filter_map(|(index, (row_action, features))| {
                if covered_by_priority[index] {
                    return None;
                }
                let is_target_action = row_action == action;
                if is_target_action {
                    target_rows += 1;
                }
                Some(DecisionTraceRow {
                    features: features.clone(),
                    allowed: !is_target_action,
                    trace_provenance: traces.trace_provenance_by_row.get(index).cloned(),
                })
            })
            .collect::<Vec<_>>();
        if target_rows == 0 {
            continue;
        }
        let route_name = sanitize_identifier(action);
        let route_gate_id = format!("{}_{}", options.artifact_name, route_name);
        let learned = learn_gate_from_rows_without_numeric_interactions_with_progress(
            &route_rows,
            &BuildOptions {
                output_dir: options.output_dir.clone(),
                gate_id: route_gate_id,
                label_column: options.action_column.clone(),
                positive_label: None,
                negative_label: Some(action.clone()),
                residual_pass: true,
                refine: options.refine,
                pinned_rules: options.pinned_rules.clone(),
                feature_dictionary: options.feature_dictionary.clone(),
                feature_governance: options.feature_governance.clone(),
                decision_mode: options.decision_mode,
                max_rules: Some(action_rule_budget),
                proposal_policy: ProposalPolicy::ReportOnly,
                feature_selection: FeatureColumnSelection::default(),
            },
            progress,
        )
        .map_err(|err| {
            LogicPearlError::message(format!(
                "failed to learn action rules for {action:?}: {err}"
            ))
        })?;
        let learned_gate = learned.gate;
        if input_schema.is_none() {
            input_schema = Some(learned_gate.input_schema.clone());
        }
        for (index, features) in traces.features_by_row.iter().enumerate() {
            if covered_by_priority[index] {
                continue;
            }
            let bitmask = evaluate_gate(&learned_gate, features).map_err(|err| {
                LogicPearlError::message(format!(
                    "failed to evaluate learned priority route for action {action:?}: {err}"
                ))
            })?;
            if !bitmask.is_zero() {
                covered_by_priority[index] = true;
            }
        }
        for rule in learned_gate.rules {
            let bit = u32::try_from(action_rules.len()).map_err(|err| {
                LogicPearlError::message(format!("too many action rules to index: {err}"))
            })?;
            action_rules.push(ActionRuleDefinition {
                id: format!("rule_{bit:03}"),
                bit,
                action: action.clone(),
                priority: bit,
                predicate: rule.deny_when,
                label: rule.label,
                message: rule.message,
                severity: rule.severity,
                counterfactual_hint: rule.counterfactual_hint,
                verification_status: rule.verification_status,
                evidence: rule.evidence,
            });
        }
    }

    let input_schema = input_schema.ok_or_else(|| {
        LogicPearlError::message("action build did not produce any non-default action rules")
    })?;
    let mut actions = traces.actions.clone();
    if let Some(no_match_action) = &no_match_action {
        if !actions.iter().any(|known| known == no_match_action) {
            actions.push(no_match_action.clone());
        }
    }

    let action_policy = LogicPearlActionIr {
        ir_version: "1.0".to_string(),
        action_policy_id: options.artifact_name.clone(),
        action_policy_type: "priority_rules".to_string(),
        action_column: options.action_column.clone(),
        default_action: default_action.clone(),
        no_match_action: no_match_action.clone(),
        actions,
        input_schema,
        rules: action_rules,
        evaluation: ActionEvaluationConfig {
            selection: ActionSelectionStrategy::FirstMatch,
        },
        verification: Some(VerificationConfig {
            domain_constraints: None,
            correctness_scope: Some(format!(
                "training parity against {} action traces",
                traces.action_by_row.len()
            )),
            verification_summary: None,
        }),
        provenance: None,
    };
    action_policy.validate()?;
    let training_parity = compute_action_training_parity(
        &action_policy,
        &traces.features_by_row,
        &traces.action_by_row,
    )?;

    Ok(ActionLearningResult {
        action_policy,
        default_action,
        no_match_action,
        priority_order,
        rule_budget,
        training_parity,
    })
}

pub fn action_rule_report(policy: &LogicPearlActionIr) -> Vec<ActionRuleBuildReport> {
    policy
        .rules
        .iter()
        .map(|rule| ActionRuleBuildReport {
            id: rule.id.clone(),
            bit: rule.bit,
            action: rule.action.clone(),
            priority: rule.priority,
            label: rule.label.clone(),
        })
        .collect()
}

pub fn build_provenance(inputs: BuildProvenanceInputs) -> Result<BuildProvenance> {
    let artifact_dir = inputs.artifact_dir.as_deref();
    let raw_source_references = inputs.source_references;
    let source_references = sanitize_source_references(&raw_source_references);
    let decision_trace_source = if let Some(path) = &inputs.decision_traces_path {
        Some(BuildInputProvenance {
            kind: "decision_traces_path".to_string(),
            value: provenance_safe_path(path),
            hash: hash_file_for_provenance(path).ok(),
        })
    } else {
        inputs
            .trace_plugin_manifest_path
            .as_ref()
            .map(|manifest| BuildInputProvenance {
                kind: "trace_plugin".to_string(),
                value: provenance_safe_path(manifest),
                hash: hash_file_for_provenance(manifest).ok(),
            })
    };

    let plugins = [inputs.trace_plugin.clone(), inputs.enricher_plugin.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let feature_dictionary = inputs
        .feature_dictionary_path
        .as_deref()
        .filter(|path| path.exists())
        .map(|path| file_provenance(path, artifact_dir))
        .transpose()?;
    let build_command = build_command_provenance();
    let mut redactions = Vec::new();
    if build_command.redacted {
        redactions.push("build_command".to_string());
    }
    let build_options = sanitize_build_options_for_provenance(&inputs.build_options);
    if build_options != inputs.build_options {
        redactions.push("build_options".to_string());
    }
    if source_references != raw_source_references {
        redactions.push("source_references".to_string());
    }

    Ok(BuildProvenance {
        schema_version: "logicpearl.build_provenance.v1".to_string(),
        engine_version: LOGICPEARL_ENGINE_VERSION.to_string(),
        engine_commit: resolve_engine_commit(),
        build_command: Some(build_command),
        build_options: Some(build_options),
        build_options_hash: Some(inputs.build_options_hash),
        input_traces: inputs.input_traces,
        feature_dictionary,
        plugins,
        observation_runs: inputs.observation_runs,
        source_manifest: inputs.source_manifest,
        environment: build_environment_summary(),
        generated_files: BTreeMap::new(),
        generated_file_notes: vec![
            "build_report and artifact.json are omitted to avoid self-referential hashes; artifact manifests carry bundle file hashes for verification."
                .to_string(),
        ],
        redactions,
        decision_trace_source,
        trace_plugin: inputs.trace_plugin,
        enricher_plugin: inputs.enricher_plugin,
        source_references,
    })
}

pub fn source_input_provenance(value: &str) -> BuildInputProvenance {
    let path = Path::new(value);
    let inline_hash = sha256_prefixed(value.as_bytes());
    BuildInputProvenance {
        kind: classify_source_value(value).to_string(),
        value: if path.exists() {
            provenance_safe_path(path)
        } else {
            format!("<inline:{inline_hash}>")
        },
        hash: if path.exists() {
            hash_file_for_provenance(path).ok()
        } else {
            Some(inline_hash)
        },
    }
}

pub fn trace_input_provenance(path: &Path, row_count: usize) -> Result<TraceInputProvenance> {
    Ok(TraceInputProvenance {
        path: provenance_safe_path(path),
        hash: hash_file_for_provenance(path)?,
        row_count,
    })
}

pub fn load_source_manifest_for_provenance(
    path: Option<&Path>,
) -> Result<Option<SourceManifestProvenance>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let content = fs::read_to_string(path).map_err(|err| {
        LogicPearlError::message(format!(
            "failed to read source manifest {}: {err}",
            path.display()
        ))
    })?;
    let manifest: SourceManifest = serde_json::from_str(&content).map_err(|err| {
        LogicPearlError::message(format!("source manifest is not valid JSON: {err}"))
    })?;
    validate_source_manifest(&manifest)?;
    Ok(Some(SourceManifestProvenance {
        path: provenance_safe_path(path),
        hash: hash_file_for_provenance(path)?,
        sources: manifest.sources,
    }))
}

pub fn plugin_provenance_from_execution(
    stage: &str,
    manifest_path: &Path,
    manifest: &PluginManifest,
    execution: &PluginExecutionResult,
    input: Option<BuildInputProvenance>,
    options: BTreeMap<String, String>,
) -> Result<PluginBuildProvenance> {
    let run = &execution.run;
    Ok(PluginBuildProvenance {
        schema_version: run.schema_version.clone(),
        plugin_run_id: Some(run.plugin_run_id.clone()),
        plugin_id: Some(run.plugin_id.clone()),
        plugin_version: run.plugin_version.clone(),
        name: manifest.name.clone(),
        plugin_name: Some(run.plugin_name.clone()),
        stage: stage.to_string(),
        protocol_version: Some(run.protocol_version.clone()),
        manifest_path: provenance_safe_path(manifest_path),
        manifest_hash: run
            .manifest_hash
            .clone()
            .or_else(|| hash_file_for_provenance(manifest_path).ok()),
        manifest_sha256: Some(sha256_file_hex(manifest_path)?),
        entrypoint_hash: Some(run.entrypoint_hash.clone()),
        entrypoint: Some(serde_json::to_value(sanitize_plugin_entrypoint_metadata(
            &run.entrypoint,
        ))?),
        input,
        input_hash: run.input_hash.clone(),
        request_hash: Some(run.request_hash.clone()),
        output_hash: Some(run.output_hash.clone()),
        options: sanitize_plugin_options(&options),
        rows_emitted: rows_emitted_from_plugin_response(stage, &execution.response),
        completed_at: Some(run.completed_at.clone()),
        started_at: Some(run.started_at.clone()),
        duration_ms: Some(run.duration_ms),
        timeout_policy: Some(serde_json::to_value(&run.timeout_policy)?),
        execution_policy: Some(serde_json::to_value(&run.execution_policy)?),
        capabilities: Some(serde_json::to_value(&run.capabilities)?),
        access: Some(serde_json::to_value(&run.access)?),
        stdio: Some(serde_json::to_value(&run.stdio)?),
    })
}

pub fn observation_run_provenance_from_rows(
    stage: &str,
    plugin_run_id: Option<&str>,
    candidate_rows: &[DecisionTraceRow],
    accepted_rows: &[DecisionTraceRow],
) -> Result<ObservationRunProvenance> {
    Ok(ObservationRunProvenance {
        schema_version: "logicpearl.observation_run_provenance.v1".to_string(),
        stage: stage.to_string(),
        plugin_run_id: plugin_run_id.map(ToOwned::to_owned),
        observation_schema_hash: observation_schema_hash(candidate_rows)?,
        candidate_rows_hash: decision_trace_rows_hash(candidate_rows)?,
        accepted_rows_hash: decision_trace_rows_hash(accepted_rows)?,
        rows_emitted: candidate_rows.len(),
        rows_accepted: accepted_rows.len(),
    })
}

fn sanitize_plugin_entrypoint_metadata(
    entrypoint: &PluginEntrypointMetadata,
) -> PluginEntrypointMetadata {
    let mut sanitized = entrypoint.clone();
    sanitized.declared = sanitized
        .declared
        .iter()
        .map(|segment| provenance_safe_path_string(segment))
        .collect();
    sanitized.resolved = sanitized
        .resolved
        .iter()
        .map(|segment| provenance_safe_path_string(segment))
        .collect();
    for hash in &mut sanitized.hashes {
        hash.path = provenance_safe_path_string(&hash.path);
    }
    sanitized
}

pub fn attach_generated_file_hashes(
    provenance: &mut Option<BuildProvenance>,
    artifact_dir: &Path,
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<()> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    for path in paths {
        if path.exists() {
            let key = path
                .strip_prefix(artifact_dir)
                .ok()
                .map(|path| path.display().to_string())
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| path.display().to_string());
            provenance
                .generated_files
                .insert(key, hash_file_for_provenance(&path)?);
        }
    }
    Ok(())
}

fn action_value_to_string(value: &Value) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.trim().to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(boolean) => Ok(boolean.to_string()),
        Value::Null => Ok(String::new()),
        other => Err(LogicPearlError::message(format!(
            "action labels must be scalar, got {other}"
        ))),
    }
}

fn resolve_default_action(explicit: Option<&str>, actions: &[String]) -> Result<String> {
    if let Some(action) = explicit {
        if actions.iter().any(|known| known == action) {
            return Ok(action.to_string());
        }
        return Err(LogicPearlError::message(format!(
            "--default-action {action:?} was not found in action traces; available actions: {}",
            actions.join(", ")
        )));
    }
    for preferred in ["do_nothing", "nothing", "wait", "none", "noop"] {
        if let Some(action) = actions.iter().find(|action| action.as_str() == preferred) {
            return Ok(action.clone());
        }
    }
    Ok(actions[0].clone())
}

fn resolve_no_match_action(explicit: Option<&str>) -> Result<Option<String>> {
    let Some(action) = explicit else {
        return Ok(None);
    };
    let action = action.trim();
    if action.is_empty() {
        return Err(LogicPearlError::message(
            "--no-match-action must be non-empty when provided",
        ));
    }
    Ok(Some(action.to_string()))
}

fn action_support_counts(action_by_row: &[String]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for action in action_by_row {
        *counts.entry(action.clone()).or_insert(0) += 1;
    }
    counts
}

fn default_action_priority_order(
    actions: &[String],
    default_action: &str,
    support_counts: &BTreeMap<String, usize>,
) -> Vec<String> {
    let action_positions = actions
        .iter()
        .enumerate()
        .map(|(index, action)| (action.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut priority_order = actions
        .iter()
        .filter(|action| action.as_str() != default_action)
        .cloned()
        .collect::<Vec<_>>();
    priority_order.sort_by(|left, right| {
        support_counts
            .get(left)
            .copied()
            .unwrap_or(0)
            .cmp(&support_counts.get(right).copied().unwrap_or(0))
            .then_with(|| {
                action_positions
                    .get(left)
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(&action_positions.get(right).copied().unwrap_or(usize::MAX))
            })
    });
    priority_order
}

fn resolve_action_priority_order(
    actions: &[String],
    default_action: &str,
    explicit_priority: Option<&str>,
    support_counts: &BTreeMap<String, usize>,
) -> Result<Vec<String>> {
    let mut priority_order = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(explicit_priority) = explicit_priority {
        for action in explicit_priority.split(',') {
            let action = action.trim();
            if action.is_empty() {
                return Err(LogicPearlError::message(
                    "--action-priority contains an empty action name",
                ));
            }
            if !actions.iter().any(|known| known == action) {
                return Err(LogicPearlError::message(format!(
                    "--action-priority references unknown action {action:?}; available actions: {}",
                    actions.join(", ")
                )));
            }
            if !seen.insert(action.to_string()) {
                return Err(LogicPearlError::message(format!(
                    "--action-priority lists {action:?} more than once"
                )));
            }
            if action != default_action {
                priority_order.push(action.to_string());
            }
        }
    }

    for action in default_action_priority_order(actions, default_action, support_counts) {
        if !seen.contains(&action) {
            priority_order.push(action);
        }
    }
    Ok(priority_order)
}

fn auto_action_rule_budget(support: usize) -> usize {
    if support == 0 {
        return 0;
    }

    fn ceil_sqrt_usize(value: usize) -> usize {
        if value <= 1 {
            return value;
        }
        let mut root = 1usize;
        while root.saturating_mul(root) < value {
            root += 1;
        }
        root
    }
    ceil_sqrt_usize(support).saturating_mul(8).clamp(16, 256)
}

fn allocate_action_rule_budget(
    priority_order: &[String],
    support_counts: &BTreeMap<String, usize>,
    requested_max_rules: Option<usize>,
) -> Result<ActionRuleBudgetReport> {
    if matches!(requested_max_rules, Some(0)) {
        return Err(LogicPearlError::message(
            "--action-max-rules must be greater than zero",
        ));
    }

    let auto_per_action = priority_order
        .iter()
        .map(|action| {
            (
                action.clone(),
                auto_action_rule_budget(support_counts.get(action).copied().unwrap_or(0)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let per_action = if let Some(max_rules) = requested_max_rules {
        let mut remaining = max_rules;
        let mut per_action = BTreeMap::new();
        for (index, action) in priority_order.iter().enumerate() {
            if remaining == 0 {
                per_action.insert(action.clone(), 0);
                continue;
            }
            let remaining_actions = priority_order.len().saturating_sub(index + 1);
            let reserved_for_later = remaining_actions.min(remaining.saturating_sub(1));
            let available = remaining.saturating_sub(reserved_for_later);
            let budget = auto_per_action
                .get(action)
                .copied()
                .unwrap_or(0)
                .min(available)
                .max(1);
            per_action.insert(action.clone(), budget);
            remaining = remaining.saturating_sub(budget);
        }
        per_action
    } else {
        auto_per_action
    };
    let total_budget = per_action.values().copied().sum();
    Ok(ActionRuleBudgetReport {
        mode: if requested_max_rules.is_some() {
            "explicit_total".to_string()
        } else {
            "support_scaled".to_string()
        },
        requested_max_rules,
        total_budget,
        priority_order: priority_order.to_vec(),
        per_action,
    })
}

fn compute_action_training_parity(
    policy: &LogicPearlActionIr,
    features_by_row: &[HashMap<String, Value>],
    action_by_row: &[String],
) -> Result<f64> {
    let mut correct = 0usize;
    for (features, expected_action) in features_by_row.iter().zip(action_by_row) {
        let selected = evaluate_action_policy(policy, features)
            .map_err(|err| {
                LogicPearlError::message(format!(
                    "failed to evaluate action policy during training parity check: {err}"
                ))
            })?
            .action;
        if &selected == expected_action {
            correct += 1;
        }
    }
    Ok(correct as f64 / action_by_row.len() as f64)
}

fn sanitize_identifier(value: &str) -> String {
    let mut output = String::new();
    let mut previous_was_separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            output.push('_');
            previous_was_separator = true;
        }
    }
    let trimmed = output.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "action".to_string()
    } else {
        trimmed
    }
}

fn classify_source_value(value: &str) -> &'static str {
    if Path::new(value).exists() {
        "path"
    } else {
        "inline"
    }
}

fn build_command_provenance() -> BuildCommandProvenance {
    let mut args = std::env::args_os()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let raw_program = args.first().cloned();
    let program = raw_program
        .as_deref()
        .map(provenance_safe_path_string)
        .unwrap_or_else(|| "logicpearl".to_string());
    if !args.is_empty() {
        args.remove(0);
    }

    let mut redacted = raw_program
        .as_deref()
        .is_some_and(|value| Path::new(value).is_absolute());
    let mut redacted_args = Vec::with_capacity(args.len());
    let mut pending_value_flag: Option<String> = None;
    for arg in args {
        if let Some(flag) = pending_value_flag.take() {
            let (value, was_redacted) = redact_cli_flag_value(&flag, &arg);
            redacted |= was_redacted;
            redacted_args.push(value);
            continue;
        }

        if let Some((flag, value)) = arg.split_once('=') {
            let (value, was_redacted) = redact_cli_flag_value(flag, value);
            redacted |= was_redacted;
            redacted_args.push(format!("{flag}={value}"));
            continue;
        }

        if matches!(
            arg.as_str(),
            "--trace-plugin-input" | "--trace-plugin-option" | "--source-ref"
        ) {
            pending_value_flag = Some(arg.clone());
        }
        let (arg, was_redacted) = sanitize_path_like_value(&arg);
        redacted |= was_redacted;
        redacted_args.push(arg);
    }

    BuildCommandProvenance {
        program,
        args: redacted_args,
        redacted,
    }
}

fn redact_cli_flag_value(flag: &str, value: &str) -> (String, bool) {
    match flag {
        "--trace-plugin-input" => {
            if Path::new(value).exists() {
                (
                    provenance_safe_path_string(value),
                    Path::new(value).is_absolute(),
                )
            } else {
                (
                    format!("<inline:{}>", sha256_prefixed(value.as_bytes())),
                    true,
                )
            }
        }
        "--trace-plugin-option" => {
            sanitize_key_value_for_provenance(value, is_safe_plugin_option_key)
        }
        "--source-ref" => sanitize_key_value_for_provenance(value, is_safe_source_reference_key),
        other if is_sensitive_key(other.trim_start_matches('-')) => (
            format!("<redacted:{}>", sha256_prefixed(value.as_bytes())),
            true,
        ),
        _ => sanitize_path_like_value(value),
    }
}

fn sanitize_path_like_value(value: &str) -> (String, bool) {
    let path = Path::new(value);
    if path.is_absolute() {
        (provenance_safe_path(path), true)
    } else {
        (value.to_string(), false)
    }
}

fn sanitize_key_value_for_provenance(entry: &str, allow_value: fn(&str) -> bool) -> (String, bool) {
    let Some((key, value)) = entry.split_once('=') else {
        return (entry.to_string(), false);
    };
    if allow_value(key) {
        (entry.to_string(), false)
    } else {
        (format!("{key}={}", redacted_hash(value)), true)
    }
}

fn sanitize_plugin_options(options: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    options
        .iter()
        .map(|(key, value)| {
            if is_safe_plugin_option_key(key) {
                (key.clone(), value.clone())
            } else {
                (key.clone(), redacted_hash(value))
            }
        })
        .collect()
}

fn sanitize_source_references(references: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    references
        .iter()
        .map(|(key, value)| {
            if is_safe_source_reference_key(key) {
                (key.clone(), value.clone())
            } else {
                (key.clone(), redacted_hash(value))
            }
        })
        .collect()
}

fn sanitize_build_options_for_provenance(value: &Value) -> Value {
    let Value::Object(object) = value else {
        return redact_provenance_value(value);
    };
    let mut sanitized = serde_json::Map::new();
    for (key, value) in object {
        if is_safe_build_option_key(key) {
            sanitized.insert(key.clone(), value.clone());
        } else {
            sanitized.insert(key.clone(), redact_provenance_value(value));
        }
    }
    Value::Object(sanitized)
}

fn redact_provenance_value(value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).expect("serializing serde_json::Value cannot fail");
    Value::String(format!("<redacted:{}>", sha256_prefixed(&bytes)))
}

fn redacted_hash(value: &str) -> String {
    format!("<redacted:{}>", sha256_prefixed(value.as_bytes()))
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "api_key",
        "apikey",
        "auth",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn is_safe_plugin_option_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "label_column" | "action_column" | "dialect" | "format"
    )
}

fn is_safe_source_reference_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "source_kind" | "kind" | "data_classification"
    )
}

fn is_safe_build_option_key(key: &str) -> bool {
    matches!(
        key,
        "action_column"
            | "action_max_rules"
            | "action_priority"
            | "actions"
            | "artifact_name"
            | "decision_mode"
            | "default_action"
            | "exclude_columns"
            | "feature_columns"
            | "gate_id"
            | "label_column"
            | "max_rules"
            | "negative_label"
            | "no_match_action"
            | "positive_label"
            | "priority_order"
            | "refine"
            | "residual_pass"
            | "rule_budget"
    )
}

fn build_environment_summary() -> BTreeMap<String, Value> {
    let mut environment = BTreeMap::new();
    environment.insert(
        "os".to_string(),
        Value::String(std::env::consts::OS.to_string()),
    );
    environment.insert(
        "arch".to_string(),
        Value::String(std::env::consts::ARCH.to_string()),
    );
    environment.insert(
        "family".to_string(),
        Value::String(std::env::consts::FAMILY.to_string()),
    );
    environment.insert(
        "ci".to_string(),
        Value::Bool(std::env::var_os("CI").is_some()),
    );
    if let Ok(backend) = std::env::var("LOGICPEARL_SOLVER_BACKEND") {
        if !backend.trim().is_empty() {
            environment.insert("solver_backend".to_string(), Value::String(backend));
        }
    }
    if let Ok(timeout) = std::env::var("LOGICPEARL_SOLVER_TIMEOUT_MS") {
        if let Ok(timeout) = timeout.parse::<u64>() {
            environment.insert(
                "solver_timeout_ms".to_string(),
                Value::Number(timeout.into()),
            );
        }
    }
    environment
}

fn resolve_engine_commit() -> Option<String> {
    if let Some(commit) = option_env!("LOGICPEARL_GIT_COMMIT") {
        let commit = commit.trim();
        if !commit.is_empty() {
            return Some(commit.to_string());
        }
    }
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_string())
}

fn file_provenance(path: &Path, artifact_dir: Option<&Path>) -> Result<FileProvenance> {
    Ok(FileProvenance {
        path: provenance_file_path(path, artifact_dir),
        hash: hash_file_for_provenance(path)?,
    })
}

fn provenance_file_path(path: &Path, artifact_dir: Option<&Path>) -> String {
    if let Some(artifact_dir) = artifact_dir {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            artifact_dir.join(path)
        };
        if let Ok(relative) = candidate.strip_prefix(artifact_dir) {
            let rendered = relative.display().to_string();
            if !rendered.is_empty() {
                return rendered;
            }
        }
    }
    provenance_safe_path(path)
}

fn validate_source_manifest(manifest: &SourceManifest) -> Result<()> {
    if manifest.schema_version != "logicpearl.source_manifest.v1" {
        return Err(LogicPearlError::message(format!(
            "unsupported source manifest schema_version {:?}; use logicpearl.source_manifest.v1",
            manifest.schema_version
        )));
    }
    if manifest.sources.is_empty() {
        return Err(LogicPearlError::message(
            "source manifest must declare at least one source",
        ));
    }

    let mut seen = BTreeSet::new();
    for source in &manifest.sources {
        if source.source_id.trim().is_empty() {
            return Err(LogicPearlError::message(
                "source manifest contains an empty source_id",
            ));
        }
        if !seen.insert(source.source_id.clone()) {
            return Err(LogicPearlError::message(format!(
                "source manifest repeats source_id {:?}",
                source.source_id
            )));
        }
        if source.title.trim().is_empty() {
            return Err(LogicPearlError::message(format!(
                "source {:?} has an empty title",
                source.source_id
            )));
        }
        if source.kind.trim().is_empty() {
            return Err(LogicPearlError::message(format!(
                "source {:?} has an empty kind",
                source.source_id
            )));
        }
        if source.data_classification.trim().is_empty() {
            return Err(LogicPearlError::message(format!(
                "source {:?} has an empty data_classification",
                source.source_id
            )));
        }
        if let Some(hash) = &source.content_hash {
            validate_sha256_prefixed(hash).map_err(|message| {
                LogicPearlError::message(format!(
                    "source {:?} has invalid content_hash: {message}",
                    source.source_id
                ))
            })?;
        }
    }
    Ok(())
}

fn validate_sha256_prefixed(value: &str) -> std::result::Result<(), &'static str> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("missing sha256: prefix");
    };
    if hex.len() != 64 {
        return Err("digest must be 64 hex characters");
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("digest must use lowercase hex");
    }
    Ok(())
}

fn rows_emitted_from_plugin_response(stage: &str, response: &PluginResponse) -> Option<usize> {
    match stage {
        "trace_source" => response
            .extra
            .get("decision_traces")
            .or_else(|| response.extra.get("records"))
            .and_then(Value::as_array)
            .map(Vec::len),
        "enricher" => response
            .extra
            .get("records")
            .and_then(Value::as_array)
            .map(Vec::len),
        "observer" => response
            .extra
            .get("features")
            .and_then(Value::as_object)
            .map(|_| 1),
        _ => None,
    }
}

fn hash_file_for_provenance(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|err| {
        LogicPearlError::message(format!(
            "failed to read file for provenance hash {}: {err}",
            path.display()
        ))
    })?;
    if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            return Ok(artifact_hash(&value));
        }
    }
    Ok(sha256_prefixed(&bytes))
}

fn observation_schema_hash(rows: &[DecisionTraceRow]) -> Result<Option<String>> {
    if rows.is_empty() {
        return Ok(None);
    }
    let mut feature_values = BTreeMap::<String, Vec<&Value>>::new();
    for row in rows {
        for (feature_id, value) in &row.features {
            feature_values
                .entry(feature_id.clone())
                .or_default()
                .push(value);
        }
    }

    let schema = ObservationSchema {
        schema_version: logicpearl_discovery::OBSERVATION_SCHEMA_VERSION.to_string(),
        features: feature_values
            .into_iter()
            .map(|(feature_id, values)| ObservedFeature {
                feature_id,
                feature_type: infer_observation_feature_type(&values),
                label: None,
                description: None,
                source_id: None,
                source_anchor: None,
                required: None,
                nullable: None,
                operators: Vec::new(),
                values: None,
            })
            .collect(),
    };

    Ok(Some(artifact_hash(&canonicalize_json_value(
        &serde_json::to_value(&schema).map_err(LogicPearlError::from)?,
    ))))
}

fn decision_trace_rows_hash(rows: &[DecisionTraceRow]) -> Result<String> {
    let value = serde_json::to_value(rows).map_err(LogicPearlError::from)?;
    Ok(artifact_hash(&canonicalize_json_value(&value)))
}

fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json_value).collect()),
        Value::Object(object) => {
            let mut canonical = Map::new();
            for (key, item) in object.iter().collect::<BTreeMap<_, _>>() {
                canonical.insert(key.clone(), canonicalize_json_value(item));
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

fn infer_observation_feature_type(values: &[&Value]) -> ObservationFeatureType {
    if values.iter().all(|value| value.is_boolean()) {
        ObservationFeatureType::Boolean
    } else if values
        .iter()
        .all(|value| value.as_i64().is_some() || value.as_u64().is_some())
    {
        ObservationFeatureType::Integer
    } else if values.iter().all(|value| value.is_number()) {
        ObservationFeatureType::Number
    } else {
        ObservationFeatureType::String
    }
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|err| {
        LogicPearlError::message(format!(
            "failed to read file for sha256 {}: {err}",
            path.display()
        ))
    })?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}
