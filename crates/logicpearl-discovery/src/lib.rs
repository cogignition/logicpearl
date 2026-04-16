// SPDX-License-Identifier: MIT
//! Discovery and trace-loading for LogicPearl artifacts.
//!
//! This crate turns normalized decision traces into learned gate IR. It owns
//! trace parsing, label inference, feature generation, rule discovery, exact
//! selection reports, and build reports. Build orchestration and provenance
//! assembly live in `logicpearl-build`; this crate stays focused on learning
//! deterministic logic from already-normalized examples.

use logicpearl_core::{artifact_hash, provenance_safe_path_string, LogicPearlError, Result};
use logicpearl_ir::{
    Expression, FeatureGovernance, FeatureSemantics, LogicPearlGateIr, RuleDefinition,
    RuleTraceEvidence, RuleVerificationStatus,
};
use logicpearl_runtime::evaluate_gate;
use logicpearl_solver::{
    resolve_backend, SolverSettings, SOLVER_BACKEND_ENV, SOLVER_DIR_ENV, SOLVER_TIMEOUT_MS_ENV,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

mod canonicalize;
mod engine;
mod features;
mod rule_text;
mod trace_loading;

use engine::{build_gate, load_pinned_rule_set};
use features::augment_rows_with_numeric_interactions;
use trace_loading::{infer_binary_label_domain, parse_allowed_label_value, BinaryLabelDomain};
pub use trace_loading::{
    load_decision_traces, load_decision_traces_auto,
    load_decision_traces_auto_with_feature_selection, load_decision_traces_with_labels,
    load_decision_traces_with_labels_and_feature_selection, load_flat_records,
    FeatureColumnSelection, LoadedFlatRecords,
};

#[cfg(test)]
use canonicalize::{canonicalize_rules, prune_redundant_rules};
#[cfg(test)]
use engine::{
    dedupe_rules_by_signature, discover_residual_rules, gate_from_rules,
    merge_discovered_and_pinned_rules, rule_from_candidate,
};

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub output_dir: PathBuf,
    pub gate_id: String,
    pub label_column: String,
    pub positive_label: Option<String>,
    pub negative_label: Option<String>,
    pub residual_pass: bool,
    pub refine: bool,
    pub pinned_rules: Option<PathBuf>,
    pub feature_dictionary: Option<PathBuf>,
    pub feature_governance: Option<PathBuf>,
    pub decision_mode: DiscoveryDecisionMode,
    pub max_rules: Option<usize>,
    pub feature_selection: FeatureColumnSelection,
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryDecisionMode {
    #[default]
    Standard,
    Review,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DecisionTraceRow {
    pub features: HashMap<String, Value>,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_provenance: Option<DecisionTraceProvenance>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DecisionTraceProvenance {
    pub trace_row_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_hash: Option<String>,
}

pub fn decision_trace_row_hash(features: &HashMap<String, Value>, allowed: bool) -> String {
    artifact_hash(&serde_json::json!({
        "features": features,
        "allowed": allowed,
    }))
}

pub fn action_trace_row_hash(features: &HashMap<String, Value>, action: &str) -> String {
    artifact_hash(&serde_json::json!({
        "features": features,
        "action": action,
    }))
}

pub fn decision_trace_provenance_from_record(
    record: &BTreeMap<String, Value>,
    features: &HashMap<String, Value>,
    allowed: bool,
) -> DecisionTraceProvenance {
    trace_provenance_from_record(record, decision_trace_row_hash(features, allowed))
}

pub fn action_trace_provenance_from_record(
    record: &BTreeMap<String, Value>,
    features: &HashMap<String, Value>,
    action: &str,
) -> DecisionTraceProvenance {
    trace_provenance_from_record(record, action_trace_row_hash(features, action))
}

fn trace_provenance_from_record(
    record: &BTreeMap<String, Value>,
    trace_row_hash: String,
) -> DecisionTraceProvenance {
    DecisionTraceProvenance {
        trace_row_hash,
        source_id: first_scalar_string(record, &["source_id"]),
        source_anchor: first_scalar_string(record, &["source_anchor"]),
        citation: first_scalar_string(record, &["source_citation", "citation"]),
        quote_hash: first_scalar_string(record, &["source_quote", "quote"])
            .map(|quote| logicpearl_core::sha256_prefixed(quote.as_bytes())),
    }
}

fn first_scalar_string(record: &BTreeMap<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| record.get(*key))
        .find_map(scalar_string)
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => non_empty(text.clone()),
        Value::Number(number) => non_empty(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn rule_trace_evidence(provenance: &DecisionTraceProvenance) -> RuleTraceEvidence {
    RuleTraceEvidence {
        trace_row_hash: provenance.trace_row_hash.clone(),
        source_id: provenance.source_id.clone(),
        source_anchor: provenance.source_anchor.clone(),
        citation: provenance.citation.clone(),
        quote_hash: provenance.quote_hash.clone(),
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct BuildResult {
    pub source_csv: String,
    pub gate_id: String,
    pub rows: usize,
    pub label_column: String,
    pub rules_discovered: usize,
    pub residual_rules_discovered: usize,
    pub refined_rules_applied: usize,
    pub pinned_rules_applied: usize,
    pub selected_features: Vec<String>,
    pub training_parity: f64,
    #[serde(default)]
    pub exact_selection: ExactSelectionReport,
    #[serde(default)]
    pub residual_recovery: ResidualRecoveryReport,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<BuildProvenance>,
    pub output_files: OutputFiles,
}

#[derive(Debug, Clone)]
pub struct LearnedGate {
    pub gate: LogicPearlGateIr,
    pub exact_selection: ExactSelectionReport,
    pub residual_rules_discovered: usize,
    pub residual_recovery: ResidualRecoveryReport,
    pub refined_rules_applied: usize,
    pub pinned_rules_applied: usize,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExactSelectionBackend {
    BruteForce,
    Smt,
    Mip,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct ExactSelectionReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<ExactSelectionBackend>,
    #[serde(default)]
    pub shortlisted_candidates: usize,
    #[serde(default)]
    pub selected_candidates: usize,
    #[serde(default)]
    pub adopted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResidualRecoveryState {
    #[default]
    Disabled,
    Applied,
    NoMissedSlices,
    SolverUnavailable,
    SolverError,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct ResidualRecoveryReport {
    #[serde(default)]
    pub state: ResidualRecoveryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, Default)]
pub struct BuildProvenance {
    #[serde(default = "default_build_provenance_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub engine_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_command: Option<BuildCommandProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_options: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_options_hash: Option<String>,
    #[serde(default)]
    pub input_traces: Vec<TraceInputProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_dictionary: Option<FileProvenance>,
    #[serde(default)]
    pub plugins: Vec<PluginBuildProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_manifest: Option<SourceManifestProvenance>,
    #[serde(default)]
    pub environment: BTreeMap<String, Value>,
    #[serde(default)]
    pub generated_files: BTreeMap<String, String>,
    #[serde(default)]
    pub generated_file_notes: Vec<String>,
    #[serde(default)]
    pub redactions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace_source: Option<BuildInputProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_plugin: Option<PluginBuildProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enricher_plugin: Option<PluginBuildProvenance>,
    #[serde(default)]
    pub source_references: BTreeMap<String, String>,
}

fn default_build_provenance_schema_version() -> String {
    "logicpearl.build_provenance.v1".to_string()
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct BuildCommandProvenance {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct BuildInputProvenance {
    pub kind: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TraceInputProvenance {
    pub path: String,
    pub hash: String,
    pub row_count: usize,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct FileProvenance {
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SourceManifestProvenance {
    pub path: String,
    pub hash: String,
    #[serde(default)]
    pub sources: Vec<SourceManifestSource>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SourceManifest {
    pub schema_version: String,
    #[serde(default)]
    pub sources: Vec<SourceManifestSource>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SourceManifestSource {
    pub source_id: String,
    pub kind: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub data_classification: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PluginBuildProvenance {
    #[serde(default = "default_plugin_run_provenance_schema_version")]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_name: Option<String>,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    pub manifest_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<BuildInputProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_emitted: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_policy: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_policy: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio: Option<Value>,
}

fn default_plugin_run_provenance_schema_version() -> String {
    "logicpearl.plugin_run_provenance.v1".to_string()
}

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    pub output_dir: PathBuf,
    pub artifact_set_id: String,
    pub target_columns: Vec<String>,
    pub feature_selection: FeatureColumnSelection,
    pub residual_pass: bool,
    pub refine: bool,
    pub pinned_rules: Option<PathBuf>,
    pub feature_dictionary: Option<PathBuf>,
    pub feature_governance: Option<PathBuf>,
    pub decision_mode: DiscoveryDecisionMode,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct FeatureGovernanceConfig {
    #[serde(default = "default_feature_governance_version")]
    pub feature_governance_version: String,
    #[serde(default)]
    pub features: BTreeMap<String, FeatureGovernance>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Default)]
pub struct FeatureDictionaryConfig {
    #[serde(default = "default_feature_dictionary_version")]
    pub feature_dictionary_version: String,
    #[serde(default)]
    pub features: BTreeMap<String, FeatureSemantics>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ArtifactDescriptor {
    pub name: String,
    pub artifact: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ArtifactSet {
    pub artifact_set_version: String,
    pub artifact_set_id: String,
    pub features: Vec<String>,
    pub binary_targets: Vec<ArtifactDescriptor>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DiscoverResult {
    pub source_csv: String,
    pub artifact_set_id: String,
    pub rows: usize,
    pub features: Vec<String>,
    pub targets: Vec<String>,
    pub artifacts: Vec<BuildResult>,
    #[serde(default)]
    pub cached_artifacts: usize,
    #[serde(default)]
    pub cache_hit: bool,
    pub skipped_targets: Vec<SkippedTarget>,
    pub output_files: DiscoverOutputFiles,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SkippedTarget {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DiscoverOutputFiles {
    pub artifact_set: String,
    pub discover_report: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct OutputFiles {
    pub artifact_dir: String,
    pub artifact_manifest: String,
    pub pearl_ir: String,
    pub build_report: String,
    #[serde(default)]
    pub native_binary: Option<String>,
    #[serde(default)]
    pub wasm_module: Option<String>,
    #[serde(default)]
    pub wasm_metadata: Option<String>,
}

pub fn build_result_for_report(result: &BuildResult) -> BuildResult {
    let mut report = result.clone();
    let artifact_dir = Path::new(&result.output_files.artifact_dir);
    report.source_csv = provenance_safe_path_string(&report.source_csv);
    report.output_files = output_files_for_report(&result.output_files, artifact_dir);
    report
}

pub fn discover_result_for_report(result: &DiscoverResult) -> DiscoverResult {
    let output_dir = discover_output_dir(&result.output_files);
    discover_result_for_report_at(result, &output_dir)
}

fn discover_result_for_report_at(result: &DiscoverResult, output_dir: &Path) -> DiscoverResult {
    let mut report = result.clone();
    report.source_csv = provenance_safe_path_string(&report.source_csv);
    report.artifacts = result
        .artifacts
        .iter()
        .map(|artifact| build_result_for_discover_report(artifact, output_dir))
        .collect();
    report.output_files = discover_output_files_for_report(&result.output_files, output_dir);
    report
}

fn discover_output_dir(output_files: &DiscoverOutputFiles) -> PathBuf {
    Path::new(&output_files.discover_report)
        .parent()
        .or_else(|| Path::new(&output_files.artifact_set).parent())
        .map(Path::to_path_buf)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn build_result_for_discover_report(result: &BuildResult, output_dir: &Path) -> BuildResult {
    let mut report = result.clone();
    report.source_csv = provenance_safe_path_string(&report.source_csv);
    report.output_files = output_files_relative_to_report_base(&result.output_files, output_dir);
    report
}

fn output_files_for_report(output_files: &OutputFiles, artifact_dir: &Path) -> OutputFiles {
    OutputFiles {
        artifact_dir: ".".to_string(),
        artifact_manifest: artifact_relative_report_path(
            &output_files.artifact_manifest,
            artifact_dir,
            "artifact.json",
        ),
        pearl_ir: artifact_relative_report_path(
            &output_files.pearl_ir,
            artifact_dir,
            "pearl.ir.json",
        ),
        build_report: artifact_relative_report_path(
            &output_files.build_report,
            artifact_dir,
            "build_report.json",
        ),
        native_binary: output_files
            .native_binary
            .as_deref()
            .map(|path| artifact_relative_report_path(path, artifact_dir, "pearl")),
        wasm_module: output_files
            .wasm_module
            .as_deref()
            .map(|path| artifact_relative_report_path(path, artifact_dir, "pearl.wasm")),
        wasm_metadata: output_files
            .wasm_metadata
            .as_deref()
            .map(|path| artifact_relative_report_path(path, artifact_dir, "pearl.wasm.meta.json")),
    }
}

fn output_files_relative_to_report_base(
    output_files: &OutputFiles,
    base_dir: &Path,
) -> OutputFiles {
    OutputFiles {
        artifact_dir: artifact_relative_report_path(&output_files.artifact_dir, base_dir, "."),
        artifact_manifest: artifact_relative_report_path(
            &output_files.artifact_manifest,
            base_dir,
            "artifact.json",
        ),
        pearl_ir: artifact_relative_report_path(&output_files.pearl_ir, base_dir, "pearl.ir.json"),
        build_report: artifact_relative_report_path(
            &output_files.build_report,
            base_dir,
            "build_report.json",
        ),
        native_binary: output_files
            .native_binary
            .as_deref()
            .map(|path| artifact_relative_report_path(path, base_dir, "pearl")),
        wasm_module: output_files
            .wasm_module
            .as_deref()
            .map(|path| artifact_relative_report_path(path, base_dir, "pearl.wasm")),
        wasm_metadata: output_files
            .wasm_metadata
            .as_deref()
            .map(|path| artifact_relative_report_path(path, base_dir, "pearl.wasm.meta.json")),
    }
}

fn discover_output_files_for_report(
    output_files: &DiscoverOutputFiles,
    output_dir: &Path,
) -> DiscoverOutputFiles {
    DiscoverOutputFiles {
        artifact_set: artifact_relative_report_path(
            &output_files.artifact_set,
            output_dir,
            "artifact_set.json",
        ),
        discover_report: artifact_relative_report_path(
            &output_files.discover_report,
            output_dir,
            "discover_report.json",
        ),
    }
}

fn artifact_relative_report_path(raw_path: &str, artifact_dir: &Path, fallback: &str) -> String {
    let path = Path::new(raw_path);
    if !path.is_absolute() {
        if let Ok(relative) = path.strip_prefix(artifact_dir) {
            let rendered = relative.display().to_string();
            if !rendered.is_empty() {
                return rendered;
            }
        }
    }

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

    if !path.is_absolute() {
        let rendered = path.display().to_string();
        if !rendered.is_empty() && !rendered.starts_with("..") {
            return rendered;
        }
    }

    if path.is_absolute() {
        return provenance_safe_path_string(raw_path);
    }

    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            let safe = provenance_safe_path_string(raw_path);
            if safe.is_empty() {
                fallback.to_string()
            } else {
                safe
            }
        })
}

#[derive(Debug, Clone)]
pub struct LoadedDecisionTraces {
    pub rows: Vec<DecisionTraceRow>,
    pub label_column: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PinnedRuleSet {
    #[serde(default = "default_rule_set_version")]
    pub rule_set_version: String,
    #[serde(default = "default_rule_set_id")]
    pub rule_set_id: String,
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone)]
struct CandidateRule {
    expression: Expression,
    denied_coverage: usize,
    false_positives: usize,
    cached_signature: String,
}

impl CandidateRule {
    fn new(expression: Expression, denied_coverage: usize, false_positives: usize) -> Self {
        let cached_signature = serde_json::to_string(&expression).unwrap_or_default();
        Self {
            expression,
            denied_coverage,
            false_positives,
            cached_signature,
        }
    }

    fn signature(&self) -> &str {
        &self.cached_signature
    }
}

#[derive(Debug, Clone)]
struct ResidualPassOptions {
    max_conditions: usize,
    min_positive_support: usize,
    max_negative_hits: usize,
    max_rules: usize,
}

#[derive(Debug, Clone)]
struct UniqueCoverageRefinementOptions {
    min_unique_false_positives: usize,
    min_true_positive_retention: f64,
}

#[derive(Debug, Clone)]
struct NumericBound {
    value: f64,
    inclusive: bool,
}

#[derive(Debug, Clone)]
struct NumericInterval {
    lower: Option<NumericBound>,
    upper: Option<NumericBound>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
struct CacheManifest {
    cache_version: String,
    operation: String,
    input_fingerprint: String,
    options_fingerprint: String,
}

const DEFAULT_RESIDUAL_PASS_OPTIONS: ResidualPassOptions = ResidualPassOptions {
    max_conditions: 3,
    min_positive_support: 2,
    max_negative_hits: 0,
    max_rules: 8,
};

const DEFAULT_UNIQUE_COVERAGE_REFINEMENT_OPTIONS: UniqueCoverageRefinementOptions =
    UniqueCoverageRefinementOptions {
        min_unique_false_positives: 1,
        min_true_positive_retention: 0.5,
    };

#[cfg(test)]
pub(crate) fn discovery_selection_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn default_rule_set_version() -> String {
    "1.0".to_string()
}

fn default_feature_governance_version() -> String {
    "1.0".to_string()
}

fn default_feature_dictionary_version() -> String {
    "1.0".to_string()
}

fn default_rule_set_id() -> String {
    "pinned_rules".to_string()
}

fn cache_manifest_path(output_dir: &Path) -> PathBuf {
    output_dir.join(".logicpearl-cache.json")
}

fn cache_fingerprint<T: Serialize>(value: &T) -> Result<String> {
    let payload = serde_json::to_string(value)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    payload.hash(&mut hasher);
    Ok(format!("{:016x}", hasher.finish()))
}

fn load_cache_manifest(path: &Path) -> Result<Option<CacheManifest>> {
    if !path.exists() {
        return Ok(None);
    }
    let payload = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&payload)?))
}

fn write_cache_manifest(path: &Path, manifest: &CacheManifest) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(manifest)? + "\n")?;
    Ok(())
}

fn resolved_solver_backend_name() -> Option<String> {
    let settings = SolverSettings::from_env().ok()?;
    resolve_backend(&settings)
        .ok()
        .map(|backend| backend.as_str().to_string())
}

fn build_cache_manifest(
    rows: &[DecisionTraceRow],
    _source_name: &str,
    options: &BuildOptions,
) -> Result<CacheManifest> {
    #[derive(Serialize)]
    struct BuildFingerprintRow<'a> {
        allowed: bool,
        features: BTreeMap<&'a str, &'a Value>,
    }

    #[derive(Serialize)]
    struct BuildFingerprintOptions<'a> {
        gate_id: &'a str,
        label_column: &'a str,
        positive_label: Option<&'a str>,
        negative_label: Option<&'a str>,
        residual_pass: bool,
        refine: bool,
        pinned_rules_fingerprint: Option<String>,
        feature_dictionary_fingerprint: Option<String>,
        feature_governance_fingerprint: Option<String>,
        decision_mode: DiscoveryDecisionMode,
        max_rules: Option<usize>,
        feature_selection: &'a FeatureColumnSelection,
        solver_backend_env: Option<String>,
        resolved_solver_backend: Option<String>,
        solver_timeout_ms_env: Option<String>,
        solver_dir_env: Option<String>,
        discovery_selection_backend_env: Option<String>,
    }

    let rows_fingerprint: Vec<BuildFingerprintRow<'_>> = rows
        .iter()
        .map(|row| BuildFingerprintRow {
            allowed: row.allowed,
            features: row
                .features
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect(),
        })
        .collect();
    let pinned_rules_fingerprint = options
        .pinned_rules
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;
    let feature_governance_fingerprint = options
        .feature_governance
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;
    let feature_dictionary_fingerprint = options
        .feature_dictionary
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;

    Ok(CacheManifest {
        cache_version: "7".to_string(),
        operation: "build".to_string(),
        input_fingerprint: cache_fingerprint(&rows_fingerprint)?,
        options_fingerprint: cache_fingerprint(&BuildFingerprintOptions {
            gate_id: &options.gate_id,
            label_column: &options.label_column,
            positive_label: options.positive_label.as_deref(),
            negative_label: options.negative_label.as_deref(),
            residual_pass: options.residual_pass,
            refine: options.refine,
            pinned_rules_fingerprint,
            feature_dictionary_fingerprint,
            feature_governance_fingerprint,
            decision_mode: options.decision_mode,
            max_rules: options.max_rules,
            feature_selection: &options.feature_selection,
            solver_backend_env: std::env::var(SOLVER_BACKEND_ENV).ok(),
            resolved_solver_backend: resolved_solver_backend_name(),
            solver_timeout_ms_env: std::env::var(SOLVER_TIMEOUT_MS_ENV).ok(),
            solver_dir_env: std::env::var(SOLVER_DIR_ENV)
                .ok()
                .map(|value| provenance_safe_path_string(&value)),
            discovery_selection_backend_env: std::env::var(engine::DISCOVERY_SELECTION_BACKEND_ENV)
                .ok(),
        })?,
    })
}

fn discover_cache_manifest(csv_path: &Path, options: &DiscoverOptions) -> Result<CacheManifest> {
    #[derive(Serialize)]
    struct DiscoverFingerprintOptions<'a> {
        artifact_set_id: &'a str,
        target_columns: &'a [String],
        residual_pass: bool,
        refine: bool,
        pinned_rules_fingerprint: Option<String>,
        feature_dictionary_fingerprint: Option<String>,
        feature_governance_fingerprint: Option<String>,
        decision_mode: DiscoveryDecisionMode,
        feature_selection: &'a FeatureColumnSelection,
        solver_backend_env: Option<String>,
        resolved_solver_backend: Option<String>,
        solver_timeout_ms_env: Option<String>,
        solver_dir_env: Option<String>,
        discovery_selection_backend_env: Option<String>,
    }

    let pinned_rules_fingerprint = options
        .pinned_rules
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;
    let feature_governance_fingerprint = options
        .feature_governance
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;
    let feature_dictionary_fingerprint = options
        .feature_dictionary
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;

    Ok(CacheManifest {
        cache_version: "5".to_string(),
        operation: "discover".to_string(),
        input_fingerprint: fingerprint_file(csv_path)?,
        options_fingerprint: cache_fingerprint(&DiscoverFingerprintOptions {
            artifact_set_id: &options.artifact_set_id,
            target_columns: &options.target_columns,
            residual_pass: options.residual_pass,
            refine: options.refine,
            pinned_rules_fingerprint,
            feature_dictionary_fingerprint,
            feature_governance_fingerprint,
            decision_mode: options.decision_mode,
            feature_selection: &options.feature_selection,
            solver_backend_env: std::env::var(SOLVER_BACKEND_ENV).ok(),
            resolved_solver_backend: resolved_solver_backend_name(),
            solver_timeout_ms_env: std::env::var(SOLVER_TIMEOUT_MS_ENV).ok(),
            solver_dir_env: std::env::var(SOLVER_DIR_ENV)
                .ok()
                .map(|value| provenance_safe_path_string(&value)),
            discovery_selection_backend_env: std::env::var(engine::DISCOVERY_SELECTION_BACKEND_ENV)
                .ok(),
        })?,
    })
}

fn fingerprint_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    Ok(format!("{:016x}", hasher.finish()))
}

pub fn load_feature_governance(path: &Path) -> Result<FeatureGovernanceConfig> {
    let payload = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&payload)?)
}

pub fn load_feature_dictionary(path: &Path) -> Result<FeatureDictionaryConfig> {
    let payload = std::fs::read_to_string(path)?;
    let config: FeatureDictionaryConfig = serde_json::from_str(&payload)?;
    if config.feature_dictionary_version != "1.0" {
        return Err(LogicPearlError::message(format!(
            "unsupported feature_dictionary_version: {}",
            config.feature_dictionary_version
        )));
    }
    Ok(config)
}

fn validate_feature_dictionary(
    dictionary: &FeatureDictionaryConfig,
    rows: &[DecisionTraceRow],
    derived_features: &[logicpearl_ir::FeatureDefinition],
) -> Result<()> {
    if dictionary.features.is_empty() {
        return Ok(());
    }
    let mut known_features = rows
        .first()
        .map(|row| row.features.keys().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    for feature in derived_features {
        known_features.insert(feature.id.clone());
    }
    let unknown = dictionary
        .features
        .keys()
        .filter(|feature| !known_features.contains(*feature))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(LogicPearlError::message(format!(
            "feature dictionary references unknown feature(s): {}",
            unknown.join(", ")
        )));
    }
    Ok(())
}

pub fn build_pearl_from_csv(csv_path: &Path, options: &BuildOptions) -> Result<BuildResult> {
    let loaded = load_decision_traces_auto_with_feature_selection(
        csv_path,
        Some(&options.label_column),
        options.positive_label.as_deref(),
        options.negative_label.as_deref(),
        &options.feature_selection,
    )?;
    let resolved_options = BuildOptions {
        output_dir: options.output_dir.clone(),
        gate_id: options.gate_id.clone(),
        label_column: loaded.label_column,
        positive_label: options.positive_label.clone(),
        negative_label: options.negative_label.clone(),
        residual_pass: options.residual_pass,
        refine: options.refine,
        pinned_rules: options.pinned_rules.clone(),
        feature_dictionary: options.feature_dictionary.clone(),
        feature_governance: options.feature_governance.clone(),
        decision_mode: options.decision_mode,
        max_rules: options.max_rules,
        feature_selection: options.feature_selection.clone(),
    };
    build_pearl_from_rows(
        &loaded.rows,
        csv_path.display().to_string(),
        &resolved_options,
    )
}

pub fn discover_from_csv(csv_path: &Path, options: &DiscoverOptions) -> Result<DiscoverResult> {
    if options.target_columns.is_empty() {
        return Err(LogicPearlError::message(
            "discover requires at least one target column",
        ));
    }

    options.output_dir.mkdir_all()?;
    let discover_manifest = discover_cache_manifest(csv_path, options)?;
    let discover_cache_path = cache_manifest_path(&options.output_dir);
    let discover_report_path = options.output_dir.join("discover_report.json");
    let artifact_set_path = options.output_dir.join("artifact_set.json");
    if artifact_set_path.exists()
        && discover_report_path.exists()
        && load_cache_manifest(&discover_cache_path)?.as_ref() == Some(&discover_manifest)
    {
        let mut cached: DiscoverResult =
            serde_json::from_str(&std::fs::read_to_string(&discover_report_path)?)?;
        cached.source_csv = csv_path.display().to_string();
        cached.output_files =
            actual_discover_output_files_from_report(&cached.output_files, &options.output_dir);
        cached.cache_hit = true;
        for artifact in &mut cached.artifacts {
            artifact.source_csv = csv_path.display().to_string();
            artifact.output_files =
                actual_output_files_from_report_base(&artifact.output_files, &options.output_dir);
            artifact.cache_hit = true;
        }
        cached.cached_artifacts = cached.artifacts.len();
        return Ok(cached);
    }

    let loaded = load_flat_records(csv_path)?;
    let headers = loaded.field_names;
    let records = loaded.records;
    for target in &options.target_columns {
        if !headers.iter().any(|header| header == target) {
            return Err(LogicPearlError::message(format!(
                "dataset is missing target column: {target:?}"
            )));
        }
    }

    let feature_columns = options.feature_selection.selected_feature_columns(
        csv_path,
        &headers,
        &options.target_columns,
    )?;

    let artifacts_dir = options.output_dir.join("artifacts");
    artifacts_dir.mkdir_all()?;
    let target_domains: HashMap<String, BinaryLabelDomain> = options
        .target_columns
        .iter()
        .map(|target| {
            infer_binary_label_domain(&records, target, None, None)
                .map(|domain| (target.clone(), domain))
        })
        .collect::<Result<_>>()?;

    let mut per_target_rows: HashMap<String, Vec<DecisionTraceRow>> = options
        .target_columns
        .iter()
        .map(|target| (target.clone(), Vec::new()))
        .collect();

    for (index, record) in records.iter().enumerate() {
        let mut features = HashMap::new();
        let mut target_values = HashMap::new();

        for header in &headers {
            let value = record.get(header).ok_or_else(|| {
                LogicPearlError::message(format!("row {} is missing field {header:?}", index + 1))
            })?;
            if options.target_columns.iter().any(|target| target == header) {
                let domain = target_domains.get(header).ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "missing inferred binary domain for target column {header:?}"
                    ))
                })?;
                target_values.insert(
                    header.to_string(),
                    parse_allowed_label_value(value, index + 1, header, domain)?,
                );
                continue;
            }
            if feature_columns.iter().any(|feature| feature == header) {
                features.insert(header.to_string(), value.clone());
            }
        }

        for target in &options.target_columns {
            let allowed = *target_values.get(target).ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {} is missing target column {target:?}",
                    index + 1
                ))
            })?;
            per_target_rows
                .get_mut(target)
                .ok_or_else(|| {
                    LogicPearlError::message(format!("target {target:?} not initialized"))
                })?
                .push(DecisionTraceRow {
                    features: features.clone(),
                    allowed,
                    trace_provenance: None,
                });
        }
    }

    let mut artifacts = Vec::with_capacity(options.target_columns.len());
    let mut descriptors = Vec::with_capacity(options.target_columns.len());
    let mut skipped_targets = Vec::new();
    let row_count = per_target_rows
        .values()
        .next()
        .map(std::vec::Vec::len)
        .unwrap_or_default();

    for target in &options.target_columns {
        let target_rows = per_target_rows.remove(target).ok_or_else(|| {
            LogicPearlError::message(format!("missing rows for target {target:?}"))
        })?;
        let denied_count = target_rows.iter().filter(|row| !row.allowed).count();
        let allowed_count = target_rows.iter().filter(|row| row.allowed).count();
        if denied_count == 0 {
            skipped_targets.push(SkippedTarget {
                name: target.clone(),
                reason: "no denied examples present".to_string(),
            });
            continue;
        }
        if allowed_count == 0 {
            skipped_targets.push(SkippedTarget {
                name: target.clone(),
                reason: "no allowed examples present".to_string(),
            });
            continue;
        }
        let target_dir = artifacts_dir.join(target);
        let build = match build_pearl_from_rows(
            &target_rows,
            csv_path.display().to_string(),
            &BuildOptions {
                output_dir: target_dir.clone(),
                gate_id: target.clone(),
                label_column: target.clone(),
                positive_label: None,
                negative_label: None,
                residual_pass: options.residual_pass,
                refine: options.refine,
                pinned_rules: options.pinned_rules.clone(),
                feature_dictionary: options.feature_dictionary.clone(),
                feature_governance: options.feature_governance.clone(),
                decision_mode: options.decision_mode,
                max_rules: None,
                feature_selection: options.feature_selection.clone(),
            },
        ) {
            Ok(build) => build,
            Err(err) => {
                skipped_targets.push(SkippedTarget {
                    name: target.clone(),
                    reason: err.to_string(),
                });
                continue;
            }
        };
        let relative_artifact = PathBuf::from("artifacts")
            .join(target)
            .join("pearl.ir.json")
            .display()
            .to_string();
        descriptors.push(ArtifactDescriptor {
            name: target.clone(),
            artifact: relative_artifact,
        });
        artifacts.push(build);
    }

    let artifact_set = ArtifactSet {
        artifact_set_version: "1.0".to_string(),
        artifact_set_id: options.artifact_set_id.clone(),
        features: feature_columns.clone(),
        binary_targets: descriptors,
    };

    let artifact_set_path = options.output_dir.join("artifact_set.json");
    std::fs::write(
        &artifact_set_path,
        serde_json::to_string_pretty(&artifact_set)? + "\n",
    )?;

    let discover = DiscoverResult {
        source_csv: csv_path.display().to_string(),
        artifact_set_id: options.artifact_set_id.clone(),
        rows: row_count,
        features: feature_columns,
        targets: options.target_columns.clone(),
        cached_artifacts: artifacts
            .iter()
            .filter(|artifact| artifact.cache_hit)
            .count(),
        cache_hit: false,
        artifacts,
        skipped_targets,
        output_files: DiscoverOutputFiles {
            artifact_set: artifact_set_path.display().to_string(),
            discover_report: discover_report_path.display().to_string(),
        },
    };

    std::fs::write(
        &discover_report_path,
        serde_json::to_string_pretty(&discover_result_for_report_at(
            &discover,
            &options.output_dir,
        ))? + "\n",
    )?;
    write_cache_manifest(&discover_cache_path, &discover_manifest)?;

    Ok(discover)
}

pub fn build_pearl_from_rows(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
) -> Result<BuildResult> {
    build_pearl_from_rows_internal(rows, source_name, options, true)
}

pub fn build_pearl_from_rows_without_numeric_interactions(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
) -> Result<BuildResult> {
    build_pearl_from_rows_internal(rows, source_name, options, false)
}

pub fn learn_gate_from_rows_without_numeric_interactions(
    rows: &[DecisionTraceRow],
    options: &BuildOptions,
) -> Result<LearnedGate> {
    learn_gate_from_rows_internal(rows, options, false)
}

fn build_pearl_from_rows_internal(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
    numeric_interactions: bool,
) -> Result<BuildResult> {
    if rows.is_empty() {
        return Err(LogicPearlError::message("decision trace CSV is empty"));
    }

    options.output_dir.mkdir_all()?;
    let build_manifest = build_cache_manifest(rows, &source_name, options)?;
    let build_cache_path = cache_manifest_path(&options.output_dir);
    let build_report_path = options.output_dir.join("build_report.json");
    let pearl_ir_path = options.output_dir.join("pearl.ir.json");
    if pearl_ir_path.exists()
        && build_report_path.exists()
        && load_cache_manifest(&build_cache_path)?.as_ref() == Some(&build_manifest)
    {
        let mut cached: BuildResult =
            serde_json::from_str(&std::fs::read_to_string(&build_report_path)?)?;
        cached.source_csv = source_name;
        cached.output_files =
            actual_output_files_from_report(&cached.output_files, &options.output_dir);
        cached.cache_hit = true;
        return Ok(cached);
    }

    let LearnedGate {
        gate,
        exact_selection,
        residual_rules_discovered,
        residual_recovery,
        refined_rules_applied,
        pinned_rules_applied,
    } = learn_gate_from_rows_internal(rows, options, numeric_interactions)?;
    gate.validate()?;
    gate.write_pretty(&pearl_ir_path)?;

    let mut correct = 0;
    for row in rows {
        let bitmask = evaluate_gate(&gate, &row.features)?;
        let allowed = bitmask.is_zero();
        if allowed == row.allowed {
            correct += 1;
        }
    }
    let training_parity = correct as f64 / rows.len() as f64;

    let build_report = BuildResult {
        source_csv: source_name,
        gate_id: options.gate_id.clone(),
        rows: rows.len(),
        label_column: options.label_column.clone(),
        rules_discovered: gate.rules.len(),
        residual_rules_discovered,
        refined_rules_applied,
        pinned_rules_applied,
        selected_features: gate
            .input_schema
            .features
            .iter()
            .map(|feature| feature.id.clone())
            .collect(),
        training_parity,
        exact_selection,
        residual_recovery,
        cache_hit: false,
        provenance: None,
        output_files: OutputFiles {
            artifact_dir: options.output_dir.display().to_string(),
            artifact_manifest: options
                .output_dir
                .join("artifact.json")
                .display()
                .to_string(),
            pearl_ir: pearl_ir_path.display().to_string(),
            build_report: build_report_path.display().to_string(),
            native_binary: None,
            wasm_module: None,
            wasm_metadata: None,
        },
    };

    std::fs::write(
        &build_report_path,
        serde_json::to_string_pretty(&build_result_for_report(&build_report))? + "\n",
    )?;
    write_cache_manifest(&build_cache_path, &build_manifest)?;

    Ok(build_report)
}

fn actual_output_files_from_report(output_files: &OutputFiles, artifact_dir: &Path) -> OutputFiles {
    OutputFiles {
        artifact_dir: artifact_dir.display().to_string(),
        artifact_manifest: actual_output_path(
            &output_files.artifact_manifest,
            artifact_dir,
            "artifact.json",
        ),
        pearl_ir: actual_output_path(&output_files.pearl_ir, artifact_dir, "pearl.ir.json"),
        build_report: actual_output_path(
            &output_files.build_report,
            artifact_dir,
            "build_report.json",
        ),
        native_binary: output_files
            .native_binary
            .as_deref()
            .map(|path| actual_output_path(path, artifact_dir, path)),
        wasm_module: output_files
            .wasm_module
            .as_deref()
            .map(|path| actual_output_path(path, artifact_dir, path)),
        wasm_metadata: output_files
            .wasm_metadata
            .as_deref()
            .map(|path| actual_output_path(path, artifact_dir, path)),
    }
}

fn actual_output_files_from_report_base(
    output_files: &OutputFiles,
    base_dir: &Path,
) -> OutputFiles {
    OutputFiles {
        artifact_dir: actual_output_path(&output_files.artifact_dir, base_dir, "."),
        artifact_manifest: actual_output_path(
            &output_files.artifact_manifest,
            base_dir,
            "artifact.json",
        ),
        pearl_ir: actual_output_path(&output_files.pearl_ir, base_dir, "pearl.ir.json"),
        build_report: actual_output_path(&output_files.build_report, base_dir, "build_report.json"),
        native_binary: output_files
            .native_binary
            .as_deref()
            .map(|path| actual_output_path(path, base_dir, path)),
        wasm_module: output_files
            .wasm_module
            .as_deref()
            .map(|path| actual_output_path(path, base_dir, path)),
        wasm_metadata: output_files
            .wasm_metadata
            .as_deref()
            .map(|path| actual_output_path(path, base_dir, path)),
    }
}

fn actual_discover_output_files_from_report(
    output_files: &DiscoverOutputFiles,
    output_dir: &Path,
) -> DiscoverOutputFiles {
    DiscoverOutputFiles {
        artifact_set: actual_output_path(
            &output_files.artifact_set,
            output_dir,
            "artifact_set.json",
        ),
        discover_report: actual_output_path(
            &output_files.discover_report,
            output_dir,
            "discover_report.json",
        ),
    }
}

fn actual_output_path(raw_path: &str, artifact_dir: &Path, fallback: &str) -> String {
    let path = Path::new(raw_path);
    let actual = if path.is_absolute() {
        path.to_path_buf()
    } else {
        artifact_dir.join(path)
    };
    if actual.as_os_str().is_empty() {
        artifact_dir.join(fallback).display().to_string()
    } else {
        actual.display().to_string()
    }
}

fn learn_gate_from_rows_internal(
    rows: &[DecisionTraceRow],
    options: &BuildOptions,
    numeric_interactions: bool,
) -> Result<LearnedGate> {
    if rows.is_empty() {
        return Err(LogicPearlError::message("decision trace CSV is empty"));
    }

    let (augmented_rows, derived_features) = if numeric_interactions {
        augment_rows_with_numeric_interactions(rows)?
    } else {
        (rows.to_vec(), Vec::new())
    };
    let feature_governance = options
        .feature_governance
        .as_deref()
        .map(load_feature_governance)
        .transpose()?
        .unwrap_or_default();
    let feature_dictionary = options
        .feature_dictionary
        .as_deref()
        .map(load_feature_dictionary)
        .transpose()?
        .unwrap_or_default();
    validate_feature_dictionary(&feature_dictionary, rows, &derived_features)?;
    let residual_options = options.residual_pass.then(|| {
        let mut residual_options = DEFAULT_RESIDUAL_PASS_OPTIONS.clone();
        if let Some(max_rules) = options.max_rules {
            residual_options.max_rules = max_rules;
        }
        residual_options
    });
    let refinement_options = options
        .refine
        .then_some(DEFAULT_UNIQUE_COVERAGE_REFINEMENT_OPTIONS.clone());
    let pinned_rules = options
        .pinned_rules
        .as_ref()
        .map(|path| load_pinned_rule_set(path))
        .transpose()?;
    let (
        gate,
        exact_selection,
        residual_rules_discovered,
        residual_recovery,
        refined_rules_applied,
        pinned_rules_applied,
    ) = build_gate(
        &augmented_rows,
        rows,
        &derived_features,
        &feature_governance.features,
        &feature_dictionary.features,
        &options.gate_id,
        options.decision_mode,
        options.max_rules,
        residual_options.as_ref(),
        refinement_options.as_ref(),
        pinned_rules.as_ref(),
    )?;
    gate.validate()?;
    Ok(LearnedGate {
        gate,
        exact_selection,
        residual_rules_discovered,
        residual_recovery,
        refined_rules_applied,
        pinned_rules_applied,
    })
}

fn verification_status(rule: &RuleDefinition) -> RuleVerificationStatus {
    rule.verification_status
        .clone()
        .unwrap_or(RuleVerificationStatus::PipelineUnverified)
}

fn verification_status_rank(status: &RuleVerificationStatus) -> i32 {
    match status {
        RuleVerificationStatus::SolverVerified => 4,
        RuleVerificationStatus::RefinedUnverified => 3,
        RuleVerificationStatus::PipelineUnverified => 2,
        RuleVerificationStatus::HeuristicUnverified => 1,
    }
}

trait CreateDirAllExt {
    fn mkdir_all(&self) -> Result<()>;
}

impl CreateDirAllExt for PathBuf {
    fn mkdir_all(&self) -> Result<()> {
        std::fs::create_dir_all(self)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
