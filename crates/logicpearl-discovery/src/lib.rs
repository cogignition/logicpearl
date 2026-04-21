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
use logicpearl_solver::{
    resolve_backend, SolverSettings, SOLVER_BACKEND_ENV, SOLVER_DIR_ENV, SOLVER_TIMEOUT_MS_ENV,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

mod canonicalize;
mod engine;
mod features;
mod proposals;
mod rule_text;
mod trace_loading;

use engine::{build_gate, load_pinned_rule_set};
use features::augment_rows_with_numeric_interactions;
pub use proposals::TrainingMismatchSummary;
use proposals::{
    auto_adopt_safe_proposals, build_auto_proposal_phase_report, detect_exact_trace_conflicts,
    evaluate_training_rows,
};
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
    pub selection_policy: SelectionPolicy,
    pub max_rules: Option<usize>,
    pub proposal_policy: ProposalPolicy,
    pub feature_selection: FeatureColumnSelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvent {
    pub phase: String,
    pub message: String,
}

impl ProgressEvent {
    pub fn new(phase: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            phase: phase.into(),
            message: message.into(),
        }
    }
}

pub type ProgressCallback<'a> = dyn Fn(ProgressEvent) + Send + Sync + 'a;

pub fn report_progress(
    progress: Option<&ProgressCallback<'_>>,
    phase: impl Into<String>,
    message: impl Into<String>,
) {
    if let Some(progress) = progress {
        progress(ProgressEvent::new(phase, message));
    }
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryDecisionMode {
    #[default]
    Standard,
    Review,
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProposalPolicy {
    #[default]
    AutoAdoptSafe,
    ReportOnly,
}

impl ProposalPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalPolicy::AutoAdoptSafe => "auto_adopt_safe",
            ProposalPolicy::ReportOnly => "report_only",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Default)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum SelectionPolicy {
    #[default]
    Balanced,
    RecallBiased {
        deny_recall_target: f64,
        max_false_positive_rate: f64,
    },
}

impl SelectionPolicy {
    pub fn validate(self) -> Result<Self> {
        match self {
            Self::Balanced => Ok(self),
            Self::RecallBiased {
                deny_recall_target,
                max_false_positive_rate,
            } => {
                validate_fraction("deny recall target", deny_recall_target)?;
                validate_fraction("max false-positive rate", max_false_positive_rate)?;
                Ok(self)
            }
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::RecallBiased { .. } => "recall_biased",
        }
    }

    pub fn deny_recall_target(self) -> Option<f64> {
        match self {
            Self::Balanced => None,
            Self::RecallBiased {
                deny_recall_target, ..
            } => Some(deny_recall_target),
        }
    }

    pub fn max_false_positive_rate(self) -> Option<f64> {
        match self {
            Self::Balanced => None,
            Self::RecallBiased {
                max_false_positive_rate,
                ..
            } => Some(max_false_positive_rate),
        }
    }

    pub fn required_denied_hits(self, denied_count: usize) -> usize {
        match self {
            Self::Balanced => 0,
            Self::RecallBiased {
                deny_recall_target, ..
            } => ceil_ratio_count(deny_recall_target, denied_count),
        }
    }

    pub fn max_allowed_false_positives(self, allowed_count: usize) -> usize {
        match self {
            Self::Balanced => usize::MAX,
            Self::RecallBiased {
                max_false_positive_rate,
                ..
            } => floor_ratio_count(max_false_positive_rate, allowed_count),
        }
    }

    pub fn constraints_satisfied(
        self,
        false_negatives: usize,
        false_positives: usize,
        denied_count: usize,
        allowed_count: usize,
    ) -> bool {
        match self {
            Self::Balanced => true,
            Self::RecallBiased { .. } => {
                let denied_hits = denied_count.saturating_sub(false_negatives);
                denied_hits >= self.required_denied_hits(denied_count)
                    && false_positives <= self.max_allowed_false_positives(allowed_count)
            }
        }
    }
}

fn validate_fraction(label: &str, value: f64) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        return Ok(());
    }
    Err(LogicPearlError::message(format!(
        "{label} must be a finite value between 0.0 and 1.0"
    )))
}

fn ceil_ratio_count(ratio: f64, total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    ((ratio * total as f64) - 1e-9)
        .ceil()
        .clamp(0.0, total as f64) as usize
}

fn floor_ratio_count(ratio: f64, total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    ((ratio * total as f64) + 1e-9)
        .floor()
        .clamp(0.0, total as f64) as usize
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
    pub selection_policy: SelectionPolicyReport,
    #[serde(default)]
    pub exact_selection: ExactSelectionReport,
    #[serde(default)]
    pub residual_recovery: ResidualRecoveryReport,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(default)]
    pub build_phases: Vec<BuildPhaseReport>,
    #[serde(default)]
    pub proposal_phase: ProposalPhaseReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<BuildProvenance>,
    pub output_files: OutputFiles,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct BuildPhaseReport {
    pub name: String,
    pub status: BuildPhaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default)]
    pub metrics: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuildPhaseStatus {
    Completed,
    Skipped,
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProposalPhaseStatus {
    #[default]
    Skipped,
    Ran,
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCandidateStatus {
    Validated,
    NeedsReview,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStageStatus {
    Completed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct ProposalPhaseReport {
    #[serde(default = "default_proposal_phase_schema_version")]
    pub schema_version: String,
    pub status: ProposalPhaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnosis: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_next_phase: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub acceptance_policy: String,
    #[serde(default)]
    pub candidates_tested: usize,
    #[serde(default)]
    pub validated_candidates: usize,
    #[serde(default)]
    pub accepted_candidates: usize,
    #[serde(default)]
    pub rejected_candidates: usize,
    #[serde(default)]
    pub accepted_candidate_ids: Vec<String>,
    #[serde(default)]
    pub accepted_because: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_adoption_training_parity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_adoption_training_parity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_risk: Option<String>,
    #[serde(default)]
    pub stages: Vec<ProposalStageReport>,
    #[serde(default)]
    pub candidates: Vec<ProposalCandidateReport>,
    #[serde(default)]
    pub exact_trace_conflicts: Vec<ProposalExactTraceConflictReport>,
}

impl Default for ProposalPhaseReport {
    fn default() -> Self {
        Self {
            schema_version: default_proposal_phase_schema_version(),
            status: ProposalPhaseStatus::Skipped,
            trigger: None,
            diagnosis: None,
            recommended_next_phase: None,
            reason: "build metrics did not trigger proposal search".to_string(),
            acceptance_policy: "report_only".to_string(),
            candidates_tested: 0,
            validated_candidates: 0,
            accepted_candidates: 0,
            rejected_candidates: 0,
            accepted_candidate_ids: Vec::new(),
            accepted_because: Vec::new(),
            pre_adoption_training_parity: None,
            post_adoption_training_parity: None,
            residual_risk: None,
            stages: Vec::new(),
            candidates: Vec::new(),
            exact_trace_conflicts: Vec::new(),
        }
    }
}

fn default_proposal_phase_schema_version() -> String {
    "logicpearl.proposal_phase.v0".to_string()
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct ProposalCandidateReport {
    pub proposal_id: String,
    pub proposal_type: String,
    pub source_stage: String,
    pub status: ProposalCandidateStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_expression: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub suggested_region: BTreeMap<String, Value>,
    pub evidence: ProposalEvidenceReport,
    pub validation: ProposalValidationReport,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalExactTraceConflictReport {
    pub feature_hash: String,
    pub row_indexes: Vec<usize>,
    pub label_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct ProposalStageReport {
    pub name: String,
    pub status: ProposalStageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default)]
    pub candidates_produced: usize,
    #[serde(default)]
    pub metrics: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalEvidenceReport {
    pub fixed_mismatches: usize,
    pub introduced_mismatches: usize,
    pub covered_rows: usize,
    pub covered_mismatch_rows: Vec<usize>,
    pub mismatch_summary: TrainingMismatchSummary,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalValidationReport {
    pub validator: String,
    pub deterministic: bool,
    pub passed: bool,
    pub detail: String,
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

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct SelectionPolicyReport {
    #[serde(default)]
    pub configured: SelectionPolicy,
    #[serde(default)]
    pub denied_examples: usize,
    #[serde(default)]
    pub allowed_examples: usize,
    #[serde(default)]
    pub false_negatives: usize,
    #[serde(default)]
    pub false_positives: usize,
    #[serde(default)]
    pub denied_recall: f64,
    #[serde(default)]
    pub false_positive_rate: f64,
    #[serde(default)]
    pub constraints_satisfied: bool,
}

impl Default for SelectionPolicyReport {
    fn default() -> Self {
        Self {
            configured: SelectionPolicy::Balanced,
            denied_examples: 0,
            allowed_examples: 0,
            false_negatives: 0,
            false_positives: 0,
            denied_recall: 0.0,
            false_positive_rate: 0.0,
            constraints_satisfied: true,
        }
    }
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_runs: Vec<ObservationRunProvenance>,
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

pub const OBSERVATION_SCHEMA_VERSION: &str = "logicpearl.observation_schema.v1";

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ObservationSchema {
    pub schema_version: String,
    #[serde(default)]
    pub features: Vec<ObservedFeature>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ObservedFeature {
    pub feature_id: String,
    #[serde(rename = "type")]
    pub feature_type: ObservationFeatureType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(default)]
    pub operators: Vec<ObservationOperator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ObservationFeatureType {
    Boolean,
    Integer,
    Number,
    String,
    Enum,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOperator {
    Eq,
    In,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    Startswith,
    IsNull,
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

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ObservationRunProvenance {
    #[serde(default = "default_observation_run_provenance_schema_version")]
    pub schema_version: String,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_schema_hash: Option<String>,
    pub candidate_rows_hash: String,
    pub accepted_rows_hash: String,
    pub rows_emitted: usize,
    pub rows_accepted: usize,
}

fn default_observation_run_provenance_schema_version() -> String {
    "logicpearl.observation_run_provenance.v1".to_string()
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
    pub selection_policy: SelectionPolicy,
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
    pub proposal_report: Option<String>,
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
    report.build_phases = build_phases_for_report(&result.build_phases, artifact_dir);
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
    report.build_phases = build_phases_for_report(&result.build_phases, output_dir);
    report
}

fn build_phases_for_report(phases: &[BuildPhaseReport], base_dir: &Path) -> Vec<BuildPhaseReport> {
    phases
        .iter()
        .map(|phase| {
            let mut report = phase.clone();
            report.detail = report
                .detail
                .as_deref()
                .map(|detail| phase_detail_for_report(detail, base_dir));
            report
        })
        .collect()
}

fn phase_detail_for_report(detail: &str, base_dir: &Path) -> String {
    let path = Path::new(detail);
    if path.is_absolute() {
        return artifact_relative_report_path(detail, base_dir, ".");
    }
    detail.to_string()
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
        proposal_report: output_files
            .proposal_report
            .as_deref()
            .map(|path| artifact_relative_report_path(path, artifact_dir, "proposal_report.json")),
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
        proposal_report: output_files
            .proposal_report
            .as_deref()
            .map(|path| artifact_relative_report_path(path, base_dir, "proposal_report.json")),
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
        selection_policy: SelectionPolicy,
        max_rules: Option<usize>,
        proposal_policy: ProposalPolicy,
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
        cache_version: "11".to_string(),
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
            selection_policy: options.selection_policy,
            max_rules: options.max_rules,
            proposal_policy: options.proposal_policy,
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
        selection_policy: SelectionPolicy,
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
        cache_version: "6".to_string(),
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
            selection_policy: options.selection_policy,
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
    let bytes = fs::read(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    Ok(format!("{:016x}", hasher.finish()))
}

pub fn load_observation_schema(path: &Path) -> Result<ObservationSchema> {
    let payload = fs::read_to_string(path).map_err(|err| {
        LogicPearlError::message(format!(
            "failed to read observation schema {}: {err}",
            path.display()
        ))
    })?;
    let schema: ObservationSchema = serde_json::from_str(&payload).map_err(|err| {
        LogicPearlError::message(format!("observation schema is not valid JSON: {err}"))
    })?;
    validate_observation_schema(&schema)?;
    Ok(schema)
}

pub fn validate_observation_schema(schema: &ObservationSchema) -> Result<()> {
    if schema.schema_version != OBSERVATION_SCHEMA_VERSION {
        return Err(LogicPearlError::message(format!(
            "unsupported observation schema_version {:?}; use {OBSERVATION_SCHEMA_VERSION}",
            schema.schema_version
        )));
    }
    if schema.features.is_empty() {
        return Err(LogicPearlError::message(
            "observation schema must declare at least one feature",
        ));
    }

    let mut seen_features = BTreeSet::new();
    for feature in &schema.features {
        validate_observed_feature(feature, &mut seen_features)?;
    }
    Ok(())
}

fn validate_observed_feature(
    feature: &ObservedFeature,
    seen_features: &mut BTreeSet<String>,
) -> Result<()> {
    if feature.feature_id.trim().is_empty() {
        return Err(LogicPearlError::message(
            "observation schema contains an empty feature_id",
        ));
    }
    if !seen_features.insert(feature.feature_id.clone()) {
        return Err(LogicPearlError::message(format!(
            "observation schema repeats feature_id {:?}",
            feature.feature_id
        )));
    }
    validate_optional_nonempty(&feature.label, &feature.feature_id, "label")?;
    validate_optional_nonempty(&feature.description, &feature.feature_id, "description")?;
    validate_optional_nonempty(&feature.source_id, &feature.feature_id, "source_id")?;
    validate_optional_nonempty(&feature.source_anchor, &feature.feature_id, "source_anchor")?;
    if feature.source_anchor.is_some() && feature.source_id.is_none() {
        return Err(LogicPearlError::message(format!(
            "feature {:?} declares source_anchor without source_id",
            feature.feature_id
        )));
    }

    if feature.operators.is_empty() {
        return Err(LogicPearlError::message(format!(
            "feature {:?} must declare at least one operator",
            feature.feature_id
        )));
    }
    let mut seen_operators = BTreeSet::new();
    for operator in &feature.operators {
        if !seen_operators.insert(operator.clone()) {
            return Err(LogicPearlError::message(format!(
                "feature {:?} repeats operator {:?}",
                feature.feature_id, operator
            )));
        }
        if !observation_operator_allowed(
            &feature.feature_type,
            operator,
            feature.nullable.unwrap_or(false),
        ) {
            return Err(LogicPearlError::message(format!(
                "feature {:?} of type {:?} does not support operator {:?}",
                feature.feature_id, feature.feature_type, operator
            )));
        }
    }

    match (&feature.feature_type, &feature.values) {
        (ObservationFeatureType::Enum, None) => {
            return Err(LogicPearlError::message(format!(
                "enum feature {:?} must declare non-empty values",
                feature.feature_id
            )));
        }
        (_, Some(values)) if values.is_empty() => {
            return Err(LogicPearlError::message(format!(
                "feature {:?} declares empty values",
                feature.feature_id
            )));
        }
        _ => {}
    }
    if let Some(values) = &feature.values {
        let mut seen_values = BTreeSet::new();
        for value in values {
            validate_observation_value(feature, value)?;
            let encoded = serde_json::to_string(value)?;
            if !seen_values.insert(encoded) {
                return Err(LogicPearlError::message(format!(
                    "feature {:?} repeats a value",
                    feature.feature_id
                )));
            }
        }
    }

    Ok(())
}

fn validate_optional_nonempty(value: &Option<String>, feature_id: &str, field: &str) -> Result<()> {
    if value
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(LogicPearlError::message(format!(
            "feature {feature_id:?} has an empty {field}"
        )));
    }
    Ok(())
}

fn observation_operator_allowed(
    feature_type: &ObservationFeatureType,
    operator: &ObservationOperator,
    nullable: bool,
) -> bool {
    use ObservationFeatureType as Type;
    use ObservationOperator as Op;

    if matches!(operator, Op::IsNull) {
        return nullable;
    }

    match feature_type {
        Type::Boolean => matches!(operator, Op::Eq | Op::In),
        Type::Integer | Type::Number => {
            matches!(
                operator,
                Op::Eq | Op::In | Op::Gt | Op::Gte | Op::Lt | Op::Lte
            )
        }
        Type::String => matches!(operator, Op::Eq | Op::In | Op::Contains | Op::Startswith),
        Type::Enum => matches!(operator, Op::Eq | Op::In),
    }
}

fn validate_observation_value(feature: &ObservedFeature, value: &Value) -> Result<()> {
    let valid = match feature.feature_type {
        ObservationFeatureType::Boolean => value.is_boolean(),
        ObservationFeatureType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
        ObservationFeatureType::Number => value.is_number(),
        ObservationFeatureType::String => value.is_string(),
        ObservationFeatureType::Enum => {
            value.is_boolean() || value.is_number() || value.is_string()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(LogicPearlError::message(format!(
            "feature {:?} has value {} incompatible with type {:?}",
            feature.feature_id, value, feature.feature_type
        )))
    }
}

pub fn load_feature_governance(path: &Path) -> Result<FeatureGovernanceConfig> {
    let payload = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&payload)?)
}

pub fn load_feature_dictionary(path: &Path) -> Result<FeatureDictionaryConfig> {
    let payload = fs::read_to_string(path)?;
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
    build_pearl_from_csv_with_progress(csv_path, options, None)
}

pub fn build_pearl_from_csv_with_progress(
    csv_path: &Path,
    options: &BuildOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<BuildResult> {
    report_progress(
        progress,
        "load_traces",
        format!("load_traces: reading {}", csv_path.display()),
    );
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
        selection_policy: options.selection_policy,
        max_rules: options.max_rules,
        proposal_policy: options.proposal_policy,
        feature_selection: options.feature_selection.clone(),
    };
    build_pearl_from_rows_with_progress(
        &loaded.rows,
        csv_path.display().to_string(),
        &resolved_options,
        progress,
    )
}

pub fn discover_from_csv(csv_path: &Path, options: &DiscoverOptions) -> Result<DiscoverResult> {
    discover_from_csv_with_progress(csv_path, options, None)
}

pub fn discover_from_csv_with_progress(
    csv_path: &Path,
    options: &DiscoverOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<DiscoverResult> {
    if options.target_columns.is_empty() {
        return Err(LogicPearlError::message(
            "discover requires at least one target column",
        ));
    }

    report_progress(
        progress,
        "prepare_output",
        format!("prepare_output: {}", options.output_dir.display()),
    );

    options.output_dir.mkdir_all()?;
    let discover_manifest = discover_cache_manifest(csv_path, options)?;
    let discover_cache_path = cache_manifest_path(&options.output_dir);
    let discover_report_path = options.output_dir.join("discover_report.json");
    let artifact_set_path = options.output_dir.join("artifact_set.json");
    if artifact_set_path.exists()
        && discover_report_path.exists()
        && load_cache_manifest(&discover_cache_path)?.as_ref() == Some(&discover_manifest)
    {
        report_progress(progress, "cache", "cache: reusing full discover output");
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

    report_progress(
        progress,
        "load_records",
        format!("load_records: reading {}", csv_path.display()),
    );
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

    report_progress(
        progress,
        "select_features",
        format!(
            "select_features: {} columns, {} targets",
            headers.len(),
            options.target_columns.len()
        ),
    );
    let feature_columns = options.feature_selection.selected_feature_columns(
        csv_path,
        &headers,
        &options.target_columns,
    )?;

    let artifacts_dir = options.output_dir.join("artifacts");
    artifacts_dir.mkdir_all()?;
    report_progress(
        progress,
        "infer_targets",
        format!(
            "infer_targets: {} target columns",
            options.target_columns.len()
        ),
    );
    let target_domains: HashMap<String, BinaryLabelDomain> = options
        .target_columns
        .iter()
        .map(|target| {
            infer_binary_label_domain(&records, target, None, None)
                .map(|domain| (target.clone(), domain))
        })
        .collect::<Result<_>>()?;

    report_progress(
        progress,
        "prepare_targets",
        format!("prepare_targets: {} rows", records.len()),
    );
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
        report_progress(progress, "target", format!("target: building {target}"));
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
        let build = match build_pearl_from_rows_with_progress(
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
                selection_policy: options.selection_policy,
                max_rules: None,
                proposal_policy: ProposalPolicy::ReportOnly,
                feature_selection: options.feature_selection.clone(),
            },
            progress,
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

    report_progress(
        progress,
        "write_outputs",
        "write_outputs: artifact set and report",
    );
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
    build_pearl_from_rows_with_progress(rows, source_name, options, None)
}

pub fn build_pearl_from_rows_with_progress(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<BuildResult> {
    build_pearl_from_rows_internal(rows, source_name, options, true, progress)
}

pub fn build_pearl_from_rows_without_numeric_interactions(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
) -> Result<BuildResult> {
    build_pearl_from_rows_internal(rows, source_name, options, false, None)
}

fn build_phase_report<const N: usize>(
    name: impl Into<String>,
    status: BuildPhaseStatus,
    detail: Option<String>,
    metrics: [(&str, Value); N],
) -> BuildPhaseReport {
    BuildPhaseReport {
        name: name.into(),
        status,
        detail,
        metrics: metrics
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    }
}

pub fn learn_gate_from_rows_without_numeric_interactions(
    rows: &[DecisionTraceRow],
    options: &BuildOptions,
) -> Result<LearnedGate> {
    learn_gate_from_rows_internal(rows, options, false, None)
}

pub fn learn_gate_from_rows_without_numeric_interactions_with_progress(
    rows: &[DecisionTraceRow],
    options: &BuildOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<LearnedGate> {
    learn_gate_from_rows_internal(rows, options, false, progress)
}

fn build_pearl_from_rows_internal(
    rows: &[DecisionTraceRow],
    source_name: String,
    options: &BuildOptions,
    numeric_interactions: bool,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<BuildResult> {
    if rows.is_empty() {
        return Err(LogicPearlError::message("decision trace CSV is empty"));
    }

    options.output_dir.mkdir_all()?;
    report_progress(
        progress,
        "prepare_output",
        format!("prepare_output: {}", options.output_dir.display()),
    );
    let build_manifest = build_cache_manifest(rows, &source_name, options)?;
    let build_cache_path = cache_manifest_path(&options.output_dir);
    let build_report_path = options.output_dir.join("build_report.json");
    let proposal_report_path = options.output_dir.join("proposal_report.json");
    let pearl_ir_path = options.output_dir.join("pearl.ir.json");
    if pearl_ir_path.exists()
        && build_report_path.exists()
        && load_cache_manifest(&build_cache_path)?.as_ref() == Some(&build_manifest)
    {
        report_progress(progress, "cache", "cache: reusing prior build output");
        let mut cached: BuildResult =
            serde_json::from_str(&std::fs::read_to_string(&build_report_path)?)?;
        cached.source_csv = source_name;
        cached.output_files =
            actual_output_files_from_report(&cached.output_files, &options.output_dir);
        cached.cache_hit = true;
        return Ok(cached);
    }

    let mut build_phases = vec![build_phase_report(
        "prepare_output",
        BuildPhaseStatus::Completed,
        Some(format!("{}", options.output_dir.display())),
        [("rows", serde_json::json!(rows.len()))],
    )];
    let LearnedGate {
        mut gate,
        exact_selection,
        residual_rules_discovered,
        residual_recovery,
        refined_rules_applied,
        pinned_rules_applied,
    } = learn_gate_from_rows_internal(rows, options, numeric_interactions, progress)?;
    build_phases.push(build_phase_report(
        "discover_rules",
        BuildPhaseStatus::Completed,
        Some("deterministic rule discovery completed".to_string()),
        [
            ("rules", serde_json::json!(gate.rules.len())),
            (
                "residual_rules",
                serde_json::json!(residual_rules_discovered),
            ),
            ("refined_rules", serde_json::json!(refined_rules_applied)),
            ("pinned_rules", serde_json::json!(pinned_rules_applied)),
        ],
    ));
    gate.validate()?;

    report_progress(
        progress,
        "pre_adoption_training_parity",
        format!(
            "pre_adoption_training_parity: evaluating {} rows",
            rows.len()
        ),
    );
    let pre_adoption_evaluation = evaluate_training_rows(&gate, rows)?;
    let pre_adoption_training_parity = pre_adoption_evaluation.correct as f64 / rows.len() as f64;
    build_phases.push(build_phase_report(
        "training_parity",
        BuildPhaseStatus::Completed,
        Some("evaluated learned gate against training rows before proposal adoption".to_string()),
        [
            (
                "pre_adoption_parity",
                serde_json::json!(pre_adoption_training_parity),
            ),
            (
                "mismatches",
                serde_json::json!(pre_adoption_evaluation.mismatches.len()),
            ),
        ],
    ));

    report_progress(
        progress,
        "proposal_phase",
        "proposal_phase: checking automatic triggers",
    );
    let exact_trace_conflicts = detect_exact_trace_conflicts(rows);
    let mut proposal_phase = build_auto_proposal_phase_report(
        rows,
        &gate,
        &pre_adoption_evaluation.mismatches,
        exact_trace_conflicts,
    );
    proposal_phase.acceptance_policy = options.proposal_policy.as_str().to_string();
    proposal_phase.pre_adoption_training_parity = Some(pre_adoption_training_parity);
    proposal_phase.post_adoption_training_parity = Some(pre_adoption_training_parity);

    let final_evaluation = match options.proposal_policy {
        ProposalPolicy::AutoAdoptSafe => {
            auto_adopt_safe_proposals(&mut gate, rows, &mut proposal_phase)?
        }
        ProposalPolicy::ReportOnly => pre_adoption_evaluation,
    };
    let training_parity = final_evaluation.correct as f64 / rows.len() as f64;
    let selection_policy =
        selection_policy_report(rows, &final_evaluation.mismatches, options.selection_policy);
    build_phases.push(build_phase_report(
        "proposal_phase",
        match proposal_phase.status {
            ProposalPhaseStatus::Ran => BuildPhaseStatus::Completed,
            ProposalPhaseStatus::Skipped => BuildPhaseStatus::Skipped,
        },
        Some(proposal_phase.reason.clone()),
        [
            (
                "candidates_tested",
                serde_json::json!(proposal_phase.candidates_tested),
            ),
            (
                "validated_candidates",
                serde_json::json!(proposal_phase.validated_candidates),
            ),
            (
                "accepted_candidates",
                serde_json::json!(proposal_phase.accepted_candidates),
            ),
            ("post_adoption_parity", serde_json::json!(training_parity)),
        ],
    ));
    build_phases.push(build_phase_report(
        "selection_policy",
        if selection_policy.constraints_satisfied {
            BuildPhaseStatus::Completed
        } else {
            BuildPhaseStatus::Skipped
        },
        Some(match options.selection_policy {
            SelectionPolicy::Balanced => {
                "balanced selection policy minimizes total replay error".to_string()
            }
            SelectionPolicy::RecallBiased {
                deny_recall_target,
                max_false_positive_rate,
            } => format!(
                "recall-biased selection targeted denied recall >= {:.1}% with false-positive rate <= {:.1}%",
                deny_recall_target * 100.0,
                max_false_positive_rate * 100.0
            ),
        }),
        [
            ("policy", serde_json::json!(options.selection_policy.name())),
            (
                "denied_recall",
                serde_json::json!(selection_policy.denied_recall),
            ),
            (
                "false_positive_rate",
                serde_json::json!(selection_policy.false_positive_rate),
            ),
            (
                "constraints_satisfied",
                serde_json::json!(selection_policy.constraints_satisfied),
            ),
            (
                "deny_recall_target",
                serde_json::json!(options.selection_policy.deny_recall_target()),
            ),
            (
                "max_false_positive_rate",
                serde_json::json!(options.selection_policy.max_false_positive_rate()),
            ),
        ],
    ));
    report_progress(progress, "write_ir", "write_ir: pearl.ir.json");
    gate.validate()?;
    gate.write_pretty(&pearl_ir_path)?;
    build_phases.push(build_phase_report(
        "write_ir",
        BuildPhaseStatus::Completed,
        Some("pearl.ir.json".to_string()),
        [
            ("rules", serde_json::json!(gate.rules.len())),
            ("training_parity", serde_json::json!(training_parity)),
        ],
    ));

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
        selection_policy,
        exact_selection,
        residual_recovery,
        cache_hit: false,
        build_phases,
        proposal_phase,
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
            proposal_report: Some(proposal_report_path.display().to_string()),
            native_binary: None,
            wasm_module: None,
            wasm_metadata: None,
        },
    };

    report_progress(
        progress,
        "write_report",
        "write_report: proposal_report.json",
    );
    std::fs::write(
        &proposal_report_path,
        serde_json::to_string_pretty(&build_report.proposal_phase)? + "\n",
    )?;
    report_progress(progress, "write_report", "write_report: build_report.json");
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
        proposal_report: output_files
            .proposal_report
            .as_deref()
            .map(|path| actual_output_path(path, artifact_dir, "proposal_report.json")),
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
        proposal_report: output_files
            .proposal_report
            .as_deref()
            .map(|path| actual_output_path(path, base_dir, "proposal_report.json")),
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

fn selection_policy_report(
    rows: &[DecisionTraceRow],
    mismatches: &[proposals::TrainingMismatch],
    configured: SelectionPolicy,
) -> SelectionPolicyReport {
    let denied_examples = rows.iter().filter(|row| !row.allowed).count();
    let allowed_examples = rows.iter().filter(|row| row.allowed).count();
    let false_negatives = mismatches
        .iter()
        .filter(|mismatch| !mismatch.expected_allowed && mismatch.predicted_allowed)
        .count();
    let false_positives = mismatches
        .iter()
        .filter(|mismatch| mismatch.expected_allowed && !mismatch.predicted_allowed)
        .count();
    let denied_recall = if denied_examples == 0 {
        1.0
    } else {
        (denied_examples.saturating_sub(false_negatives)) as f64 / denied_examples as f64
    };
    let false_positive_rate = if allowed_examples == 0 {
        0.0
    } else {
        false_positives as f64 / allowed_examples as f64
    };

    SelectionPolicyReport {
        configured,
        denied_examples,
        allowed_examples,
        false_negatives,
        false_positives,
        denied_recall,
        false_positive_rate,
        constraints_satisfied: configured.constraints_satisfied(
            false_negatives,
            false_positives,
            denied_examples,
            allowed_examples,
        ),
    }
}

fn learn_gate_from_rows_internal(
    rows: &[DecisionTraceRow],
    options: &BuildOptions,
    numeric_interactions: bool,
    progress: Option<&ProgressCallback<'_>>,
) -> Result<LearnedGate> {
    if rows.is_empty() {
        return Err(LogicPearlError::message("decision trace CSV is empty"));
    }

    let (augmented_rows, derived_features) = if numeric_interactions {
        report_progress(
            progress,
            "prepare_features",
            "prepare_features: deriving numeric interactions",
        );
        augment_rows_with_numeric_interactions(rows)?
    } else {
        (rows.to_vec(), Vec::new())
    };
    report_progress(
        progress,
        "load_metadata",
        "load_metadata: feature governance and dictionary",
    );
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
    let selection_policy = options.selection_policy.validate()?;
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
    report_progress(
        progress,
        "learn_rules",
        format!("learn_rules: {} rows", augmented_rows.len()),
    );
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
        selection_policy,
        options.max_rules,
        residual_options.as_ref(),
        refinement_options.as_ref(),
        pinned_rules.as_ref(),
        progress,
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
