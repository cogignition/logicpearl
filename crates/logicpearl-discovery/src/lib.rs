// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    Expression, FeatureGovernance, FeatureSemantics, LogicPearlGateIr, RuleDefinition,
    RuleVerificationStatus,
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
    load_decision_traces, load_decision_traces_auto, load_decision_traces_with_labels,
    load_flat_records, LoadedFlatRecords,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace_source: Option<BuildInputProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_plugin: Option<PluginBuildProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enricher_plugin: Option<PluginBuildProvenance>,
    #[serde(default)]
    pub source_references: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct BuildInputProvenance {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PluginBuildProvenance {
    pub name: String,
    pub stage: String,
    pub manifest_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<BuildInputProvenance>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    pub output_dir: PathBuf,
    pub artifact_set_id: String,
    pub target_columns: Vec<String>,
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
    source_name: &str,
    options: &BuildOptions,
) -> Result<CacheManifest> {
    #[derive(Serialize)]
    struct BuildFingerprintRow<'a> {
        allowed: bool,
        features: BTreeMap<&'a str, &'a Value>,
    }

    #[derive(Serialize)]
    struct BuildFingerprintOptions<'a> {
        source_name: &'a str,
        gate_id: &'a str,
        label_column: &'a str,
        positive_label: Option<&'a str>,
        negative_label: Option<&'a str>,
        residual_pass: bool,
        refine: bool,
        pinned_rules_path: Option<String>,
        pinned_rules_fingerprint: Option<String>,
        feature_dictionary_path: Option<String>,
        feature_dictionary_fingerprint: Option<String>,
        feature_governance_path: Option<String>,
        feature_governance_fingerprint: Option<String>,
        decision_mode: DiscoveryDecisionMode,
        max_rules: Option<usize>,
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
        cache_version: "5".to_string(),
        operation: "build".to_string(),
        input_fingerprint: cache_fingerprint(&rows_fingerprint)?,
        options_fingerprint: cache_fingerprint(&BuildFingerprintOptions {
            source_name,
            gate_id: &options.gate_id,
            label_column: &options.label_column,
            positive_label: options.positive_label.as_deref(),
            negative_label: options.negative_label.as_deref(),
            residual_pass: options.residual_pass,
            refine: options.refine,
            pinned_rules_path: options
                .pinned_rules
                .as_ref()
                .map(|path| path.display().to_string()),
            pinned_rules_fingerprint,
            feature_dictionary_path: options
                .feature_dictionary
                .as_ref()
                .map(|path| path.display().to_string()),
            feature_dictionary_fingerprint,
            feature_governance_path: options
                .feature_governance
                .as_ref()
                .map(|path| path.display().to_string()),
            feature_governance_fingerprint,
            decision_mode: options.decision_mode,
            max_rules: options.max_rules,
            solver_backend_env: std::env::var(SOLVER_BACKEND_ENV).ok(),
            resolved_solver_backend: resolved_solver_backend_name(),
            solver_timeout_ms_env: std::env::var(SOLVER_TIMEOUT_MS_ENV).ok(),
            solver_dir_env: std::env::var(SOLVER_DIR_ENV).ok(),
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
        pinned_rules_path: Option<String>,
        pinned_rules_fingerprint: Option<String>,
        feature_dictionary_path: Option<String>,
        feature_dictionary_fingerprint: Option<String>,
        feature_governance_path: Option<String>,
        feature_governance_fingerprint: Option<String>,
        decision_mode: DiscoveryDecisionMode,
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
        cache_version: "3".to_string(),
        operation: "discover".to_string(),
        input_fingerprint: fingerprint_file(csv_path)?,
        options_fingerprint: cache_fingerprint(&DiscoverFingerprintOptions {
            artifact_set_id: &options.artifact_set_id,
            target_columns: &options.target_columns,
            residual_pass: options.residual_pass,
            refine: options.refine,
            pinned_rules_path: options
                .pinned_rules
                .as_ref()
                .map(|path| path.display().to_string()),
            pinned_rules_fingerprint,
            feature_dictionary_path: options
                .feature_dictionary
                .as_ref()
                .map(|path| path.display().to_string()),
            feature_dictionary_fingerprint,
            feature_governance_path: options
                .feature_governance
                .as_ref()
                .map(|path| path.display().to_string()),
            feature_governance_fingerprint,
            decision_mode: options.decision_mode,
            solver_backend_env: std::env::var(SOLVER_BACKEND_ENV).ok(),
            resolved_solver_backend: resolved_solver_backend_name(),
            solver_timeout_ms_env: std::env::var(SOLVER_TIMEOUT_MS_ENV).ok(),
            solver_dir_env: std::env::var(SOLVER_DIR_ENV).ok(),
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
    let loaded = load_decision_traces_auto(
        csv_path,
        Some(&options.label_column),
        options.positive_label.as_deref(),
        options.negative_label.as_deref(),
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
        cached.cache_hit = true;
        for artifact in &mut cached.artifacts {
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

    let feature_columns: Vec<String> = headers
        .iter()
        .filter(|header| {
            !options
                .target_columns
                .iter()
                .any(|target| target == *header)
        })
        .map(ToOwned::to_owned)
        .collect();
    if feature_columns.is_empty() {
        return Err(LogicPearlError::message(
            "discover needs at least one feature column after removing targets",
        ));
    }

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
            features.insert(header.to_string(), value.clone());
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
        serde_json::to_string_pretty(&discover)? + "\n",
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
        serde_json::to_string_pretty(&build_report)? + "\n",
    )?;
    write_cache_manifest(&build_cache_path, &build_manifest)?;

    Ok(build_report)
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
mod tests {
    use super::{
        build_pearl_from_csv, build_pearl_from_rows, canonicalize_rules, dedupe_rules_by_signature,
        discover_from_csv, discover_residual_rules, discovery_selection_env_lock, gate_from_rules,
        load_decision_traces, load_decision_traces_auto, merge_discovered_and_pinned_rules,
        prune_redundant_rules, rule_from_candidate, BuildOptions, CandidateRule, DecisionTraceRow,
        DiscoverOptions, DiscoveryDecisionMode, PinnedRuleSet, ResidualPassOptions,
        ResidualRecoveryState,
    };
    use logicpearl_ir::{
        ComparisonExpression, ComparisonOperator, ComparisonValue, Expression, LogicPearlGateIr,
        RuleDefinition, RuleKind, RuleVerificationStatus,
    };
    use logicpearl_solver::{check_sat, SolverSettings};
    use serde_json::{Number, Value};
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;

    fn solver_available() -> bool {
        check_sat("(check-sat)\n", &SolverSettings::default()).is_ok()
    }

    #[test]
    fn load_decision_traces_parses_allowed_column() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "age,is_member,allowed\n21,1,allowed\n15,1,denied\n",
        )
        .unwrap();

        let rows = load_decision_traces(&csv_path, "allowed").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].features["age"], 21);
        assert_eq!(rows[0].features["is_member"], 1);
        assert!(rows[0].allowed);
        assert!(!rows[1].allowed);
    }

    #[test]
    fn load_decision_traces_auto_prefers_allowed_name() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "age,is_member,allowed\n21,1,allowed\n15,0,denied\n",
        )
        .unwrap();

        let loaded = load_decision_traces_auto(&csv_path, None, None, None).unwrap();
        assert_eq!(loaded.label_column, "allowed");
        assert_eq!(loaded.rows.len(), 2);
    }

    #[test]
    fn load_decision_traces_auto_supports_realistic_binary_labels() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "credit_score,approved\n780,approved\n570,denied\n",
        )
        .unwrap();

        let loaded = load_decision_traces_auto(&csv_path, None, None, None).unwrap();
        assert_eq!(loaded.label_column, "approved");
        assert!(loaded.rows[0].allowed);
        assert!(!loaded.rows[1].allowed);
    }

    #[test]
    fn load_decision_traces_normalizes_formatted_scalars() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "annual_income,debt_ratio,mfa_enabled,approved\n\"$95,000\",22%,Yes,approved\n\"$31,000\",61%,No,denied\n",
        )
        .unwrap();

        let loaded = load_decision_traces_auto(&csv_path, None, None, None).unwrap();
        assert_eq!(loaded.rows[0].features["annual_income"], 95_000);
        assert_eq!(
            loaded.rows[0].features["debt_ratio"],
            Value::Number(Number::from_f64(0.22).unwrap())
        );
        assert_eq!(loaded.rows[0].features["mfa_enabled"], Value::Bool(true));
        assert_eq!(loaded.rows[1].features["mfa_enabled"], Value::Bool(false));
    }

    #[test]
    fn load_decision_traces_auto_supports_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("decision_traces.jsonl");
        std::fs::write(
            &jsonl_path,
            "{\"credit_score\":780,\"annual_income\":\"$95,000\",\"approved\":\"approved\"}\n{\"credit_score\":570,\"annual_income\":\"$48,000\",\"approved\":\"denied\"}\n",
        )
        .unwrap();

        let loaded = load_decision_traces_auto(&jsonl_path, None, None, None).unwrap();
        assert_eq!(loaded.label_column, "approved");
        assert_eq!(loaded.rows[0].features["annual_income"], 95_000);
        assert!(loaded.rows[0].allowed);
        assert!(!loaded.rows[1].allowed);
    }

    #[test]
    fn load_decision_traces_auto_supports_nested_json() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("decision_traces.json");
        std::fs::write(
            &json_path,
            r#"[
  {
    "account": {"age_days": 730, "verified": "Yes"},
    "signals": {"toxicity_score": 0.05, "spam_likelihood": 0.10},
    "result": {"verdict": "pass"}
  },
  {
    "account": {"age_days": 12, "verified": "No"},
    "signals": {"toxicity_score": 0.82, "spam_likelihood": 0.91},
    "result": {"verdict": "flagged"}
  }
]"#,
        )
        .unwrap();

        let loaded = load_decision_traces_auto(&json_path, None, None, None).unwrap();
        assert_eq!(loaded.label_column, "result.verdict");
        assert_eq!(loaded.rows[0].features["account.age_days"], 730);
        assert_eq!(
            loaded.rows[0].features["account.verified"],
            Value::Bool(true)
        );
        assert_eq!(
            loaded.rows[1].features["signals.spam_likelihood"],
            Value::Number(Number::from_f64(0.91).unwrap())
        );
        assert!(loaded.rows[0].allowed);
        assert!(!loaded.rows[1].allowed);
    }

    #[test]
    fn decision_trace_loader_errors_explain_normalization_boundary() {
        let dir = tempfile::tempdir().unwrap();

        let csv_path = dir.path().join("empty_value.csv");
        std::fs::write(&csv_path, "age,allowed\n,yes\n").unwrap();
        let err = load_decision_traces_auto(&csv_path, None, None, None).unwrap_err();
        assert!(err.to_string().contains("empty value"));
        assert!(err
            .to_string()
            .contains("normalized rectangular decision traces"));

        let json_path = dir.path().join("null_value.json");
        std::fs::write(
            &json_path,
            r#"[{"age":21,"allowed":"yes"},{"age":null,"allowed":"no"}]"#,
        )
        .unwrap();
        let err = load_decision_traces_auto(&json_path, None, None, None).unwrap_err();
        assert!(err.to_string().contains("contains null"));
        assert!(err.to_string().contains("trace_source plugin"));

        let ragged_path = dir.path().join("ragged.jsonl");
        std::fs::write(
            &ragged_path,
            "{\"age\":21,\"allowed\":\"yes\"}\n{\"score\":9,\"allowed\":\"no\"}\n",
        )
        .unwrap();
        let err = load_decision_traces_auto(&ragged_path, None, None, None).unwrap_err();
        assert!(err.to_string().contains("different schema"));
        assert!(err.to_string().contains("adapter before discovery"));
    }

    #[test]
    fn load_decision_traces_requires_explicit_mapping_for_unknown_binary_labels() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(&csv_path, "score,status\n1,alpha\n0,beta\n").unwrap();

        let err = load_decision_traces_auto(&csv_path, Some("status"), None, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("pass --default-label or --rule-label explicitly"));

        let loaded =
            load_decision_traces_auto(&csv_path, Some("status"), Some("alpha"), None).unwrap();
        assert!(loaded.rows[0].allowed);
        assert!(!loaded.rows[1].allowed);
    }

    #[test]
    fn load_decision_traces_auto_rejects_ambiguous_binary_columns() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(&csv_path, "is_member,is_urgent\n1,0\n0,1\n").unwrap();

        let err = load_decision_traces_auto(&csv_path, None, None, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("multiple possible binary label fields"));
        assert!(err.to_string().contains("is_member"));
        assert!(err.to_string().contains("is_urgent"));
    }

    #[test]
    fn build_pearl_from_csv_emits_gate_ir_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "age,is_member,allowed\n21,1,allowed\n25,0,allowed\n30,1,allowed\n35,0,allowed\n16,1,denied\n15,0,denied\n14,1,denied\n13,0,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &csv_path,
            &BuildOptions {
                output_dir: PathBuf::from(&output_dir),
                gate_id: "age_gate".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.rows, 8);
        assert_eq!(result.rules_discovered, 1);
        assert_eq!(result.training_parity, 1.0);
        assert_eq!(
            result.residual_recovery.state,
            ResidualRecoveryState::Disabled
        );
        assert!(output_dir.join("pearl.ir.json").exists());
        assert!(output_dir.join("build_report.json").exists());
    }

    #[test]
    fn build_pearl_from_jsonl_emits_gate_ir_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("decision_traces.jsonl");
        std::fs::write(
            &jsonl_path,
            "{\"age\":21,\"is_member\":1,\"allowed\":\"allowed\"}\n{\"age\":25,\"is_member\":0,\"allowed\":\"allowed\"}\n{\"age\":16,\"is_member\":1,\"allowed\":\"denied\"}\n{\"age\":15,\"is_member\":0,\"allowed\":\"denied\"}\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &jsonl_path,
            &BuildOptions {
                output_dir: PathBuf::from(&output_dir),
                gate_id: "age_gate_jsonl".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.rows, 4);
        assert_eq!(result.training_parity, 1.0);
        assert!(output_dir.join("pearl.ir.json").exists());
    }

    #[test]
    fn canonicalize_rules_merges_adjacent_numeric_intervals() {
        let rules = vec![
            RuleDefinition {
                id: "rule_a".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "toxicity".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
                }),
                label: Some("deny".to_string()),
                message: Some("deny toxic content".to_string()),
                severity: Some("high".to_string()),
                counterfactual_hint: Some("lower toxicity".to_string()),
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            },
            RuleDefinition {
                id: "rule_b".to_string(),
                kind: RuleKind::Predicate,
                bit: 1,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "toxicity".to_string(),
                    op: ComparisonOperator::Gt,
                    value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
                }),
                label: Some("deny".to_string()),
                message: Some("deny toxic content".to_string()),
                severity: Some("high".to_string()),
                counterfactual_hint: Some("lower toxicity".to_string()),
                verification_status: Some(RuleVerificationStatus::RefinedUnverified),
            },
        ];

        let canonicalized = canonicalize_rules(rules);
        assert_eq!(canonicalized.len(), 1);
        assert_eq!(
            canonicalized[0].verification_status,
            Some(RuleVerificationStatus::RefinedUnverified)
        );
        assert_eq!(
            canonicalized[0].deny_when,
            Expression::Comparison(ComparisonExpression {
                feature: "toxicity".to_string(),
                op: ComparisonOperator::Gte,
                value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
            })
        );
    }

    #[test]
    fn canonicalize_rules_preserves_distinct_messages() {
        let rules = vec![
            RuleDefinition {
                id: "rule_a".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "toxicity".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
                }),
                label: None,
                message: Some("exact threshold".to_string()),
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            },
            RuleDefinition {
                id: "rule_b".to_string(),
                kind: RuleKind::Predicate,
                bit: 1,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "toxicity".to_string(),
                    op: ComparisonOperator::Gt,
                    value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
                }),
                label: None,
                message: Some("strictly above threshold".to_string()),
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            },
        ];

        let canonicalized = canonicalize_rules(rules);
        assert_eq!(canonicalized.len(), 2);
    }

    #[test]
    fn discover_from_csv_emits_artifact_set_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("multi_target.csv");
        std::fs::write(
            &csv_path,
            "signal_a,signal_b,target_a,target_b\n0,0,allowed,allowed\n1,0,denied,allowed\n0,1,allowed,denied\n1,1,denied,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("discovered");

        let result = discover_from_csv(
            &csv_path,
            &DiscoverOptions {
                output_dir: output_dir.clone(),
                artifact_set_id: "multi_target_demo".to_string(),
                target_columns: vec!["target_a".to_string(), "target_b".to_string()],
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
            },
        )
        .unwrap();

        assert_eq!(result.targets.len(), 2);
        assert_eq!(result.artifacts.len(), 2);
        assert!(output_dir.join("artifact_set.json").exists());
        assert!(output_dir.join("discover_report.json").exists());
        assert!(output_dir.join("artifacts/target_a/pearl.ir.json").exists());
        assert!(output_dir.join("artifacts/target_b/pearl.ir.json").exists());
        assert!(result.skipped_targets.is_empty());
    }

    #[test]
    fn build_prefers_higher_parity_rule_over_tiny_zero_fp_fragment() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "signal_flag,confidence,allowed\n0,0.02,allowed\n0,0.02,allowed\n0,0.02,allowed\n1,0.02,allowed\n1,0.02,denied\n1,0.02,denied\n1,0.02,denied\n1,0.21,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &csv_path,
            &BuildOptions {
                output_dir: PathBuf::from(&output_dir),
                gate_id: "approximate_gate".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        let pearl_ir = std::fs::read_to_string(output_dir.join("pearl.ir.json")).unwrap();
        assert!(pearl_ir.contains("signal_flag"));
        assert!(result.training_parity > 0.8);
    }

    #[test]
    fn build_residual_pass_recovers_missed_boolean_slice() {
        if !solver_available() {
            return;
        }

        let rows = vec![
            row(&[("seed", 1), ("a", 1), ("b", 1)], false),
            row(&[("seed", 0), ("a", 1), ("b", 1)], false),
            row(&[("seed", 0), ("a", 1), ("b", 1)], false),
            row(&[("seed", 0), ("a", 1), ("b", 0)], true),
            row(&[("seed", 0), ("a", 0), ("b", 1)], true),
            row(&[("seed", 0), ("a", 0), ("b", 0)], true),
        ];
        let first_pass_gate = gate_from_rules(
            &rows,
            &rows,
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            "residual_gate",
            vec![rule_from_candidate(
                0,
                &CandidateRule::new(
                    Expression::Comparison(ComparisonExpression {
                        feature: "seed".to_string(),
                        op: ComparisonOperator::Gt,
                        value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    }),
                    1,
                    0,
                ),
            )],
        )
        .unwrap();

        let residual_rules = discover_residual_rules(
            &rows,
            &first_pass_gate,
            &BTreeMap::new(),
            &ResidualPassOptions {
                max_conditions: 2,
                min_positive_support: 2,
                max_negative_hits: 0,
                max_rules: 1,
            },
        )
        .unwrap();

        assert_eq!(residual_rules.len(), 1);
        match &residual_rules[0].deny_when {
            Expression::All { all } => {
                assert_eq!(all.len(), 2);
                let rendered = serde_json::to_string(all).unwrap();
                assert!(rendered.contains("\"feature\":\"a\""));
                assert!(rendered.contains("\"feature\":\"b\""));
            }
            other => panic!("expected residual all-expression, got {other:?}"),
        }
    }

    #[test]
    fn build_refine_tightens_uniquely_overbroad_rule() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "signal,guard,allowed\n1,1,denied\n1,1,denied\n1,0,allowed\n0,1,allowed\n0,0,allowed\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &csv_path,
            &BuildOptions {
                output_dir: PathBuf::from(&output_dir),
                gate_id: "refined_gate".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: true,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.refined_rules_applied, 1);
        assert_eq!(result.training_parity, 1.0);

        let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
        let gate_json = serde_json::to_string_pretty(&gate).unwrap();
        assert!(gate_json.contains("\"all\""));
        assert!(gate_json.contains("\"feature\": \"signal\""));
        assert!(gate_json.contains("\"feature\": \"guard\""));
    }

    #[test]
    fn build_residual_pass_recovers_policy_style_conjunction_rules() {
        if !solver_available() {
            return;
        }

        let rows = vec![
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(1)),
                    ("action_read", Value::from(0)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(1)),
                    ("action_read", Value::from(0)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(1)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(1)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(0)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(1)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(0)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(1)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(0)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(0)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(0)),
                    ("sensitivity", Value::from(2)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(0)),
                    ("sensitivity", Value::from(1)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                false,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                true,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(1)),
                ],
                true,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(1)),
                    ("action_delete", Value::from(1)),
                    ("action_read", Value::from(0)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                true,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(1)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(1)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                true,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(1)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(0)),
                    ("is_public", Value::from(1)),
                    ("is_contractor", Value::from(0)),
                ],
                true,
            ),
            row_values(
                &[
                    ("is_admin", Value::from(0)),
                    ("action_delete", Value::from(0)),
                    ("action_read", Value::from(1)),
                    ("archived", Value::from(0)),
                    ("is_authenticated", Value::from(0)),
                    ("sensitivity", Value::from(0)),
                    ("team_match", Value::from(1)),
                    ("is_public", Value::from(0)),
                    ("is_contractor", Value::from(0)),
                ],
                true,
            ),
        ];

        let dir = tempfile::tempdir().unwrap();
        let coarse_output = dir.path().join("coarse");
        let recovered_output = dir.path().join("recovered");

        let coarse = build_pearl_from_rows(
            &rows,
            "policy_style".to_string(),
            &BuildOptions {
                output_dir: coarse_output.clone(),
                gate_id: "policy_style".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();
        assert!(coarse.training_parity < 1.0);
        assert_eq!(
            coarse.residual_recovery.state,
            ResidualRecoveryState::Disabled
        );

        let recovered = build_pearl_from_rows(
            &rows,
            "policy_style".to_string(),
            &BuildOptions {
                output_dir: recovered_output.clone(),
                gate_id: "policy_style".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: true,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(recovered.training_parity, 1.0);
        assert_eq!(
            recovered.residual_recovery.state,
            ResidualRecoveryState::Applied
        );
        let gate = LogicPearlGateIr::from_path(recovered_output.join("pearl.ir.json")).unwrap();
        let rendered = serde_json::to_string(&gate.rules).unwrap();
        assert!(rendered.contains("\"all\""));
        assert!(rendered.contains("\"feature\":\"action_read\""));
        assert!(rendered.contains("\"feature\":\"is_admin\""));
        assert!(rendered.contains("\"feature\":\"archived\""));
        assert!(rendered.contains("\"feature\":\"team_match\""));
        assert!(rendered.contains("\"feature\":\"sensitivity\""));
    }

    #[test]
    fn build_discovers_boolean_feature_predicate() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "mfa_enabled,approved\nYes,approved\nYes,approved\nYes,approved\nNo,denied\nNo,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &csv_path,
            &BuildOptions {
                output_dir: output_dir.clone(),
                gate_id: "bool_gate".to_string(),
                label_column: "approved".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.training_parity, 1.0);
        let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
        let rendered = serde_json::to_string(&gate).unwrap();
        assert!(rendered.contains("\"feature\":\"mfa_enabled\""));
        assert!(rendered.contains("\"value\":false"));
    }

    #[test]
    fn build_learns_numeric_feature_relationships() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("access_control.csv");
        std::fs::write(
            &csv_path,
            "clearance_level,resource_sensitivity,allowed\n\
5,2,allowed\n\
4,1,allowed\n\
3,2,allowed\n\
2,1,allowed\n\
4,5,denied\n\
3,4,denied\n\
2,3,denied\n\
1,2,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &csv_path,
            &BuildOptions {
                output_dir: output_dir.clone(),
                gate_id: "access_control".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.training_parity, 1.0);
        let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
        let rendered = serde_json::to_string(&gate).unwrap();
        assert!(rendered.contains("\"feature_ref\":\"resource_sensitivity\""));
    }

    #[test]
    fn build_prefers_zero_false_positive_multi_rule_completion() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("content.csv");
        std::fs::write(
            &csv_path,
            "toxicity,spam,account_age,report_count,allowed\n\
0.05,0.10,730,0,allowed\n\
0.12,0.08,1200,1,allowed\n\
0.20,0.15,365,0,allowed\n\
0.08,0.22,540,1,allowed\n\
0.15,0.18,900,0,allowed\n\
0.03,0.05,2000,0,allowed\n\
0.18,0.12,450,1,allowed\n\
0.10,0.30,180,0,allowed\n\
0.22,0.25,60,2,allowed\n\
0.06,0.11,1500,0,allowed\n\
0.25,0.20,300,1,allowed\n\
0.14,0.35,90,1,allowed\n\
0.28,0.40,45,2,allowed\n\
0.80,0.15,800,0,denied\n\
0.82,0.20,1200,1,denied\n\
0.90,0.10,600,0,denied\n\
0.78,0.25,365,0,denied\n\
0.18,0.85,180,0,denied\n\
0.12,0.90,365,1,denied\n\
0.22,0.82,540,0,denied\n\
0.15,0.18,10,0,denied\n\
0.08,0.25,5,1,denied\n\
0.20,0.22,20,0,denied\n\
0.18,0.20,730,5,denied\n\
0.10,0.18,900,6,denied\n\
0.22,0.25,540,7,denied\n\
0.78,0.88,8,9,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("output");

        let result = build_pearl_from_csv(
            &csv_path,
            &BuildOptions {
                output_dir: output_dir.clone(),
                gate_id: "content_gate".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.training_parity, 1.0);
        let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
        let rendered = serde_json::to_string(&gate).unwrap();
        assert!(rendered.contains("\"feature\":\"spam\""));
        assert!(rendered.contains("\"feature\":\"toxicity\""));
        assert!(!rendered.contains("\"feature\":\"toxicity\",\"op\":\">\",\"value\":0.15"));
    }

    #[test]
    fn prune_redundant_rules_drops_exact_match_shards() {
        let rows = vec![
            row_values(
                &[
                    ("annual_income", Value::Number(Number::from(85000))),
                    ("debt_ratio", Value::Number(Number::from_f64(0.56).unwrap())),
                    ("credit_score", Value::Number(Number::from(680))),
                ],
                false,
            ),
            row_values(
                &[
                    ("annual_income", Value::Number(Number::from(62000))),
                    ("debt_ratio", Value::Number(Number::from_f64(0.55).unwrap())),
                    ("credit_score", Value::Number(Number::from(680))),
                ],
                false,
            ),
            row_values(
                &[
                    ("annual_income", Value::Number(Number::from(48000))),
                    ("debt_ratio", Value::Number(Number::from_f64(0.61).unwrap())),
                    ("credit_score", Value::Number(Number::from(650))),
                ],
                false,
            ),
            row_values(
                &[
                    ("annual_income", Value::Number(Number::from(45000))),
                    ("debt_ratio", Value::Number(Number::from_f64(0.35).unwrap())),
                    ("credit_score", Value::Number(Number::from(650))),
                ],
                true,
            ),
            row_values(
                &[
                    ("annual_income", Value::Number(Number::from(72000))),
                    ("debt_ratio", Value::Number(Number::from_f64(0.31).unwrap())),
                    ("credit_score", Value::Number(Number::from(720))),
                ],
                true,
            ),
        ];
        let rules = vec![
            rule_from_candidate(
                0,
                &CandidateRule::new(
                    Expression::Comparison(ComparisonExpression {
                        feature: "annual_income".to_string(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::Number(Number::from(85000))),
                    }),
                    1,
                    0,
                ),
            ),
            rule_from_candidate(
                1,
                &CandidateRule::new(
                    Expression::Comparison(ComparisonExpression {
                        feature: "credit_score".to_string(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::Number(Number::from(680))),
                    }),
                    2,
                    0,
                ),
            ),
            rule_from_candidate(
                2,
                &CandidateRule::new(
                    Expression::Comparison(ComparisonExpression {
                        feature: "debt_ratio".to_string(),
                        op: ComparisonOperator::Gte,
                        value: ComparisonValue::Literal(Value::Number(
                            Number::from_f64(0.55).unwrap(),
                        )),
                    }),
                    3,
                    0,
                ),
            ),
        ];

        let pruned = prune_redundant_rules(&rows, rules);
        let rendered = serde_json::to_string(&pruned).unwrap();
        assert_eq!(pruned.len(), 1);
        assert!(rendered.contains("\"feature\":\"debt_ratio\""));
        assert!(!rendered.contains("\"feature\":\"annual_income\""));
        assert!(!rendered.contains("\"feature\":\"credit_score\""));
    }

    #[test]
    fn build_reuses_cached_output_when_rows_and_options_match() {
        let _guard = discovery_selection_env_lock()
            .lock()
            .expect("env lock should be available");
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(&csv_path, "flag,allowed\n0,allowed\n1,denied\n1,denied\n").unwrap();
        let output_dir = dir.path().join("output");
        let options = BuildOptions {
            output_dir: output_dir.clone(),
            gate_id: "cached_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            max_rules: None,
        };

        let first = build_pearl_from_csv(&csv_path, &options).unwrap();
        let second = build_pearl_from_csv(&csv_path, &options).unwrap();

        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(second.rules_discovered, first.rules_discovered);
        assert!(output_dir.join(".logicpearl-cache.json").exists());
    }

    #[test]
    fn dedupe_prefers_stronger_verification_for_same_rule() {
        let pipeline_rule = RuleDefinition {
            id: "rule_a".to_string(),
            kind: RuleKind::Predicate,
            bit: 5,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "flag".to_string(),
                op: ComparisonOperator::Gt,
                value: ComparisonValue::Literal(Value::Number(Number::from(0))),
            }),
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: Some(RuleVerificationStatus::PipelineUnverified),
        };
        let refined_rule = RuleDefinition {
            id: "rule_b".to_string(),
            kind: RuleKind::Predicate,
            bit: 9,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "flag".to_string(),
                op: ComparisonOperator::Gt,
                value: ComparisonValue::Literal(Value::Number(Number::from(0))),
            }),
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: Some(RuleVerificationStatus::RefinedUnverified),
        };

        let deduped = dedupe_rules_by_signature(vec![pipeline_rule, refined_rule]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(
            deduped[0].verification_status,
            Some(RuleVerificationStatus::RefinedUnverified)
        );
        assert_eq!(deduped[0].bit, 0);
        assert_eq!(deduped[0].id, "rule_000");
    }

    #[test]
    fn merge_applies_pinned_rule_layer() {
        let discovered = vec![RuleDefinition {
            id: "rule_000".to_string(),
            kind: RuleKind::Predicate,
            bit: 0,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "signal".to_string(),
                op: ComparisonOperator::Gt,
                value: ComparisonValue::Literal(Value::Number(Number::from(0))),
            }),
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: Some(RuleVerificationStatus::PipelineUnverified),
        }];
        let pinned = PinnedRuleSet {
            rule_set_version: "1.0".to_string(),
            rule_set_id: "pinned_rules".to_string(),
            rules: vec![RuleDefinition {
                id: "claims_r05".to_string(),
                kind: RuleKind::Predicate,
                bit: 99,
                deny_when: Expression::All {
                    all: vec![
                        Expression::Comparison(ComparisonExpression {
                            feature: "signal".to_string(),
                            op: ComparisonOperator::Gt,
                            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                        }),
                        Expression::Comparison(ComparisonExpression {
                            feature: "guard".to_string(),
                            op: ComparisonOperator::Gt,
                            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                        }),
                    ],
                },
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::RefinedUnverified),
            }],
        };

        let merged = merge_discovered_and_pinned_rules(discovered, &pinned);
        assert_eq!(merged.len(), 2);
        let rendered = serde_json::to_string(&merged).unwrap();
        assert!(rendered.contains("\"feature\":\"guard\""));
    }

    #[test]
    fn discover_reuses_cached_output_when_dataset_and_options_match() {
        let _guard = discovery_selection_env_lock()
            .lock()
            .expect("env lock should be available");
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("multi_target.csv");
        std::fs::write(
            &csv_path,
            "signal_a,signal_b,target_a,target_b\n0,0,allowed,allowed\n1,0,denied,allowed\n0,1,allowed,denied\n1,1,denied,denied\n",
        )
        .unwrap();
        let output_dir = dir.path().join("discovered");
        let options = DiscoverOptions {
            output_dir: output_dir.clone(),
            artifact_set_id: "multi_target_demo".to_string(),
            target_columns: vec!["target_a".to_string(), "target_b".to_string()],
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
        };

        let first = discover_from_csv(&csv_path, &options).unwrap();
        let second = discover_from_csv(&csv_path, &options).unwrap();

        assert!(!first.cache_hit);
        assert!(!first.artifacts.iter().any(|artifact| artifact.cache_hit));
        assert!(second.cache_hit);
        assert_eq!(second.cached_artifacts, 2);
        assert!(second.artifacts.iter().all(|artifact| artifact.cache_hit));
        assert!(output_dir.join(".logicpearl-cache.json").exists());
    }

    fn row(features: &[(&str, i64)], allowed: bool) -> DecisionTraceRow {
        DecisionTraceRow {
            features: features
                .iter()
                .map(|(name, value)| ((*name).to_string(), Value::Number(Number::from(*value))))
                .collect::<HashMap<_, _>>(),
            allowed,
        }
    }

    fn row_values(features: &[(&str, Value)], allowed: bool) -> DecisionTraceRow {
        DecisionTraceRow {
            features: features
                .iter()
                .map(|(name, value)| ((*name).to_string(), value.clone()))
                .collect::<HashMap<_, _>>(),
            allowed,
        }
    }

    #[test]
    fn build_discovers_ratio_interaction_feature_when_axis_rules_are_insufficient() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("ratio_gate");
        let rows = vec![
            row_values(
                &[("debt", Value::from(50.0)), ("income", Value::from(100.0))],
                false,
            ),
            row_values(
                &[("debt", Value::from(60.0)), ("income", Value::from(120.0))],
                false,
            ),
            row_values(
                &[("debt", Value::from(45.0)), ("income", Value::from(80.0))],
                false,
            ),
            row_values(
                &[("debt", Value::from(30.0)), ("income", Value::from(50.0))],
                false,
            ),
            row_values(
                &[("debt", Value::from(50.0)), ("income", Value::from(150.0))],
                true,
            ),
            row_values(
                &[("debt", Value::from(60.0)), ("income", Value::from(200.0))],
                true,
            ),
            row_values(
                &[("debt", Value::from(30.0)), ("income", Value::from(80.0))],
                true,
            ),
            row_values(
                &[("debt", Value::from(45.0)), ("income", Value::from(120.0))],
                true,
            ),
        ];
        let result = build_pearl_from_rows(
            &rows,
            "ratio_demo".to_string(),
            &BuildOptions {
                output_dir: output_dir.clone(),
                gate_id: "ratio_demo".to_string(),
                label_column: "allowed".to_string(),
                positive_label: None,
                negative_label: None,
                residual_pass: false,
                refine: false,
                pinned_rules: None,
                feature_dictionary: None,
                feature_governance: None,
                decision_mode: DiscoveryDecisionMode::Standard,
                max_rules: None,
            },
        )
        .unwrap();

        assert_eq!(result.training_parity, 1.0);
        let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
        let derived_feature = gate
            .input_schema
            .features
            .iter()
            .find(|feature| feature.id.contains("debt__over__income"))
            .expect("ratio feature should be emitted into the schema");
        assert!(derived_feature.derived.is_some());
        let rendered_rules = serde_json::to_string(&gate.rules).unwrap();
        assert!(rendered_rules.contains(&derived_feature.id));
    }
}
