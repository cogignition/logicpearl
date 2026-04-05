use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig, Expression,
    FeatureDefinition, FeatureType, InputSchema, LogicPearlGateIr, Provenance, RuleDefinition, RuleKind,
    RuleVerificationStatus, VerificationConfig,
};
use logicpearl_runtime::evaluate_gate;
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionCandidate, BooleanConjunctionSearchOptions,
    BooleanSearchExample,
};
use serde::Serialize;
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

mod canonicalize;
mod trace_loading;

use canonicalize::{canonicalize_rules, comparison_matches, expression_matches, prune_redundant_rules};
pub use trace_loading::{load_decision_traces, load_decision_traces_auto, load_decision_traces_with_labels};
use trace_loading::{infer_binary_label_domain, parse_allowed_label, parse_scalar, BinaryLabelDomain};

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
    pub cache_hit: bool,
    pub output_files: OutputFiles,
}

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    pub output_dir: PathBuf,
    pub artifact_set_id: String,
    pub target_columns: Vec<String>,
    pub residual_pass: bool,
    pub refine: bool,
    pub pinned_rules: Option<PathBuf>,
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
    feature: String,
    op: ComparisonOperator,
    value: ComparisonValue,
    denied_coverage: usize,
    false_positives: usize,
}

impl CandidateRule {
    fn signature(&self) -> String {
        match &self.value {
            ComparisonValue::Literal(value) => {
                format!("{}{}{}", self.feature, self.op.as_str(), value)
            }
            ComparisonValue::FeatureRef { feature_ref } => {
                format!("{}{}@{}", self.feature, self.op.as_str(), feature_ref)
            }
        }
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
    max_rules: 4,
};

const DEFAULT_UNIQUE_COVERAGE_REFINEMENT_OPTIONS: UniqueCoverageRefinementOptions =
    UniqueCoverageRefinementOptions {
        min_unique_false_positives: 1,
        min_true_positive_retention: 0.5,
    };

fn default_rule_set_version() -> String {
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

    Ok(CacheManifest {
        cache_version: "1".to_string(),
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
    }

    let pinned_rules_fingerprint = options
        .pinned_rules
        .as_ref()
        .map(|path| fingerprint_file(path))
        .transpose()?;

    Ok(CacheManifest {
        cache_version: "1".to_string(),
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
        })?,
    })
}

fn fingerprint_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    Ok(format!("{:016x}", hasher.finish()))
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
    };
    build_pearl_from_rows(&loaded.rows, csv_path.display().to_string(), &resolved_options)
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
    if artifact_set_path.exists() && discover_report_path.exists() {
        if load_cache_manifest(&discover_cache_path)?.as_ref() == Some(&discover_manifest) {
            let mut cached: DiscoverResult =
                serde_json::from_str(&std::fs::read_to_string(&discover_report_path)?)?;
            cached.cache_hit = true;
            for artifact in &mut cached.artifacts {
                artifact.cache_hit = true;
            }
            cached.cached_artifacts = cached.artifacts.len();
            return Ok(cached);
        }
    }

    let mut reader = csv::Reader::from_path(csv_path)?;
    let headers = reader.headers()?.clone();
    let records = reader
        .records()
        .collect::<std::result::Result<Vec<_>, csv::Error>>()?;
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
            infer_binary_label_domain(&records, &headers, target, None, None)
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

        for (header, value) in headers.iter().zip(record.iter()) {
            if options.target_columns.iter().any(|target| target == header) {
                let domain = target_domains.get(header).ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "missing inferred binary domain for target column {header:?}"
                    ))
                })?;
                target_values.insert(
                    header.to_string(),
                    parse_allowed_label(value, index + 2, header, domain)?,
                );
                continue;
            }
            if value.trim().is_empty() {
                return Err(LogicPearlError::message(format!(
                    "row {} has an empty value for feature {header:?}",
                    index + 2
                )));
            }
            features.insert(header.to_string(), parse_scalar(value)?);
        }

        for target in &options.target_columns {
            let allowed = *target_values.get(target).ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {} is missing target column {target:?}",
                    index + 2
                ))
            })?;
            per_target_rows
                .get_mut(target)
                .expect("target initialized")
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
    if rows.is_empty() {
        return Err(LogicPearlError::message("decision trace CSV is empty"));
    }

    options.output_dir.mkdir_all()?;
    let build_manifest = build_cache_manifest(rows, &source_name, options)?;
    let build_cache_path = cache_manifest_path(&options.output_dir);
    let build_report_path = options.output_dir.join("build_report.json");
    let pearl_ir_path = options.output_dir.join("pearl.ir.json");
    if pearl_ir_path.exists() && build_report_path.exists() {
        if load_cache_manifest(&build_cache_path)?.as_ref() == Some(&build_manifest) {
            let mut cached: BuildResult =
                serde_json::from_str(&std::fs::read_to_string(&build_report_path)?)?;
            cached.cache_hit = true;
            return Ok(cached);
        }
    }

    let residual_options = options
        .residual_pass
        .then_some(DEFAULT_RESIDUAL_PASS_OPTIONS.clone());
    let refinement_options = options
        .refine
        .then_some(DEFAULT_UNIQUE_COVERAGE_REFINEMENT_OPTIONS.clone());
    let pinned_rules = options
        .pinned_rules
        .as_ref()
        .map(|path| load_pinned_rule_set(path))
        .transpose()?;
    let (gate, residual_rules_discovered, refined_rules_applied, pinned_rules_applied) =
        build_gate(
            &rows,
            &options.gate_id,
            residual_options.as_ref(),
            refinement_options.as_ref(),
            pinned_rules.as_ref(),
        )?;
    gate.write_pretty(&pearl_ir_path)?;

    let mut correct = 0;
    for row in rows {
        let bitmask = evaluate_gate(&gate, &row.features)?;
        let allowed = bitmask == 0;
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
        selected_features: sorted_feature_names(&rows),
        training_parity,
        cache_hit: false,
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
        },
    };

    std::fs::write(
        &build_report_path,
        serde_json::to_string_pretty(&build_report)? + "\n",
    )?;
    write_cache_manifest(&build_cache_path, &build_manifest)?;

    Ok(build_report)
}

fn build_gate(
    rows: &[DecisionTraceRow],
    gate_id: &str,
    residual_options: Option<&ResidualPassOptions>,
    refinement_options: Option<&UniqueCoverageRefinementOptions>,
    pinned_rules: Option<&PinnedRuleSet>,
) -> Result<(LogicPearlGateIr, usize, usize, usize)> {
    let mut rules = discover_rules(rows)?;
    let mut residual_rules_discovered = 0usize;
    if let Some(options) = residual_options {
        let first_pass_gate = gate_from_rules(rows, gate_id, rules.clone())?;
        let residual_rules = discover_residual_rules(rows, &first_pass_gate, options)?;
        residual_rules_discovered = residual_rules.len();
        rules.extend(residual_rules);
    }
    let mut refined_rules_applied = 0usize;
    if let Some(options) = refinement_options {
        let (refined_rules, applied) = refine_rules_unique_coverage(rows, &rules, options)?;
        rules = refined_rules;
        refined_rules_applied = applied;
    }
    let mut pinned_rules_applied = 0usize;
    if let Some(pinned_rules) = pinned_rules {
        pinned_rules_applied = pinned_rules.rules.len();
        rules = merge_discovered_and_pinned_rules(rules, pinned_rules);
    } else {
        rules = dedupe_rules_by_signature(rules);
    }
    rules = canonicalize_rules(rules);
    rules = dedupe_rules_by_signature(rules);
    rules = prune_redundant_rules(rows, rules);
    if rules.is_empty() {
        return Err(LogicPearlError::message(
            "no deny rules could be discovered from decision traces",
        ));
    }

    Ok((
        gate_from_rules(rows, gate_id, rules)?,
        residual_rules_discovered,
        refined_rules_applied,
        pinned_rules_applied,
    ))
}

fn gate_from_rules(
    rows: &[DecisionTraceRow],
    gate_id: &str,
    rules: Vec<RuleDefinition>,
) -> Result<LogicPearlGateIr> {
    let feature_sample = rows[0].features.clone();
    let verification_summary = rule_verification_summary(&rules);
    Ok(LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: gate_id.to_string(),
        gate_type: "bitmask_gate".to_string(),
        input_schema: InputSchema {
            features: sorted_feature_names(rows)
                .into_iter()
                .map(|feature| FeatureDefinition {
                    id: feature.clone(),
                    feature_type: infer_feature_type(feature_sample.get(&feature).unwrap()),
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                })
                .collect(),
        },
        rules,
        evaluation: EvaluationConfig {
            combine: "bitwise_or".to_string(),
            allow_when_bitmask: 0,
        },
        verification: Some(VerificationConfig {
            domain_constraints: None,
            correctness_scope: Some(format!(
                "training parity against {} decision traces",
                rows.len()
            )),
            verification_summary: Some(verification_summary),
        }),
        provenance: Some(Provenance {
            generator: Some("logicpearl.build".to_string()),
            generator_version: Some("0.1.0".to_string()),
            source_commit: None,
            created_at: None,
        }),
    })
}

fn rule_verification_summary(rules: &[RuleDefinition]) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for rule in rules {
        let key = match rule
            .verification_status
            .as_ref()
            .unwrap_or(&RuleVerificationStatus::PipelineUnverified)
        {
            RuleVerificationStatus::Z3Verified => "z3_verified",
            RuleVerificationStatus::PipelineUnverified => "pipeline_unverified",
            RuleVerificationStatus::HeuristicUnverified => "heuristic_unverified",
            RuleVerificationStatus::RefinedUnverified => "refined_unverified",
        };
        *counts.entry(key.to_string()).or_insert(0) += 1;
    }
    counts
}

pub fn load_pinned_rule_set(path: &Path) -> Result<PinnedRuleSet> {
    let payload = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&payload)?)
}

pub fn merge_discovered_and_pinned_rules(
    discovered: Vec<RuleDefinition>,
    pinned: &PinnedRuleSet,
) -> Vec<RuleDefinition> {
    let mut merged = discovered;
    merged.extend(pinned.rules.clone());
    dedupe_rules_by_signature(merged)
}

pub fn dedupe_rules_by_signature(rules: Vec<RuleDefinition>) -> Vec<RuleDefinition> {
    let mut by_signature: BTreeMap<String, RuleDefinition> = BTreeMap::new();
    for rule in rules {
        let signature = rule_signature(&rule);
        match by_signature.get(&signature) {
            None => {
                by_signature.insert(signature, rule);
            }
            Some(existing) => {
                if prefer_rule(&rule, existing) == Ordering::Greater {
                    by_signature.insert(signature, rule);
                }
            }
        }
    }

    by_signature
        .into_values()
        .enumerate()
        .map(|(index, mut rule)| {
            rule.bit = index as u32;
            rule.id = format!("rule_{index:03}");
            rule
        })
        .collect()
}

fn prefer_rule(left: &RuleDefinition, right: &RuleDefinition) -> Ordering {
    verification_rank(left)
        .cmp(&verification_rank(right))
        .then_with(|| {
            expression_complexity(&right.deny_when).cmp(&expression_complexity(&left.deny_when))
        })
}

fn verification_rank(rule: &RuleDefinition) -> i32 {
    match rule
        .verification_status
        .as_ref()
        .unwrap_or(&RuleVerificationStatus::PipelineUnverified)
    {
        RuleVerificationStatus::Z3Verified => 4,
        RuleVerificationStatus::RefinedUnverified => 3,
        RuleVerificationStatus::PipelineUnverified => 2,
        RuleVerificationStatus::HeuristicUnverified => 1,
    }
}

fn expression_complexity(expression: &Expression) -> usize {
    match expression {
        Expression::Comparison(_) => 1,
        Expression::All { all } => all.iter().map(expression_complexity).sum(),
        Expression::Any { any } => any.iter().map(expression_complexity).sum(),
        Expression::Not { expr } => expression_complexity(expr),
    }
}

fn rule_signature(rule: &RuleDefinition) -> String {
    let mut normalized = rule.clone();
    normalized.id = String::new();
    normalized.bit = 0;
    normalized.verification_status = None;
    serde_json::to_string(&normalized).expect("rule signature serialization")
}

fn verification_status(rule: &RuleDefinition) -> RuleVerificationStatus {
    rule.verification_status
        .clone()
        .unwrap_or(RuleVerificationStatus::PipelineUnverified)
}

fn verification_status_rank(status: &RuleVerificationStatus) -> i32 {
    match status {
        RuleVerificationStatus::Z3Verified => 4,
        RuleVerificationStatus::RefinedUnverified => 3,
        RuleVerificationStatus::PipelineUnverified => 2,
        RuleVerificationStatus::HeuristicUnverified => 1,
    }
}

fn discover_rules(rows: &[DecisionTraceRow]) -> Result<Vec<RuleDefinition>> {
    let mut remaining_denied: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (!row.allowed).then_some(index))
        .collect();
    let allowed_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| row.allowed.then_some(index))
        .collect();

    let mut discovered = Vec::new();
    while !remaining_denied.is_empty() {
        let candidate = select_candidate_rule(rows, &remaining_denied, &allowed_indices)
            .ok_or_else(|| LogicPearlError::message("no recoverable deny rule found"))?;
        if candidate.denied_coverage == 0 {
            break;
        }

        let bit = discovered.len() as u32;
        let has_false_positives = candidate.false_positives > 0;
        discovered.push(rule_from_candidate(bit, &candidate));
        remaining_denied.retain(|index| !matches_candidate(&rows[*index].features, &candidate));
        if has_false_positives {
            break;
        }
    }

    Ok(discovered)
}

const LOOKAHEAD_FRONTIER_LIMIT: usize = 12;

#[derive(Debug, Clone, PartialEq)]
struct CandidatePlanScore {
    training_parity: f64,
    total_false_positives: usize,
    uncovered_denied: usize,
    rule_count: usize,
}

fn select_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Option<CandidateRule> {
    let mut candidates = candidate_rules(rows, denied_indices, allowed_indices);
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(compare_candidate_priority);
    candidates.truncate(LOOKAHEAD_FRONTIER_LIMIT);

    let mut best: Option<(CandidateRule, CandidatePlanScore)> = None;
    for candidate in candidates {
        let score = simulate_candidate_plan(rows, denied_indices, allowed_indices, &candidate);
        let better = match &best {
            None => true,
            Some((current_candidate, current_score)) => {
                compare_candidate_plan(&candidate, &score, current_candidate, current_score)
                    == Ordering::Less
            }
        };
        if better {
            best = Some((candidate, score));
        }
    }
    best.map(|(candidate, _score)| candidate)
}

fn simulate_candidate_plan(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    first_candidate: &CandidateRule,
) -> CandidatePlanScore {
    let mut rules = vec![first_candidate.clone()];
    let mut remaining_denied: Vec<usize> = denied_indices
        .iter()
        .copied()
        .filter(|index| !matches_candidate(&rows[*index].features, first_candidate))
        .collect();

    if first_candidate.false_positives == 0 {
        while !remaining_denied.is_empty() {
            let Some(next) =
                best_immediate_candidate_rule(rows, &remaining_denied, allowed_indices)
            else {
                break;
            };
            if next.denied_coverage == 0 {
                break;
            }
            remaining_denied.retain(|index| !matches_candidate(&rows[*index].features, &next));
            let has_false_positives = next.false_positives > 0;
            rules.push(next);
            if has_false_positives {
                break;
            }
        }
    }

    let total_false_positives = allowed_indices
        .iter()
        .filter(|index| rules.iter().any(|rule| matches_candidate(&rows[**index].features, rule)))
        .count();
    let correct = rows
        .iter()
        .filter(|row| {
            let predicted_deny = rules.iter().any(|rule| matches_candidate(&row.features, rule));
            predicted_deny != row.allowed
        })
        .count();

    CandidatePlanScore {
        training_parity: correct as f64 / rows.len() as f64,
        total_false_positives,
        uncovered_denied: remaining_denied.len(),
        rule_count: rules.len(),
    }
}

fn compare_candidate_plan(
    candidate: &CandidateRule,
    score: &CandidatePlanScore,
    current_candidate: &CandidateRule,
    current_score: &CandidatePlanScore,
) -> Ordering {
    current_score
        .training_parity
        .total_cmp(&score.training_parity)
        .then_with(|| score.total_false_positives.cmp(&current_score.total_false_positives))
        .then_with(|| score.uncovered_denied.cmp(&current_score.uncovered_denied))
        .then_with(|| score.rule_count.cmp(&current_score.rule_count))
        .then_with(|| compare_candidate_priority(candidate, current_candidate))
}

fn discover_residual_rules(
    rows: &[DecisionTraceRow],
    gate: &LogicPearlGateIr,
    options: &ResidualPassOptions,
) -> Result<Vec<RuleDefinition>> {
    let binary_features = infer_binary_feature_names(rows);
    if binary_features.is_empty() {
        return Ok(Vec::new());
    }

    let mut examples = Vec::new();
    for row in rows {
        let predicted_deny = evaluate_gate(gate, &row.features)? != 0;
        if !row.allowed && !predicted_deny {
            examples.push(BooleanSearchExample {
                features: boolean_feature_map(&row.features, &binary_features),
                positive: true,
            });
        } else if row.allowed {
            examples.push(BooleanSearchExample {
                features: boolean_feature_map(&row.features, &binary_features),
                positive: false,
            });
        }
    }

    if examples.iter().filter(|example| example.positive).count() < options.min_positive_support {
        return Ok(Vec::new());
    }

    let candidates = synthesize_boolean_conjunctions(
        &examples,
        &BooleanConjunctionSearchOptions {
            max_conditions: options.max_conditions,
            min_positive_support: options.min_positive_support,
            max_negative_hits: options.max_negative_hits,
            max_rules: options.max_rules,
        },
    )?;

    Ok(candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            residual_rule_from_candidate(gate.rules.len() as u32 + index as u32, candidate)
        })
        .collect())
}

fn refine_rules_unique_coverage(
    rows: &[DecisionTraceRow],
    rules: &[RuleDefinition],
    options: &UniqueCoverageRefinementOptions,
) -> Result<(Vec<RuleDefinition>, usize)> {
    let binary_features = infer_binary_feature_names(rows);
    if binary_features.is_empty() || rules.is_empty() {
        return Ok((rules.to_vec(), 0));
    }

    let mut refined = Vec::with_capacity(rules.len());
    let mut refined_rules_applied = 0usize;

    for (rule_index, rule) in rules.iter().enumerate() {
        let mut unique_positive_rows = Vec::new();
        let mut unique_negative_rows = Vec::new();

        for row in rows {
            if !expression_matches(&rule.deny_when, &row.features) {
                continue;
            }
            let matched_by_other = rules.iter().enumerate().any(|(other_index, other)| {
                other_index != rule_index && expression_matches(&other.deny_when, &row.features)
            });
            if matched_by_other {
                continue;
            }
            if row.allowed {
                unique_negative_rows.push(row);
            } else {
                unique_positive_rows.push(row);
            }
        }

        if unique_negative_rows.len() < options.min_unique_false_positives
            || unique_positive_rows.is_empty()
        {
            refined.push(rule.clone());
            continue;
        }

        let current_negative_hits = unique_negative_rows.len();
        let current_positive_hits = unique_positive_rows.len();
        let mut best_addition: Option<(ComparisonExpression, usize, usize)> = None;

        for feature in &binary_features {
            if rule_contains_feature(rule, feature) {
                continue;
            }
            for op in [ComparisonOperator::Gt, ComparisonOperator::Lte] {
                let candidate = ComparisonExpression {
                    feature: feature.clone(),
                    op: op.clone(),
                    value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                };
                let positive_hits = unique_positive_rows
                    .iter()
                    .filter(|row| comparison_matches(&candidate, &row.features))
                    .count();
                if positive_hits == 0 {
                    continue;
                }
                let retained = positive_hits as f64 / current_positive_hits as f64;
                if retained < options.min_true_positive_retention {
                    continue;
                }
                let negative_hits = unique_negative_rows
                    .iter()
                    .filter(|row| comparison_matches(&candidate, &row.features))
                    .count();
                if negative_hits >= current_negative_hits {
                    continue;
                }

                let better = match &best_addition {
                    None => true,
                    Some((_best, best_positive_hits, best_negative_hits)) => {
                        let candidate_reduction =
                            current_negative_hits.saturating_sub(negative_hits);
                        let best_reduction =
                            current_negative_hits.saturating_sub(*best_negative_hits);
                        match candidate_reduction.cmp(&best_reduction) {
                            Ordering::Greater => true,
                            Ordering::Less => false,
                            Ordering::Equal => match positive_hits.cmp(best_positive_hits) {
                                Ordering::Greater => true,
                                Ordering::Less => false,
                                Ordering::Equal => negative_hits < *best_negative_hits,
                            },
                        }
                    }
                };
                if better {
                    best_addition = Some((candidate, positive_hits, negative_hits));
                }
            }
        }

        if let Some((addition, _positive_hits, _negative_hits)) = best_addition {
            refined.push(rule_with_added_condition(rule, addition));
            refined_rules_applied += 1;
        } else {
            refined.push(rule.clone());
        }
    }

    Ok((refined, refined_rules_applied))
}

fn candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Vec<CandidateRule> {
    let feature_names = sorted_feature_names(rows);
    let numeric_features = numeric_feature_names(rows);
    let mut candidates = Vec::new();

    for feature in feature_names {
        let values: Vec<&Value> = rows
            .iter()
            .filter_map(|row| row.features.get(&feature))
            .collect();
        if values.iter().all(|value| value.is_number()) {
            let unique_thresholds = numeric_thresholds(rows, denied_indices, &feature);
            for threshold in unique_thresholds {
                for op in [
                    ComparisonOperator::Lt,
                    ComparisonOperator::Lte,
                    ComparisonOperator::Eq,
                    ComparisonOperator::Gte,
                    ComparisonOperator::Gt,
                ] {
                    let candidate = CandidateRule {
                        feature: feature.clone(),
                        op: op.clone(),
                        value: ComparisonValue::Literal(
                            Value::Number(Number::from_f64(threshold).unwrap()),
                        ),
                        denied_coverage: 0,
                        false_positives: 0,
                    };
                    let candidate = CandidateRule {
                        denied_coverage: candidate_coverage(rows, denied_indices, &candidate),
                        false_positives: candidate_coverage(rows, allowed_indices, &candidate),
                        ..candidate
                    };
                    candidates.push(candidate);
                }
            }
        } else if values.iter().all(|value| value.is_boolean()) {
            let unique_values: BTreeSet<bool> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(Value::as_bool)
                .collect();
            for boolean in unique_values {
                let candidate = CandidateRule {
                    feature: feature.clone(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Bool(boolean)),
                    denied_coverage: candidate_coverage(
                        rows,
                        denied_indices,
                        &CandidateRule {
                            feature: feature.clone(),
                            op: ComparisonOperator::Eq,
                            value: ComparisonValue::Literal(Value::Bool(boolean)),
                            denied_coverage: 0,
                            false_positives: 0,
                        },
                    ),
                    false_positives: candidate_coverage(
                        rows,
                        allowed_indices,
                        &CandidateRule {
                            feature: feature.clone(),
                            op: ComparisonOperator::Eq,
                            value: ComparisonValue::Literal(Value::Bool(boolean)),
                            denied_coverage: 0,
                            false_positives: 0,
                        },
                    ),
                };
                candidates.push(candidate);
            }
        } else {
            let unique_values: BTreeSet<String> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect();
            for text in unique_values {
                let candidate = CandidateRule {
                    feature: feature.clone(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String(text.clone())),
                    denied_coverage: string_coverage_for(rows, denied_indices, &feature, &text),
                    false_positives: string_coverage_for(rows, allowed_indices, &feature, &text),
                };
                candidates.push(candidate);
            }
        }
    }

    for left in &numeric_features {
        for right in &numeric_features {
            if left == right {
                continue;
            }
            for op in [
                ComparisonOperator::Lt,
                ComparisonOperator::Lte,
                ComparisonOperator::Gt,
                ComparisonOperator::Gte,
                ComparisonOperator::Eq,
                ComparisonOperator::Ne,
            ] {
                let candidate = CandidateRule {
                    feature: left.clone(),
                    op,
                    value: ComparisonValue::FeatureRef {
                        feature_ref: right.clone(),
                    },
                    denied_coverage: 0,
                    false_positives: 0,
                };
                let candidate = CandidateRule {
                    denied_coverage: candidate_coverage(rows, denied_indices, &candidate),
                    false_positives: candidate_coverage(rows, allowed_indices, &candidate),
                    ..candidate
                };
                candidates.push(candidate);
            }
        }
    }

    candidates.retain(|candidate| candidate.denied_coverage > 0);
    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    candidates
}

fn best_immediate_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Option<CandidateRule> {
    candidate_rules(rows, denied_indices, allowed_indices)
        .into_iter()
        .next()
}

fn compare_candidate_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
    let left_net = left.denied_coverage as isize - left.false_positives as isize;
    let right_net = right.denied_coverage as isize - right.false_positives as isize;
    right_net
        .cmp(&left_net)
        .then_with(|| left.false_positives.cmp(&right.false_positives))
        .then_with(|| right.denied_coverage.cmp(&left.denied_coverage))
        .then_with(|| candidate_complexity_penalty(left).cmp(&candidate_complexity_penalty(right)))
        .then_with(|| {
            candidate_memorization_penalty(left).cmp(&candidate_memorization_penalty(right))
        })
        .then_with(|| left.signature().cmp(&right.signature()))
}

fn candidate_complexity_penalty(candidate: &CandidateRule) -> usize {
    match candidate.value {
        ComparisonValue::FeatureRef { .. } => 1,
        ComparisonValue::Literal(_) => 0,
    }
}

fn candidate_memorization_penalty(candidate: &CandidateRule) -> usize {
    if candidate.op == ComparisonOperator::Eq
        && candidate
            .value
            .literal()
            .and_then(Value::as_f64)
            .is_some()
    {
        1_000_000usize.saturating_sub(candidate.denied_coverage)
    } else {
        0
    }
}

fn numeric_thresholds(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    feature: &str,
) -> Vec<f64> {
    let mut thresholds: BTreeSet<i64> = BTreeSet::new();
    for index in denied_indices {
        if let Some(value) = rows[*index].features.get(feature).and_then(Value::as_f64) {
            thresholds.insert((value * 1000.0).round() as i64);
        }
    }
    thresholds
        .into_iter()
        .map(|scaled| scaled as f64 / 1000.0)
        .collect()
}

fn candidate_coverage(rows: &[DecisionTraceRow], indices: &[usize], candidate: &CandidateRule) -> usize {
    indices
        .iter()
        .filter(|index| matches_candidate(&rows[**index].features, candidate))
        .count()
}

fn string_coverage_for(
    rows: &[DecisionTraceRow],
    indices: &[usize],
    feature: &str,
    expected: &str,
) -> usize {
    indices
        .iter()
        .filter(|index| {
            rows[**index]
                .features
                .get(feature)
                .and_then(Value::as_str)
                .map(|value| value == expected)
                .unwrap_or(false)
        })
        .count()
}

fn rule_from_candidate(bit: u32, candidate: &CandidateRule) -> RuleDefinition {
    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: candidate.feature.clone(),
            op: candidate.op.clone(),
            value: candidate.value.clone(),
        }),
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: Some(RuleVerificationStatus::PipelineUnverified),
    }
}

fn residual_rule_from_candidate(
    bit: u32,
    candidate: BooleanConjunctionCandidate,
) -> RuleDefinition {
    let deny_when = if candidate.required_true_features.len() == 1 {
        Expression::Comparison(ComparisonExpression {
            feature: candidate.required_true_features[0].clone(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
        })
    } else {
        Expression::All {
            all: candidate
                .required_true_features
                .iter()
                .map(|feature| {
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Gt,
                        value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    })
                })
                .collect(),
        }
    };

    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: Some(RuleVerificationStatus::RefinedUnverified),
    }
}

fn matches_candidate(features: &HashMap<String, Value>, candidate: &CandidateRule) -> bool {
    comparison_matches(
        &ComparisonExpression {
            feature: candidate.feature.clone(),
            op: candidate.op.clone(),
            value: candidate.value.clone(),
        },
        features,
    )
}

fn rule_contains_feature(rule: &RuleDefinition, feature: &str) -> bool {
    expression_features(&rule.deny_when)
        .iter()
        .any(|existing| existing == feature)
}

fn expression_features(expression: &Expression) -> Vec<String> {
    match expression {
        Expression::Comparison(comparison) => {
            let mut features = vec![comparison.feature.clone()];
            if let Some(feature_ref) = comparison.value.feature_ref() {
                features.push(feature_ref.to_string());
            }
            features
        }
        Expression::All { all } => all.iter().flat_map(expression_features).collect(),
        Expression::Any { any } => any.iter().flat_map(expression_features).collect(),
        Expression::Not { expr } => expression_features(expr),
    }
}

fn numeric_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    sorted_feature_names(rows)
        .into_iter()
        .filter(|feature| {
            rows.iter()
                .filter_map(|row| row.features.get(feature))
                .all(Value::is_number)
        })
        .collect()
}

fn rule_with_added_condition(
    rule: &RuleDefinition,
    addition: ComparisonExpression,
) -> RuleDefinition {
    let deny_when = match &rule.deny_when {
        Expression::Comparison(existing) => Expression::All {
            all: vec![
                Expression::Comparison(existing.clone()),
                Expression::Comparison(addition),
            ],
        },
        Expression::All { all } => {
            let mut next = all.clone();
            next.push(Expression::Comparison(addition));
            Expression::All { all: next }
        }
        _ => rule.deny_when.clone(),
    };

    RuleDefinition {
        id: rule.id.clone(),
        kind: rule.kind.clone(),
        bit: rule.bit,
        deny_when,
        label: rule.label.clone(),
        message: rule.message.clone(),
        severity: rule.severity.clone(),
        counterfactual_hint: rule.counterfactual_hint.clone(),
        verification_status: Some(RuleVerificationStatus::RefinedUnverified),
    }
}

fn infer_binary_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| {
            let mut names: Vec<String> = row
                .features
                .keys()
                .filter(|feature| {
                    rows.iter()
                        .all(|row| is_binary_value(row.features.get(*feature)))
                })
                .cloned()
                .collect();
            names.sort();
            names
        })
        .unwrap_or_default()
}

fn is_binary_value(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(_)) => true,
        Some(Value::Number(number)) => number
            .as_f64()
            .map(|value| (value - 0.0).abs() < 1e-9 || (value - 1.0).abs() < 1e-9)
            .unwrap_or(false),
        _ => false,
    }
}

fn boolean_feature_map(
    features: &HashMap<String, Value>,
    binary_features: &[String],
) -> BTreeMap<String, bool> {
    binary_features
        .iter()
        .map(|feature| {
            let value = match features.get(feature) {
                Some(Value::Bool(value)) => *value,
                Some(Value::Number(number)) => number.as_f64().unwrap_or_default() > 0.5,
                _ => false,
            };
            (feature.clone(), value)
        })
        .collect()
}

fn sorted_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| {
            let mut keys: Vec<String> = row.features.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default()
}

fn infer_feature_type(value: &Value) -> FeatureType {
    if value.is_boolean() {
        FeatureType::Bool
    } else if value.as_i64().is_some() {
        FeatureType::Int
    } else if value.as_f64().is_some() {
        FeatureType::Float
    } else {
        FeatureType::String
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
        build_pearl_from_csv, canonicalize_rules, dedupe_rules_by_signature, discover_from_csv,
        discover_residual_rules, gate_from_rules, load_decision_traces, load_decision_traces_auto,
        merge_discovered_and_pinned_rules, prune_redundant_rules, rule_from_candidate,
        BuildOptions, CandidateRule, ComparisonOperator, DecisionTraceRow, DiscoverOptions,
        PinnedRuleSet, ResidualPassOptions,
    };
    use logicpearl_ir::{
        ComparisonExpression, ComparisonValue, Expression, LogicPearlGateIr, RuleDefinition, RuleKind,
        RuleVerificationStatus,
    };
    use serde_json::{Number, Value};
    use std::collections::HashMap;
    use std::path::PathBuf;

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
    fn load_decision_traces_requires_explicit_mapping_for_unknown_binary_labels() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(&csv_path, "score,status\n1,alpha\n0,beta\n").unwrap();

        let err = load_decision_traces_auto(&csv_path, Some("status"), None, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("pass --positive-label or --negative-label explicitly"));

        let loaded =
            load_decision_traces_auto(&csv_path, Some("status"), Some("alpha"), None).unwrap();
        assert!(loaded.rows[0].allowed);
        assert!(!loaded.rows[1].allowed);
    }

    #[test]
    fn load_decision_traces_auto_rejects_ambiguous_binary_columns() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("decision_traces.csv");
        std::fs::write(
            &csv_path,
            "is_member,is_urgent\n1,0\n0,1\n",
        )
        .unwrap();

        let err = load_decision_traces_auto(&csv_path, None, None, None).unwrap_err();
        assert!(err.to_string().contains("multiple possible binary label columns"));
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
            },
        )
        .unwrap();

        assert_eq!(result.rows, 8);
        assert_eq!(result.rules_discovered, 1);
        assert_eq!(result.training_parity, 1.0);
        assert!(output_dir.join("pearl.ir.json").exists());
        assert!(output_dir.join("build_report.json").exists());
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
            },
        )
        .unwrap();

        let pearl_ir = std::fs::read_to_string(output_dir.join("pearl.ir.json")).unwrap();
        assert!(pearl_ir.contains("signal_flag"));
        assert!(result.training_parity > 0.8);
    }

    #[test]
    fn build_residual_pass_recovers_missed_boolean_slice() {
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
            "residual_gate",
            vec![rule_from_candidate(
                0,
                &CandidateRule {
                    feature: "seed".to_string(),
                    op: ComparisonOperator::Gt,
                    value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    denied_coverage: 1,
                    false_positives: 0,
                },
            )],
        )
        .unwrap();

        let residual_rules = discover_residual_rules(
            &rows,
            &first_pass_gate,
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
                &CandidateRule {
                    feature: "annual_income".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Number(Number::from(85000))),
                    denied_coverage: 1,
                    false_positives: 0,
                },
            ),
            rule_from_candidate(
                1,
                &CandidateRule {
                    feature: "credit_score".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Number(Number::from(680))),
                    denied_coverage: 2,
                    false_positives: 0,
                },
            ),
            rule_from_candidate(
                2,
                &CandidateRule {
                    feature: "debt_ratio".to_string(),
                    op: ComparisonOperator::Gte,
                    value: ComparisonValue::Literal(
                        Value::Number(Number::from_f64(0.55).unwrap()),
                    ),
                    denied_coverage: 3,
                    false_positives: 0,
                },
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
}
