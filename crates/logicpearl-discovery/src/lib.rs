use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, EvaluationConfig, Expression, FeatureDefinition, FeatureType,
    InputSchema, LogicPearlGateIr, Provenance, RuleDefinition, RuleKind, RuleVerificationStatus,
    VerificationConfig,
};
use logicpearl_runtime::evaluate_gate;
use serde::Serialize;
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub output_dir: PathBuf,
    pub gate_id: String,
    pub label_column: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DecisionTraceRow {
    pub features: HashMap<String, Value>,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildResult {
    pub source_csv: String,
    pub gate_id: String,
    pub rows: usize,
    pub label_column: String,
    pub rules_discovered: usize,
    pub selected_features: Vec<String>,
    pub training_parity: f64,
    pub output_files: OutputFiles,
}

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    pub output_dir: PathBuf,
    pub artifact_set_id: String,
    pub target_columns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactDescriptor {
    pub name: String,
    pub artifact: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactSet {
    pub artifact_set_version: String,
    pub artifact_set_id: String,
    pub features: Vec<String>,
    pub binary_targets: Vec<ArtifactDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoverResult {
    pub source_csv: String,
    pub artifact_set_id: String,
    pub rows: usize,
    pub features: Vec<String>,
    pub targets: Vec<String>,
    pub artifacts: Vec<BuildResult>,
    pub skipped_targets: Vec<SkippedTarget>,
    pub output_files: DiscoverOutputFiles,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedTarget {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoverOutputFiles {
    pub artifact_set: String,
    pub discover_report: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputFiles {
    pub pearl_ir: String,
}

#[derive(Debug, Clone)]
struct CandidateRule {
    feature: String,
    op: ComparisonOperator,
    value: Value,
    denied_coverage: usize,
    false_positives: usize,
}

pub fn build_pearl_from_csv(csv_path: &Path, options: &BuildOptions) -> Result<BuildResult> {
    let rows = load_decision_traces(csv_path, &options.label_column)?;
    build_pearl_from_rows(&rows, csv_path.display().to_string(), options)
}

pub fn discover_from_csv(csv_path: &Path, options: &DiscoverOptions) -> Result<DiscoverResult> {
    if options.target_columns.is_empty() {
        return Err(LogicPearlError::message(
            "discover requires at least one target column",
        ));
    }

    let mut reader = csv::Reader::from_path(csv_path)?;
    let headers = reader.headers()?.clone();
    for target in &options.target_columns {
        if !headers.iter().any(|header| header == target) {
            return Err(LogicPearlError::message(format!(
                "dataset is missing target column: {target:?}"
            )));
        }
    }

    let feature_columns: Vec<String> = headers
        .iter()
        .filter(|header| !options.target_columns.iter().any(|target| target == *header))
        .map(ToOwned::to_owned)
        .collect();
    if feature_columns.is_empty() {
        return Err(LogicPearlError::message(
            "discover needs at least one feature column after removing targets",
        ));
    }

    options.output_dir.mkdir_all()?;
    let artifacts_dir = options.output_dir.join("artifacts");
    artifacts_dir.mkdir_all()?;

    let mut per_target_rows: HashMap<String, Vec<DecisionTraceRow>> = options
        .target_columns
        .iter()
        .map(|target| (target.clone(), Vec::new()))
        .collect();

    for (index, record) in reader.records().enumerate() {
        let record = record?;
        let mut features = HashMap::new();
        let mut target_values = HashMap::new();

        for (header, value) in headers.iter().zip(record.iter()) {
            if options.target_columns.iter().any(|target| target == header) {
                target_values.insert(
                    header.to_string(),
                    parse_allowed_label(value, index + 2, header)?,
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
        let target_rows = per_target_rows
            .remove(target)
            .ok_or_else(|| LogicPearlError::message(format!("missing rows for target {target:?}")))?;
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
        artifacts,
        skipped_targets,
        output_files: DiscoverOutputFiles {
            artifact_set: artifact_set_path.display().to_string(),
            discover_report: options
                .output_dir
                .join("discover_report.json")
                .display()
                .to_string(),
        },
    };

    let discover_report_path = options.output_dir.join("discover_report.json");
    std::fs::write(
        &discover_report_path,
        serde_json::to_string_pretty(&discover)? + "\n",
    )?;

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

    let gate = build_gate(&rows, &options.gate_id)?;
    options.output_dir.mkdir_all()?;
    let pearl_ir_path = options.output_dir.join("pearl.ir.json");
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
        selected_features: sorted_feature_names(&rows),
        training_parity,
        output_files: OutputFiles {
            pearl_ir: pearl_ir_path.display().to_string(),
        },
    };

    let build_report_path = options.output_dir.join("build_report.json");
    std::fs::write(
        &build_report_path,
        serde_json::to_string_pretty(&build_report)? + "\n",
    )?;

    Ok(build_report)
}

pub fn load_decision_traces(csv_path: &Path, label_column: &str) -> Result<Vec<DecisionTraceRow>> {
    let mut reader = csv::Reader::from_path(csv_path)?;
    let headers = reader.headers()?.clone();
    if !headers.iter().any(|header| header == label_column) {
        return Err(LogicPearlError::message(format!(
            "decision trace CSV is missing required label column: {label_column:?}"
        )));
    }

    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let record = record?;
        let mut features = HashMap::new();
        let mut allowed = None;
        for (header, value) in headers.iter().zip(record.iter()) {
            if header == label_column {
                allowed = Some(parse_allowed_label(value, index + 2, label_column)?);
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
        rows.push(DecisionTraceRow {
            features,
            allowed: allowed.ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {} is missing label column {label_column:?}",
                    index + 2
                ))
            })?,
        });
    }
    Ok(rows)
}

fn build_gate(rows: &[DecisionTraceRow], gate_id: &str) -> Result<LogicPearlGateIr> {
    let feature_sample = rows[0].features.clone();
    let rules = discover_rules(rows)?;
    if rules.is_empty() {
        return Err(LogicPearlError::message(
            "no deny rules could be discovered from decision traces",
        ));
    }

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
            verification_summary: Some(HashMap::from([(
                "pipeline_unverified".to_string(),
                1_u64,
            )])),
        }),
        provenance: Some(Provenance {
            generator: Some("logicpearl.build".to_string()),
            generator_version: Some("0.1.0".to_string()),
            source_commit: None,
            created_at: None,
        }),
    })
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
        let candidate = best_candidate_rule(rows, &remaining_denied, &allowed_indices)
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

fn best_candidate_rule(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Option<CandidateRule> {
    let feature_names = sorted_feature_names(rows);
    let mut best: Option<CandidateRule> = None;

    for feature in feature_names {
        let values: Vec<&Value> = rows
            .iter()
            .filter_map(|row| row.features.get(&feature))
            .collect();
        if values.iter().all(|value| value.is_number()) {
            let unique_thresholds = numeric_thresholds(rows, denied_indices, &feature);
            for threshold in unique_thresholds {
                for op in [ComparisonOperator::Lte, ComparisonOperator::Eq, ComparisonOperator::Gt] {
                    let candidate = CandidateRule {
                        feature: feature.clone(),
                        op: op.clone(),
                        value: Value::Number(Number::from_f64(threshold).unwrap()),
                        denied_coverage: coverage_for(rows, denied_indices, &feature, &op, threshold),
                        false_positives: coverage_for(rows, allowed_indices, &feature, &op, threshold),
                    };
                    consider_candidate(&mut best, candidate);
                }
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
                    value: Value::String(text.clone()),
                    denied_coverage: string_coverage_for(rows, denied_indices, &feature, &text),
                    false_positives: string_coverage_for(rows, allowed_indices, &feature, &text),
                };
                consider_candidate(&mut best, candidate);
            }
        }
    }

    best
}

fn consider_candidate(best: &mut Option<CandidateRule>, candidate: CandidateRule) {
    if candidate.denied_coverage == 0 {
        return;
    }
    match best {
        None => *best = Some(candidate),
        Some(current) => {
            let candidate_net = candidate.denied_coverage as isize - candidate.false_positives as isize;
            let current_net = current.denied_coverage as isize - current.false_positives as isize;
            let better = match candidate_net.cmp(&current_net) {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => match candidate.false_positives.cmp(&current.false_positives) {
                    Ordering::Less => true,
                    Ordering::Greater => false,
                    Ordering::Equal => match candidate.denied_coverage.cmp(&current.denied_coverage) {
                        Ordering::Greater => true,
                        Ordering::Less => false,
                        Ordering::Equal => candidate.feature < current.feature,
                    },
                },
            };
            if better {
                *best = Some(candidate);
            }
        }
    }
}

fn numeric_thresholds(rows: &[DecisionTraceRow], denied_indices: &[usize], feature: &str) -> Vec<f64> {
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

fn coverage_for(
    rows: &[DecisionTraceRow],
    indices: &[usize],
    feature: &str,
    op: &ComparisonOperator,
    threshold: f64,
) -> usize {
    indices
        .iter()
        .filter(|index| {
            rows[**index]
                .features
                .get(feature)
                .and_then(Value::as_f64)
                .map(|value| match op {
                    ComparisonOperator::Lte => value <= threshold,
                    ComparisonOperator::Eq => (value - threshold).abs() < 1e-9,
                    ComparisonOperator::Gt => value > threshold,
                    _ => false,
                })
                .unwrap_or(false)
        })
        .count()
}

fn string_coverage_for(rows: &[DecisionTraceRow], indices: &[usize], feature: &str, expected: &str) -> usize {
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

fn matches_candidate(features: &HashMap<String, Value>, candidate: &CandidateRule) -> bool {
    let value = match features.get(&candidate.feature) {
        Some(value) => value,
        None => return false,
    };
    match (&candidate.op, value, &candidate.value) {
        (ComparisonOperator::Eq, Value::Number(left), Value::Number(right)) => {
            match (left.as_f64(), right.as_f64()) {
                (Some(left), Some(right)) => (left - right).abs() < 1e-9,
                _ => false,
            }
        }
        (ComparisonOperator::Eq, left, right) => left == right,
        (ComparisonOperator::Lte, Value::Number(left), Value::Number(right)) => {
            left.as_f64().unwrap_or_default() <= right.as_f64().unwrap_or_default()
        }
        (ComparisonOperator::Gt, Value::Number(left), Value::Number(right)) => {
            left.as_f64().unwrap_or_default() > right.as_f64().unwrap_or_default()
        }
        _ => false,
    }
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

fn parse_allowed_label(raw: &str, row_number: usize, label_column: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "allow" | "allowed" => Ok(true),
        "0" | "false" | "no" | "n" | "deny" | "denied" => Ok(false),
        _ => Err(LogicPearlError::message(format!(
            "row {row_number} has unsupported label value {raw:?} in column {label_column:?}; use allowed/denied or 1/0"
        ))),
    }
}

fn parse_scalar(raw: &str) -> Result<Value> {
    let value = raw.trim();
    let lowered = value.to_ascii_lowercase();
    if lowered == "true" {
        return Ok(Value::Bool(true));
    }
    if lowered == "false" {
        return Ok(Value::Bool(false));
    }
    if let Ok(parsed) = value.parse::<i64>() {
        return Ok(Value::Number(Number::from(parsed)));
    }
    if let Ok(parsed) = value.parse::<f64>() {
        return Ok(Value::Number(
            Number::from_f64(parsed)
                .ok_or_else(|| LogicPearlError::message("encountered non-finite float"))?,
        ));
    }
    Ok(Value::String(value.to_string()))
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
    use super::{build_pearl_from_csv, discover_from_csv, load_decision_traces, BuildOptions, DiscoverOptions};
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
            },
        )
        .unwrap();

        let pearl_ir = std::fs::read_to_string(output_dir.join("pearl.ir.json")).unwrap();
        assert!(pearl_ir.contains("\"feature\": \"signal_flag\""));
        assert!(!pearl_ir.contains("\"feature\": \"confidence\""));
        assert!(result.training_parity > 0.8);
    }
}
