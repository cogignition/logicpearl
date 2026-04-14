// SPDX-License-Identifier: MIT
use super::ObservedBenchmarkCase;
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProjectionConfig {
    #[serde(default)]
    pub feature_columns: Vec<String>,
    #[serde(default)]
    pub binary_targets: Vec<BinaryTargetProjection>,
    #[serde(default = "default_true")]
    pub emit_multi_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryTargetProjection {
    pub name: String,
    #[serde(default)]
    pub trace_features: Vec<String>,
    #[serde(default)]
    pub positive_when: ProjectionPredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectionPredicate {
    #[serde(default)]
    pub expected_routes: Vec<String>,
    #[serde(default)]
    pub any_features: Vec<String>,
    #[serde(default)]
    pub all_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceEmitSummary {
    pub rows: usize,
    pub output_dir: String,
    pub config: String,
    pub files: Vec<String>,
}

pub fn load_trace_projection_config(config_path: &Path) -> Result<TraceProjectionConfig> {
    let config_text = fs::read_to_string(config_path)?;
    let config: TraceProjectionConfig = serde_json::from_str(&config_text).map_err(|err| {
        LogicPearlError::message(format!("trace projection config is not valid JSON ({err})"))
    })?;
    if config.binary_targets.is_empty() {
        return Err(LogicPearlError::message(
            "trace projection config must declare at least one binary target",
        ));
    }
    Ok(config)
}

pub fn emit_trace_tables(
    observed_jsonl: &Path,
    config_path: &Path,
    output_dir: &Path,
) -> Result<TraceEmitSummary> {
    let config = load_trace_projection_config(config_path)?;
    let file = fs::File::open(observed_jsonl)?;
    let reader = BufReader::new(file);
    fs::create_dir_all(output_dir)?;

    let mut inferred_features: Option<Vec<String>> = None;
    let mut multi_target = String::new();
    let mut target_csvs: BTreeMap<String, String> = BTreeMap::new();
    let mut rows = 0_usize;

    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: ObservedBenchmarkCase = serde_json::from_str(trimmed).map_err(|err| {
            LogicPearlError::message(format!(
                "invalid observed benchmark JSON on line {} ({err})",
                line_no + 1
            ))
        })?;

        let feature_columns = if config.feature_columns.is_empty() {
            inferred_features.get_or_insert_with(|| {
                let mut keys = case.features.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                keys
            })
        } else {
            &config.feature_columns
        };

        if config.emit_multi_target && multi_target.is_empty() {
            let mut header = feature_columns.join(",");
            header.push(',');
            header.push_str(
                &config
                    .binary_targets
                    .iter()
                    .map(|target| target.name.clone())
                    .collect::<Vec<_>>()
                    .join(","),
            );
            header.push('\n');
            multi_target.push_str(&header);
        }

        let mut target_values = Vec::with_capacity(config.binary_targets.len());
        for target in &config.binary_targets {
            if !target_csvs.contains_key(&target.name) {
                let target_features = if target.trace_features.is_empty() {
                    feature_columns.clone()
                } else {
                    target.trace_features.clone()
                };
                let mut header = target_features.join(",");
                header.push_str(",allowed\n");
                target_csvs.insert(target.name.clone(), header);
            }

            let denied = projection_matches(&case, &target.positive_when);
            target_values.push(allow_word(!denied).to_string());

            let target_features = if target.trace_features.is_empty() {
                feature_columns.clone()
            } else {
                target.trace_features.clone()
            };
            let values = target_features
                .iter()
                .map(|feature| csv_value(case.features.get(feature)))
                .collect::<Vec<_>>()
                .join(",");
            target_csvs
                .get_mut(&target.name)
                .expect("target csv initialized")
                .push_str(&format!("{values},{}\n", allow_word(!denied)));
        }

        if config.emit_multi_target {
            let mut values = feature_columns
                .iter()
                .map(|feature| csv_value(case.features.get(feature)))
                .collect::<Vec<_>>();
            values.extend(target_values);
            multi_target.push_str(&values.join(","));
            multi_target.push('\n');
        }
        rows += 1;
    }

    if rows == 0 {
        return Err(LogicPearlError::message(
            "observed benchmark dataset is empty",
        ));
    }

    let mut files = Vec::new();
    if config.emit_multi_target {
        let path = output_dir.join("multi_target.csv");
        fs::write(&path, multi_target)?;
        files.push("multi_target.csv".to_string());
    }
    for (target_name, contents) in &target_csvs {
        let filename = format!("{target_name}_traces.csv");
        let path = output_dir.join(&filename);
        fs::write(&path, contents)?;
        files.push(filename);
    }

    Ok(TraceEmitSummary {
        rows,
        output_dir: output_dir.display().to_string(),
        config: config_path.display().to_string(),
        files,
    })
}

fn default_true() -> bool {
    true
}

fn projection_matches(case: &ObservedBenchmarkCase, predicate: &ProjectionPredicate) -> bool {
    let expected_route_match = predicate.expected_routes.is_empty()
        || predicate
            .expected_routes
            .iter()
            .any(|route| route == &case.expected_route);
    let any_match = predicate.any_features.is_empty()
        || predicate
            .any_features
            .iter()
            .any(|feature| boolish(case.features.get(feature)));
    let all_match = predicate
        .all_features
        .iter()
        .all(|feature| boolish(case.features.get(feature)));
    expected_route_match && any_match && all_match
}

pub(crate) fn csv_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::Bool(boolean)) => boolean.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.replace(',', "_"),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string().replace(',', "_"),
    }
}

pub(super) fn boolish(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(boolean)) => *boolean,
        Some(Value::Number(number)) => number.as_i64().unwrap_or_default() != 0,
        Some(Value::String(text)) => matches!(
            text.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y"
        ),
        _ => false,
    }
}

fn allow_word(allowed: bool) -> &'static str {
    if allowed {
        "allowed"
    } else {
        "denied"
    }
}
