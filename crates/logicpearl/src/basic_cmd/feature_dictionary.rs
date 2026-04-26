// SPDX-License-Identifier: MIT
use super::BuildArgs;
use logicpearl_discovery::{DecisionTraceRow, FeatureDictionaryConfig};
use logicpearl_ir::InputSchema;
use miette::{IntoDiagnostic, Result, WrapErr};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn generated_feature_dictionary_path(output_dir: &Path) -> PathBuf {
    output_dir.join("feature_dictionary.generated.json")
}

pub(super) fn should_generate_feature_dictionary(args: &BuildArgs) -> bool {
    !args.raw_feature_ids && args.feature_dictionary.is_none()
}

pub(super) fn generated_feature_dictionary_for_output<'a>(
    args: &'a BuildArgs,
    output_dir: &Path,
) -> Option<&'a PathBuf> {
    let generated = generated_feature_dictionary_path(output_dir);
    args.feature_dictionary
        .as_ref()
        .filter(|path| **path == generated)
}

pub(super) fn feature_columns_from_decision_rows(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| row.features.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
}

pub(super) fn write_feature_dictionary_from_columns(
    path: &Path,
    columns: Vec<String>,
) -> Result<()> {
    let dictionary = starter_feature_dictionary_from_columns(columns);
    write_feature_dictionary(path, &dictionary)
}

pub(super) fn write_feature_dictionary_from_schema(
    path: &Path,
    schema: &InputSchema,
) -> Result<()> {
    let columns = schema
        .features
        .iter()
        .map(|feature| feature.id.clone())
        .collect::<Vec<_>>();
    let dictionary = starter_feature_dictionary_from_columns(columns);
    write_feature_dictionary(path, &dictionary)
}

fn write_feature_dictionary(path: &Path, dictionary: &FeatureDictionaryConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create feature dictionary output directory")?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(dictionary).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write generated feature dictionary")?;
    Ok(())
}

fn starter_feature_dictionary_from_columns(columns: Vec<String>) -> FeatureDictionaryConfig {
    let mut features = BTreeMap::new();
    for column in columns {
        features.insert(column.clone(), starter_feature_semantics(&column));
    }
    FeatureDictionaryConfig {
        feature_dictionary_version: "1.0".to_string(),
        features,
    }
}

fn starter_feature_semantics(feature_id: &str) -> logicpearl_ir::FeatureSemantics {
    let lower = feature_id.to_ascii_lowercase();
    logicpearl_ir::FeatureSemantics {
        label: Some(humanize_feature_id(feature_id)),
        kind: infer_feature_kind(&lower).map(str::to_string),
        unit: infer_feature_unit(&lower).map(str::to_string),
        higher_is_better: infer_higher_is_better(&lower),
        source_id: None,
        source_anchor: None,
        states: BTreeMap::new(),
    }
}

fn humanize_feature_id(feature_id: &str) -> String {
    let mut normalized = feature_id.to_ascii_lowercase();
    for suffix in [
        "_pct", "_percent", "_gallons", "_gallon", "_count", "_score",
    ] {
        if let Some(stem) = normalized.strip_suffix(suffix) {
            normalized = stem.to_string();
            break;
        }
    }
    normalized = normalized.replace("_cm_last_", "_last_");

    if let Some(rest) = normalized.strip_prefix("days_since_") {
        return format!("Days since {}", lower_phrase_words(rest));
    }
    if let Some((subject, window)) = normalized.split_once("_last_") {
        if let Some(days) = window.strip_suffix("_days") {
            let subject = if subject == "water" {
                "Water used".to_string()
            } else {
                title_case_words(subject)
            };
            return format!("{subject} in the last {days} days");
        }
    }

    title_case_words(&normalized)
}

fn title_case_words(value: &str) -> String {
    let words = value
        .replace(['_', '-', '.'], " ")
        .split_whitespace()
        .map(|word| match word {
            "pct" => "percent".to_string(),
            "cm" => "cm".to_string(),
            "id" => "ID".to_string(),
            "url" => "URL".to_string(),
            "api" => "API".to_string(),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_uppercase().collect::<String>()
                            + &chars.as_str().to_ascii_lowercase()
                    }
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>();
    words.join(" ")
}

fn lower_phrase_words(value: &str) -> String {
    value
        .replace(['_', '-', '.'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn infer_feature_kind(lower_feature_id: &str) -> Option<&'static str> {
    if lower_feature_id.ends_with("_score") || lower_feature_id.contains("_score_") {
        Some("score")
    } else if lower_feature_id.ends_with("_count") || lower_feature_id.contains("_count_") {
        Some("count")
    } else if lower_feature_id.ends_with("_pct") || lower_feature_id.contains("_pct_") {
        Some("measurement")
    } else if lower_feature_id.starts_with("has_")
        || lower_feature_id.starts_with("is_")
        || lower_feature_id.starts_with("contains_")
    {
        Some("flag")
    } else {
        None
    }
}

fn infer_feature_unit(lower_feature_id: &str) -> Option<&'static str> {
    if lower_feature_id.ends_with("_pct") || lower_feature_id.contains("_pct_") {
        Some("percent")
    } else if lower_feature_id.contains("gallon") {
        Some("gallons")
    } else if lower_feature_id.starts_with("days_") || lower_feature_id.contains("_days_") {
        Some("days")
    } else if lower_feature_id.ends_with("_cm") || lower_feature_id.contains("_cm_") {
        Some("cm")
    } else {
        None
    }
}

fn infer_higher_is_better(lower_feature_id: &str) -> Option<bool> {
    if lower_feature_id.contains("risk")
        || lower_feature_id.contains("pale")
        || lower_feature_id.contains("crowd")
        || lower_feature_id.contains("crack")
        || lower_feature_id.contains("error")
        || lower_feature_id.contains("fail")
    {
        Some(false)
    } else if lower_feature_id.contains("score")
        || lower_feature_id.contains("confidence")
        || lower_feature_id.contains("growth")
    {
        Some(true)
    } else {
        None
    }
}
