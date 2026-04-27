// SPDX-License-Identifier: MIT
use super::*;
use logicpearl_discovery::FeatureColumnSelection;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn default_gate_id_from_path(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "decision_traces".to_string());
    if stem != "traces" {
        return stem;
    }
    let parent_name = match path
        .parent()
        .and_then(|value| value.file_name())
        .map(|value| value.to_string_lossy().into_owned())
    {
        Some(value) => value,
        None => return stem,
    };
    format!("{}_{}", sanitize_identifier(&parent_name), stem)
}

pub(super) fn build_trace_plugin_options(args: &BuildArgs) -> Result<BTreeMap<String, String>> {
    let mut options = parse_key_value_entries(&args.trace_plugin_options, "trace-plugin-option")?;
    if let Some(label_column) = &args.label_column {
        options.insert("label_column".to_string(), label_column.clone());
    }
    Ok(options)
}

pub(super) fn feature_column_selection(
    feature_columns: &[String],
    exclude_columns: &[String],
) -> Result<FeatureColumnSelection> {
    if !feature_columns.is_empty() && !exclude_columns.is_empty() {
        return Err(CommandCoaching::simple(
            "feature column selection received both an allow-list and an exclude-list",
            "Use either --feature-columns or --exclude-columns, not both.",
        ));
    }
    Ok(FeatureColumnSelection {
        feature_columns: (!feature_columns.is_empty()).then(|| feature_columns.to_vec()),
        exclude_columns: exclude_columns.to_vec(),
    })
}

pub(super) fn parse_key_value_entries(
    entries: &[String],
    flag_name: &str,
) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(CommandCoaching::simple(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        };
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(CommandCoaching::simple(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        }
        parsed.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(parsed)
}
