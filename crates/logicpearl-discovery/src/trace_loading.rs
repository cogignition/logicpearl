// SPDX-License-Identifier: MIT
use super::{DecisionTraceRow, LoadedDecisionTraces};
use logicpearl_core::{LogicPearlError, Result};
use serde_json::{Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct BinaryLabelDomain {
    pub(crate) positive_value: Option<String>,
    pub(crate) negative_value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoadedFlatRecords {
    pub field_names: Vec<String>,
    pub records: Vec<BTreeMap<String, Value>>,
}

const NORMALIZED_TRACE_INPUT_HINT: &str = "Build and discover inputs must be normalized rectangular decision traces. Normalize missing, null, optional, or domain-specific raw structures in an observer, trace_source plugin, or adapter before discovery.";

pub fn load_decision_traces(csv_path: &Path, label_column: &str) -> Result<Vec<DecisionTraceRow>> {
    load_decision_traces_with_labels(csv_path, label_column, None, None)
}

pub fn load_decision_traces_with_labels(
    path: &Path,
    label_column: &str,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<Vec<DecisionTraceRow>> {
    let loaded = load_flat_records(path)?;
    load_decision_traces_from_records(
        path,
        &loaded.field_names,
        &loaded.records,
        label_column,
        positive_label,
        negative_label,
    )
}

pub fn load_decision_traces_auto(
    path: &Path,
    label_column: Option<&str>,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<LoadedDecisionTraces> {
    let loaded = load_flat_records(path)?;
    let resolved_label =
        infer_label_column(path, &loaded.field_names, &loaded.records, label_column)?;
    let rows = load_decision_traces_from_records(
        path,
        &loaded.field_names,
        &loaded.records,
        &resolved_label,
        positive_label,
        negative_label,
    )?;
    Ok(LoadedDecisionTraces {
        rows,
        label_column: resolved_label,
    })
}

pub fn load_flat_records(path: &Path) -> Result<LoadedFlatRecords> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => load_json_records(path),
        Some("jsonl") | Some("ndjson") => load_jsonl_records(path),
        _ => load_csv_records(path),
    }
}

fn load_csv_records(path: &Path) -> Result<LoadedFlatRecords> {
    let mut reader = csv::Reader::from_path(path)?;
    let headers = reader.headers()?.clone();
    let records = reader
        .records()
        .collect::<std::result::Result<Vec<_>, csv::Error>>()?;
    if headers.is_empty() {
        return Err(LogicPearlError::message(format!(
            "decision trace input {} has no columns",
            path.display()
        )));
    }

    let field_names = headers.iter().map(ToOwned::to_owned).collect::<Vec<_>>();
    let mut out = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let mut row = BTreeMap::new();
        for (header, value) in headers.iter().zip(record.iter()) {
            if value.trim().is_empty() {
                return Err(LogicPearlError::message(format!(
                    "row {} has an empty value for field {header:?}\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                    index + 2,
                )));
            }
            row.insert(header.to_string(), parse_scalar(value)?);
        }
        out.push(row);
    }

    Ok(LoadedFlatRecords {
        field_names,
        records: out,
    })
}

fn load_json_records(path: &Path) -> Result<LoadedFlatRecords> {
    let payload = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&payload).map_err(|err| {
        LogicPearlError::message(format!("failed to parse JSON decision traces: {err}"))
    })?;
    let rows = match value {
        Value::Array(rows) => rows,
        Value::Object(mut object) => match object.remove("decision_traces") {
            Some(Value::Array(rows)) => rows,
            Some(_) => {
                return Err(LogicPearlError::message(
                    "top-level `decision_traces` must be a JSON array",
                ))
            }
            None => {
                return Err(LogicPearlError::message(
                    "JSON decision traces must be an array or an object with a top-level `decision_traces` array",
                ))
            }
        },
        _ => {
            return Err(LogicPearlError::message(
                "JSON decision traces must be an array or an object with a top-level `decision_traces` array",
            ))
        }
    };
    flatten_json_rows(path, rows)
}

fn load_jsonl_records(path: &Path) -> Result<LoadedFlatRecords> {
    let payload = fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for (index, line) in payload.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|err| {
            LogicPearlError::message(format!(
                "failed to parse JSONL decision trace row {}: {err}",
                index + 1
            ))
        })?;
        rows.push(value);
    }
    flatten_json_rows(path, rows)
}

fn flatten_json_rows(path: &Path, rows: Vec<Value>) -> Result<LoadedFlatRecords> {
    if rows.is_empty() {
        return Ok(LoadedFlatRecords {
            field_names: Vec::new(),
            records: Vec::new(),
        });
    }

    let mut flat_rows = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        let Value::Object(object) = row else {
            return Err(LogicPearlError::message(format!(
                "decision trace row {} in {} must be a JSON object\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                index + 1,
                path.display()
            )));
        };
        let mut flat = BTreeMap::new();
        flatten_json_object(index + 1, None, &Value::Object(object), &mut flat)?;
        if flat.is_empty() {
            return Err(LogicPearlError::message(format!(
                "decision trace row {} in {} did not produce any scalar fields\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                index + 1,
                path.display()
            )));
        }
        flat_rows.push(flat);
    }

    let field_names = ensure_rectangular_schema(path, &flat_rows)?;
    Ok(LoadedFlatRecords {
        field_names,
        records: flat_rows,
    })
}

fn flatten_json_object(
    row_number: usize,
    prefix: Option<&str>,
    value: &Value,
    out: &mut BTreeMap<String, Value>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.is_empty() {
                return Err(LogicPearlError::message(format!(
                    "row {row_number} contains an empty object at {}\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                    prefix.unwrap_or("<root>")
                )));
            }
            for (key, nested) in object {
                let next = match prefix {
                    Some(prefix) => format!("{prefix}.{key}"),
                    None => key.clone(),
                };
                flatten_json_object(row_number, Some(&next), nested, out)?;
            }
        }
        Value::Array(values) => {
            if values.is_empty() {
                return Err(LogicPearlError::message(format!(
                    "row {row_number} contains an empty array at {}\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                    prefix.unwrap_or("<root>")
                )));
            }
            for (index, nested) in values.iter().enumerate() {
                let next = match prefix {
                    Some(prefix) => format!("{prefix}.{index}"),
                    None => index.to_string(),
                };
                flatten_json_object(row_number, Some(&next), nested, out)?;
            }
        }
        Value::Null => {
            return Err(LogicPearlError::message(format!(
                "row {row_number} contains null at {}\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                prefix.unwrap_or("<root>")
            )))
        }
        Value::String(raw) => {
            let key = prefix.ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {row_number} contains a bare scalar at the root\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}"
                ))
            })?;
            out.insert(key.to_string(), parse_scalar(raw)?);
        }
        Value::Bool(boolean) => {
            let key = prefix.ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {row_number} contains a bare scalar at the root\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}"
                ))
            })?;
            out.insert(key.to_string(), Value::Bool(*boolean));
        }
        Value::Number(number) => {
            let key = prefix.ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {row_number} contains a bare scalar at the root\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}"
                ))
            })?;
            out.insert(key.to_string(), Value::Number(number.clone()));
        }
    }
    Ok(())
}

fn ensure_rectangular_schema(path: &Path, rows: &[BTreeMap<String, Value>]) -> Result<Vec<String>> {
    let first_keys = rows
        .first()
        .map(|row| row.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let expected = first_keys.iter().cloned().collect::<BTreeSet<_>>();
    for (index, row) in rows.iter().enumerate().skip(1) {
        let actual = row.keys().cloned().collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected
                .difference(&actual)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let extra = actual
                .difference(&expected)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(LogicPearlError::message(format!(
                "decision trace row {} in {} has a different schema; missing: [{}], extra: [{}]\n\nHint: {NORMALIZED_TRACE_INPUT_HINT}",
                index + 1,
                path.display(),
                missing,
                extra
            )));
        }
    }
    Ok(first_keys)
}

fn load_decision_traces_from_records(
    path: &Path,
    field_names: &[String],
    records: &[BTreeMap<String, Value>],
    label_column: &str,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<Vec<DecisionTraceRow>> {
    if !field_names.iter().any(|header| header == label_column) {
        let candidates = detect_label_candidates(field_names, records);
        let candidate_text = if candidates.is_empty() {
            "none".to_string()
        } else {
            candidates.join(", ")
        };
        return Err(LogicPearlError::message(format!(
            "decision trace input {} is missing label field {:?}; candidate binary fields: {}",
            path.display(),
            label_column,
            candidate_text
        )));
    }
    let label_domain =
        infer_binary_label_domain(records, label_column, positive_label, negative_label)?;

    let mut rows = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let mut features = std::collections::HashMap::new();
        let mut allowed = None;
        for field_name in field_names {
            let value = record.get(field_name).ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {} is missing field {field_name:?}",
                    index + 1
                ))
            })?;
            if field_name == label_column {
                allowed = Some(parse_allowed_label_value(
                    value,
                    index + 1,
                    label_column,
                    &label_domain,
                )?);
            } else {
                features.insert(field_name.to_string(), value.clone());
            }
        }
        rows.push(DecisionTraceRow {
            features,
            allowed: allowed.ok_or_else(|| {
                LogicPearlError::message(format!(
                    "row {} is missing label field {label_column:?}",
                    index + 1
                ))
            })?,
        });
    }
    Ok(rows)
}

fn infer_label_column(
    path: &Path,
    field_names: &[String],
    records: &[BTreeMap<String, Value>],
    explicit_label: Option<&str>,
) -> Result<String> {
    if let Some(label_column) = explicit_label {
        if field_names.iter().any(|field| field == label_column) {
            return Ok(label_column.to_string());
        }
        let candidates = detect_label_candidates(field_names, records);
        let candidate_text = if candidates.is_empty() {
            "none".to_string()
        } else {
            candidates.join(", ")
        };
        return Err(LogicPearlError::message(format!(
            "decision trace input {} is missing label field {:?}; candidate binary fields: {}",
            path.display(),
            label_column,
            candidate_text
        )));
    }

    let candidates = detect_label_candidates(field_names, records);
    if candidates.is_empty() {
        return Err(LogicPearlError::message(format!(
            "could not infer a binary label field from {}; pass --label-column explicitly",
            path.display()
        )));
    }
    let strong_candidates: Vec<&str> = candidates
        .iter()
        .map(String::as_str)
        .filter(|candidate| is_preferred_label_name(candidate))
        .collect();
    if strong_candidates.len() == 1 {
        return Ok(strong_candidates[0].to_string());
    }
    if strong_candidates.len() > 1 {
        return Err(LogicPearlError::message(format!(
            "multiple likely label fields found in {}: {}; pass --label-column explicitly",
            path.display(),
            strong_candidates.join(", ")
        )));
    }
    if candidates.len() == 1 {
        return Ok(candidates[0].clone());
    }
    Err(LogicPearlError::message(format!(
        "multiple possible binary label fields found in {}: {}; pass --label-column explicitly",
        path.display(),
        candidates.join(", ")
    )))
}

fn detect_label_candidates(
    field_names: &[String],
    records: &[BTreeMap<String, Value>],
) -> Vec<String> {
    field_names
        .iter()
        .filter_map(|field_name| {
            infer_binary_label_domain(records, field_name, None, None)
                .ok()
                .map(|_| field_name.clone())
        })
        .collect()
}

fn is_preferred_label_name(name: &str) -> bool {
    let lowered = name
        .rsplit('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "allowed" | "approved" | "label" | "target" | "decision" | "outcome" | "verdict" | "result"
    ) || lowered.ends_with("_label")
        || lowered.ends_with("_target")
        || lowered.ends_with("_decision")
        || lowered.ends_with("_outcome")
        || lowered.ends_with("_verdict")
        || lowered.ends_with("_result")
}

pub(crate) fn infer_binary_label_domain(
    records: &[BTreeMap<String, Value>],
    label_column: &str,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<BinaryLabelDomain> {
    let mut unique_values = BTreeMap::<String, String>::new();
    for (row_index, record) in records.iter().enumerate() {
        let raw = record.get(label_column).ok_or_else(|| {
            LogicPearlError::message(format!(
                "row {} is missing label field {label_column:?}",
                row_index + 1
            ))
        })?;
        let normalized = normalize_binary_token_value(raw)?;
        if normalized.is_empty() {
            return Err(LogicPearlError::message(format!(
                "row {} has an empty label value in field {label_column:?}",
                row_index + 1
            )));
        }
        unique_values
            .entry(normalized)
            .or_insert_with(|| render_label_value(raw));
    }
    if unique_values.is_empty() || unique_values.len() > 2 {
        let distinct = if unique_values.is_empty() {
            "none".to_string()
        } else {
            unique_values
                .values()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(LogicPearlError::message(format!(
            "label field {label_column:?} must contain one or two distinct non-empty values; found {}: {}",
            unique_values.len(),
            distinct
        )));
    }

    let explicit_positive = positive_label.map(normalize_binary_token);
    let explicit_negative = negative_label.map(normalize_binary_token);
    if let Some(label) = explicit_positive.as_ref() {
        if !unique_values.contains_key(label) {
            return Err(LogicPearlError::message(format!(
                "--default-label {:?} was not found in field {label_column:?}; distinct values: {}",
                positive_label.unwrap_or_default(),
                unique_values
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    if let Some(label) = explicit_negative.as_ref() {
        if !unique_values.contains_key(label) {
            return Err(LogicPearlError::message(format!(
                "--rule-label {:?} was not found in field {label_column:?}; distinct values: {}",
                negative_label.unwrap_or_default(),
                unique_values
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    if explicit_positive.is_some() && explicit_positive == explicit_negative {
        return Err(LogicPearlError::message(
            "--default-label and --rule-label must be different",
        ));
    }

    let keys: Vec<String> = unique_values.keys().cloned().collect();
    if let (Some(positive), Some(negative)) = (explicit_positive.clone(), explicit_negative.clone())
    {
        return Ok(BinaryLabelDomain {
            positive_value: Some(positive),
            negative_value: Some(negative),
        });
    }
    if let Some(positive) = explicit_positive {
        return Ok(BinaryLabelDomain {
            positive_value: Some(positive.clone()),
            negative_value: keys.iter().find(|value| **value != positive).cloned(),
        });
    }
    if let Some(negative) = explicit_negative {
        return Ok(BinaryLabelDomain {
            positive_value: keys.iter().find(|value| **value != negative).cloned(),
            negative_value: Some(negative),
        });
    }

    let positive_candidates: Vec<String> = keys
        .iter()
        .filter(|value| is_positive_label_token(value))
        .cloned()
        .collect();
    let negative_candidates: Vec<String> = keys
        .iter()
        .filter(|value| is_negative_label_token(value))
        .cloned()
        .collect();
    if positive_candidates.len() == 1 && negative_candidates.len() == 1 {
        return Ok(BinaryLabelDomain {
            positive_value: Some(positive_candidates[0].clone()),
            negative_value: Some(negative_candidates[0].clone()),
        });
    }
    if positive_candidates.len() == 1 {
        return Ok(BinaryLabelDomain {
            positive_value: Some(positive_candidates[0].clone()),
            negative_value: keys
                .iter()
                .find(|value| **value != positive_candidates[0])
                .cloned(),
        });
    }
    if negative_candidates.len() == 1 {
        return Ok(BinaryLabelDomain {
            positive_value: keys
                .iter()
                .find(|value| **value != negative_candidates[0])
                .cloned(),
            negative_value: Some(negative_candidates[0].clone()),
        });
    }
    Err(LogicPearlError::message(format!(
        "could not infer which value in label field {label_column:?} is the default/pass value from binary values {}; pass --default-label or --rule-label explicitly",
        unique_values.values().cloned().collect::<Vec<_>>().join(", ")
    )))
}

fn normalize_binary_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn normalize_binary_token_value(raw: &Value) -> Result<String> {
    match raw {
        Value::String(value) => Ok(normalize_binary_token(value)),
        Value::Bool(value) => Ok(if *value { "true" } else { "false" }.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(LogicPearlError::message(format!(
            "label values must be scalar; got {}",
            raw
        ))),
    }
}

fn render_label_value(raw: &Value) -> String {
    match raw {
        Value::String(value) => value.trim().to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn is_positive_label_token(value: &str) -> bool {
    matches!(
        value,
        "1" | "true"
            | "yes"
            | "y"
            | "allow"
            | "allowed"
            | "approve"
            | "approved"
            | "grant"
            | "granted"
            | "pass"
            | "passed"
            | "ok"
            | "safe"
            | "benign"
    )
}

fn is_negative_label_token(value: &str) -> bool {
    matches!(
        value,
        "0" | "false"
            | "no"
            | "n"
            | "deny"
            | "denied"
            | "reject"
            | "rejected"
            | "block"
            | "blocked"
            | "flag"
            | "flagged"
            | "fail"
            | "failed"
            | "unsafe"
            | "malicious"
    )
}

pub(crate) fn parse_allowed_label_value(
    raw: &Value,
    row_number: usize,
    label_column: &str,
    domain: &BinaryLabelDomain,
) -> Result<bool> {
    let normalized = normalize_binary_token_value(raw)?;
    if domain.positive_value.as_deref() == Some(normalized.as_str()) {
        Ok(true)
    } else if domain.negative_value.as_deref() == Some(normalized.as_str()) {
        Ok(false)
    } else {
        let mut expected = Vec::new();
        if let Some(positive) = domain.positive_value.as_deref() {
            expected.push(positive.to_string());
        }
        if let Some(negative) = domain.negative_value.as_deref() {
            expected.push(negative.to_string());
        }
        Err(LogicPearlError::message(format!(
            "row {row_number} has unsupported label value {:?} in field {label_column:?}; expected one of {}",
            render_label_value(raw),
            expected.join(", ")
        )))
    }
}

pub(crate) fn parse_scalar(raw: &str) -> Result<Value> {
    let value = raw.trim();
    let lowered = value.to_ascii_lowercase();
    if let Some(boolean) = parse_boolean_scalar(&lowered) {
        return Ok(Value::Bool(boolean));
    }
    if let Some(parsed) = parse_numeric_scalar(value)? {
        return Ok(parsed);
    }
    Ok(Value::String(value.to_string()))
}

fn parse_boolean_scalar(lowered: &str) -> Option<bool> {
    match lowered {
        "true" | "yes" | "y" | "on" => Some(true),
        "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn parse_numeric_scalar(raw: &str) -> Result<Option<Value>> {
    let mut candidate = raw.trim();
    let mut is_percent = false;
    if let Some(stripped) = candidate.strip_suffix('%') {
        candidate = stripped.trim();
        is_percent = true;
    }
    candidate = candidate
        .strip_prefix('$')
        .or_else(|| candidate.strip_prefix('€'))
        .or_else(|| candidate.strip_prefix('£'))
        .or_else(|| candidate.strip_prefix('¥'))
        .unwrap_or(candidate)
        .trim();
    let negative_wrapped = candidate.starts_with('(') && candidate.ends_with(')');
    if negative_wrapped {
        candidate = candidate
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or(candidate)
            .trim();
    }
    let mut normalized = candidate.replace(',', "");
    if negative_wrapped {
        normalized = format!("-{normalized}");
    }

    if !is_percent {
        if let Ok(parsed) = normalized.parse::<i64>() {
            return Ok(Some(Value::Number(Number::from(parsed))));
        }
    }
    if let Ok(mut parsed) = normalized.parse::<f64>() {
        if is_percent {
            parsed /= 100.0;
        }
        return Ok(Some(Value::Number(Number::from_f64(parsed).ok_or_else(
            || LogicPearlError::message("encountered non-finite float"),
        )?)));
    }
    Ok(None)
}
