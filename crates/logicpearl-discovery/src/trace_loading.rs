use super::{DecisionTraceRow, LoadedDecisionTraces};
use logicpearl_core::{LogicPearlError, Result};
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct BinaryLabelDomain {
    pub(crate) positive_value: Option<String>,
    pub(crate) negative_value: Option<String>,
}

pub fn load_decision_traces(
    csv_path: &Path,
    label_column: &str,
) -> Result<Vec<DecisionTraceRow>> {
    load_decision_traces_with_labels(csv_path, label_column, None, None)
}

pub fn load_decision_traces_with_labels(
    csv_path: &Path,
    label_column: &str,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<Vec<DecisionTraceRow>> {
    let mut reader = csv::Reader::from_path(csv_path)?;
    let headers = reader.headers()?.clone();
    let records = reader
        .records()
        .collect::<std::result::Result<Vec<_>, csv::Error>>()?;
    load_decision_traces_from_records(
        csv_path,
        &headers,
        &records,
        label_column,
        positive_label,
        negative_label,
    )
}

pub fn load_decision_traces_auto(
    csv_path: &Path,
    label_column: Option<&str>,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<LoadedDecisionTraces> {
    let mut reader = csv::Reader::from_path(csv_path)?;
    let headers = reader.headers()?.clone();
    let records = reader
        .records()
        .collect::<std::result::Result<Vec<_>, csv::Error>>()?;
    let resolved_label = infer_label_column(csv_path, &headers, &records, label_column)?;
    let rows = load_decision_traces_from_records(
        csv_path,
        &headers,
        &records,
        &resolved_label,
        positive_label,
        negative_label,
    )?;
    Ok(LoadedDecisionTraces {
        rows,
        label_column: resolved_label,
    })
}

fn load_decision_traces_from_records(
    csv_path: &Path,
    headers: &csv::StringRecord,
    records: &[csv::StringRecord],
    label_column: &str,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<Vec<DecisionTraceRow>> {
    if !headers.iter().any(|header| header == label_column) {
        let candidates = detect_label_candidates(headers, records);
        let candidate_text = if candidates.is_empty() {
            "none".to_string()
        } else {
            candidates.join(", ")
        };
        return Err(LogicPearlError::message(format!(
            "decision trace CSV {} is missing label column {:?}; candidate binary columns: {}",
            csv_path.display(),
            label_column,
            candidate_text
        )));
    }
    let label_domain =
        infer_binary_label_domain(records, headers, label_column, positive_label, negative_label)?;

    let mut rows = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let mut features = std::collections::HashMap::new();
        let mut allowed = None;
        for (header, value) in headers.iter().zip(record.iter()) {
            if header == label_column {
                allowed = Some(parse_allowed_label(value, index + 2, label_column, &label_domain)?);
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

fn infer_label_column(
    csv_path: &Path,
    headers: &csv::StringRecord,
    records: &[csv::StringRecord],
    explicit_label: Option<&str>,
) -> Result<String> {
    if let Some(label_column) = explicit_label {
        if headers.iter().any(|header| header == label_column) {
            return Ok(label_column.to_string());
        }
        let candidates = detect_label_candidates(headers, records);
        let candidate_text = if candidates.is_empty() {
            "none".to_string()
        } else {
            candidates.join(", ")
        };
        return Err(LogicPearlError::message(format!(
            "decision trace CSV {} is missing label column {:?}; candidate binary columns: {}",
            csv_path.display(),
            label_column,
            candidate_text
        )));
    }

    let candidates = detect_label_candidates(headers, records);
    if candidates.is_empty() {
        return Err(LogicPearlError::message(format!(
            "could not infer a binary label column from {}; pass --label-column explicitly",
            csv_path.display()
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
            "multiple likely label columns found in {}: {}; pass --label-column explicitly",
            csv_path.display(),
            strong_candidates.join(", ")
        )));
    }
    if candidates.len() == 1 {
        return Ok(candidates[0].clone());
    }
    Err(LogicPearlError::message(format!(
        "multiple possible binary label columns found in {}: {}; pass --label-column explicitly",
        csv_path.display(),
        candidates.join(", ")
    )))
}

fn detect_label_candidates(headers: &csv::StringRecord, records: &[csv::StringRecord]) -> Vec<String> {
    headers
        .iter()
        .enumerate()
        .filter_map(|(index, header)| {
            let mut saw_value = false;
            let all_non_empty = records.iter().all(|record| {
                let Some(value) = record.get(index) else {
                    return false;
                };
                if value.trim().is_empty() {
                    return false;
                }
                saw_value = true;
                true
            });
            if all_non_empty
                && saw_value
                && infer_binary_label_domain(records, headers, header, None, None).is_ok()
            {
                Some(header.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_preferred_label_name(name: &str) -> bool {
    let lowered = name.trim().to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "allowed"
            | "approved"
            | "label"
            | "target"
            | "decision"
            | "outcome"
            | "verdict"
            | "result"
    ) || lowered.ends_with("_label")
        || lowered.ends_with("_target")
        || lowered.ends_with("_decision")
        || lowered.ends_with("_outcome")
        || lowered.ends_with("_verdict")
        || lowered.ends_with("_result")
}

pub(crate) fn infer_binary_label_domain(
    records: &[csv::StringRecord],
    headers: &csv::StringRecord,
    label_column: &str,
    positive_label: Option<&str>,
    negative_label: Option<&str>,
) -> Result<BinaryLabelDomain> {
    let label_index = headers
        .iter()
        .position(|header| header == label_column)
        .ok_or_else(|| LogicPearlError::message(format!("missing label column {label_column:?}")))?;
    let mut unique_values = BTreeMap::<String, String>::new();
    for (row_index, record) in records.iter().enumerate() {
        let raw = record.get(label_index).ok_or_else(|| {
            LogicPearlError::message(format!(
                "row {} is missing label column {label_column:?}",
                row_index + 2
            ))
        })?;
        let normalized = normalize_binary_token(raw);
        if normalized.is_empty() {
            return Err(LogicPearlError::message(format!(
                "row {} has an empty label value in column {label_column:?}",
                row_index + 2
            )));
        }
        unique_values
            .entry(normalized)
            .or_insert_with(|| raw.trim().to_string());
    }
    if unique_values.is_empty() || unique_values.len() > 2 {
        let distinct = if unique_values.is_empty() {
            "none".to_string()
        } else {
            unique_values.values().cloned().collect::<Vec<_>>().join(", ")
        };
        return Err(LogicPearlError::message(format!(
            "label column {label_column:?} must contain one or two distinct non-empty values; found {}: {}",
            unique_values.len(),
            distinct
        )));
    }

    let explicit_positive = positive_label.map(normalize_binary_token);
    let explicit_negative = negative_label.map(normalize_binary_token);
    if let Some(label) = explicit_positive.as_ref() {
        if !unique_values.contains_key(label) {
            return Err(LogicPearlError::message(format!(
                "--positive-label {:?} was not found in column {label_column:?}; distinct values: {}",
                positive_label.unwrap_or_default(),
                unique_values.values().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
    }
    if let Some(label) = explicit_negative.as_ref() {
        if !unique_values.contains_key(label) {
            return Err(LogicPearlError::message(format!(
                "--negative-label {:?} was not found in column {label_column:?}; distinct values: {}",
                negative_label.unwrap_or_default(),
                unique_values.values().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
    }
    if explicit_positive.is_some() && explicit_positive == explicit_negative {
        return Err(LogicPearlError::message(
            "--positive-label and --negative-label must be different",
        ));
    }

    let keys: Vec<String> = unique_values.keys().cloned().collect();
    if let (Some(positive), Some(negative)) = (explicit_positive.clone(), explicit_negative.clone()) {
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
        "could not infer which value in label column {label_column:?} means allow/pass from binary values {}; pass --positive-label or --negative-label explicitly",
        unique_values.values().cloned().collect::<Vec<_>>().join(", ")
    )))
}

fn normalize_binary_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn is_positive_label_token(value: &str) -> bool {
    matches!(
        value,
        "1"
            | "true"
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
        "0"
            | "false"
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

pub(crate) fn parse_allowed_label(
    raw: &str,
    row_number: usize,
    label_column: &str,
    domain: &BinaryLabelDomain,
) -> Result<bool> {
    let normalized = normalize_binary_token(raw);
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
            "row {row_number} has unsupported label value {raw:?} in column {label_column:?}; expected one of {}",
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
