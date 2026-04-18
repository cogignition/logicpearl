// SPDX-License-Identifier: MIT
use crate::{BenchmarkAdapterParser, SquadDataset};
use logicpearl_core::{LogicPearlError, Result};
use serde_json::Value;

pub(crate) fn parse_rows_for_parser(
    raw: &str,
    parser: BenchmarkAdapterParser,
) -> Result<Vec<serde_json::Map<String, Value>>> {
    match parser {
        BenchmarkAdapterParser::JsonObjectRows => parse_json_object_rows(raw),
        BenchmarkAdapterParser::YamlObjectRows => parse_yaml_object_rows(raw),
        BenchmarkAdapterParser::SquadQuestions => parse_squad_question_rows(raw),
    }
}

pub(crate) fn parse_json_object_rows(raw: &str) -> Result<Vec<serde_json::Map<String, Value>>> {
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) {
        let mut rows = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            let object = item.as_object().cloned().ok_or_else(|| {
                LogicPearlError::message(format!("row {} is not a JSON object", index + 1))
            })?;
            rows.push(object);
        }
        return Ok(rows);
    }

    let mut rows = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|error| {
            LogicPearlError::message(format!("invalid JSON on line {}: {}", line_no + 1, error))
        })?;
        let object = value.as_object().cloned().ok_or_else(|| {
            LogicPearlError::message(format!("line {} is not a JSON object", line_no + 1))
        })?;
        rows.push(object);
    }
    Ok(rows)
}

pub(crate) fn parse_yaml_object_rows(raw: &str) -> Result<Vec<serde_json::Map<String, Value>>> {
    let yaml_value: serde_norway::Value = serde_norway::from_str(raw)
        .map_err(|error| LogicPearlError::message(format!("invalid YAML: {error}")))?;
    let json_value = serde_json::to_value(yaml_value).map_err(|error| {
        LogicPearlError::message(format!("could not convert YAML to JSON value ({error})"))
    })?;
    let items = json_value.as_array().cloned().ok_or_else(|| {
        LogicPearlError::message("YAML benchmark dataset must be a top-level list of objects")
    })?;

    let mut rows = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        let object = item.as_object().cloned().ok_or_else(|| {
            LogicPearlError::message(format!("row {} is not a YAML object", index + 1))
        })?;
        rows.push(object);
    }
    Ok(rows)
}

pub(crate) fn parse_squad_question_rows(raw: &str) -> Result<Vec<serde_json::Map<String, Value>>> {
    let dataset: SquadDataset = serde_json::from_str(raw).map_err(|err| {
        LogicPearlError::message(format!(
            "raw SQuAD JSON is not valid for the expected dataset format ({err})"
        ))
    })?;
    if dataset.data.is_empty() {
        return Err(LogicPearlError::message("raw SQuAD dataset is empty"));
    }

    let mut rows = Vec::new();
    for article in &dataset.data {
        for paragraph in &article.paragraphs {
            for question in &paragraph.qas {
                let mut row = serde_json::Map::new();
                row.insert("id".to_string(), Value::String(question.id.clone()));
                row.insert(
                    "question".to_string(),
                    Value::String(question.question.clone()),
                );
                row.insert(
                    "context".to_string(),
                    Value::String(paragraph.context.clone()),
                );
                if let Some(title) = &article.title {
                    row.insert("title".to_string(), Value::String(title.clone()));
                }
                rows.push(row);
            }
        }
    }

    if rows.is_empty() {
        return Err(LogicPearlError::message(
            "raw SQuAD dataset contains no question rows",
        ));
    }

    Ok(rows)
}
