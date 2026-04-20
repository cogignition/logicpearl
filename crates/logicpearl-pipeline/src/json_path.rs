// SPDX-License-Identifier: MIT

use crate::staged::PipelineStage;
use logicpearl_core::{LogicPearlError, Result};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

pub(crate) fn validate_value_reference(
    value: &Value,
    visible_exports: &HashMap<String, BTreeSet<String>>,
) -> Result<()> {
    match value {
        Value::String(reference) => validate_reference(reference, visible_exports),
        Value::Array(items) => {
            for item in items {
                validate_value_reference(item, visible_exports)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for item in map.values() {
                validate_value_reference(item, visible_exports)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_reference(
    reference: &str,
    visible_exports: &HashMap<String, BTreeSet<String>>,
) -> Result<()> {
    if reference.starts_with("$.") {
        if reference.len() < 3 {
            return Err(LogicPearlError::message(format!(
                "invalid root reference: {reference}"
            )));
        }
        return Ok(());
    }
    if let Some(rest) = reference.strip_prefix('@') {
        let mut parts = rest.split('.');
        let stage_id = parts.next().ok_or_else(|| {
            LogicPearlError::message(format!("invalid stage reference: {reference}"))
        })?;
        let export_name = parts.next().ok_or_else(|| {
            LogicPearlError::message(format!("invalid stage reference: {reference}"))
        })?;
        if parts.next().is_some() {
            return Err(LogicPearlError::message(format!(
                "invalid stage reference: {reference}"
            )));
        }
        let exports = visible_exports.get(stage_id).ok_or_else(|| {
            LogicPearlError::message(format!(
                "reference uses unknown or future stage {stage_id}: {reference}"
            ))
        })?;
        if !exports.contains(export_name) {
            return Err(LogicPearlError::message(format!(
                "reference uses unknown export {export_name} from stage {stage_id}"
            )));
        }
        return Ok(());
    }
    Ok(())
}

pub(crate) fn build_stage_input_object(
    stage: &PipelineStage,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<HashMap<String, Value>> {
    let payload = build_stage_payload_value(stage, root_input, stage_exports)?;
    let object = payload.as_object().ok_or_else(|| {
        LogicPearlError::message(format!(
            "stage {} expected an object payload for pearl input",
            stage.id
        ))
    })?;
    let mut resolved = HashMap::new();
    for (key, value) in object {
        resolved.insert(key.clone(), value.clone());
    }
    Ok(resolved)
}

pub(crate) fn build_stage_payload_value(
    stage: &PipelineStage,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    match &stage.payload {
        Some(payload) => resolve_stage_input_value(payload, root_input, stage_exports),
        None => Ok(Value::Object(Map::from_iter(
            stage
                .input
                .iter()
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        resolve_stage_input_value(value, root_input, stage_exports)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        ))),
    }
}

pub(crate) fn build_stage_options_value(
    stage: &PipelineStage,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Option<Value>> {
    stage
        .options
        .as_ref()
        .map(|value| resolve_stage_input_value(value, root_input, stage_exports))
        .transpose()
}

pub(crate) fn build_stage_exports(
    export_map: &HashMap<String, Value>,
    raw_result: &Value,
) -> Result<HashMap<String, Value>> {
    let mut resolved = HashMap::new();
    for (key, value) in export_map {
        resolved.insert(key.clone(), resolve_stage_output_value(value, raw_result)?);
    }
    Ok(resolved)
}

pub(crate) fn resolve_stage_input_value(
    value: &Value,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    resolve_value(value, root_input, None, stage_exports)
}

fn resolve_stage_output_value(value: &Value, stage_result: &Value) -> Result<Value> {
    resolve_value(value, stage_result, Some(stage_result), &HashMap::new())
}

pub(crate) fn resolve_pipeline_output_value(
    value: &Value,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    resolve_value(value, root_input, None, stage_exports)
}

fn resolve_value(
    value: &Value,
    dollar_scope: &Value,
    local_scope: Option<&Value>,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    match value {
        Value::String(reference) if reference.starts_with("$.") => {
            lookup_json_path(local_scope.unwrap_or(dollar_scope), reference)
        }
        Value::String(reference) if reference.starts_with('@') => {
            let mut parts = reference[1..].split('.');
            let stage_id = parts.next().ok_or_else(|| {
                LogicPearlError::message(format!("invalid stage reference: {reference}"))
            })?;
            let export_name = parts.next().ok_or_else(|| {
                LogicPearlError::message(format!("invalid stage reference: {reference}"))
            })?;
            if parts.next().is_some() {
                return Err(LogicPearlError::message(format!(
                    "invalid stage reference: {reference}"
                )));
            }
            let exports = stage_exports.get(stage_id).ok_or_else(|| {
                LogicPearlError::message(format!("unknown stage reference: {reference}"))
            })?;
            exports.get(export_name).cloned().ok_or_else(|| {
                LogicPearlError::message(format!("unknown export reference: {reference}"))
            })
        }
        Value::Array(items) => {
            let mut resolved = Vec::with_capacity(items.len());
            for item in items {
                resolved.push(resolve_value(
                    item,
                    dollar_scope,
                    local_scope,
                    stage_exports,
                )?);
            }
            Ok(Value::Array(resolved))
        }
        Value::Object(map) => {
            let mut resolved = Map::new();
            for (key, item) in map {
                resolved.insert(
                    key.clone(),
                    resolve_value(item, dollar_scope, local_scope, stage_exports)?,
                );
            }
            Ok(Value::Object(resolved))
        }
        _ => Ok(value.clone()),
    }
}

fn lookup_json_path(scope: &Value, reference: &str) -> Result<Value> {
    let mut current = scope;
    for segment in reference.trim_start_matches("$.").split('.') {
        if segment.is_empty() {
            continue;
        }
        current = current
            .as_object()
            .and_then(|object| object.get(segment))
            .ok_or_else(|| LogicPearlError::message(format!("path not found: {reference}")))?;
    }
    Ok(current.clone())
}

pub(crate) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                int != 0
            } else if let Some(float) = number.as_f64() {
                float != 0.0
            } else {
                false
            }
        }
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}
