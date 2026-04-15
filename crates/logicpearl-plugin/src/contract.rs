// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde_json::Value;

use super::schema_subset::validate_value_against_declared_schema;
use super::{PluginManifest, PluginRequest, PluginResponse, PluginStage};

/// Return a JSON summary of the manifest's declared schemas and capabilities.
pub fn manifest_contract_summary(manifest: &PluginManifest) -> Value {
    serde_json::json!({
        "input_schema": manifest.input_schema,
        "options_schema": manifest.options_schema,
        "output_schema": manifest.output_schema,
    })
}

pub(super) fn parse_plugin_response(
    manifest: &PluginManifest,
    stdout: &str,
) -> Result<PluginResponse> {
    let response: PluginResponse = serde_json::from_str(stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid JSON: {}",
            manifest.name, err
        ))
    })?;
    validate_ok_plugin_response(manifest, &response)?;
    Ok(response)
}

pub(crate) fn validate_ok_plugin_response(
    manifest: &PluginManifest,
    response: &PluginResponse,
) -> Result<()> {
    if !response.ok {
        if let Some(error) = &response.error {
            return Err(LogicPearlError::message(format!(
                "plugin {} failed [{}]: {}",
                manifest.name, error.code, error.message
            )));
        }
        return Err(LogicPearlError::message(format!(
            "plugin {} returned ok=false without structured error",
            manifest.name
        )));
    }
    if let Some(schema) = &manifest.output_schema {
        let response_value = serde_json::to_value(response).map_err(LogicPearlError::from)?;
        validate_value_against_declared_schema(
            "output_schema",
            schema,
            &response_value,
            "$response",
        )?;
    }
    Ok(())
}

pub(crate) fn validate_plugin_request_contract(
    manifest: &PluginManifest,
    request: &PluginRequest,
) -> Result<()> {
    validate_plugin_payload_contract(manifest, &request.stage, &request.payload)
}

pub(crate) fn validate_plugin_payload_contract(
    manifest: &PluginManifest,
    stage: &PluginStage,
    payload: &Value,
) -> Result<()> {
    if let Some(schema) = &manifest.input_schema {
        let input = extract_payload_input(stage, payload).ok_or_else(|| {
            LogicPearlError::message(format!(
                "plugin {} manifest declares input_schema but request payload is missing payload.input",
                manifest.name
            ))
        })?;
        validate_value_against_declared_schema("input_schema", schema, input, "$payload.input")?;
    }
    if let Some(schema) = &manifest.options_schema {
        let null = Value::Null;
        let options = extract_payload_options(payload).unwrap_or(&null);
        validate_value_against_declared_schema(
            "options_schema",
            schema,
            options,
            "$payload.options",
        )?;
    }
    Ok(())
}

fn extract_payload_input<'a>(_stage: &PluginStage, payload: &'a Value) -> Option<&'a Value> {
    payload.as_object().and_then(|object| object.get("input"))
}

fn extract_payload_options(payload: &Value) -> Option<&Value> {
    payload.as_object().and_then(|object| object.get("options"))
}
