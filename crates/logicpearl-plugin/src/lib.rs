// SPDX-License-Identifier: MIT
//! Trusted local process plugin contracts and runner.
//!
//! Plugins adapt external sources into normalized LogicPearl inputs or verify
//! generated artifacts. This crate validates plugin manifests, constructs the
//! canonical JSON payload, enforces conservative process execution defaults,
//! captures bounded stdout/stderr metadata, and emits plugin run provenance.
//! It is not an OS sandbox for untrusted code.

use logicpearl_core::{LogicPearlError, Result};
use serde_json::{Map, Value};
mod contract;
mod manifest;
mod process_runner;
mod provenance;
mod schema_subset;
mod types;

pub use contract::manifest_contract_summary;
use contract::{
    parse_plugin_response, validate_ok_plugin_response, validate_plugin_payload_contract,
    validate_plugin_request_contract,
};
pub use manifest::{PluginExecutionPolicy, PluginManifest, PluginStage, DEFAULT_PLUGIN_TIMEOUT_MS};
pub(crate) use process_runner::ResolvedPluginEntrypoint;
use process_runner::{effective_timeout_ms, resolve_entrypoint, run_plugin_raw};
use provenance::{build_plugin_run_metadata, now_utc_rfc3339, PluginRunMetadataInputs};
pub use provenance::{
    PluginAccessMetadata, PluginCapabilityMetadata, PluginEntrypointMetadata,
    PluginEntrypointSegmentHash, PluginExecutionPolicyMetadata, PluginRunMetadata,
    PluginStdioMetadata, PluginTimeoutPolicyMetadata,
};
pub use types::{
    PluginBatchExecutionResult, PluginBatchRequest, PluginBatchResponse, PluginErrorPayload,
    PluginExecutionResult, PluginRequest, PluginResponse,
};

/// Build the canonical JSON payload sent to a plugin process on stdin.
pub fn build_canonical_payload(
    _stage: &PluginStage,
    input: Value,
    options: Option<Value>,
) -> Value {
    let mut payload = Map::new();
    payload.insert("input".to_string(), input);

    if let Some(options) = options {
        payload.insert("options".to_string(), options);
    }

    Value::Object(payload)
}

/// Execute a plugin with default execution policy.
pub fn run_plugin(manifest: &PluginManifest, request: &PluginRequest) -> Result<PluginResponse> {
    run_plugin_with_policy(manifest, request, &PluginExecutionPolicy::default())
}

/// Execute a plugin under the given execution policy.
pub fn run_plugin_with_policy(
    manifest: &PluginManifest,
    request: &PluginRequest,
    policy: &PluginExecutionPolicy,
) -> Result<PluginResponse> {
    Ok(run_plugin_with_policy_and_metadata(manifest, request, policy)?.response)
}

/// Execute a plugin under the given execution policy and return execution metadata.
pub fn run_plugin_with_policy_and_metadata(
    manifest: &PluginManifest,
    request: &PluginRequest,
    policy: &PluginExecutionPolicy,
) -> Result<PluginExecutionResult> {
    if manifest.stage != request.stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, request.stage
        )));
    }
    validate_plugin_request_contract(manifest, request)?;

    let raw = run_plugin_raw(manifest, request, policy)?;
    let response = parse_plugin_response(manifest, &raw.stdout)?;
    Ok(PluginExecutionResult {
        response,
        run: raw.metadata,
    })
}

/// Execute a plugin for multiple payloads with default execution policy.
pub fn run_plugin_batch(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
) -> Result<Vec<PluginResponse>> {
    run_plugin_batch_with_policy(manifest, stage, payloads, &PluginExecutionPolicy::default())
}

/// Execute a plugin for multiple payloads under the given execution policy.
pub fn run_plugin_batch_with_policy(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
    policy: &PluginExecutionPolicy,
) -> Result<Vec<PluginResponse>> {
    if payloads.is_empty() {
        return Ok(Vec::new());
    }
    Ok(run_plugin_batch_with_policy_and_metadata(manifest, stage, payloads, policy)?.responses)
}

/// Execute a plugin for multiple payloads under the given execution policy and return execution metadata.
pub fn run_plugin_batch_with_policy_and_metadata(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
    policy: &PluginExecutionPolicy,
) -> Result<PluginBatchExecutionResult> {
    if manifest.stage != stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, stage
        )));
    }
    if payloads.is_empty() {
        return Ok(PluginBatchExecutionResult {
            responses: Vec::new(),
            runs: Vec::new(),
            run: empty_plugin_batch_metadata(manifest, &stage, policy)?,
        });
    }
    if !manifest.supports_capability("batch_requests") {
        let mut responses = Vec::with_capacity(payloads.len());
        let mut runs = Vec::with_capacity(payloads.len());
        let mut last_run = None;
        for payload in payloads {
            validate_plugin_payload_contract(manifest, &stage, payload)?;
            let execution = run_plugin_with_policy_and_metadata(
                manifest,
                &PluginRequest {
                    protocol_version: "1".to_string(),
                    stage: stage.clone(),
                    payload: payload.clone(),
                },
                policy,
            )?;
            let run = execution.run;
            last_run = Some(run.clone());
            runs.push(run);
            responses.push(execution.response);
        }
        return Ok(PluginBatchExecutionResult {
            responses,
            runs,
            run: last_run.unwrap_or(empty_plugin_batch_metadata(manifest, &stage, policy)?),
        });
    }
    for payload in payloads {
        validate_plugin_payload_contract(manifest, &stage, payload)?;
    }

    let raw = run_plugin_raw(
        manifest,
        &PluginBatchRequest {
            protocol_version: "1".to_string(),
            stage: stage.clone(),
            payloads: payloads.to_vec(),
        },
        policy,
    )?;
    let batch: PluginBatchResponse = serde_json::from_str(&raw.stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid batch JSON: {}",
            manifest.name, err
        ))
    })?;
    if !batch.ok {
        if let Some(error) = &batch.error {
            return Err(LogicPearlError::message(format!(
                "plugin {} failed [{}]: {}",
                manifest.name, error.code, error.message
            )));
        }
        return Err(LogicPearlError::message(format!(
            "plugin {} returned ok=false without structured batch error",
            manifest.name
        )));
    }
    if batch.responses.len() != payloads.len() {
        return Err(LogicPearlError::message(format!(
            "plugin {} returned {} batch responses for {} payloads",
            manifest.name,
            batch.responses.len(),
            payloads.len()
        )));
    }
    for response in &batch.responses {
        validate_ok_plugin_response(manifest, response)?;
    }
    let runs = vec![raw.metadata.clone(); batch.responses.len()];
    Ok(PluginBatchExecutionResult {
        responses: batch.responses,
        runs,
        run: raw.metadata,
    })
}

fn empty_plugin_batch_metadata(
    manifest: &PluginManifest,
    stage: &PluginStage,
    policy: &PluginExecutionPolicy,
) -> Result<PluginRunMetadata> {
    let request = PluginBatchRequest {
        protocol_version: "1".to_string(),
        stage: stage.clone(),
        payloads: Vec::new(),
    };
    let request_value = serde_json::to_value(&request).map_err(LogicPearlError::from)?;
    build_plugin_run_metadata(PluginRunMetadataInputs {
        manifest,
        policy,
        resolved_entrypoint: &resolve_entrypoint(manifest, policy)?,
        request_value: &request_value,
        stdout: Vec::new(),
        stderr: Vec::new(),
        effective_timeout_ms: effective_timeout_ms(manifest, policy)?,
        started_at: now_utc_rfc3339(),
        completed_at: now_utc_rfc3339(),
        duration_ms: 0,
    })
}

#[cfg(test)]
mod tests;
