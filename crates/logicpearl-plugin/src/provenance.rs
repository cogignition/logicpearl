// SPDX-License-Identifier: MIT
use super::{PluginExecutionPolicy, PluginManifest, PluginStage, ResolvedPluginEntrypoint};
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRunMetadata {
    pub schema_version: String,
    pub plugin_run_id: String,
    pub plugin_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    pub plugin_name: String,
    pub stage: PluginStage,
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub entrypoint_hash: String,
    pub entrypoint: PluginEntrypointMetadata,
    pub request_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    pub output_hash: String,
    pub timeout_policy: PluginTimeoutPolicyMetadata,
    pub execution_policy: PluginExecutionPolicyMetadata,
    pub capabilities: PluginCapabilityMetadata,
    pub access: PluginAccessMetadata,
    pub stdio: PluginStdioMetadata,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntrypointMetadata {
    pub declared: Vec<String>,
    pub resolved: Vec<String>,
    #[serde(default)]
    pub hashes: Vec<PluginEntrypointSegmentHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntrypointSegmentHash {
    pub index: usize,
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTimeoutPolicyMetadata {
    pub manifest_timeout_ms: Option<u64>,
    pub default_timeout_ms: u64,
    pub effective_timeout_ms: Option<u64>,
    pub allow_no_timeout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionPolicyMetadata {
    pub allow_absolute_entrypoint: bool,
    pub allow_path_lookup: bool,
    pub allow_no_timeout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilityMetadata {
    #[serde(default)]
    pub declared: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub enforced: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAccessMetadata {
    pub network: String,
    pub filesystem: String,
    pub enforcement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStdioMetadata {
    pub stdout_hash: String,
    pub stdout_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_summary: Option<String>,
    pub stderr_hash: String,
    pub stderr_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_summary: Option<String>,
}

pub(crate) struct PluginRunMetadataInputs<'a> {
    pub(crate) manifest: &'a PluginManifest,
    pub(crate) policy: &'a PluginExecutionPolicy,
    pub(crate) resolved_entrypoint: &'a ResolvedPluginEntrypoint,
    pub(crate) request_value: &'a Value,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) effective_timeout_ms: Option<u64>,
    pub(crate) started_at: String,
    pub(crate) completed_at: String,
    pub(crate) duration_ms: u64,
}

pub(crate) fn build_plugin_run_metadata(
    inputs: PluginRunMetadataInputs<'_>,
) -> Result<PluginRunMetadata> {
    let manifest = inputs.manifest;
    let policy = inputs.policy;
    let entrypoint = build_entrypoint_metadata(manifest, inputs.resolved_entrypoint);
    let entrypoint_hash = hash_serializable(&entrypoint)?;
    let request_hash = hash_serializable(inputs.request_value)?;
    let input_hash = inputs
        .request_value
        .get("payload")
        .and_then(|payload| payload.get("input"))
        .map(hash_serializable)
        .transpose()?;
    let output_hash = sha256_prefixed(&inputs.stdout);
    let manifest_hash = manifest
        .manifest_path
        .as_ref()
        .and_then(|path| sha256_prefixed_file(path).ok());
    let plugin_id = manifest
        .plugin_id
        .clone()
        .unwrap_or_else(|| manifest.name.clone());
    let protocol_version = inputs
        .request_value
        .get("protocol_version")
        .and_then(Value::as_str)
        .unwrap_or(&manifest.protocol_version)
        .to_string();
    let declared_capabilities = manifest.capabilities.clone().unwrap_or_default();
    let enforced_capabilities = enforced_capabilities_for_request(manifest, inputs.request_value);
    let stdout_hash = output_hash.clone();
    let stderr_hash = sha256_prefixed(&inputs.stderr);
    let mut metadata = PluginRunMetadata {
        schema_version: "logicpearl.plugin_run_provenance.v1".to_string(),
        plugin_run_id: String::new(),
        plugin_id,
        plugin_version: manifest.plugin_version.clone(),
        plugin_name: manifest.name.clone(),
        stage: manifest.stage.clone(),
        protocol_version,
        manifest_path: manifest
            .manifest_path
            .as_ref()
            .map(|path| path.display().to_string()),
        manifest_hash,
        entrypoint_hash,
        entrypoint,
        request_hash,
        input_hash,
        output_hash,
        timeout_policy: PluginTimeoutPolicyMetadata {
            manifest_timeout_ms: manifest.timeout_ms,
            default_timeout_ms: policy.default_timeout_ms,
            effective_timeout_ms: inputs.effective_timeout_ms,
            allow_no_timeout: policy.allow_no_timeout,
        },
        execution_policy: PluginExecutionPolicyMetadata {
            allow_absolute_entrypoint: policy.allow_absolute_entrypoint,
            allow_path_lookup: policy.allow_path_lookup,
            allow_no_timeout: policy.allow_no_timeout,
        },
        capabilities: PluginCapabilityMetadata {
            declared: declared_capabilities.clone(),
            allowed: declared_capabilities,
            enforced: enforced_capabilities,
        },
        access: PluginAccessMetadata {
            network: "not_enforced".to_string(),
            filesystem: "process_default".to_string(),
            enforcement: "none".to_string(),
        },
        stdio: PluginStdioMetadata {
            stdout_hash,
            stdout_bytes: inputs.stdout.len(),
            stdout_summary: (!inputs.stdout.is_empty())
                .then(|| redacted_hash_summary(&inputs.stdout)),
            stderr_hash,
            stderr_bytes: inputs.stderr.len(),
            stderr_summary: (!inputs.stderr.is_empty())
                .then(|| redacted_hash_summary(&inputs.stderr)),
        },
        started_at: inputs.started_at,
        completed_at: inputs.completed_at,
        duration_ms: inputs.duration_ms,
    };
    metadata.plugin_run_id = build_plugin_run_id(&metadata)?;
    Ok(metadata)
}

fn build_entrypoint_metadata(
    manifest: &PluginManifest,
    resolved_entrypoint: &ResolvedPluginEntrypoint,
) -> PluginEntrypointMetadata {
    let resolved = resolved_entrypoint.segments();
    let hashes = resolved
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| {
            let path = Path::new(segment);
            if !path.is_file() {
                return None;
            }
            sha256_prefixed_file(path)
                .ok()
                .map(|hash| PluginEntrypointSegmentHash {
                    index,
                    path: segment.clone(),
                    hash,
                })
        })
        .collect();

    PluginEntrypointMetadata {
        declared: manifest.entrypoint.clone(),
        resolved,
        hashes,
    }
}

fn enforced_capabilities_for_request(
    manifest: &PluginManifest,
    request_value: &Value,
) -> Vec<String> {
    if request_value.get("payloads").is_some() && manifest.supports_capability("batch_requests") {
        vec!["batch_requests".to_string()]
    } else {
        Vec::new()
    }
}

fn build_plugin_run_id(metadata: &PluginRunMetadata) -> Result<String> {
    hash_serializable(&serde_json::json!({
        "schema_version": metadata.schema_version,
        "plugin_id": metadata.plugin_id,
        "plugin_version": metadata.plugin_version,
        "plugin_name": metadata.plugin_name,
        "stage": metadata.stage,
        "protocol_version": metadata.protocol_version,
        "manifest_hash": metadata.manifest_hash,
        "entrypoint_hash": metadata.entrypoint_hash,
        "request_hash": metadata.request_hash,
        "output_hash": metadata.output_hash,
        "started_at": metadata.started_at,
        "completed_at": metadata.completed_at,
    }))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_prefixed(&bytes))
        .map_err(LogicPearlError::from)
}

fn sha256_prefixed_file(path: &Path) -> std::io::Result<String> {
    std::fs::read(path).map(|bytes| sha256_prefixed(&bytes))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn redacted_hash_summary(bytes: &[u8]) -> String {
    format!("<redacted:{}>", sha256_prefixed(bytes))
}

pub(crate) fn now_utc_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
