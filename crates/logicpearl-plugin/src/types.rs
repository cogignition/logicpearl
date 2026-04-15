// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{PluginRunMetadata, PluginStage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    pub protocol_version: String,
    pub stage: PluginStage,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBatchRequest {
    pub protocol_version: String,
    pub stage: PluginStage,
    pub payloads: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResponse {
    pub ok: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<PluginErrorPayload>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBatchResponse {
    pub ok: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<PluginErrorPayload>,
    #[serde(default)]
    pub responses: Vec<PluginResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionResult {
    pub response: PluginResponse,
    pub run: PluginRunMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBatchExecutionResult {
    pub responses: Vec<PluginResponse>,
    #[serde(default)]
    pub runs: Vec<PluginRunMetadata>,
    pub run: PluginRunMetadata,
}
