use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginStage {
    Observer,
    TraceSource,
    Enricher,
    Verify,
    Render,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub protocol_version: String,
    pub stage: PluginStage,
    pub entrypoint: Vec<String>,
    pub language: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub timeout_ms: Option<u64>,
    #[serde(skip)]
    pub manifest_dir: Option<PathBuf>,
}

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

impl PluginManifest {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut manifest: Self = serde_json::from_str(&content)?;
        manifest.manifest_dir = path.parent().map(Path::to_path_buf);
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(LogicPearlError::message(
                "plugin manifest name must be non-empty",
            ));
        }
        if self.protocol_version != "1" {
            return Err(LogicPearlError::message(format!(
                "unsupported plugin protocol_version: {}",
                self.protocol_version
            )));
        }
        if self.entrypoint.is_empty() {
            return Err(LogicPearlError::message(
                "plugin manifest entrypoint must contain at least one command segment",
            ));
        }
        Ok(())
    }

    pub fn supports_capability(&self, capability: &str) -> bool {
        self.capabilities
            .as_ref()
            .map(|caps| caps.iter().any(|item| item == capability))
            .unwrap_or(false)
    }
}

pub fn run_plugin(manifest: &PluginManifest, request: &PluginRequest) -> Result<PluginResponse> {
    if manifest.stage != request.stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, request.stage
        )));
    }

    let stdout = run_plugin_raw(manifest, request)?;
    parse_plugin_response(manifest, &stdout)
}

pub fn run_plugin_batch(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
) -> Result<Vec<PluginResponse>> {
    if manifest.stage != stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, stage
        )));
    }
    if payloads.is_empty() {
        return Ok(Vec::new());
    }
    if !manifest.supports_capability("batch_requests") {
        return payloads
            .iter()
            .map(|payload| {
                run_plugin(
                    manifest,
                    &PluginRequest {
                        protocol_version: "1".to_string(),
                        stage: stage.clone(),
                        payload: payload.clone(),
                    },
                )
            })
            .collect();
    }

    let stdout = run_plugin_raw(
        manifest,
        &PluginBatchRequest {
            protocol_version: "1".to_string(),
            stage: stage.clone(),
            payloads: payloads.to_vec(),
        },
    )?;
    let batch: PluginBatchResponse = serde_json::from_str(&stdout).map_err(|err| {
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
    Ok(batch.responses)
}

fn run_plugin_raw<T: Serialize>(manifest: &PluginManifest, request: &T) -> Result<String> {
    let program = manifest
        .entrypoint
        .first()
        .ok_or_else(|| LogicPearlError::message("plugin entrypoint is empty"))?;
    let resolved_program = resolve_entrypoint_segment(manifest, program, true);
    let mut command = Command::new(&resolved_program);
    if manifest.entrypoint.len() > 1 {
        let args: Vec<String> = manifest.entrypoint[1..]
            .iter()
            .map(|segment| resolve_entrypoint_segment(manifest, segment, false))
            .collect();
        command.args(&args);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| LogicPearlError::message("failed to open plugin stdin"))?;
    let payload = serde_json::to_vec(request)?;
    stdin.write_all(&payload)?;
    stdin.write_all(b"\n")?;
    drop(child.stdin.take());

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(LogicPearlError::message(format!(
            "plugin {} exited with status {}{}",
            manifest.name,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )));
    }

    String::from_utf8(output.stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid UTF-8: {}",
            manifest.name, err
        ))
    })
}

fn parse_plugin_response(manifest: &PluginManifest, stdout: &str) -> Result<PluginResponse> {
    let response: PluginResponse = serde_json::from_str(stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid JSON: {}",
            manifest.name, err
        ))
    })?;
    validate_ok_plugin_response(manifest, &response)?;
    Ok(response)
}

fn validate_ok_plugin_response(manifest: &PluginManifest, response: &PluginResponse) -> Result<()> {
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
    Ok(())
}

fn resolve_entrypoint_segment(
    manifest: &PluginManifest,
    segment: &str,
    executable: bool,
) -> String {
    if let Some(dir) = &manifest.manifest_dir {
        let candidate = dir.join(segment);
        if candidate.exists() {
            return candidate.display().to_string();
        }
        if executable && !segment.contains(std::path::MAIN_SEPARATOR) {
            return segment.to_string();
        }
    }
    segment.to_string()
}

#[cfg(test)]
mod tests {
    use super::{PluginManifest, PluginStage};

    #[test]
    fn validates_basic_manifest() {
        let manifest = PluginManifest {
            name: "demo".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
            language: Some("python".to_string()),
            capabilities: None,
            timeout_ms: None,
            manifest_dir: None,
        };
        assert!(manifest.validate().is_ok());
    }
}
