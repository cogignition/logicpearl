// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use logicpearl_pipeline::{PipelineDefinition, PipelineExecution, PreparedPipeline};
use logicpearl_plugin::PluginExecutionPolicy;
use logicpearl_runtime::{
    evaluate_action_policy, evaluate_gate_with_explanation, parse_input_payload,
    ActionEvaluationResult, GateEvaluationResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    Artifact,
    ActionArtifact,
    Pipeline,
}

pub type ArtifactEvaluation = GateEvaluationResult;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactExecution {
    pub gate_id: String,
    pub evaluation: ArtifactEvaluation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactBatchExecution {
    pub gate_id: String,
    pub evaluations: Vec<ArtifactEvaluation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionArtifactExecution {
    pub action_policy_id: String,
    pub evaluation: ActionEvaluationResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionArtifactBatchExecution {
    pub action_policy_id: String,
    pub evaluations: Vec<ActionEvaluationResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineSingleExecution {
    Artifact(ArtifactExecution),
    ActionArtifact(ActionArtifactExecution),
    Pipeline(PipelineExecution),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineBatchExecution {
    Artifact(ArtifactBatchExecution),
    ActionArtifact(ActionArtifactBatchExecution),
    Pipeline(Vec<PipelineExecution>),
}

#[derive(Debug, Clone)]
pub struct LogicPearlEngine {
    kind: EngineKind,
    source_path: PathBuf,
    prepared: PreparedExecution,
}

#[derive(Debug, Clone)]
enum PreparedExecution {
    Artifact(PreparedArtifact),
    ActionArtifact(PreparedActionArtifact),
    Pipeline(PreparedPipeline),
}

#[derive(Debug, Clone)]
struct PreparedArtifact {
    gate: LogicPearlGateIr,
}

#[derive(Debug, Clone)]
struct PreparedActionArtifact {
    policy: LogicPearlActionIr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedArtifactManifest {
    files: NamedArtifactFiles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedArtifactFiles {
    #[serde(alias = "ir")]
    pearl_ir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActionArtifactManifest {
    artifact_kind: String,
    files: ActionArtifactFiles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActionArtifactFiles {
    #[serde(alias = "ir")]
    pearl_ir: String,
}

impl LogicPearlEngine {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if looks_like_pipeline_path(path) {
            return Self::from_pipeline_path(path);
        }
        if let Some(pipeline_path) = resolve_pipeline_manifest_input(path)? {
            return Self::from_pipeline_path(pipeline_path);
        }
        if looks_like_artifact_path(path) {
            return Self::from_artifact_path(path);
        }

        if path.is_file() {
            let content = fs::read_to_string(path)?;
            let value: Value = serde_json::from_str(&content)?;
            if value.get("pipeline_version").is_some() {
                return Self::from_pipeline_path(path);
            }
            if value.get("ir_version").is_some() || value.get("files").is_some() {
                return Self::from_artifact_path(path);
            }
        }

        if path.is_dir() {
            if path.join("pipeline.json").exists() {
                return Self::from_pipeline_path(path.join("pipeline.json"));
            }
            if path.join("artifact.json").exists() || path.join("pearl.ir.json").exists() {
                return Self::from_artifact_path(path);
            }
        }

        Err(LogicPearlError::message(format!(
            "could not determine whether {} is a LogicPearl artifact or pipeline",
            path.display()
        )))
    }

    pub fn from_artifact_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(action_policy_ir) = resolve_action_artifact_input(path)? {
            let policy = LogicPearlActionIr::from_path(&action_policy_ir)?;
            return Ok(Self {
                kind: EngineKind::ActionArtifact,
                source_path: path.to_path_buf(),
                prepared: PreparedExecution::ActionArtifact(PreparedActionArtifact { policy }),
            });
        }
        let resolved = resolve_artifact_input(path)?;
        let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)?;
        Ok(Self {
            kind: EngineKind::Artifact,
            source_path: path.to_path_buf(),
            prepared: PreparedExecution::Artifact(PreparedArtifact { gate }),
        })
    }

    pub fn from_pipeline_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_pipeline_path_with_plugin_policy(path, PluginExecutionPolicy::default())
    }

    pub fn from_path_with_plugin_policy(
        path: impl AsRef<Path>,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<Self> {
        let path = path.as_ref();
        if looks_like_pipeline_path(path) {
            return Self::from_pipeline_path_with_plugin_policy(path, plugin_policy);
        }
        if let Some(pipeline_path) = resolve_pipeline_manifest_input(path)? {
            return Self::from_pipeline_path_with_plugin_policy(pipeline_path, plugin_policy);
        }
        if looks_like_artifact_path(path) {
            return Self::from_artifact_path(path);
        }

        if path.is_file() {
            let content = fs::read_to_string(path)?;
            let value: Value = serde_json::from_str(&content)?;
            if value.get("pipeline_version").is_some() {
                return Self::from_pipeline_path_with_plugin_policy(path, plugin_policy);
            }
            if value.get("ir_version").is_some() || value.get("files").is_some() {
                return Self::from_artifact_path(path);
            }
        }

        if path.is_dir() {
            if path.join("pipeline.json").exists() {
                return Self::from_pipeline_path_with_plugin_policy(
                    path.join("pipeline.json"),
                    plugin_policy,
                );
            }
            if path.join("artifact.json").exists() || path.join("pearl.ir.json").exists() {
                return Self::from_artifact_path(path);
            }
        }

        Err(LogicPearlError::message(format!(
            "could not determine whether {} is a LogicPearl artifact or pipeline",
            path.display()
        )))
    }

    pub fn from_pipeline_path_with_plugin_policy(
        path: impl AsRef<Path>,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<Self> {
        let path = path.as_ref();
        let resolved_path = if path.is_dir() {
            path.join("pipeline.json")
        } else {
            path.to_path_buf()
        };
        let pipeline = PipelineDefinition::from_path(&resolved_path)?;
        let base_dir = resolved_path.parent().unwrap_or_else(|| Path::new("."));
        let prepared = pipeline.prepare_with_plugin_policy(base_dir, plugin_policy)?;
        Ok(Self {
            kind: EngineKind::Pipeline,
            source_path: resolved_path,
            prepared: PreparedExecution::Pipeline(prepared),
        })
    }

    pub fn kind(&self) -> EngineKind {
        self.kind
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn run_single_json(&self, input: &Value) -> Result<EngineSingleExecution> {
        match &self.prepared {
            PreparedExecution::Artifact(artifact) => {
                Ok(EngineSingleExecution::Artifact(ArtifactExecution {
                    gate_id: artifact.gate.gate_id.clone(),
                    evaluation: evaluate_artifact_single(&artifact.gate, input)?,
                }))
            }
            PreparedExecution::ActionArtifact(artifact) => Ok(
                EngineSingleExecution::ActionArtifact(ActionArtifactExecution {
                    action_policy_id: artifact.policy.action_policy_id.clone(),
                    evaluation: evaluate_action_artifact_single(&artifact.policy, input)?,
                }),
            ),
            PreparedExecution::Pipeline(pipeline) => {
                Ok(EngineSingleExecution::Pipeline(pipeline.run(input)?))
            }
        }
    }

    pub fn run_batch_json(&self, inputs: &[Value]) -> Result<EngineBatchExecution> {
        match &self.prepared {
            PreparedExecution::Artifact(artifact) => {
                Ok(EngineBatchExecution::Artifact(ArtifactBatchExecution {
                    gate_id: artifact.gate.gate_id.clone(),
                    evaluations: inputs
                        .iter()
                        .map(|input| evaluate_artifact_single(&artifact.gate, input))
                        .collect::<Result<Vec<_>>>()?,
                }))
            }
            PreparedExecution::ActionArtifact(artifact) => Ok(
                EngineBatchExecution::ActionArtifact(ActionArtifactBatchExecution {
                    action_policy_id: artifact.policy.action_policy_id.clone(),
                    evaluations: inputs
                        .iter()
                        .map(|input| evaluate_action_artifact_single(&artifact.policy, input))
                        .collect::<Result<Vec<_>>>()?,
                }),
            ),
            PreparedExecution::Pipeline(pipeline) => {
                Ok(EngineBatchExecution::Pipeline(pipeline.run_batch(inputs)?))
            }
        }
    }

    pub fn run_json_value(&self, input: &Value) -> Result<EngineExecutionEnvelope> {
        match input {
            Value::Array(items) => self
                .run_batch_json(items)
                .map(EngineExecutionEnvelope::Batch),
            _ => self
                .run_single_json(input)
                .map(|execution| EngineExecutionEnvelope::Single(Box::new(execution))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EngineExecutionEnvelope {
    Single(Box<EngineSingleExecution>),
    Batch(EngineBatchExecution),
}

fn evaluate_artifact_single(gate: &LogicPearlGateIr, input: &Value) -> Result<ArtifactEvaluation> {
    let parsed = parse_input_payload(input.clone())?;
    if parsed.len() != 1 {
        return Err(LogicPearlError::message(
            "artifact single execution expects one feature object",
        ));
    }
    evaluate_gate_with_explanation(gate, &parsed[0])
}

fn evaluate_action_artifact_single(
    policy: &LogicPearlActionIr,
    input: &Value,
) -> Result<ActionEvaluationResult> {
    let parsed = parse_input_payload(input.clone())?;
    if parsed.len() != 1 {
        return Err(LogicPearlError::message(
            "action artifact single execution expects one feature object",
        ));
    }
    evaluate_action_policy(policy, &parsed[0])
}

#[derive(Debug, Clone)]
struct ResolvedArtifactInput {
    pearl_ir: PathBuf,
}

fn resolve_action_artifact_input(path: &Path) -> Result<Option<PathBuf>> {
    if path.is_dir() {
        let manifest_path = path.join("artifact.json");
        if manifest_path.exists() {
            return resolve_action_manifest_input(&manifest_path);
        }
        let pearl_ir = path.join("pearl.ir.json");
        if pearl_ir.exists() && is_action_policy_ir(&pearl_ir)? {
            return Ok(Some(pearl_ir));
        }
        return Ok(None);
    }

    if path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        return resolve_action_manifest_input(path);
    }

    if path.is_file() && is_action_policy_ir(path)? {
        return Ok(Some(path.to_path_buf()));
    }

    Ok(None)
}

fn resolve_pipeline_manifest_input(path: &Path) -> Result<Option<PathBuf>> {
    let manifest_path = if path.is_dir() {
        let candidate = path.join("artifact.json");
        if candidate.exists() {
            candidate
        } else {
            return Ok(None);
        }
    } else if path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        path.to_path_buf()
    } else {
        return Ok(None);
    };
    let content = fs::read_to_string(&manifest_path)?;
    let value: Value = serde_json::from_str(&content)?;
    if value.get("artifact_kind").and_then(Value::as_str) != Some("pipeline") {
        return Ok(None);
    }
    let ir = value
        .get("files")
        .and_then(|files| files.get("ir").or_else(|| files.get("pearl_ir")))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LogicPearlError::message("pipeline artifact manifest is missing files.ir")
        })?;
    Ok(Some(resolve_manifest_path(&manifest_path, ir)))
}

fn resolve_action_manifest_input(manifest_path: &Path) -> Result<Option<PathBuf>> {
    let content = fs::read_to_string(manifest_path)?;
    let value: Value = serde_json::from_str(&content)?;
    if !matches!(
        value.get("artifact_kind").and_then(Value::as_str),
        Some("action") | Some("action_policy")
    ) {
        return Ok(None);
    }
    let manifest: ActionArtifactManifest = serde_json::from_value(value)?;
    Ok(Some(resolve_manifest_path(
        manifest_path,
        &manifest.files.pearl_ir,
    )))
}

fn is_action_policy_ir(path: &Path) -> Result<bool> {
    let content = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&content)?;
    Ok(value.get("action_policy_id").is_some())
}

fn resolve_artifact_input(path: &Path) -> Result<ResolvedArtifactInput> {
    if path.is_dir() {
        let manifest_path = path.join("artifact.json");
        if manifest_path.exists() {
            let manifest = load_named_artifact_manifest(&manifest_path)?;
            return Ok(ResolvedArtifactInput {
                pearl_ir: resolve_manifest_path(&manifest_path, &manifest.files.pearl_ir),
            });
        }
        let pearl_ir = path.join("pearl.ir.json");
        if pearl_ir.exists() {
            return Ok(ResolvedArtifactInput { pearl_ir });
        }
        return Err(LogicPearlError::message(format!(
            "artifact directory {} is missing artifact.json and pearl.ir.json",
            path.display()
        )));
    }

    if path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        let manifest = load_named_artifact_manifest(path)?;
        return Ok(ResolvedArtifactInput {
            pearl_ir: resolve_manifest_path(path, &manifest.files.pearl_ir),
        });
    }

    Ok(ResolvedArtifactInput {
        pearl_ir: path.to_path_buf(),
    })
}

fn load_named_artifact_manifest(path: &Path) -> Result<NamedArtifactManifest> {
    let content = fs::read_to_string(path)?;
    let manifest = serde_json::from_str(&content)?;
    Ok(manifest)
}

fn resolve_manifest_path(manifest_path: &Path, value: &str) -> PathBuf {
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn looks_like_pipeline_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.ends_with(".pipeline.json") || name == "pipeline.json")
}

fn looks_like_artifact_path(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("artifact.json").exists() || path.join("pearl.ir.json").exists();
    }
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            name == "artifact.json" || name == "pearl.ir.json" || name.ends_with(".ir.json")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("crate should live under workspace/crates/logicpearl-engine")
            .to_path_buf()
    }

    #[test]
    fn loads_and_runs_artifact_from_direct_ir_path() {
        let repo_root = repo_root();
        let artifact = repo_root.join("fixtures/ir/valid/auth-demo-v1.json");
        let engine = LogicPearlEngine::from_artifact_path(&artifact).expect("artifact loads");
        let result = engine
            .run_single_json(&json!({
                "action": "delete",
                "resource_archived": true,
                "user_role": "viewer",
                "failed_attempts": 99
            }))
            .expect("artifact runs");
        match result {
            EngineSingleExecution::Artifact(output) => {
                assert_eq!(output.gate_id, "auth_demo_v1");
                assert!(!output.evaluation.allow);
                assert_eq!(output.evaluation.bitmask.as_u64(), Some(7));
            }
            _ => panic!("expected artifact result"),
        }
    }

    #[test]
    fn loads_artifact_from_manifest() {
        let repo_root = repo_root();
        let dir = tempdir().expect("tempdir should exist");
        let ir_path = repo_root.join("fixtures/ir/valid/auth-demo-v1.json");
        fs::copy(&ir_path, dir.path().join("pearl.ir.json")).expect("fixture should copy");
        fs::write(
            dir.path().join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "artifact_version": "1.0",
                "artifact_name": "auth-demo",
                "gate_id": "auth_demo_v1",
                "files": {
                    "pearl_ir": "pearl.ir.json"
                }
            }))
            .expect("manifest encodes"),
        )
        .expect("manifest writes");

        let engine =
            LogicPearlEngine::from_path(dir.path()).expect("manifest-backed artifact loads");
        assert_eq!(engine.kind(), EngineKind::Artifact);
    }

    #[test]
    fn loads_and_runs_action_artifact_from_manifest() {
        let dir = tempdir().expect("tempdir should exist");
        fs::write(
            dir.path().join("pearl.ir.json"),
            serde_json::to_string_pretty(&json!({
                "ir_version": "1.0",
                "action_policy_id": "garden_actions",
                "action_policy_type": "priority_rules",
                "action_column": "next_action",
                "default_action": "do_nothing",
                "actions": ["do_nothing", "water"],
                "input_schema": {
                    "features": [
                        {"id": "soil_moisture_pct", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null}
                    ]
                },
                "rules": [
                    {
                        "id": "rule_000",
                        "bit": 0,
                        "action": "water",
                        "priority": 0,
                        "when": {"feature": "soil_moisture_pct", "op": "<=", "value": 0.18},
                        "label": "Soil is dry",
                        "message": null,
                        "severity": null,
                        "counterfactual_hint": null,
                        "verification_status": null
                    }
                ],
                "evaluation": {"selection": "first_match"},
                "verification": null,
                "provenance": null
            }))
            .expect("action policy encodes"),
        )
        .expect("action policy writes");
        fs::write(
            dir.path().join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "artifact_version": "1.0",
                "artifact_kind": "action_policy",
                "artifact_name": "garden_actions",
                "action_column": "next_action",
                "default_action": "do_nothing",
                "actions": ["do_nothing", "water"],
                "files": {
                    "pearl_ir": "pearl.ir.json",
                    "action_report": "action_report.json"
                }
            }))
            .expect("manifest encodes"),
        )
        .expect("manifest writes");

        let engine = LogicPearlEngine::from_path(dir.path()).expect("action artifact should load");
        assert_eq!(engine.kind(), EngineKind::ActionArtifact);
        let result = engine
            .run_single_json(&json!({"soil_moisture_pct": "14%"}))
            .expect("action artifact should run");
        match result {
            EngineSingleExecution::ActionArtifact(output) => {
                assert_eq!(output.action_policy_id, "garden_actions");
                assert_eq!(output.evaluation.action, "water");
                assert_eq!(output.evaluation.bitmask.as_u64(), Some(1));
            }
            _ => panic!("expected action artifact result"),
        }
    }

    #[test]
    fn loads_and_runs_pipeline() {
        let repo_root = repo_root();
        let pipeline =
            repo_root.join("examples/pipelines/observer_membership_verify/pipeline.json");
        let input = json!({
            "age": 34,
            "member": true,
            "country": "US"
        });
        let engine = LogicPearlEngine::from_path(&pipeline).expect("pipeline loads");
        let result = engine.run_single_json(&input).expect("pipeline runs");
        match result {
            EngineSingleExecution::Pipeline(output) => {
                assert_eq!(output.output.get("allow"), Some(&json!(true)));
                assert_eq!(
                    output.output.get("audit_status"),
                    Some(&json!("clean_pass"))
                );
            }
            _ => panic!("expected pipeline result"),
        }
    }

    #[test]
    fn loads_and_runs_pipeline_from_artifact_manifest_v1() {
        let repo_root = repo_root();
        let pipeline =
            repo_root.join("examples/pipelines/observer_membership_verify/pipeline.json");
        let dir = tempdir().expect("tempdir should exist");
        fs::write(
            dir.path().join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "observer_membership_verify",
                "artifact_kind": "pipeline",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "files": {
                    "ir": pipeline.display().to_string()
                }
            }))
            .expect("manifest encodes"),
        )
        .expect("manifest writes");

        let input = json!({
            "age": 34,
            "member": true,
            "country": "US"
        });
        let engine = LogicPearlEngine::from_path(dir.path()).expect("pipeline manifest loads");
        assert_eq!(engine.kind(), EngineKind::Pipeline);
        let result = engine.run_single_json(&input).expect("pipeline runs");
        match result {
            EngineSingleExecution::Pipeline(output) => {
                assert_eq!(output.output.get("allow"), Some(&json!(true)));
            }
            _ => panic!("expected pipeline result"),
        }
    }
}
