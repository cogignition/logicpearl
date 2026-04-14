// SPDX-License-Identifier: MIT
//! Application-facing loader and execution facade.
//!
//! This crate is the library entrypoint for services that want to run
//! LogicPearl bundles without invoking the CLI. It resolves artifact
//! manifests with the shared bundle path policy, loads gate, action, and
//! pipeline artifacts, and delegates deterministic evaluation to the runtime.
//! It does not learn new artifacts or execute build-time discovery.
//!
//! ```no_run
//! use logicpearl_engine::LogicPearlEngine;
//! use serde_json::json;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = LogicPearlEngine::from_path("artifacts/access_policy")?;
//! let result = engine.run_single_json(&json!({
//!     "clearance_ok": false,
//!     "mfa_enabled": true
//! }))?;
//! println!("{result:?}");
//! # Ok(())
//! # }
//! ```

use logicpearl_core::{
    load_artifact_bundle, ArtifactKind, LoadedArtifactBundle, LogicPearlError, Result,
};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use logicpearl_pipeline::{PipelineDefinition, PipelineExecution, PreparedPipeline};
use logicpearl_plugin::PluginExecutionPolicy;
use logicpearl_runtime::{
    evaluate_action_policy, evaluate_gate_with_explanation, parse_input_payload,
    ActionEvaluationResult, GateEvaluationResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

impl LogicPearlEngine {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_path_with_plugin_policy(path, PluginExecutionPolicy::default())
    }

    pub fn from_artifact_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bundle = load_artifact_bundle(path)?;
        Self::from_loaded_bundle(path, bundle, PluginExecutionPolicy::default())
    }

    pub fn from_pipeline_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_pipeline_path_with_plugin_policy(path, PluginExecutionPolicy::default())
    }

    pub fn from_path_with_plugin_policy(
        path: impl AsRef<Path>,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<Self> {
        let path = path.as_ref();
        let bundle = load_artifact_bundle(path)?;
        Self::from_loaded_bundle(path, bundle, plugin_policy)
    }

    pub fn from_pipeline_path_with_plugin_policy(
        path: impl AsRef<Path>,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<Self> {
        let path = path.as_ref();
        let bundle = load_artifact_bundle(path)?;
        if bundle.manifest.artifact_kind != ArtifactKind::Pipeline {
            return Err(LogicPearlError::message(format!(
                "{} resolved to a {:?} artifact, not a pipeline",
                path.display(),
                bundle.manifest.artifact_kind
            )));
        }
        let resolved_path = bundle.ir_path()?;
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

    fn from_loaded_bundle(
        source_path: &Path,
        bundle: LoadedArtifactBundle,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<Self> {
        let ir_path = bundle.ir_path()?;
        match bundle.manifest.artifact_kind {
            ArtifactKind::Gate => {
                let gate = LogicPearlGateIr::from_path(&ir_path)?;
                Ok(Self {
                    kind: EngineKind::Artifact,
                    source_path: source_path.to_path_buf(),
                    prepared: PreparedExecution::Artifact(PreparedArtifact { gate }),
                })
            }
            ArtifactKind::Action => {
                let policy = LogicPearlActionIr::from_path(&ir_path)?;
                Ok(Self {
                    kind: EngineKind::ActionArtifact,
                    source_path: source_path.to_path_buf(),
                    prepared: PreparedExecution::ActionArtifact(PreparedActionArtifact { policy }),
                })
            }
            ArtifactKind::Pipeline => {
                let pipeline = PipelineDefinition::from_path(&ir_path)?;
                let base_dir = ir_path.parent().unwrap_or_else(|| Path::new("."));
                let prepared = pipeline.prepare_with_plugin_policy(base_dir, plugin_policy)?;
                Ok(Self {
                    kind: EngineKind::Pipeline,
                    source_path: ir_path,
                    prepared: PreparedExecution::Pipeline(prepared),
                })
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    const ZERO_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

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
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "auth_demo_v1",
                "artifact_kind": "gate",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": ZERO_HASH,
                "files": {
                    "ir": "pearl.ir.json"
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
    fn loads_manifest_with_redundant_artifact_dir_prefix() {
        let repo_root = repo_root();
        let dir = tempdir().expect("tempdir should exist");
        let artifact_dir = dir.path().join("gate");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        let ir_path = repo_root.join("fixtures/ir/valid/auth-demo-v1.json");
        fs::copy(&ir_path, artifact_dir.join("pearl.ir.json")).expect("fixture should copy");
        fs::write(
            artifact_dir.join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "auth_demo_v1",
                "artifact_kind": "gate",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": ZERO_HASH,
                "files": {
                    "ir": "gate/pearl.ir.json"
                }
            }))
            .expect("manifest encodes"),
        )
        .expect("manifest writes");

        let engine =
            LogicPearlEngine::from_path(&artifact_dir).expect("prefixed manifest path loads");
        assert_eq!(engine.kind(), EngineKind::Artifact);
    }

    #[test]
    fn rejects_manifest_members_that_escape_artifact_dir() {
        let repo_root = repo_root();
        let dir = tempdir().expect("tempdir should exist");
        let artifact_dir = dir.path().join("gate");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        let outside = dir.path().join("outside.ir.json");
        fs::copy(
            repo_root.join("fixtures/ir/valid/auth-demo-v1.json"),
            &outside,
        )
        .expect("fixture should copy");
        fs::write(
            artifact_dir.join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "auth_demo_v1",
                "artifact_kind": "gate",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": ZERO_HASH,
                "files": {
                    "ir": outside.display().to_string()
                }
            }))
            .expect("manifest encodes"),
        )
        .expect("manifest writes");

        let err = LogicPearlEngine::from_path(&artifact_dir)
            .expect_err("absolute manifest member should fail")
            .to_string();
        assert!(err.contains("must be relative"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_manifest_member_symlinks_that_escape_artifact_dir() {
        let repo_root = repo_root();
        let dir = tempdir().expect("tempdir should exist");
        let artifact_dir = dir.path().join("gate");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        let outside = dir.path().join("outside.ir.json");
        fs::copy(
            repo_root.join("fixtures/ir/valid/auth-demo-v1.json"),
            &outside,
        )
        .expect("fixture should copy");
        std::os::unix::fs::symlink(&outside, artifact_dir.join("pearl.ir.json"))
            .expect("symlink should be created");
        fs::write(
            artifact_dir.join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "auth_demo_v1",
                "artifact_kind": "gate",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": ZERO_HASH,
                "files": {
                    "ir": "pearl.ir.json"
                }
            }))
            .expect("manifest encodes"),
        )
        .expect("manifest writes");

        let err = LogicPearlEngine::from_path(&artifact_dir)
            .expect_err("escaping symlink should fail")
            .to_string();
        assert!(err.contains("escapes bundle directory"));
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
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "garden_actions",
                "artifact_kind": "action",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": ZERO_HASH,
                "files": {
                    "ir": "pearl.ir.json",
                    "build_report": "action_report.json"
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
        let source_dir = repo_root.join("examples/pipelines/observer_membership_verify");
        let dir = tempdir().expect("tempdir should exist");
        fs::create_dir_all(dir.path().join("artifacts")).expect("artifact dir should exist");
        fs::create_dir_all(dir.path().join("plugins/python_observer"))
            .expect("observer plugin dir should exist");
        fs::create_dir_all(dir.path().join("plugins/python_pipeline_verify"))
            .expect("verify plugin dir should exist");
        fs::copy(
            source_dir.join("pipeline.json"),
            dir.path().join("pipeline.json"),
        )
        .expect("pipeline should copy");
        fs::copy(
            source_dir.join("artifacts/membership-demo-v1.json"),
            dir.path().join("artifacts/membership-demo-v1.json"),
        )
        .expect("artifact should copy");
        for file in ["manifest.json", "plugin.py"] {
            fs::copy(
                source_dir.join("plugins/python_observer").join(file),
                dir.path().join("plugins/python_observer").join(file),
            )
            .expect("observer plugin should copy");
            fs::copy(
                source_dir.join("plugins/python_pipeline_verify").join(file),
                dir.path().join("plugins/python_pipeline_verify").join(file),
            )
            .expect("verify plugin should copy");
        }
        fs::write(
            dir.path().join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": "logicpearl.artifact_manifest.v1",
                "artifact_id": "observer_membership_verify_pipeline",
                "artifact_kind": "pipeline",
                "engine_version": "0.1.5",
                "ir_version": "1.0",
                "created_at": "2026-04-12T00:00:00Z",
                "artifact_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "files": {
                    "ir": "pipeline.json"
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
