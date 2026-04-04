use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_plugin::PluginManifest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineDefinition {
    pub pipeline_version: String,
    pub pipeline_id: String,
    pub entrypoint: String,
    pub stages: Vec<PipelineStage>,
    pub output: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineStage {
    pub id: String,
    pub kind: PipelineStageKind,
    pub artifact: Option<String>,
    pub plugin_manifest: Option<String>,
    #[serde(default)]
    pub input: HashMap<String, Value>,
    #[serde(default)]
    pub export: HashMap<String, Value>,
    #[serde(default)]
    pub when: Option<Value>,
    #[serde(default)]
    pub foreach: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStageKind {
    Pearl,
    ObserverPlugin,
    EnricherPlugin,
    VerifyPlugin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedPipeline {
    pub pipeline_id: String,
    pub pipeline_version: String,
    pub entrypoint: String,
    pub stage_count: usize,
    pub stages: Vec<ValidatedStage>,
    pub exports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedStage {
    pub id: String,
    pub kind: PipelineStageKind,
    pub artifact: Option<String>,
    pub plugin_manifest: Option<String>,
    pub exports: Vec<String>,
}

impl PipelineDefinition {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let pipeline: Self = serde_json::from_str(input)?;
        Ok(pipeline)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    pub fn validate(&self, base_dir: impl AsRef<Path>) -> Result<ValidatedPipeline> {
        if self.pipeline_version != "1.0" {
            return Err(LogicPearlError::message(format!(
                "unsupported pipeline_version: {}",
                self.pipeline_version
            )));
        }
        if self.pipeline_id.trim().is_empty() {
            return Err(LogicPearlError::message(
                "pipeline_id must be non-empty",
            ));
        }
        if self.entrypoint.trim().is_empty() {
            return Err(LogicPearlError::message(
                "entrypoint must be non-empty",
            ));
        }
        if self.stages.is_empty() {
            return Err(LogicPearlError::message(
                "pipeline must define at least one stage",
            ));
        }
        if self.output.is_empty() {
            return Err(LogicPearlError::message(
                "pipeline output must define at least one field",
            ));
        }

        let base_dir = base_dir.as_ref();
        let mut stage_ids = BTreeSet::new();
        let mut visible_exports: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut validated_stages = Vec::with_capacity(self.stages.len());

        for stage in &self.stages {
            if stage.id.trim().is_empty() {
                return Err(LogicPearlError::message("stage id must be non-empty"));
            }
            if !stage_ids.insert(stage.id.clone()) {
                return Err(LogicPearlError::message(format!(
                    "duplicate stage id: {}",
                    stage.id
                )));
            }
            stage.validate(base_dir, &visible_exports)?;
            let export_names = stage.export.keys().cloned().collect::<BTreeSet<_>>();
            visible_exports.insert(stage.id.clone(), export_names.clone());
            validated_stages.push(ValidatedStage {
                id: stage.id.clone(),
                kind: stage.kind.clone(),
                artifact: stage
                    .artifact
                    .as_ref()
                    .map(|value| resolve_relative_path(base_dir, value).display().to_string()),
                plugin_manifest: stage
                    .plugin_manifest
                    .as_ref()
                    .map(|value| resolve_relative_path(base_dir, value).display().to_string()),
                exports: export_names.into_iter().collect(),
            });
        }

        for (field, value) in &self.output {
            if field.trim().is_empty() {
                return Err(LogicPearlError::message(
                    "pipeline output keys must be non-empty",
                ));
            }
            validate_value_reference(value, &visible_exports)?;
        }

        let exports = self.output.keys().cloned().collect();
        Ok(ValidatedPipeline {
            pipeline_id: self.pipeline_id.clone(),
            pipeline_version: self.pipeline_version.clone(),
            entrypoint: self.entrypoint.clone(),
            stage_count: self.stages.len(),
            stages: validated_stages,
            exports,
        })
    }
}

impl PipelineStage {
    fn validate(
        &self,
        base_dir: &Path,
        visible_exports: &HashMap<String, BTreeSet<String>>,
    ) -> Result<()> {
        match self.kind {
            PipelineStageKind::Pearl => {
                let artifact = self.artifact.as_ref().ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "stage {} of kind pearl requires artifact",
                        self.id
                    ))
                })?;
                if self.plugin_manifest.is_some() {
                    return Err(LogicPearlError::message(format!(
                        "stage {} of kind pearl must not set plugin_manifest",
                        self.id
                    )));
                }
                let artifact_path = resolve_relative_path(base_dir, artifact);
                if !artifact_path.exists() {
                    return Err(LogicPearlError::message(format!(
                        "stage {} artifact does not exist: {}",
                        self.id,
                        artifact_path.display()
                    )));
                }
                LogicPearlGateIr::from_path(&artifact_path)?;
            }
            PipelineStageKind::ObserverPlugin
            | PipelineStageKind::EnricherPlugin
            | PipelineStageKind::VerifyPlugin => {
                let manifest = self.plugin_manifest.as_ref().ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "stage {} of kind {:?} requires plugin_manifest",
                        self.id, self.kind
                    ))
                })?;
                if self.artifact.is_some() {
                    return Err(LogicPearlError::message(format!(
                        "stage {} plugin stage must not set artifact",
                        self.id
                    )));
                }
                let manifest_path = resolve_relative_path(base_dir, manifest);
                if !manifest_path.exists() {
                    return Err(LogicPearlError::message(format!(
                        "stage {} plugin manifest does not exist: {}",
                        self.id,
                        manifest_path.display()
                    )));
                }
                PluginManifest::from_path(&manifest_path)?;
            }
        }

        for (field, value) in &self.input {
            if field.trim().is_empty() {
                return Err(LogicPearlError::message(format!(
                    "stage {} input keys must be non-empty",
                    self.id
                )));
            }
            validate_value_reference(value, visible_exports)?;
        }
        for (field, value) in &self.export {
            if field.trim().is_empty() {
                return Err(LogicPearlError::message(format!(
                    "stage {} export keys must be non-empty",
                    self.id
                )));
            }
            validate_value_reference(value, visible_exports)?;
        }
        if let Some(value) = &self.when {
            validate_value_reference(value, visible_exports)?;
        }
        if let Some(value) = &self.foreach {
            validate_value_reference(value, visible_exports)?;
        }
        Ok(())
    }
}

fn resolve_relative_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    normalize_path(&joined)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn validate_value_reference(
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

#[cfg(test)]
mod tests {
    use super::{PipelineDefinition, PipelineStageKind};
    use std::path::Path;

    #[test]
    fn validates_basic_pipeline() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "authz",
                  "kind": "pearl",
                  "artifact": "../../../fixtures/ir/valid/auth-demo-v1.json",
                  "input": {
                    "member_age": "$.member.age"
                  },
                  "export": {
                    "bitmask": "$.bitmask"
                  }
                }
              ],
              "output": {
                "bitmask": "@authz.bitmask"
              }
            }"#,
        )
        .expect("pipeline parses");
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/pipelines/authz");
        let validated = pipeline.validate(base_dir).expect("pipeline validates");
        assert_eq!(validated.pipeline_id, "demo");
        assert_eq!(validated.stage_count, 1);
        assert_eq!(validated.stages[0].kind, PipelineStageKind::Pearl);
    }

    #[test]
    fn rejects_future_stage_reference() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "authz",
                  "kind": "pearl",
                  "artifact": "../../../fixtures/ir/valid/auth-demo-v1.json",
                  "input": {
                    "member_age": "@later.bitmask"
                  },
                  "export": {
                    "bitmask": "$.bitmask"
                  }
                }
              ],
              "output": {
                "bitmask": "@authz.bitmask"
              }
            }"#,
        )
        .expect("pipeline parses");
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/pipelines/authz");
        let err = pipeline.validate(base_dir).expect_err("validation should fail");
        assert!(err.to_string().contains("unknown or future stage"));
    }
}
