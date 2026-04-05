use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_plugin::{run_plugin, PluginManifest, PluginRequest, PluginResponse, PluginStage};
use serde::{Deserialize, Serialize};
use serde_json::Map;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineExecution {
    pub pipeline_id: String,
    pub ok: bool,
    pub output: HashMap<String, Value>,
    pub stages: Vec<StageExecution>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StageExecution {
    pub id: String,
    pub kind: PipelineStageKind,
    pub ok: bool,
    pub skipped: bool,
    pub exports: HashMap<String, Value>,
    pub raw_result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComposePlan {
    pub pipeline: PipelineDefinition,
    pub notes: Vec<String>,
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

    pub fn inspect(&self, base_dir: impl AsRef<Path>) -> Result<ValidatedPipeline> {
        self.validate(base_dir)
    }

    pub fn run(&self, base_dir: impl AsRef<Path>, root_input: &Value) -> Result<PipelineExecution> {
        self.validate(&base_dir)?;

        let base_dir = base_dir.as_ref();
        let mut stage_exports: HashMap<String, HashMap<String, Value>> = HashMap::new();
        let mut stages = Vec::with_capacity(self.stages.len());

        for stage in &self.stages {
            let should_run = match &stage.when {
                Some(condition) => truthy(&resolve_stage_input_value(condition, root_input, &stage_exports)?),
                None => true,
            };

            if !should_run {
                stages.push(StageExecution {
                    id: stage.id.clone(),
                    kind: stage.kind.clone(),
                    ok: true,
                    skipped: true,
                    exports: HashMap::new(),
                    raw_result: Value::Null,
                });
                stage_exports.insert(stage.id.clone(), HashMap::new());
                continue;
            }

            let raw_result = match stage.kind {
                PipelineStageKind::Pearl => {
                    let artifact_path = resolve_relative_path(
                        base_dir,
                        stage.artifact.as_ref().expect("validated pearl artifact"),
                    );
                    let gate = LogicPearlGateIr::from_path(&artifact_path)?;
                    let features = build_stage_input_object(&stage.input, root_input, &stage_exports)?;
                    let bitmask = logicpearl_runtime::evaluate_gate(&gate, &features)?;
                    Value::Object(
                        Map::from_iter([
                            ("gate_id".to_string(), Value::String(gate.gate_id.clone())),
                            ("bitmask".to_string(), Value::Number(bitmask.into())),
                            (
                                "allow".to_string(),
                                Value::Bool(bitmask == gate.evaluation.allow_when_bitmask),
                            ),
                        ]),
                    )
                }
                PipelineStageKind::ObserverPlugin => {
                    run_observer_plugin_stage(stage, base_dir, root_input, &stage_exports)?
                }
                PipelineStageKind::EnricherPlugin | PipelineStageKind::VerifyPlugin => {
                    run_generic_plugin_stage(stage, base_dir, root_input, &stage_exports)?
                }
            };

            let exports = build_stage_exports(&stage.export, &raw_result)?;
            stage_exports.insert(stage.id.clone(), exports.clone());
            stages.push(StageExecution {
                id: stage.id.clone(),
                kind: stage.kind.clone(),
                ok: true,
                skipped: false,
                exports,
                raw_result,
            });
        }

        let mut output = HashMap::new();
        for (key, value) in &self.output {
            output.insert(key.clone(), resolve_pipeline_output_value(value, root_input, &stage_exports)?);
        }

        Ok(PipelineExecution {
            pipeline_id: self.pipeline_id.clone(),
            ok: true,
            output,
            stages,
        })
    }

    pub fn write_pretty(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }
}

pub fn compose_pipeline(
    pipeline_id: impl Into<String>,
    artifact_paths: &[PathBuf],
    base_dir: impl AsRef<Path>,
) -> Result<ComposePlan> {
    if artifact_paths.is_empty() {
        return Err(LogicPearlError::message(
            "compose requires at least one pearl artifact path",
        ));
    }

    let pipeline_id = pipeline_id.into();
    let base_dir = base_dir.as_ref();
    let mut stages = Vec::with_capacity(artifact_paths.len());
    let mut notes = Vec::new();

    for (index, artifact_path) in artifact_paths.iter().enumerate() {
        let gate = LogicPearlGateIr::from_path(artifact_path)?;
        let stage_id = sanitize_stage_id(&gate.gate_id, index);
        let artifact = relative_or_absolute_path(base_dir, artifact_path);

        let mut input = HashMap::new();
        for feature in &gate.input_schema.features {
            input.insert(
                feature.id.clone(),
                Value::String(format!("$.TODO_{}", feature.id)),
            );
        }

        let mut export = HashMap::new();
        export.insert("bitmask".to_string(), Value::String("$.bitmask".to_string()));
        export.insert("allow".to_string(), Value::String("$.allow".to_string()));

        notes.push(format!(
            "stage `{}` maps {} input feature(s) from placeholder root paths; replace `$.TODO_*` with real paths or `@stage.export` references",
            stage_id,
            gate.input_schema.features.len()
        ));

        stages.push(PipelineStage {
            id: stage_id,
            kind: PipelineStageKind::Pearl,
            artifact: Some(artifact),
            plugin_manifest: None,
            input,
            export,
            when: None,
            foreach: None,
        });
    }

    let mut output = HashMap::new();
    let final_stage = stages
        .last()
        .ok_or_else(|| LogicPearlError::message("compose produced no stages"))?;
    output.insert(
        "bitmask".to_string(),
        Value::String(format!("@{}.bitmask", final_stage.id)),
    );
    output.insert(
        "allow".to_string(),
        Value::String(format!("@{}.allow", final_stage.id)),
    );

    Ok(ComposePlan {
        pipeline: PipelineDefinition {
            pipeline_version: "1.0".to_string(),
            pipeline_id,
            entrypoint: "input".to_string(),
            stages,
            output,
        },
        notes,
    })
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
                let manifest = PluginManifest::from_path(&manifest_path)?;
                let expected_stage = plugin_stage_for_kind(&self.kind).ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "stage {} does not map to a plugin stage",
                        self.id
                    ))
                })?;
                if manifest.stage != expected_stage {
                    return Err(LogicPearlError::message(format!(
                        "stage {} expects plugin stage {:?}, found {:?}",
                        self.id, expected_stage, manifest.stage
                    )));
                }
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

fn plugin_stage_for_kind(kind: &PipelineStageKind) -> Option<PluginStage> {
    match kind {
        PipelineStageKind::ObserverPlugin => Some(PluginStage::Observer),
        PipelineStageKind::EnricherPlugin => Some(PluginStage::Enricher),
        PipelineStageKind::VerifyPlugin => Some(PluginStage::Verify),
        PipelineStageKind::Pearl => None,
    }
}

fn run_observer_plugin_stage(
    stage: &PipelineStage,
    base_dir: &Path,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    let manifest_path = resolve_relative_path(
        base_dir,
        stage
            .plugin_manifest
            .as_ref()
            .expect("validated observer plugin manifest"),
    );
    let manifest = PluginManifest::from_path(&manifest_path)?;
    let raw_input = Value::Object(
        build_stage_input_object(&stage.input, root_input, stage_exports)?
            .into_iter()
            .collect(),
    );
    let response = run_plugin(
        &manifest,
        &PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            payload: serde_json::json!({
                "raw_input": raw_input,
            }),
        },
    )?;
    plugin_response_to_value(response)
}

fn run_generic_plugin_stage(
    stage: &PipelineStage,
    base_dir: &Path,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    let manifest_path = resolve_relative_path(
        base_dir,
        stage
            .plugin_manifest
            .as_ref()
            .expect("validated plugin manifest"),
    );
    let manifest = PluginManifest::from_path(&manifest_path)?;
    let plugin_stage = plugin_stage_for_kind(&stage.kind).ok_or_else(|| {
        LogicPearlError::message(format!(
            "stage {} does not map to a plugin stage",
            stage.id
        ))
    })?;
    let payload = Value::Object(
        build_stage_input_object(&stage.input, root_input, stage_exports)?
            .into_iter()
            .collect(),
    );
    let response = run_plugin(
        &manifest,
        &PluginRequest {
            protocol_version: "1".to_string(),
            stage: plugin_stage,
            payload,
        },
    )?;
    plugin_response_to_value(response)
}

fn plugin_response_to_value(response: PluginResponse) -> Result<Value> {
    let mut map = Map::new();
    map.insert("ok".to_string(), Value::Bool(response.ok));
    if !response.warnings.is_empty() {
        map.insert(
            "warnings".to_string(),
            Value::Array(response.warnings.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(error) = response.error {
        map.insert(
            "error".to_string(),
            serde_json::to_value(error).map_err(LogicPearlError::from)?,
        );
    }
    for (key, value) in response.extra {
        map.insert(key, value);
    }
    Ok(Value::Object(map))
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

fn build_stage_input_object(
    input_map: &HashMap<String, Value>,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<HashMap<String, Value>> {
    let mut resolved = HashMap::new();
    for (key, value) in input_map {
        resolved.insert(
            key.clone(),
            resolve_stage_input_value(value, root_input, stage_exports)?,
        );
    }
    Ok(resolved)
}

fn build_stage_exports(
    export_map: &HashMap<String, Value>,
    raw_result: &Value,
) -> Result<HashMap<String, Value>> {
    let mut resolved = HashMap::new();
    for (key, value) in export_map {
        resolved.insert(key.clone(), resolve_stage_output_value(value, raw_result)?);
    }
    Ok(resolved)
}

fn resolve_stage_input_value(
    value: &Value,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
) -> Result<Value> {
    resolve_value(value, root_input, None, stage_exports)
}

fn resolve_stage_output_value(value: &Value, stage_result: &Value) -> Result<Value> {
    resolve_value(value, stage_result, Some(stage_result), &HashMap::new())
}

fn resolve_pipeline_output_value(
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
                resolved.push(resolve_value(item, dollar_scope, local_scope, stage_exports)?);
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

fn truthy(value: &Value) -> bool {
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

fn sanitize_stage_id(value: &str, index: usize) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        format!("stage_{}", index + 1)
    } else {
        out
    }
}

fn relative_or_absolute_path(base_dir: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(base_dir) {
        relative.display().to_string()
    } else {
        path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{compose_pipeline, PipelineDefinition, PipelineStageKind};
    use serde_json::json;
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

    #[test]
    fn runs_basic_pearl_pipeline() {
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
                    "action": "$.request.action",
                    "resource_archived": "$.request.resource_archived",
                    "user_role": "$.user.role",
                    "failed_attempts": "$.user.failed_attempts"
                  },
                  "export": {
                    "bitmask": "$.bitmask",
                    "allow": "$.allow"
                  }
                }
              ],
              "output": {
                "bitmask": "@authz.bitmask",
                "allow": "@authz.allow"
              }
            }"#,
        )
        .expect("pipeline parses");
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/pipelines/authz");
        let input = json!({
            "request": {
                "action": "delete",
                "resource_archived": true
            },
            "user": {
                "role": "viewer",
                "failed_attempts": 99
            }
        });
        let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
        assert_eq!(execution.output.get("bitmask"), Some(&json!(7)));
        assert_eq!(execution.output.get("allow"), Some(&json!(false)));
    }

    #[test]
    fn runs_observer_then_pearl_pipeline() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "observer_demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "observer",
                  "kind": "observer_plugin",
                  "plugin_manifest": "../../plugins/python_observer/manifest.json",
                  "input": {
                    "age": "$.age",
                    "member": "$.member",
                    "country": "$.country"
                  },
                  "export": {
                    "age": "$.features.age",
                    "is_member": "$.features.is_member"
                  }
                },
                {
                  "id": "gate",
                  "kind": "pearl",
                  "artifact": "../../../fixtures/ir/valid/membership-demo-v1.json",
                  "input": {
                    "age": "@observer.age",
                    "is_member": "@observer.is_member"
                  },
                  "export": {
                    "bitmask": "$.bitmask",
                    "allow": "$.allow"
                  }
                }
              ],
              "output": {
                "bitmask": "@gate.bitmask",
                "allow": "@gate.allow"
              }
            }"#,
        )
        .expect("pipeline parses");
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/pipelines/observer_membership");
        let input = json!({
            "age": 34,
            "member": true,
            "country": "US"
        });
        let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
        assert_eq!(execution.output.get("bitmask"), Some(&json!(0)));
        assert_eq!(execution.output.get("allow"), Some(&json!(true)));
    }

    #[test]
    fn runs_observer_pearl_verify_pipeline() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "observer_verify_demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "observer",
                  "kind": "observer_plugin",
                  "plugin_manifest": "../../plugins/python_observer/manifest.json",
                  "input": {
                    "age": "$.age",
                    "member": "$.member",
                    "country": "$.country"
                  },
                  "export": {
                    "age": "$.features.age",
                    "is_member": "$.features.is_member"
                  }
                },
                {
                  "id": "gate",
                  "kind": "pearl",
                  "artifact": "../../../fixtures/ir/valid/membership-demo-v1.json",
                  "input": {
                    "age": "@observer.age",
                    "is_member": "@observer.is_member"
                  },
                  "export": {
                    "bitmask": "$.bitmask",
                    "allow": "$.allow"
                  }
                },
                {
                  "id": "audit",
                  "kind": "verify_plugin",
                  "plugin_manifest": "../../plugins/python_pipeline_verify/manifest.json",
                  "input": {
                    "bitmask": "@gate.bitmask",
                    "allow": "@gate.allow"
                  },
                  "export": {
                    "audit_status": "$.audit_status",
                    "consistent": "$.summary.consistent"
                  }
                }
              ],
              "output": {
                "bitmask": "@gate.bitmask",
                "allow": "@gate.allow",
                "audit_status": "@audit.audit_status",
                "consistent": "@audit.consistent"
              }
            }"#,
        )
        .expect("pipeline parses");
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/pipelines/observer_membership_verify");
        let input = json!({
            "age": 34,
            "member": true,
            "country": "US"
        });
        let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
        assert_eq!(execution.output.get("bitmask"), Some(&json!(0)));
        assert_eq!(execution.output.get("allow"), Some(&json!(true)));
        assert_eq!(execution.output.get("audit_status"), Some(&json!("clean_pass")));
        assert_eq!(execution.output.get("consistent"), Some(&json!(true)));
    }

    #[test]
    fn composes_starter_pipeline_from_artifacts() {
        let artifact_paths = vec![
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/ir/valid/auth-demo-v1.json"),
        ];
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/pipelines/generated");
        let plan = compose_pipeline("starter", &artifact_paths, &base_dir).expect("compose works");
        assert_eq!(plan.pipeline.pipeline_id, "starter");
        assert_eq!(plan.pipeline.stages.len(), 1);
        assert_eq!(plan.pipeline.stages[0].id, "auth_demo_v1");
        assert!(plan.pipeline.stages[0]
            .input
            .contains_key("action"));
        assert_eq!(
            plan.pipeline.output.get("allow"),
            Some(&json!("@auth_demo_v1.allow"))
        );
    }
}
