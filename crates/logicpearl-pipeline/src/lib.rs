// SPDX-License-Identifier: MIT
use logicpearl_core::{resolve_manifest_member_path, LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_plugin::{
    run_plugin_batch_with_policy_and_metadata, run_plugin_with_policy_and_metadata,
    PluginExecutionPolicy, PluginExecutionResult, PluginManifest, PluginRequest, PluginResponse,
    PluginStage,
};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

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
    pub payload: Option<Value>,
    #[serde(default)]
    pub options: Option<Value>,
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
    TraceSourcePlugin,
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
    pub schema_version: String,
    pub engine_version: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub decision_kind: String,
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

#[derive(Debug, Clone)]
pub struct PreparedPipeline {
    definition: PipelineDefinition,
    stages: Vec<PreparedStage>,
    plugin_policy: PluginExecutionPolicy,
}

#[derive(Debug, Clone)]
struct PreparedStage {
    stage: PipelineStage,
    executable: PreparedStageExecutable,
}

#[derive(Debug, Clone)]
enum PreparedStageExecutable {
    Pearl(LogicPearlGateIr),
    Plugin {
        manifest: PluginManifest,
        stage: PluginStage,
    },
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
            return Err(LogicPearlError::message("pipeline_id must be non-empty"));
        }
        if self.entrypoint.trim().is_empty() {
            return Err(LogicPearlError::message("entrypoint must be non-empty"));
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
                    .map(|value| {
                        resolve_relative_path(base_dir, value)
                            .map(|path| path.display().to_string())
                    })
                    .transpose()?,
                plugin_manifest: stage
                    .plugin_manifest
                    .as_ref()
                    .map(|value| {
                        resolve_relative_path(base_dir, value)
                            .map(|path| path.display().to_string())
                    })
                    .transpose()?,
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
        self.run_with_plugin_policy(base_dir, root_input, PluginExecutionPolicy::default())
    }

    pub fn run_with_plugin_policy(
        &self,
        base_dir: impl AsRef<Path>,
        root_input: &Value,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<PipelineExecution> {
        self.prepare_with_plugin_policy(base_dir, plugin_policy)?
            .run(root_input)
    }

    pub fn write_pretty(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn prepare(&self, base_dir: impl AsRef<Path>) -> Result<PreparedPipeline> {
        self.prepare_with_plugin_policy(base_dir, PluginExecutionPolicy::default())
    }

    pub fn prepare_with_plugin_policy(
        &self,
        base_dir: impl AsRef<Path>,
        plugin_policy: PluginExecutionPolicy,
    ) -> Result<PreparedPipeline> {
        self.validate(&base_dir)?;
        let base_dir = base_dir.as_ref();
        let mut prepared_stages = Vec::with_capacity(self.stages.len());
        for stage in &self.stages {
            let executable = match stage.kind {
                PipelineStageKind::Pearl => {
                    let artifact_path = resolve_relative_path(
                        base_dir,
                        stage.artifact.as_ref().expect("validated pearl artifact"),
                    )?;
                    PreparedStageExecutable::Pearl(LogicPearlGateIr::from_path(&artifact_path)?)
                }
                PipelineStageKind::ObserverPlugin
                | PipelineStageKind::TraceSourcePlugin
                | PipelineStageKind::EnricherPlugin
                | PipelineStageKind::VerifyPlugin => {
                    let manifest_path = resolve_relative_path(
                        base_dir,
                        stage
                            .plugin_manifest
                            .as_ref()
                            .expect("validated plugin manifest"),
                    )?;
                    let manifest = PluginManifest::from_path(&manifest_path)?;
                    let plugin_stage = plugin_stage_for_kind(&stage.kind).ok_or_else(|| {
                        LogicPearlError::message(format!(
                            "stage {} does not map to a plugin stage",
                            stage.id
                        ))
                    })?;
                    PreparedStageExecutable::Plugin {
                        manifest,
                        stage: plugin_stage,
                    }
                }
            };
            prepared_stages.push(PreparedStage {
                stage: stage.clone(),
                executable,
            });
        }
        Ok(PreparedPipeline {
            definition: self.clone(),
            stages: prepared_stages,
            plugin_policy,
        })
    }
}

impl PreparedPipeline {
    pub fn run(&self, root_input: &Value) -> Result<PipelineExecution> {
        let mut stage_exports: HashMap<String, HashMap<String, Value>> = HashMap::new();
        let mut stages = Vec::with_capacity(self.stages.len());

        for prepared_stage in &self.stages {
            let stage = &prepared_stage.stage;
            let should_run = match &stage.when {
                Some(condition) => truthy(&resolve_stage_input_value(
                    condition,
                    root_input,
                    &stage_exports,
                )?),
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

            let raw_result = run_prepared_stage(
                prepared_stage,
                root_input,
                &stage_exports,
                &self.plugin_policy,
            )?;

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
        for (key, value) in &self.definition.output {
            output.insert(
                key.clone(),
                resolve_pipeline_output_value(value, root_input, &stage_exports)?,
            );
        }

        Ok(PipelineExecution {
            schema_version: logicpearl_runtime::PIPELINE_RESULT_SCHEMA_VERSION.to_string(),
            engine_version: logicpearl_runtime::LOGICPEARL_ENGINE_VERSION.to_string(),
            artifact_id: self.definition.pipeline_id.clone(),
            artifact_hash: logicpearl_runtime::artifact_hash(&self.definition),
            decision_kind: "pipeline".to_string(),
            pipeline_id: self.definition.pipeline_id.clone(),
            ok: true,
            output,
            stages,
        })
    }

    pub fn run_batch(&self, root_inputs: &[Value]) -> Result<Vec<PipelineExecution>> {
        let mut stage_exports: Vec<HashMap<String, HashMap<String, Value>>> =
            vec![HashMap::new(); root_inputs.len()];
        let mut case_stages: Vec<Vec<StageExecution>> = (0..root_inputs.len())
            .map(|_| Vec::with_capacity(self.stages.len()))
            .collect();

        for prepared_stage in &self.stages {
            let stage = &prepared_stage.stage;
            let should_run: Vec<bool> = root_inputs
                .iter()
                .zip(stage_exports.iter())
                .map(|(root_input, exports)| -> Result<bool> {
                    Ok(match &stage.when {
                        Some(condition) => {
                            truthy(&resolve_stage_input_value(condition, root_input, exports)?)
                        }
                        None => true,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let runnable_indexes: Vec<usize> = should_run
                .iter()
                .enumerate()
                .filter_map(|(index, should)| should.then_some(index))
                .collect();

            let raw_results = run_prepared_stage_batch(
                prepared_stage,
                root_inputs,
                &stage_exports,
                &runnable_indexes,
                &self.plugin_policy,
            )?;
            let mut raw_iter = raw_results.into_iter();

            for index in 0..root_inputs.len() {
                if !should_run[index] {
                    case_stages[index].push(StageExecution {
                        id: stage.id.clone(),
                        kind: stage.kind.clone(),
                        ok: true,
                        skipped: true,
                        exports: HashMap::new(),
                        raw_result: Value::Null,
                    });
                    stage_exports[index].insert(stage.id.clone(), HashMap::new());
                    continue;
                }

                let raw_result = raw_iter.next().ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "prepared stage batch for {} returned fewer results than expected",
                        stage.id
                    ))
                })?;
                let exports = build_stage_exports(&stage.export, &raw_result)?;
                stage_exports[index].insert(stage.id.clone(), exports.clone());
                case_stages[index].push(StageExecution {
                    id: stage.id.clone(),
                    kind: stage.kind.clone(),
                    ok: true,
                    skipped: false,
                    exports,
                    raw_result,
                });
            }
        }

        root_inputs
            .iter()
            .enumerate()
            .map(|(index, root_input)| {
                let mut output = HashMap::new();
                for (key, value) in &self.definition.output {
                    output.insert(
                        key.clone(),
                        resolve_pipeline_output_value(value, root_input, &stage_exports[index])?,
                    );
                }
                Ok(PipelineExecution {
                    schema_version: logicpearl_runtime::PIPELINE_RESULT_SCHEMA_VERSION.to_string(),
                    engine_version: logicpearl_runtime::LOGICPEARL_ENGINE_VERSION.to_string(),
                    artifact_id: self.definition.pipeline_id.clone(),
                    artifact_hash: logicpearl_runtime::artifact_hash(&self.definition),
                    decision_kind: "pipeline".to_string(),
                    pipeline_id: self.definition.pipeline_id.clone(),
                    ok: true,
                    output,
                    stages: case_stages[index].clone(),
                })
            })
            .collect()
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
        let artifact = manifest_member_path_for_base(base_dir, artifact_path)?;

        let mut input = HashMap::new();
        for feature in &gate.input_schema.features {
            input.insert(
                feature.id.clone(),
                Value::String(format!("$.TODO_{}", feature.id)),
            );
        }

        let mut export = HashMap::new();
        export.insert(
            "bitmask".to_string(),
            Value::String("$.bitmask".to_string()),
        );
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
            payload: None,
            options: None,
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
                let artifact_path = resolve_relative_path(base_dir, artifact)?;
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
            | PipelineStageKind::TraceSourcePlugin
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
                let manifest_path = resolve_relative_path(base_dir, manifest)?;
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
        if let Some(value) = &self.payload {
            validate_value_reference(value, visible_exports)?;
        }
        if let Some(value) = &self.options {
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

fn resolve_relative_path(base_dir: &Path, value: &str) -> Result<PathBuf> {
    resolve_manifest_member_path(base_dir, value)
}

fn plugin_stage_for_kind(kind: &PipelineStageKind) -> Option<PluginStage> {
    match kind {
        PipelineStageKind::ObserverPlugin => Some(PluginStage::Observer),
        PipelineStageKind::TraceSourcePlugin => Some(PluginStage::TraceSource),
        PipelineStageKind::EnricherPlugin => Some(PluginStage::Enricher),
        PipelineStageKind::VerifyPlugin => Some(PluginStage::Verify),
        PipelineStageKind::Pearl => None,
    }
}

fn run_prepared_stage(
    prepared_stage: &PreparedStage,
    root_input: &Value,
    stage_exports: &HashMap<String, HashMap<String, Value>>,
    plugin_policy: &PluginExecutionPolicy,
) -> Result<Value> {
    let stage = &prepared_stage.stage;
    match &prepared_stage.executable {
        PreparedStageExecutable::Pearl(gate) => {
            let features = build_stage_input_object(stage, root_input, stage_exports)?;
            serde_json::to_value(logicpearl_runtime::evaluate_gate_with_explanation(
                gate, &features,
            )?)
            .map_err(Into::into)
        }
        PreparedStageExecutable::Plugin {
            manifest,
            stage: plugin_stage,
        } => {
            let payload = logicpearl_plugin::build_canonical_payload(
                plugin_stage,
                build_stage_payload_value(stage, root_input, stage_exports)?,
                build_stage_options_value(stage, root_input, stage_exports)?,
            );
            let execution = run_plugin_with_policy_and_metadata(
                manifest,
                &PluginRequest {
                    protocol_version: "1".to_string(),
                    stage: plugin_stage.clone(),
                    payload,
                },
                plugin_policy,
            )?;
            plugin_execution_to_value(execution)
        }
    }
}

fn run_prepared_stage_batch(
    prepared_stage: &PreparedStage,
    root_inputs: &[Value],
    stage_exports: &[HashMap<String, HashMap<String, Value>>],
    runnable_indexes: &[usize],
    plugin_policy: &PluginExecutionPolicy,
) -> Result<Vec<Value>> {
    if runnable_indexes.is_empty() {
        return Ok(Vec::new());
    }

    let stage = &prepared_stage.stage;
    match &prepared_stage.executable {
        PreparedStageExecutable::Pearl(gate) => runnable_indexes
            .iter()
            .map(|index| {
                let features =
                    build_stage_input_object(stage, &root_inputs[*index], &stage_exports[*index])?;
                serde_json::to_value(logicpearl_runtime::evaluate_gate_with_explanation(
                    gate, &features,
                )?)
                .map_err(Into::into)
            })
            .collect(),
        PreparedStageExecutable::Plugin {
            manifest,
            stage: plugin_stage,
        } => {
            let payloads: Vec<Value> = runnable_indexes
                .iter()
                .map(|index| {
                    Ok(logicpearl_plugin::build_canonical_payload(
                        plugin_stage,
                        build_stage_payload_value(
                            stage,
                            &root_inputs[*index],
                            &stage_exports[*index],
                        )?,
                        build_stage_options_value(
                            stage,
                            &root_inputs[*index],
                            &stage_exports[*index],
                        )?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let execution = run_plugin_batch_with_policy_and_metadata(
                manifest,
                plugin_stage.clone(),
                &payloads,
                plugin_policy,
            )?;
            if execution.runs.len() != execution.responses.len() {
                return Err(LogicPearlError::message(format!(
                    "plugin {} returned {} execution records for {} responses",
                    manifest.name,
                    execution.runs.len(),
                    execution.responses.len()
                )));
            }
            execution
                .responses
                .into_iter()
                .zip(execution.runs)
                .map(|(response, run)| plugin_response_with_run_to_value(response, &run))
                .collect()
        }
    }
}

fn plugin_execution_to_value(execution: PluginExecutionResult) -> Result<Value> {
    plugin_response_with_run_to_value(execution.response, &execution.run)
}

fn plugin_response_with_run_to_value(
    response: PluginResponse,
    run: &logicpearl_plugin::PluginRunMetadata,
) -> Result<Value> {
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
    map.insert(
        "plugin_run".to_string(),
        serde_json::to_value(run).map_err(LogicPearlError::from)?,
    );
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

fn build_stage_payload_value(
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

fn build_stage_options_value(
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

fn manifest_member_path_for_base(base_dir: &Path, path: &Path) -> Result<String> {
    let relative = if let Ok(relative) = path.strip_prefix(base_dir) {
        relative.to_path_buf()
    } else {
        let canonical_base = fs::canonicalize(base_dir).map_err(|error| {
            LogicPearlError::message(format!(
                "failed to canonicalize pipeline bundle directory {}: {error}",
                base_dir.display()
            ))
        })?;
        let canonical_path = fs::canonicalize(path).map_err(|error| {
            LogicPearlError::message(format!(
                "failed to canonicalize pipeline artifact {}: {error}",
                path.display()
            ))
        })?;
        canonical_path
            .strip_prefix(&canonical_base)
            .map(Path::to_path_buf)
            .map_err(|_| {
                LogicPearlError::message(format!(
                    "compose artifact must be inside the pipeline bundle directory: {}",
                    path.display()
                ))
            })?
    };

    let rendered = relative.display().to_string();
    resolve_manifest_member_path(base_dir, &rendered)?;
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::{compose_pipeline, PipelineDefinition, PipelineStageKind};
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("crate should live under workspace/crates/logicpearl-pipeline")
            .to_path_buf()
    }

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
                  "artifact": "fixtures/ir/valid/auth-demo-v1.json",
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
        let base_dir = repo_root();
        let validated = pipeline.validate(base_dir).expect("pipeline validates");
        assert_eq!(validated.pipeline_id, "demo");
        assert_eq!(validated.stage_count, 1);
        assert_eq!(validated.stages[0].kind, PipelineStageKind::Pearl);
    }

    #[test]
    fn rejects_pipeline_stage_paths_that_escape_base_dir() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "authz",
                  "kind": "pearl",
                  "artifact": "../fixtures/ir/valid/auth-demo-v1.json",
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
        let err = pipeline
            .validate(repo_root())
            .expect_err("escaping stage paths should fail");
        assert!(err.to_string().contains("escapes bundle directory"));
    }

    #[test]
    fn rejects_absolute_pipeline_stage_paths() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "authz",
                  "kind": "pearl",
                  "artifact": "/tmp/auth-demo-v1.json",
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
        let err = pipeline
            .validate(repo_root())
            .expect_err("absolute stage paths should fail");
        assert!(err.to_string().contains("must be relative"));
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
                  "artifact": "fixtures/ir/valid/auth-demo-v1.json",
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
        let base_dir = repo_root();
        let err = pipeline
            .validate(base_dir)
            .expect_err("validation should fail");
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
                  "artifact": "fixtures/ir/valid/auth-demo-v1.json",
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
        let base_dir = repo_root();
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
                  "plugin_manifest": "examples/plugins/python_observer/manifest.json",
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
                  "artifact": "fixtures/ir/valid/membership-demo-v1.json",
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
        let base_dir = repo_root();
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
                  "plugin_manifest": "examples/plugins/python_observer/manifest.json",
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
                  "artifact": "fixtures/ir/valid/membership-demo-v1.json",
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
                  "plugin_manifest": "examples/plugins/python_pipeline_verify/manifest.json",
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
        let base_dir = repo_root();
        let input = json!({
            "age": 34,
            "member": true,
            "country": "US"
        });
        let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
        assert_eq!(execution.output.get("bitmask"), Some(&json!(0)));
        assert_eq!(execution.output.get("allow"), Some(&json!(true)));
        assert_eq!(
            execution.output.get("audit_status"),
            Some(&json!("clean_pass"))
        );
        assert_eq!(execution.output.get("consistent"), Some(&json!(true)));
    }

    #[test]
    fn runs_trace_source_plugin_pipeline() {
        let pipeline = PipelineDefinition::from_json_str(
            r#"{
              "pipeline_version": "1.0",
              "pipeline_id": "trace_source_demo",
              "entrypoint": "input",
              "stages": [
                {
                  "id": "trace_source",
                  "kind": "trace_source_plugin",
                  "plugin_manifest": "examples/plugins/python_trace_source/manifest.json",
                  "payload": "$.source",
                  "options": {
                    "label_column": "$.label_column"
                  },
                  "export": {
                    "decision_traces": "$.decision_traces"
                  }
                }
              ],
              "output": {
                "decision_traces": "@trace_source.decision_traces"
              }
            }"#,
        )
        .expect("pipeline parses");
        let base_dir = repo_root();
        let input = json!({
            "source": Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/getting_started/decision_traces.csv")
                .display()
                .to_string(),
            "label_column": "allowed"
        });
        let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
        let rows = execution
            .output
            .get("decision_traces")
            .and_then(|value| value.as_array())
            .expect("pipeline should export decision traces");
        assert!(!rows.is_empty());
        assert!(rows[0].get("features").is_some());
        assert!(rows[0].get("allowed").is_some());
    }

    #[test]
    fn composes_starter_pipeline_from_artifacts() {
        let base_dir = repo_root();
        let artifact_paths = vec![base_dir.join("fixtures/ir/valid/auth-demo-v1.json")];
        let plan = compose_pipeline("starter", &artifact_paths, &base_dir).expect("compose works");
        assert_eq!(plan.pipeline.pipeline_id, "starter");
        assert_eq!(plan.pipeline.stages.len(), 1);
        assert_eq!(plan.pipeline.stages[0].id, "auth_demo_v1");
        assert_eq!(
            plan.pipeline.stages[0].artifact.as_deref(),
            Some("fixtures/ir/valid/auth-demo-v1.json")
        );
        assert!(plan.pipeline.stages[0].input.contains_key("action"));
        assert_eq!(
            plan.pipeline.output.get("allow"),
            Some(&json!("@auth_demo_v1.allow"))
        );
    }
}
