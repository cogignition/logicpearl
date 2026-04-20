// SPDX-License-Identifier: MIT

use crate::json_path::{
    build_stage_exports, build_stage_input_object, build_stage_options_value,
    build_stage_payload_value, resolve_pipeline_output_value, resolve_stage_input_value, truthy,
    validate_value_reference,
};
use crate::path::{parse_document, resolve_relative_path};
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_plugin::{
    run_plugin_batch_with_policy_and_metadata, run_plugin_with_policy_and_metadata,
    PluginExecutionPolicy, PluginExecutionResult, PluginManifest, PluginRequest, PluginResponse,
    PluginStage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

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
        parse_document(&content)
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
