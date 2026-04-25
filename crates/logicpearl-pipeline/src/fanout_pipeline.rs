// SPDX-License-Identifier: MIT

use crate::json_path::{resolve_stage_input_value, validate_value_reference};
use crate::path::{manifest_member_path_for_base, parse_document, resolve_relative_path};
use logicpearl_core::{artifact_hash, load_artifact_bundle, ArtifactKind, LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

pub const FANOUT_PIPELINE_SCHEMA_VERSION: &str = "logicpearl.fanout_pipeline.v1";
pub const FANOUT_RESULT_SCHEMA_VERSION: &str = "logicpearl.fanout_result.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FanoutPipelineDefinition {
    #[serde(default = "default_fanout_pipeline_schema_version")]
    pub schema_version: String,
    pub pipeline_id: String,
    #[serde(default)]
    pub input: HashMap<String, Value>,
    pub actions: Vec<FanoutActionGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FanoutActionGate {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedFanoutPipeline {
    pub schema_version: String,
    pub pipeline_id: String,
    pub actions: Vec<ValidatedFanoutActionGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedFanoutActionGate {
    pub action: String,
    pub id: String,
    pub artifact: String,
    pub input_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FanoutPipelineExecution {
    pub schema_version: String,
    pub engine_version: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub decision_kind: String,
    pub pipeline_id: String,
    pub ok: bool,
    pub applicable_actions: Vec<String>,
    pub verdicts: BTreeMap<String, FanoutActionVerdict>,
    pub output: Value,
    pub stages: Vec<FanoutActionVerdict>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FanoutActionVerdict {
    pub id: String,
    pub action: String,
    pub applies: bool,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub bitmask: Value,
    pub matched_rules: Value,
    pub result: Value,
}

#[derive(Debug, Clone)]
pub struct PreparedFanoutPipeline {
    definition: FanoutPipelineDefinition,
    actions: Vec<PreparedFanoutActionGate>,
}

#[derive(Debug, Clone)]
struct PreparedFanoutActionGate {
    action: String,
    id: String,
    gate: LogicPearlGateIr,
    input: HashMap<String, Value>,
}

impl FanoutPipelineDefinition {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let pipeline: Self = serde_json::from_str(input)?;
        Ok(pipeline)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        parse_document(&content)
    }

    pub fn write_pretty(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn validate(&self, base_dir: impl AsRef<Path>) -> Result<ValidatedFanoutPipeline> {
        if self.schema_version != FANOUT_PIPELINE_SCHEMA_VERSION {
            return Err(LogicPearlError::message(format!(
                "unsupported fan-out pipeline schema_version: {}; use {FANOUT_PIPELINE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.pipeline_id.trim().is_empty() {
            return Err(LogicPearlError::message(
                "fan-out pipeline_id must be non-empty",
            ));
        }
        if self.actions.is_empty() {
            return Err(LogicPearlError::message(
                "fan-out pipeline must define at least one action",
            ));
        }
        validate_fanout_input_map("pipeline input", &self.input)?;
        let base_dir = base_dir.as_ref();
        let mut ids = BTreeSet::new();
        let mut action_names = BTreeSet::new();
        let actions = self
            .actions
            .iter()
            .enumerate()
            .map(|(index, action)| {
                validate_fanout_action(
                    base_dir,
                    action,
                    index,
                    &self.input,
                    &mut ids,
                    &mut action_names,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ValidatedFanoutPipeline {
            schema_version: self.schema_version.clone(),
            pipeline_id: self.pipeline_id.clone(),
            actions,
        })
    }

    pub fn inspect(&self, base_dir: impl AsRef<Path>) -> Result<ValidatedFanoutPipeline> {
        self.validate(base_dir)
    }

    pub fn prepare(&self, base_dir: impl AsRef<Path>) -> Result<PreparedFanoutPipeline> {
        self.validate(&base_dir)?;
        let base_dir = base_dir.as_ref();
        let actions = self
            .actions
            .iter()
            .enumerate()
            .map(|(index, action)| prepare_fanout_action(base_dir, action, index, &self.input))
            .collect::<Result<Vec<_>>>()?;
        Ok(PreparedFanoutPipeline {
            definition: self.clone(),
            actions,
        })
    }

    pub fn run(
        &self,
        base_dir: impl AsRef<Path>,
        root_input: &Value,
    ) -> Result<FanoutPipelineExecution> {
        self.prepare(base_dir)?.run(root_input)
    }
}

impl PreparedFanoutPipeline {
    pub fn run(&self, root_input: &Value) -> Result<FanoutPipelineExecution> {
        let mut applicable_actions = Vec::new();
        let mut verdicts = BTreeMap::new();
        let mut stages = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            let features = build_fanout_input_object(action, root_input)?;
            let result = serde_json::to_value(logicpearl_runtime::evaluate_gate_with_explanation(
                &action.gate,
                &features,
            )?)?;
            let applies = result.get("bitmask").is_some_and(rule_mask_value_nonzero)
                || result
                    .get("matched_rules")
                    .and_then(Value::as_array)
                    .is_some_and(|rules| !rules.is_empty());
            if applies {
                applicable_actions.push(action.action.clone());
            }
            let verdict = FanoutActionVerdict {
                id: action.id.clone(),
                action: action.action.clone(),
                applies,
                artifact_id: result
                    .get("artifact_id")
                    .and_then(Value::as_str)
                    .unwrap_or(&action.id)
                    .to_string(),
                artifact_hash: result
                    .get("artifact_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                bitmask: result.get("bitmask").cloned().unwrap_or(Value::Null),
                matched_rules: result
                    .get("matched_rules")
                    .cloned()
                    .unwrap_or_else(|| Value::Array(Vec::new())),
                result,
            };
            verdicts.insert(action.action.clone(), verdict.clone());
            stages.push(verdict);
        }

        let output = Value::Object(Map::from_iter([
            (
                "applicable_actions".to_string(),
                serde_json::to_value(&applicable_actions)?,
            ),
            ("verdicts".to_string(), serde_json::to_value(&verdicts)?),
        ]));
        Ok(FanoutPipelineExecution {
            schema_version: FANOUT_RESULT_SCHEMA_VERSION.to_string(),
            engine_version: logicpearl_runtime::LOGICPEARL_ENGINE_VERSION.to_string(),
            artifact_id: self.definition.pipeline_id.clone(),
            artifact_hash: artifact_hash(&self.definition),
            decision_kind: "fanout".to_string(),
            pipeline_id: self.definition.pipeline_id.clone(),
            ok: true,
            applicable_actions,
            verdicts,
            output,
            stages,
        })
    }
}

pub fn build_fanout_pipeline(
    pipeline_id: impl Into<String>,
    action_artifacts: &[(String, PathBuf)],
    base_dir: impl AsRef<Path>,
    input: HashMap<String, Value>,
) -> Result<FanoutPipelineDefinition> {
    let base_dir = base_dir.as_ref();
    let actions = action_artifacts
        .iter()
        .map(|(action, artifact_path)| {
            Ok(FanoutActionGate {
                action: action.clone(),
                id: Some(action.clone()),
                artifact: manifest_member_path_for_base(base_dir, artifact_path)?,
                input: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let definition = FanoutPipelineDefinition {
        schema_version: FANOUT_PIPELINE_SCHEMA_VERSION.to_string(),
        pipeline_id: pipeline_id.into(),
        input,
        actions,
    };
    definition.validate(base_dir)?;
    Ok(definition)
}

fn default_fanout_pipeline_schema_version() -> String {
    FANOUT_PIPELINE_SCHEMA_VERSION.to_string()
}

fn validate_fanout_action(
    base_dir: &Path,
    action: &FanoutActionGate,
    index: usize,
    default_input: &HashMap<String, Value>,
    ids: &mut BTreeSet<String>,
    action_names: &mut BTreeSet<String>,
) -> Result<ValidatedFanoutActionGate> {
    let action_name = action.action.trim();
    if action_name.is_empty() {
        return Err(LogicPearlError::message(
            "fan-out action names must be non-empty",
        ));
    }
    if !action_names.insert(action_name.to_string()) {
        return Err(LogicPearlError::message(format!(
            "duplicate fan-out action: {action_name}"
        )));
    }
    let id = fanout_action_id(action, index);
    if !ids.insert(id.clone()) {
        return Err(LogicPearlError::message(format!(
            "duplicate fan-out action id: {id}"
        )));
    }
    let input = action.input.as_ref().unwrap_or(default_input);
    validate_fanout_input_map(&format!("fan-out action {id} input"), input)?;
    let artifact_path = resolve_relative_path(base_dir, &action.artifact)?;
    let bundle = load_artifact_bundle(&artifact_path)?;
    if bundle.manifest.artifact_kind != ArtifactKind::Gate {
        return Err(LogicPearlError::message(format!(
            "fan-out action {id} must reference a gate artifact"
        )));
    }
    LogicPearlGateIr::from_path(bundle.ir_path()?)?;
    let mut input_fields = input.keys().cloned().collect::<Vec<_>>();
    input_fields.sort();
    Ok(ValidatedFanoutActionGate {
        action: action_name.to_string(),
        id,
        artifact: action.artifact.clone(),
        input_fields,
    })
}

fn prepare_fanout_action(
    base_dir: &Path,
    action: &FanoutActionGate,
    index: usize,
    default_input: &HashMap<String, Value>,
) -> Result<PreparedFanoutActionGate> {
    let id = fanout_action_id(action, index);
    let artifact_path = resolve_relative_path(base_dir, &action.artifact)?;
    let bundle = load_artifact_bundle(&artifact_path)?;
    let gate = LogicPearlGateIr::from_path(bundle.ir_path()?)?;
    Ok(PreparedFanoutActionGate {
        action: action.action.clone(),
        id,
        gate,
        input: action
            .input
            .clone()
            .unwrap_or_else(|| default_input.clone()),
    })
}

fn validate_fanout_input_map(label: &str, input: &HashMap<String, Value>) -> Result<()> {
    let visible_exports = HashMap::new();
    for (field, value) in input {
        if field.trim().is_empty() {
            return Err(LogicPearlError::message(format!(
                "{label} contains an empty input field"
            )));
        }
        validate_value_reference(value, &visible_exports)?;
    }
    Ok(())
}

fn build_fanout_input_object(
    action: &PreparedFanoutActionGate,
    root_input: &Value,
) -> Result<HashMap<String, Value>> {
    if action.input.is_empty() {
        let object = root_input.as_object().ok_or_else(|| {
            LogicPearlError::message(format!(
                "fan-out action {} expected object pipeline input",
                action.id
            ))
        })?;
        return Ok(object
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect());
    }
    let exports = HashMap::new();
    action
        .input
        .iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                resolve_stage_input_value(value, root_input, &exports)?,
            ))
        })
        .collect()
}

fn fanout_action_id(action: &FanoutActionGate, index: usize) -> String {
    action
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("action_{index:03}"))
}

fn rule_mask_value_nonzero(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_u64().unwrap_or(0) != 0,
        Value::String(text) => text != "0" && !text.is_empty(),
        Value::Array(items) => items.iter().any(rule_mask_value_nonzero),
        _ => false,
    }
}
