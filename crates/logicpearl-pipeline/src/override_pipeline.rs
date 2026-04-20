// SPDX-License-Identifier: MIT

use crate::json_path::{resolve_stage_input_value, validate_value_reference};
use crate::path::{parse_document, resolve_relative_path, sanitize_stage_id};
use logicpearl_core::{load_artifact_bundle, ArtifactKind, LogicPearlError, Result};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

pub const OVERRIDE_PIPELINE_SCHEMA_VERSION: &str = "logicpearl.override_pipeline.v1";
pub const OVERRIDE_PIPELINE_RESULT_SCHEMA_VERSION: &str = "logicpearl.override_pipeline_result.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverridePipelineDefinition {
    #[serde(default = "default_override_pipeline_schema_version")]
    pub schema_version: String,
    pub pipeline_id: String,
    #[serde(default)]
    pub input: HashMap<String, Value>,
    pub base: OverridePipelinePearl,
    #[serde(default)]
    pub refinements: Vec<OverridePipelineRefinement>,
    #[serde(default)]
    pub conflict: OverrideConflictPolicy,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OverridePipelinePearl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OverridePipelineRefinement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<HashMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<OverrideRefinementAction>,
    #[serde(default)]
    pub effect: OverrideEffect,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OverridePearlInput {
    Artifact(String),
    Object(OverridePearlFields),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverridePearlFields {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    artifact: Option<String>,
    #[serde(default)]
    pearl: Option<String>,
    #[serde(default)]
    input: Option<HashMap<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideRefinementFields {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    artifact: Option<String>,
    #[serde(default)]
    pearl: Option<String>,
    #[serde(default)]
    input: Option<HashMap<String, Value>>,
    #[serde(default)]
    action: Option<OverrideRefinementAction>,
    #[serde(default)]
    effect: OverrideEffect,
}

impl<'de> Deserialize<'de> for OverridePipelinePearl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match OverridePearlInput::deserialize(deserializer)? {
            OverridePearlInput::Artifact(artifact) => Ok(Self {
                id: None,
                artifact,
                input: None,
            }),
            OverridePearlInput::Object(fields) => Ok(Self {
                id: fields.id,
                artifact: override_artifact_field(fields.artifact, fields.pearl)?,
                input: fields.input,
            }),
        }
    }
}

impl<'de> Deserialize<'de> for OverridePipelineRefinement {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = OverrideRefinementFields::deserialize(deserializer)?;
        Ok(Self {
            id: fields.id,
            artifact: override_artifact_field(fields.artifact, fields.pearl)?,
            input: fields.input,
            action: fields.action,
            effect: fields.effect,
        })
    }
}

fn override_artifact_field<E>(
    artifact: Option<String>,
    pearl: Option<String>,
) -> std::result::Result<String, E>
where
    E: serde::de::Error,
{
    artifact
        .or(pearl)
        .ok_or_else(|| serde::de::Error::missing_field("artifact"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideConflictPolicy {
    #[serde(default)]
    pub mode: OverrideConflictMode,
}

impl Default for OverrideConflictPolicy {
    fn default() -> Self {
        Self {
            mode: OverrideConflictMode::FirstMatch,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverrideConflictMode {
    #[default]
    FirstMatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverrideRefinementAction {
    OverrideIfFires,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverrideEffect {
    #[default]
    UseResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedOverridePipeline {
    pub schema_version: String,
    pub pipeline_id: String,
    pub base: ValidatedOverridePearl,
    pub refinements: Vec<ValidatedOverridePearl>,
    pub conflict: OverrideConflictPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedOverridePearl {
    pub id: String,
    pub role: OverridePearlRole,
    pub artifact: String,
    pub artifact_kind: ArtifactKind,
    pub input_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverridePipelineExecution {
    pub schema_version: String,
    pub engine_version: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub decision_kind: String,
    pub pipeline_id: String,
    pub ok: bool,
    pub output: Value,
    pub selected: String,
    pub selection: OverrideSelection,
    pub base: OverridePearlExecution,
    pub refinements: Vec<OverridePearlExecution>,
    pub stages: Vec<OverridePearlExecution>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverrideSelection {
    pub mode: OverrideConflictMode,
    pub selected_stage: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverridePearlExecution {
    pub id: String,
    pub role: OverridePearlRole,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub artifact_kind: ArtifactKind,
    pub decision_kind: String,
    pub fired: bool,
    pub effect_applied: bool,
    pub skipped: bool,
    pub result: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverridePearlRole {
    Base,
    Refinement,
}

#[derive(Debug, Clone)]
pub struct PreparedOverridePipeline {
    definition: OverridePipelineDefinition,
    base: PreparedOverridePearl,
    refinements: Vec<PreparedOverrideRefinement>,
}

#[derive(Debug, Clone)]
struct PreparedOverridePearl {
    id: String,
    artifact: PreparedOverrideArtifact,
    input: HashMap<String, Value>,
}

#[derive(Debug, Clone)]
struct PreparedOverrideRefinement {
    pearl: PreparedOverridePearl,
    effect: OverrideEffect,
}

#[derive(Debug, Clone)]
enum PreparedOverrideArtifact {
    Gate(LogicPearlGateIr),
    Action(LogicPearlActionIr),
}

impl OverridePipelineDefinition {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let pipeline: Self = serde_json::from_str(input)?;
        Ok(pipeline)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        parse_document(&content)
    }

    pub fn validate(&self, base_dir: impl AsRef<Path>) -> Result<ValidatedOverridePipeline> {
        if self.schema_version != OVERRIDE_PIPELINE_SCHEMA_VERSION {
            return Err(LogicPearlError::message(format!(
                "unsupported override pipeline schema_version: {}; use {OVERRIDE_PIPELINE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.pipeline_id.trim().is_empty() {
            return Err(LogicPearlError::message(
                "override pipeline_id must be non-empty",
            ));
        }
        if self.refinements.is_empty() {
            return Err(LogicPearlError::message(
                "override pipeline must define at least one refinement",
            ));
        }
        validate_override_input_map("pipeline input", &self.input)?;

        let base_dir = base_dir.as_ref();
        let mut ids = BTreeSet::new();
        let base = validate_override_pearl(
            base_dir,
            &self.base,
            OverridePearlRole::Base,
            0,
            &self.input,
            &mut ids,
        )?;
        let refinements = self
            .refinements
            .iter()
            .enumerate()
            .map(|(index, refinement)| {
                validate_override_refinement(base_dir, refinement, index, &self.input, &mut ids)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ValidatedOverridePipeline {
            schema_version: self.schema_version.clone(),
            pipeline_id: self.pipeline_id.clone(),
            base,
            refinements,
            conflict: self.conflict.clone(),
        })
    }

    pub fn inspect(&self, base_dir: impl AsRef<Path>) -> Result<ValidatedOverridePipeline> {
        self.validate(base_dir)
    }

    pub fn run(
        &self,
        base_dir: impl AsRef<Path>,
        root_input: &Value,
    ) -> Result<OverridePipelineExecution> {
        self.prepare(base_dir)?.run(root_input)
    }

    pub fn prepare(&self, base_dir: impl AsRef<Path>) -> Result<PreparedOverridePipeline> {
        self.validate(&base_dir)?;
        let base_dir = base_dir.as_ref();
        let base = prepare_override_pearl(
            base_dir,
            &self.base,
            OverridePearlRole::Base,
            0,
            &self.input,
        )?;
        let refinements = self
            .refinements
            .iter()
            .enumerate()
            .map(|(index, refinement)| {
                let pearl = prepare_override_pearl(
                    base_dir,
                    refinement,
                    OverridePearlRole::Refinement,
                    index,
                    &self.input,
                )?;
                Ok(PreparedOverrideRefinement {
                    pearl,
                    effect: resolve_override_effect(refinement)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(PreparedOverridePipeline {
            definition: self.clone(),
            base,
            refinements,
        })
    }
}

impl PreparedOverridePipeline {
    pub fn run(&self, root_input: &Value) -> Result<OverridePipelineExecution> {
        let base =
            run_prepared_override_pearl(&self.base, OverridePearlRole::Base, root_input, true)?;
        let mut selected = base.id.clone();
        let mut output = base.result.clone();
        let mut selection_reason = "base result used because no refinement fired".to_string();
        let mut applied_refinement = None::<String>;
        let mut refinements = Vec::with_capacity(self.refinements.len());

        for refinement in &self.refinements {
            let mut execution = run_prepared_override_pearl(
                &refinement.pearl,
                OverridePearlRole::Refinement,
                root_input,
                false,
            )?;
            if execution.fired && applied_refinement.is_none() {
                output = apply_override_effect(&refinement.effect, &output, &execution.result)?;
                execution.effect_applied = true;
                selected = execution.id.clone();
                selection_reason = format!(
                    "refinement {} fired and applied first-match override",
                    execution.id
                );
                applied_refinement = Some(execution.id.clone());
            }
            refinements.push(execution);
        }

        let stages = std::iter::once(base.clone())
            .chain(refinements.iter().cloned())
            .collect::<Vec<_>>();

        Ok(OverridePipelineExecution {
            schema_version: OVERRIDE_PIPELINE_RESULT_SCHEMA_VERSION.to_string(),
            engine_version: logicpearl_runtime::LOGICPEARL_ENGINE_VERSION.to_string(),
            artifact_id: self.definition.pipeline_id.clone(),
            artifact_hash: logicpearl_runtime::artifact_hash(&self.definition),
            decision_kind: "pipeline".to_string(),
            pipeline_id: self.definition.pipeline_id.clone(),
            ok: true,
            output,
            selected: selected.clone(),
            selection: OverrideSelection {
                mode: self.definition.conflict.mode,
                selected_stage: selected,
                reason: selection_reason,
            },
            base,
            refinements,
            stages,
        })
    }
}

fn default_override_pipeline_schema_version() -> String {
    OVERRIDE_PIPELINE_SCHEMA_VERSION.to_string()
}

trait OverridePearlConfig {
    fn id(&self) -> Option<&String>;
    fn artifact(&self) -> &str;
    fn input(&self) -> Option<&HashMap<String, Value>>;
}

impl OverridePearlConfig for OverridePipelinePearl {
    fn id(&self) -> Option<&String> {
        self.id.as_ref()
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn input(&self) -> Option<&HashMap<String, Value>> {
        self.input.as_ref()
    }
}

impl OverridePearlConfig for OverridePipelineRefinement {
    fn id(&self) -> Option<&String> {
        self.id.as_ref()
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn input(&self) -> Option<&HashMap<String, Value>> {
        self.input.as_ref()
    }
}

fn validate_override_refinement(
    base_dir: &Path,
    refinement: &OverridePipelineRefinement,
    index: usize,
    default_input: &HashMap<String, Value>,
    ids: &mut BTreeSet<String>,
) -> Result<ValidatedOverridePearl> {
    resolve_override_effect(refinement)?;
    validate_override_pearl(
        base_dir,
        refinement,
        OverridePearlRole::Refinement,
        index,
        default_input,
        ids,
    )
}

fn validate_override_pearl<T: OverridePearlConfig>(
    base_dir: &Path,
    pearl: &T,
    role: OverridePearlRole,
    index: usize,
    default_input: &HashMap<String, Value>,
    ids: &mut BTreeSet<String>,
) -> Result<ValidatedOverridePearl> {
    let id = override_pearl_id(pearl.id(), pearl.artifact(), role, index);
    if !ids.insert(id.clone()) {
        return Err(LogicPearlError::message(format!(
            "duplicate override pipeline pearl id: {id}"
        )));
    }
    let input = effective_override_input(pearl.input(), default_input);
    validate_override_input_map(&format!("override pearl {id} input"), input)?;
    let artifact_path = resolve_relative_path(base_dir, pearl.artifact())?;
    let bundle = load_artifact_bundle(&artifact_path)?;
    let artifact_kind = bundle.manifest.artifact_kind;
    if artifact_kind == ArtifactKind::Pipeline {
        return Err(LogicPearlError::message(format!(
            "override pearl {id} must reference a gate or action artifact, not a pipeline"
        )));
    }
    let ir_path = bundle.ir_path()?;
    match artifact_kind {
        ArtifactKind::Gate => {
            LogicPearlGateIr::from_path(&ir_path)?;
        }
        ArtifactKind::Action => {
            LogicPearlActionIr::from_path(&ir_path)?;
        }
        ArtifactKind::Pipeline => unreachable!("pipeline artifact rejected above"),
    }

    let mut input_fields = input.keys().cloned().collect::<Vec<_>>();
    input_fields.sort();

    Ok(ValidatedOverridePearl {
        id,
        role,
        artifact: pearl.artifact().to_string(),
        artifact_kind,
        input_fields,
    })
}

fn prepare_override_pearl<T: OverridePearlConfig>(
    base_dir: &Path,
    pearl: &T,
    role: OverridePearlRole,
    index: usize,
    default_input: &HashMap<String, Value>,
) -> Result<PreparedOverridePearl> {
    let id = override_pearl_id(pearl.id(), pearl.artifact(), role, index);
    let input = effective_override_input(pearl.input(), default_input).clone();
    let artifact_path = resolve_relative_path(base_dir, pearl.artifact())?;
    let bundle = load_artifact_bundle(&artifact_path)?;
    let artifact = match bundle.manifest.artifact_kind {
        ArtifactKind::Gate => {
            PreparedOverrideArtifact::Gate(LogicPearlGateIr::from_path(bundle.ir_path()?)?)
        }
        ArtifactKind::Action => {
            PreparedOverrideArtifact::Action(LogicPearlActionIr::from_path(bundle.ir_path()?)?)
        }
        ArtifactKind::Pipeline => {
            return Err(LogicPearlError::message(format!(
                "override pearl {id} must reference a gate or action artifact, not a pipeline"
            )))
        }
    };
    Ok(PreparedOverridePearl {
        id,
        artifact,
        input,
    })
}

fn effective_override_input<'a>(
    pearl_input: Option<&'a HashMap<String, Value>>,
    default_input: &'a HashMap<String, Value>,
) -> &'a HashMap<String, Value> {
    pearl_input.unwrap_or(default_input)
}

fn validate_override_input_map(label: &str, input: &HashMap<String, Value>) -> Result<()> {
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

fn resolve_override_effect(refinement: &OverridePipelineRefinement) -> Result<OverrideEffect> {
    match refinement.action {
        Some(OverrideRefinementAction::OverrideIfFires) => {}
        None => {
            return Err(LogicPearlError::message(
                "override refinements must set action: override_if_fires",
            ));
        }
    }
    Ok(refinement.effect.clone())
}

fn run_prepared_override_pearl(
    pearl: &PreparedOverridePearl,
    role: OverridePearlRole,
    root_input: &Value,
    effect_applied: bool,
) -> Result<OverridePearlExecution> {
    let features = build_override_input_object(pearl, root_input)?;
    let (artifact_kind, result) = match &pearl.artifact {
        PreparedOverrideArtifact::Gate(gate) => (
            ArtifactKind::Gate,
            serde_json::to_value(logicpearl_runtime::evaluate_gate_with_explanation(
                gate, &features,
            )?)?,
        ),
        PreparedOverrideArtifact::Action(policy) => (
            ArtifactKind::Action,
            serde_json::to_value(logicpearl_runtime::evaluate_action_policy(
                policy, &features,
            )?)?,
        ),
    };
    let artifact_id = result
        .get("artifact_id")
        .and_then(Value::as_str)
        .unwrap_or(&pearl.id)
        .to_string();
    let artifact_hash = result
        .get("artifact_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let decision_kind = result
        .get("decision_kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let fired = runtime_result_fired(&result);
    Ok(OverridePearlExecution {
        id: pearl.id.clone(),
        role,
        artifact_id,
        artifact_hash,
        artifact_kind,
        decision_kind,
        fired,
        effect_applied,
        skipped: false,
        result,
    })
}

fn build_override_input_object(
    pearl: &PreparedOverridePearl,
    root_input: &Value,
) -> Result<HashMap<String, Value>> {
    if pearl.input.is_empty() {
        let object = root_input.as_object().ok_or_else(|| {
            LogicPearlError::message(format!(
                "override pearl {} expected object pipeline input",
                pearl.id
            ))
        })?;
        return Ok(object
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect());
    }

    let exports = HashMap::new();
    pearl
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

fn apply_override_effect(
    effect: &OverrideEffect,
    _current: &Value,
    refinement: &Value,
) -> Result<Value> {
    match effect {
        OverrideEffect::UseResult => Ok(refinement.clone()),
    }
}

fn runtime_result_fired(result: &Value) -> bool {
    let rule_fired = result.get("bitmask").is_some_and(rule_mask_value_nonzero)
        || result
            .get("matched_rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| !rules.is_empty());
    let action_selected = result
        .get("decision_kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "action")
        && result
            .get("defaulted")
            .and_then(Value::as_bool)
            .is_some_and(|defaulted| !defaulted);
    rule_fired || action_selected
}

fn rule_mask_value_nonzero(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_u64().unwrap_or(0) != 0,
        Value::String(text) => text != "0" && !text.is_empty(),
        Value::Array(items) => items.iter().any(rule_mask_value_nonzero),
        _ => false,
    }
}

fn override_pearl_id(
    configured: Option<&String>,
    artifact: &str,
    role: OverridePearlRole,
    index: usize,
) -> String {
    if let Some(id) = configured {
        let id = id.trim();
        if !id.is_empty() {
            return id.to_string();
        }
    }
    let path = Path::new(artifact);
    let source = path
        .file_stem()
        .or_else(|| path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or(match role {
            OverridePearlRole::Base => "base",
            OverridePearlRole::Refinement => "refinement",
        });
    sanitize_stage_id(source, index)
}
