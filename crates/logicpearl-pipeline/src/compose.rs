// SPDX-License-Identifier: MIT

use crate::path::{manifest_member_path_for_base, parse_document, sanitize_stage_id};
use crate::staged::{PipelineDefinition, PipelineStage, PipelineStageKind};
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ComposePlan {
    pub pipeline: PipelineDefinition,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ComposeInputMap {
    #[serde(default)]
    pub features: HashMap<String, Value>,
    #[serde(default)]
    pub stages: HashMap<String, HashMap<String, Value>>,
}

impl ComposeInputMap {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let value: Value = parse_document(input)?;
        Self::from_value(value)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    fn from_value(value: Value) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            LogicPearlError::message("compose input map must be a JSON or YAML object")
        })?;
        let structured = object.contains_key("features") || object.contains_key("stages");
        if !structured {
            return Ok(Self {
                features: object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
                stages: HashMap::new(),
            });
        }

        for key in object.keys() {
            if key != "features" && key != "stages" {
                return Err(LogicPearlError::message(format!(
                    "unknown compose input map field `{key}`; expected `features` or `stages`"
                )));
            }
        }

        serde_json::from_value(value).map_err(LogicPearlError::from)
    }

    fn get(&self, stage_id: &str, feature_id: &str) -> Option<&Value> {
        self.stages
            .get(stage_id)
            .and_then(|stage| stage.get(feature_id))
            .or_else(|| self.features.get(feature_id))
    }
}

pub fn compose_pipeline(
    pipeline_id: impl Into<String>,
    artifact_paths: &[PathBuf],
    base_dir: impl AsRef<Path>,
    input_map: &ComposeInputMap,
) -> Result<ComposePlan> {
    let base_dir = base_dir.as_ref();
    let plan = build_pipeline(
        pipeline_id,
        artifact_paths,
        base_dir,
        ComposeInputMode::Explicit(input_map),
    )?;
    plan.pipeline.validate(base_dir)?;
    Ok(plan)
}

pub fn scaffold_pipeline(
    pipeline_id: impl Into<String>,
    artifact_paths: &[PathBuf],
    base_dir: impl AsRef<Path>,
) -> Result<ComposePlan> {
    build_pipeline(
        pipeline_id,
        artifact_paths,
        base_dir.as_ref(),
        ComposeInputMode::Scaffold,
    )
}

enum ComposeInputMode<'a> {
    Explicit(&'a ComposeInputMap),
    Scaffold,
}

fn build_pipeline(
    pipeline_id: impl Into<String>,
    artifact_paths: &[PathBuf],
    base_dir: &Path,
    input_mode: ComposeInputMode<'_>,
) -> Result<ComposePlan> {
    if artifact_paths.is_empty() {
        return Err(LogicPearlError::message(
            "compose requires at least one pearl artifact path",
        ));
    }

    let pipeline_id = pipeline_id.into();
    let mut stages = Vec::with_capacity(artifact_paths.len());
    let mut notes = Vec::new();

    for (index, artifact_path) in artifact_paths.iter().enumerate() {
        let gate = LogicPearlGateIr::from_path(artifact_path)?;
        let stage_id = sanitize_stage_id(&gate.gate_id, index);
        let artifact = manifest_member_path_for_base(base_dir, artifact_path)?;

        let mut input = HashMap::new();
        for feature in &gate.input_schema.features {
            let value = match input_mode {
                ComposeInputMode::Explicit(input_map) => input_map
                    .get(&stage_id, &feature.id)
                    .cloned()
                    .ok_or_else(|| {
                        LogicPearlError::message(format!(
                            "compose input map is missing feature `{}` for stage `{}`",
                            feature.id, stage_id
                        ))
                    })?,
                ComposeInputMode::Scaffold => Value::String(format!("$.TODO_{}", feature.id)),
            };
            input.insert(feature.id.clone(), value);
        }

        let mut export = HashMap::new();
        export.insert(
            "bitmask".to_string(),
            Value::String("$.bitmask".to_string()),
        );
        export.insert("allow".to_string(), Value::String("$.allow".to_string()));

        match input_mode {
            ComposeInputMode::Explicit(_) => notes.push(format!(
                "stage `{}` maps {} input feature(s) from the explicit input map",
                stage_id,
                gate.input_schema.features.len()
            )),
            ComposeInputMode::Scaffold => notes.push(format!(
                "stage `{}` maps {} input feature(s) from placeholder root paths; this scaffold is not runnable until `$.TODO_*` references are replaced",
                stage_id,
                gate.input_schema.features.len()
            )),
        }

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
