// SPDX-License-Identifier: MIT
//! Pipeline composition and execution for "string of pearls" workflows.
//!
//! Pipelines wire together pearl artifacts, plugin stages, stage inputs,
//! exports, and final outputs. This crate parses pipeline definitions,
//! prepares manifest-relative paths with the shared path policy, executes
//! trusted local plugins when requested, and preserves each stage's raw
//! runtime result for audit.

mod compose;
mod fanout_pipeline;
mod json_path;
mod override_pipeline;
mod path;
mod staged;

pub use compose::{compose_pipeline, scaffold_pipeline, ComposeInputMap, ComposePlan};
pub use fanout_pipeline::{
    build_fanout_pipeline, FanoutActionGate, FanoutActionVerdict, FanoutPipelineDefinition,
    FanoutPipelineExecution, PreparedFanoutPipeline, ValidatedFanoutActionGate,
    ValidatedFanoutPipeline, FANOUT_PIPELINE_SCHEMA_VERSION, FANOUT_RESULT_SCHEMA_VERSION,
};
pub use override_pipeline::{
    OverrideConflictMode, OverrideConflictPolicy, OverrideEffect, OverridePearlExecution,
    OverridePearlRole, OverridePipelineDefinition, OverridePipelineExecution,
    OverridePipelinePearl, OverridePipelineRefinement, OverrideRefinementAction, OverrideSelection,
    PreparedOverridePipeline, ValidatedOverridePearl, ValidatedOverridePipeline,
    OVERRIDE_PIPELINE_RESULT_SCHEMA_VERSION, OVERRIDE_PIPELINE_SCHEMA_VERSION,
};
pub use staged::{
    PipelineDefinition, PipelineExecution, PipelineStage, PipelineStageKind, PreparedPipeline,
    StageExecution, ValidatedPipeline, ValidatedStage,
};

#[cfg(test)]
pub(crate) use path::parse_document;

#[cfg(test)]
mod tests;
