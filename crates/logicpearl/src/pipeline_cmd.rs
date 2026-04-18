// SPDX-License-Identifier: MIT
use super::*;
use anstream::println;
use clap::Args;
use logicpearl_pipeline::{
    OverridePipelineDefinition, PipelineDefinition, OVERRIDE_PIPELINE_SCHEMA_VERSION,
};
use std::path::Path;

enum LoadedPipeline {
    Staged(PipelineDefinition),
    Override(OverridePipelineDefinition),
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  logicpearl pipeline validate examples/pipelines/authz/pipeline.json --json\n  logicpearl pipeline validate pipeline.yaml --json"
)]
pub(crate) struct PipelineValidateArgs {
    /// Pipeline definition to validate.
    #[arg(value_name = "PIPELINE")]
    pub pipeline_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  logicpearl pipeline inspect examples/pipelines/observer_membership_verify/pipeline.json --json\n  logicpearl pipeline inspect pipeline.yaml --json"
)]
pub(crate) struct PipelineInspectArgs {
    /// Pipeline definition to inspect.
    #[arg(value_name = "PIPELINE")]
    pub pipeline_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Plugin trust:\n  Plugin-backed pipelines execute local programs declared by plugin manifests.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl pipeline run examples/pipelines/authz/pipeline.json examples/pipelines/authz/input.json --json\n  logicpearl pipeline run pipeline.yaml input.json --json\n  logicpearl pipeline run examples/pipelines/authz/pipeline.json - --json\n  cat examples/pipelines/authz/input.json | logicpearl pipeline run examples/pipelines/authz/pipeline.json --json"
)]
pub(crate) struct PipelineRunArgs {
    /// Pipeline definition to run.
    #[arg(value_name = "PIPELINE")]
    pub pipeline_json: PathBuf,
    /// Input JSON file, `-` for stdin, or omit to read stdin.
    #[arg(value_name = "INPUT")]
    pub input_json: Option<PathBuf>,
    #[command(flatten)]
    pub plugin_execution: PluginExecutionArgs,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Plugin trust:\n  Plugin-backed pipelines execute local programs declared by plugin manifests.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json\n  logicpearl pipeline trace pipeline.yaml input.json --json"
)]
pub(crate) struct PipelineTraceArgs {
    /// Pipeline definition to trace.
    #[arg(value_name = "PIPELINE")]
    pub pipeline_json: PathBuf,
    /// Input JSON file to run through the pipeline.
    #[arg(value_name = "INPUT")]
    pub input_json: PathBuf,
    #[command(flatten)]
    pub plugin_execution: PluginExecutionArgs,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn run_pipeline_validate(args: PipelineValidateArgs) -> Result<()> {
    let pipeline = load_pipeline(&args.pipeline_json)?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    match pipeline {
        LoadedPipeline::Staged(pipeline) => {
            let validated = pipeline
                .validate(base_dir)
                .into_diagnostic()
                .wrap_err("pipeline validation failed")?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&validated).into_diagnostic()?
                );
            } else {
                println!(
                    "{} {}",
                    "Pipeline".bold().bright_cyan(),
                    format!("manifest is valid ({})", validated.pipeline_id).bright_black()
                );
                println!("  {} {}", "Stages".bright_black(), validated.stage_count);
                println!(
                    "  {} {}",
                    "Exports".bright_black(),
                    validated.exports.join(", ")
                );
                for stage in &validated.stages {
                    println!(
                        "  {} {} {}",
                        "-".bright_black(),
                        stage.id.bold(),
                        format!("{:?}", stage.kind).bright_black()
                    );
                }
            }
        }
        LoadedPipeline::Override(pipeline) => {
            let validated = pipeline
                .validate(base_dir)
                .into_diagnostic()
                .wrap_err("override pipeline validation failed")?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&validated).into_diagnostic()?
                );
            } else {
                println!(
                    "{} {}",
                    "Override Pipeline".bold().bright_cyan(),
                    format!("manifest is valid ({})", validated.pipeline_id).bright_black()
                );
                println!("  {} {}", "Base".bright_black(), validated.base.id);
                println!(
                    "  {} {}",
                    "Refinements".bright_black(),
                    validated.refinements.len()
                );
                for refinement in &validated.refinements {
                    println!("  {} {}", "-".bright_black(), refinement.id.bold());
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn run_pipeline_inspect(args: PipelineInspectArgs) -> Result<()> {
    let pipeline = load_pipeline(&args.pipeline_json)?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    match pipeline {
        LoadedPipeline::Staged(pipeline) => {
            let validated = pipeline
                .inspect(base_dir)
                .into_diagnostic()
                .wrap_err("pipeline inspection failed")?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&validated).into_diagnostic()?
                );
            } else {
                println!(
                    "{} {}",
                    "String Of Pearls".bold().bright_blue(),
                    validated.pipeline_id.bold()
                );
                println!("  {} {}", "Entrypoint".bright_black(), validated.entrypoint);
                println!("  {} {}", "Stages".bright_black(), validated.stage_count);
                println!(
                    "  {} {}",
                    "Final exports".bright_black(),
                    validated.exports.join(", ")
                );
                for stage in &validated.stages {
                    println!(
                        "  {} {} {}",
                        "-".bright_black(),
                        stage.id.bold(),
                        format!("{:?}", stage.kind).bright_black()
                    );
                    if let Some(artifact) = &stage.artifact {
                        println!("    {} {}", "Artifact".bright_black(), artifact);
                    }
                    if let Some(plugin_manifest) = &stage.plugin_manifest {
                        println!("    {} {}", "Plugin".bright_black(), plugin_manifest);
                    }
                    if !stage.exports.is_empty() {
                        println!(
                            "    {} {}",
                            "Exports".bright_black(),
                            stage.exports.join(", ")
                        );
                    }
                }
            }
        }
        LoadedPipeline::Override(pipeline) => {
            let validated = pipeline
                .inspect(base_dir)
                .into_diagnostic()
                .wrap_err("override pipeline inspection failed")?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&validated).into_diagnostic()?
                );
            } else {
                println!(
                    "{} {}",
                    "Override Pipeline".bold().bright_blue(),
                    validated.pipeline_id.bold()
                );
                println!("  {} {}", "Base".bright_black(), validated.base.id);
                for refinement in &validated.refinements {
                    println!("  {} {}", "Refinement".bright_black(), refinement.id);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn run_pipeline_run(args: PipelineRunArgs) -> Result<()> {
    let pipeline = load_pipeline(&args.pipeline_json)?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let input = read_json_input_argument(args.input_json.as_ref(), "pipeline input")?;
    let policy = plugin_execution_policy(&args.plugin_execution);
    if matches!(pipeline, LoadedPipeline::Override(_))
        && policy != logicpearl_plugin::PluginExecutionPolicy::default()
    {
        return Err(miette::miette!(
            "override pipelines do not execute plugin stages; plugin execution flags are not used"
        ));
    }
    let execution = match pipeline {
        LoadedPipeline::Staged(pipeline) => serde_json::to_value(
            pipeline
                .run_with_plugin_policy(base_dir, &input, policy)
                .into_diagnostic()
                .wrap_err("pipeline execution failed")?,
        )
        .into_diagnostic()?,
        LoadedPipeline::Override(pipeline) => serde_json::to_value(
            pipeline
                .run(base_dir, &input)
                .into_diagnostic()
                .wrap_err("override pipeline execution failed")?,
        )
        .into_diagnostic()?,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&execution).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Pipeline".bold().bright_green(),
            execution["pipeline_id"]
                .as_str()
                .unwrap_or("pipeline")
                .bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&execution["output"]).into_diagnostic()?
        );
    }
    Ok(())
}

pub(crate) fn run_pipeline_trace(args: PipelineTraceArgs) -> Result<()> {
    let pipeline = load_pipeline(&args.pipeline_json)?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input_json)
            .into_diagnostic()
            .wrap_err("failed to read pipeline input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("pipeline input JSON is not valid JSON")?;
    let policy = plugin_execution_policy(&args.plugin_execution);
    if matches!(pipeline, LoadedPipeline::Override(_))
        && policy != logicpearl_plugin::PluginExecutionPolicy::default()
    {
        return Err(miette::miette!(
            "override pipelines do not execute plugin stages; plugin execution flags are not used"
        ));
    }
    let execution = match pipeline {
        LoadedPipeline::Staged(pipeline) => serde_json::to_value(
            pipeline
                .run_with_plugin_policy(base_dir, &input, policy)
                .into_diagnostic()
                .wrap_err("pipeline trace execution failed")?,
        )
        .into_diagnostic()?,
        LoadedPipeline::Override(pipeline) => serde_json::to_value(
            pipeline
                .run(base_dir, &input)
                .into_diagnostic()
                .wrap_err("override pipeline trace execution failed")?,
        )
        .into_diagnostic()?,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&execution).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Pipeline Trace".bold().bright_yellow(),
            execution["pipeline_id"]
                .as_str()
                .unwrap_or("pipeline")
                .bold()
        );
        println!(
            "  {} {}",
            "Final output".bright_black(),
            serde_json::to_string(&execution["output"]).into_diagnostic()?
        );
        let stages = execution["stages"].as_array().cloned().unwrap_or_default();
        for stage in stages {
            println!(
                "  {} {} {}",
                "-".bright_black(),
                stage["id"].as_str().unwrap_or("stage").bold(),
                stage["role"]
                    .as_str()
                    .or_else(|| stage["kind"].as_str())
                    .unwrap_or("stage")
                    .bright_black()
            );
            println!("    {} {}", "Skipped".bright_black(), stage["skipped"]);
            println!(
                "    {} {}",
                "Raw".bright_black(),
                serde_json::to_string(
                    stage
                        .get("raw_result")
                        .or_else(|| stage.get("result"))
                        .unwrap_or(&Value::Null)
                )
                .into_diagnostic()?
            );
        }
    }
    Ok(())
}

fn load_pipeline(path: &Path) -> Result<LoadedPipeline> {
    if is_override_pipeline(path)? {
        Ok(LoadedPipeline::Override(
            OverridePipelineDefinition::from_path(path)
                .into_diagnostic()
                .wrap_err("could not load override pipeline artifact")?,
        ))
    } else {
        Ok(LoadedPipeline::Staged(
            PipelineDefinition::from_path(path)
                .into_diagnostic()
                .wrap_err("could not load pipeline artifact")?,
        ))
    }
}

fn is_override_pipeline(path: &Path) -> Result<bool> {
    let content = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err("failed to read pipeline artifact")?;
    let value: Value = serde_json::from_str(&content)
        .or_else(|_| serde_norway::from_str(&content))
        .into_diagnostic()
        .wrap_err("pipeline artifact is not valid JSON or YAML")?;
    Ok(value
        .get("schema_version")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema == OVERRIDE_PIPELINE_SCHEMA_VERSION))
}
