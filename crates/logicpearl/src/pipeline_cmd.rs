// SPDX-License-Identifier: MIT
use super::*;
use anstream::println;
use clap::Args;

#[derive(Debug, Args)]
#[command(
    after_help = "Example:\n  logicpearl pipeline validate examples/pipelines/authz/pipeline.json --json"
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
    after_help = "Example:\n  logicpearl pipeline inspect examples/pipelines/observer_membership_verify/pipeline.json --json"
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
    after_help = "Plugin trust:\n  Plugin-backed pipelines execute local programs declared by plugin manifests.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl pipeline run examples/pipelines/authz/pipeline.json examples/pipelines/authz/input.json --json\n  logicpearl pipeline run examples/pipelines/authz/pipeline.json - --json\n  cat examples/pipelines/authz/input.json | logicpearl pipeline run examples/pipelines/authz/pipeline.json --json"
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
    after_help = "Plugin trust:\n  Plugin-backed pipelines execute local programs declared by plugin manifests.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExample:\n  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
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
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("could not load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
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
    Ok(())
}

pub(crate) fn run_pipeline_inspect(args: PipelineInspectArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("could not load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
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
    Ok(())
}

pub(crate) fn run_pipeline_run(args: PipelineRunArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("could not load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let input = read_json_input_argument(args.input_json.as_ref(), "pipeline input")?;
    let policy = plugin_execution_policy(&args.plugin_execution);
    let execution = pipeline
        .run_with_plugin_policy(base_dir, &input, policy)
        .into_diagnostic()
        .wrap_err("pipeline execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&execution).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Pipeline".bold().bright_green(),
            execution.pipeline_id.bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&execution.output).into_diagnostic()?
        );
    }
    Ok(())
}

pub(crate) fn run_pipeline_trace(args: PipelineTraceArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("could not load pipeline artifact")?;
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
    let execution = pipeline
        .run_with_plugin_policy(base_dir, &input, policy)
        .into_diagnostic()
        .wrap_err("pipeline trace execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&execution).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Pipeline Trace".bold().bright_yellow(),
            execution.pipeline_id.bold()
        );
        println!(
            "  {} {}",
            "Final output".bright_black(),
            serde_json::to_string(&execution.output).into_diagnostic()?
        );
        for stage in &execution.stages {
            println!(
                "  {} {} {}",
                "-".bright_black(),
                stage.id.bold(),
                format!("{:?}", stage.kind).bright_black()
            );
            println!("    {} {}", "Skipped".bright_black(), stage.skipped);
            println!(
                "    {} {}",
                "Exports".bright_black(),
                serde_json::to_string(&stage.exports).into_diagnostic()?
            );
            println!(
                "    {} {}",
                "Raw".bright_black(),
                serde_json::to_string(&stage.raw_result).into_diagnostic()?
            );
        }
    }
    Ok(())
}
