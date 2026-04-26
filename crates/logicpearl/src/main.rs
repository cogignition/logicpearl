// SPDX-License-Identifier: MIT
#![recursion_limit = "256"]

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use logicpearl_benchmark::{
    benchmark_adapter_registry, detect_benchmark_adapter_profile, emit_trace_tables,
    load_benchmark_cases, load_synthesis_case_rows, load_synthesis_cases,
    load_trace_projection_config, sanitize_identifier, write_benchmark_cases_jsonl,
    BenchmarkAdaptDefaults, BenchmarkAdapterProfile, BenchmarkCase, ObservedBenchmarkCase,
    SynthesisCase, SynthesisCaseRow,
};
use logicpearl_discovery::{
    discover_from_csv, DecisionTraceRow, DiscoverOptions, DiscoveryDecisionMode,
};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_observer::{
    default_artifact_for_profile, detect_profile_from_input, load_artifact, observe_with_artifact,
    observe_with_profile, profile_id as native_profile_id, profile_registry,
    status as observer_status, GuardrailsSignal, NativeObserverArtifact,
    ObserverProfile as NativeObserverProfile,
};
use logicpearl_observer_synthesis::{
    repair_guardrails_artifact, synthesize_guardrails_artifact,
    synthesize_guardrails_artifact_auto, ObserverAutoSynthesisOptions, ObserverBootstrapStrategy,
    ObserverTargetGoal,
};
use logicpearl_pipeline::PipelineDefinition;
use logicpearl_plugin::{
    run_plugin_batch_with_policy, run_plugin_with_policy, run_plugin_with_policy_and_metadata,
    PluginExecutionPolicy, PluginExecutionResult, PluginManifest, PluginRequest, PluginStage,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::{Map, Value};
use std::fs;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

mod artifact_cmd;
mod basic_cmd;
mod benchmark_cmd;
#[cfg(feature = "conformance")]
mod conformance_cmd;
mod diff_cmd;
mod observer_cmd;
mod pipeline_cmd;
mod plugin_cmd;
mod trace_cmd;

use artifact_cmd::{
    artifact_bundle_descriptor_from_manifest, build_deployable_bundle_descriptor,
    build_options_hash, compile_native_fanout_runner, compile_native_runner,
    compile_wasm_fanout_module, compile_wasm_module, is_rust_target_installed,
    native_artifact_output_path, pearl_artifact_id, persist_build_report,
    refresh_artifact_manifest_deployables, resolve_artifact_input, resolve_manifest_member_path,
    run_artifact_digest, run_artifact_inspect, run_artifact_verify,
    run_embedded_native_runner_if_present, wasm_artifact_output_path, write_artifact_manifest_v1,
    write_named_artifact_manifest, ArtifactBundleDescriptor, ArtifactCommand,
    ArtifactManifestWriteOptions,
};
use basic_cmd::{
    run_build, run_compile, run_compose, run_discover, run_doctor, run_eval, run_inspect,
    run_quickstart, run_refine, run_review, run_trace, run_verify, BuildArgs, CompileArgs,
    ComposeArgs, DiscoverArgs, DoctorArgs, InspectArgs, QuickstartArgs, RefineArgs, ReviewArgs,
    RunArgs, TraceArgs, VerifyArgs,
};
use benchmark_cmd::{
    run_benchmark, run_benchmark_adapt, run_benchmark_detect_profile, run_benchmark_emit_traces,
    run_benchmark_learn, run_benchmark_list_profiles, run_benchmark_merge_cases,
    run_benchmark_observe, run_benchmark_score_artifacts, run_benchmark_split_cases,
    BenchmarkCommand,
};
#[cfg(feature = "conformance")]
use conformance_cmd::{
    run_conformance_runtime_parity, run_conformance_spec_verify,
    run_conformance_validate_artifacts, run_conformance_write_manifest, ConformanceCommand,
};
use diff_cmd::{run_diff, DiffArgs};
use observer_cmd::{
    run_observer_detect, run_observer_list, run_observer_repair, run_observer_run,
    run_observer_scaffold, run_observer_synthesize, run_observer_validate, ObserverCommand,
};
use pipeline_cmd::{
    run_pipeline_inspect, run_pipeline_run, run_pipeline_trace, run_pipeline_validate,
    PipelineCommand,
};
use plugin_cmd::{run_plugin_run, run_plugin_validate, PluginCommand};
use trace_cmd::{
    run_traces_audit, run_traces_generate, run_traces_observation_schema, TraceCommand,
};

const CLI_LONG_ABOUT: &str = "\
LogicPearl turns normalized decision behavior into deterministic artifacts.

Use this CLI to:
- get a guided first run
- build pearls from labeled traces
- inspect and run pearls
- compile optional native or Wasm deployables
- compose and execute string-of-pearls pipelines
- score benchmark datasets with explicit route outputs

Common commands:
- quickstart
- doctor
- traces
- build
- inspect
- review
- trace
- refine
- diff
- run
- compile
- pipeline
- benchmark";

const CLI_AFTER_HELP: &str = "\
Examples:
  logicpearl quickstart
  logicpearl doctor examples/getting_started/decision_traces.csv
  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output
  logicpearl inspect examples/getting_started/output
  logicpearl review examples/getting_started/output examples/getting_started/new_input.json
  logicpearl trace examples/getting_started/output examples/getting_started/decision_traces.csv --show-near-misses
  logicpearl refine examples/getting_started/output --pin rules.json
  logicpearl diff old_output new_output
  logicpearl run examples/getting_started/output examples/getting_started/new_input.json
  cat examples/getting_started/new_input.json | logicpearl run examples/getting_started/output -
  logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json
  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json

For command-specific help, run:
  logicpearl <command> --help";

fn guidance(message: impl AsRef<str>, hint: impl AsRef<str>) -> miette::Report {
    miette::miette!(help = hint.as_ref().to_owned(), "{}", message.as_ref())
}

fn plugin_execution_policy(args: &PluginExecutionArgs) -> PluginExecutionPolicy {
    PluginExecutionPolicy::default()
        .with_allow_no_timeout(args.allow_no_timeout)
        .with_allow_absolute_entrypoint(args.allow_absolute_plugin_entrypoint)
        .with_allow_path_lookup(args.allow_plugin_path_lookup)
}

#[derive(Debug, Clone, Default, Args)]
struct PluginExecutionArgs {
    /// Allow trusted plugin manifests to disable timeouts with timeout_ms=0.
    #[arg(long, help_heading = "Plugin Execution")]
    allow_no_timeout: bool,
    /// Allow trusted plugin manifests to use absolute executable or script paths.
    #[arg(long, help_heading = "Plugin Execution")]
    allow_absolute_plugin_entrypoint: bool,
    /// Allow trusted plugin manifests to resolve arbitrary entrypoint programs from PATH.
    #[arg(long, help_heading = "Plugin Execution")]
    allow_plugin_path_lookup: bool,
}

fn read_json_input_argument(input_json: Option<&PathBuf>, context: &str) -> Result<Value> {
    let raw = match input_json {
        None => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .into_diagnostic()
                .wrap_err(format!("failed to read {context} JSON from stdin"))?;
            buffer
        }
        Some(path) if path.as_os_str() == "-" => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .into_diagnostic()
                .wrap_err(format!("failed to read {context} JSON from stdin"))?;
            buffer
        }
        Some(path) => fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err(format!("failed to read {context} JSON"))?,
    };

    serde_json::from_str(&raw)
        .into_diagnostic()
        .wrap_err(format!("{context} JSON is not valid JSON"))
}

const fn cli_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects, Style};
    clap::builder::Styles::styled()
        .header(
            Style::new()
                .fg_color(Some(clap::builder::styling::Color::Ansi(
                    AnsiColor::BrightGreen,
                )))
                .effects(Effects::BOLD),
        )
        .usage(
            Style::new()
                .fg_color(Some(clap::builder::styling::Color::Ansi(
                    AnsiColor::BrightGreen,
                )))
                .effects(Effects::BOLD),
        )
        .literal(
            Style::new().fg_color(Some(clap::builder::styling::Color::Ansi(
                AnsiColor::BrightCyan,
            ))),
        )
        .placeholder(
            Style::new().fg_color(Some(clap::builder::styling::Color::Ansi(AnsiColor::Cyan))),
        )
        .valid(Style::new().fg_color(Some(clap::builder::styling::Color::Ansi(AnsiColor::Green))))
        .invalid(Style::new().fg_color(Some(clap::builder::styling::Color::Ansi(AnsiColor::Red))))
        .error(
            Style::new()
                .fg_color(Some(clap::builder::styling::Color::Ansi(AnsiColor::Red)))
                .effects(Effects::BOLD),
        )
}

#[derive(Debug, Parser)]
#[command(
    name = "logicpearl",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("LOGICPEARL_GIT_HASH"), ")"),
    about = "Build, inspect, run, and benchmark deterministic LogicPearl artifacts.",
    long_about = CLI_LONG_ABOUT,
    after_help = CLI_AFTER_HELP,
    styles = cli_styles(),
)]
struct Cli {
    /// When to use terminal colors.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ColorChoice {
    /// Colorize output when stdout is a terminal and NO_COLOR is not set.
    Auto,
    /// Always colorize output.
    Always,
    /// Never colorize output.
    Never,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Print the shortest command recipes for trying LogicPearl.
    Quickstart(QuickstartArgs),
    /// Turn labeled examples into a pearl.
    Build(BuildArgs),
    /// Inspect traces and recommend the right build command.
    Doctor(DoctorArgs),
    /// Generate and audit labeled decision traces.
    Traces {
        #[command(subcommand)]
        command: TraceCommand,
    },
    /// Inspect a pearl and see what it does.
    Inspect(InspectArgs),
    /// Review one input against a pearl with evidence-oriented output.
    Review(ReviewArgs),
    /// Replay reviewed traces against a pearl.
    Trace(TraceArgs),
    /// Rebuild a pearl from its provenance while pinning reviewer-edited rules.
    Refine(RefineArgs),
    /// Compare two artifacts semantically instead of by raw bit position.
    Diff(DiffArgs),
    /// Inspect, digest, and verify artifact bundle manifests.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Run a pearl on an input file.
    Run(RunArgs),
    /// Work with string-of-pearls pipelines.
    Pipeline {
        #[command(subcommand)]
        command: PipelineCommand,
    },
    /// Validate and smoke-test JSON plugin stages.
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Test a pipeline against a benchmark dataset and see how it performs.
    Benchmark {
        #[command(subcommand)]
        command: BenchmarkCommand,
    },
    #[command(hide = true)]
    /// Learn multiple pearls from one dataset.
    Discover(DiscoverArgs),
    #[command(hide = true)]
    /// Create a starter pipeline from existing pearls.
    Compose(ComposeArgs),
    /// Compile a pearl into an optional native or Wasm deployable.
    Compile(CompileArgs),
    #[cfg(feature = "conformance")]
    #[command(hide = true)]
    /// Validate artifact freshness and check runtime parity.
    Conformance {
        #[command(subcommand)]
        command: ConformanceCommand,
    },
    #[command(hide = true)]
    /// Check a pearl with a verifier plugin.
    Verify(VerifyArgs),
    #[command(hide = true)]
    /// Work with observers that turn messy input into normalized features.
    Observer {
        #[command(subcommand)]
        command: ObserverCommand,
    },
    /// Generate shell completion scripts.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() -> Result<()> {
    if run_embedded_native_runner_if_present()? {
        return Ok(());
    }

    let cli = Cli::parse();

    // Respect --color flag, NO_COLOR env var (https://no-color.org), and TTY detection.
    // anstream strips ANSI codes from println! output; owo_colors set_override gates
    // if_supports_color() calls.
    let anstream_choice = match cli.color {
        ColorChoice::Always => anstream::ColorChoice::Always,
        ColorChoice::Never => anstream::ColorChoice::Never,
        ColorChoice::Auto => anstream::ColorChoice::Auto,
    };
    anstream_choice.write_global();
    let color = match cli.color {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    };
    owo_colors::set_override(color);
    match cli.command {
        Commands::Benchmark {
            command: BenchmarkCommand::ListProfiles(args),
        } => run_benchmark_list_profiles(args),
        Commands::Benchmark {
            command: BenchmarkCommand::DetectProfile(args),
        } => run_benchmark_detect_profile(args),
        Commands::Benchmark {
            command: BenchmarkCommand::Adapt(args),
        } => run_benchmark_adapt(args),
        Commands::Benchmark {
            command: BenchmarkCommand::SplitCases(args),
        } => run_benchmark_split_cases(args),
        Commands::Benchmark {
            command: BenchmarkCommand::Learn(args),
        } => run_benchmark_learn(args),
        Commands::Benchmark {
            command: BenchmarkCommand::MergeCases(args),
        } => run_benchmark_merge_cases(args),
        Commands::Benchmark {
            command: BenchmarkCommand::Observe(args),
        } => run_benchmark_observe(args),
        Commands::Benchmark {
            command: BenchmarkCommand::EmitTraces(args),
        } => run_benchmark_emit_traces(args),
        Commands::Benchmark {
            command: BenchmarkCommand::ScoreArtifacts(args),
        } => run_benchmark_score_artifacts(args),
        Commands::Benchmark {
            command: BenchmarkCommand::Run(args),
        } => run_benchmark(args),
        Commands::Traces {
            command: TraceCommand::Generate(args),
        } => run_traces_generate(args),
        Commands::Traces {
            command: TraceCommand::Audit(args),
        } => run_traces_audit(args),
        Commands::Traces {
            command: TraceCommand::ObservationSchema(args),
        } => run_traces_observation_schema(args),
        Commands::Build(args) => run_build(args),
        Commands::Doctor(args) => run_doctor(args),
        Commands::Quickstart(args) => run_quickstart(args),
        Commands::Discover(args) => run_discover(args),
        Commands::Compose(args) => run_compose(args),
        Commands::Compile(args) => run_compile(args),
        #[cfg(feature = "conformance")]
        Commands::Conformance {
            command: ConformanceCommand::WriteManifest(args),
        } => run_conformance_write_manifest(args),
        #[cfg(feature = "conformance")]
        Commands::Conformance {
            command: ConformanceCommand::ValidateArtifacts(args),
        } => run_conformance_validate_artifacts(args),
        #[cfg(feature = "conformance")]
        Commands::Conformance {
            command: ConformanceCommand::RuntimeParity(args),
        } => run_conformance_runtime_parity(args),
        #[cfg(feature = "conformance")]
        Commands::Conformance {
            command: ConformanceCommand::SpecVerify(args),
        } => run_conformance_spec_verify(args),
        Commands::Diff(args) => run_diff(args),
        Commands::Review(args) => run_review(args),
        Commands::Trace(args) => run_trace(args),
        Commands::Refine(args) => run_refine(args),
        Commands::Artifact {
            command: ArtifactCommand::Inspect(args),
        } => run_artifact_inspect(args),
        Commands::Artifact {
            command: ArtifactCommand::Digest(args),
        } => run_artifact_digest(args),
        Commands::Artifact {
            command: ArtifactCommand::Verify(args),
        } => run_artifact_verify(args),
        Commands::Run(args) => run_eval(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Verify(args) => run_verify(args),
        Commands::Pipeline {
            command: PipelineCommand::Validate(args),
        } => run_pipeline_validate(args),
        Commands::Pipeline {
            command: PipelineCommand::Inspect(args),
        } => run_pipeline_inspect(args),
        Commands::Pipeline {
            command: PipelineCommand::Run(args),
        } => run_pipeline_run(args),
        Commands::Pipeline {
            command: PipelineCommand::Trace(args),
        } => run_pipeline_trace(args),
        Commands::Plugin {
            command: PluginCommand::Validate(args),
        } => run_plugin_validate(args),
        Commands::Plugin {
            command: PluginCommand::Run(args),
        } => run_plugin_run(args),
        Commands::Observer {
            command: ObserverCommand::List(args),
        } => run_observer_list(args),
        Commands::Observer {
            command: ObserverCommand::Validate(args),
        } => run_observer_validate(args),
        Commands::Observer {
            command: ObserverCommand::Run(args),
        } => run_observer_run(args),
        Commands::Observer {
            command: ObserverCommand::Detect(args),
        } => run_observer_detect(args),
        Commands::Observer {
            command: ObserverCommand::Scaffold(args),
        } => run_observer_scaffold(args),
        Commands::Observer {
            command: ObserverCommand::Synthesize(args),
        } => run_observer_synthesize(args),
        Commands::Observer {
            command: ObserverCommand::Repair(args),
        } => run_observer_repair(args),
        Commands::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "logicpearl",
                &mut std::io::stdout(),
            );
            Ok(())
        }
    }
}
