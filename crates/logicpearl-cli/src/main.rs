use clap::{Args, Parser, Subcommand};
use logicpearl_core::ArtifactRenderer;
use logicpearl_discovery::{
    build_pearl_from_rows, discover_from_csv, BuildOptions, DecisionTraceRow, DiscoverOptions,
};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_observer::{
    default_artifact_for_profile, detect_profile_from_input, load_artifact, observe_with_artifact,
    observe_with_profile, status as observer_status, NativeObserverArtifact,
    ObserverProfile as NativeObserverProfile,
};
use logicpearl_pipeline::{compose_pipeline, PipelineDefinition};
use logicpearl_plugin::{run_plugin, PluginManifest, PluginRequest, PluginStage};
use logicpearl_render::TextInspector;
use logicpearl_runtime::{evaluate_gate, parse_input_payload};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_yaml;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const CLI_LONG_ABOUT: &str = "\
LogicPearl turns normalized decision behavior into deterministic artifacts.

Use this CLI to:
- build pearls from labeled traces
- discover multiple target artifacts from one dataset
- inspect and run pearls
- compose and execute string-of-pearls pipelines
- score benchmark datasets with explicit route outputs";

const CLI_AFTER_HELP: &str = "\
Examples:
  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output
  logicpearl discover benchmarks/guardrails/examples/agent_guardrail/discovery/multi_target_demo.csv --targets target_instruction_boundary,target_exfiltration,target_tool_use
  logicpearl inspect examples/getting_started/output/pearl.ir.json
  logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json
  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json";

const PIPELINE_AFTER_HELP: &str = "\
Examples:
  logicpearl pipeline validate examples/pipelines/authz/pipeline.json
  logicpearl pipeline inspect examples/pipelines/observer_membership_verify/pipeline.json
  logicpearl pipeline run examples/pipelines/authz/pipeline.json examples/pipelines/authz/input.json
  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json";

const BENCHMARK_AFTER_HELP: &str = "\
Examples:
  logicpearl benchmark adapt ~/Documents/LogicPearl/datasets/public/alert/ALERT_Adv.jsonl --profile alert --output /tmp/alert_attack.jsonl
  logicpearl benchmark observe /tmp/salad_dev.jsonl --output /tmp/salad_dev_observed.jsonl
  logicpearl benchmark prepare /tmp/salad_dev.jsonl --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json --output-dir /tmp/guardrail_prep --json
  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json";

const OBSERVER_AFTER_HELP: &str = "\
Examples:
  logicpearl observer detect --input examples/plugins/python_observer/raw_input.json --json
  logicpearl observer run --observer-profile guardrails-v1 --input examples/plugins/python_observer/raw_input.json --json
  logicpearl observer scaffold --profile guardrails-v1 --output /tmp/guardrails_observer.json";

const QUICKSTART_AFTER_HELP: &str = "\
Examples:
  logicpearl quickstart
  logicpearl quickstart build
  logicpearl quickstart pipeline
  logicpearl quickstart benchmark";

fn guidance(message: impl AsRef<str>, hint: impl AsRef<str>) -> miette::Report {
    miette::miette!("{}\n\nHint: {}", message.as_ref(), hint.as_ref())
}

#[derive(Debug, Parser)]
#[command(
    name = "logicpearl",
    version,
    about = "Build, inspect, discover, and benchmark deterministic LogicPearl artifacts.",
    long_about = CLI_LONG_ABOUT,
    after_help = CLI_AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Test a pipeline against a benchmark dataset and see how it performs.
    Benchmark {
        #[command(subcommand)]
        command: BenchmarkCommand,
    },
    /// Turn labeled examples into a pearl.
    Build(BuildArgs),
    /// Show the quickest ways to try LogicPearl.
    Quickstart(QuickstartArgs),
    /// Learn multiple pearls from one dataset.
    Discover(DiscoverArgs),
    /// Create a starter pipeline from existing pearls.
    Compose(ComposeArgs),
    /// Compile a pearl into a standalone executable.
    Compile(CompileArgs),
    /// Run a pearl on an input file.
    Run(RunArgs),
    /// Inspect a pearl and see what it does.
    Inspect(InspectArgs),
    /// Check a pearl with a verifier plugin.
    Verify(VerifyArgs),
    /// Work with string-of-pearls pipelines.
    Pipeline {
        #[command(subcommand)]
        command: PipelineCommand,
    },
    /// Work with observers that turn messy input into normalized features.
    Observer {
        #[command(subcommand)]
        command: ObserverCommand,
    },
}

#[derive(Debug, Subcommand)]
#[command(after_help = BENCHMARK_AFTER_HELP)]
enum BenchmarkCommand {
    /// Convert a raw benchmark dataset into LogicPearl benchmark-case JSONL using a built-in adapter profile.
    Adapt(BenchmarkAdaptArgs),
    /// Convert a raw Salad-Data JSON file into LogicPearl benchmark-case JSONL.
    AdaptSalad(BenchmarkAdaptSaladArgs),
    /// Convert a raw ALERT JSON file into LogicPearl benchmark-case JSONL.
    AdaptAlert(BenchmarkAdaptAlertArgs),
    /// Convert a raw SQuAD-style JSON file into LogicPearl benchmark-case JSONL.
    AdaptSquad(BenchmarkAdaptSquadArgs),
    /// Observe benchmark cases, emit traces, and discover artifacts in one run.
    Prepare(BenchmarkPrepareArgs),
    /// Merge multiple benchmark-case JSONL files into one dataset.
    MergeCases(BenchmarkMergeCasesArgs),
    /// Run an observer over benchmark cases and emit observed feature rows.
    Observe(BenchmarkObserveArgs),
    /// Project observed benchmark rows into discovery-ready trace CSVs.
    EmitTraces(BenchmarkEmitTracesArgs),
    /// Convert a raw PINT YAML dataset into LogicPearl benchmark-case JSONL.
    AdaptPint(BenchmarkAdaptPintArgs),
    /// Run a benchmark dataset through a pipeline and compute metrics.
    Run(BenchmarkRunArgs),
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum QuickstartTopic {
    Build,
    Pipeline,
    Benchmark,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ObserverProfileArg {
    GuardrailsV1,
    Auto,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output --json")]
struct BuildArgs {
    /// Path to a CSV file of labeled decision traces.
    decision_traces: Option<PathBuf>,
    /// Directory to write pearl.ir.json and build_report.json into.
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Gate ID to embed in the emitted pearl.
    #[arg(long)]
    gate_id: Option<String>,
    /// Column name for the decision label.
    #[arg(long, default_value = "allowed")]
    label_column: String,
    /// Plugin manifest for a trace-source plugin that emits decision traces over JSON.
    #[arg(long)]
    trace_plugin_manifest: Option<PathBuf>,
    /// Source passed to the trace-source plugin.
    #[arg(long)]
    trace_plugin_input: Option<String>,
    /// Plugin manifest for an enricher plugin that transforms decision traces over JSON.
    #[arg(long)]
    enricher_plugin_manifest: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = QUICKSTART_AFTER_HELP)]
struct QuickstartArgs {
    /// Optional quickstart path to focus on.
    topic: Option<QuickstartTopic>,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl discover traces.csv --targets target_a,target_b --output-dir discovered")]
struct DiscoverArgs {
    dataset_csv: PathBuf,
    /// Single binary target column to learn.
    #[arg(long)]
    target: Option<String>,
    /// Comma-delimited binary target columns to learn.
    #[arg(long, value_delimiter = ',')]
    targets: Vec<String>,
    /// Directory to write artifacts, artifact_set.json, and discover_report.json into.
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Stable artifact set identifier.
    #[arg(long)]
    artifact_set_id: Option<String>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json")]
struct BenchmarkRunArgs {
    pipeline_json: PathBuf,
    dataset_jsonl: PathBuf,
    /// Collapse all non-allow routes into `deny` before scoring.
    #[arg(long)]
    collapse_non_allow_to_deny: bool,
    /// Optional path to write the full benchmark result JSON.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  logicpearl benchmark adapt benchmarks/guardrails/prep/example_salad_base_set.json --profile salad-base-set --output /tmp/salad_benign.jsonl\n  logicpearl benchmark adapt ~/Documents/LogicPearl/datasets/public/alert/ALERT_Adv.jsonl --profile alert --output /tmp/alert_attack.jsonl\n  logicpearl benchmark adapt ~/Documents/LogicPearl/datasets/public/squad/train-v2.0.json --profile squad --output /tmp/squad_benign.jsonl")]
struct BenchmarkAdaptArgs {
    raw_dataset: PathBuf,
    /// Built-in adapter profile to use for this dataset.
    #[arg(long, value_enum)]
    profile: BenchmarkAdapterProfile,
    /// Output JSONL path in LogicPearl benchmark-case format.
    #[arg(long)]
    output: PathBuf,
    /// Default requested tool when the source row does not provide one.
    #[arg(long, default_value = "none")]
    requested_tool: String,
    /// Default requested action when the source row does not provide one.
    #[arg(long, default_value = "chat_response")]
    requested_action: String,
    /// Default scope when the source row does not provide one.
    #[arg(long, default_value = "allowed")]
    scope: String,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum BenchmarkAdapterProfile {
    SaladBaseSet,
    SaladAttackEnhancedSet,
    Alert,
    Squad,
    Pint,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark adapt-pint raw_pint.yaml --output /tmp/pint_cases.jsonl")]
struct BenchmarkAdaptPintArgs {
    raw_pint_yaml: PathBuf,
    /// Output JSONL path in LogicPearl benchmark-case format.
    #[arg(long)]
    output: PathBuf,
    /// Default requested tool when the source row does not provide one.
    #[arg(long, default_value = "none")]
    requested_tool: String,
    /// Default requested action when the source row does not provide one.
    #[arg(long, default_value = "chat_response")]
    requested_action: String,
    /// Default scope when the source row does not provide one.
    #[arg(long, default_value = "allowed")]
    scope: String,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum SaladSubset {
    BaseSet,
    AttackEnhancedSet,
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  logicpearl benchmark adapt-salad raw_base_set.json --subset base-set --output /tmp/salad_benign.jsonl\n  logicpearl benchmark adapt-salad raw_attack_enhanced_set.json --subset attack-enhanced-set --output /tmp/salad_attack.jsonl")]
struct BenchmarkAdaptSaladArgs {
    raw_salad_json: PathBuf,
    /// Which Salad-Data subset format this file uses.
    #[arg(long, value_enum)]
    subset: SaladSubset,
    /// Output JSONL path in LogicPearl benchmark-case format.
    #[arg(long)]
    output: PathBuf,
    /// Default requested tool when the source row does not provide one.
    #[arg(long, default_value = "none")]
    requested_tool: String,
    /// Default requested action when the source row does not provide one.
    #[arg(long, default_value = "chat_response")]
    requested_action: String,
    /// Default scope when the source row does not provide one.
    #[arg(long, default_value = "allowed")]
    scope: String,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark adapt-alert raw_alert.json --output /tmp/alert_attack.jsonl")]
struct BenchmarkAdaptAlertArgs {
    raw_alert_json: PathBuf,
    /// Output JSONL path in LogicPearl benchmark-case format.
    #[arg(long)]
    output: PathBuf,
    /// Default requested tool when the source row does not provide one.
    #[arg(long, default_value = "none")]
    requested_tool: String,
    /// Default requested action when the source row does not provide one.
    #[arg(long, default_value = "chat_response")]
    requested_action: String,
    /// Default scope when the source row does not provide one.
    #[arg(long, default_value = "allowed")]
    scope: String,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark adapt-squad train-v2.0.json --output /tmp/squad_benign.jsonl")]
struct BenchmarkAdaptSquadArgs {
    raw_squad_json: PathBuf,
    /// Output JSONL path in LogicPearl benchmark-case format.
    #[arg(long)]
    output: PathBuf,
    /// Default requested tool when the source row does not provide one.
    #[arg(long, default_value = "none")]
    requested_tool: String,
    /// Default requested action when the source row does not provide one.
    #[arg(long, default_value = "chat_response")]
    requested_action: String,
    /// Default scope when the source row does not provide one.
    #[arg(long, default_value = "allowed")]
    scope: String,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark merge-cases /tmp/salad_base.jsonl /tmp/salad_attack.jsonl --output /tmp/salad_dev.jsonl")]
struct BenchmarkMergeCasesArgs {
    inputs: Vec<PathBuf>,
    /// Output JSONL path containing the concatenated benchmark cases.
    #[arg(long)]
    output: PathBuf,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  logicpearl benchmark prepare /tmp/salad_dev.jsonl --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json --output-dir /tmp/guardrail_prep --json\n  logicpearl benchmark prepare /tmp/salad_dev.jsonl --observer-artifact /tmp/guardrails_observer.json --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json --output-dir /tmp/guardrail_prep")]
struct BenchmarkPrepareArgs {
    dataset_jsonl: PathBuf,
    /// Built-in observer profile to use. If omitted, LogicPearl auto-detects a native profile from the input shape.
    #[arg(long, value_enum)]
    observer_profile: Option<ObserverProfileArg>,
    /// Observer artifact to run natively.
    #[arg(long)]
    observer_artifact: Option<PathBuf>,
    /// Observer plugin manifest used to normalize each benchmark case input when no native profile or artifact fits.
    #[arg(long)]
    plugin_manifest: Option<PathBuf>,
    /// Projection config that maps observed rows into discovery-ready trace tables.
    #[arg(long)]
    config: PathBuf,
    /// Directory to write observed rows, traces, and discovered artifacts into.
    #[arg(long)]
    output_dir: PathBuf,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  logicpearl benchmark observe /tmp/salad_attack.jsonl --output /tmp/salad_attack_observed.jsonl\n  logicpearl benchmark observe /tmp/salad_attack.jsonl --observer-artifact /tmp/guardrails_observer.json --output /tmp/salad_attack_observed.jsonl")]
struct BenchmarkObserveArgs {
    dataset_jsonl: PathBuf,
    /// Built-in observer profile to use. If omitted, LogicPearl auto-detects a native profile from the input shape.
    #[arg(long, value_enum)]
    observer_profile: Option<ObserverProfileArg>,
    /// Observer artifact to run natively.
    #[arg(long)]
    observer_artifact: Option<PathBuf>,
    /// Observer plugin manifest used to normalize each benchmark case input when no native profile or artifact fits.
    #[arg(long)]
    plugin_manifest: Option<PathBuf>,
    /// Output JSONL path with benchmark metadata plus observer features.
    #[arg(long)]
    output: PathBuf,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark emit-traces /tmp/salad_attack_observed.jsonl --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json --output-dir /tmp/trace_exports")]
struct BenchmarkEmitTracesArgs {
    observed_jsonl: PathBuf,
    /// Projection config that maps observed rows into discovery-ready trace tables.
    #[arg(long)]
    config: PathBuf,
    /// Directory to write discovery-ready trace CSVs into.
    #[arg(long)]
    output_dir: PathBuf,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl run examples/getting_started/output/pearl.ir.json examples/getting_started/new_input.json")]
struct RunArgs {
    pearl_ir: PathBuf,
    input_json: PathBuf,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl compose --pipeline-id starter_authz --output examples/pipelines/generated/starter_authz.pipeline.json fixtures/ir/valid/auth-demo-v1.json")]
struct ComposeArgs {
    /// Stable pipeline identifier for the emitted starter artifact.
    #[arg(long)]
    pipeline_id: String,
    /// Output path for the generated pipeline.json.
    #[arg(long)]
    output: PathBuf,
    /// Pearl artifacts to compose into a starter pipeline.
    artifacts: Vec<PathBuf>,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl compile examples/getting_started/output/pearl.ir.json --name authz-demo --target x86_64-unknown-linux-gnu")]
struct CompileArgs {
    pearl_ir: PathBuf,
    /// Rust target triple, for example x86_64-unknown-linux-gnu or x86_64-pc-windows-msvc.
    #[arg(long)]
    target: Option<String>,
    /// Pearl artifact name. Defaults to the gate id.
    #[arg(long)]
    name: Option<String>,
    /// Output executable path. Defaults to <name>.pearl or <name>.pearl.exe for Windows targets.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl inspect examples/getting_started/output/pearl.ir.json --json")]
struct InspectArgs {
    pearl_ir: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl verify examples/getting_started/output/pearl.ir.json --plugin-manifest examples/plugins/python_verify/manifest.json --json")]
struct VerifyArgs {
    pearl_ir: PathBuf,
    /// Plugin manifest for the verifier backend.
    #[arg(long)]
    plugin_manifest: PathBuf,
    /// Optional fixtures or cases payload passed through to the verifier.
    #[arg(long)]
    fixtures: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
#[command(after_help = PIPELINE_AFTER_HELP)]
enum PipelineCommand {
    /// Check that a pipeline and everything it references are valid.
    Validate(PipelineValidateArgs),
    /// Inspect a pipeline and summarize its stages.
    Inspect(PipelineInspectArgs),
    /// Run a pipeline on one input file.
    Run(PipelineRunArgs),
    /// Run a pipeline and show every stage in the trace.
    Trace(PipelineTraceArgs),
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl pipeline validate examples/pipelines/authz/pipeline.json --json")]
struct PipelineValidateArgs {
    pipeline_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl pipeline inspect examples/pipelines/observer_membership_verify/pipeline.json --json")]
struct PipelineInspectArgs {
    pipeline_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl pipeline run examples/pipelines/authz/pipeline.json examples/pipelines/authz/input.json --json")]
struct PipelineRunArgs {
    pipeline_json: PathBuf,
    input_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json")]
struct PipelineTraceArgs {
    pipeline_json: PathBuf,
    input_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
#[command(after_help = OBSERVER_AFTER_HELP)]
enum ObserverCommand {
    /// Check that an observer profile artifact or plugin manifest is valid.
    Validate(ObserverValidateArgs),
    /// Run an observer on raw input and emit normalized features.
    Run(ObserverRunArgs),
    /// Detect which built-in observer profile fits the input shape.
    Detect(ObserverDetectArgs),
    /// Scaffold a native observer artifact from a built-in profile.
    Scaffold(ObserverScaffoldArgs),
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  logicpearl observer validate /tmp/guardrails_observer.json\n  logicpearl observer validate examples/plugins/python_observer/manifest.json --plugin-manifest")]
struct ObserverValidateArgs {
    target: PathBuf,
    /// Validate a plugin manifest instead of a static observer artifact.
    #[arg(long)]
    plugin_manifest: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  logicpearl observer run --input examples/plugins/python_observer/raw_input.json --json\n  logicpearl observer run --observer-artifact /tmp/guardrails_observer.json --input raw.json --json\n  logicpearl observer run --plugin-manifest examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json --json")]
struct ObserverRunArgs {
    /// Built-in observer profile to use. If omitted, LogicPearl auto-detects one from the raw input when possible.
    #[arg(long)]
    observer_profile: Option<ObserverProfileArg>,
    /// Native observer artifact to execute.
    #[arg(long)]
    observer_artifact: Option<PathBuf>,
    /// Plugin manifest for the observer plugin to execute when no native profile or artifact fits.
    #[arg(long)]
    plugin_manifest: Option<PathBuf>,
    /// Raw input JSON to normalize.
    #[arg(long)]
    input: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl observer detect --input examples/plugins/python_observer/raw_input.json --json")]
struct ObserverDetectArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl observer scaffold --profile guardrails-v1 --output /tmp/guardrails_observer.json")]
struct ObserverScaffoldArgs {
    #[arg(long, value_enum)]
    profile: ObserverProfileArg,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkCase {
    id: String,
    input: Value,
    expected_route: String,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PintRawCase {
    text: String,
    #[serde(default)]
    category: Option<String>,
    label: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObservedBenchmarkCase {
    id: String,
    input: Value,
    expected_route: String,
    #[serde(default)]
    category: Option<String>,
    features: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraceProjectionConfig {
    #[serde(default)]
    feature_columns: Vec<String>,
    #[serde(default = "default_true")]
    emit_multi_target: bool,
    binary_targets: Vec<BinaryTargetProjection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BinaryTargetProjection {
    name: String,
    #[serde(default)]
    trace_features: Vec<String>,
    #[serde(default)]
    positive_when: ProjectionPredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProjectionPredicate {
    #[serde(default)]
    expected_routes: Vec<String>,
    #[serde(default)]
    any_features: Vec<String>,
    #[serde(default)]
    all_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SaladBaseCase {
    qid: serde_json::Value,
    question: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SaladAttackCase {
    aid: serde_json::Value,
    augq: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default, rename = "1-category")]
    category_1: Option<String>,
    #[serde(default, rename = "2-category")]
    category_2: Option<String>,
    #[serde(default, rename = "3-category")]
    category_3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SquadDataset {
    data: Vec<SquadArticle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SquadArticle {
    #[serde(default)]
    title: Option<String>,
    paragraphs: Vec<SquadParagraph>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SquadParagraph {
    context: String,
    qas: Vec<SquadQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SquadQuestion {
    id: String,
    question: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkCaseResult {
    id: String,
    expected_route: String,
    actual_route: String,
    matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attack_confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkSummary {
    total_cases: usize,
    matched_cases: usize,
    exact_match_rate: f64,
    attack_cases: usize,
    benign_cases: usize,
    attack_catch_rate: f64,
    benign_pass_rate: f64,
    false_positive_rate: f64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    category_accuracy: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkResult {
    pipeline_id: String,
    dataset_path: String,
    summary: BenchmarkSummary,
    cases: Vec<BenchmarkCaseResult>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceEmitSummary {
    rows: usize,
    output_dir: String,
    config: String,
    files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ObserverResolution {
    NativeProfile { profile: String },
    NativeArtifact { observer_id: String },
    Plugin { name: String },
}

#[derive(Debug, Clone)]
enum ResolvedObserver {
    NativeProfile(NativeObserverProfile),
    NativeArtifact(NativeObserverArtifact),
    Plugin(PluginManifest),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Benchmark {
            command: BenchmarkCommand::Adapt(args),
        } => run_benchmark_adapt(args),
        Commands::Benchmark {
            command: BenchmarkCommand::AdaptSalad(args),
        } => run_benchmark_adapt_salad(args),
        Commands::Benchmark {
            command: BenchmarkCommand::AdaptAlert(args),
        } => run_benchmark_adapt_alert(args),
        Commands::Benchmark {
            command: BenchmarkCommand::AdaptSquad(args),
        } => run_benchmark_adapt_squad(args),
        Commands::Benchmark {
            command: BenchmarkCommand::Prepare(args),
        } => run_benchmark_prepare(args),
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
            command: BenchmarkCommand::AdaptPint(args),
        } => run_benchmark_adapt_pint(args),
        Commands::Benchmark {
            command: BenchmarkCommand::Run(args),
        } => run_benchmark(args),
        Commands::Build(args) => run_build(args),
        Commands::Quickstart(args) => run_quickstart(args),
        Commands::Discover(args) => run_discover(args),
        Commands::Compose(args) => run_compose(args),
        Commands::Compile(args) => run_compile(args),
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
    }
}

fn run_benchmark_merge_cases(args: BenchmarkMergeCasesArgs) -> Result<()> {
    if args.inputs.is_empty() {
        return Err(guidance(
            "merge-cases needs at least one input file",
            "Pass one or more benchmark-case JSONL files followed by --output <merged.jsonl>.",
        ));
    }
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create merged benchmark output directory")?;
    }

    let mut merged = String::new();
    let mut total_rows = 0_usize;
    let mut seen_ids = std::collections::BTreeSet::new();
    for input in &args.inputs {
        let cases = load_benchmark_cases(input)?;
        for case in cases {
            if !seen_ids.insert(case.id.clone()) {
                return Err(guidance(
                    format!("duplicate benchmark case id detected: {}", case.id),
                    "Make sure merged benchmark-case files have unique ids before combining them.",
                ));
            }
            merged.push_str(&serde_json::to_string(&case).into_diagnostic()?);
            merged.push('\n');
            total_rows += 1;
        }
    }

    fs::write(&args.output, merged)
        .into_diagnostic()
        .wrap_err("failed to write merged benchmark JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": total_rows,
                "inputs": args.inputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Merged".bold().bright_green(), "benchmark cases".bold());
        println!("  {} {}", "Inputs".bright_black(), args.inputs.len());
        println!("  {} {}", "Rows".bright_black(), total_rows);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_benchmark_prepare(args: BenchmarkPrepareArgs) -> Result<()> {
    fs::create_dir_all(&args.output_dir)
        .into_diagnostic()
        .wrap_err("failed to create benchmark prepare output directory")?;

    let observed_path = args.output_dir.join("observed.jsonl");
    let traces_dir = args.output_dir.join("traces");
    let discovered_dir = args.output_dir.join("discovered");

    let observer = resolve_observer_for_cases(
        &args.dataset_jsonl,
        args.observer_profile.clone(),
        args.observer_artifact.clone(),
        args.plugin_manifest.clone(),
    )?;
    let observed_rows = observe_benchmark_cases(&args.dataset_jsonl, &observer, &observed_path)?;
    let trace_summary = emit_trace_tables(&observed_path, &args.config, &traces_dir)?;
    let config = load_trace_projection_config(&args.config)?;

    let discover_result = if config.emit_multi_target {
        let targets = config
            .binary_targets
            .iter()
            .map(|target| target.name.clone())
            .collect::<Vec<_>>();
        Some(
            discover_from_csv(
                &traces_dir.join("multi_target.csv"),
                &DiscoverOptions {
                    output_dir: discovered_dir,
                    artifact_set_id: format!(
                        "{}_artifact_set",
                        args.dataset_jsonl
                            .file_stem()
                            .map(|stem| stem.to_string_lossy().to_string())
                            .unwrap_or_else(|| "benchmark".to_string())
                    ),
                    target_columns: targets,
                },
            )
            .into_diagnostic()
            .wrap_err("could not discover artifacts from emitted benchmark traces")?,
        )
    } else {
        None
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dataset": args.dataset_jsonl.display().to_string(),
                "observer": observer_resolution(&observer),
                "observed_rows": observed_rows,
                "observed_output": observed_path.display().to_string(),
                "trace_summary": trace_summary,
                "discover_result": discover_result,
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Prepared".bold().bright_green(), "benchmark dataset".bold());
        println!("  {} {}", "Observed".bright_black(), observed_rows);
        println!(
            "  {} {}",
            "Observer".bright_black(),
            render_observer_resolution(&observer_resolution(&observer))
        );
        println!("  {} {}", "Observed output".bright_black(), observed_path.display());
        println!("  {} {}", "Trace output".bright_black(), traces_dir.display());
        if let Some(discover_result) = discover_result {
            println!("  {} {}", "Artifacts".bright_black(), discover_result.artifacts.len());
            println!(
                "  {} {}",
                "Artifact set".bright_black(),
                discover_result.output_files.artifact_set
            );
        }
    }
    Ok(())
}

fn run_benchmark_observe(args: BenchmarkObserveArgs) -> Result<()> {
    let observer = resolve_observer_for_cases(
        &args.dataset_jsonl,
        args.observer_profile.clone(),
        args.observer_artifact.clone(),
        args.plugin_manifest.clone(),
    )?;
    let rows = observe_benchmark_cases(&args.dataset_jsonl, &observer, &args.output)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": rows,
                "output": args.output.display().to_string(),
                "observer": observer_resolution(&observer)
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Observed".bold().bright_green(), "benchmark cases".bold());
        println!("  {} {}", "Rows".bright_black(), rows);
        println!(
            "  {} {}",
            "Observer".bright_black(),
            render_observer_resolution(&observer_resolution(&observer))
        );
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_benchmark_emit_traces(args: BenchmarkEmitTracesArgs) -> Result<()> {
    let summary = emit_trace_tables(&args.observed_jsonl, &args.config, &args.output_dir)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        println!("{} {}", "Emitted".bold().bright_green(), "discovery traces".bold());
        println!("  {} {}", "Rows".bright_black(), summary.rows);
        println!("  {} {}", "Config".bright_black(), summary.config);
        println!("  {} {}", "Output".bright_black(), summary.output_dir);
    }
    Ok(())
}

fn run_benchmark_adapt(args: BenchmarkAdaptArgs) -> Result<()> {
    match args.profile {
        BenchmarkAdapterProfile::SaladBaseSet => run_benchmark_adapt_salad(BenchmarkAdaptSaladArgs {
            raw_salad_json: args.raw_dataset,
            subset: SaladSubset::BaseSet,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
        BenchmarkAdapterProfile::SaladAttackEnhancedSet => {
            run_benchmark_adapt_salad(BenchmarkAdaptSaladArgs {
                raw_salad_json: args.raw_dataset,
                subset: SaladSubset::AttackEnhancedSet,
                output: args.output,
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
                json: args.json,
            })
        }
        BenchmarkAdapterProfile::Alert => run_benchmark_adapt_alert(BenchmarkAdaptAlertArgs {
            raw_alert_json: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
        BenchmarkAdapterProfile::Squad => run_benchmark_adapt_squad(BenchmarkAdaptSquadArgs {
            raw_squad_json: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
        BenchmarkAdapterProfile::Pint => run_benchmark_adapt_pint(BenchmarkAdaptPintArgs {
            raw_pint_yaml: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
    }
}

fn run_benchmark_adapt_salad(args: BenchmarkAdaptSaladArgs) -> Result<()> {
    let raw_json = fs::read_to_string(&args.raw_salad_json)
        .into_diagnostic()
        .wrap_err("could not read raw Salad-Data JSON")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create adapted benchmark output directory")?;
    }

    let mut out = String::new();
    let rows = match args.subset {
        SaladSubset::BaseSet => {
            let raw_cases: Vec<SaladBaseCase> = serde_json::from_str(&raw_json)
                .into_diagnostic()
                .wrap_err("raw Salad base_set JSON is not valid for the expected dataset format")?;
            if raw_cases.is_empty() {
                return Err(guidance(
                    "raw Salad base_set dataset is empty",
                    "Provide a JSON array of rows with qid, question, and optional source.",
                ));
            }
            let count = raw_cases.len();
            for (index, case) in raw_cases.iter().enumerate() {
                let benchmark_case = BenchmarkCase {
                    id: format!("salad_base_{}", stable_value_id(&case.qid, index)),
                    input: serde_json::json!({
                        "prompt": case.question,
                        "requested_tool": args.requested_tool,
                        "requested_action": args.requested_action,
                        "scope": args.scope,
                        "document_instructions_present": false
                    }),
                    expected_route: "allow".to_string(),
                    category: case.source.clone(),
                };
                out.push_str(&serde_json::to_string(&benchmark_case).into_diagnostic()?);
                out.push('\n');
            }
            count
        }
        SaladSubset::AttackEnhancedSet => {
            let raw_cases: Vec<SaladAttackCase> = serde_json::from_str(&raw_json)
                .into_diagnostic()
                .wrap_err("raw Salad attack_enhanced_set JSON is not valid for the expected dataset format")?;
            if raw_cases.is_empty() {
                return Err(guidance(
                    "raw Salad attack_enhanced_set dataset is empty",
                    "Provide a JSON array of rows with aid, augq, and optional method/category fields.",
                ));
            }
            let count = raw_cases.len();
            for (index, case) in raw_cases.iter().enumerate() {
                let category = case
                    .category_3
                    .clone()
                    .or(case.category_2.clone())
                    .or(case.category_1.clone())
                    .or(case.method.clone());
                let benchmark_case = BenchmarkCase {
                    id: format!("salad_attack_{}", stable_value_id(&case.aid, index)),
                    input: serde_json::json!({
                        "prompt": case.augq,
                        "requested_tool": args.requested_tool,
                        "requested_action": args.requested_action,
                        "scope": args.scope,
                        "document_instructions_present": false
                    }),
                    expected_route: "deny".to_string(),
                    category,
                };
                out.push_str(&serde_json::to_string(&benchmark_case).into_diagnostic()?);
                out.push('\n');
            }
            count
        }
    };

    fs::write(&args.output, out)
        .into_diagnostic()
        .wrap_err("failed to write adapted Salad JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "salad-data",
                "subset": match args.subset {
                    SaladSubset::BaseSet => "base_set",
                    SaladSubset::AttackEnhancedSet => "attack_enhanced_set",
                },
                "rows": rows,
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Adapted".bold().bright_green(), "Salad-Data dataset".bold());
        println!("  {} {}", "Rows".bright_black(), rows);
        println!(
            "  {} {}",
            "Subset".bright_black(),
            match args.subset {
                SaladSubset::BaseSet => "base_set",
                SaladSubset::AttackEnhancedSet => "attack_enhanced_set",
            }
        );
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_benchmark_adapt_alert(args: BenchmarkAdaptAlertArgs) -> Result<()> {
    let raw_json = fs::read_to_string(&args.raw_alert_json)
        .into_diagnostic()
        .wrap_err("could not read raw ALERT JSON")?;
    let rows = parse_json_object_rows(&raw_json)
        .wrap_err("raw ALERT JSON is not valid for the expected dataset format")?;
    if rows.is_empty() {
        return Err(guidance(
            "raw ALERT dataset is empty",
            "Provide a JSON array or JSONL file of objects with a prompt-like text field.",
        ));
    }

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create adapted benchmark output directory")?;
    }

    let mut out = String::new();
    for (index, row) in rows.iter().enumerate() {
        let prompt = first_string_field(
            row,
            &["prompt", "instruction", "text", "question", "input", "content"],
        )
        .ok_or_else(|| {
            guidance(
                format!("ALERT row {} is missing a prompt-like text field", index + 1),
                "Expected one of: prompt, instruction, text, question, input, content.",
            )
        })?;

        let benchmark_case = BenchmarkCase {
            id: row
                .get("id")
                .or_else(|| row.get("aid"))
                .or_else(|| row.get("qid"))
                .map(|value| format!("alert_{}", stable_value_id(value, index)))
                .unwrap_or_else(|| format!("alert_{index:06}")),
            input: serde_json::json!({
                "prompt": prompt,
                "requested_tool": args.requested_tool,
                "requested_action": args.requested_action,
                "scope": args.scope,
                "document_instructions_present": false
            }),
            expected_route: "deny".to_string(),
            category: first_string_field(
                row,
                &[
                    "category",
                    "subcategory",
                    "harm_category",
                    "attack_category",
                    "label",
                    "source",
                ],
            ),
        };
        out.push_str(&serde_json::to_string(&benchmark_case).into_diagnostic()?);
        out.push('\n');
    }

    fs::write(&args.output, out)
        .into_diagnostic()
        .wrap_err("failed to write adapted ALERT JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "alert",
                "rows": rows.len(),
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Adapted".bold().bright_green(), "ALERT dataset".bold());
        println!("  {} {}", "Rows".bright_black(), rows.len());
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_benchmark_adapt_squad(args: BenchmarkAdaptSquadArgs) -> Result<()> {
    let raw_json = fs::read_to_string(&args.raw_squad_json)
        .into_diagnostic()
        .wrap_err("could not read raw SQuAD JSON")?;
    let dataset: SquadDataset = serde_json::from_str(&raw_json)
        .into_diagnostic()
        .wrap_err("raw SQuAD JSON is not valid for the expected dataset format")?;
    if dataset.data.is_empty() {
        return Err(guidance(
            "raw SQuAD dataset is empty",
            "Provide a SQuAD-style JSON file with a top-level data array.",
        ));
    }

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create adapted benchmark output directory")?;
    }

    let mut out = String::new();
    let mut rows = 0_usize;
    for article in &dataset.data {
        for paragraph in &article.paragraphs {
            for question in &paragraph.qas {
                let benchmark_case = BenchmarkCase {
                    id: format!("squad_{}", question.id),
                    input: serde_json::json!({
                        "prompt": question.question,
                        "context": paragraph.context,
                        "requested_tool": args.requested_tool,
                        "requested_action": args.requested_action,
                        "scope": args.scope,
                        "document_instructions_present": false
                    }),
                    expected_route: "allow".to_string(),
                    category: article
                        .title
                        .clone()
                        .or_else(|| Some("benign_negative".to_string())),
                };
                out.push_str(&serde_json::to_string(&benchmark_case).into_diagnostic()?);
                out.push('\n');
                rows += 1;
            }
        }
    }

    if rows == 0 {
        return Err(guidance(
            "raw SQuAD dataset contains no question rows",
            "Make sure the JSON contains data[].paragraphs[].qas[] entries.",
        ));
    }

    fs::write(&args.output, out)
        .into_diagnostic()
        .wrap_err("failed to write adapted SQuAD JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "squad",
                "rows": rows,
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Adapted".bold().bright_green(), "SQuAD dataset".bold());
        println!("  {} {}", "Rows".bright_black(), rows);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_quickstart(args: QuickstartArgs) -> Result<()> {
    match args.topic {
        None => {
            println!("{}", "LogicPearl Quickstart".bold().bright_blue());
            println!("  {}", "Choose the shortest path for what you want to prove first:".bright_black());
            println!("  {} {}", "Build".bold(), "learn one pearl from labeled traces".bright_black());
            println!("    logicpearl quickstart build");
            println!("  {} {}", "Pipeline".bold(), "run a string-of-pearls artifact".bright_black());
            println!("    logicpearl quickstart pipeline");
            println!("  {} {}", "Benchmark".bold(), "score a guardrail benchmark slice".bright_black());
            println!("    logicpearl quickstart benchmark");
        }
        Some(QuickstartTopic::Build) => {
            println!("{}", "Quickstart: Build".bold().bright_green());
            println!("  {}", "Build your first pearl:".bright_black());
            println!(
                "  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output"
            );
            println!("  {}", "Then inspect and run it:".bright_black());
            println!("  logicpearl inspect examples/getting_started/output/pearl.ir.json");
            println!("  logicpearl run examples/getting_started/output/pearl.ir.json examples/getting_started/new_input.json");
        }
        Some(QuickstartTopic::Pipeline) => {
            println!("{}", "Quickstart: Pipeline".bold().bright_green());
            println!("  {}", "Run a public string-of-pearls example:".bright_black());
            println!(
                "  logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
            );
            println!("  {}", "Trace the full stage-by-stage execution:".bright_black());
            println!(
                "  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
            );
        }
        Some(QuickstartTopic::Benchmark) => {
            println!("{}", "Quickstart: Benchmark".bold().bright_green());
            println!("  {}", "Score the public guardrail benchmark slice:".bright_black());
            println!(
                "  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json"
            );
            println!("  {}", "Inspect the benchmark pipeline if you want the artifact view:".bright_black());
            println!(
                "  logicpearl pipeline inspect benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json"
            );
        }
    }
    Ok(())
}

fn run_discover(args: DiscoverArgs) -> Result<()> {
    let mut targets = args.targets;
    if let Some(target) = args.target {
        targets.push(target);
    }
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(guidance(
            "discover needs at least one explicit target column",
            "Use --target <column> for one binary target or --targets <a,b,c> for multiple targets.",
        ));
    }

    let output_dir = args.output_dir.unwrap_or_else(|| {
        args.dataset_csv
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("discovered")
    });
    let artifact_set_id = args.artifact_set_id.unwrap_or_else(|| {
        args.dataset_csv
            .file_stem()
            .map(|stem| format!("{}_artifact_set", stem.to_string_lossy()))
            .unwrap_or_else(|| "artifact_set".to_string())
    });

    let result = discover_from_csv(
        &args.dataset_csv,
        &DiscoverOptions {
            output_dir,
            artifact_set_id,
            target_columns: targets,
        },
    )
    .into_diagnostic()
    .wrap_err("could not discover artifacts from the dataset")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result).into_diagnostic()?);
    } else {
        println!(
            "{} {}",
            "Discovered".bold().bright_green(),
            result.artifact_set_id.bold()
        );
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!("  {} {}", "Features".bright_black(), result.features.join(", "));
        println!("  {} {}", "Targets".bright_black(), result.targets.join(", "));
        println!("  {} {}", "Artifacts".bright_black(), result.artifacts.len());
        if !result.skipped_targets.is_empty() {
            for skipped in &result.skipped_targets {
                println!(
                    "  {} {} ({})",
                    "Skipped".bright_black(),
                    skipped.name,
                    skipped.reason
                );
            }
        }
        println!(
            "  {} {}",
            "Artifact set".bright_black(),
            result.output_files.artifact_set
        );
        println!(
            "  {} {}",
            "Discover report".bright_black(),
            result.output_files.discover_report
        );
    }
    Ok(())
}

fn run_benchmark_adapt_pint(args: BenchmarkAdaptPintArgs) -> Result<()> {
    let raw_yaml = fs::read_to_string(&args.raw_pint_yaml)
        .into_diagnostic()
        .wrap_err("could not read raw PINT YAML")?;
    let raw_cases: Vec<PintRawCase> = serde_yaml::from_str(&raw_yaml)
        .into_diagnostic()
        .wrap_err("raw PINT YAML is not valid for the expected dataset format")?;
    if raw_cases.is_empty() {
        return Err(guidance(
            "raw PINT dataset is empty",
            "Provide a YAML list of rows with text, optional category, and boolean label.",
        ));
    }

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create adapted benchmark output directory")?;
    }

    let mut out = String::new();
    for (index, case) in raw_cases.iter().enumerate() {
        let benchmark_case = BenchmarkCase {
            id: format!("pint_{index:06}"),
            input: serde_json::json!({
                "prompt": case.text,
                "requested_tool": args.requested_tool,
                "requested_action": args.requested_action,
                "scope": args.scope,
                "document_instructions_present": false
            }),
            expected_route: if case.label {
                "deny".to_string()
            } else {
                "allow".to_string()
            },
            category: case.category.clone(),
        };
        out.push_str(&serde_json::to_string(&benchmark_case).into_diagnostic()?);
        out.push('\n');
    }

    fs::write(&args.output, out)
        .into_diagnostic()
        .wrap_err("failed to write adapted PINT JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "pint",
                "rows": raw_cases.len(),
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Adapted".bold().bright_green(), "PINT dataset".bold());
        println!("  {} {}", "Rows".bright_black(), raw_cases.len());
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_benchmark(args: BenchmarkRunArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("failed to load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    let file = fs::File::open(&args.dataset_jsonl)
        .into_diagnostic()
        .wrap_err("could not open benchmark dataset JSONL")?;
    let reader = BufReader::new(file);

    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line
            .into_diagnostic()
            .wrap_err("failed to read benchmark dataset line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: BenchmarkCase = serde_json::from_str(trimmed)
            .into_diagnostic()
            .wrap_err(format!(
                "invalid benchmark case JSON on line {}. Each line must contain id, input, and expected_route",
                line_no + 1
            ))?;
        cases.push(case);
    }

    if cases.is_empty() {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one JSON object per line with id, input, expected_route, and optional category.",
        ));
    }

    let mut results = Vec::with_capacity(cases.len());
    let mut matched_cases = 0_usize;
    let mut attack_cases = 0_usize;
    let mut benign_cases = 0_usize;
    let mut caught_attacks = 0_usize;
    let mut benign_passes = 0_usize;
    let mut false_positives = 0_usize;
    let mut category_totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_matches: BTreeMap<String, usize> = BTreeMap::new();

    for case in cases {
        let execution = pipeline
            .run(base_dir, &case.input)
            .into_diagnostic()
            .wrap_err(format!("benchmark pipeline execution failed for case {}", case.id))?;

        let actual_route_raw = execution
            .output
            .get("route_status")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                guidance(
                    "benchmark pipeline output is missing `route_status`",
                    "Make sure the pipeline output exports a string route_status field, for example allow or deny_tool_use.",
                )
            })?;
        let actual_route = collapse_route(actual_route_raw, args.collapse_non_allow_to_deny);
        let expected_route = collapse_route(&case.expected_route, args.collapse_non_allow_to_deny);
        let matched = actual_route == expected_route;
        if matched {
            matched_cases += 1;
        }

        let attack_confidence = execution
            .output
            .get("attack_confidence")
            .and_then(Value::as_f64);

        let is_attack = expected_route != "allow";
        if is_attack {
            attack_cases += 1;
            if actual_route != "allow" {
                caught_attacks += 1;
            }
        } else {
            benign_cases += 1;
            if actual_route == "allow" {
                benign_passes += 1;
            } else {
                false_positives += 1;
            }
        }

        if let Some(category) = &case.category {
            *category_totals.entry(category.clone()).or_insert(0) += 1;
            if matched {
                *category_matches.entry(category.clone()).or_insert(0) += 1;
            }
        }

        results.push(BenchmarkCaseResult {
            id: case.id,
            expected_route,
            actual_route,
            matched,
            category: case.category,
            attack_confidence,
        });
    }

    let mut category_accuracy = BTreeMap::new();
    for (category, total) in category_totals {
        let matches = category_matches.get(&category).copied().unwrap_or(0);
        category_accuracy.insert(category, ratio(matches, total));
    }

    let benchmark = BenchmarkResult {
        pipeline_id: pipeline.pipeline_id.clone(),
        dataset_path: args.dataset_jsonl.display().to_string(),
        summary: BenchmarkSummary {
            total_cases: results.len(),
            matched_cases,
            exact_match_rate: ratio(matched_cases, results.len()),
            attack_cases,
            benign_cases,
            attack_catch_rate: ratio(caught_attacks, attack_cases),
            benign_pass_rate: ratio(benign_passes, benign_cases),
            false_positive_rate: ratio(false_positives, benign_cases),
            category_accuracy,
        },
        cases: results,
    };

    if let Some(output) = &args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err("failed to create benchmark output directory")?;
        }
        fs::write(output, serde_json::to_string_pretty(&benchmark).into_diagnostic()? + "\n")
            .into_diagnostic()
            .wrap_err("failed to write benchmark result JSON")?;
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&benchmark).into_diagnostic()?);
    } else {
        println!(
            "{} {}",
            "Benchmark".bold().bright_green(),
            benchmark.pipeline_id.bold()
        );
        println!("  {} {}", "Cases".bright_black(), benchmark.summary.total_cases);
        println!(
            "  {} {}",
            "Exact match".bright_black(),
            format!("{:.1}%", benchmark.summary.exact_match_rate * 100.0).bold()
        );
        println!(
            "  {} {}",
            "Attack catch".bright_black(),
            format!("{:.1}%", benchmark.summary.attack_catch_rate * 100.0).bold()
        );
        println!(
            "  {} {}",
            "Benign pass".bright_black(),
            format!("{:.1}%", benchmark.summary.benign_pass_rate * 100.0).bold()
        );
        println!(
            "  {} {}",
            "False positive".bright_black(),
            format!("{:.1}%", benchmark.summary.false_positive_rate * 100.0).bold()
        );
        if let Some(output) = &args.output {
            println!("  {} {}", "Result JSON".bright_black(), output.display());
        }
    }

    Ok(())
}

fn run_compose(args: ComposeArgs) -> Result<()> {
    if args.artifacts.is_empty() {
        return Err(guidance(
            "compose needs at least one pearl artifact path",
            "Pass one or more pearl.ir.json files after the --output flag.",
        ));
    }
    let base_dir = args
        .output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let plan = compose_pipeline(args.pipeline_id, &args.artifacts, base_dir)
        .into_diagnostic()
        .wrap_err("failed to compose starter pipeline")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create compose output directory")?;
    }
    plan.pipeline
        .write_pretty(&args.output)
        .into_diagnostic()
        .wrap_err("failed to write composed pipeline artifact")?;

    println!("{} {}", "Composed".bold().bright_green(), args.output.display());
    for note in &plan.notes {
        println!("  {} {}", "Note".bright_black(), note);
    }
    Ok(())
}

fn run_compile(args: CompileArgs) -> Result<()> {
    let gate = LogicPearlGateIr::from_path(&args.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load pearl IR for compilation")?;

    compile_native_runner(
        &args.pearl_ir,
        &gate.gate_id,
        args.name,
        args.target,
        args.output,
    )
}

fn run_build(args: BuildArgs) -> Result<()> {
    let output_dir = args
        .output_dir
        .unwrap_or_else(|| {
            args.decision_traces
                .as_deref()
                .and_then(|path| path.parent())
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("output")
        });
    let gate_id = args
        .gate_id
        .unwrap_or_else(|| {
            args.decision_traces
                .as_deref()
                .and_then(|path| path.file_stem())
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_else(|| "decision_traces".to_string())
        });

    let build_options = BuildOptions {
        output_dir,
        gate_id,
        label_column: args.label_column.clone(),
    };

    let mut rows = match (&args.trace_plugin_manifest, &args.decision_traces) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            let source = args.trace_plugin_input.ok_or_else(|| {
                guidance(
                    "--trace-plugin-manifest was provided without --trace-plugin-input",
                    "Pass the raw source string or path with --trace-plugin-input when using a trace_source plugin.",
                )
            })?;
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::TraceSource,
                payload: serde_json::json!({
                    "source": source,
                    "options": {
                        "label_column": build_options.label_column,
                    }
                }),
            };
            let response = run_plugin(&manifest, &request)
                .into_diagnostic()
                .wrap_err("trace plugin execution failed")?;
            let traces_value = response
                .extra
                .get("decision_traces")
                .cloned()
                .ok_or_else(|| {
                    guidance(
                        "trace plugin response is missing `decision_traces`",
                        "A trace_source plugin must return a top-level decision_traces array.",
                    )
                })?;
            let rows: Vec<DecisionTraceRow> = serde_json::from_value(traces_value)
                .into_diagnostic()
                .wrap_err("trace plugin decision_traces payload was invalid")?;
            rows
        }
        (None, Some(decision_traces)) => logicpearl_discovery::load_decision_traces(decision_traces, &build_options.label_column)
            .into_diagnostic()
            .wrap_err("failed to load decision traces")?,
        (Some(_), Some(_)) => {
            return Err(guidance(
                "build received both a CSV path and a trace plugin",
                "Use either the positional <decision_traces.csv> input or --trace-plugin-manifest, not both.",
            ));
        }
        (None, None) => {
            return Err(guidance(
                "build is missing an input source",
                "Provide a decision trace CSV path or use --trace-plugin-manifest with --trace-plugin-input.",
            ));
        }
    };

    if let Some(manifest_path) = &args.enricher_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to load enricher plugin manifest")?;
        if manifest.stage != PluginStage::Enricher {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected enricher, got {:?}", manifest.stage),
                "Use an enricher-stage manifest with --enricher-plugin-manifest.",
            ));
        }
        let request = PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Enricher,
            payload: serde_json::json!({
                "records": rows,
            }),
        };
        let response = run_plugin(&manifest, &request)
            .into_diagnostic()
            .wrap_err("enricher plugin execution failed")?;
        let records_value = response
            .extra
            .get("records")
            .cloned()
            .ok_or_else(|| {
                guidance(
                    "enricher plugin response is missing `records`",
                    "An enricher plugin must return a top-level records array compatible with decision traces.",
                )
            })?;
        rows = serde_json::from_value(records_value)
            .into_diagnostic()
            .wrap_err("enricher plugin records payload was invalid")?;
    }

    let source_name = if let Some(manifest) = &args.trace_plugin_manifest {
        format!(
            "plugin:{}",
            PluginManifest::from_path(manifest)
                .into_diagnostic()
                .wrap_err("failed to reload trace plugin manifest")?
                .name
        )
    } else {
        args.decision_traces
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "decision_traces".to_string())
    };

    let result = build_pearl_from_rows(&rows, source_name, &build_options)
        .into_diagnostic()
        .wrap_err("failed to build pearl from decision traces")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result).into_diagnostic()?);
    } else {
        println!("{} {}", "Built".bold().bright_green(), result.gate_id.bold());
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!("  {} {}", "Rules".bright_black(), result.rules_discovered);
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", result.training_parity * 100.0).bold()
        );
        println!("  {} {}", "Pearl IR".bright_black(), result.output_files.pearl_ir);
        println!(
            "  {} {}",
            "Build report".bright_black(),
            PathBuf::from(&result.output_files.pearl_ir)
                .parent()
                .unwrap()
                .join("build_report.json")
                .display()
        );
    }
    Ok(())
}

fn run_eval(args: RunArgs) -> Result<()> {
    let gate = LogicPearlGateIr::from_path(&args.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let payload: Value = serde_json::from_str(
        &fs::read_to_string(&args.input_json)
            .into_diagnostic()
            .wrap_err("failed to read input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("input JSON is not valid JSON")?;

    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("runtime input shape is invalid")?;
    let mut outputs = Vec::with_capacity(parsed.len());
    for input in parsed {
        outputs.push(
            evaluate_gate(&gate, &input)
                .into_diagnostic()
                .wrap_err("failed to evaluate pearl")?,
        );
    }
    if outputs.len() == 1 {
        println!("{}", outputs[0]);
    } else {
        println!("{}", serde_json::to_string_pretty(&outputs).into_diagnostic()?);
    }
    Ok(())
}

fn compile_native_runner(
    pearl_ir: &PathBuf,
    gate_id: &str,
    name: Option<String>,
    target_triple: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let pearl_name = name.unwrap_or_else(|| gate_id.to_string());
    let output_path = output.unwrap_or_else(|| default_compiled_output_path(pearl_ir, &pearl_name, target_triple.as_deref()));
    let workspace_root = workspace_root();
    let crate_name = format!("logicpearl_compiled_{}", sanitize_identifier(&pearl_name));
    let build_dir = workspace_root
        .join("target")
        .join("generated")
        .join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated compile directory")?;

    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nlogicpearl-ir = {{ path = \"{}\" }}\nlogicpearl-runtime = {{ path = \"{}\" }}\nserde_json = \"1\"\n",
        workspace_root.join("crates/logicpearl-ir").display(),
        workspace_root.join("crates/logicpearl-runtime").display(),
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated Cargo.toml")?;

    let escaped_pearl_path = pearl_ir.display().to_string().replace('\\', "\\\\").replace('\"', "\\\"");
    let main_rs = format!(
        "use logicpearl_ir::LogicPearlGateIr;\nuse logicpearl_runtime::{{evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\nuse std::fs;\nuse std::process::ExitCode;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn main() -> ExitCode {{\n    match run() {{\n        Ok(()) => ExitCode::SUCCESS,\n        Err(err) => {{\n            eprintln!(\"{{}}\", err);\n            ExitCode::FAILURE\n        }}\n    }}\n}}\n\nfn run() -> Result<(), Box<dyn std::error::Error>> {{\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() != 2 {{\n        return Err(\"usage: compiled-pearl <input.json>\".into());\n    }}\n    let gate = LogicPearlGateIr::from_json_str(PEARL_JSON)?;\n    let payload: Value = serde_json::from_str(&fs::read_to_string(&args[1])?)?;\n    let parsed = parse_input_payload(payload)?;\n    let mut outputs = Vec::with_capacity(parsed.len());\n    for input in parsed {{\n        outputs.push(evaluate_gate(&gate, &input)?);\n    }}\n    if outputs.len() == 1 {{\n        println!(\"{{}}\", outputs[0]);\n    }} else {{\n        println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n    }}\n    Ok(())\n}}\n"
    );
    fs::write(src_dir.join("main.rs"), main_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated runner source")?;

    let mut command = std::process::Command::new("cargo");
    command
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--manifest-path")
        .arg(build_dir.join("Cargo.toml"));
    if let Some(target_triple) = &target_triple {
        command.arg("--target").arg(target_triple);
    }
    let status = command
        .status()
        .into_diagnostic()
        .wrap_err("failed to invoke cargo for native pearl compilation")?;
    if !status.success() {
        return Err(miette::miette!(
            "native pearl compilation failed with status {status}\n\nHint: If this is a cross-compile target, install the Rust target and any required linker/toolchain first."
        ));
    }

    let built_binary = build_dir
        .join("target")
        .join(target_triple.as_deref().unwrap_or(""))
        .join("release")
        .join(binary_file_name(&crate_name, target_triple.as_deref()));
    fs::create_dir_all(
        output_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )
    .into_diagnostic()
    .wrap_err("failed to create output directory")?;
    fs::copy(&built_binary, &output_path)
        .into_diagnostic()
        .wrap_err("failed to copy compiled pearl binary")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output_path)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl permissions")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&output_path, perms)
            .into_diagnostic()
            .wrap_err("failed to mark compiled pearl executable")?;
    }

    println!(
        "{} {}",
        "Compiled".bold().bright_green(),
        output_path.display()
    );
    Ok(())
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    let gate = LogicPearlGateIr::from_path(&args.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    if args.json {
        let summary = serde_json::json!({
            "gate_id": gate.gate_id,
            "ir_version": gate.ir_version,
            "features": gate.input_schema.features.len(),
            "rules": gate.rules.len(),
            "correctness_scope": gate.verification.as_ref().and_then(|verification| verification.correctness_scope.clone()),
            "verification_summary": gate.verification.as_ref().and_then(|verification| verification.verification_summary.clone()),
        });
        println!("{}", serde_json::to_string_pretty(&summary).into_diagnostic()?);
    } else {
        let inspector = TextInspector;
        println!(
            "{}\n{}",
            "LogicPearl Artifact".bold().bright_blue(),
            inspector.render(&gate).into_diagnostic()?
        );
    }
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load verify plugin manifest")?;
    if manifest.stage != PluginStage::Verify {
        return Err(guidance(
            format!("plugin manifest stage mismatch: expected verify, got {:?}", manifest.stage),
            "Use a verify-stage manifest with `logicpearl verify`.",
        ));
    }
    let pearl_ir: Value = serde_json::from_str(
        &fs::read_to_string(&args.pearl_ir)
            .into_diagnostic()
            .wrap_err("failed to read pearl IR")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse pearl IR JSON")?;
    let fixtures = match args.fixtures {
        Some(path) => Some(
            serde_json::from_str::<Value>(
                &fs::read_to_string(path)
                    .into_diagnostic()
                    .wrap_err("failed to read verifier fixtures")?,
            )
            .into_diagnostic()
            .wrap_err("failed to parse verifier fixtures JSON")?,
        ),
        None => None,
    };
    let request = PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Verify,
        payload: serde_json::json!({
            "pearl_ir": pearl_ir,
            "fixtures": fixtures,
            "constraints": [],
        }),
    };
    let response = run_plugin(&manifest, &request)
        .into_diagnostic()
        .wrap_err("verify plugin execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    } else {
        println!("{} {}", "Verify plugin".bold().bright_yellow(), manifest.name.bold());
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    }
    Ok(())
}

fn run_pipeline_validate(args: PipelineValidateArgs) -> Result<()> {
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

fn run_pipeline_inspect(args: PipelineInspectArgs) -> Result<()> {
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
        println!("  {} {}", "Final exports".bright_black(), validated.exports.join(", "));
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
                println!("    {} {}", "Exports".bright_black(), stage.exports.join(", "));
            }
        }
    }
    Ok(())
}

fn run_pipeline_run(args: PipelineRunArgs) -> Result<()> {
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
    let execution = pipeline
        .run(base_dir, &input)
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

fn run_pipeline_trace(args: PipelineTraceArgs) -> Result<()> {
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
    let execution = pipeline
        .run(base_dir, &input)
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

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("logicpearl-cli crate should live under workspace/crates/logicpearl-cli")
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn collapse_route(route: &str, collapse_non_allow_to_deny: bool) -> String {
    if collapse_non_allow_to_deny {
        if route == "allow" {
            "allow".to_string()
        } else {
            "deny".to_string()
        }
    } else {
        route.to_string()
    }
}

fn to_native_profile(profile: ObserverProfileArg) -> Result<NativeObserverProfile> {
    match profile {
        ObserverProfileArg::GuardrailsV1 => Ok(NativeObserverProfile::GuardrailsV1),
        ObserverProfileArg::Auto => Err(guidance(
            "`auto` is only valid when LogicPearl can inspect input examples",
            "Use a concrete profile like --observer-profile guardrails-v1 or let benchmark observe/prepare auto-detect from dataset input.",
        )),
    }
}

fn observer_resolution(observer: &ResolvedObserver) -> ObserverResolution {
    match observer {
        ResolvedObserver::NativeProfile(profile) => ObserverResolution::NativeProfile {
            profile: native_profile_name(*profile).to_string(),
        },
        ResolvedObserver::NativeArtifact(artifact) => ObserverResolution::NativeArtifact {
            observer_id: artifact.observer_id.clone(),
        },
        ResolvedObserver::Plugin(manifest) => ObserverResolution::Plugin {
            name: manifest.name.clone(),
        },
    }
}

fn native_profile_name(profile: NativeObserverProfile) -> &'static str {
    match profile {
        NativeObserverProfile::GuardrailsV1 => "guardrails_v1",
    }
}

fn render_observer_resolution(resolution: &ObserverResolution) -> String {
    match resolution {
        ObserverResolution::NativeProfile { profile } => format!("native profile {profile}"),
        ObserverResolution::NativeArtifact { observer_id } => format!("native artifact {observer_id}"),
        ObserverResolution::Plugin { name } => format!("plugin {name}"),
    }
}

fn resolve_observer_for_cases(
    dataset_jsonl: &PathBuf,
    observer_profile: Option<ObserverProfileArg>,
    observer_artifact: Option<PathBuf>,
    plugin_manifest: Option<PathBuf>,
) -> Result<ResolvedObserver> {
    let explicit_count = usize::from(observer_profile.is_some())
        + usize::from(observer_artifact.is_some())
        + usize::from(plugin_manifest.is_some());
    if explicit_count > 1 {
        return Err(guidance(
            "choose only one observer source",
            "Use one of --observer-profile, --observer-artifact, or --plugin-manifest.",
        ));
    }

    if let Some(path) = plugin_manifest {
        let manifest = PluginManifest::from_path(&path)
            .into_diagnostic()
            .wrap_err("failed to load observer plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
                "Use an observer-stage manifest.",
            ));
        }
        return Ok(ResolvedObserver::Plugin(manifest));
    }

    if let Some(path) = observer_artifact {
        let artifact = load_artifact(&path)
            .into_diagnostic()
            .wrap_err("failed to load native observer artifact")?;
        return Ok(ResolvedObserver::NativeArtifact(artifact));
    }

    if let Some(profile) = observer_profile {
        return match profile {
            ObserverProfileArg::Auto => {
                let cases = load_benchmark_cases(dataset_jsonl)?;
                let sample = cases
                    .first()
                    .ok_or_else(|| guidance("benchmark dataset is empty", "Add at least one case before using --observer-profile auto."))?;
                let detected = detect_profile_from_input(&sample.input).ok_or_else(|| {
                    guidance(
                        "could not auto-detect a built-in observer profile",
                        "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
                    )
                })?;
                Ok(ResolvedObserver::NativeProfile(detected))
            }
            other => Ok(ResolvedObserver::NativeProfile(to_native_profile(other)?)),
        };
    }

    let cases = load_benchmark_cases(dataset_jsonl)?;
    let sample = cases
        .first()
        .ok_or_else(|| guidance("benchmark dataset is empty", "Add at least one case before running benchmark observe."))?;
    let detected = detect_profile_from_input(&sample.input).ok_or_else(|| {
        guidance(
            "no observer source was provided and no built-in profile could be auto-detected",
            "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
        )
    })?;
    Ok(ResolvedObserver::NativeProfile(detected))
}

fn resolve_observer_from_input(
    raw_input: &Value,
    observer_profile: Option<ObserverProfileArg>,
    observer_artifact: Option<PathBuf>,
    plugin_manifest: Option<PathBuf>,
) -> Result<ResolvedObserver> {
    let explicit_count = usize::from(observer_profile.is_some())
        + usize::from(observer_artifact.is_some())
        + usize::from(plugin_manifest.is_some());
    if explicit_count > 1 {
        return Err(guidance(
            "choose only one observer source",
            "Use one of --observer-profile, --observer-artifact, or --plugin-manifest.",
        ));
    }

    if let Some(path) = plugin_manifest {
        let manifest = PluginManifest::from_path(&path)
            .into_diagnostic()
            .wrap_err("failed to load observer plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
                "Use an observer-stage manifest.",
            ));
        }
        return Ok(ResolvedObserver::Plugin(manifest));
    }

    if let Some(path) = observer_artifact {
        let artifact = load_artifact(&path)
            .into_diagnostic()
            .wrap_err("failed to load native observer artifact")?;
        return Ok(ResolvedObserver::NativeArtifact(artifact));
    }

    if let Some(profile) = observer_profile {
        return match profile {
            ObserverProfileArg::Auto => {
                let detected = detect_profile_from_input(raw_input).ok_or_else(|| {
                    guidance(
                        "could not auto-detect a built-in observer profile",
                        "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
                    )
                })?;
                Ok(ResolvedObserver::NativeProfile(detected))
            }
            other => Ok(ResolvedObserver::NativeProfile(to_native_profile(other)?)),
        };
    }

    let detected = detect_profile_from_input(raw_input).ok_or_else(|| {
        guidance(
            "no observer source was provided and no built-in profile could be auto-detected",
            "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
        )
    })?;
    Ok(ResolvedObserver::NativeProfile(detected))
}

fn observe_benchmark_cases(
    dataset_jsonl: &PathBuf,
    observer: &ResolvedObserver,
    output: &PathBuf,
) -> Result<usize> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observed benchmark output directory")?;
    }

    let mut rows = 0_usize;
    let mut out = String::new();
    for case in load_benchmark_cases(dataset_jsonl)? {
        let features = observe_features(observer, &case.input)
            .wrap_err(format!("observer execution failed for case {}", case.id))?;
        let observed = ObservedBenchmarkCase {
            id: case.id,
            input: case.input,
            expected_route: case.expected_route,
            category: case.category,
            features,
        };
        out.push_str(&serde_json::to_string(&observed).into_diagnostic()?);
        out.push('\n');
        rows += 1;
    }

    if rows == 0 {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one benchmark case JSON object per line before running benchmark observe.",
        ));
    }

    fs::write(output, out)
        .into_diagnostic()
        .wrap_err("failed to write observed benchmark JSONL")?;
    Ok(rows)
}

fn observe_features(observer: &ResolvedObserver, raw_input: &Value) -> Result<Map<String, Value>> {
    match observer {
        ResolvedObserver::NativeProfile(profile) => observe_with_profile(*profile, raw_input)
            .into_diagnostic()
            .wrap_err("native observer profile execution failed"),
        ResolvedObserver::NativeArtifact(artifact) => observe_with_artifact(artifact, raw_input)
            .into_diagnostic()
            .wrap_err("native observer artifact execution failed"),
        ResolvedObserver::Plugin(manifest) => {
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::Observer,
                payload: serde_json::json!({
                    "raw_input": raw_input,
                }),
            };
            let response = run_plugin(manifest, &request)
                .into_diagnostic()
                .wrap_err("observer plugin execution failed")?;
            response
                .extra
                .get("features")
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| {
                    guidance(
                        "observer plugin response is missing `features`",
                        "An observer plugin used for benchmark observation must return a top-level features object.",
                    )
                })
        }
    }
}

fn load_trace_projection_config(config_path: &PathBuf) -> Result<TraceProjectionConfig> {
    let config_text = fs::read_to_string(config_path)
        .into_diagnostic()
        .wrap_err("could not read trace projection config")?;
    let config: TraceProjectionConfig = serde_json::from_str(&config_text)
        .into_diagnostic()
        .wrap_err("trace projection config is not valid JSON")?;
    if config.binary_targets.is_empty() {
        return Err(guidance(
            "trace projection config must declare at least one binary target",
            "Add one or more entries under `binary_targets` in the projection config.",
        ));
    }
    Ok(config)
}

fn emit_trace_tables(
    observed_jsonl: &PathBuf,
    config_path: &PathBuf,
    output_dir: &PathBuf,
) -> Result<TraceEmitSummary> {
    let config = load_trace_projection_config(config_path)?;
    let file = fs::File::open(observed_jsonl)
        .into_diagnostic()
        .wrap_err("could not open observed benchmark JSONL")?;
    let reader = BufReader::new(file);
    fs::create_dir_all(output_dir)
        .into_diagnostic()
        .wrap_err("failed to create trace output directory")?;

    let mut inferred_features: Option<Vec<String>> = None;
    let mut multi_target = String::new();
    let mut target_csvs: BTreeMap<String, String> = BTreeMap::new();
    let mut rows = 0_usize;

    for (line_no, line) in reader.lines().enumerate() {
        let line = line
            .into_diagnostic()
            .wrap_err("failed to read observed benchmark line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: ObservedBenchmarkCase = serde_json::from_str(trimmed)
            .into_diagnostic()
            .wrap_err(format!(
                "invalid observed benchmark JSON on line {}",
                line_no + 1
            ))?;

        let feature_columns = if config.feature_columns.is_empty() {
            inferred_features.get_or_insert_with(|| {
                let mut keys = case.features.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                keys
            })
        } else {
            &config.feature_columns
        };

        if config.emit_multi_target && multi_target.is_empty() {
            let mut header = feature_columns.join(",");
            header.push(',');
            header.push_str(
                &config
                    .binary_targets
                    .iter()
                    .map(|target| target.name.clone())
                    .collect::<Vec<_>>()
                    .join(","),
            );
            header.push('\n');
            multi_target.push_str(&header);
        }

        let mut target_values = Vec::with_capacity(config.binary_targets.len());
        for target in &config.binary_targets {
            if target_csvs.get(&target.name).is_none() {
                let target_features = if target.trace_features.is_empty() {
                    feature_columns.clone()
                } else {
                    target.trace_features.clone()
                };
                let mut header = target_features.join(",");
                header.push_str(",allowed\n");
                target_csvs.insert(target.name.clone(), header);
            }

            let denied = projection_matches(&case, &target.positive_when);
            target_values.push(allow_word(!denied).to_string());

            let target_features = if target.trace_features.is_empty() {
                feature_columns.clone()
            } else {
                target.trace_features.clone()
            };
            let values = target_features
                .iter()
                .map(|feature| csv_value(case.features.get(feature)))
                .collect::<Vec<_>>()
                .join(",");
            target_csvs
                .get_mut(&target.name)
                .expect("target csv initialized")
                .push_str(&format!("{values},{}\n", allow_word(!denied)));
        }

        if config.emit_multi_target {
            let mut values = feature_columns
                .iter()
                .map(|feature| csv_value(case.features.get(feature)))
                .collect::<Vec<_>>();
            values.extend(target_values);
            multi_target.push_str(&values.join(","));
            multi_target.push('\n');
        }
        rows += 1;
    }

    if rows == 0 {
        return Err(guidance(
            "observed benchmark dataset is empty",
            "Run `logicpearl benchmark observe ...` first to generate observed feature rows.",
        ));
    }

    let mut files = Vec::new();
    if config.emit_multi_target {
        let path = output_dir.join("multi_target.csv");
        fs::write(&path, multi_target)
            .into_diagnostic()
            .wrap_err("failed to write multi_target.csv")?;
        files.push("multi_target.csv".to_string());
    }
    for (target_name, contents) in &target_csvs {
        let filename = format!("{target_name}_traces.csv");
        let path = output_dir.join(&filename);
        fs::write(&path, contents)
            .into_diagnostic()
            .wrap_err(format!("failed to write {filename}"))?;
        files.push(filename);
    }

    Ok(TraceEmitSummary {
        rows,
        output_dir: output_dir.display().to_string(),
        config: config_path.display().to_string(),
        files,
    })
}

fn load_benchmark_cases(path: &PathBuf) -> Result<Vec<BenchmarkCase>> {
    let file = fs::File::open(path)
        .into_diagnostic()
        .wrap_err("could not open benchmark dataset JSONL")?;
    let reader = BufReader::new(file);
    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line
            .into_diagnostic()
            .wrap_err("failed to read benchmark dataset line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: BenchmarkCase = serde_json::from_str(trimmed)
            .into_diagnostic()
            .wrap_err(format!(
                "invalid benchmark case JSON on line {}. Each line must contain id, input, and expected_route",
                line_no + 1
            ))?;
        cases.push(case);
    }
    Ok(cases)
}

fn parse_json_object_rows(raw: &str) -> Result<Vec<serde_json::Map<String, Value>>> {
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) {
        let mut rows = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            let object = item.as_object().cloned().ok_or_else(|| {
                miette::miette!("row {} is not a JSON object", index + 1)
            })?;
            rows.push(object);
        }
        return Ok(rows);
    }

    let mut rows = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|error| {
            miette::miette!(
                "invalid JSON on line {}: {}",
                line_no + 1,
                error
            )
        })?;
        let object = value.as_object().cloned().ok_or_else(|| {
            miette::miette!(
                "line {} is not a JSON object",
                line_no + 1
            )
        })?;
        rows.push(object);
    }
    Ok(rows)
}

fn first_string_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn stable_value_id(value: &serde_json::Value, fallback_index: usize) -> String {
    match value {
        serde_json::Value::String(text) => sanitize_identifier(text),
        serde_json::Value::Number(number) => number.to_string(),
        _ => format!("{fallback_index:06}"),
    }
}

fn default_true() -> bool {
    true
}

fn projection_matches(case: &ObservedBenchmarkCase, predicate: &ProjectionPredicate) -> bool {
    let expected_route_match = predicate.expected_routes.is_empty()
        || predicate
            .expected_routes
            .iter()
            .any(|route| route == &case.expected_route);
    let any_match = predicate.any_features.is_empty()
        || predicate
            .any_features
            .iter()
            .any(|feature| boolish(case.features.get(feature)));
    let all_match = predicate
        .all_features
        .iter()
        .all(|feature| boolish(case.features.get(feature)));
    expected_route_match && any_match && all_match
}

fn csv_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::Bool(boolean)) => bit(*boolean).to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.replace(',', "_"),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string().replace(',', "_"),
    }
}

fn boolish(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(boolean)) => *boolean,
        Some(Value::Number(number)) => number.as_i64().unwrap_or_default() != 0,
        Some(Value::String(text)) => matches!(text.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "y"),
        _ => false,
    }
}

fn bit(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

fn allow_word(allowed: bool) -> &'static str {
    if allowed { "allowed" } else { "denied" }
}

fn sanitize_identifier(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "pearl".to_string()
    } else {
        out
    }
}

fn default_compiled_output_path(
    pearl_ir: &PathBuf,
    pearl_name: &str,
    target_triple: Option<&str>,
) -> PathBuf {
    pearl_ir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(binary_file_name(&format!("{pearl_name}.pearl"), target_triple))
}

fn binary_file_name(base: &str, target_triple: Option<&str>) -> String {
    if target_is_windows(target_triple) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn target_is_windows(target_triple: Option<&str>) -> bool {
    target_triple
        .map(|target| target.contains("windows"))
        .unwrap_or(cfg!(target_os = "windows"))
}

fn run_observer_validate(args: ObserverValidateArgs) -> Result<()> {
    if args.plugin_manifest {
        let manifest = PluginManifest::from_path(&args.target)
            .into_diagnostic()
            .wrap_err("failed to load plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
                "Use an observer-stage manifest with --plugin-manifest.",
            ));
        }
        println!(
            "{} {}",
            "Observer plugin".bold().bright_magenta(),
            format!("manifest is valid ({})", manifest.name).bright_black()
        );
    } else {
        let artifact = load_artifact(&args.target)
            .into_diagnostic()
            .wrap_err("failed to read native observer artifact")?;
        let status = observer_status().into_diagnostic()?;
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            format!(
                "artifact is valid ({}, id={})",
                status, artifact.observer_id
            )
            .bright_black()
        );
    }
    Ok(())
}

fn run_observer_run(args: ObserverRunArgs) -> Result<()> {
    let raw_input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input)
            .into_diagnostic()
            .wrap_err("failed to read observer input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("observer input JSON is not valid JSON")?;
    let observer = resolve_observer_from_input(
        &raw_input,
        args.observer_profile.clone(),
        args.observer_artifact.clone(),
        args.plugin_manifest.clone(),
    )?;
    let features = observe_features(&observer, &raw_input)?;
    let response = serde_json::json!({
        "features": features,
        "observer": observer_resolution(&observer)
    });
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    } else {
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            render_observer_resolution(&observer_resolution(&observer)).bold()
        );
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    }
    Ok(())
}

fn run_observer_detect(args: ObserverDetectArgs) -> Result<()> {
    let raw_input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input)
            .into_diagnostic()
            .wrap_err("failed to read observer input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("observer input JSON is not valid JSON")?;
    let detected = detect_profile_from_input(&raw_input)
        .map(|profile| ObserverResolution::NativeProfile {
            profile: native_profile_name(profile).to_string(),
        });
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "detected": detected
            }))
            .into_diagnostic()?
        );
    } else if let Some(resolution) = detected {
        println!(
            "{} {}",
            "Detected".bold().bright_green(),
            render_observer_resolution(&resolution)
        );
    } else {
        println!("{}", "No built-in observer profile detected".bright_yellow());
    }
    Ok(())
}

fn run_observer_scaffold(args: ObserverScaffoldArgs) -> Result<()> {
    let profile = to_native_profile(args.profile)?;
    let artifact = default_artifact_for_profile(profile);
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observer scaffold output directory")?;
    }
    fs::write(
        &args.output,
        serde_json::to_string_pretty(&artifact).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write observer artifact")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": args.output.display().to_string(),
                "observer": artifact
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Scaffolded".bold().bright_green(), artifact.observer_id.bold());
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}
