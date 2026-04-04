use clap::{Args, Parser, Subcommand};
use logicpearl_core::ArtifactRenderer;
use logicpearl_discovery::{
    build_pearl_from_rows, discover_from_csv, BuildOptions, DecisionTraceRow, DiscoverOptions,
};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_pipeline::{compose_pipeline, PipelineDefinition};
use logicpearl_plugin::{run_plugin, PluginManifest, PluginRequest, PluginStage};
use logicpearl_observer::status as observer_status;
use logicpearl_render::TextInspector;
use logicpearl_runtime::{evaluate_gate, parse_input_payload};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
Example:
  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json";

const OBSERVER_AFTER_HELP: &str = "\
Examples:
  logicpearl observer validate examples/plugins/python_observer/manifest.json --plugin-manifest
  logicpearl observer run --plugin-manifest examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json --json";

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
    /// Convert a raw Salad-Data JSON file into LogicPearl benchmark-case JSONL.
    AdaptSalad(BenchmarkAdaptSaladArgs),
    /// Run an observer plugin over benchmark cases and emit observed feature rows.
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
#[command(after_help = "Example:\n  logicpearl benchmark observe /tmp/salad_attack.jsonl --plugin-manifest benchmarks/guardrails/examples/agent_guardrail/plugins/observer/manifest.json --output /tmp/salad_attack_observed.jsonl")]
struct BenchmarkObserveArgs {
    dataset_jsonl: PathBuf,
    /// Observer plugin manifest used to normalize each benchmark case input.
    #[arg(long)]
    plugin_manifest: PathBuf,
    /// Output JSONL path with benchmark metadata plus observer features.
    #[arg(long)]
    output: PathBuf,
    /// Emit machine-readable JSON summary instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl benchmark emit-traces /tmp/salad_attack_observed.jsonl --output-dir /tmp/trace_exports")]
struct BenchmarkEmitTracesArgs {
    observed_jsonl: PathBuf,
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
    /// Check that an observer plugin or observer artifact is valid.
    Validate(ObserverValidateArgs),
    /// Run an observer on raw input and emit normalized features.
    Run(ObserverRunArgs),
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl observer validate examples/plugins/python_observer/manifest.json --plugin-manifest")]
struct ObserverValidateArgs {
    target: PathBuf,
    /// Validate a plugin manifest instead of a static observer artifact.
    #[arg(long)]
    plugin_manifest: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Example:\n  logicpearl observer run --plugin-manifest examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json --json")]
struct ObserverRunArgs {
    /// Plugin manifest for the observer plugin to execute.
    #[arg(long)]
    plugin_manifest: PathBuf,
    /// Raw input JSON to send to the plugin.
    #[arg(long)]
    input: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Benchmark {
            command: BenchmarkCommand::AdaptSalad(args),
        } => run_benchmark_adapt_salad(args),
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
    }
}

fn run_benchmark_observe(args: BenchmarkObserveArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load observer plugin manifest")?;
    if manifest.stage != PluginStage::Observer {
        return Err(guidance(
            format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
            "Use an observer-stage manifest with `logicpearl benchmark observe`.",
        ));
    }

    let file = fs::File::open(&args.dataset_jsonl)
        .into_diagnostic()
        .wrap_err("could not open benchmark dataset JSONL")?;
    let reader = BufReader::new(file);
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observed benchmark output directory")?;
    }

    let mut rows = 0_usize;
    let mut out = String::new();
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
        let request = PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            payload: serde_json::json!({
                "raw_input": case.input,
            }),
        };
        let response = run_plugin(&manifest, &request)
            .into_diagnostic()
            .wrap_err(format!("observer plugin execution failed for case {}", case.id))?;
        let features = response
            .extra
            .get("features")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| {
                guidance(
                    "observer plugin response is missing `features`",
                    "An observer plugin used for benchmark observation must return a top-level features object.",
                )
            })?;
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

    fs::write(&args.output, out)
        .into_diagnostic()
        .wrap_err("failed to write observed benchmark JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": rows,
                "output": args.output.display().to_string(),
                "observer_plugin": manifest.name
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Observed".bold().bright_green(), "benchmark cases".bold());
        println!("  {} {}", "Rows".bright_black(), rows);
        println!("  {} {}", "Observer".bright_black(), manifest.name);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

fn run_benchmark_emit_traces(args: BenchmarkEmitTracesArgs) -> Result<()> {
    let file = fs::File::open(&args.observed_jsonl)
        .into_diagnostic()
        .wrap_err("could not open observed benchmark JSONL")?;
    let reader = BufReader::new(file);
    fs::create_dir_all(&args.output_dir)
        .into_diagnostic()
        .wrap_err("failed to create trace output directory")?;

    let mut multi_target = String::from(
        "requests_instruction_override,targets_system_prompt,requests_secret_exfiltration,requests_tool_misuse,requests_data_access_outside_scope,contains_indirect_document_authority,is_likely_benign_question,attack_confidence,target_instruction_boundary,target_exfiltration,target_tool_use\n",
    );
    let mut instruction_boundary = String::from(
        "requests_instruction_override,targets_system_prompt,contains_indirect_document_authority,allowed\n",
    );
    let mut data_exfiltration =
        String::from("requests_secret_exfiltration,requests_data_access_outside_scope,allowed\n");
    let mut tool_authorization =
        String::from("requests_tool_misuse,requests_data_access_outside_scope,allowed\n");
    let mut route_status = String::from(
        "tool_authorization_bitmask,instruction_boundary_bitmask,data_exfiltration_bitmask,attack_confidence,is_likely_benign_question,allowed\n",
    );

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

        let fio = boolish(case.features.get("requests_instruction_override"));
        let tsp = boolish(case.features.get("targets_system_prompt"));
        let rse = boolish(case.features.get("requests_secret_exfiltration"));
        let rtm = boolish(case.features.get("requests_tool_misuse"));
        let rdas = boolish(case.features.get("requests_data_access_outside_scope"));
        let cida = boolish(case.features.get("contains_indirect_document_authority"));
        let ilbq = boolish(case.features.get("is_likely_benign_question"));
        let attack_confidence = numericish(case.features.get("attack_confidence"));

        let target_instruction_boundary = case.expected_route != "allow" && (fio || tsp || cida);
        let target_exfiltration = case.expected_route != "allow" && rse;
        let target_tool_use = case.expected_route != "allow" && rtm;

        multi_target.push_str(&format!(
            "{},{},{},{},{},{},{},{:.2},{},{},{}\n",
            bit(fio),
            bit(tsp),
            bit(rse),
            bit(rtm),
            bit(rdas),
            bit(cida),
            bit(ilbq),
            attack_confidence,
            allow_word(!target_instruction_boundary),
            allow_word(!target_exfiltration),
            allow_word(!target_tool_use),
        ));

        instruction_boundary.push_str(&format!(
            "{},{},{},{}\n",
            bit(fio),
            bit(tsp),
            bit(cida),
            allow_word(!target_instruction_boundary),
        ));
        data_exfiltration.push_str(&format!(
            "{},{},{}\n",
            bit(rse),
            bit(rdas),
            allow_word(!target_exfiltration),
        ));
        tool_authorization.push_str(&format!(
            "{},{},{}\n",
            bit(rtm),
            bit(rdas),
            allow_word(!target_tool_use),
        ));
        route_status.push_str(&format!(
            "{},{},{},{:.2},{},{}\n",
            if target_tool_use { 1 } else { 0 },
            if target_instruction_boundary { 1 } else { 0 },
            if target_exfiltration { 1 } else { 0 },
            attack_confidence,
            bit(ilbq),
            allow_word(case.expected_route == "allow"),
        ));
        rows += 1;
    }

    if rows == 0 {
        return Err(guidance(
            "observed benchmark dataset is empty",
            "Run `logicpearl benchmark observe ...` first to generate observed feature rows.",
        ));
    }

    fs::write(args.output_dir.join("multi_target.csv"), multi_target)
        .into_diagnostic()
        .wrap_err("failed to write multi_target.csv")?;
    fs::write(
        args.output_dir.join("instruction_boundary_traces.csv"),
        instruction_boundary,
    )
    .into_diagnostic()
    .wrap_err("failed to write instruction_boundary_traces.csv")?;
    fs::write(
        args.output_dir.join("data_exfiltration_traces.csv"),
        data_exfiltration,
    )
    .into_diagnostic()
    .wrap_err("failed to write data_exfiltration_traces.csv")?;
    fs::write(
        args.output_dir.join("tool_authorization_traces.csv"),
        tool_authorization,
    )
    .into_diagnostic()
    .wrap_err("failed to write tool_authorization_traces.csv")?;
    fs::write(args.output_dir.join("route_status_traces.csv"), route_status)
        .into_diagnostic()
        .wrap_err("failed to write route_status_traces.csv")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": rows,
                "output_dir": args.output_dir.display().to_string(),
                "files": [
                    "multi_target.csv",
                    "instruction_boundary_traces.csv",
                    "data_exfiltration_traces.csv",
                    "tool_authorization_traces.csv",
                    "route_status_traces.csv"
                ]
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Emitted".bold().bright_green(), "discovery traces".bold());
        println!("  {} {}", "Rows".bright_black(), rows);
        println!("  {} {}", "Output".bright_black(), args.output_dir.display());
    }
    Ok(())
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

fn stable_value_id(value: &serde_json::Value, fallback_index: usize) -> String {
    match value {
        serde_json::Value::String(text) => sanitize_identifier(text),
        serde_json::Value::Number(number) => number.to_string(),
        _ => format!("{fallback_index:06}"),
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

fn numericish(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap_or_default(),
        Some(Value::String(text)) => text.parse::<f64>().unwrap_or_default(),
        _ => 0.0,
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
        let _payload = fs::read_to_string(&args.target)
            .into_diagnostic()
            .wrap_err("failed to read observer JSON")?;
        let status = observer_status().into_diagnostic()?;
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            format!("validation entrypoint ready ({status})").bright_black()
        );
    }
    Ok(())
}

fn run_observer_run(args: ObserverRunArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load observer plugin manifest")?;
    if manifest.stage != PluginStage::Observer {
        return Err(guidance(
            format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
            "Use an observer-stage manifest with `logicpearl observer run`.",
        ));
    }
    let raw_input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input)
            .into_diagnostic()
            .wrap_err("failed to read observer input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("observer input JSON is not valid JSON")?;

    let request = PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        payload: serde_json::json!({
            "raw_input": raw_input,
        }),
    };
    let response = run_plugin(&manifest, &request)
        .into_diagnostic()
        .wrap_err("observer plugin execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Observer plugin".bold().bright_magenta(),
            manifest.name.bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    }
    Ok(())
}
