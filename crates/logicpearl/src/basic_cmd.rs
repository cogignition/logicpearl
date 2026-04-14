// SPDX-License-Identifier: MIT
use super::*;
use anstream::println;
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use logicpearl_core::{
    load_artifact_bundle, provenance_safe_path_string, ArtifactKind, LoadedArtifactBundle,
};
use logicpearl_discovery::build_result_for_report;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod feature_dictionary;

use feature_dictionary::{
    feature_columns_from_decision_rows, generated_feature_dictionary_for_output,
    generated_feature_dictionary_path, should_generate_feature_dictionary,
    write_feature_dictionary_from_columns,
};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum QuickstartTopic {
    Traces,
    Garden,
    Build,
    Pipeline,
    Benchmark,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum DiscoveryDecisionModeArg {
    Standard,
    Review,
}

pub(crate) fn to_discovery_decision_mode(arg: DiscoveryDecisionModeArg) -> DiscoveryDecisionMode {
    match arg {
        DiscoveryDecisionModeArg::Standard => DiscoveryDecisionMode::Standard,
        DiscoveryDecisionModeArg::Review => DiscoveryDecisionMode::Review,
    }
}

#[derive(Debug, Args)]
#[command(after_help = QUICKSTART_AFTER_HELP)]
pub(crate) struct QuickstartArgs {
    /// Optional quickstart path to focus on.
    pub topic: Option<QuickstartTopic>,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Plugin trust:\n  --trace-plugin-manifest and --enricher-plugin-manifest execute local programs declared by plugin manifests.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output --json\n  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output --compile\n  logicpearl build --trace-plugin-manifest examples/plugins/python_trace_source/manifest.json --trace-plugin-input examples/getting_started/decision_traces.csv --trace-plugin-option label_column=allowed --output-dir /tmp/output\n  logicpearl build examples/demos/loan_approval/traces.jsonl --output-dir /tmp/output\n  logicpearl build examples/demos/content_moderation/traces_nested.json --output-dir /tmp/output --refine\n  logicpearl build traces.json --feature-dictionary feature_dictionary.json --source-manifest sources.json --output-dir /tmp/output\n  logicpearl build traces.csv --action-column next_action --output-dir /tmp/actions\n  logicpearl build traces.json --pinned-rules rules.json --output-dir /tmp/output"
)]
pub(crate) struct BuildArgs {
    /// Path to labeled decision traces in CSV, JSONL/NDJSON, or JSON form.
    #[arg(value_name = "TRACES")]
    pub decision_traces: Option<PathBuf>,
    /// Directory to write the named artifact bundle into.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
    /// Gate ID to embed in the emitted pearl.
    #[arg(long)]
    pub gate_id: Option<String>,
    /// Decision label column. If omitted, LogicPearl infers it when there is one unambiguous binary candidate.
    #[arg(long)]
    pub label_column: Option<String>,
    /// Column containing a multi-action label such as water, fertilize, repot, or do_nothing.
    #[arg(long)]
    pub action_column: Option<String>,
    /// Default/pass value for binary gate builds. Rules fire for the other value unless --rule-label is set.
    #[arg(long, help_heading = "Advanced")]
    pub default_label: Option<String>,
    /// Rule/fire value for binary gate builds.
    #[arg(long, help_heading = "Advanced")]
    pub rule_label: Option<String>,
    /// Default action when no action route matches. If omitted, LogicPearl prefers do_nothing, wait, none, or noop when present.
    #[arg(long, help_heading = "Advanced")]
    pub default_action: Option<String>,
    /// Maximum total rules emitted across non-default action routes. If omitted, LogicPearl scales per-action budgets from trace support.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub action_max_rules: Option<usize>,
    /// Comma-separated high-to-low action priority order. Unlisted actions keep LogicPearl's support-based order after the listed actions.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub action_priority: Option<String>,
    /// Do not generate starter feature metadata when --feature-dictionary is omitted.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub raw_feature_ids: bool,
    /// Plugin manifest for a trace-source plugin that emits decision traces over JSON.
    #[arg(long, help_heading = "Advanced")]
    pub trace_plugin_manifest: Option<PathBuf>,
    /// Source passed to the trace-source plugin.
    #[arg(long, help_heading = "Advanced")]
    pub trace_plugin_input: Option<String>,
    /// Repeated key=value options passed through to the trace-source plugin payload.
    #[arg(long = "trace-plugin-option", help_heading = "Advanced")]
    pub trace_plugin_options: Vec<String>,
    /// Plugin manifest for an enricher plugin that transforms decision traces over JSON.
    #[arg(long, help_heading = "Advanced")]
    pub enricher_plugin_manifest: Option<PathBuf>,
    /// Repeated key=value source references to record in build_report.json, such as document_id=claim_1234.
    #[arg(long = "source-ref", help_heading = "Advanced")]
    pub source_references: Vec<String>,
    /// Generic source manifest to hash and attach to build provenance.
    #[arg(long, help_heading = "Advanced")]
    pub source_manifest: Option<PathBuf>,
    /// Tighten over-broad rules using unique-coverage refinement over binary features.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub refine: bool,
    /// JSON file of pinned rules to merge after discovery and refinement.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub pinned_rules: Option<PathBuf>,
    /// JSON feature dictionary that gives raw feature IDs readable labels, states, and provenance.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub feature_dictionary: Option<PathBuf>,
    /// JSON file declaring feature governance such as one-sided boolean evidence.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub feature_governance: Option<PathBuf>,
    /// Discovery policy for this target family. Use `review` for broad, stable suspicion targets.
    #[arg(long, value_enum, default_value_t = DiscoveryDecisionModeArg::Standard, help_heading = "Advanced Discovery")]
    pub discovery_mode: DiscoveryDecisionModeArg,
    /// Also compile native and Wasm deployables after writing the artifact bundle.
    #[arg(long, help_heading = "Advanced")]
    pub compile: bool,
    #[command(flatten)]
    pub plugin_execution: PluginExecutionArgs,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  logicpearl discover traces.csv --targets target_a,target_b --output-dir discovered\n  logicpearl discover traces.jsonl --targets target_a,target_b --residual-pass --refine\n  logicpearl discover traces.json --targets target_a --feature-dictionary feature_dictionary.json --output-dir discovered\n  logicpearl discover traces.json --targets target_a --pinned-rules rules.json --output-dir discovered"
)]
pub(crate) struct DiscoverArgs {
    /// Dataset of labeled traces in CSV, JSONL/NDJSON, or JSON form.
    #[arg(value_name = "DATASET")]
    pub dataset_csv: PathBuf,
    /// Single binary target column to learn.
    #[arg(long)]
    pub target: Option<String>,
    /// Comma-delimited binary target columns to learn.
    #[arg(long, value_delimiter = ',')]
    pub targets: Vec<String>,
    /// Directory to write artifacts, artifact_set.json, and discover_report.json into.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
    /// Stable artifact set identifier.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub artifact_set_id: Option<String>,
    /// Enable solver-backed conjunction recovery and a second residual pass on each target.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub residual_pass: bool,
    /// Tighten over-broad rules using unique-coverage refinement over binary features.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub refine: bool,
    /// JSON file of pinned rules to merge after discovery and refinement.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub pinned_rules: Option<PathBuf>,
    /// JSON feature dictionary that gives raw feature IDs readable labels, states, and provenance.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub feature_dictionary: Option<PathBuf>,
    /// JSON file declaring feature governance such as one-sided boolean evidence.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub feature_governance: Option<PathBuf>,
    /// Discovery policy for this target family. Use `review` for broad, stable suspicion targets.
    #[arg(long, value_enum, default_value_t = DiscoveryDecisionModeArg::Standard, help_heading = "Advanced Discovery")]
    pub discovery_mode: DiscoveryDecisionModeArg,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  logicpearl run examples/getting_started/output examples/getting_started/new_input.json\n  logicpearl run examples/getting_started/output -\n  cat examples/getting_started/new_input.json | logicpearl run examples/getting_started/output\n  logicpearl run examples/getting_started/output/pearl.ir.json examples/getting_started/new_input.json\n  logicpearl run today.json --explain"
)]
pub(crate) struct RunArgs {
    /// Artifact path, or input path when logicpearl.yaml provides run.artifact.
    #[arg(value_name = "ARTIFACT_OR_INPUT")]
    pub pearl_ir: Option<PathBuf>,
    /// Input JSON file, `-` for stdin, or omit to read stdin or the configured example input.
    #[arg(value_name = "INPUT")]
    pub input_json: Option<PathBuf>,
    /// Print matched rules and readable action output instead of only the raw bitmask.
    #[arg(long)]
    pub explain: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Example:\n  logicpearl compose --pipeline-id starter_authz --output examples/pipelines/generated/starter_authz.pipeline.json fixtures/ir/valid/auth-demo-v1.json"
)]
pub(crate) struct ComposeArgs {
    /// Stable pipeline identifier for the emitted starter artifact.
    #[arg(long)]
    pub pipeline_id: String,
    /// Output path for the generated pipeline.json.
    #[arg(long)]
    pub output: PathBuf,
    /// Pearl artifacts to compose into a starter pipeline.
    pub artifacts: Vec<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Requirements:\n  Same-host native compile is self-contained and copies the installed LogicPearl runner.\n  Wasm and non-host --target builds shell out to `cargo build --offline --release`.\n  Those Cargo-backed paths need Rust/Cargo, cached dependencies, and any requested\n  Rust target or linker/toolchain.\n\nExamples:\n  logicpearl compile examples/getting_started/output\n  logicpearl compile examples/getting_started/output --target wasm32-unknown-unknown\n  logicpearl compile examples/getting_started/output/pearl.ir.json --name authz-demo --target x86_64-unknown-linux-gnu"
)]
pub(crate) struct CompileArgs {
    /// Pearl artifact directory, artifact manifest, or pearl.ir.json file.
    #[arg(value_name = "ARTIFACT")]
    pub pearl_ir: PathBuf,
    /// Rust target triple, for example x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, or wasm32-unknown-unknown.
    #[arg(long)]
    pub target: Option<String>,
    /// Pearl artifact name. Defaults to the gate id.
    #[arg(long)]
    pub name: Option<String>,
    /// Output path. Defaults to <name>.pearl, <name>.pearl.exe, or <name>.pearl.wasm depending on target.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  logicpearl inspect examples/getting_started/output --json\n  logicpearl inspect examples/getting_started/output/pearl.ir.json --json"
)]
pub(crate) struct InspectArgs {
    /// Pearl artifact directory, artifact manifest, or pearl.ir.json file.
    #[arg(value_name = "ARTIFACT")]
    pub pearl_ir: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Plugin trust:\n  verify executes the local program declared by --plugin-manifest.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl verify examples/getting_started/output --plugin-manifest examples/plugins/python_verify/manifest.json --json\n  logicpearl verify examples/getting_started/output/pearl.ir.json --plugin-manifest examples/plugins/python_verify/manifest.json --json"
)]
pub(crate) struct VerifyArgs {
    /// Pearl artifact directory, artifact manifest, or pearl.ir.json file.
    #[arg(value_name = "ARTIFACT")]
    pub pearl_ir: PathBuf,
    /// Plugin manifest for the verifier backend.
    #[arg(long)]
    pub plugin_manifest: PathBuf,
    /// Optional fixtures or cases payload passed through to the verifier.
    #[arg(long)]
    pub fixtures: Option<PathBuf>,
    #[command(flatten)]
    pub plugin_execution: PluginExecutionArgs,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct LogicPearlProjectConfig {
    #[serde(default)]
    build: Option<LogicPearlBuildConfig>,
    #[serde(default)]
    run: Option<LogicPearlRunConfig>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct LogicPearlBuildConfig {
    traces: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    gate_id: Option<String>,
    label_column: Option<String>,
    action_column: Option<String>,
    default_label: Option<String>,
    rule_label: Option<String>,
    default_action: Option<String>,
    action_max_rules: Option<usize>,
    action_priority: Option<String>,
    #[serde(default)]
    raw_feature_ids: bool,
    feature_dictionary: Option<PathBuf>,
    source_manifest: Option<PathBuf>,
    feature_governance: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct LogicPearlRunConfig {
    artifact: Option<PathBuf>,
    example_input: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct ActionBuildReport {
    source: String,
    artifact_name: String,
    action_column: String,
    default_action: String,
    rows: usize,
    actions: Vec<String>,
    rule_budget: ActionRuleBudgetReport,
    rules: Vec<ActionRuleBuildReport>,
    training_parity: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provenance: Option<BuildProvenance>,
}

fn action_build_report_for_report(report: &ActionBuildReport) -> ActionBuildReport {
    let mut sanitized = report.clone();
    sanitized.source = provenance_safe_path_string(&sanitized.source);
    sanitized
}

struct LoadedActionTraceRecords {
    loaded: LoadedFlatRecords,
    source_name: String,
    default_output_base: PathBuf,
    default_artifact_name: String,
    trace_plugin: Option<PluginBuildProvenance>,
}

fn default_gate_id_from_path(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "decision_traces".to_string());
    if stem != "traces" {
        return stem;
    }
    let parent_name = match path
        .parent()
        .and_then(|value| value.file_name())
        .map(|value| value.to_string_lossy().into_owned())
    {
        Some(value) => value,
        None => return stem,
    };
    format!("{}_{}", sanitize_identifier(&parent_name), stem)
}

fn load_project_config() -> Result<Option<(PathBuf, LogicPearlProjectConfig)>> {
    for name in ["logicpearl.yaml", "logicpearl.yml"] {
        let path = PathBuf::from(name);
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err("failed to read logicpearl project config")?;
        let config = serde_yaml::from_str(&content)
            .into_diagnostic()
            .wrap_err("failed to parse logicpearl project config")?;
        return Ok(Some((path, config)));
    }
    Ok(None)
}

fn resolve_config_path(config_path: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(path)
}

fn apply_build_config(args: &mut BuildArgs) -> Result<()> {
    let Some((config_path, config)) = load_project_config()? else {
        return Ok(());
    };
    let Some(build) = config.build else {
        return Ok(());
    };
    if args.decision_traces.is_none() {
        args.decision_traces = build
            .traces
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.output_dir.is_none() {
        args.output_dir = build
            .output_dir
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.gate_id.is_none() {
        args.gate_id = build.gate_id;
    }
    if args.label_column.is_none() {
        args.label_column = build.label_column;
    }
    if args.action_column.is_none() {
        args.action_column = build.action_column;
    }
    if args.default_label.is_none() {
        args.default_label = build.default_label;
    }
    if args.rule_label.is_none() {
        args.rule_label = build.rule_label;
    }
    if args.default_action.is_none() {
        args.default_action = build.default_action;
    }
    if args.action_max_rules.is_none() {
        args.action_max_rules = build.action_max_rules;
    }
    if args.action_priority.is_none() {
        args.action_priority = build.action_priority;
    }
    if !args.raw_feature_ids {
        args.raw_feature_ids = build.raw_feature_ids;
    }
    if args.feature_dictionary.is_none() {
        args.feature_dictionary = build
            .feature_dictionary
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.source_manifest.is_none() {
        args.source_manifest = build
            .source_manifest
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.feature_governance.is_none() {
        args.feature_governance = build
            .feature_governance
            .map(|path| resolve_config_path(&config_path, path));
    }
    Ok(())
}

fn configured_run_defaults() -> Result<Option<(PathBuf, LogicPearlRunConfig)>> {
    let Some((config_path, config)) = load_project_config()? else {
        return Ok(None);
    };
    Ok(config.run.map(|run| (config_path, run)))
}

pub(crate) fn run_quickstart(args: QuickstartArgs) -> Result<()> {
    match args.topic {
        None => {
            println!();
            println!("{}", "━━ LogicPearl Quickstart ━━".bold().bright_blue());
            println!();
            println!(
                "  {}",
                "Choose the shortest path for what you want to prove first:".bright_black()
            );
            println!(
                "  {}",
                "Use these commands with the checked-in examples, or copy the shape for your own traces."
                    .bright_black()
            );
            println!();
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "traces".bold().bright_cyan(),
                "generate clean synthetic traces from declarative policy".bright_black()
            );
            println!("    {}", "logicpearl quickstart traces".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "garden".bold().bright_cyan(),
                "learn a small action policy from garden-care examples".bright_black()
            );
            println!("    {}", "logicpearl quickstart garden".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "build".bold().bright_cyan(),
                "learn one pearl from labeled traces".bright_black()
            );
            println!("    {}", "logicpearl quickstart build".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "pipeline".bold().bright_cyan(),
                "run a string-of-pearls artifact".bright_black()
            );
            println!("    {}", "logicpearl quickstart pipeline".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "benchmark".bold().bright_cyan(),
                "score a guardrail benchmark slice".bright_black()
            );
            println!("    {}", "logicpearl quickstart benchmark".bright_black());
            println!();
        }
        Some(QuickstartTopic::Traces) => {
            println!();
            println!("{}", "━━ Quickstart: Traces ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Generate synthetic traces with nuisance fields balanced by construction:"
                    .bright_black()
            );
            println!(
                "     {}",
                "logicpearl traces generate examples/getting_started/synthetic_access_policy.tracegen.json --output /tmp/synthetic_traces.jsonl"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Audit the generated traces:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl traces audit /tmp/synthetic_traces.jsonl --spec examples/getting_started/synthetic_access_policy.tracegen.json"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "3.".bold().bright_cyan(),
                "Build a pearl from them:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl build /tmp/synthetic_traces.jsonl --output-dir /tmp/synthetic_access_policy"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Garden) => {
            println!();
            println!(
                "{}",
                "━━ Quickstart: Garden Actions ━━".bold().bright_green()
            );
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Build a multi-action pearl from reviewed garden-care traces:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl build examples/demos/garden_actions/traces.csv --action-column next_action --default-action do_nothing --gate-id garden_actions --output-dir /tmp/garden-actions"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Inspect the learned action rules:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl inspect /tmp/garden-actions".bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "3.".bold().bright_cyan(),
                "Run today's garden input with an explanation:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl run /tmp/garden-actions examples/demos/garden_actions/today.json --explain"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Build) => {
            println!();
            println!("{}", "━━ Quickstart: Build ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Build your first pearl:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Inspect what it learned:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl inspect examples/getting_started/output".bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "3.".bold().bright_cyan(),
                "Run it on new input:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl run examples/getting_started/output examples/getting_started/new_input.json"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Pipeline) => {
            println!();
            println!("{}", "━━ Quickstart: Pipeline ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Run a public string-of-pearls example:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Trace the full stage-by-stage execution:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Benchmark) => {
            println!();
            println!("{}", "━━ Quickstart: Benchmark ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Run the checked-in guardrail benchmark slice:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Inspect the benchmark pipeline:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl pipeline inspect benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json"
                    .bright_cyan()
            );
            println!();
        }
    }
    Ok(())
}

pub(crate) fn run_discover(args: DiscoverArgs) -> Result<()> {
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

    let output_dir = args.output_dir.clone().unwrap_or_else(|| {
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

    let spinner = if !args.json {
        let sp = ProgressBar::new_spinner();
        sp.set_style(ProgressStyle::with_template("{spinner:.green} {msg} ({elapsed})").unwrap());
        sp.enable_steady_tick(std::time::Duration::from_millis(80));
        sp.set_message(format!(
            "{} artifacts from {}",
            "Discovering".bold().bright_green(),
            args.dataset_csv.display()
        ));
        Some(sp)
    } else {
        None
    };
    let result = discover_from_csv(
        &args.dataset_csv,
        &DiscoverOptions {
            output_dir,
            artifact_set_id,
            target_columns: targets,
            residual_pass: args.residual_pass,
            refine: args.refine,
            pinned_rules: args.pinned_rules.clone(),
            feature_dictionary: args.feature_dictionary.clone(),
            feature_governance: args.feature_governance.clone(),
            decision_mode: to_discovery_decision_mode(args.discovery_mode),
        },
    )
    .into_diagnostic()
    .wrap_err("could not discover artifacts from the dataset")?;
    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Discovered".bold().bright_green(),
            result.artifact_set_id.bold()
        );
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!(
            "  {} {}",
            "Features".bright_black(),
            result.features.join(", ")
        );
        println!(
            "  {} {}",
            "Targets".bright_black(),
            result.targets.join(", ")
        );
        println!(
            "  {} {}",
            "Artifacts".bright_black(),
            result.artifacts.len()
        );
        let residual_rules: usize = result
            .artifacts
            .iter()
            .map(|artifact| artifact.residual_rules_discovered)
            .sum();
        let refined_rules: usize = result
            .artifacts
            .iter()
            .map(|artifact| artifact.refined_rules_applied)
            .sum();
        let pinned_rules: usize = result
            .artifacts
            .iter()
            .map(|artifact| artifact.pinned_rules_applied)
            .sum();
        if result.cache_hit {
            println!(
                "  {} {}",
                "Cache".bright_black(),
                "reused full discover output".bold()
            );
        } else if result.cached_artifacts > 0 {
            println!(
                "  {} {}",
                "Cached artifacts".bright_black(),
                result.cached_artifacts
            );
        }
        if residual_rules > 0 {
            println!("  {} {}", "Residual rules".bright_black(), residual_rules);
        }
        if refined_rules > 0 {
            println!("  {} {}", "Refined rules".bright_black(), refined_rules);
        }
        if pinned_rules > 0 {
            println!("  {} {}", "Pinned rules".bright_black(), pinned_rules);
        }
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

pub(crate) fn run_compose(args: ComposeArgs) -> Result<()> {
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
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create compose output directory")?;
    }
    let packaged_artifacts = package_compose_artifacts(&args.artifacts, base_dir)?;
    let plan = compose_pipeline(args.pipeline_id, &packaged_artifacts, base_dir)
        .into_diagnostic()
        .wrap_err("failed to compose starter pipeline")?;
    plan.pipeline
        .write_pretty(&args.output)
        .into_diagnostic()
        .wrap_err("failed to write composed pipeline artifact")?;
    write_artifact_manifest_v1(
        base_dir,
        ArtifactManifestWriteOptions {
            artifact_kind: ArtifactKind::Pipeline,
            artifact_id: plan.pipeline.pipeline_id.clone(),
            ir_path: args.output.clone(),
            build_report_path: None,
            feature_dictionary_path: None,
            native_path: None,
            wasm_path: None,
            wasm_metadata_path: None,
            build_options_hash: Some(build_options_hash(&serde_json::json!({
                "pipeline_id": plan.pipeline.pipeline_id,
                "artifacts": args
                    .artifacts
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>(),
            }))),
            bundle: ArtifactBundleDescriptor {
                bundle_kind: "pipeline_bundle".to_string(),
                cli_entrypoint: "artifact.json".to_string(),
                primary_runtime: None,
                deployables: Vec::new(),
                metadata_files: Vec::new(),
            },
            extensions: BTreeMap::new(),
            file_extensions: BTreeMap::new(),
        },
    )
    .wrap_err("failed to write pipeline artifact manifest")?;

    println!(
        "{} {}",
        "Composed".bold().bright_green(),
        args.output.display()
    );
    for note in &plan.notes {
        println!("  {} {}", "Note".bright_black(), note);
    }
    Ok(())
}

fn package_compose_artifacts(
    artifact_paths: &[PathBuf],
    output_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let artifacts_dir = output_dir.join("artifacts");
    fs::create_dir_all(&artifacts_dir)
        .into_diagnostic()
        .wrap_err("failed to create composed pipeline artifacts directory")?;

    artifact_paths
        .iter()
        .enumerate()
        .map(|(index, artifact_path)| {
            let source = fs::canonicalize(artifact_path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to resolve compose artifact {}",
                        artifact_path.display()
                    )
                })?;
            let dest = artifacts_dir.join(compose_artifact_file_name(index, artifact_path));

            if fs::canonicalize(&dest)
                .map(|existing| existing == source)
                .unwrap_or(false)
            {
                return Ok(dest);
            }

            fs::copy(&source, &dest)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to package compose artifact {} into {}",
                        artifact_path.display(),
                        dest.display()
                    )
                })?;
            Ok(dest)
        })
        .collect()
}

fn compose_artifact_file_name(index: usize, artifact_path: &Path) -> String {
    let file_name = artifact_path
        .file_name()
        .map(|name| name.to_string_lossy())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "pearl.ir.json".into());
    format!("{:02}-{file_name}", index + 1)
}

pub(crate) fn run_compile(args: CompileArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let artifact_id = pearl_artifact_id(&resolved.pearl_ir)?;
    if args.target.as_deref() == Some("wasm32-unknown-unknown") {
        let output = compile_wasm_module(
            &resolved.pearl_ir,
            &resolved.artifact_dir,
            &artifact_id,
            args.name,
            args.output,
        )?;
        println!(
            "{} {}",
            "Compiled".bold().bright_green(),
            output.module_path.display()
        );
        println!(
            "  {} {}",
            "Wasm metadata".bright_black(),
            output.metadata_path.display()
        );
        refresh_artifact_manifest_deployables(
            &resolved.artifact_dir,
            &resolved.pearl_ir,
            None,
            Some(&output.module_path),
            Some(&output.metadata_path),
        )?;
    } else {
        let output_path = compile_native_runner(
            &resolved.pearl_ir,
            &resolved.artifact_dir,
            &artifact_id,
            args.name,
            args.target,
            args.output,
        )?;
        println!(
            "{} {}",
            "Compiled".bold().bright_green(),
            output_path.display()
        );
        refresh_artifact_manifest_deployables(
            &resolved.artifact_dir,
            &resolved.pearl_ir,
            Some(&output_path),
            None,
            None,
        )?;
    }
    Ok(())
}

pub(crate) fn run_build(mut args: BuildArgs) -> Result<()> {
    apply_build_config(&mut args)?;
    if args.action_column.is_some() {
        return run_action_build(args);
    }
    if args.trace_plugin_manifest.is_none()
        && (!args.trace_plugin_options.is_empty() || args.trace_plugin_input.is_some())
    {
        return Err(guidance(
            "trace plugin input/options were provided without a trace plugin manifest",
            "Pass --trace-plugin-manifest before using --trace-plugin-input or --trace-plugin-option.",
        ));
    }
    let plugin_policy = plugin_execution_policy(&args.plugin_execution);

    let output_dir = args.output_dir.clone().unwrap_or_else(|| {
        args.decision_traces
            .as_deref()
            .and_then(|path| path.parent())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("output")
    });
    let gate_id = args.gate_id.clone().unwrap_or_else(|| {
        args.decision_traces
            .as_deref()
            .map(default_gate_id_from_path)
            .unwrap_or_else(|| "decision_traces".to_string())
    });

    let mut input_traces = Vec::new();
    let mut trace_plugin_provenance = None;
    let mut enricher_plugin_provenance = None;
    let (mut rows, resolved_label_column) = match (
        &args.trace_plugin_manifest,
        &args.decision_traces,
    ) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            let mut trace_plugin_options = build_trace_plugin_options(&args)?;
            let plugin_label_column = trace_plugin_options
                .get("label_column")
                .cloned()
                .unwrap_or_else(|| "allowed".to_string());
            trace_plugin_options
                .entry("label_column".to_string())
                .or_insert_with(|| plugin_label_column.clone());
            let source = args.trace_plugin_input.clone().ok_or_else(|| {
                guidance(
                    "--trace-plugin-manifest was provided without --trace-plugin-input",
                    "Pass the raw source string or path with --trace-plugin-input when using a trace_source plugin.",
                )
            })?;
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::TraceSource,
                payload: logicpearl_plugin::build_canonical_payload(
                    &PluginStage::TraceSource,
                    Value::String(source.clone()),
                    Some(serde_json::to_value(&trace_plugin_options).into_diagnostic()?),
                ),
            };
            let execution =
                run_plugin_with_policy_and_metadata(&manifest, &request, &plugin_policy)
                    .into_diagnostic()
                    .wrap_err("trace plugin execution failed")?;
            trace_plugin_provenance = Some(
                plugin_provenance_from_execution(
                    "trace_source",
                    manifest_path,
                    &manifest,
                    &execution,
                    Some(source_input_provenance(&source)),
                    trace_plugin_options.clone(),
                )
                .into_diagnostic()?,
            );
            let traces_value = execution
                .response
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
            (rows, plugin_label_column)
        }
        (None, Some(decision_traces)) => {
            let loaded = load_decision_traces_auto(
                decision_traces,
                args.label_column.as_deref(),
                args.default_label.as_deref(),
                args.rule_label.as_deref(),
            )
            .into_diagnostic()
            .wrap_err("failed to load decision traces")?;
            input_traces.push(
                trace_input_provenance(decision_traces, loaded.rows.len()).into_diagnostic()?,
            );
            (loaded.rows, loaded.label_column)
        }
        (Some(_), Some(_)) => {
            return Err(guidance(
                "build received both a CSV path and a trace plugin",
                "Use either the positional decision trace dataset input or --trace-plugin-manifest, not both.",
            ));
        }
        (None, None) => {
            return Err(guidance(
                "build is missing an input source",
                "Provide a decision trace dataset path (.csv, .jsonl, or .json) or use --trace-plugin-manifest with --trace-plugin-input.",
            ));
        }
    };

    if should_generate_feature_dictionary(&args) {
        let dictionary_path = generated_feature_dictionary_path(&output_dir);
        write_feature_dictionary_from_columns(
            &dictionary_path,
            feature_columns_from_decision_rows(&rows),
        )?;
        args.feature_dictionary = Some(dictionary_path);
    }

    let build_options = BuildOptions {
        output_dir,
        gate_id,
        label_column: resolved_label_column.clone(),
        positive_label: args.default_label.clone(),
        negative_label: args.rule_label.clone(),
        residual_pass: true,
        refine: args.refine,
        pinned_rules: args.pinned_rules.clone(),
        feature_dictionary: args.feature_dictionary.clone(),
        feature_governance: args.feature_governance.clone(),
        decision_mode: to_discovery_decision_mode(args.discovery_mode),
        max_rules: None,
    };
    let build_options_value = serde_json::json!({
        "gate_id": &build_options.gate_id,
        "label_column": &build_options.label_column,
        "positive_label": &build_options.positive_label,
        "negative_label": &build_options.negative_label,
        "residual_pass": build_options.residual_pass,
        "refine": build_options.refine,
        "pinned_rules": build_options
            .pinned_rules
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_dictionary": build_options
            .feature_dictionary
            .as_ref()
            .map(|path| path.display().to_string()),
        "source_manifest": args
            .source_manifest
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_governance": build_options
            .feature_governance
            .as_ref()
            .map(|path| path.display().to_string()),
        "decision_mode": build_options.decision_mode,
        "max_rules": build_options.max_rules,
    });
    let build_options_digest = build_options_hash(&build_options_value);

    if let Some(manifest_path) = &args.enricher_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to load enricher plugin manifest")?;
        if manifest.stage != PluginStage::Enricher {
            return Err(guidance(
                format!(
                    "plugin manifest stage mismatch: expected enricher, got {:?}",
                    manifest.stage
                ),
                "Use an enricher-stage manifest with --enricher-plugin-manifest.",
            ));
        }
        let request = PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Enricher,
            payload: logicpearl_plugin::build_canonical_payload(
                &PluginStage::Enricher,
                serde_json::to_value(&rows).into_diagnostic()?,
                None,
            ),
        };
        let execution = run_plugin_with_policy_and_metadata(&manifest, &request, &plugin_policy)
            .into_diagnostic()
            .wrap_err("enricher plugin execution failed")?;
        enricher_plugin_provenance = Some(
            plugin_provenance_from_execution(
                "enricher",
                manifest_path,
                &manifest,
                &execution,
                None,
                BTreeMap::new(),
            )
            .into_diagnostic()?,
        );
        let records_value = execution
            .response
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

    let provenance_inputs = BuildProvenanceInputs {
        artifact_dir: Some(build_options.output_dir.clone()),
        source_references: parse_key_value_entries(&args.source_references, "source-ref")?,
        decision_traces_path: args.decision_traces.clone(),
        trace_plugin_manifest_path: args.trace_plugin_manifest.clone(),
        input_traces,
        trace_plugin: trace_plugin_provenance,
        enricher_plugin: enricher_plugin_provenance,
        feature_dictionary_path: args.feature_dictionary.clone(),
        source_manifest: load_source_manifest_for_provenance(args.source_manifest.as_deref())
            .into_diagnostic()?,
        build_options: build_options_value,
        build_options_hash: build_options_digest.clone(),
    };

    let spinner = if !args.json {
        let sp = ProgressBar::new_spinner();
        sp.set_style(ProgressStyle::with_template("{spinner:.green} {msg} ({elapsed})").unwrap());
        sp.enable_steady_tick(std::time::Duration::from_millis(80));
        sp.set_message(format!(
            "{} pearl from {} rows",
            "Building".bold().bright_green(),
            rows.len()
        ));
        Some(sp)
    } else {
        None
    };
    let mut result =
        build_gate_artifact_from_rows(&rows, source_name, &build_options, provenance_inputs)
            .into_diagnostic()
            .wrap_err("failed to build pearl from decision traces")?;
    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    let artifact_dir = PathBuf::from(&result.output_files.artifact_dir);
    let pearl_ir_path = PathBuf::from(&result.output_files.pearl_ir);
    let artifact_name = result.gate_id.clone();
    if args.compile {
        let native_binary_path = result
            .output_files
            .native_binary
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| native_artifact_output_path(&artifact_dir, &artifact_name, None));
        let native_binary = compile_native_runner(
            &pearl_ir_path,
            &artifact_dir,
            &result.gate_id,
            Some(artifact_name.clone()),
            None,
            Some(native_binary_path),
        )?;
        result.output_files.native_binary = Some(native_binary.display().to_string());

        let wasm_output = if is_rust_target_installed("wasm32-unknown-unknown") {
            let wasm_output_path = result
                .output_files
                .wasm_module
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| wasm_artifact_output_path(&artifact_dir, &artifact_name));
            Some(compile_wasm_module(
                &pearl_ir_path,
                &artifact_dir,
                &result.gate_id,
                Some(artifact_name.clone()),
                Some(wasm_output_path),
            )?)
        } else {
            None
        };
        result.output_files.wasm_module = wasm_output
            .as_ref()
            .map(|output| output.module_path.display().to_string());
        result.output_files.wasm_metadata = wasm_output
            .as_ref()
            .map(|output| output.metadata_path.display().to_string());
    } else {
        result.output_files.native_binary = None;
        result.output_files.wasm_module = None;
        result.output_files.wasm_metadata = None;
    }
    attach_generated_file_hashes(
        &mut result.provenance,
        &artifact_dir,
        [
            Some(pearl_ir_path.clone()),
            generated_feature_dictionary_for_output(&args, &artifact_dir).cloned(),
            result
                .output_files
                .native_binary
                .as_ref()
                .map(PathBuf::from),
            result.output_files.wasm_module.as_ref().map(PathBuf::from),
            result
                .output_files
                .wasm_metadata
                .as_ref()
                .map(PathBuf::from),
        ]
        .into_iter()
        .flatten(),
    )
    .into_diagnostic()?;
    persist_build_report(&result)?;
    write_named_artifact_manifest(
        &artifact_dir,
        &result.gate_id,
        &result.output_files,
        generated_feature_dictionary_for_output(&args, &artifact_dir).map(|path| path.as_path()),
        Some(build_options_digest),
    )?;

    if args.json {
        let report = build_result_for_report(&result);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Built".bold().bright_green(),
            result.gate_id.bold()
        );
        if result.cache_hit {
            println!(
                "  {} {}",
                "Cache".bright_black(),
                "reused prior build output".bold()
            );
        }
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!("  {} {}", "Rules".bright_black(), result.rules_discovered);
        if let Some(backend) = &result.exact_selection.backend {
            let backend_label = match backend {
                ExactSelectionBackend::BruteForce => "brute force",
                ExactSelectionBackend::Smt => "smt",
                ExactSelectionBackend::Mip => "mip",
            };
            let selection_summary = if result.exact_selection.adopted {
                format!(
                    "{backend_label} exact selection adopted on {} candidates",
                    result.exact_selection.shortlisted_candidates
                )
            } else {
                format!(
                    "{backend_label} exact selection kept greedy plan on {} candidates",
                    result.exact_selection.shortlisted_candidates
                )
            };
            println!(
                "  {} {}",
                "Exact selection".bright_black(),
                selection_summary
            );
            if let Some(detail) = &result.exact_selection.detail {
                println!("  {} {}", "Selection detail".bright_black(), detail);
            }
        }
        match result.residual_recovery.state {
            ResidualRecoveryState::Applied => {
                println!(
                    "  {} {}",
                    "Solver recovery".bright_black(),
                    result
                        .residual_recovery
                        .detail
                        .clone()
                        .unwrap_or_else(|| "applied".to_string())
                );
            }
            ResidualRecoveryState::NoMissedSlices => {
                println!(
                    "  {} no missed deny slices found",
                    "Solver recovery".bright_black(),
                );
            }
            ResidualRecoveryState::SolverUnavailable => {
                println!(
                    "  {} {}",
                    "Solver recovery".bright_black(),
                    result
                        .residual_recovery
                        .detail
                        .as_deref()
                        .unwrap_or("unavailable")
                );
            }
            ResidualRecoveryState::SolverError => {
                println!(
                    "  {} {}",
                    "Solver recovery".bright_black(),
                    result
                        .residual_recovery
                        .detail
                        .as_deref()
                        .unwrap_or("skipped after a solver error")
                );
            }
            ResidualRecoveryState::Disabled => {}
        }
        if result.refined_rules_applied > 0 {
            println!(
                "  {} {}",
                "Refined rules".bright_black(),
                result.refined_rules_applied
            );
        }
        if result.pinned_rules_applied > 0 {
            println!(
                "  {} {}",
                "Pinned rules".bright_black(),
                result.pinned_rules_applied
            );
        }
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", result.training_parity * 100.0).bold()
        );
        println!(
            "  {} {}",
            "Artifact bundle".bright_black(),
            result.output_files.artifact_dir
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            result.output_files.artifact_manifest
        );
        println!(
            "  {} {}",
            "Pearl IR".bright_black(),
            result.output_files.pearl_ir
        );
        println!(
            "  {} {}",
            "Build report".bright_black(),
            result.output_files.build_report
        );
        if let Some(feature_dictionary) =
            generated_feature_dictionary_for_output(&args, &artifact_dir)
        {
            println!(
                "  {} {}",
                "Feature dictionary".bright_black(),
                feature_dictionary.display()
            );
        }
        if let Some(native_binary) = &result.output_files.native_binary {
            println!("  {} {}", "Deployable".bright_black(), native_binary);
        }
        if let Some(wasm_module) = &result.output_files.wasm_module {
            println!("  {} {}", "Deployable".bright_black(), wasm_module);
            if let Some(wasm_metadata) = &result.output_files.wasm_metadata {
                println!("  {} {}", "Wasm metadata".bright_black(), wasm_metadata);
            }
        } else if args.compile {
            println!(
                "  {} {}",
                "Wasm module".bright_black(),
                "skipped (install wasm32-unknown-unknown to emit it)".bright_black()
            );
        } else {
            println!(
                "  {} {}",
                "Deployables".bright_black(),
                "not compiled by default; run `logicpearl compile <artifact>` when needed"
                    .bright_black()
            );
        }
    }
    Ok(())
}

fn run_action_build(mut args: BuildArgs) -> Result<()> {
    if args.enricher_plugin_manifest.is_some() {
        return Err(guidance(
            "action-column builds do not support enricher plugins yet",
            "Use a trace-source plugin or normalized trace file that already includes the action column.",
        ));
    }
    let action_column = args.action_column.clone().ok_or_else(|| {
        guidance(
            "action build is missing --action-column",
            "Pass --action-column <column> or set build.action_column in logicpearl.yaml.",
        )
    })?;
    let LoadedActionTraceRecords {
        loaded,
        source_name,
        default_output_base,
        default_artifact_name,
        trace_plugin: trace_plugin_provenance,
    } = load_action_trace_records(&args, &action_column)?;
    let input_traces = if let Some(path) = &args.decision_traces {
        vec![trace_input_provenance(path, loaded.records.len()).into_diagnostic()?]
    } else {
        Vec::new()
    };
    let action_traces = prepare_action_traces(&loaded, &action_column)
        .into_diagnostic()
        .wrap_err("failed to prepare action traces")?;
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| default_output_base.join("output"));
    fs::create_dir_all(&output_dir)
        .into_diagnostic()
        .wrap_err("failed to create action artifact directory")?;
    let artifact_name = args.gate_id.clone().unwrap_or(default_artifact_name);

    if should_generate_feature_dictionary(&args) {
        let dictionary_path = generated_feature_dictionary_path(&output_dir);
        write_feature_dictionary_from_columns(
            &dictionary_path,
            action_traces.feature_columns.clone(),
        )?;
        args.feature_dictionary = Some(dictionary_path);
    }
    let source_manifest_provenance =
        load_source_manifest_for_provenance(args.source_manifest.as_deref()).into_diagnostic()?;

    let stale_actions_dir = output_dir.join("actions");
    if stale_actions_dir.exists() {
        fs::remove_dir_all(&stale_actions_dir)
            .into_diagnostic()
            .wrap_err("failed to remove stale action route artifacts")?;
    }
    for stale_file in [
        "pearl.ir.json",
        "pearl.wasm",
        "pearl.wasm.meta.json",
        "action_policy.ir.json",
        "build_report.json",
        ".logicpearl-cache.json",
    ] {
        let path = output_dir.join(stale_file);
        if path.exists() {
            fs::remove_file(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove stale artifact file {stale_file}"))?;
        }
    }

    let learned_action = learn_action_policy(
        &action_traces,
        &ActionLearningOptions {
            artifact_name: artifact_name.clone(),
            action_column: action_column.clone(),
            default_action: args.default_action.clone(),
            action_priority: args.action_priority.clone(),
            action_max_rules: args.action_max_rules,
            output_dir: output_dir.clone(),
            refine: args.refine,
            pinned_rules: args.pinned_rules.clone(),
            feature_dictionary: args.feature_dictionary.clone(),
            feature_governance: args.feature_governance.clone(),
            decision_mode: to_discovery_decision_mode(args.discovery_mode),
        },
    )
    .into_diagnostic()
    .wrap_err("failed to learn action policy")?;
    let action_policy = learned_action.action_policy;
    let default_action = learned_action.default_action;
    let priority_order = learned_action.priority_order;
    let rule_budget = learned_action.rule_budget;
    let training_parity = learned_action.training_parity;
    let action_policy_path = output_dir.join("pearl.ir.json");
    action_policy
        .write_pretty(&action_policy_path)
        .into_diagnostic()
        .wrap_err("failed to write action policy IR")?;

    let build_options_value = serde_json::json!({
        "artifact_name": &artifact_name,
        "action_column": &action_column,
        "default_action": &default_action,
        "actions": &action_traces.actions,
        "action_priority": &args.action_priority,
        "priority_order": &priority_order,
        "action_max_rules": args.action_max_rules,
        "rule_budget": &rule_budget,
        "refine": args.refine,
        "pinned_rules": args
            .pinned_rules
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_dictionary": args
            .feature_dictionary
            .as_ref()
            .map(|path| path.display().to_string()),
        "source_manifest": args
            .source_manifest
            .as_ref()
            .map(|path| path.display().to_string()),
        "feature_governance": args
            .feature_governance
            .as_ref()
            .map(|path| path.display().to_string()),
        "decision_mode": to_discovery_decision_mode(args.discovery_mode),
    });
    let build_options_digest = build_options_hash(&build_options_value);

    let mut action_report = ActionBuildReport {
        source: source_name,
        artifact_name: artifact_name.clone(),
        action_column: action_column.clone(),
        default_action: default_action.clone(),
        rows: loaded.records.len(),
        actions: action_traces.actions.clone(),
        rule_budget: rule_budget.clone(),
        rules: action_rule_report(&action_policy),
        training_parity,
        provenance: Some(
            build_provenance(BuildProvenanceInputs {
                artifact_dir: Some(output_dir.clone()),
                source_references: parse_key_value_entries(&args.source_references, "source-ref")?,
                decision_traces_path: args.decision_traces.clone(),
                trace_plugin_manifest_path: args.trace_plugin_manifest.clone(),
                input_traces,
                trace_plugin: trace_plugin_provenance,
                enricher_plugin: None,
                feature_dictionary_path: args.feature_dictionary.clone(),
                source_manifest: source_manifest_provenance,
                build_options: build_options_value,
                build_options_hash: build_options_digest.clone(),
            })
            .into_diagnostic()?,
        ),
    };
    let action_report_path = output_dir.join("action_report.json");

    let mut native_binary_file = None;
    let mut wasm_module_file = None;
    let mut wasm_metadata_file = None;
    if args.compile {
        let native_binary_path = native_artifact_output_path(&output_dir, &artifact_name, None);
        let native_binary = compile_native_runner(
            &action_policy_path,
            &output_dir,
            &artifact_name,
            Some(artifact_name.clone()),
            None,
            Some(native_binary_path),
        )?;
        native_binary_file = native_binary
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());

        if is_rust_target_installed("wasm32-unknown-unknown") {
            let wasm_output = compile_wasm_module(
                &action_policy_path,
                &output_dir,
                &artifact_name,
                Some(artifact_name.clone()),
                Some(output_dir.join("pearl.wasm")),
            )?;
            wasm_module_file = wasm_output
                .module_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            wasm_metadata_file = wasm_output
                .metadata_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
        }
    }

    attach_generated_file_hashes(
        &mut action_report.provenance,
        &output_dir,
        [
            Some(action_policy_path.clone()),
            generated_feature_dictionary_for_output(&args, &output_dir).cloned(),
            native_binary_file
                .as_ref()
                .map(|file| output_dir.join(file)),
            wasm_module_file.as_ref().map(|file| output_dir.join(file)),
            wasm_metadata_file
                .as_ref()
                .map(|file| output_dir.join(file)),
        ]
        .into_iter()
        .flatten(),
    )
    .into_diagnostic()?;
    let public_action_report = action_build_report_for_report(&action_report);
    fs::write(
        &action_report_path,
        serde_json::to_string_pretty(&public_action_report).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write action report")?;

    let mut extensions = BTreeMap::new();
    extensions.insert(
        "action_column".to_string(),
        serde_json::json!(action_column),
    );
    extensions.insert(
        "default_action".to_string(),
        serde_json::json!(default_action),
    );
    extensions.insert(
        "actions".to_string(),
        serde_json::json!(action_traces.actions),
    );
    extensions.insert(
        "action_priority".to_string(),
        serde_json::json!(priority_order),
    );
    extensions.insert(
        "action_rule_budget".to_string(),
        serde_json::json!(rule_budget),
    );
    write_artifact_manifest_v1(
        &output_dir,
        ArtifactManifestWriteOptions {
            artifact_kind: ArtifactKind::Action,
            artifact_id: artifact_name.clone(),
            ir_path: action_policy_path.clone(),
            build_report_path: Some(action_report_path.clone()),
            feature_dictionary_path: generated_feature_dictionary_for_output(&args, &output_dir)
                .map(|path| path.as_path().to_path_buf()),
            native_path: native_binary_file
                .as_ref()
                .map(|file| output_dir.join(file)),
            wasm_path: wasm_module_file.as_ref().map(|file| output_dir.join(file)),
            wasm_metadata_path: wasm_metadata_file
                .as_ref()
                .map(|file| output_dir.join(file)),
            build_options_hash: Some(build_options_digest),
            bundle: build_deployable_bundle_descriptor(
                native_binary_file.clone(),
                wasm_module_file.clone(),
                wasm_metadata_file.clone(),
            ),
            extensions,
            file_extensions: BTreeMap::new(),
        },
    )
    .wrap_err("failed to write action artifact manifest")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&public_action_report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Built action artifact".bold().bright_green(),
            artifact_name.bold()
        );
        println!("  {} {}", "Rows".bright_black(), action_report.rows);
        println!(
            "  {} {}",
            "Actions".bright_black(),
            action_report.actions.join(", ")
        );
        println!(
            "  {} {}",
            "Default action".bright_black(),
            action_report.default_action
        );
        println!(
            "  {} {}",
            "Action priority".bright_black(),
            action_report.rule_budget.priority_order.join(", ")
        );
        println!(
            "  {} {} ({})",
            "Rule budget".bright_black(),
            action_report.rule_budget.total_budget,
            action_report.rule_budget.mode
        );
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", action_report.training_parity * 100.0).bold()
        );
        println!(
            "  {} {}",
            "Artifact bundle".bright_black(),
            output_dir.display()
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            output_dir.join("artifact.json").display()
        );
        println!(
            "  {} {}",
            "Pearl IR".bright_black(),
            action_policy_path.display()
        );
        if let Some(feature_dictionary) =
            generated_feature_dictionary_for_output(&args, &output_dir)
        {
            println!(
                "  {} {}",
                "Feature dictionary".bright_black(),
                feature_dictionary.display()
            );
        }
        if let Some(native_binary) = &native_binary_file {
            println!(
                "  {} {}",
                "Deployable".bright_black(),
                output_dir.join(native_binary).display()
            );
        }
        if let Some(wasm_module) = &wasm_module_file {
            println!(
                "  {} {}",
                "Deployable".bright_black(),
                output_dir.join(wasm_module).display()
            );
            if let Some(wasm_metadata) = &wasm_metadata_file {
                println!(
                    "  {} {}",
                    "Wasm metadata".bright_black(),
                    output_dir.join(wasm_metadata).display()
                );
            }
        } else if args.compile {
            println!(
                "  {} {}",
                "Wasm module".bright_black(),
                "skipped (install wasm32-unknown-unknown to emit it)".bright_black()
            );
        }
    }
    Ok(())
}

fn load_action_trace_records(
    args: &BuildArgs,
    action_column: &str,
) -> Result<LoadedActionTraceRecords> {
    if args.trace_plugin_manifest.is_none()
        && (!args.trace_plugin_options.is_empty() || args.trace_plugin_input.is_some())
    {
        return Err(guidance(
            "trace plugin input/options were provided without a trace plugin manifest",
            "Pass --trace-plugin-manifest before using --trace-plugin-input or --trace-plugin-option.",
        ));
    }

    match (&args.trace_plugin_manifest, &args.decision_traces) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            if manifest.stage != PluginStage::TraceSource {
                return Err(guidance(
                    format!(
                        "plugin manifest stage mismatch: expected trace_source, got {:?}",
                        manifest.stage
                    ),
                    "Use a trace_source-stage manifest with --trace-plugin-manifest.",
                ));
            }
            let mut options = build_trace_plugin_options(args)?;
            options
                .entry("action_column".to_string())
                .or_insert_with(|| action_column.to_string());
            let source = args.trace_plugin_input.clone().ok_or_else(|| {
                guidance(
                    "--trace-plugin-manifest was provided without --trace-plugin-input",
                    "Pass the raw source string or path with --trace-plugin-input when using a trace_source plugin.",
                )
            })?;
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::TraceSource,
                payload: logicpearl_plugin::build_canonical_payload(
                    &PluginStage::TraceSource,
                    Value::String(source.clone()),
                    Some(serde_json::to_value(&options).into_diagnostic()?),
                ),
            };
            let policy = plugin_execution_policy(&args.plugin_execution);
            let execution = run_plugin_with_policy_and_metadata(&manifest, &request, &policy)
                .into_diagnostic()
                .wrap_err("trace plugin execution failed")?;
            let provenance = plugin_provenance_from_execution(
                "trace_source",
                manifest_path,
                &manifest,
                &execution,
                Some(source_input_provenance(&source)),
                options.clone(),
            )
            .into_diagnostic()?;
            let loaded = action_records_from_plugin_response(&execution.response, action_column)?;
            let source_name = format!(
                "plugin:{}:{}",
                manifest.name,
                redacted_source_display(&source)
            );
            let default_artifact_name = default_action_artifact_name_from_plugin_input(&source);
            Ok(LoadedActionTraceRecords {
                loaded,
                source_name,
                default_output_base: PathBuf::from("."),
                default_artifact_name: if default_artifact_name.is_empty() {
                    "action_policy".to_string()
                } else {
                    default_artifact_name
                },
                trace_plugin: Some(provenance),
            })
        }
        (None, Some(traces)) => {
            let loaded = load_flat_records(traces)
                .into_diagnostic()
                .wrap_err("failed to load action traces")?;
            Ok(LoadedActionTraceRecords {
                loaded,
                source_name: traces.display().to_string(),
                default_output_base: traces
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
                default_artifact_name: default_gate_id_from_path(traces),
                trace_plugin: None,
            })
        }
        (Some(_), Some(_)) => Err(guidance(
            "action build received both a trace file and a trace plugin",
            "Use either the positional trace dataset input or --trace-plugin-manifest, not both.",
        )),
        (None, None) => Err(guidance(
            "action build is missing traces",
            "Pass a trace dataset path or use --trace-plugin-manifest with --trace-plugin-input.",
        )),
    }
}

fn default_action_artifact_name_from_plugin_input(source: &str) -> String {
    let path = Path::new(source);
    if path.exists() {
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            let name = sanitize_identifier(stem);
            if !name.is_empty() {
                return name;
            }
        }
    }
    let hash = sha256_prefixed(source.as_bytes());
    format!(
        "action_policy_{}",
        &hash["sha256:".len().."sha256:".len() + 12]
    )
}

fn redacted_source_display(source: &str) -> String {
    if Path::new(source).exists() {
        provenance_safe_path_string(source)
    } else {
        format!("<inline:{}>", sha256_prefixed(source.as_bytes()))
    }
}

fn action_records_from_plugin_response(
    response: &PluginResponse,
    action_column: &str,
) -> Result<LoadedFlatRecords> {
    let records_value = response
        .extra
        .get("records")
        .or_else(|| response.extra.get("decision_traces"))
        .cloned()
        .ok_or_else(|| {
            guidance(
                "trace plugin response is missing action records",
                "For action builds, return a top-level `records` array of flat trace rows, or `decision_traces` rows with features plus the action column.",
            )
        })?;
    let rows = records_value.as_array().ok_or_else(|| {
        guidance(
            "trace plugin action records must be an array",
            "Return `records: [...]` or `decision_traces: [...]` from the trace_source plugin.",
        )
    })?;

    let mut records = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        records.push(flatten_plugin_action_record(index + 1, row, action_column)?);
    }
    let field_names = action_record_field_names(&records)?;
    Ok(LoadedFlatRecords {
        field_names,
        records,
    })
}

fn flatten_plugin_action_record(
    row_number: usize,
    row: &Value,
    action_column: &str,
) -> Result<BTreeMap<String, Value>> {
    let object = row.as_object().ok_or_else(|| {
        guidance(
            format!("trace plugin action row {row_number} is not an object"),
            "Each action trace row must be a flat object, or an object with `features` plus the action column.",
        )
    })?;
    let mut out = BTreeMap::new();
    if let Some(features) = object.get("features") {
        let features = features.as_object().ok_or_else(|| {
            guidance(
                format!("trace plugin action row {row_number} has non-object features"),
                "`features` must be an object of scalar feature values.",
            )
        })?;
        for (key, value) in features {
            insert_plugin_scalar(&mut out, key, value, row_number)?;
        }
        let action = object
            .get(action_column)
            .or_else(|| object.get("action"))
            .ok_or_else(|| {
                guidance(
                    format!("trace plugin action row {row_number} is missing {action_column:?}"),
                    "Put the action label at the top level beside `features`, or return flat records.",
                )
            })?;
        insert_plugin_scalar(&mut out, action_column, action, row_number)?;
        return Ok(out);
    }

    for (key, value) in object {
        insert_plugin_scalar(&mut out, key, value, row_number)?;
    }
    Ok(out)
}

fn insert_plugin_scalar(
    out: &mut BTreeMap<String, Value>,
    key: &str,
    value: &Value,
    row_number: usize,
) -> Result<()> {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => Err(guidance(
            format!("trace plugin action row {row_number} has a non-scalar value for {key:?}"),
            "Action trace plugins must emit normalized scalar fields before discovery.",
        )),
        scalar => {
            out.insert(key.to_string(), scalar.clone());
            Ok(())
        }
    }
}

fn action_record_field_names(records: &[BTreeMap<String, Value>]) -> Result<Vec<String>> {
    let Some(first) = records.first() else {
        return Ok(Vec::new());
    };
    let field_names = first.keys().cloned().collect::<Vec<_>>();
    for (index, record) in records.iter().enumerate().skip(1) {
        let names = record.keys().cloned().collect::<Vec<_>>();
        if names != field_names {
            return Err(guidance(
                format!("trace plugin action row {} has a different schema", index + 1),
                "Action trace plugins must emit rectangular records with the same fields in every row.",
            ));
        }
    }
    Ok(field_names)
}

fn build_trace_plugin_options(args: &BuildArgs) -> Result<BTreeMap<String, String>> {
    let mut options = parse_key_value_entries(&args.trace_plugin_options, "trace-plugin-option")?;
    if let Some(label_column) = &args.label_column {
        options.insert("label_column".to_string(), label_column.clone());
    }
    Ok(options)
}

fn parse_key_value_entries(
    entries: &[String],
    flag_name: &str,
) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(guidance(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        };
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(guidance(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        }
        parsed.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(parsed)
}

pub(crate) fn run_eval(args: RunArgs) -> Result<()> {
    let (artifact, input_json) = resolve_run_arguments(&args)?;
    let bundle = load_artifact_bundle(&artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", artifact.display()))?;
    let pearl_ir = bundle.ir_path().into_diagnostic()?;
    if bundle.manifest.artifact_kind == ArtifactKind::Action {
        return run_action_eval(&pearl_ir, input_json.as_ref(), args.explain, args.json);
    }
    if bundle.manifest.artifact_kind == ArtifactKind::Pipeline {
        return Err(guidance(
            "run received a pipeline artifact",
            "Use `logicpearl pipeline run` for pipeline artifacts.",
        ));
    }
    let gate = LogicPearlGateIr::from_path(&pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let payload = read_json_input_argument(input_json.as_ref(), "input")?;

    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("runtime input shape is invalid")?;
    let mut outputs = Vec::with_capacity(parsed.len());
    for input in parsed {
        let bitmask = evaluate_gate(&gate, &input)
            .into_diagnostic()
            .wrap_err("failed to evaluate pearl")?;
        if args.explain || args.json {
            outputs
                .push(serde_json::to_value(explain_gate_output(&gate, bitmask)).into_diagnostic()?);
        } else {
            outputs.push(bitmask.to_json_value());
        }
    }
    if args.json {
        if outputs.len() == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs).into_diagnostic()?
            );
        }
    } else if args.explain {
        if outputs.len() == 1 {
            print_explained_gate_output(&outputs[0])?;
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs).into_diagnostic()?
            );
        }
    } else if outputs.len() == 1 {
        println!("{}", outputs[0]);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&outputs).into_diagnostic()?
        );
    }
    Ok(())
}

fn resolve_run_arguments(args: &RunArgs) -> Result<(PathBuf, Option<PathBuf>)> {
    let configured = configured_run_defaults()?;
    match (&args.pearl_ir, &args.input_json) {
        (Some(artifact), Some(input)) => Ok((artifact.clone(), Some(input.clone()))),
        (Some(first), None) => {
            if let Some((config_path, run)) = configured {
                if let Some(config_artifact) = run.artifact {
                    if !looks_like_artifact_path(first) {
                        return Ok((
                            resolve_config_path(&config_path, config_artifact),
                            Some(resolve_config_path(&config_path, first.clone())),
                        ));
                    }
                }
                let input = run
                    .example_input
                    .map(|path| resolve_config_path(&config_path, path));
                Ok((first.clone(), input))
            } else {
                Ok((first.clone(), None))
            }
        }
        (None, None) => {
            let Some((config_path, run)) = configured else {
                return Err(guidance(
                    "run is missing an artifact",
                    "Pass an artifact path, or set run.artifact in logicpearl.yaml.",
                ));
            };
            let artifact = run.artifact.ok_or_else(|| {
                guidance(
                    "run.artifact is missing in logicpearl.yaml",
                    "Set run.artifact to an artifact directory such as /tmp/garden-actions.",
                )
            })?;
            let input = run
                .example_input
                .map(|path| resolve_config_path(&config_path, path));
            Ok((resolve_config_path(&config_path, artifact), input))
        }
        (None, Some(_)) => unreachable!("clap cannot fill the second positional first"),
    }
}

fn looks_like_artifact_path(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("artifact.json").exists()
            || path.join("pearl.ir.json").exists()
            || path.join("pipeline.json").exists();
    }
    path.file_name().is_some_and(|name| {
        name == std::ffi::OsStr::new("artifact.json")
            || name == std::ffi::OsStr::new("pearl.ir.json")
            || name == std::ffi::OsStr::new("pipeline.json")
    })
}

fn run_action_eval(
    action_policy_path: &Path,
    input_json: Option<&PathBuf>,
    explain: bool,
    json: bool,
) -> Result<()> {
    let action_policy = LogicPearlActionIr::from_path(action_policy_path)
        .into_diagnostic()
        .wrap_err("could not load action policy IR")?;
    run_action_policy_eval(&action_policy, input_json, explain, json)
}

fn run_action_policy_eval(
    action_policy: &LogicPearlActionIr,
    input_json: Option<&PathBuf>,
    explain: bool,
    json: bool,
) -> Result<()> {
    let payload = read_json_input_argument(input_json, "input")?;
    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("runtime input shape is invalid")?;
    let mut outputs = Vec::with_capacity(parsed.len());
    for input in parsed {
        outputs.push(
            evaluate_action_policy(action_policy, &input)
                .into_diagnostic()
                .wrap_err("failed to evaluate action policy")?,
        );
    }

    if json {
        if outputs.len() == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs).into_diagnostic()?
            );
        }
        return Ok(());
    }

    if outputs.len() != 1 {
        println!(
            "{}",
            serde_json::to_string_pretty(&outputs).into_diagnostic()?
        );
        return Ok(());
    }

    let output = &outputs[0];
    if explain {
        println!("action: {}", output.action.bold());
        if output.selected_rules.is_empty() {
            println!("reason: no rule matched; using default action");
        } else {
            println!("reason:");
            for reason in &output.selected_rules {
                println!(
                    "  - {}",
                    reason
                        .label
                        .as_deref()
                        .or(reason.message.as_deref())
                        .unwrap_or(&reason.id)
                );
            }
        }
        if let Some(ambiguity) = &output.ambiguity {
            println!("note: {ambiguity}");
        }
    } else {
        println!("{}", output.action);
    }
    Ok(())
}

fn explain_gate_output(
    gate: &LogicPearlGateIr,
    bitmask: logicpearl_core::RuleMask,
) -> GateEvaluationResult {
    explain_gate_result(gate, bitmask)
}

fn print_explained_gate_output(value: &Value) -> Result<()> {
    let output: GateEvaluationResult = serde_json::from_value(value.clone())
        .into_diagnostic()
        .wrap_err("failed to render explained output")?;
    println!("bitmask: {}", output.bitmask);
    if output.matched_rules.is_empty() {
        println!("matched: none");
    } else {
        println!("matched:");
        for rule in output.matched_rules {
            println!(
                "  bit {}: {}",
                rule.bit,
                rule.label
                    .as_deref()
                    .or(rule.message.as_deref())
                    .unwrap_or(&rule.id)
            );
        }
    }
    Ok(())
}

pub(crate) fn run_inspect(args: InspectArgs) -> Result<()> {
    let artifact = resolve_inspect_artifact(args.pearl_ir.as_ref())?;
    let bundle = load_artifact_bundle(&artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", artifact.display()))?;
    let pearl_ir = bundle.ir_path().into_diagnostic()?;
    match bundle.manifest.artifact_kind {
        ArtifactKind::Action => return run_action_inspect(&bundle, args.json),
        ArtifactKind::Pipeline => {
            return Err(guidance(
                "inspect received a pipeline artifact",
                "Use `logicpearl pipeline inspect` for pipeline artifacts.",
            ));
        }
        ArtifactKind::Gate => {}
    }
    let gate = LogicPearlGateIr::from_path(&pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let descriptor = artifact_bundle_descriptor_from_manifest(&bundle.manifest)
        .wrap_err("could not load artifact bundle metadata")?;
    if args.json {
        let summary = serde_json::json!({
            "artifact_dir": bundle.base_dir,
            "pearl_ir": pearl_ir,
            "gate_id": gate.gate_id,
            "ir_version": gate.ir_version,
            "features": gate.input_schema.features.len(),
            "rules": gate.rules.len(),
            "feature_dictionary": inspect_feature_dictionary(&gate),
            "rule_details": inspect_rule_details(&gate),
            "correctness_scope": gate.verification.as_ref().and_then(|verification| verification.correctness_scope.clone()),
            "verification_summary": gate.verification.as_ref().and_then(|verification| verification.verification_summary.clone()),
            "bundle": descriptor,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        let inspector = TextInspector;
        println!("{}", "LogicPearl Artifact".bold().bright_blue());
        println!(
            "  {} {}",
            "Bundle".bright_black(),
            bundle.base_dir.display()
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            bundle.base_dir.join(&descriptor.cli_entrypoint).display()
        );
        if let Some(primary_runtime) = &descriptor.primary_runtime {
            println!("  {} {}", "Primary runtime".bright_black(), primary_runtime);
        }
        for deployable in &descriptor.deployables {
            println!(
                "  {} {}",
                "Deployable".bright_black(),
                bundle.base_dir.join(&deployable.path).display()
            );
        }
        for metadata_file in &descriptor.metadata_files {
            println!(
                "  {} {}",
                "Wasm metadata".bright_black(),
                bundle.base_dir.join(&metadata_file.path).display()
            );
        }
        println!();
        println!("{}", inspector.render(&gate).into_diagnostic()?);
    }
    Ok(())
}

fn resolve_inspect_artifact(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.clone());
    }
    let Some((config_path, config)) = load_project_config()? else {
        return Err(guidance(
            "inspect is missing an artifact",
            "Pass an artifact path, or set run.artifact or build.output_dir in logicpearl.yaml.",
        ));
    };
    if let Some(run) = config.run {
        if let Some(artifact) = run.artifact {
            return Ok(resolve_config_path(&config_path, artifact));
        }
    }
    if let Some(build) = config.build {
        if let Some(output_dir) = build.output_dir {
            return Ok(resolve_config_path(&config_path, output_dir));
        }
    }
    Err(guidance(
        "inspect could not find an artifact in logicpearl.yaml",
        "Set run.artifact or build.output_dir.",
    ))
}

fn run_action_inspect(bundle: &LoadedArtifactBundle, json: bool) -> Result<()> {
    let action_policy_path = bundle.ir_path().into_diagnostic()?;
    let action_policy = LogicPearlActionIr::from_path(&action_policy_path)
        .into_diagnostic()
        .wrap_err("could not load action policy IR")?;
    let report_path = bundle
        .manifest
        .files
        .build_report
        .as_deref()
        .map(|file| resolve_manifest_member_path(&bundle.base_dir, file))
        .transpose()?;
    let report: Option<Value> = if report_path.as_ref().is_some_and(|path| path.exists()) {
        let report_path = report_path.as_ref().expect("report path should exist");
        Some(
            serde_json::from_str(
                &fs::read_to_string(report_path)
                    .into_diagnostic()
                    .wrap_err("failed to read action report")?,
            )
            .into_diagnostic()
            .wrap_err("failed to parse action report")?,
        )
    } else {
        None
    };
    run_action_policy_inspect(
        &bundle.base_dir,
        "action",
        &bundle.manifest.artifact_id,
        &action_policy_path,
        &action_policy,
        report,
        json,
    )
}

fn run_action_policy_inspect(
    artifact_dir: &Path,
    artifact_kind: &str,
    artifact_name: &str,
    action_policy_path: &Path,
    action_policy: &LogicPearlActionIr,
    report: Option<Value>,
    json: bool,
) -> Result<()> {
    if json {
        let summary = serde_json::json!({
            "artifact_dir": artifact_dir,
            "artifact_kind": artifact_kind,
            "artifact_name": artifact_name,
            "action_policy_id": action_policy.action_policy_id,
            "ir_version": action_policy.ir_version,
            "action_column": action_policy.action_column,
            "default_action": action_policy.default_action,
            "actions": action_policy.actions,
            "features": action_policy.input_schema.features.len(),
            "action_report": report,
            "pearl_ir": action_policy_path,
            "rules": action_policy.rules.iter().map(|rule| {
                serde_json::json!({
                    "id": rule.id,
                    "bit": rule.bit,
                    "action": rule.action,
                    "priority": rule.priority,
                    "when": rule.predicate,
                    "label": rule.label,
                    "message": rule.message,
                    "counterfactual_hint": rule.counterfactual_hint,
                    "verification_status": rule.verification_status,
                })
            }).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
        return Ok(());
    }

    println!("{}", "LogicPearl Action Artifact".bold().bright_blue());
    println!("  {} {}", "Bundle".bright_black(), artifact_dir.display());
    println!(
        "  {} {}",
        "Action policy".bright_black(),
        action_policy.action_policy_id
    );
    println!(
        "  {} {}",
        "Action column".bright_black(),
        action_policy.action_column
    );
    println!(
        "  {} {}",
        "Default action".bright_black(),
        action_policy.default_action
    );
    println!("Action rules:");
    for (index, rule) in action_policy.rules.iter().enumerate() {
        println!("  {}. {}", index + 1, rule.action.bold());
        println!(
            "     {}",
            rule.label
                .as_deref()
                .or(rule.message.as_deref())
                .unwrap_or(&rule.id)
        );
    }
    if let Some(report) = report {
        if let Some(training_parity) = report.get("training_parity").and_then(Value::as_f64) {
            println!(
                "  {} {:.1}%",
                "Training parity".bright_black(),
                training_parity * 100.0
            );
        }
    }
    Ok(())
}

fn inspect_feature_dictionary(gate: &LogicPearlGateIr) -> Value {
    let features = gate
        .input_schema
        .features
        .iter()
        .filter_map(|feature| {
            let semantics = feature.semantics.as_ref()?;
            Some(serde_json::json!({
                "id": feature.id,
                "label": semantics.label,
                "kind": semantics.kind,
                "unit": semantics.unit,
                "higher_is_better": semantics.higher_is_better,
                "source_id": semantics.source_id,
                "source_anchor": semantics.source_anchor,
                "states": semantics.states,
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "features": features,
        "feature_count": features.len(),
    })
}

fn inspect_rule_details(gate: &LogicPearlGateIr) -> Vec<Value> {
    gate.rules
        .iter()
        .map(|rule| {
            let referenced_features = expression_feature_ids(&rule.deny_when)
                .into_iter()
                .filter_map(|feature_id| inspect_rule_feature(gate, &feature_id))
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": rule.id,
                "bit": rule.bit,
                "deny_when": rule.deny_when,
                "label": rule.label,
                "message": rule.message,
                "severity": rule.severity,
                "counterfactual_hint": rule.counterfactual_hint,
                "verification_status": rule.verification_status,
                "feature_dictionary": referenced_features,
            })
        })
        .collect()
}

fn inspect_rule_feature(gate: &LogicPearlGateIr, feature_id: &str) -> Option<Value> {
    let feature = gate
        .input_schema
        .features
        .iter()
        .find(|feature| feature.id == feature_id)?;
    let semantics = feature.semantics.as_ref()?;
    Some(serde_json::json!({
        "id": feature.id,
        "label": semantics.label,
        "source_id": semantics.source_id,
        "source_anchor": semantics.source_anchor,
    }))
}

fn expression_feature_ids(expression: &logicpearl_ir::Expression) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    collect_expression_feature_ids(expression, &mut features);
    features
}

fn collect_expression_feature_ids(
    expression: &logicpearl_ir::Expression,
    features: &mut BTreeSet<String>,
) {
    match expression {
        logicpearl_ir::Expression::Comparison(comparison) => {
            features.insert(comparison.feature.clone());
            if let logicpearl_ir::ComparisonValue::FeatureRef { feature_ref } = &comparison.value {
                features.insert(feature_ref.clone());
            }
        }
        logicpearl_ir::Expression::All { all } => {
            for child in all {
                collect_expression_feature_ids(child, features);
            }
        }
        logicpearl_ir::Expression::Any { any } => {
            for child in any {
                collect_expression_feature_ids(child, features);
            }
        }
        logicpearl_ir::Expression::Not { expr } => collect_expression_feature_ids(expr, features),
    }
}

pub(crate) fn run_verify(args: VerifyArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load verify plugin manifest")?;
    if manifest.stage != PluginStage::Verify {
        return Err(guidance(
            format!(
                "plugin manifest stage mismatch: expected verify, got {:?}",
                manifest.stage
            ),
            "Use a verify-stage manifest with `logicpearl verify`.",
        ));
    }
    let pearl_ir: Value = serde_json::from_str(
        &fs::read_to_string(&resolved.pearl_ir)
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
    let mut payload =
        logicpearl_plugin::build_canonical_payload(&PluginStage::Verify, pearl_ir, None);
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "fixtures".to_string(),
            fixtures.clone().unwrap_or(Value::Null),
        );
        object.insert("constraints".to_string(), Value::Array(Vec::new()));
    }
    let request = PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Verify,
        payload,
    };
    let policy = plugin_execution_policy(&args.plugin_execution);
    let response = run_plugin_with_policy(&manifest, &request, &policy)
        .into_diagnostic()
        .wrap_err("verify plugin execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Verify plugin".bold().bright_yellow(),
            manifest.name.bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    }
    Ok(())
}
