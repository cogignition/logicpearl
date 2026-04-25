// SPDX-License-Identifier: MIT
use super::*;
use clap::Args;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use logicpearl_discovery::FeatureColumnSelection;
use logicpearl_discovery::ProgressEvent;
use logicpearl_discovery::ProposalPolicy;
use logicpearl_discovery::SelectionPolicy;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

mod action_build;
mod build;
mod compile;
mod compose;
mod config;
mod conflicts;
mod discover;
mod fanout_build;
mod feature_dictionary;
mod inspect;
mod quickstart;
mod run;
mod verify;

use action_build::run_action_build;
pub(crate) use build::run_build;
pub(crate) use compile::run_compile;
pub(crate) use compose::run_compose;
pub(crate) use discover::run_discover;
use fanout_build::run_fanout_build;
use feature_dictionary::{
    feature_columns_from_decision_rows, generated_feature_dictionary_for_output,
    generated_feature_dictionary_path, should_generate_feature_dictionary,
    write_feature_dictionary_from_columns,
};
pub(crate) use inspect::run_inspect;
pub(crate) use quickstart::run_quickstart;
pub(crate) use run::run_eval;
pub(crate) use verify::run_verify;

const QUICKSTART_AFTER_HELP: &str = "\
Examples:
  logicpearl quickstart
  logicpearl quickstart traces
  logicpearl quickstart garden
  logicpearl quickstart build
  logicpearl quickstart pipeline
  logicpearl quickstart benchmark";

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum QuickstartTopic {
    Traces,
    Garden,
    Build,
    Pipeline,
    Benchmark,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProposalPolicyArg {
    AutoAdoptSafe,
    ReportOnly,
}

impl From<ProposalPolicyArg> for ProposalPolicy {
    fn from(value: ProposalPolicyArg) -> Self {
        match value {
            ProposalPolicyArg::AutoAdoptSafe => ProposalPolicy::AutoAdoptSafe,
            ProposalPolicyArg::ReportOnly => ProposalPolicy::ReportOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum DiscoveryDecisionModeArg {
    Standard,
    Review,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActionSelectionArg {
    FirstMatch,
    WeightedVote,
}

impl From<ActionSelectionArg> for logicpearl_ir::ActionSelectionStrategy {
    fn from(value: ActionSelectionArg) -> Self {
        match value {
            ActionSelectionArg::FirstMatch => logicpearl_ir::ActionSelectionStrategy::FirstMatch,
            ActionSelectionArg::WeightedVote => {
                logicpearl_ir::ActionSelectionStrategy::WeightedVote
            }
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectionPolicyArg {
    Balanced,
    RecallBiased,
}

pub(crate) fn to_discovery_decision_mode(arg: DiscoveryDecisionModeArg) -> DiscoveryDecisionMode {
    match arg {
        DiscoveryDecisionModeArg::Standard => DiscoveryDecisionMode::Standard,
        DiscoveryDecisionModeArg::Review => DiscoveryDecisionMode::Review,
    }
}

pub(crate) fn selection_policy_from_args(
    policy: Option<SelectionPolicyArg>,
    deny_recall_target: Option<f64>,
    max_false_positive_rate: Option<f64>,
) -> Result<SelectionPolicy, String> {
    match policy.unwrap_or(SelectionPolicyArg::Balanced) {
        SelectionPolicyArg::Balanced => {
            if deny_recall_target.is_some() || max_false_positive_rate.is_some() {
                return Err(
                    "use --selection-policy recall-biased when setting recall/false-positive targets"
                        .to_string(),
                );
            }
            Ok(SelectionPolicy::Balanced)
        }
        SelectionPolicyArg::RecallBiased => {
            let deny_recall_target = deny_recall_target.ok_or_else(|| {
                "--selection-policy recall-biased requires --deny-recall-target".to_string()
            })?;
            let max_false_positive_rate = max_false_positive_rate.ok_or_else(|| {
                "--selection-policy recall-biased requires --max-false-positive-rate".to_string()
            })?;
            SelectionPolicy::RecallBiased {
                deny_recall_target,
                max_false_positive_rate,
            }
            .validate()
            .map_err(|err| err.to_string())
        }
    }
}

pub(super) fn progress_enabled(_json: bool, progress: bool) -> bool {
    progress
}

pub(super) enum CliProgress {
    Spinner(ProgressBar),
    Lines,
}

pub(super) fn start_progress(
    enabled: bool,
    initial_message: impl Into<String>,
) -> Option<CliProgress> {
    if !enabled {
        return None;
    }
    let initial_message = initial_message.into();
    if std::io::stderr().is_terminal() {
        let sp = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
        sp.set_style(ProgressStyle::with_template("{spinner:.green} {msg} ({elapsed})").unwrap());
        sp.enable_steady_tick(std::time::Duration::from_millis(80));
        sp.set_message(initial_message);
        sp.tick();
        Some(CliProgress::Spinner(sp))
    } else {
        eprintln!("{initial_message}");
        Some(CliProgress::Lines)
    }
}

pub(super) fn progress_callback(
    progress: Option<&CliProgress>,
) -> Option<Box<dyn Fn(ProgressEvent) + Send + Sync>> {
    progress.map(|progress| match progress {
        CliProgress::Spinner(sp) => {
            let sp = sp.clone();
            Box::new(move |event: ProgressEvent| {
                sp.set_message(event.message);
                sp.tick();
            }) as Box<dyn Fn(ProgressEvent) + Send + Sync>
        }
        CliProgress::Lines => Box::new(move |event: ProgressEvent| {
            eprintln!("{}", event.message);
        }) as Box<dyn Fn(ProgressEvent) + Send + Sync>,
    })
}

pub(super) fn set_progress_message(progress: Option<&CliProgress>, message: impl Into<String>) {
    let Some(progress) = progress else {
        return;
    };
    let message = message.into();
    match progress {
        CliProgress::Spinner(sp) => {
            sp.set_message(message);
            sp.tick();
        }
        CliProgress::Lines => eprintln!("{message}"),
    }
}

pub(super) fn finish_progress(progress: Option<CliProgress>) {
    if let Some(CliProgress::Spinner(sp)) = progress {
        sp.finish_and_clear();
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
    after_help = "Plugin trust:\n  --trace-plugin-manifest and --enricher-plugin-manifest execute local programs declared by plugin manifests.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output --json\n  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output --compile\n  logicpearl build --trace-plugin-manifest examples/plugins/python_trace_source/manifest.json --trace-plugin-input examples/getting_started/decision_traces.csv --trace-plugin-option label_column=allowed --output-dir /tmp/output\n  logicpearl build examples/demos/loan_approval/traces.jsonl --output-dir /tmp/output\n  logicpearl build examples/demos/content_moderation/traces_nested.json --output-dir /tmp/output --refine\n  logicpearl build traces.json --feature-dictionary feature_dictionary.json --source-manifest sources.json --output-dir /tmp/output\n  logicpearl build traces.csv --feature-columns age,is_member --output-dir /tmp/output\n  logicpearl build traces.csv --exclude-columns source,note --output-dir /tmp/output\n  logicpearl build traces.csv --show-conflicts --output-dir /tmp/output\n  logicpearl build traces.csv --action-column next_action --no-match-action insufficient_context --output-dir /tmp/actions\n  logicpearl build traces.json --pinned-rules rules.json --output-dir /tmp/output\n  logicpearl build traces.csv --selection-policy recall-biased --deny-recall-target 0.70 --max-false-positive-rate 0.05 --output-dir /tmp/output\n  logicpearl build traces.csv --json --progress --output-dir /tmp/output"
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
    /// Column containing a multi-label list of applicable actions. Builds one applicability gate per action and packages them as a fan-out pipeline.
    #[arg(long, conflicts_with = "action_column")]
    pub fanout_column: Option<String>,
    /// Comma-separated actions to build fan-out gates for. Defaults to actions observed in --fanout-column.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "ACTIONS",
        requires = "fanout_column"
    )]
    pub fanout_actions: Vec<String>,
    /// Comma-separated allow-list of input columns to learn as features.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "COLUMNS",
        help_heading = "Advanced Discovery"
    )]
    pub feature_columns: Vec<String>,
    /// Comma-separated input columns to keep in traces but exclude from learned features.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "COLUMNS",
        conflicts_with = "feature_columns",
        help_heading = "Advanced Discovery"
    )]
    pub exclude_columns: Vec<String>,
    /// Default/pass value for binary gate builds. Rules fire for the other value unless --rule-label is set.
    #[arg(long, help_heading = "Advanced")]
    pub default_label: Option<String>,
    /// Rule/fire value for binary gate builds.
    #[arg(long, help_heading = "Advanced")]
    pub rule_label: Option<String>,
    /// Business default action. Also used when no action route matches unless --no-match-action is set.
    #[arg(long, help_heading = "Advanced")]
    pub default_action: Option<String>,
    /// Action returned when no learned action rule matches. Defaults to --default-action.
    #[arg(long, help_heading = "Advanced")]
    pub no_match_action: Option<String>,
    /// Maximum total rules emitted across non-default action routes. If omitted, LogicPearl scales per-action budgets from trace support.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub action_max_rules: Option<usize>,
    /// Maximum rules emitted for a binary gate build. Useful for budgeted discovery and proposal-phase diagnostics.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub max_rules: Option<usize>,
    /// Maximum atoms per discovered boolean conjunction (default 3). Raising to 4 or 5 lets rules express deeper feature interactions at the cost of a larger Z3 search per synthesis call.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub max_conditions: Option<usize>,
    /// How the runtime evaluator chooses among matched action rules. `first-match` (the default) returns the priority-earliest rule's action; `weighted-vote` tallies matched rules by training support so a single outlier rule can't dominate when multiple rules agree on a different action.
    #[arg(long, value_enum, help_heading = "Advanced Discovery")]
    pub action_selection: Option<ActionSelectionArg>,
    /// Proposal acceptance policy. Defaults to auto-adopt-safe for binary gate builds.
    #[arg(long, value_enum, help_heading = "Advanced Discovery")]
    pub proposal_policy: Option<ProposalPolicyArg>,
    /// Rule selection policy. `recall-biased` requires --deny-recall-target and --max-false-positive-rate.
    #[arg(long, value_enum, help_heading = "Advanced Discovery")]
    pub selection_policy: Option<SelectionPolicyArg>,
    /// Minimum denied-example recall target for `recall-biased` selection.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub deny_recall_target: Option<f64>,
    /// Maximum allowed-example false-positive rate for `recall-biased` selection.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub max_false_positive_rate: Option<f64>,
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
    /// Write a diagnostic report for trace rows not reproduced by the learned artifact.
    #[arg(long, help_heading = "Diagnostics")]
    pub show_conflicts: bool,
    /// Path for --show-conflicts output. Defaults to conflict_report.json in the output directory.
    #[arg(long, value_name = "PATH", help_heading = "Diagnostics")]
    pub conflict_report: Option<PathBuf>,
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
    /// Emit phase progress to stderr. Useful with --json because stdout remains machine-readable.
    #[arg(long)]
    pub progress: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  logicpearl discover traces.csv --targets target_a,target_b --output-dir discovered\n  logicpearl discover traces.jsonl --targets target_a,target_b --residual-pass --refine\n  logicpearl discover traces.json --targets target_a --feature-dictionary feature_dictionary.json --output-dir discovered\n  logicpearl discover traces.csv --targets target_a,target_b --exclude-columns source,note --output-dir discovered\n  logicpearl discover traces.json --targets target_a --pinned-rules rules.json --output-dir discovered\n  logicpearl discover traces.csv --targets target_a --selection-policy recall-biased --deny-recall-target 0.70 --max-false-positive-rate 0.05 --output-dir discovered\n  logicpearl discover traces.csv --targets target_a,target_b --json --progress"
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
    /// Comma-separated allow-list of input columns to learn as features.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "COLUMNS",
        help_heading = "Advanced Discovery"
    )]
    pub feature_columns: Vec<String>,
    /// Comma-separated input columns to keep in traces but exclude from learned features.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "COLUMNS",
        conflicts_with = "feature_columns",
        help_heading = "Advanced Discovery"
    )]
    pub exclude_columns: Vec<String>,
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
    /// Rule selection policy. `recall-biased` requires --deny-recall-target and --max-false-positive-rate.
    #[arg(long, value_enum, help_heading = "Advanced Discovery")]
    pub selection_policy: Option<SelectionPolicyArg>,
    /// Minimum denied-example recall target for `recall-biased` selection.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub deny_recall_target: Option<f64>,
    /// Maximum allowed-example false-positive rate for `recall-biased` selection.
    #[arg(long, help_heading = "Advanced Discovery")]
    pub max_false_positive_rate: Option<f64>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
    /// Emit phase progress to stderr. Useful with --json because stdout remains machine-readable.
    #[arg(long)]
    pub progress: bool,
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
    after_help = "Examples:\n  logicpearl compose --pipeline-id starter_authz --input-map examples/pipelines/input-map.json --output examples/pipelines/generated/starter_authz.pipeline.json fixtures/ir/valid/auth-demo-v1.json\n  logicpearl compose --pipeline-id starter_authz --scaffold --output examples/pipelines/generated/starter_authz.pipeline.json fixtures/ir/valid/auth-demo-v1.json"
)]
pub(crate) struct ComposeArgs {
    /// Stable pipeline identifier for the emitted pipeline artifact.
    #[arg(long)]
    pub pipeline_id: String,
    /// Output path for the generated pipeline.json.
    #[arg(long)]
    pub output: PathBuf,
    /// JSON/YAML map from pearl feature ids to root input paths or literal values.
    #[arg(long, conflicts_with = "scaffold")]
    pub input_map: Option<PathBuf>,
    /// Emit a draft scaffold with $.TODO_* placeholders instead of a runnable pipeline.
    #[arg(long)]
    pub scaffold: bool,
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
    after_help = "Examples:\n  logicpearl inspect examples/getting_started/output --json\n  logicpearl inspect examples/getting_started/output --show-provenance\n  logicpearl inspect examples/getting_started/output/pearl.ir.json --json"
)]
pub(crate) struct InspectArgs {
    /// Pearl artifact directory, artifact manifest, or pearl.ir.json file.
    #[arg(value_name = "ARTIFACT")]
    pub pearl_ir: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
    /// Include rule evidence such as trace row hashes and source refs.
    #[arg(long)]
    pub show_provenance: bool,
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

fn build_trace_plugin_options(args: &BuildArgs) -> Result<BTreeMap<String, String>> {
    let mut options = parse_key_value_entries(&args.trace_plugin_options, "trace-plugin-option")?;
    if let Some(label_column) = &args.label_column {
        options.insert("label_column".to_string(), label_column.clone());
    }
    Ok(options)
}

fn feature_column_selection(
    feature_columns: &[String],
    exclude_columns: &[String],
) -> Result<FeatureColumnSelection> {
    if !feature_columns.is_empty() && !exclude_columns.is_empty() {
        return Err(guidance(
            "feature column selection received both an allow-list and an exclude-list",
            "Use either --feature-columns or --exclude-columns, not both.",
        ));
    }
    Ok(FeatureColumnSelection {
        feature_columns: (!feature_columns.is_empty()).then(|| feature_columns.to_vec()),
        exclude_columns: exclude_columns.to_vec(),
    })
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
