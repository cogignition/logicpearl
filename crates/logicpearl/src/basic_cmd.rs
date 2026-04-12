use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

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
    #[serde(default)]
    raw_feature_ids: bool,
    feature_dictionary: Option<PathBuf>,
    feature_governance: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct LogicPearlRunConfig {
    artifact: Option<PathBuf>,
    example_input: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct ActionArtifactManifest {
    artifact_version: String,
    artifact_kind: String,
    artifact_name: String,
    action_column: String,
    default_action: String,
    actions: Vec<String>,
    files: ActionArtifactFiles,
    #[serde(default)]
    bundle: ArtifactBundleDescriptor,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct ActionArtifactFiles {
    pearl_ir: String,
    action_report: String,
    #[serde(default)]
    native_binary: Option<String>,
    #[serde(default)]
    wasm_module: Option<String>,
    #[serde(default)]
    wasm_metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ActionBuildReport {
    source: String,
    artifact_name: String,
    action_column: String,
    default_action: String,
    rows: usize,
    actions: Vec<String>,
    rules: Vec<ActionRuleBuildReport>,
    training_parity: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ActionRuleBuildReport {
    id: String,
    bit: u32,
    action: String,
    priority: u32,
    label: Option<String>,
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

fn generated_feature_dictionary_path(output_dir: &Path) -> PathBuf {
    output_dir.join("feature_dictionary.generated.json")
}

fn should_generate_feature_dictionary(args: &BuildArgs) -> bool {
    !args.raw_feature_ids && args.feature_dictionary.is_none()
}

fn generated_feature_dictionary_for_output<'a>(
    args: &'a BuildArgs,
    output_dir: &Path,
) -> Option<&'a PathBuf> {
    let generated = generated_feature_dictionary_path(output_dir);
    args.feature_dictionary
        .as_ref()
        .filter(|path| **path == generated)
}

fn feature_columns_from_decision_rows(rows: &[DecisionTraceRow]) -> Vec<String> {
    rows.first()
        .map(|row| row.features.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
}

fn write_feature_dictionary_from_columns(path: &Path, columns: Vec<String>) -> Result<()> {
    let dictionary = starter_feature_dictionary_from_columns(columns);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create feature dictionary output directory")?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(&dictionary).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write generated feature dictionary")?;
    Ok(())
}

fn starter_feature_dictionary_from_columns(columns: Vec<String>) -> FeatureDictionaryConfig {
    let mut features = BTreeMap::new();
    for column in columns {
        features.insert(column.clone(), starter_feature_semantics(&column));
    }
    FeatureDictionaryConfig {
        feature_dictionary_version: "1.0".to_string(),
        features,
    }
}

fn starter_feature_semantics(feature_id: &str) -> logicpearl_ir::FeatureSemantics {
    let lower = feature_id.to_ascii_lowercase();
    logicpearl_ir::FeatureSemantics {
        label: Some(humanize_feature_id(feature_id)),
        kind: infer_feature_kind(&lower).map(str::to_string),
        unit: infer_feature_unit(&lower).map(str::to_string),
        higher_is_better: infer_higher_is_better(&lower),
        source_id: None,
        source_anchor: None,
        states: BTreeMap::new(),
    }
}

fn humanize_feature_id(feature_id: &str) -> String {
    let mut normalized = feature_id.to_ascii_lowercase();
    for suffix in [
        "_pct", "_percent", "_gallons", "_gallon", "_count", "_score",
    ] {
        if let Some(stem) = normalized.strip_suffix(suffix) {
            normalized = stem.to_string();
            break;
        }
    }
    normalized = normalized.replace("_cm_last_", "_last_");

    if let Some(rest) = normalized.strip_prefix("days_since_") {
        return format!("Days since {}", lower_phrase_words(rest));
    }
    if let Some((subject, window)) = normalized.split_once("_last_") {
        if let Some(days) = window.strip_suffix("_days") {
            let subject = if subject == "water" {
                "Water used".to_string()
            } else {
                title_case_words(subject)
            };
            return format!("{subject} in the last {days} days");
        }
    }

    title_case_words(&normalized)
}

fn title_case_words(value: &str) -> String {
    let words = value
        .replace(['_', '-', '.'], " ")
        .split_whitespace()
        .map(|word| match word {
            "pct" => "percent".to_string(),
            "cm" => "cm".to_string(),
            "id" => "ID".to_string(),
            "url" => "URL".to_string(),
            "api" => "API".to_string(),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_uppercase().collect::<String>()
                            + &chars.as_str().to_ascii_lowercase()
                    }
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>();
    words.join(" ")
}

fn lower_phrase_words(value: &str) -> String {
    value
        .replace(['_', '-', '.'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn infer_feature_kind(lower_feature_id: &str) -> Option<&'static str> {
    if lower_feature_id.ends_with("_score") || lower_feature_id.contains("_score_") {
        Some("score")
    } else if lower_feature_id.ends_with("_count") || lower_feature_id.contains("_count_") {
        Some("count")
    } else if lower_feature_id.ends_with("_pct") || lower_feature_id.contains("_pct_") {
        Some("measurement")
    } else if lower_feature_id.starts_with("has_")
        || lower_feature_id.starts_with("is_")
        || lower_feature_id.starts_with("contains_")
    {
        Some("flag")
    } else {
        None
    }
}

fn infer_feature_unit(lower_feature_id: &str) -> Option<&'static str> {
    if lower_feature_id.ends_with("_pct") || lower_feature_id.contains("_pct_") {
        Some("percent")
    } else if lower_feature_id.contains("gallon") {
        Some("gallons")
    } else if lower_feature_id.starts_with("days_") || lower_feature_id.contains("_days_") {
        Some("days")
    } else if lower_feature_id.ends_with("_cm") || lower_feature_id.contains("_cm_") {
        Some("cm")
    } else {
        None
    }
}

fn infer_higher_is_better(lower_feature_id: &str) -> Option<bool> {
    if lower_feature_id.contains("risk")
        || lower_feature_id.contains("pale")
        || lower_feature_id.contains("crowd")
        || lower_feature_id.contains("crack")
        || lower_feature_id.contains("error")
        || lower_feature_id.contains("fail")
    {
        Some(false)
    } else if lower_feature_id.contains("score")
        || lower_feature_id.contains("confidence")
        || lower_feature_id.contains("growth")
    {
        Some(true)
    } else {
        None
    }
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
    if !args.raw_feature_ids {
        args.raw_feature_ids = build.raw_feature_ids;
    }
    if args.feature_dictionary.is_none() {
        args.feature_dictionary = build
            .feature_dictionary
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
            println!("{}", "LogicPearl Quickstart".bold().bright_blue());
            println!(
                "  {}",
                "Choose the shortest path for what you want to prove first:".bright_black()
            );
            println!(
                "  {} {}",
                "Traces".bold(),
                "generate clean synthetic traces from declarative policy".bright_black()
            );
            println!("    logicpearl quickstart traces");
            println!(
                "  {} {}",
                "Build".bold(),
                "learn one pearl from labeled traces".bright_black()
            );
            println!("    logicpearl quickstart build");
            println!(
                "  {} {}",
                "Pipeline".bold(),
                "run a string-of-pearls artifact".bright_black()
            );
            println!("    logicpearl quickstart pipeline");
            println!(
                "  {} {}",
                "Benchmark".bold(),
                "score a guardrail benchmark slice".bright_black()
            );
            println!("    logicpearl quickstart benchmark");
        }
        Some(QuickstartTopic::Traces) => {
            println!("{}", "Quickstart: Traces".bold().bright_green());
            println!(
                "  {}",
                "Generate synthetic traces with nuisance fields balanced by construction:"
                    .bright_black()
            );
            println!(
                "  logicpearl traces generate examples/getting_started/synthetic_access_policy.tracegen.json --output /tmp/synthetic_traces.jsonl"
            );
            println!("  {}", "Audit the generated traces:".bright_black());
            println!(
                "  logicpearl traces audit /tmp/synthetic_traces.jsonl --spec examples/getting_started/synthetic_access_policy.tracegen.json"
            );
            println!("  {}", "Then build a pearl from them:".bright_black());
            println!(
                "  logicpearl build /tmp/synthetic_traces.jsonl --output-dir /tmp/synthetic_access_policy"
            );
        }
        Some(QuickstartTopic::Build) => {
            println!("{}", "Quickstart: Build".bold().bright_green());
            println!("  {}", "Build your first pearl:".bright_black());
            println!(
                "  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output"
            );
            println!("  {}", "Then inspect and run it:".bright_black());
            println!("  logicpearl inspect examples/getting_started/output");
            println!("  logicpearl run examples/getting_started/output examples/getting_started/new_input.json");
        }
        Some(QuickstartTopic::Pipeline) => {
            println!("{}", "Quickstart: Pipeline".bold().bright_green());
            println!(
                "  {}",
                "Run a public string-of-pearls example:".bright_black()
            );
            println!(
                "  logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
            );
            println!(
                "  {}",
                "Trace the full stage-by-stage execution:".bright_black()
            );
            println!(
                "  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
            );
        }
        Some(QuickstartTopic::Benchmark) => {
            println!("{}", "Quickstart: Benchmark".bold().bright_green());
            println!(
                "  {}",
                "Run the checked-in guardrail benchmark slice:".bright_black()
            );
            println!(
                "  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json"
            );
            println!("  {}", "Inspect the benchmark pipeline:".bright_black());
            println!(
                "  logicpearl pipeline inspect benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json"
            );
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
            let response = run_plugin_with_policy(&manifest, &request, &plugin_policy)
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

    let build_provenance = build_build_provenance(&args, &resolved_label_column)?;

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
    };

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
        let response = run_plugin_with_policy(&manifest, &request, &plugin_policy)
            .into_diagnostic()
            .wrap_err("enricher plugin execution failed")?;
        let records_value = response.extra.get("records").cloned().ok_or_else(|| {
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

    let mut result = build_pearl_from_rows(&rows, source_name, &build_options)
        .into_diagnostic()
        .wrap_err("failed to build pearl from decision traces")?;
    result.provenance = build_provenance;

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
    persist_build_report(&result)?;
    write_named_artifact_manifest(
        &artifact_dir,
        &artifact_name,
        &result.gate_id,
        &result.output_files,
    )?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).into_diagnostic()?
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
    let (loaded, source_name, default_output_base, default_artifact_name) =
        load_action_trace_records(&args, &action_column)?;
    if !loaded.field_names.iter().any(|name| name == &action_column) {
        return Err(guidance(
            format!("action trace input is missing action column {action_column:?}"),
            "Use --action-column with the column that contains labels such as water, fertilize, repot, or do_nothing.",
        ));
    }
    let feature_columns = loaded
        .field_names
        .iter()
        .filter(|name| *name != &action_column)
        .cloned()
        .collect::<Vec<_>>();
    if feature_columns.is_empty() {
        return Err(guidance(
            "action traces have no feature columns",
            "Keep normalized input features beside the action column.",
        ));
    }

    let mut actions = Vec::<String>::new();
    let mut action_by_row = Vec::<String>::new();
    let mut features_by_row = Vec::<HashMap<String, Value>>::new();
    for (index, record) in loaded.records.iter().enumerate() {
        let raw_action = record.get(&action_column).ok_or_else(|| {
            guidance(
                format!(
                    "row {} is missing action column {action_column:?}",
                    index + 1
                ),
                "Every action trace row needs a next action.",
            )
        })?;
        let action = action_value_to_string(raw_action)?;
        if action.is_empty() {
            return Err(guidance(
                format!("row {} has an empty action", index + 1),
                "Use a concrete action label such as water, fertilize, repot, or do_nothing.",
            ));
        }
        if !actions.iter().any(|known| known == &action) {
            actions.push(action.clone());
        }
        let mut features = HashMap::new();
        for feature in &feature_columns {
            let value = record.get(feature).ok_or_else(|| {
                guidance(
                    format!("row {} is missing feature {feature:?}", index + 1),
                    "Action traces must be rectangular.",
                )
            })?;
            features.insert(feature.clone(), value.clone());
        }
        action_by_row.push(action);
        features_by_row.push(features);
    }
    if actions.len() < 2 {
        return Err(guidance(
            "action traces need at least two distinct actions",
            "Use a binary gate build for a one-action yes/no decision, or add more reviewed action examples.",
        ));
    }

    let default_action = resolve_default_action(args.default_action.as_deref(), &actions)?;
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
        write_feature_dictionary_from_columns(&dictionary_path, feature_columns.clone())?;
        args.feature_dictionary = Some(dictionary_path);
    }

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

    let mut input_schema = None;
    let mut action_rules = Vec::new();
    for action in actions.iter().filter(|action| *action != &default_action) {
        let route_rows = action_by_row
            .iter()
            .zip(features_by_row.iter())
            .map(|(row_action, features)| DecisionTraceRow {
                features: features.clone(),
                allowed: row_action != action,
            })
            .collect::<Vec<_>>();
        let route_name = sanitize_identifier(action);
        let route_gate_id = format!("{}_{}", artifact_name, route_name);
        let learned = learn_gate_from_rows_without_numeric_interactions(
            &route_rows,
            &BuildOptions {
                output_dir: output_dir.clone(),
                gate_id: route_gate_id.clone(),
                label_column: action_column.clone(),
                positive_label: None,
                negative_label: Some(action.clone()),
                residual_pass: true,
                refine: args.refine,
                pinned_rules: args.pinned_rules.clone(),
                feature_dictionary: args.feature_dictionary.clone(),
                feature_governance: args.feature_governance.clone(),
                decision_mode: to_discovery_decision_mode(args.discovery_mode),
            },
        )
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to learn action rules for {action:?}"))?;
        if input_schema.is_none() {
            input_schema = Some(learned.gate.input_schema.clone());
        }
        for rule in learned.gate.rules {
            let bit = u32::try_from(action_rules.len()).into_diagnostic()?;
            action_rules.push(ActionRuleDefinition {
                id: format!("rule_{bit:03}"),
                bit,
                action: action.clone(),
                priority: bit,
                predicate: rule.deny_when,
                label: rule.label,
                message: rule.message,
                severity: rule.severity,
                counterfactual_hint: rule.counterfactual_hint,
                verification_status: rule.verification_status,
            });
        }
    }

    let input_schema = input_schema.ok_or_else(|| {
        guidance(
            "action build did not produce any non-default action rules",
            "Add reviewed examples for at least one non-default action.",
        )
    })?;
    let action_policy = LogicPearlActionIr {
        ir_version: "1.0".to_string(),
        action_policy_id: artifact_name.clone(),
        action_policy_type: "priority_rules".to_string(),
        action_column: action_column.clone(),
        default_action: default_action.clone(),
        actions: actions.clone(),
        input_schema,
        rules: action_rules,
        evaluation: ActionEvaluationConfig {
            selection: ActionSelectionStrategy::FirstMatch,
        },
        verification: Some(logicpearl_ir::VerificationConfig {
            domain_constraints: None,
            correctness_scope: Some(format!(
                "training parity against {} action traces",
                loaded.records.len()
            )),
            verification_summary: None,
        }),
        provenance: None,
    };
    action_policy.validate().into_diagnostic()?;
    let training_parity =
        compute_action_training_parity(&action_policy, &features_by_row, &action_by_row)?;
    let action_policy_path = output_dir.join("pearl.ir.json");
    action_policy
        .write_pretty(&action_policy_path)
        .into_diagnostic()
        .wrap_err("failed to write action policy IR")?;

    let action_report = ActionBuildReport {
        source: source_name,
        artifact_name: artifact_name.clone(),
        action_column: action_column.clone(),
        default_action: default_action.clone(),
        rows: loaded.records.len(),
        actions: actions.clone(),
        rules: action_policy
            .rules
            .iter()
            .map(|rule| ActionRuleBuildReport {
                id: rule.id.clone(),
                bit: rule.bit,
                action: rule.action.clone(),
                priority: rule.priority,
                label: rule.label.clone(),
            })
            .collect(),
        training_parity,
    };
    let action_report_path = output_dir.join("action_report.json");
    fs::write(
        &action_report_path,
        serde_json::to_string_pretty(&action_report).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write action report")?;

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

    let manifest = ActionArtifactManifest {
        artifact_version: "1.0".to_string(),
        artifact_kind: "action_policy".to_string(),
        artifact_name: artifact_name.clone(),
        action_column,
        default_action,
        actions,
        files: ActionArtifactFiles {
            pearl_ir: "pearl.ir.json".to_string(),
            action_report: "action_report.json".to_string(),
            native_binary: native_binary_file.clone(),
            wasm_module: wasm_module_file.clone(),
            wasm_metadata: wasm_metadata_file.clone(),
        },
        bundle: build_deployable_bundle_descriptor(
            native_binary_file.clone(),
            wasm_module_file.clone(),
            wasm_metadata_file.clone(),
        ),
    };
    fs::write(
        output_dir.join("artifact.json"),
        serde_json::to_string_pretty(&manifest).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write action artifact manifest")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&action_report).into_diagnostic()?
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
) -> Result<(LoadedFlatRecords, String, PathBuf, String)> {
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
            let response = run_plugin_with_policy(&manifest, &request, &policy)
                .into_diagnostic()
                .wrap_err("trace plugin execution failed")?;
            let loaded = action_records_from_plugin_response(&response, action_column)?;
            let source_name = format!("plugin:{}:{source}", manifest.name);
            let default_artifact_name = default_action_artifact_name_from_plugin_input(&source);
            Ok((
                loaded,
                source_name,
                PathBuf::from("."),
                if default_artifact_name.is_empty() {
                    "action_policy".to_string()
                } else {
                    default_artifact_name
                },
            ))
        }
        (None, Some(traces)) => {
            let loaded = load_flat_records(traces)
                .into_diagnostic()
                .wrap_err("failed to load action traces")?;
            Ok((
                loaded,
                traces.display().to_string(),
                traces
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
                default_gate_id_from_path(traces),
            ))
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
    sanitize_identifier(source)
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

fn action_value_to_string(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.trim().to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        other => Err(guidance(
            format!("action labels must be scalar, got {other}"),
            "Use string action labels such as water, fertilize, repot, or do_nothing.",
        )),
    }
}

fn resolve_default_action(explicit: Option<&str>, actions: &[String]) -> Result<String> {
    if let Some(action) = explicit {
        if actions.iter().any(|known| known == action) {
            return Ok(action.to_string());
        }
        return Err(guidance(
            format!("--default-action {action:?} was not found in action traces"),
            format!("Available actions: {}", actions.join(", ")),
        ));
    }
    for preferred in ["do_nothing", "nothing", "wait", "none", "noop"] {
        if let Some(action) = actions.iter().find(|action| action.as_str() == preferred) {
            return Ok(action.clone());
        }
    }
    Ok(actions[0].clone())
}

fn compute_action_training_parity(
    policy: &LogicPearlActionIr,
    features_by_row: &[HashMap<String, Value>],
    action_by_row: &[String],
) -> Result<f64> {
    let mut correct = 0;
    for (features, expected_action) in features_by_row.iter().zip(action_by_row) {
        let selected = evaluate_action_policy(policy, features)
            .into_diagnostic()
            .wrap_err("failed to evaluate action policy during training parity check")?
            .action;
        if &selected == expected_action {
            correct += 1;
        }
    }
    Ok(correct as f64 / action_by_row.len() as f64)
}

fn build_build_provenance(
    args: &BuildArgs,
    resolved_label_column: &str,
) -> Result<Option<BuildProvenance>> {
    let source_references = parse_key_value_entries(&args.source_references, "source-ref")?;
    let decision_trace_source = if let Some(path) = &args.decision_traces {
        Some(BuildInputProvenance {
            kind: "decision_traces_path".to_string(),
            value: path.display().to_string(),
        })
    } else {
        args.trace_plugin_manifest
            .as_ref()
            .map(|manifest| BuildInputProvenance {
                kind: "trace_plugin".to_string(),
                value: manifest.display().to_string(),
            })
    };

    let trace_plugin = if let Some(manifest_path) = &args.trace_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to reload trace plugin manifest for build provenance")?;
        let input = args
            .trace_plugin_input
            .as_ref()
            .map(|value| BuildInputProvenance {
                kind: classify_source_value(value).to_string(),
                value: value.clone(),
            });
        let mut options = build_trace_plugin_options(args)?;
        options
            .entry("label_column".to_string())
            .or_insert_with(|| resolved_label_column.to_string());
        Some(PluginBuildProvenance {
            name: manifest.name,
            stage: "trace_source".to_string(),
            manifest_path: manifest_path.display().to_string(),
            manifest_sha256: Some(sha256_file(manifest_path)?),
            input,
            options,
        })
    } else {
        None
    };

    let enricher_plugin = if let Some(manifest_path) = &args.enricher_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to reload enricher plugin manifest for build provenance")?;
        Some(PluginBuildProvenance {
            name: manifest.name,
            stage: "enricher".to_string(),
            manifest_path: manifest_path.display().to_string(),
            manifest_sha256: Some(sha256_file(manifest_path)?),
            input: None,
            options: BTreeMap::new(),
        })
    } else {
        None
    };

    if decision_trace_source.is_none()
        && trace_plugin.is_none()
        && enricher_plugin.is_none()
        && source_references.is_empty()
    {
        return Ok(None);
    }

    Ok(Some(BuildProvenance {
        decision_trace_source,
        trace_plugin,
        enricher_plugin,
        source_references,
    }))
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

fn classify_source_value(value: &str) -> &'static str {
    if std::path::Path::new(value).exists() {
        "path"
    } else {
        "inline"
    }
}

fn sha256_file(path: &PathBuf) -> Result<String> {
    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err("failed to read file for sha256")?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn run_eval(args: RunArgs) -> Result<()> {
    let (artifact, input_json) = resolve_run_arguments(&args)?;
    if let Some((manifest_dir, manifest)) = load_action_artifact_manifest(&artifact)? {
        return run_action_eval(
            &manifest_dir,
            &manifest,
            input_json.as_ref(),
            args.explain,
            args.json,
        );
    }
    let resolved = resolve_artifact_input(&artifact)?;
    if let Some(action_policy) = load_direct_action_policy(&resolved.pearl_ir)? {
        return run_action_policy_eval(
            &action_policy,
            input_json.as_ref(),
            args.explain,
            args.json,
        );
    }
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
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
        return path.join("artifact.json").exists() || path.join("pearl.ir.json").exists();
    }
    path.file_name().is_some_and(|name| {
        name == std::ffi::OsStr::new("artifact.json")
            || name == std::ffi::OsStr::new("pearl.ir.json")
            || name == std::ffi::OsStr::new("artifact_set.json")
    })
}

fn load_action_artifact_manifest(
    artifact: &Path,
) -> Result<Option<(PathBuf, ActionArtifactManifest)>> {
    let manifest_path = if artifact.is_dir() {
        artifact.join("artifact.json")
    } else if artifact
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        artifact.to_path_buf()
    } else {
        return Ok(None);
    };
    if !manifest_path.exists() {
        return Ok(None);
    }
    let payload = fs::read_to_string(&manifest_path)
        .into_diagnostic()
        .wrap_err("failed to read artifact manifest")?;
    let value: Value = serde_json::from_str(&payload)
        .into_diagnostic()
        .wrap_err("failed to parse artifact manifest")?;
    match value.get("artifact_kind").and_then(Value::as_str) {
        Some("action_policy") => {}
        Some("action_router") => {
            return Err(guidance(
                "action artifact uses the older route layout",
                "Run `logicpearl build` again to emit a single action policy artifact.",
            ));
        }
        _ => return Ok(None),
    }
    let manifest = serde_json::from_value(value)
        .into_diagnostic()
        .wrap_err("failed to parse action artifact manifest")?;
    Ok(Some((
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        manifest,
    )))
}

fn run_action_eval(
    manifest_dir: &Path,
    manifest: &ActionArtifactManifest,
    input_json: Option<&PathBuf>,
    explain: bool,
    json: bool,
) -> Result<()> {
    let action_policy = LogicPearlActionIr::from_path(manifest_dir.join(&manifest.files.pearl_ir))
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

fn load_direct_action_policy(pearl_ir: &Path) -> Result<Option<LogicPearlActionIr>> {
    let payload = fs::read_to_string(pearl_ir)
        .into_diagnostic()
        .wrap_err("could not read pearl IR")?;
    let value: Value = serde_json::from_str(&payload)
        .into_diagnostic()
        .wrap_err("pearl IR is not valid JSON")?;
    if value.get("action_policy_id").is_none() {
        return Ok(None);
    }
    LogicPearlActionIr::from_json_str(&payload)
        .into_diagnostic()
        .map(Some)
        .wrap_err("could not load action policy IR")
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
    if let Some((manifest_dir, manifest)) = load_action_artifact_manifest(&artifact)? {
        return run_action_inspect(&manifest_dir, &manifest, args.json);
    }
    let resolved = resolve_artifact_input(&artifact)?;
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let bundle = load_artifact_bundle_descriptor(&resolved.artifact_dir)
        .wrap_err("could not load artifact bundle metadata")?;
    if args.json {
        let summary = serde_json::json!({
            "artifact_dir": resolved.artifact_dir,
            "pearl_ir": resolved.pearl_ir,
            "gate_id": gate.gate_id,
            "ir_version": gate.ir_version,
            "features": gate.input_schema.features.len(),
            "rules": gate.rules.len(),
            "feature_dictionary": inspect_feature_dictionary(&gate),
            "rule_details": inspect_rule_details(&gate),
            "correctness_scope": gate.verification.as_ref().and_then(|verification| verification.correctness_scope.clone()),
            "verification_summary": gate.verification.as_ref().and_then(|verification| verification.verification_summary.clone()),
            "bundle": bundle,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        let inspector = TextInspector;
        println!("{}", "LogicPearl Artifact".bold().bright_blue());
        if let Some(bundle) = bundle {
            println!(
                "  {} {}",
                "Bundle".bright_black(),
                resolved.artifact_dir.display()
            );
            println!(
                "  {} {}",
                "CLI entrypoint".bright_black(),
                resolved.artifact_dir.join(&bundle.cli_entrypoint).display()
            );
            if let Some(primary_runtime) = &bundle.primary_runtime {
                println!("  {} {}", "Primary runtime".bright_black(), primary_runtime);
            }
            for deployable in &bundle.deployables {
                println!(
                    "  {} {}",
                    "Deployable".bright_black(),
                    resolved.artifact_dir.join(&deployable.path).display()
                );
            }
            for metadata_file in &bundle.metadata_files {
                println!(
                    "  {} {}",
                    "Wasm metadata".bright_black(),
                    resolved.artifact_dir.join(&metadata_file.path).display()
                );
            }
            println!();
        }
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

fn run_action_inspect(
    manifest_dir: &Path,
    manifest: &ActionArtifactManifest,
    json: bool,
) -> Result<()> {
    let action_policy_path = manifest_dir.join(&manifest.files.pearl_ir);
    let action_policy = LogicPearlActionIr::from_path(&action_policy_path)
        .into_diagnostic()
        .wrap_err("could not load action policy IR")?;
    let report_path = manifest_dir.join(&manifest.files.action_report);
    let report: Option<Value> = if report_path.exists() {
        Some(
            serde_json::from_str(
                &fs::read_to_string(&report_path)
                    .into_diagnostic()
                    .wrap_err("failed to read action report")?,
            )
            .into_diagnostic()
            .wrap_err("failed to parse action report")?,
        )
    } else {
        None
    };
    if json {
        let summary = serde_json::json!({
            "artifact_dir": manifest_dir,
            "artifact_kind": manifest.artifact_kind,
            "artifact_name": manifest.artifact_name,
            "action_column": manifest.action_column,
            "default_action": manifest.default_action,
            "actions": manifest.actions,
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
    println!("  {} {}", "Bundle".bright_black(), manifest_dir.display());
    println!(
        "  {} {}",
        "Action column".bright_black(),
        manifest.action_column
    );
    println!(
        "  {} {}",
        "Default action".bright_black(),
        manifest.default_action
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
