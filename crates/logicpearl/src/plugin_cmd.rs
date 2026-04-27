// SPDX-License-Identifier: MIT
use super::*;
use anstream::println;
use clap::{Args, Subcommand};
use std::collections::BTreeMap;

const PLUGIN_AFTER_HELP: &str = "\
Plugin trust:
  plugin run and plugin validate with a smoke input execute the manifest entrypoint as local code.
  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.

Examples:
  logicpearl plugin validate examples/plugins/python_observer/manifest.json
  logicpearl plugin run examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json --json
  logicpearl plugin run examples/plugins/python_trace_source/manifest.json --input-string examples/getting_started/decision_traces.csv --option label_column=allowed --json";

#[derive(Debug, Subcommand)]
#[command(after_help = PLUGIN_AFTER_HELP)]
pub(crate) enum PluginCommand {
    /// Check that a plugin manifest is valid. Optionally run a smoke request too.
    Validate(PluginValidateArgs),
    /// Run a plugin manifest against a JSON input or an explicit payload.
    Run(PluginRunArgs),
}

#[derive(Debug, Args)]
#[command(
    after_help = "Plugin trust:\n  plugin validate executes the manifest entrypoint when a smoke input is provided.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl plugin validate examples/plugins/python_observer/manifest.json\n  logicpearl plugin validate examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json --json"
)]
pub(crate) struct PluginValidateArgs {
    /// Plugin manifest to validate.
    #[arg(value_name = "MANIFEST")]
    pub manifest: PathBuf,
    /// Canonical stage input JSON. LogicPearl wraps this into the stage payload for you.
    #[arg(long, conflicts_with_all = ["input_string", "raw_payload"])]
    pub input: Option<PathBuf>,
    /// Input string for stages like trace_source.
    #[arg(long, conflicts_with_all = ["input", "raw_payload"])]
    pub input_string: Option<String>,
    /// Exact stage payload JSON to send without canonical wrapping.
    #[arg(long, conflicts_with_all = ["input", "input_string"])]
    pub raw_payload: Option<PathBuf>,
    /// Repeated key=value options to include in the canonical payload.
    #[arg(long = "option")]
    pub options: Vec<String>,
    #[command(flatten)]
    pub plugin_execution: PluginExecutionArgs,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Plugin trust:\n  plugin run executes the manifest entrypoint as local code.\n  Only relax timeout, absolute-entrypoint, or PATH lookup defaults for manifests you trust.\n\nExamples:\n  logicpearl plugin run examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json --json\n  logicpearl plugin run examples/plugins/python_trace_source/manifest.json --input-string examples/getting_started/decision_traces.csv --option label_column=allowed --json"
)]
pub(crate) struct PluginRunArgs {
    /// Plugin manifest to execute.
    #[arg(value_name = "MANIFEST")]
    pub manifest: PathBuf,
    /// Canonical stage input JSON. LogicPearl wraps this into the stage payload for you.
    #[arg(long, conflicts_with_all = ["input_string", "raw_payload"])]
    pub input: Option<PathBuf>,
    /// Input string for stages like trace_source.
    #[arg(long, conflicts_with_all = ["input", "raw_payload"])]
    pub input_string: Option<String>,
    /// Exact stage payload JSON to send without canonical wrapping.
    #[arg(long, conflicts_with_all = ["input", "input_string"])]
    pub raw_payload: Option<PathBuf>,
    /// Repeated key=value options to include in the canonical payload.
    #[arg(long = "option")]
    pub options: Vec<String>,
    #[command(flatten)]
    pub plugin_execution: PluginExecutionArgs,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn run_plugin_validate(args: PluginValidateArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.manifest)
        .into_diagnostic()
        .wrap_err("failed to load plugin manifest")?;
    let request = optional_plugin_request(
        &manifest,
        args.input.as_ref(),
        args.input_string.as_ref(),
        args.raw_payload.as_ref(),
        &args.options,
    )?;

    let smoke = if let Some(request) = &request {
        let policy = plugin_execution_policy(&args.plugin_execution);
        let execution = run_plugin_with_policy_and_metadata(&manifest, request, &policy)
            .into_diagnostic()
            .wrap_err("plugin smoke execution failed")?;
        Some(build_plugin_smoke_report(&manifest, request, &execution)?)
    } else {
        None
    };

    let summary = serde_json::json!({
        "manifest": {
            "path": args.manifest.display().to_string(),
            "name": manifest.name.clone(),
            "plugin_id": manifest.plugin_id.clone(),
            "plugin_version": manifest.plugin_version.clone(),
            "stage": manifest.stage.clone(),
            "language": manifest.language.clone(),
            "capabilities": manifest.capabilities.clone(),
            "timeout_ms": manifest.timeout_ms,
        },
        "canonical_contract": canonical_contract_for_stage(&manifest.stage),
        "declared_contract": logicpearl_plugin::manifest_contract_summary(&manifest),
        "smoke": smoke,
    });

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Valid".bold().bright_green(),
            args.manifest.display()
        );
        println!(
            "  {} {}",
            "Stage".bright_black(),
            stage_name(&manifest.stage)
        );
        println!(
            "  {} {}",
            "Canonical input".bright_black(),
            canonical_input_name(&manifest.stage)
        );
        if smoke.is_some() {
            println!("  {} {}", "Smoke run".bright_black(), "passed".bold());
        }
        println!(
            "  {} input={} options={} output={}",
            "Schema subset".bright_black(),
            schema_presence(&manifest.input_schema),
            schema_presence(&manifest.options_schema),
            schema_presence(&manifest.output_schema)
        );
    }
    Ok(())
}

pub(crate) fn run_plugin_run(args: PluginRunArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.manifest)
        .into_diagnostic()
        .wrap_err("failed to load plugin manifest")?;
    let request = required_plugin_request(
        &manifest,
        args.input.as_ref(),
        args.input_string.as_ref(),
        args.raw_payload.as_ref(),
        &args.options,
    )?;
    let policy = plugin_execution_policy(&args.plugin_execution);
    let execution = run_plugin_with_policy_and_metadata(&manifest, &request, &policy)
        .into_diagnostic()
        .wrap_err("plugin execution failed")?;
    let report = build_plugin_smoke_report(&manifest, &request, &execution)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Ran".bold().bright_green(),
            args.manifest.display()
        );
        println!(
            "  {} {}",
            "Stage".bright_black(),
            stage_name(&manifest.stage)
        );
        println!(
            "  {} {}",
            "Canonical input".bright_black(),
            canonical_input_name(&manifest.stage)
        );
        println!(
            "  {} {}",
            "Response keys".bright_black(),
            report["response_shape"]["top_level_keys"]
                .as_array()
                .map(|keys| {
                    keys.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        );
        println!(
            "  {} input={} options={} output={}",
            "Schema subset".bright_black(),
            schema_presence(&manifest.input_schema),
            schema_presence(&manifest.options_schema),
            schema_presence(&manifest.output_schema)
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&report["response"]).into_diagnostic()?
        );
    }
    Ok(())
}

fn required_plugin_request(
    manifest: &PluginManifest,
    input_path: Option<&PathBuf>,
    input_string: Option<&String>,
    payload_path: Option<&PathBuf>,
    options: &[String],
) -> Result<PluginRequest> {
    optional_plugin_request(manifest, input_path, input_string, payload_path, options)?.ok_or_else(
        || {
            CommandCoaching::simple(
                "plugin run is missing an input source",
                "Use --input input.json, --input-string STRING, or --raw-payload payload.json.",
            )
        },
    )
}

fn optional_plugin_request(
    manifest: &PluginManifest,
    input_path: Option<&PathBuf>,
    input_string: Option<&String>,
    payload_path: Option<&PathBuf>,
    options: &[String],
) -> Result<Option<PluginRequest>> {
    let provided = usize::from(input_path.is_some())
        + usize::from(input_string.is_some())
        + usize::from(payload_path.is_some());
    if provided == 0 {
        return Ok(None);
    }
    if provided > 1 {
        return Err(CommandCoaching::simple(
            "choose only one plugin input source",
            "Use one of --input, --input-string, or --raw-payload.",
        ));
    }

    let payload = if let Some(payload_path) = payload_path {
        read_json_value(payload_path)?
    } else {
        let input = if let Some(input_path) = input_path {
            read_json_value(input_path)?
        } else {
            Value::String(input_string.cloned().unwrap_or_default())
        };
        let options = parse_key_value_entries(options, "option")?;
        let options_value = if options.is_empty() {
            None
        } else {
            Some(
                serde_json::to_value(options)
                    .into_diagnostic()
                    .wrap_err("failed to encode plugin options")?,
            )
        };
        logicpearl_plugin::build_canonical_payload(&manifest.stage, input, options_value)
    };

    Ok(Some(PluginRequest {
        protocol_version: "1".to_string(),
        stage: manifest.stage.clone(),
        payload,
    }))
}

fn build_plugin_smoke_report(
    manifest: &PluginManifest,
    request: &PluginRequest,
    execution: &PluginExecutionResult,
) -> Result<Value> {
    let response = &execution.response;
    let expected_output = expected_output_key(&manifest.stage);
    let top_level_keys = response.extra.keys().cloned().collect::<Vec<_>>();
    let mut warnings = Vec::new();
    if let Some(key) = expected_output {
        if !response.extra.contains_key(key) {
            warnings.push(format!(
                "expected top-level `{key}` in {stage} plugin response",
                stage = stage_name(&manifest.stage)
            ));
        }
    }

    Ok(serde_json::json!({
        "manifest": {
            "name": manifest.name,
            "plugin_id": manifest.plugin_id,
            "plugin_version": manifest.plugin_version,
            "stage": manifest.stage,
        },
        "canonical_contract": canonical_contract_for_stage(&manifest.stage),
        "declared_contract": logicpearl_plugin::manifest_contract_summary(manifest),
        "plugin_run": execution.run,
        "request": request,
        "response": response,
        "response_shape": {
            "top_level_keys": top_level_keys,
            "expected_primary_key": expected_output,
        },
        "warnings": warnings,
    }))
}

fn schema_presence(schema: &Option<Value>) -> &'static str {
    if schema.is_some() {
        "declared"
    } else {
        "none"
    }
}

fn stage_name(stage: &PluginStage) -> &'static str {
    match stage {
        PluginStage::Observer => "observer",
        PluginStage::TraceSource => "trace_source",
        PluginStage::Enricher => "enricher",
        PluginStage::Verify => "verify",
        PluginStage::Render => "render",
    }
}

fn canonical_input_name(stage: &PluginStage) -> &'static str {
    match stage {
        PluginStage::Observer => "payload.input",
        PluginStage::TraceSource => "payload.input",
        PluginStage::Enricher => "payload.input",
        PluginStage::Verify => "payload.input",
        PluginStage::Render => "payload.input",
    }
}

fn expected_output_key(stage: &PluginStage) -> Option<&'static str> {
    match stage {
        PluginStage::Observer => Some("features"),
        PluginStage::TraceSource => Some("decision_traces"),
        PluginStage::Enricher => Some("records"),
        PluginStage::Verify => None,
        PluginStage::Render => None,
    }
}

fn canonical_contract_for_stage(stage: &PluginStage) -> Value {
    serde_json::json!({
        "canonical_input": canonical_input_name(stage),
        "expected_primary_output": expected_output_key(stage),
    })
}

fn read_json_value(path: &PathBuf) -> Result<Value> {
    serde_json::from_str(
        &fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read plugin input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("plugin input is not valid JSON")
}

fn parse_key_value_entries(
    entries: &[String],
    flag_name: &str,
) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(CommandCoaching::simple(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        };
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(CommandCoaching::simple(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        }
        parsed.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(parsed)
}
