// SPDX-License-Identifier: MIT
use super::*;
use anstream::println;
use std::collections::BTreeMap;

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
        let response = run_plugin_with_policy(&manifest, request, &policy)
            .into_diagnostic()
            .wrap_err("plugin smoke execution failed")?;
        Some(build_plugin_smoke_report(&manifest, request, &response)?)
    } else {
        None
    };

    let summary = serde_json::json!({
        "manifest": {
            "path": args.manifest.display().to_string(),
            "name": manifest.name.clone(),
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
    let response = run_plugin_with_policy(&manifest, &request, &policy)
        .into_diagnostic()
        .wrap_err("plugin execution failed")?;
    let report = build_plugin_smoke_report(&manifest, &request, &response)?;

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
            guidance(
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
        return Err(guidance(
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
    response: &PluginResponse,
) -> Result<Value> {
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
            "stage": manifest.stage,
        },
        "canonical_contract": canonical_contract_for_stage(&manifest.stage),
        "declared_contract": logicpearl_plugin::manifest_contract_summary(manifest),
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
