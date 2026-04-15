// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_plugin::{run_plugin_with_policy, PluginManifest, PluginRequest, PluginStage};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde_json::Value;
use std::fs;

use super::{guidance, VerifyArgs};
use crate::{plugin_execution_policy, resolve_artifact_input};

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
