// SPDX-License-Identifier: MIT
use anstream::println;
use miette::Result;
use owo_colors::OwoColorize;

use super::CompileArgs;
use crate::{
    compile_native_fanout_runner, compile_native_runner, compile_wasm_fanout_module,
    compile_wasm_module, pearl_artifact_id, refresh_artifact_manifest_deployables,
    resolve_artifact_input,
};

pub(crate) fn run_compile(args: CompileArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let artifact_id = pearl_artifact_id(&resolved.pearl_ir)?;
    let artifact_value: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&resolved.pearl_ir)
            .map_err(|err| miette::miette!("failed to read artifact IR: {err}"))?,
    )
    .map_err(|err| miette::miette!("artifact IR is not valid JSON: {err}"))?;
    let is_fanout = artifact_value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|schema| schema == logicpearl_pipeline::FANOUT_PIPELINE_SCHEMA_VERSION);
    if args.target.as_deref() == Some("wasm32-unknown-unknown") {
        let output = if is_fanout {
            compile_wasm_fanout_module(
                &resolved.pearl_ir,
                &resolved.artifact_dir,
                &artifact_id,
                args.name,
                args.output,
            )?
        } else {
            compile_wasm_module(
                &resolved.pearl_ir,
                &resolved.artifact_dir,
                &artifact_id,
                args.name,
                args.output,
            )?
        };
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
    } else if is_fanout {
        let output_path = compile_native_fanout_runner(
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
