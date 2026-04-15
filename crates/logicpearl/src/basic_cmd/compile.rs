// SPDX-License-Identifier: MIT
use anstream::println;
use miette::Result;
use owo_colors::OwoColorize;

use super::CompileArgs;
use crate::{
    compile_native_runner, compile_wasm_module, pearl_artifact_id,
    refresh_artifact_manifest_deployables, resolve_artifact_input,
};

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
