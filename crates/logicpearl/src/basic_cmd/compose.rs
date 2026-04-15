// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_core::ArtifactKind;
use logicpearl_pipeline::compose_pipeline;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{guidance, ComposeArgs};
use crate::{
    build_options_hash, write_artifact_manifest_v1, ArtifactBundleDescriptor,
    ArtifactManifestWriteOptions,
};

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
