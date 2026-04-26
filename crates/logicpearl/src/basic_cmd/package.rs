// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_core::{load_artifact_bundle, ArtifactKind};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use super::{guidance, PackageArgs};
use crate::{
    compile_native_fanout_runner, compile_native_runner, compile_wasm_fanout_module,
    compile_wasm_module, is_rust_target_installed, pearl_artifact_id,
    refresh_artifact_manifest_deployables, resolve_artifact_input, resolve_manifest_member_path,
    verify_artifact_bundle,
};

const PACKAGE_SCHEMA_VERSION: &str = "logicpearl.deploy_package.v1";

pub(crate) fn run_package(args: PackageArgs) -> Result<()> {
    let mode = PackageMode::from_args(&args)?;
    let resolved = resolve_artifact_input(&args.artifact)?;
    let artifact_id = pearl_artifact_id(&resolved.pearl_ir)?;
    let is_fanout = is_fanout_artifact(&resolved.pearl_ir)?;
    match mode {
        PackageMode::Browser => {
            if !is_rust_target_installed("wasm32-unknown-unknown") {
                return Err(guidance(
                    "browser packaging needs the wasm32-unknown-unknown Rust target",
                    "Install it with `rustup target add wasm32-unknown-unknown`, then rerun `logicpearl package --browser`.",
                ));
            }
            let output = if is_fanout {
                compile_wasm_fanout_module(
                    &resolved.pearl_ir,
                    &resolved.artifact_dir,
                    &artifact_id,
                    args.name.clone(),
                    None,
                )?
            } else {
                compile_wasm_module(
                    &resolved.pearl_ir,
                    &resolved.artifact_dir,
                    &artifact_id,
                    args.name.clone(),
                    None,
                )?
            };
            refresh_artifact_manifest_deployables(
                &resolved.artifact_dir,
                &resolved.pearl_ir,
                None,
                Some(&output.module_path),
                Some(&output.metadata_path),
            )?;
        }
        PackageMode::Native => {
            let output_path = if is_fanout {
                compile_native_fanout_runner(
                    &resolved.pearl_ir,
                    &resolved.artifact_dir,
                    &artifact_id,
                    args.name.clone(),
                    args.target.clone(),
                    None,
                )?
            } else {
                compile_native_runner(
                    &resolved.pearl_ir,
                    &resolved.artifact_dir,
                    &artifact_id,
                    args.name.clone(),
                    args.target.clone(),
                    None,
                )?
            };
            refresh_artifact_manifest_deployables(
                &resolved.artifact_dir,
                &resolved.pearl_ir,
                Some(&output_path),
                None,
                None,
            )?;
        }
    }

    let bundle = load_artifact_bundle(&resolved.artifact_dir)
        .into_diagnostic()
        .wrap_err("failed to reload compiled artifact bundle")?;
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| default_package_dir(&bundle.base_dir, mode));
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to clear package directory {}", output_dir.display())
            })?;
    }
    fs::create_dir_all(&output_dir)
        .into_diagnostic()
        .wrap_err("failed to create package directory")?;

    let manifest_path = bundle.base_dir.join("artifact.json");
    let manifest_value: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .into_diagnostic()
            .wrap_err("failed to read artifact manifest")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse artifact manifest")?;
    let package_manifest = package_artifact_manifest(mode, manifest_value);
    fs::write(
        output_dir.join("artifact.json"),
        serde_json::to_string_pretty(&package_manifest).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write packaged artifact manifest")?;
    let copied_files = copy_manifest_files(mode, &bundle.base_dir, &package_manifest, &output_dir)?;
    validate_package(mode, &output_dir, &package_manifest)?;
    verify_artifact_bundle(&output_dir)?;

    let deployable = primary_deployable(mode, &package_manifest)?;
    write_package_manifest(
        &PackageManifest {
            schema_version: PACKAGE_SCHEMA_VERSION.to_string(),
            package_kind: mode.package_kind().to_string(),
            artifact_id: bundle.manifest.artifact_id.clone(),
            artifact_kind: artifact_kind_name(bundle.manifest.artifact_kind).to_string(),
            artifact_manifest: "artifact.json".to_string(),
            primary_deployable: deployable.clone(),
            files: copied_files.clone(),
        },
        &output_dir,
    )?;
    write_package_readme(mode, &bundle.manifest.artifact_id, &deployable, &output_dir)?;

    let copied_bundle = load_artifact_bundle(&output_dir)
        .into_diagnostic()
        .wrap_err("packaged artifact bundle is not loadable")?;
    copied_bundle.ir_path().into_diagnostic()?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": PACKAGE_SCHEMA_VERSION,
                "package_kind": mode.package_kind(),
                "artifact_id": bundle.manifest.artifact_id,
                "output_dir": output_dir,
                "primary_deployable": deployable,
                "files": copied_files,
                "validated": true,
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Packaged".bold().bright_green(),
            output_dir.display()
        );
        println!("  {} {}", "Mode".bright_black(), mode.package_kind());
        println!(
            "  {} {}",
            "Artifact".bright_black(),
            bundle.manifest.artifact_id
        );
        println!("  {} {}", "Deploy".bright_black(), deployable);
        println!(
            "  {} {}",
            "Validate".bright_black(),
            format!(
                "logicpearl artifact verify {}",
                output_dir.join("artifact.json").display()
            )
        );
        if mode == PackageMode::Browser {
            println!(
                "  {} {}",
                "Serve".bright_black(),
                format!(
                    "python3 -m http.server --directory {} 8080",
                    output_dir.display()
                )
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageMode {
    Browser,
    Native,
}

impl PackageMode {
    fn from_args(args: &PackageArgs) -> Result<Self> {
        match (args.browser, args.native) {
            (true, false) => Ok(Self::Browser),
            (false, true) => Ok(Self::Native),
            _ => Err(guidance(
                "package needs a deploy target",
                "Pass exactly one of --browser or --native.",
            )),
        }
    }

    fn package_kind(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Native => "native",
        }
    }
}

#[derive(Debug, Serialize)]
struct PackageManifest {
    schema_version: String,
    package_kind: String,
    artifact_id: String,
    artifact_kind: String,
    artifact_manifest: String,
    primary_deployable: String,
    files: Vec<String>,
}

fn is_fanout_artifact(path: &Path) -> Result<bool> {
    let value: Value = serde_json::from_str(
        &fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read artifact IR")?,
    )
    .into_diagnostic()
    .wrap_err("artifact IR is not valid JSON")?;
    Ok(value
        .get("schema_version")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema == logicpearl_pipeline::FANOUT_PIPELINE_SCHEMA_VERSION))
}

fn copy_manifest_files(
    mode: PackageMode,
    base_dir: &Path,
    manifest: &Value,
    output_dir: &Path,
) -> Result<Vec<String>> {
    let files = manifest
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            guidance(
                "artifact manifest is missing files",
                "Rebuild the artifact first.",
            )
        })?;
    let mut copied = vec!["artifact.json".to_string()];
    for key in package_file_keys(mode) {
        let Some(relative) = files.get(*key).and_then(Value::as_str) else {
            continue;
        };
        if relative.is_empty() || copied.iter().any(|known| known == relative) {
            continue;
        }
        let source = resolve_manifest_member_path(base_dir, relative)?;
        let destination = output_dir.join(relative);
        copy_one(&source, &destination)?;
        copied.push(relative.to_string());
    }
    copied.sort();
    Ok(copied)
}

fn package_file_keys(mode: PackageMode) -> &'static [&'static str] {
    match mode {
        PackageMode::Browser => &[
            "ir",
            "build_report",
            "feature_dictionary",
            "wasm",
            "wasm_metadata",
        ],
        PackageMode::Native => &["ir", "build_report", "feature_dictionary", "native"],
    }
}

fn package_artifact_manifest(mode: PackageMode, mut manifest: Value) -> Value {
    if let Some(files) = manifest.get_mut("files").and_then(Value::as_object_mut) {
        match mode {
            PackageMode::Browser => {
                files.remove("native");
            }
            PackageMode::Native => {
                files.remove("wasm");
                files.remove("wasm_metadata");
            }
        }
    }
    if let Some(file_hashes) = manifest
        .get_mut("file_hashes")
        .and_then(Value::as_object_mut)
    {
        match mode {
            PackageMode::Browser => {
                file_hashes.remove("native");
            }
            PackageMode::Native => {
                file_hashes.remove("wasm");
                file_hashes.remove("wasm_metadata");
            }
        }
    }
    manifest
}

fn copy_one(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create package member directory")?;
    }
    fs::copy(source, destination)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to copy package member {} to {}",
                source.display(),
                destination.display()
            )
        })?;
    Ok(())
}

fn validate_package(mode: PackageMode, output_dir: &Path, manifest: &Value) -> Result<()> {
    let files = manifest
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            guidance(
                "artifact manifest is missing files",
                "Rebuild the artifact first.",
            )
        })?;
    let required = match mode {
        PackageMode::Browser => ["ir", "wasm", "wasm_metadata"].as_slice(),
        PackageMode::Native => ["ir", "native"].as_slice(),
    };
    for key in required {
        let relative = files.get(*key).and_then(Value::as_str).ok_or_else(|| {
            guidance(
                format!("package is missing files.{key}"),
                "Compile the requested deployable or rerun `logicpearl package`.",
            )
        })?;
        let path = output_dir.join(relative);
        if !path.exists() {
            return Err(guidance(
                format!("package is missing {}", path.display()),
                "The package directory is incomplete; rerun `logicpearl package`.",
            ));
        }
    }
    Ok(())
}

fn primary_deployable(mode: PackageMode, manifest: &Value) -> Result<String> {
    let files = manifest
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            guidance(
                "artifact manifest is missing files",
                "Rebuild the artifact first.",
            )
        })?;
    let key = match mode {
        PackageMode::Browser => "wasm",
        PackageMode::Native => "native",
    };
    files
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            guidance(
                format!("package is missing files.{key}"),
                "Compile the requested deployable or rerun `logicpearl package`.",
            )
        })
}

fn write_package_manifest(manifest: &PackageManifest, output_dir: &Path) -> Result<()> {
    fs::write(
        output_dir.join("logicpearl.package.json"),
        serde_json::to_string_pretty(manifest).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write package manifest")
}

fn write_package_readme(
    mode: PackageMode,
    artifact_id: &str,
    deployable: &str,
    output_dir: &Path,
) -> Result<()> {
    let body = match mode {
        PackageMode::Browser => format!(
            "# LogicPearl Browser Package\n\nArtifact: `{artifact_id}`\n\nServe this directory as static files:\n\n```bash\npython3 -m http.server --directory . 8080\n```\n\nLoad `artifact.json` with `@logicpearl/browser` from your app. The primary Wasm deployable is `{deployable}`.\n"
        ),
        PackageMode::Native => format!(
            "# LogicPearl Native Package\n\nArtifact: `{artifact_id}`\n\nRun the packaged binary:\n\n```bash\n./{deployable} input.json\n```\n\nThe artifact manifest is included for audit, diff, and verification.\n"
        ),
    };
    fs::write(output_dir.join("README.md"), body)
        .into_diagnostic()
        .wrap_err("failed to write package README")
}

fn default_package_dir(artifact_dir: &Path, mode: PackageMode) -> PathBuf {
    artifact_dir.join("package").join(mode.package_kind())
}

fn artifact_kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Gate => "gate",
        ArtifactKind::Action => "action",
        ArtifactKind::Pipeline => "pipeline",
    }
}
