// SPDX-License-Identifier: MIT
use clap::{Args, Subcommand};
use logicpearl_benchmark::sanitize_identifier;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod manifest;
mod native_compile;
mod pearl;
mod verify;
mod wasm_compile;
mod wasm_metadata;

#[cfg(test)]
use manifest::relative_manifest_file;
pub(crate) use manifest::{
    artifact_bundle_descriptor_from_manifest, build_deployable_bundle_descriptor,
    build_options_hash, native_artifact_output_path, pearl_artifact_id, persist_build_report,
    refresh_artifact_manifest_deployables, resolve_artifact_input, resolve_manifest_member_path,
    wasm_artifact_output_path, write_artifact_manifest_v1, write_named_artifact_manifest,
    ArtifactBundleDescriptor, ArtifactDeployable, ArtifactManifestWriteOptions, ArtifactSidecar,
    ResolvedArtifactInput,
};
use manifest::{hash_file_canonical_if_json, read_json_file};
#[cfg(test)]
use native_compile::parse_embedded_native_payload;
pub(crate) use native_compile::{
    compile_native_fanout_runner, compile_native_runner, run_embedded_native_runner_if_present,
};
use pearl::CompilablePearl;
pub(crate) use verify::{run_artifact_digest, run_artifact_inspect, run_artifact_verify};
pub(crate) use wasm_compile::{
    compile_wasm_fanout_module, compile_wasm_module, is_rust_target_installed,
};
#[cfg(test)]
use wasm_compile::{generate_wasm_fanout_runner_source, generate_wasm_runner_source};
#[cfg(test)]
use wasm_metadata::{
    write_wasm_metadata, write_wasm_metadata_for_fanout, write_wasm_metadata_for_pearl,
    FanoutWasmGateMetadata,
};

const ARTIFACT_AFTER_HELP: &str = "\
Examples:
  logicpearl artifact inspect output/artifact.json --json
  logicpearl artifact digest output
  logicpearl artifact verify output/artifact.json";

#[derive(Debug, Subcommand)]
#[command(after_help = ARTIFACT_AFTER_HELP)]
pub(crate) enum ArtifactCommand {
    /// Inspect the normalized artifact manifest.
    Inspect(ArtifactInspectArgs),
    /// Print the artifact and bundle digests.
    Digest(ArtifactDigestArgs),
    /// Validate the manifest, hashes, and referenced files.
    Verify(ArtifactVerifyArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactInspectArgs {
    /// Artifact bundle directory, artifact.json, pearl.ir.json, or pipeline JSON path.
    #[arg(value_name = "ARTIFACT")]
    pub artifact: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactDigestArgs {
    /// Artifact bundle directory, artifact.json, pearl.ir.json, or pipeline JSON path.
    #[arg(value_name = "ARTIFACT")]
    pub artifact: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactVerifyArgs {
    /// Artifact bundle directory or artifact.json to verify.
    #[arg(value_name = "ARTIFACT")]
    pub artifact: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

fn artifact_file_stem(name: &str) -> String {
    let sanitized = sanitize_identifier(name);
    if sanitized.is_empty() {
        "pearl".to_string()
    } else {
        sanitized
    }
}

pub(super) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
}

pub(super) fn generated_build_root(workspace_root: &Path) -> PathBuf {
    if has_workspace_sources(workspace_root) {
        workspace_root.join("target").join("generated")
    } else {
        std::env::temp_dir()
            .join("logicpearl")
            .join("target")
            .join("generated")
    }
}

pub(super) fn cleanup_generated_build_dir(build_dir: &Path) {
    if std::env::var_os("LOGICPEARL_KEEP_GENERATED_BUILDS").is_some() {
        return;
    }

    if let Err(error) = fs::remove_dir_all(build_dir) {
        eprintln!(
            "warning: failed to clean generated compile directory {}: {error}",
            build_dir.display()
        );
    }
}

pub(super) fn unique_generated_crate_name(prefix: &str) -> String {
    static NEXT_GENERATED_BUILD_ID: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = NEXT_GENERATED_BUILD_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{}_{}_{}", std::process::id(), nanos, counter)
}

pub(super) fn dependency_spec(
    workspace_root: &Path,
    crate_name: &str,
    relative_path: &str,
) -> String {
    let local_path = workspace_root.join(relative_path);
    if has_workspace_sources(workspace_root) && local_path.exists() {
        format!("{{ path = \"{}\" }}", local_path.display())
    } else {
        format!("\"{}\"", published_crate_version(crate_name))
    }
}

fn published_crate_version(_crate_name: &str) -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn has_workspace_sources(workspace_root: &Path) -> bool {
    workspace_root.join("crates/logicpearl-ir").exists()
        && workspace_root.join("crates/logicpearl-runtime").exists()
}

pub(super) fn binary_file_name(base: &str, target_triple: Option<&str>) -> String {
    if target_is_windows(target_triple) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn target_is_windows(target_triple: Option<&str>) -> bool {
    target_triple
        .map(|target| target.contains("windows"))
        .unwrap_or(cfg!(target_os = "windows"))
}

#[cfg(test)]
mod tests;
