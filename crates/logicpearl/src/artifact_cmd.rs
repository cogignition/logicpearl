// SPDX-License-Identifier: MIT
use clap::Args;
use logicpearl_benchmark::sanitize_identifier;
use logicpearl_core::{
    load_artifact_bundle, manifest_file_roles, manifest_member_without_base_prefix, ArtifactKind,
    ArtifactManifestFiles, ArtifactManifestV1, LoadedArtifactBundle,
    ARTIFACT_MANIFEST_SCHEMA_VERSION,
};
use logicpearl_discovery::{build_result_for_report, BuildResult, OutputFiles};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use logicpearl_pipeline::PipelineDefinition;
use logicpearl_runtime::{artifact_hash, sha256_prefixed, LOGICPEARL_ENGINE_VERSION};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod native_compile;
mod pearl;
mod wasm_compile;
mod wasm_metadata;

pub(crate) use native_compile::{compile_native_runner, run_embedded_native_runner_if_present};
use pearl::CompilablePearl;
#[cfg(test)]
use wasm_compile::generate_wasm_runner_source;
pub(crate) use wasm_compile::{compile_wasm_module, is_rust_target_installed};
#[cfg(test)]
use wasm_metadata::{write_wasm_metadata, write_wasm_metadata_for_pearl};

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ArtifactBundleDescriptor {
    pub(crate) bundle_kind: String,
    pub(crate) cli_entrypoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) primary_runtime: Option<String>,
    #[serde(default)]
    pub(crate) deployables: Vec<ArtifactDeployable>,
    #[serde(default)]
    pub(crate) metadata_files: Vec<ArtifactSidecar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArtifactDeployable {
    pub(crate) kind: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArtifactSidecar {
    pub(crate) kind: String,
    pub(crate) path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) companion_to: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactManifestWriteOptions {
    pub(crate) artifact_kind: ArtifactKind,
    pub(crate) artifact_id: String,
    pub(crate) ir_path: PathBuf,
    pub(crate) build_report_path: Option<PathBuf>,
    pub(crate) feature_dictionary_path: Option<PathBuf>,
    pub(crate) native_path: Option<PathBuf>,
    pub(crate) wasm_path: Option<PathBuf>,
    pub(crate) wasm_metadata_path: Option<PathBuf>,
    pub(crate) build_options_hash: Option<String>,
    pub(crate) bundle: ArtifactBundleDescriptor,
    pub(crate) extensions: BTreeMap<String, Value>,
    pub(crate) file_extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactManifestInspection {
    manifest_path: Option<String>,
    artifact_dir: String,
    manifest: ArtifactManifestV1,
    resolved_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactDigestReport {
    manifest_path: Option<String>,
    artifact_id: String,
    artifact_kind: ArtifactKind,
    artifact_hash: String,
    bundle_hash: Option<String>,
    file_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactVerificationReport {
    ok: bool,
    manifest_path: Option<String>,
    artifact_id: Option<String>,
    artifact_kind: Option<ArtifactKind>,
    checks: Vec<ArtifactVerificationCheck>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactVerificationCheck {
    name: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedArtifactInput {
    pub(crate) artifact_dir: PathBuf,
    pub(crate) pearl_ir: PathBuf,
}

pub(crate) fn resolve_artifact_input(path: &Path) -> Result<ResolvedArtifactInput> {
    let bundle = load_artifact_bundle(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", path.display()))?;
    Ok(ResolvedArtifactInput {
        artifact_dir: bundle.base_dir.clone(),
        pearl_ir: bundle.ir_path().into_diagnostic()?,
    })
}

pub(crate) fn pearl_artifact_id(pearl_ir: &Path) -> Result<String> {
    Ok(CompilablePearl::from_path(pearl_ir)?
        .artifact_id()
        .to_string())
}

pub(crate) fn native_artifact_output_path(
    artifact_dir: &Path,
    artifact_name: &str,
    target_triple: Option<&str>,
) -> PathBuf {
    artifact_dir.join(binary_file_name(
        &format!("{}.pearl", artifact_file_stem(artifact_name)),
        target_triple,
    ))
}

pub(crate) fn wasm_artifact_output_path(artifact_dir: &Path, artifact_name: &str) -> PathBuf {
    artifact_dir.join(format!("{}.pearl.wasm", artifact_file_stem(artifact_name)))
}

pub(crate) fn write_named_artifact_manifest(
    output_dir: &Path,
    gate_id: &str,
    output_files: &OutputFiles,
    feature_dictionary_path: Option<&Path>,
    build_options_hash: Option<String>,
) -> Result<()> {
    let native_path = output_files.native_binary.as_ref().map(PathBuf::from);
    let wasm_path = output_files.wasm_module.as_ref().map(PathBuf::from);
    let wasm_metadata_path = output_files.wasm_metadata.as_ref().map(PathBuf::from);
    write_artifact_manifest_v1(
        output_dir,
        ArtifactManifestWriteOptions {
            artifact_kind: ArtifactKind::Gate,
            artifact_id: gate_id.to_string(),
            ir_path: PathBuf::from(&output_files.pearl_ir),
            build_report_path: Some(PathBuf::from(&output_files.build_report)),
            feature_dictionary_path: feature_dictionary_path.map(Path::to_path_buf),
            native_path,
            wasm_path,
            wasm_metadata_path,
            build_options_hash,
            bundle: build_artifact_bundle_descriptor(output_files),
            extensions: BTreeMap::new(),
            file_extensions: BTreeMap::new(),
        },
    )
}

pub(crate) fn write_artifact_manifest_v1(
    output_dir: &Path,
    options: ArtifactManifestWriteOptions,
) -> Result<()> {
    let ir_value = read_json_file(&options.ir_path).wrap_err("failed to read artifact IR")?;
    let ir_version = artifact_ir_version(&ir_value, options.artifact_kind)?;
    let artifact_hash_value = artifact_hash(&ir_value);
    let input_schema_hash = ir_value.get("input_schema").map(artifact_hash);
    let feature_dictionary_hash = options
        .feature_dictionary_path
        .as_ref()
        .filter(|path| path.exists())
        .map(|path| hash_file_canonical_if_json(path))
        .transpose()?;

    let ir_file = relative_manifest_file(output_dir, &options.ir_path, "pearl.ir.json");
    let build_report_file = options
        .build_report_path
        .as_ref()
        .map(|path| relative_manifest_file(output_dir, path, "build_report.json"));
    let feature_dictionary_file = options
        .feature_dictionary_path
        .as_ref()
        .filter(|path| path.exists())
        .map(|path| relative_manifest_file(output_dir, path, "feature_dictionary.generated.json"));
    let native_file = options
        .native_path
        .as_ref()
        .map(|path| relative_manifest_file(output_dir, path, ""));
    let wasm_file = options
        .wasm_path
        .as_ref()
        .map(|path| relative_manifest_file(output_dir, path, "pearl.wasm"));
    let wasm_metadata_file = options
        .wasm_metadata_path
        .as_ref()
        .map(|path| relative_manifest_file(output_dir, path, "pearl.wasm.meta.json"));

    let mut file_hashes = BTreeMap::new();
    insert_file_hash(output_dir, &mut file_hashes, "ir", Some(&ir_file))?;
    insert_file_hash(
        output_dir,
        &mut file_hashes,
        "build_report",
        build_report_file.as_deref(),
    )?;
    insert_file_hash(
        output_dir,
        &mut file_hashes,
        "feature_dictionary",
        feature_dictionary_file.as_deref(),
    )?;
    insert_file_hash(
        output_dir,
        &mut file_hashes,
        "native",
        native_file.as_deref(),
    )?;
    insert_file_hash(output_dir, &mut file_hashes, "wasm", wasm_file.as_deref())?;
    insert_file_hash(
        output_dir,
        &mut file_hashes,
        "wasm_metadata",
        wasm_metadata_file.as_deref(),
    )?;

    let files = ArtifactManifestFiles {
        ir: ir_file,
        build_report: build_report_file,
        feature_dictionary: feature_dictionary_file,
        wasm: wasm_file,
        wasm_metadata: wasm_metadata_file,
        native: native_file,
        extensions: options.file_extensions,
    };

    let bundle_hash = Some(artifact_hash(&json!({
        "artifact_hash": artifact_hash_value.clone(),
        "files": files.clone(),
        "file_hashes": file_hashes.clone(),
    })));

    let mut extensions = options.extensions;
    extensions.insert(
        "bundle".to_string(),
        serde_json::to_value(options.bundle).into_diagnostic()?,
    );

    let manifest = ArtifactManifestV1 {
        schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
        artifact_id: options.artifact_id,
        artifact_kind: options.artifact_kind,
        engine_version: LOGICPEARL_ENGINE_VERSION.to_string(),
        ir_version,
        created_at: current_timestamp()?,
        artifact_hash: artifact_hash_value,
        files,
        input_schema_hash,
        feature_dictionary_hash,
        build_options_hash: options.build_options_hash,
        file_hashes,
        bundle_hash,
        extensions,
    };

    fs::write(
        output_dir.join("artifact.json"),
        serde_json::to_string_pretty(&manifest).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write artifact manifest")?;
    Ok(())
}

pub(crate) fn refresh_artifact_manifest_deployables(
    artifact_dir: &Path,
    pearl_ir: &Path,
    native_path: Option<&Path>,
    wasm_path: Option<&Path>,
    wasm_metadata_path: Option<&Path>,
) -> Result<()> {
    let manifest_path = artifact_dir.join("artifact.json");
    if !manifest_path.exists() {
        return Ok(());
    }
    let context = load_artifact_manifest_context(artifact_dir)?;
    if context.manifest.artifact_kind == ArtifactKind::Pipeline {
        return Ok(());
    }
    let native_path = native_path.map(Path::to_path_buf).or_else(|| {
        context
            .manifest
            .files
            .native
            .map(|path| artifact_dir.join(path))
    });
    let wasm_path = wasm_path.map(Path::to_path_buf).or_else(|| {
        context
            .manifest
            .files
            .wasm
            .map(|path| artifact_dir.join(path))
    });
    let wasm_metadata_path = wasm_metadata_path.map(Path::to_path_buf).or_else(|| {
        context
            .manifest
            .files
            .wasm_metadata
            .map(|path| artifact_dir.join(path))
    });
    let build_report_path = context
        .manifest
        .files
        .build_report
        .as_ref()
        .map(|path| artifact_dir.join(path));
    let feature_dictionary_path = context
        .manifest
        .files
        .feature_dictionary
        .as_ref()
        .map(|path| artifact_dir.join(path));
    let native_file = native_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    let wasm_file = wasm_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    let wasm_metadata_file = wasm_metadata_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    let bundle = build_deployable_bundle_descriptor(native_file, wasm_file, wasm_metadata_file);

    write_artifact_manifest_v1(
        artifact_dir,
        ArtifactManifestWriteOptions {
            artifact_kind: context.manifest.artifact_kind,
            artifact_id: context.manifest.artifact_id,
            ir_path: pearl_ir.to_path_buf(),
            build_report_path,
            feature_dictionary_path,
            native_path,
            wasm_path,
            wasm_metadata_path,
            build_options_hash: context.manifest.build_options_hash,
            bundle,
            extensions: context.manifest.extensions,
            file_extensions: context.manifest.files.extensions,
        },
    )
}

pub(crate) fn build_deployable_bundle_descriptor(
    native_binary: Option<String>,
    wasm_module: Option<String>,
    wasm_metadata: Option<String>,
) -> ArtifactBundleDescriptor {
    let mut deployables = Vec::new();
    if let Some(path) = &native_binary {
        deployables.push(ArtifactDeployable {
            kind: "native_binary".to_string(),
            path: path.clone(),
        });
    }
    if let Some(path) = &wasm_module {
        deployables.push(ArtifactDeployable {
            kind: "wasm_module".to_string(),
            path: path.clone(),
        });
    }

    let mut metadata_files = Vec::new();
    if let Some(path) = &wasm_metadata {
        metadata_files.push(ArtifactSidecar {
            kind: "wasm_metadata".to_string(),
            path: path.clone(),
            companion_to: wasm_module.clone(),
        });
    }

    ArtifactBundleDescriptor {
        bundle_kind: "direct_pearl_bundle".to_string(),
        cli_entrypoint: "artifact.json".to_string(),
        primary_runtime: native_binary
            .as_ref()
            .map(|_| "native_binary".to_string())
            .or_else(|| wasm_module.as_ref().map(|_| "wasm_module".to_string())),
        deployables,
        metadata_files,
    }
}

fn current_timestamp() -> Result<String> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .into_diagnostic()
        .wrap_err("failed to format artifact timestamp")
}

fn read_json_file(path: &Path) -> Result<Value> {
    serde_json::from_str(
        &fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read JSON file {}", path.display()))?,
    )
    .into_diagnostic()
    .wrap_err_with(|| format!("JSON file is invalid: {}", path.display()))
}

fn artifact_ir_version(value: &Value, artifact_kind: ArtifactKind) -> Result<String> {
    match artifact_kind {
        ArtifactKind::Gate | ArtifactKind::Action => value
            .get("ir_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| miette::miette!("artifact IR is missing ir_version")),
        ArtifactKind::Pipeline => value
            .get("pipeline_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| miette::miette!("pipeline artifact is missing pipeline_version")),
    }
}

fn relative_manifest_file(base_dir: &Path, path: &Path, fallback: &str) -> String {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    if candidate.exists() {
        if let Ok(relative) = candidate.strip_prefix(base_dir) {
            let rendered = relative.display().to_string();
            if !rendered.is_empty() {
                return rendered;
            }
        }
    }
    if let Some(relative) = manifest_member_without_base_prefix(base_dir, path) {
        let rendered = relative.display().to_string();
        if !rendered.is_empty() {
            return rendered;
        }
    }
    if let Ok(relative) = candidate.strip_prefix(base_dir) {
        let rendered = relative.display().to_string();
        if !rendered.is_empty() {
            return rendered;
        }
    }
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn insert_file_hash(
    base_dir: &Path,
    file_hashes: &mut BTreeMap<String, String>,
    role: &str,
    relative_path: Option<&str>,
) -> Result<()> {
    let Some(relative_path) = relative_path else {
        return Ok(());
    };
    let path = resolve_manifest_member_path(base_dir, relative_path)?;
    if path.exists() {
        file_hashes.insert(role.to_string(), hash_file_canonical_if_json(&path)?);
    }
    Ok(())
}

fn hash_file_canonical_if_json(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read file for hashing: {}", path.display()))?;
    if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            return Ok(artifact_hash(&value));
        }
    }
    Ok(sha256_prefixed(&bytes))
}

pub(crate) fn build_options_hash(value: &Value) -> String {
    artifact_hash(value)
}

pub(crate) fn artifact_bundle_descriptor_from_manifest(
    manifest: &ArtifactManifestV1,
) -> Result<ArtifactBundleDescriptor> {
    if let Some(bundle) = manifest.extensions.get("bundle") {
        return serde_json::from_value(bundle.clone())
            .into_diagnostic()
            .wrap_err("failed to parse artifact bundle descriptor");
    }
    Ok(build_bundle_descriptor_from_manifest_files(&manifest.files))
}

pub(crate) fn run_artifact_inspect(args: ArtifactInspectArgs) -> Result<()> {
    let inspection = inspect_artifact(&args.artifact)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Artifact".bold().bright_cyan(),
            inspection.manifest.artifact_id.bold()
        );
        println!(
            "  {} {:?}",
            "Kind".bright_black(),
            inspection.manifest.artifact_kind
        );
        println!(
            "  {} {}",
            "Schema".bright_black(),
            inspection.manifest.schema_version
        );
        println!(
            "  {} {}",
            "Artifact hash".bright_black(),
            inspection.manifest.artifact_hash
        );
        if let Some(bundle_hash) = &inspection.manifest.bundle_hash {
            println!("  {} {}", "Bundle hash".bright_black(), bundle_hash);
        }
        println!("  {} {}", "IR".bright_black(), inspection.manifest.files.ir);
        for (role, path) in &inspection.resolved_files {
            println!("  {} {} {}", "File".bright_black(), role, path);
        }
    }
    Ok(())
}

pub(crate) fn run_artifact_digest(args: ArtifactDigestArgs) -> Result<()> {
    let inspection = inspect_artifact(&args.artifact)?;
    let report = ArtifactDigestReport {
        manifest_path: inspection.manifest_path,
        artifact_id: inspection.manifest.artifact_id,
        artifact_kind: inspection.manifest.artifact_kind,
        artifact_hash: inspection.manifest.artifact_hash,
        bundle_hash: inspection.manifest.bundle_hash,
        file_hashes: inspection.manifest.file_hashes,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", report.artifact_hash);
        if let Some(bundle_hash) = &report.bundle_hash {
            println!("bundle {bundle_hash}");
        }
    }
    Ok(())
}

pub(crate) fn run_artifact_verify(args: ArtifactVerifyArgs) -> Result<()> {
    let report = verify_artifact(&args.artifact)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else if report.ok {
        println!(
            "{} {}",
            "Verified".bold().bright_green(),
            report.artifact_id.as_deref().unwrap_or("artifact").bold()
        );
        for check in &report.checks {
            println!("  {} {}", "ok".bright_black(), check.name);
        }
    } else {
        println!("{}", "Artifact verification failed".bold().bright_red());
        for check in &report.checks {
            let status = if check.ok { "ok" } else { "fail" };
            if let Some(message) = &check.message {
                println!("  {} {} - {}", status.bright_black(), check.name, message);
            } else {
                println!("  {} {}", status.bright_black(), check.name);
            }
        }
    }
    if report.ok {
        Ok(())
    } else {
        Err(miette::miette!("artifact verification failed"))
    }
}

fn inspect_artifact(path: &Path) -> Result<ArtifactManifestInspection> {
    let context = load_artifact_manifest_context(path)?;
    let resolved_files = resolved_manifest_files(&context.base_dir, &context.manifest.files)?;
    Ok(ArtifactManifestInspection {
        manifest_path: context
            .manifest_path
            .as_ref()
            .map(|path| path.display().to_string()),
        artifact_dir: context.base_dir.display().to_string(),
        manifest: context.manifest,
        resolved_files,
    })
}

fn verify_artifact(path: &Path) -> Result<ArtifactVerificationReport> {
    let context = load_artifact_manifest_context(path)?;
    let mut checks = Vec::new();
    let raw_schema_version = context.raw_manifest.as_ref().and_then(|value| {
        value
            .get("schema_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    });
    push_check(
        &mut checks,
        "schema_version",
        raw_schema_version.as_deref() == Some(ARTIFACT_MANIFEST_SCHEMA_VERSION),
        raw_schema_version
            .as_deref()
            .filter(|value| *value != ARTIFACT_MANIFEST_SCHEMA_VERSION)
            .map(|value| format!("expected {ARTIFACT_MANIFEST_SCHEMA_VERSION}, found {value}"))
            .or_else(|| {
                if raw_schema_version.is_none() {
                    Some(format!("expected {ARTIFACT_MANIFEST_SCHEMA_VERSION}"))
                } else {
                    None
                }
            }),
    );

    let ir_path = resolve_manifest_member_path(&context.base_dir, &context.manifest.files.ir)?;
    push_check(
        &mut checks,
        "files.ir_exists",
        ir_path.exists(),
        (!ir_path.exists()).then(|| format!("missing {}", ir_path.display())),
    );

    if ir_path.exists() {
        let ir_value = read_json_file(&ir_path)?;
        let actual_hash = artifact_hash(&ir_value);
        push_check(
            &mut checks,
            "artifact_hash",
            actual_hash == context.manifest.artifact_hash,
            (actual_hash != context.manifest.artifact_hash).then(|| {
                format!(
                    "expected {}, computed {}",
                    context.manifest.artifact_hash, actual_hash
                )
            }),
        );
        match validate_manifest_kind_and_ir(&context.manifest, &context.base_dir, &ir_path) {
            Ok(()) => push_check(&mut checks, "ir_valid", true, None),
            Err(err) => push_check(&mut checks, "ir_valid", false, Some(err.to_string())),
        }
        if let Some(expected) = &context.manifest.input_schema_hash {
            let actual = ir_value.get("input_schema").map(artifact_hash);
            push_check(
                &mut checks,
                "input_schema_hash",
                actual.as_ref() == Some(expected),
                (actual.as_ref() != Some(expected)).then(|| {
                    format!(
                        "expected {}, computed {}",
                        expected,
                        actual.unwrap_or_else(|| "missing input_schema".to_string())
                    )
                }),
            );
        }
    }

    for (role, relative_path) in manifest_file_roles(&context.manifest.files)
        .into_iter()
        .filter(|(role, _)| role != "ir")
    {
        let path = resolve_manifest_member_path(&context.base_dir, &relative_path)?;
        push_check(
            &mut checks,
            format!("files.{role}_exists"),
            path.exists(),
            (!path.exists()).then(|| format!("missing {}", path.display())),
        );
        if path.exists() {
            let actual = hash_file_canonical_if_json(&path)?;
            if let Some(expected) = context.manifest.file_hashes.get(&role) {
                push_check(
                    &mut checks,
                    format!("file_hashes.{role}"),
                    &actual == expected,
                    (&actual != expected)
                        .then(|| format!("expected {expected}, computed {actual}")),
                );
            }
        }
    }

    if let (Some(path), Some(expected)) = (
        context.manifest.files.feature_dictionary.as_ref(),
        context.manifest.feature_dictionary_hash.as_ref(),
    ) {
        let dictionary_path = resolve_manifest_member_path(&context.base_dir, path)?;
        if dictionary_path.exists() {
            let actual = hash_file_canonical_if_json(&dictionary_path)?;
            push_check(
                &mut checks,
                "feature_dictionary_hash",
                &actual == expected,
                (&actual != expected).then(|| format!("expected {expected}, computed {actual}")),
            );
        }
    }

    push_check(
        &mut checks,
        "build_options_hash_format",
        context
            .manifest
            .build_options_hash
            .as_ref()
            .map(|value| value.starts_with("sha256:"))
            .unwrap_or(true),
        context
            .manifest
            .build_options_hash
            .as_ref()
            .filter(|value| !value.starts_with("sha256:"))
            .map(|value| format!("not a sha256 digest: {value}")),
    );

    let ok = checks.iter().all(|check| check.ok);
    Ok(ArtifactVerificationReport {
        ok,
        manifest_path: context
            .manifest_path
            .as_ref()
            .map(|path| path.display().to_string()),
        artifact_id: Some(context.manifest.artifact_id),
        artifact_kind: Some(context.manifest.artifact_kind),
        checks,
    })
}

fn push_check(
    checks: &mut Vec<ArtifactVerificationCheck>,
    name: impl Into<String>,
    ok: bool,
    message: Option<String>,
) {
    checks.push(ArtifactVerificationCheck {
        name: name.into(),
        ok,
        message,
    });
}

fn load_artifact_manifest_context(path: &Path) -> Result<LoadedArtifactBundle> {
    load_artifact_bundle(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to load artifact manifest {}", path.display()))
}

fn validate_manifest_kind_and_ir(
    manifest: &ArtifactManifestV1,
    base_dir: &Path,
    ir_path: &Path,
) -> Result<()> {
    match manifest.artifact_kind {
        ArtifactKind::Gate => {
            let gate = LogicPearlGateIr::from_path(ir_path)
                .into_diagnostic()
                .wrap_err("could not parse gate IR")?;
            gate.validate()
                .into_diagnostic()
                .wrap_err("gate IR did not validate")?;
            if gate.gate_id != manifest.artifact_id {
                return Err(miette::miette!(
                    "manifest artifact_id {} does not match gate_id {}",
                    manifest.artifact_id,
                    gate.gate_id
                ));
            }
        }
        ArtifactKind::Action => {
            let policy = LogicPearlActionIr::from_path(ir_path)
                .into_diagnostic()
                .wrap_err("could not parse action policy IR")?;
            policy
                .validate()
                .into_diagnostic()
                .wrap_err("action policy IR did not validate")?;
            if policy.action_policy_id != manifest.artifact_id {
                return Err(miette::miette!(
                    "manifest artifact_id {} does not match action_policy_id {}",
                    manifest.artifact_id,
                    policy.action_policy_id
                ));
            }
        }
        ArtifactKind::Pipeline => {
            let pipeline = PipelineDefinition::from_path(ir_path)
                .into_diagnostic()
                .wrap_err("could not parse pipeline definition")?;
            let pipeline_base = if ir_path.is_absolute() {
                ir_path.parent().unwrap_or(base_dir)
            } else {
                base_dir
            };
            pipeline
                .validate(pipeline_base)
                .into_diagnostic()
                .wrap_err("pipeline definition did not validate")?;
            if pipeline.pipeline_id != manifest.artifact_id {
                return Err(miette::miette!(
                    "manifest artifact_id {} does not match pipeline_id {}",
                    manifest.artifact_id,
                    pipeline.pipeline_id
                ));
            }
        }
    }
    Ok(())
}

fn resolved_manifest_files(
    base_dir: &Path,
    files: &ArtifactManifestFiles,
) -> Result<BTreeMap<String, String>> {
    manifest_file_roles(files)
        .into_iter()
        .map(|(role, path)| {
            let resolved = resolve_manifest_member_path(base_dir, &path)
                .wrap_err_with(|| format!("invalid manifest file path for {role}"))?;
            Ok((role, resolved.display().to_string()))
        })
        .collect()
}

fn build_artifact_bundle_descriptor(output_files: &OutputFiles) -> ArtifactBundleDescriptor {
    build_deployable_bundle_descriptor(
        output_files.native_binary.as_ref().and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        output_files.wasm_module.as_ref().and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        output_files.wasm_metadata.as_ref().and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
    )
}

fn build_bundle_descriptor_from_manifest_files(
    files: &ArtifactManifestFiles,
) -> ArtifactBundleDescriptor {
    build_deployable_bundle_descriptor(
        files.native.clone(),
        files.wasm.clone(),
        files.wasm_metadata.clone(),
    )
}

pub(crate) fn persist_build_report(result: &BuildResult) -> Result<()> {
    let report = build_result_for_report(result);
    fs::write(
        &result.output_files.build_report,
        serde_json::to_string_pretty(&report).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to update build report")?;
    Ok(())
}

pub(crate) fn resolve_manifest_member_path(base_dir: &Path, raw_path: &str) -> Result<PathBuf> {
    logicpearl_core::resolve_manifest_member_path(base_dir, raw_path).into_diagnostic()
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
mod tests {
    use super::{
        generate_wasm_runner_source, relative_manifest_file, resolve_manifest_member_path,
        unique_generated_crate_name, write_wasm_metadata, write_wasm_metadata_for_pearl,
        CompilablePearl,
    };
    use logicpearl_ir::{
        ActionEvaluationConfig, ActionRuleDefinition, ActionSelectionStrategy, CombineStrategy,
        ComparisonExpression, ComparisonOperator, ComparisonValue, DerivedFeatureDefinition,
        DerivedFeatureOperator, EvaluationConfig, Expression, FeatureDefinition, FeatureSemantics,
        FeatureStatePredicate, FeatureStateSemantics, FeatureType, GateType, InputSchema,
        LogicPearlActionIr, LogicPearlGateIr, RuleDefinition, RuleKind,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn generated_crate_names_are_isolated_per_invocation() {
        let first = unique_generated_crate_name("logicpearl_compiled_demo");
        let second = unique_generated_crate_name("logicpearl_compiled_demo");
        assert_ne!(first, second);
        assert!(first.starts_with("logicpearl_compiled_demo_"));
        assert!(second.starts_with("logicpearl_compiled_demo_"));
    }

    #[test]
    fn manifest_paths_do_not_double_prefix_relative_output_dirs() {
        assert_eq!(
            relative_manifest_file(
                Path::new("gate"),
                Path::new("gate/pearl.ir.json"),
                "pearl.ir.json"
            ),
            "pearl.ir.json"
        );
        assert_eq!(
            relative_manifest_file(
                Path::new("/tmp/project/gate"),
                Path::new("gate/pearl.ir.json"),
                "pearl.ir.json"
            ),
            "pearl.ir.json"
        );

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let artifact_dir = temp_dir.path().join("gate");
        std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
        std::fs::write(artifact_dir.join("pearl.ir.json"), "{}").expect("pearl file");

        assert_eq!(
            resolve_manifest_member_path(&artifact_dir, "gate/pearl.ir.json")
                .expect("manifest path should resolve"),
            artifact_dir.join("pearl.ir.json")
        );
    }

    #[test]
    fn manifest_member_paths_cannot_escape_artifact_dir() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let artifact_dir = temp_dir.path().join("artifact");
        let outside = temp_dir.path().join("outside.json");
        std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
        std::fs::write(&outside, "{}").expect("outside file");

        let absolute_error =
            resolve_manifest_member_path(&artifact_dir, &outside.display().to_string())
                .expect_err("absolute manifest paths should be rejected")
                .to_string();
        assert!(
            absolute_error.contains("must be relative"),
            "unexpected error: {absolute_error}"
        );

        let parent_error = resolve_manifest_member_path(&artifact_dir, "../outside.json")
            .expect_err("parent escapes should be rejected")
            .to_string();
        assert!(
            parent_error.contains("escapes bundle directory"),
            "unexpected error: {parent_error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn manifest_member_symlinks_cannot_escape_artifact_dir() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let artifact_dir = temp_dir.path().join("artifact");
        let outside = temp_dir.path().join("outside.json");
        let link = artifact_dir.join("outside-link.json");
        std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
        std::fs::write(&outside, "{}").expect("outside file");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink should be created");

        let error = resolve_manifest_member_path(&artifact_dir, "outside-link.json")
            .expect_err("symlink escapes should be rejected")
            .to_string();
        assert!(
            error.contains("escapes bundle directory"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn generated_wasm_bitmask_abi_does_not_reserve_u64_max() {
        let gate = gate_with_rule_count(64);
        let source = generate_wasm_runner_source(&gate);

        assert!(source.contains("pub extern \"C\" fn logicpearl_eval_status_slots_f64"));
        assert!(source.contains("bitmask |= 1u64 << 63;"));
        assert!(source.contains("return 0;"));
        assert!(!source.contains("u64::MAX"));
    }

    #[test]
    fn generated_wasm_orders_derived_assignments_by_dependency() {
        let gate = gate_with_out_of_order_derived_chain();
        let source = generate_wasm_runner_source(&gate);

        let dependency = source
            .find("let derived_debt_to_income")
            .expect("dependency assignment should be generated");
        let dependent = source
            .find("let derived_risk_margin")
            .expect("dependent assignment should be generated");
        assert!(dependency < dependent);
        assert!(source.contains("let derived_risk_margin = (derived_debt_to_income -"));
    }

    #[test]
    fn wasm_metadata_orders_derived_features_by_dependency() {
        let gate = gate_with_out_of_order_derived_chain();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("pearl.wasm.meta.json");

        write_wasm_metadata(&path, &gate).expect("write wasm metadata");

        let metadata: Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read generated wasm metadata"),
        )
        .expect("parse generated wasm metadata");
        let derived_ids = metadata["derived_features"]
            .as_array()
            .expect("derived feature metadata should be an array")
            .iter()
            .map(|feature| {
                feature["id"]
                    .as_str()
                    .expect("derived id should be a string")
            })
            .collect::<Vec<_>>();
        assert_eq!(derived_ids, vec!["debt_to_income", "risk_margin"]);
    }

    #[test]
    fn wasm_metadata_declares_explicit_status_entrypoint() {
        let gate = gate_with_rule_count(1);
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("pearl.wasm.meta.json");

        write_wasm_metadata(&path, &gate).expect("write wasm metadata");

        let metadata: Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read generated wasm metadata"),
        )
        .expect("parse generated wasm metadata");
        assert_eq!(
            metadata["entrypoint"].as_str(),
            Some("logicpearl_eval_bitmask_slots_f64")
        );
        assert_eq!(
            metadata["status_entrypoint"].as_str(),
            Some("logicpearl_eval_status_slots_f64")
        );
        assert_eq!(
            metadata["allow_entrypoint"].as_str(),
            Some("logicpearl_eval_allow_slots_f64")
        );
    }

    #[test]
    fn wasm_metadata_includes_runtime_feature_explanations() {
        let mut gate = gate_with_rule_count(1);
        gate.input_schema.features[0].semantics = Some(enabled_semantics());
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("pearl.wasm.meta.json");

        write_wasm_metadata(&path, &gate).expect("write wasm metadata");

        let metadata: Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read generated wasm metadata"),
        )
        .expect("parse generated wasm metadata");
        assert_eq!(metadata["rules"][0]["features"][0]["feature_id"], "enabled");
        assert_eq!(
            metadata["rules"][0]["features"][0]["feature_label"],
            "Enabled flag"
        );
        assert_eq!(
            metadata["rules"][0]["features"][0]["source_id"],
            "source_policy"
        );
        assert_eq!(
            metadata["rules"][0]["features"][0]["source_anchor"],
            "enabled"
        );
        assert_eq!(
            metadata["rules"][0]["features"][0]["state_label"],
            "Enabled"
        );
        assert_eq!(
            metadata["rules"][0]["features"][0]["state_message"],
            "Enabled items are denied."
        );
        assert_eq!(
            metadata["rules"][0]["features"][0]["counterfactual_hint"],
            "Disable the item."
        );
    }

    #[test]
    fn action_wasm_metadata_declares_policy_selection_metadata() {
        let policy = action_policy();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("pearl.wasm.meta.json");

        write_wasm_metadata_for_pearl(&path, &CompilablePearl::Action(policy))
            .expect("write action wasm metadata");

        let metadata: Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read generated wasm metadata"),
        )
        .expect("parse generated wasm metadata");
        assert_eq!(metadata["decision_kind"], "action");
        assert_eq!(metadata["action_policy_id"], "garden_actions");
        assert_eq!(metadata["default_action"], "do_nothing");
        assert_eq!(metadata["rules"][0]["bit"], 0);
        assert_eq!(metadata["rules"][0]["action"], "water");
        assert_eq!(metadata["rules"][0]["priority"], 0);
        assert_eq!(metadata["rules"][0]["features"][0]["feature_id"], "enabled");
        assert_eq!(
            metadata["rules"][0]["features"][0]["feature_label"],
            "Enabled flag"
        );
    }

    fn enabled_semantics() -> FeatureSemantics {
        FeatureSemantics {
            label: Some("Enabled flag".to_string()),
            kind: None,
            unit: None,
            higher_is_better: None,
            source_id: Some("source_policy".to_string()),
            source_anchor: Some("enabled".to_string()),
            states: BTreeMap::from([(
                "enabled".to_string(),
                FeatureStateSemantics {
                    predicate: FeatureStatePredicate {
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::Bool(true)),
                    },
                    label: Some("Enabled".to_string()),
                    message: Some("Enabled items are denied.".to_string()),
                    counterfactual_hint: Some("Disable the item.".to_string()),
                },
            )]),
        }
    }

    fn gate_with_rule_count(rule_count: u32) -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "test_gate".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "enabled".to_string(),
                    feature_type: FeatureType::Bool,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: Some(enabled_semantics()),
                    governance: None,
                    derived: None,
                }],
            },
            rules: (0..rule_count)
                .map(|bit| RuleDefinition {
                    id: format!("rule_{bit}"),
                    kind: RuleKind::Predicate,
                    bit,
                    deny_when: Expression::Comparison(ComparisonExpression {
                        feature: "enabled".to_string(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::Bool(true)),
                    }),
                    label: None,
                    message: None,
                    severity: None,
                    counterfactual_hint: None,
                    verification_status: None,
                })
                .collect(),
            evaluation: EvaluationConfig {
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        }
    }

    fn gate_with_out_of_order_derived_chain() -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "derived_chain".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![
                    FeatureDefinition {
                        id: "risk_margin".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: Some(DerivedFeatureDefinition {
                            op: DerivedFeatureOperator::Difference,
                            left_feature: "debt_to_income".to_string(),
                            right_feature: "limit".to_string(),
                        }),
                    },
                    FeatureDefinition {
                        id: "debt_to_income".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: Some(DerivedFeatureDefinition {
                            op: DerivedFeatureOperator::Ratio,
                            left_feature: "debt".to_string(),
                            right_feature: "income".to_string(),
                        }),
                    },
                    FeatureDefinition {
                        id: "limit".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "debt".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "income".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                ],
            },
            rules: vec![RuleDefinition {
                id: "rule_000".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "risk_margin".to_string(),
                    op: ComparisonOperator::Gte,
                    value: ComparisonValue::Literal(json!(0.0)),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: None,
            }],
            evaluation: EvaluationConfig {
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        }
    }

    fn action_policy() -> LogicPearlActionIr {
        LogicPearlActionIr {
            ir_version: "1.0".to_string(),
            action_policy_id: "garden_actions".to_string(),
            action_policy_type: "priority_rules".to_string(),
            action_column: "next_action".to_string(),
            default_action: "do_nothing".to_string(),
            actions: vec!["do_nothing".to_string(), "water".to_string()],
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "enabled".to_string(),
                    feature_type: FeatureType::Bool,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: Some(enabled_semantics()),
                    governance: None,
                    derived: None,
                }],
            },
            rules: vec![ActionRuleDefinition {
                id: "rule_0".to_string(),
                bit: 0,
                action: "water".to_string(),
                priority: 0,
                predicate: Expression::Comparison(ComparisonExpression {
                    feature: "enabled".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Bool(true)),
                }),
                label: Some("Water enabled plants".to_string()),
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: None,
            }],
            evaluation: ActionEvaluationConfig {
                selection: ActionSelectionStrategy::FirstMatch,
            },
            verification: None,
            provenance: None,
        }
    }
}
