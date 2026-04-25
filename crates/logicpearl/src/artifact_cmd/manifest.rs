// SPDX-License-Identifier: MIT
use logicpearl_core::{
    load_artifact_bundle, ArtifactKind, ArtifactManifestFiles, ArtifactManifestV1,
    ARTIFACT_MANIFEST_SCHEMA_VERSION,
};
use logicpearl_discovery::{build_result_for_report, BuildResult, OutputFiles};
use logicpearl_runtime::{artifact_hash, sha256_prefixed, LOGICPEARL_ENGINE_VERSION};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::pearl::CompilablePearl;
use super::verify::load_artifact_manifest_context;
use super::{artifact_file_stem, binary_file_name};

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
    let value = read_json_file(pearl_ir)?;
    if let Some(pipeline_id) = value.get("pipeline_id").and_then(Value::as_str) {
        return Ok(pipeline_id.to_string());
    }
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
    let mut bundle = build_deployable_bundle_descriptor(
        native_file.clone(),
        wasm_file.clone(),
        wasm_metadata_file,
    );
    if context.manifest.artifact_kind == ArtifactKind::Pipeline {
        bundle.bundle_kind = context
            .manifest
            .extensions
            .get("pipeline_type")
            .and_then(Value::as_str)
            .map(|kind| format!("{kind}_pipeline_bundle"))
            .unwrap_or_else(|| "pipeline_bundle".to_string());
        bundle.primary_runtime = native_file
            .as_ref()
            .map(|_| "native_binary".to_string())
            .or_else(|| wasm_file.as_ref().map(|_| "wasm_module".to_string()))
            .or_else(|| Some("pipeline.json".to_string()));
    }

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

pub(super) fn read_json_file(path: &Path) -> Result<Value> {
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
            .or_else(|| value.get("schema_version"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                miette::miette!("pipeline artifact is missing pipeline_version or schema_version")
            }),
    }
}

pub(super) fn relative_manifest_file(base_dir: &Path, path: &Path, fallback: &str) -> String {
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
    if let Some(relative) = manifest_output_member_path(base_dir, path) {
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

fn manifest_output_member_path(base_dir: &Path, path: &Path) -> Option<PathBuf> {
    if let Ok(relative) = path.strip_prefix(base_dir) {
        if !relative.as_os_str().is_empty() {
            return Some(relative.to_path_buf());
        }
    }

    let base_name = base_dir.file_name()?;
    let mut components = path.components();
    let first = components.next()?;
    if first.as_os_str() == base_name {
        let relative = components.as_path();
        if !relative.as_os_str().is_empty() {
            return Some(relative.to_path_buf());
        }
    }
    None
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

pub(super) fn hash_file_canonical_if_json(path: &Path) -> Result<String> {
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
