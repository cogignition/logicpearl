// SPDX-License-Identifier: MIT
use clap::Args;
use logicpearl_benchmark::sanitize_identifier;
use logicpearl_core::{
    ArtifactKind, ArtifactManifestFiles, ArtifactManifestV1, ARTIFACT_MANIFEST_SCHEMA_VERSION,
};
use logicpearl_discovery::{BuildResult, OutputFiles};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, DerivedFeatureDefinition, DerivedFeatureOperator,
    Expression, FeatureDefinition, FeatureType, InputSchema, LogicPearlActionIr, LogicPearlGateIr,
};
use logicpearl_pipeline::PipelineDefinition;
use logicpearl_runtime::{artifact_hash, sha256_prefixed, LOGICPEARL_ENGINE_VERSION};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const EMBEDDED_NATIVE_RUNNER_MAGIC: &[u8; 16] = b"LPEARL_RUNNER_V1";
const EMBEDDED_NATIVE_RUNNER_TRAILER_LEN: u64 = 24;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedArtifactManifest {
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    artifact_id: Option<String>,
    #[serde(default)]
    artifact_kind: Option<String>,
    #[serde(default)]
    engine_version: Option<String>,
    #[serde(default)]
    ir_version: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    artifact_hash: Option<String>,
    #[serde(default)]
    artifact_version: String,
    #[serde(default)]
    artifact_name: String,
    #[serde(default)]
    gate_id: String,
    files: NamedArtifactFiles,
    #[serde(default)]
    bundle: ArtifactBundleDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedArtifactFiles {
    #[serde(alias = "ir")]
    pearl_ir: String,
    #[serde(default)]
    build_report: String,
    #[serde(default)]
    feature_dictionary: Option<String>,
    #[serde(default, alias = "native")]
    native_binary: Option<String>,
    #[serde(default, alias = "wasm")]
    wasm_module: Option<String>,
    #[serde(default)]
    wasm_metadata: Option<String>,
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

struct ArtifactManifestContext {
    manifest_path: Option<PathBuf>,
    base_dir: PathBuf,
    manifest: ArtifactManifestV1,
    raw_manifest: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmArtifactMetadata {
    artifact_version: String,
    engine_version: String,
    artifact_hash: String,
    decision_kind: String,
    gate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_action: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    actions: Vec<String>,
    entrypoint: String,
    status_entrypoint: String,
    allow_entrypoint: String,
    feature_count: usize,
    missing_value: String,
    features: Vec<WasmFeatureDescriptor>,
    #[serde(default)]
    derived_features: Vec<WasmDerivedFeatureDescriptor>,
    string_codes: BTreeMap<String, u32>,
    rules: Vec<WasmRuleMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmFeatureDescriptor {
    id: String,
    index: usize,
    #[serde(rename = "type")]
    feature_type: FeatureType,
    encoding: WasmFeatureEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmDerivedFeatureDescriptor {
    id: String,
    op: DerivedFeatureOperator,
    left_feature: String,
    right_feature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WasmFeatureEncoding {
    Numeric,
    Boolean,
    StringCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmRuleMetadata {
    id: String,
    bit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u32>,
    label: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    counterfactual_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct WasmArtifactOutput {
    pub(crate) module_path: PathBuf,
    pub(crate) metadata_path: PathBuf,
}

#[derive(Debug, Clone, Copy, Default)]
struct UsedWasmOperators {
    eq: bool,
    gt: bool,
    gte: bool,
    lt: bool,
    lte: bool,
    ratio: bool,
}

#[derive(Debug, Clone)]
enum CompilablePearl {
    Gate(LogicPearlGateIr),
    Action(LogicPearlActionIr),
}

#[derive(Debug, Clone, Copy)]
struct WasmRuleView<'a> {
    id: &'a str,
    bit: u32,
    expression: &'a Expression,
    action: Option<&'a str>,
    priority: Option<u32>,
    label: Option<&'a String>,
    message: Option<&'a String>,
    severity: Option<&'a String>,
    counterfactual_hint: Option<&'a String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedArtifactInput {
    pub(crate) artifact_dir: PathBuf,
    pub(crate) pearl_ir: PathBuf,
}

pub(crate) fn resolve_artifact_input(path: &Path) -> Result<ResolvedArtifactInput> {
    if path.is_dir() {
        let manifest_path = path.join("artifact.json");
        if manifest_path.exists() {
            let pearl_ir = load_manifest_pearl_ir(&manifest_path)?;
            return Ok(ResolvedArtifactInput {
                artifact_dir: path.to_path_buf(),
                pearl_ir: resolve_manifest_path(&manifest_path, &pearl_ir)?,
            });
        }

        let pearl_ir = path.join("pearl.ir.json");
        if pearl_ir.exists() {
            return Ok(ResolvedArtifactInput {
                artifact_dir: path.to_path_buf(),
                pearl_ir,
            });
        }

        return Err(miette::miette!(
            "artifact directory {} is missing artifact.json and pearl.ir.json\n\nHint: Pass a LogicPearl build output directory or a direct pearl.ir.json path.",
            path.display()
        ));
    }

    if path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        let pearl_ir = load_manifest_pearl_ir(path)?;
        return Ok(ResolvedArtifactInput {
            artifact_dir: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            pearl_ir: resolve_manifest_path(path, &pearl_ir)?,
        });
    }

    Ok(ResolvedArtifactInput {
        artifact_dir: path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        pearl_ir: path.to_path_buf(),
    })
}

pub(crate) fn pearl_artifact_id(pearl_ir: &Path) -> Result<String> {
    Ok(CompilablePearl::from_path(pearl_ir)?
        .artifact_id()
        .to_string())
}

impl CompilablePearl {
    fn from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read pearl IR")?;
        Self::from_json_str(&content)
    }

    fn from_json_str(input: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(input)
            .into_diagnostic()
            .wrap_err("pearl IR is not valid JSON")?;
        if value.get("action_policy_id").is_some() {
            let policy = LogicPearlActionIr::from_json_str(input)
                .into_diagnostic()
                .wrap_err("pearl IR is not a valid action policy")?;
            Ok(Self::Action(policy))
        } else {
            let gate = LogicPearlGateIr::from_json_str(input)
                .into_diagnostic()
                .wrap_err("pearl IR is not a valid gate")?;
            Ok(Self::Gate(gate))
        }
    }

    fn artifact_id(&self) -> &str {
        match self {
            Self::Gate(gate) => &gate.gate_id,
            Self::Action(policy) => &policy.action_policy_id,
        }
    }

    fn decision_kind(&self) -> &'static str {
        match self {
            Self::Gate(_) => "gate",
            Self::Action(_) => "action",
        }
    }

    fn input_schema(&self) -> &InputSchema {
        match self {
            Self::Gate(gate) => &gate.input_schema,
            Self::Action(policy) => &policy.input_schema,
        }
    }

    fn wasm_rules(&self) -> Vec<WasmRuleView<'_>> {
        match self {
            Self::Gate(gate) => gate
                .rules
                .iter()
                .map(|rule| WasmRuleView {
                    id: &rule.id,
                    bit: rule.bit,
                    expression: &rule.deny_when,
                    action: None,
                    priority: None,
                    label: rule.label.as_ref(),
                    message: rule.message.as_ref(),
                    severity: rule.severity.as_ref(),
                    counterfactual_hint: rule.counterfactual_hint.as_ref(),
                })
                .collect(),
            Self::Action(policy) => policy
                .rules
                .iter()
                .map(|rule| WasmRuleView {
                    id: &rule.id,
                    bit: rule.bit,
                    expression: &rule.predicate,
                    action: Some(&rule.action),
                    priority: Some(rule.priority),
                    label: rule.label.as_ref(),
                    message: rule.message.as_ref(),
                    severity: rule.severity.as_ref(),
                    counterfactual_hint: rule.counterfactual_hint.as_ref(),
                })
                .collect(),
        }
    }

    fn default_action(&self) -> Option<&str> {
        match self {
            Self::Gate(_) => None,
            Self::Action(policy) => Some(&policy.default_action),
        }
    }

    fn actions(&self) -> &[String] {
        match self {
            Self::Gate(_) => &[],
            Self::Action(policy) => &policy.actions,
        }
    }
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
    artifact_name: &str,
    gate_id: &str,
    output_files: &OutputFiles,
    feature_dictionary_path: Option<&Path>,
    build_options_hash: Option<String>,
) -> Result<()> {
    let native_path = output_files.native_binary.as_ref().map(PathBuf::from);
    let wasm_path = output_files.wasm_module.as_ref().map(PathBuf::from);
    let wasm_metadata_path = output_files.wasm_metadata.as_ref().map(PathBuf::from);
    let mut extensions = BTreeMap::new();
    extensions.insert("artifact_version".to_string(), json!("1.0"));
    extensions.insert("artifact_name".to_string(), json!(artifact_name));
    extensions.insert("gate_id".to_string(), json!(gate_id));
    extensions.insert(
        "bundle".to_string(),
        serde_json::to_value(build_artifact_bundle_descriptor(output_files)).into_diagnostic()?,
    );
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
            extensions,
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

fn manifest_member_without_base_prefix(base_dir: &Path, path: &Path) -> Option<PathBuf> {
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

pub(crate) fn load_artifact_bundle_descriptor(
    artifact_dir: &Path,
) -> Result<Option<ArtifactBundleDescriptor>> {
    let manifest_path = artifact_dir.join("artifact.json");
    if !manifest_path.exists() {
        return Ok(None);
    }
    let manifest = load_named_artifact_manifest(&manifest_path)?;
    if manifest.bundle.bundle_kind.is_empty() {
        return Ok(Some(build_bundle_descriptor_from_named_files(
            &manifest.files,
        )));
    }
    Ok(Some(manifest.bundle))
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

fn load_artifact_manifest_context(path: &Path) -> Result<ArtifactManifestContext> {
    if path.is_dir() {
        let manifest_path = path.join("artifact.json");
        if manifest_path.exists() {
            return load_manifest_file(&manifest_path);
        }
        let pipeline_path = path.join("pipeline.json");
        if pipeline_path.exists() {
            return derive_manifest_from_artifact_file(&pipeline_path);
        }
        let ir_path = path.join("pearl.ir.json");
        if ir_path.exists() {
            return derive_manifest_from_artifact_file(&ir_path);
        }
    }
    if path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        return load_manifest_file(path);
    }
    derive_manifest_from_artifact_file(path)
}

fn load_manifest_file(path: &Path) -> Result<ArtifactManifestContext> {
    let raw_manifest = read_json_file(path)?;
    let base_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let manifest = if raw_manifest.get("schema_version").and_then(Value::as_str)
        == Some(ARTIFACT_MANIFEST_SCHEMA_VERSION)
    {
        serde_json::from_value(raw_manifest.clone())
            .into_diagnostic()
            .wrap_err("artifact manifest does not match v1 shape")?
    } else {
        legacy_manifest_from_value(&base_dir, &raw_manifest)?
    };
    Ok(ArtifactManifestContext {
        manifest_path: Some(path.to_path_buf()),
        base_dir,
        manifest,
        raw_manifest: Some(raw_manifest),
    })
}

fn derive_manifest_from_artifact_file(path: &Path) -> Result<ArtifactManifestContext> {
    let value = read_json_file(path)?;
    let base_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let relative = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let (artifact_kind, artifact_id, ir_version, input_schema_hash) =
        artifact_identity_from_value(&value)?;
    let file_hash = hash_file_canonical_if_json(path)?;
    let mut file_hashes = BTreeMap::new();
    file_hashes.insert("ir".to_string(), file_hash);
    let files = ArtifactManifestFiles {
        ir: relative,
        build_report: None,
        feature_dictionary: None,
        wasm: None,
        wasm_metadata: None,
        native: None,
        extensions: BTreeMap::new(),
    };
    let artifact_hash_value = artifact_hash(&value);
    Ok(ArtifactManifestContext {
        manifest_path: None,
        base_dir,
        manifest: ArtifactManifestV1 {
            schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
            artifact_id,
            artifact_kind,
            engine_version: LOGICPEARL_ENGINE_VERSION.to_string(),
            ir_version,
            created_at: current_timestamp()?,
            artifact_hash: artifact_hash_value.clone(),
            files: files.clone(),
            input_schema_hash,
            feature_dictionary_hash: None,
            build_options_hash: None,
            file_hashes,
            bundle_hash: Some(artifact_hash(&json!({
                "artifact_hash": artifact_hash_value,
                "files": files.clone(),
            }))),
            extensions: BTreeMap::new(),
        },
        raw_manifest: None,
    })
}

fn legacy_manifest_from_value(base_dir: &Path, value: &Value) -> Result<ArtifactManifestV1> {
    let files_value = value
        .get("files")
        .ok_or_else(|| miette::miette!("artifact manifest is missing files"))?;
    let ir = files_value
        .get("ir")
        .or_else(|| files_value.get("pearl_ir"))
        .and_then(Value::as_str)
        .ok_or_else(|| miette::miette!("artifact manifest is missing files.ir"))?
        .to_string();
    let ir_path = resolve_manifest_member_path(base_dir, &ir)?;
    let ir_value = read_json_file(&ir_path)?;
    let (artifact_kind, artifact_id, ir_version, input_schema_hash) =
        artifact_identity_from_value(&ir_value)?;
    let build_report = files_value
        .get("build_report")
        .or_else(|| files_value.get("action_report"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let feature_dictionary = files_value
        .get("feature_dictionary")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let native = files_value
        .get("native")
        .or_else(|| files_value.get("native_binary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let wasm = files_value
        .get("wasm")
        .or_else(|| files_value.get("wasm_module"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let wasm_metadata = files_value
        .get("wasm_metadata")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let mut file_hashes = BTreeMap::new();
    insert_file_hash(base_dir, &mut file_hashes, "ir", Some(&ir))?;
    insert_file_hash(
        base_dir,
        &mut file_hashes,
        "build_report",
        build_report.as_deref(),
    )?;
    insert_file_hash(
        base_dir,
        &mut file_hashes,
        "feature_dictionary",
        feature_dictionary.as_deref(),
    )?;
    insert_file_hash(base_dir, &mut file_hashes, "native", native.as_deref())?;
    insert_file_hash(base_dir, &mut file_hashes, "wasm", wasm.as_deref())?;
    insert_file_hash(
        base_dir,
        &mut file_hashes,
        "wasm_metadata",
        wasm_metadata.as_deref(),
    )?;
    let files = ArtifactManifestFiles {
        ir,
        build_report,
        feature_dictionary,
        wasm,
        wasm_metadata,
        native,
        extensions: BTreeMap::new(),
    };
    let artifact_hash_value = artifact_hash(&ir_value);
    Ok(ArtifactManifestV1 {
        schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
        artifact_id: value
            .get("artifact_id")
            .or_else(|| value.get("gate_id"))
            .or_else(|| value.get("artifact_name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or(artifact_id),
        artifact_kind,
        engine_version: value
            .get("engine_version")
            .and_then(Value::as_str)
            .unwrap_or(LOGICPEARL_ENGINE_VERSION)
            .to_string(),
        ir_version,
        created_at: value
            .get("created_at")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or(current_timestamp()?),
        artifact_hash: value
            .get("artifact_hash")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or(artifact_hash_value.clone()),
        files: files.clone(),
        input_schema_hash,
        feature_dictionary_hash: None,
        build_options_hash: None,
        file_hashes,
        bundle_hash: Some(artifact_hash(&json!({
            "artifact_hash": artifact_hash_value,
            "files": files.clone(),
        }))),
        extensions: BTreeMap::new(),
    })
}

fn artifact_identity_from_value(
    value: &Value,
) -> Result<(ArtifactKind, String, String, Option<String>)> {
    if value.get("pipeline_version").is_some() {
        return Ok((
            ArtifactKind::Pipeline,
            value
                .get("pipeline_id")
                .and_then(Value::as_str)
                .unwrap_or("logicpearl_pipeline")
                .to_string(),
            value
                .get("pipeline_version")
                .and_then(Value::as_str)
                .unwrap_or("1.0")
                .to_string(),
            None,
        ));
    }
    if value.get("action_policy_id").is_some() {
        return Ok((
            ArtifactKind::Action,
            value
                .get("action_policy_id")
                .and_then(Value::as_str)
                .unwrap_or("logicpearl_action")
                .to_string(),
            value
                .get("ir_version")
                .and_then(Value::as_str)
                .unwrap_or("1.0")
                .to_string(),
            value.get("input_schema").map(artifact_hash),
        ));
    }
    Ok((
        ArtifactKind::Gate,
        value
            .get("gate_id")
            .and_then(Value::as_str)
            .unwrap_or("logicpearl_gate")
            .to_string(),
        value
            .get("ir_version")
            .and_then(Value::as_str)
            .unwrap_or("1.0")
            .to_string(),
        value.get("input_schema").map(artifact_hash),
    ))
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

fn manifest_file_roles(files: &ArtifactManifestFiles) -> Vec<(String, String)> {
    let mut roles = vec![("ir".to_string(), files.ir.clone())];
    if let Some(path) = &files.build_report {
        roles.push(("build_report".to_string(), path.clone()));
    }
    if let Some(path) = &files.feature_dictionary {
        roles.push(("feature_dictionary".to_string(), path.clone()));
    }
    if let Some(path) = &files.native {
        roles.push(("native".to_string(), path.clone()));
    }
    if let Some(path) = &files.wasm {
        roles.push(("wasm".to_string(), path.clone()));
    }
    if let Some(path) = &files.wasm_metadata {
        roles.push(("wasm_metadata".to_string(), path.clone()));
    }
    roles
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
    let files = NamedArtifactFiles {
        pearl_ir: file_name_or_fallback(&output_files.pearl_ir, "pearl.ir.json"),
        build_report: file_name_or_fallback(&output_files.build_report, "build_report.json"),
        feature_dictionary: None,
        native_binary: output_files.native_binary.as_ref().and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        wasm_module: output_files.wasm_module.as_ref().and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        wasm_metadata: output_files.wasm_metadata.as_ref().and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
    };
    build_bundle_descriptor_from_named_files(&files)
}

fn build_bundle_descriptor_from_named_files(
    files: &NamedArtifactFiles,
) -> ArtifactBundleDescriptor {
    build_deployable_bundle_descriptor(
        files.native_binary.clone(),
        files.wasm_module.clone(),
        files.wasm_metadata.clone(),
    )
}

fn file_name_or_fallback(path: &str, fallback: &str) -> String {
    PathBuf::from(path)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(fallback))
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn persist_build_report(result: &BuildResult) -> Result<()> {
    fs::write(
        &result.output_files.build_report,
        serde_json::to_string_pretty(result).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to update build report")?;
    Ok(())
}

pub(crate) fn compile_native_runner(
    pearl_ir: &Path,
    artifact_dir: &Path,
    gate_id: &str,
    name: Option<String>,
    target_triple: Option<String>,
    output: Option<PathBuf>,
) -> Result<PathBuf> {
    let pearl_name = name.unwrap_or_else(|| gate_id.to_string());
    let output_path = output.unwrap_or_else(|| {
        native_artifact_output_path(artifact_dir, &pearl_name, target_triple.as_deref())
    });
    if should_use_embedded_native_runner(target_triple.as_deref()) {
        return compile_embedded_native_runner(pearl_ir, &output_path);
    }

    let workspace_root = workspace_root();
    let generated_root = generated_build_root(&workspace_root);
    let crate_name = unique_generated_crate_name(&format!(
        "logicpearl_compiled_{}",
        sanitize_identifier(&pearl_name)
    ));
    let build_dir = generated_root.join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated compile directory")?;

    let logicpearl_ir_dep =
        dependency_spec(&workspace_root, "logicpearl-ir", "crates/logicpearl-ir");
    let logicpearl_runtime_dep = dependency_spec(
        &workspace_root,
        "logicpearl-runtime",
        "crates/logicpearl-runtime",
    );
    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nlogicpearl-ir = {logicpearl_ir_dep}\nlogicpearl-runtime = {logicpearl_runtime_dep}\nserde_json = \"1\"\n",
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated Cargo.toml")?;

    let escaped_pearl_path = pearl_ir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('\"', "\\\"");
    let main_rs = generated_native_runner_source(&escaped_pearl_path);
    fs::write(src_dir.join("main.rs"), main_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated runner source")?;

    let mut command = std::process::Command::new("cargo");
    command
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--manifest-path")
        .arg(build_dir.join("Cargo.toml"));
    if let Some(target_triple) = &target_triple {
        command.arg("--target").arg(target_triple);
    }
    let status = command
        .status()
        .into_diagnostic()
        .wrap_err(
            "failed to invoke cargo for cross-target native pearl compilation; install Rust/Cargo and make sure `cargo` is on PATH",
        )?;
    if !status.success() {
        return Err(miette::miette!(
            "cross-target native pearl compilation failed with status {status}\n\nHint: same-host native compile is self-contained. Non-host `--target` builds run `cargo build --offline --release`; make sure Rust/Cargo is installed, required crates are present in Cargo's local cache, and the requested target plus linker/toolchain is installed."
        ));
    }

    let built_binary = build_dir
        .join("target")
        .join(target_triple.as_deref().unwrap_or(""))
        .join("release")
        .join(binary_file_name(&crate_name, target_triple.as_deref()));
    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&built_binary, &output_path)
        .into_diagnostic()
        .wrap_err("failed to copy compiled pearl binary")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output_path)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl permissions")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&output_path, perms)
            .into_diagnostic()
            .wrap_err("failed to mark compiled pearl executable")?;
    }

    cleanup_generated_build_dir(&build_dir);
    Ok(output_path)
}

fn compile_embedded_native_runner(pearl_ir: &Path, output_path: &Path) -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current LogicPearl executable for native compilation")?;
    let pearl_payload = fs::read(pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to read pearl IR for native runner payload")?;

    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&current_exe, output_path)
        .into_diagnostic()
        .wrap_err("failed to copy LogicPearl executable as native pearl runner")?;

    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(output_path)
        .into_diagnostic()
        .wrap_err("failed to open native pearl runner for payload embedding")?;
    output
        .write_all(&pearl_payload)
        .into_diagnostic()
        .wrap_err("failed to write native pearl runner payload")?;
    output
        .write_all(&(pearl_payload.len() as u64).to_le_bytes())
        .into_diagnostic()
        .wrap_err("failed to write native pearl runner payload length")?;
    output
        .write_all(EMBEDDED_NATIVE_RUNNER_MAGIC)
        .into_diagnostic()
        .wrap_err("failed to write native pearl runner payload marker")?;

    mark_executable(output_path)?;
    Ok(output_path.to_path_buf())
}

fn generated_native_runner_source(escaped_pearl_path: &str) -> String {
    format!(
        "use logicpearl_ir::{{LogicPearlActionIr, LogicPearlGateIr}};\nuse logicpearl_runtime::{{evaluate_action_policy, evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\nuse std::fs;\nuse std::io::Read;\nuse std::process::ExitCode;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn main() -> ExitCode {{\n    match run() {{\n        Ok(()) => ExitCode::SUCCESS,\n        Err(err) => {{\n            eprintln!(\"{{}}\", err);\n            ExitCode::FAILURE\n        }}\n    }}\n}}\n\nfn run() -> Result<(), Box<dyn std::error::Error>> {{\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() != 2 {{\n        return Err(\"usage: compiled-pearl <input.json>\".into());\n    }}\n    let input = if args[1] == \"-\" {{\n        let mut buffer = String::new();\n        std::io::stdin().read_to_string(&mut buffer)?;\n        buffer\n    }} else {{\n        fs::read_to_string(&args[1])?\n    }};\n    let payload: Value = serde_json::from_str(&input)?;\n    let parsed = parse_input_payload(payload)?;\n    let pearl_value: Value = serde_json::from_str(PEARL_JSON)?;\n    if pearl_value.get(\"action_policy_id\").is_some() {{\n        let policy = LogicPearlActionIr::from_json_str(PEARL_JSON)?;\n        let mut outputs = Vec::with_capacity(parsed.len());\n        for input in parsed {{\n            outputs.push(evaluate_action_policy(&policy, &input)?);\n        }}\n        if outputs.len() == 1 {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs[0])?);\n        }} else {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n        }}\n    }} else {{\n        let gate = LogicPearlGateIr::from_json_str(PEARL_JSON)?;\n        let mut outputs = Vec::with_capacity(parsed.len());\n        for input in parsed {{\n            outputs.push(evaluate_gate(&gate, &input)?);\n        }}\n        if outputs.len() == 1 {{\n            println!(\"{{}}\", outputs[0]);\n        }} else {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n        }}\n    }}\n    Ok(())\n}}\n"
    )
}

pub(crate) fn run_embedded_native_runner_if_present() -> Result<bool> {
    let Some(payload) = read_embedded_native_runner_payload()? else {
        return Ok(false);
    };
    let pearl_json = std::str::from_utf8(&payload)
        .into_diagnostic()
        .wrap_err("embedded pearl payload is not valid UTF-8")?;
    let pearl = CompilablePearl::from_json_str(pearl_json)
        .wrap_err("embedded pearl payload is not valid LogicPearl IR")?;
    let args = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if args.len() != 1 {
        return Err(miette::miette!("usage: compiled-pearl <input.json>"));
    }
    if args[0].as_os_str() == "--help" || args[0].as_os_str() == "-h" {
        println!("usage: compiled-pearl <input.json>");
        return Ok(true);
    }

    let input = if args[0].as_os_str() == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl input JSON from stdin")?;
        buffer
    } else {
        fs::read_to_string(&args[0])
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl input JSON")?
    };
    let payload: Value = serde_json::from_str(&input)
        .into_diagnostic()
        .wrap_err("compiled pearl input is not valid JSON")?;
    let parsed = logicpearl_runtime::parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("compiled pearl input does not match the expected payload shape")?;
    match pearl {
        CompilablePearl::Gate(gate) => {
            let mut outputs = Vec::with_capacity(parsed.len());
            for input in parsed {
                outputs.push(
                    logicpearl_runtime::evaluate_gate(&gate, &input)
                        .into_diagnostic()
                        .wrap_err("failed to evaluate compiled pearl")?,
                );
            }
            if outputs.len() == 1 {
                println!("{}", outputs[0]);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outputs).into_diagnostic()?
                );
            }
        }
        CompilablePearl::Action(policy) => {
            let mut outputs = Vec::with_capacity(parsed.len());
            for input in parsed {
                outputs.push(
                    logicpearl_runtime::evaluate_action_policy(&policy, &input)
                        .into_diagnostic()
                        .wrap_err("failed to evaluate compiled action policy")?,
                );
            }
            if outputs.len() == 1 {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outputs).into_diagnostic()?
                );
            }
        }
    }
    Ok(true)
}

fn read_embedded_native_runner_payload() -> Result<Option<Vec<u8>>> {
    let current_exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current executable")?;
    let mut file = fs::File::open(&current_exe)
        .into_diagnostic()
        .wrap_err("failed to open current executable")?;
    let executable_len = file
        .metadata()
        .into_diagnostic()
        .wrap_err("failed to read current executable metadata")?
        .len();
    if executable_len < EMBEDDED_NATIVE_RUNNER_TRAILER_LEN {
        return Ok(None);
    }

    file.seek(SeekFrom::End(-(EMBEDDED_NATIVE_RUNNER_TRAILER_LEN as i64)))
        .into_diagnostic()
        .wrap_err("failed to seek current executable payload trailer")?;
    let mut trailer = [0u8; EMBEDDED_NATIVE_RUNNER_TRAILER_LEN as usize];
    file.read_exact(&mut trailer)
        .into_diagnostic()
        .wrap_err("failed to read current executable payload trailer")?;
    if &trailer[8..] != EMBEDDED_NATIVE_RUNNER_MAGIC {
        return Ok(None);
    }

    let payload_len = u64::from_le_bytes(
        trailer[..8]
            .try_into()
            .expect("payload length trailer should be exactly 8 bytes"),
    );
    let max_payload_len = executable_len - EMBEDDED_NATIVE_RUNNER_TRAILER_LEN;
    if payload_len > max_payload_len {
        return Err(miette::miette!(
            "embedded pearl payload length exceeds executable size"
        ));
    }
    let payload_start = max_payload_len - payload_len;
    file.seek(SeekFrom::Start(payload_start))
        .into_diagnostic()
        .wrap_err("failed to seek embedded pearl payload")?;
    let mut payload = vec![0u8; payload_len as usize];
    file.read_exact(&mut payload)
        .into_diagnostic()
        .wrap_err("failed to read embedded pearl payload")?;
    Ok(Some(payload))
}

fn should_use_embedded_native_runner(target_triple: Option<&str>) -> bool {
    match target_triple {
        None => true,
        Some(target) => current_host_target_triple()
            .map(|host| host == target)
            .unwrap_or(false),
    }
}

fn current_host_target_triple() -> Option<&'static str> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        return Some("x86_64-unknown-linux-gnu");
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        return Some("aarch64-unknown-linux-gnu");
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        return Some("x86_64-apple-darwin");
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        return Some("aarch64-apple-darwin");
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    {
        return Some("x86_64-pc-windows-msvc");
    }
    #[cfg(all(target_arch = "aarch64", target_os = "windows", target_env = "msvc"))]
    {
        return Some("aarch64-pc-windows-msvc");
    }
    #[allow(unreachable_code)]
    None
}

fn mark_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl permissions")?
            .permissions();
        permissions.set_mode(permissions.mode() | 0o755);
        fs::set_permissions(path, permissions)
            .into_diagnostic()
            .wrap_err("failed to mark compiled pearl executable")?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn compile_wasm_module(
    pearl_ir: &Path,
    artifact_dir: &Path,
    artifact_id: &str,
    name: Option<String>,
    output: Option<PathBuf>,
) -> Result<WasmArtifactOutput> {
    let pearl_name = name.unwrap_or_else(|| artifact_id.to_string());
    let output_path =
        output.unwrap_or_else(|| wasm_artifact_output_path(artifact_dir, &pearl_name));
    let metadata_path = wasm_metadata_path_for_module(&output_path);
    let workspace_root = workspace_root();
    let generated_root = generated_build_root(&workspace_root);
    let crate_name = unique_generated_crate_name(&format!(
        "logicpearl_compiled_{}_wasm",
        sanitize_identifier(&pearl_name)
    ));
    let pearl = CompilablePearl::from_path(pearl_ir)
        .wrap_err("failed to load pearl IR for wasm compilation")?;
    if let Some(rule) = pearl.wasm_rules().into_iter().find(|rule| rule.bit >= 64) {
        return Err(miette::miette!(
            "wasm compilation currently supports only rule bits 0-63; artifact `{}` includes rule `{}` at bit {}\n\nHint: Use the native compile target for wider artifacts, or keep wasm-targeted artifacts at 64 rules or fewer for now.",
            pearl.artifact_id(),
            rule.id,
            rule.bit
        ));
    }
    let build_dir = generated_root.join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated wasm compile directory")?;

    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[workspace]\n\n[profile.release]\nopt-level = \"z\"\nlto = true\ncodegen-units = 1\npanic = \"abort\"\nstrip = \"symbols\"\n"
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm Cargo.toml")?;

    let lib_rs = generate_wasm_runner_source_for_pearl(&pearl);
    fs::write(src_dir.join("lib.rs"), lib_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm runner source")?;
    write_wasm_metadata_for_pearl(&metadata_path, &pearl)?;

    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--manifest-path")
        .arg(build_dir.join("Cargo.toml"))
        .status()
        .into_diagnostic()
        .wrap_err(
            "failed to invoke cargo for wasm pearl compilation; install Rust/Cargo and make sure `cargo` is on PATH",
        )?;
    if !status.success() {
        return Err(miette::miette!(
            "wasm pearl compilation failed with status {status}\n\nHint: `logicpearl compile --target wasm32-unknown-unknown` runs `cargo build --offline --release --target wasm32-unknown-unknown`. Install Rust/Cargo, make sure required crates are present in Cargo's local cache, then install the target with `rustup target add wasm32-unknown-unknown`."
        ));
    }

    let built_module = build_dir
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(format!("{crate_name}.wasm"));
    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&built_module, &output_path)
        .into_diagnostic()
        .wrap_err("failed to copy compiled pearl wasm module")?;
    cleanup_generated_build_dir(&build_dir);
    Ok(WasmArtifactOutput {
        module_path: output_path,
        metadata_path,
    })
}

fn wasm_metadata_path_for_module(module_path: &Path) -> PathBuf {
    let file_name = module_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pearl.wasm");
    let metadata_name = file_name
        .strip_suffix(".wasm")
        .map(|stem| format!("{stem}.wasm.meta.json"))
        .unwrap_or_else(|| format!("{file_name}.meta.json"));
    module_path.with_file_name(metadata_name)
}

#[cfg(test)]
fn write_wasm_metadata(path: &Path, gate: &LogicPearlGateIr) -> Result<()> {
    write_wasm_metadata_for_pearl(path, &CompilablePearl::Gate(gate.clone()))
}

fn write_wasm_metadata_for_pearl(path: &Path, pearl: &CompilablePearl) -> Result<()> {
    let wasm_rules = pearl.wasm_rules();
    let string_codes = build_string_codes(pearl.input_schema(), &wasm_rules);
    let input_features = pearl
        .input_schema()
        .features
        .iter()
        .filter(|feature| feature.derived.is_none())
        .collect::<Vec<_>>();
    let metadata = WasmArtifactMetadata {
        artifact_version: "1.0".to_string(),
        engine_version: logicpearl_runtime::LOGICPEARL_ENGINE_VERSION.to_string(),
        artifact_hash: match pearl {
            CompilablePearl::Gate(gate) => logicpearl_runtime::artifact_hash(gate),
            CompilablePearl::Action(policy) => logicpearl_runtime::artifact_hash(policy),
        },
        decision_kind: pearl.decision_kind().to_string(),
        gate_id: pearl.artifact_id().to_string(),
        action_policy_id: matches!(pearl, CompilablePearl::Action(_))
            .then(|| pearl.artifact_id().to_string()),
        default_action: pearl.default_action().map(ToOwned::to_owned),
        actions: pearl.actions().to_vec(),
        entrypoint: "logicpearl_eval_bitmask_slots_f64".to_string(),
        status_entrypoint: "logicpearl_eval_status_slots_f64".to_string(),
        allow_entrypoint: "logicpearl_eval_allow_slots_f64".to_string(),
        feature_count: input_features.len(),
        missing_value: "NaN".to_string(),
        features: input_features
            .iter()
            .enumerate()
            .map(|(index, feature)| WasmFeatureDescriptor {
                id: feature.id.clone(),
                index,
                feature_type: feature.feature_type.clone(),
                encoding: match feature.feature_type {
                    FeatureType::Bool => WasmFeatureEncoding::Boolean,
                    FeatureType::Int | FeatureType::Float => WasmFeatureEncoding::Numeric,
                    FeatureType::String | FeatureType::Enum => WasmFeatureEncoding::StringCode,
                },
            })
            .collect(),
        derived_features: pearl
            .input_schema()
            .features
            .iter()
            .filter_map(|feature| {
                feature
                    .derived
                    .as_ref()
                    .map(|derived| WasmDerivedFeatureDescriptor {
                        id: feature.id.clone(),
                        op: derived.op.clone(),
                        left_feature: derived.left_feature.clone(),
                        right_feature: derived.right_feature.clone(),
                    })
            })
            .collect(),
        string_codes,
        rules: wasm_rules
            .iter()
            .map(|rule| WasmRuleMetadata {
                id: rule.id.to_string(),
                bit: rule.bit,
                action: rule.action.map(ToOwned::to_owned),
                priority: rule.priority,
                label: rule.label.cloned(),
                message: rule.message.cloned(),
                severity: rule.severity.cloned(),
                counterfactual_hint: rule.counterfactual_hint.cloned(),
            })
            .collect(),
    };
    fs::write(
        path,
        serde_json::to_string_pretty(&metadata).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write wasm metadata")?;
    Ok(())
}

#[cfg(test)]
fn generate_wasm_runner_source(gate: &LogicPearlGateIr) -> String {
    generate_wasm_runner_source_for_pearl(&CompilablePearl::Gate(gate.clone()))
}

fn generate_wasm_runner_source_for_pearl(pearl: &CompilablePearl) -> String {
    let wasm_rules = pearl.wasm_rules();
    let input_features = pearl
        .input_schema()
        .features
        .iter()
        .filter(|feature| feature.derived.is_none())
        .collect::<Vec<_>>();
    let feature_indexes: HashMap<&str, usize> = input_features
        .iter()
        .enumerate()
        .map(|(index, feature)| (feature.id.as_str(), index))
        .collect();
    let feature_defs: HashMap<&str, &FeatureDefinition> = pearl
        .input_schema()
        .features
        .iter()
        .map(|feature| (feature.id.as_str(), feature))
        .collect();
    let derived_identifiers: HashMap<&str, String> = pearl
        .input_schema()
        .features
        .iter()
        .filter(|feature| feature.derived.is_some())
        .map(|feature| {
            (
                feature.id.as_str(),
                format!("derived_{}", sanitize_identifier(&feature.id)),
            )
        })
        .collect();
    let string_codes = build_string_codes(pearl.input_schema(), &wasm_rules);
    let mut used_ops = collect_used_comparison_operators(&wasm_rules);
    collect_used_derived_operators(pearl.input_schema(), &mut used_ops);
    let derived_assignments = pearl
        .input_schema()
        .features
        .iter()
        .filter_map(|feature| {
            let derived = feature.derived.as_ref()?;
            let variable = derived_identifiers[feature.id.as_str()].clone();
            let expression =
                emit_wasm_derived_expression(derived, &feature_indexes, &derived_identifiers);
            Some(format!("    let {variable} = {expression};\n"))
        })
        .collect::<String>();

    let mut rule_source = String::new();
    for rule in &wasm_rules {
        let expression = emit_wasm_expression(
            rule.expression,
            &feature_defs,
            &feature_indexes,
            &derived_identifiers,
            &string_codes,
        );
        let condition = wasm_if_condition(&expression);
        rule_source.push_str(&format!(
            "    if {condition} {{ bitmask |= 1u64 << {}; }}\n",
            rule.bit
        ));
    }
    let mut helpers =
        String::from("#[inline]\nfn slot(values: &[f64], index: usize) -> f64 { values[index] }\n");
    if used_ops.eq {
        helpers.push_str(
            "\n#[inline]\nfn eq_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && (left - right).abs() < f64::EPSILON }\n",
        );
    }
    if used_ops.gt {
        helpers.push_str(
            "\n#[inline]\nfn gt_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left > right }\n",
        );
    }
    if used_ops.gte {
        helpers.push_str(
            "\n#[inline]\nfn gte_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left >= right }\n",
        );
    }
    if used_ops.lt {
        helpers.push_str(
            "\n#[inline]\nfn lt_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left < right }\n",
        );
    }
    if used_ops.lte {
        helpers.push_str(
            "\n#[inline]\nfn lte_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left <= right }\n",
        );
    }
    if used_ops.ratio {
        helpers.push_str(
            "\n#[inline]\nfn ratio_num(left: f64, right: f64) -> f64 {\n    if left.is_nan() || right.is_nan() || right.abs() < f64::EPSILON {\n        0.0\n    } else {\n        let value = left / right;\n        if value.is_finite() { value } else { 0.0 }\n    }\n}\n",
        );
    }

    format!(
        "const FEATURE_COUNT: usize = {};\nconst LOGICPEARL_STATUS_OK: u32 = 0;\nconst LOGICPEARL_STATUS_NULL_PTR: u32 = 1;\nconst LOGICPEARL_STATUS_INSUFFICIENT_LEN: u32 = 2;\n\n{helpers}\n\nfn evaluate(values: &[f64]) -> u64 {{\n    let mut bitmask = 0u64;\n{derived_assignments}{rules}    bitmask\n}}\n\n#[inline]\nfn validate_slots(ptr: *const f64, len: usize) -> u32 {{\n    if ptr.is_null() {{\n        return LOGICPEARL_STATUS_NULL_PTR;\n    }}\n    if len < FEATURE_COUNT {{\n        return LOGICPEARL_STATUS_INSUFFICIENT_LEN;\n    }}\n    LOGICPEARL_STATUS_OK\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_alloc(len: usize) -> *mut u8 {{\n    let mut bytes = Vec::<u8>::with_capacity(len);\n    let ptr = bytes.as_mut_ptr();\n    std::mem::forget(bytes);\n    ptr\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_dealloc(ptr: *mut u8, capacity: usize) {{\n    if ptr.is_null() {{\n        return;\n    }}\n    unsafe {{\n        let _ = Vec::from_raw_parts(ptr, 0, capacity);\n    }}\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_status_slots_f64(ptr: *const f64, len: usize) -> u32 {{\n    validate_slots(ptr, len)\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_bitmask_slots_f64(ptr: *const f64, len: usize) -> u64 {{\n    if validate_slots(ptr, len) != LOGICPEARL_STATUS_OK {{\n        return 0;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    evaluate(values)\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_allow_slots_f64(ptr: *const f64, len: usize) -> u32 {{\n    if validate_slots(ptr, len) != LOGICPEARL_STATUS_OK {{\n        return 2;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    if evaluate(values) == 0 {{ 1 }} else {{ 0 }}\n}}\n",
        input_features.len(),
        helpers = helpers,
        derived_assignments = derived_assignments,
        rules = rule_source,
    )
}

fn wasm_if_condition(expression: &str) -> &str {
    expression
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(expression)
}

fn collect_used_comparison_operators(rules: &[WasmRuleView<'_>]) -> UsedWasmOperators {
    let mut ops = UsedWasmOperators::default();
    for rule in rules {
        collect_expression_operators(rule.expression, &mut ops);
    }
    ops
}

fn collect_expression_operators(expression: &Expression, ops: &mut UsedWasmOperators) {
    match expression {
        Expression::Comparison(comparison) => match comparison.op {
            ComparisonOperator::Eq
            | ComparisonOperator::Ne
            | ComparisonOperator::In
            | ComparisonOperator::NotIn => {
                ops.eq = true;
            }
            ComparisonOperator::Gt => ops.gt = true,
            ComparisonOperator::Gte => ops.gte = true,
            ComparisonOperator::Lt => ops.lt = true,
            ComparisonOperator::Lte => ops.lte = true,
        },
        Expression::All { all } => {
            for child in all {
                collect_expression_operators(child, ops);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_expression_operators(child, ops);
            }
        }
        Expression::Not { expr } => collect_expression_operators(expr, ops),
    }
}

fn collect_used_derived_operators(input_schema: &InputSchema, ops: &mut UsedWasmOperators) {
    for feature in &input_schema.features {
        match feature.derived.as_ref().map(|derived| &derived.op) {
            Some(DerivedFeatureOperator::Ratio) => ops.ratio = true,
            Some(DerivedFeatureOperator::Difference) | None => {}
        }
    }
}

fn emit_wasm_expression(
    expression: &Expression,
    feature_defs: &HashMap<&str, &FeatureDefinition>,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    match expression {
        Expression::Comparison(comparison) => emit_wasm_comparison(
            comparison,
            feature_defs,
            feature_indexes,
            derived_identifiers,
            string_codes,
        ),
        Expression::All { all } => format!(
            "({})",
            all.iter()
                .map(|child| emit_wasm_expression(
                    child,
                    feature_defs,
                    feature_indexes,
                    derived_identifiers,
                    string_codes
                ))
                .collect::<Vec<_>>()
                .join(" && ")
        ),
        Expression::Any { any } => format!(
            "({})",
            any.iter()
                .map(|child| emit_wasm_expression(
                    child,
                    feature_defs,
                    feature_indexes,
                    derived_identifiers,
                    string_codes
                ))
                .collect::<Vec<_>>()
                .join(" || ")
        ),
        Expression::Not { expr } => format!(
            "(!{})",
            emit_wasm_expression(
                expr,
                feature_defs,
                feature_indexes,
                derived_identifiers,
                string_codes,
            )
        ),
    }
}

fn emit_wasm_comparison(
    comparison: &ComparisonExpression,
    feature_defs: &HashMap<&str, &FeatureDefinition>,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    let left = emit_wasm_feature_source(&comparison.feature, feature_indexes, derived_identifiers);
    let feature_type = &feature_defs[comparison.feature.as_str()].feature_type;

    if let Some(feature_ref) = comparison.value.feature_ref() {
        let right = emit_wasm_feature_source(feature_ref, feature_indexes, derived_identifiers);
        return emit_operator_expr(comparison.op.clone(), &left, &right);
    }

    let literal = comparison
        .value
        .literal()
        .expect("literal comparison must provide a literal value");
    match comparison.op {
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let values = literal
                .as_array()
                .expect("in/not_in literal must be an array")
                .iter()
                .map(|item| emit_literal_value(feature_type, item, string_codes))
                .map(|item| format!("eq_num({left}, {item})"))
                .collect::<Vec<_>>()
                .join(" || ");
            if matches!(comparison.op, ComparisonOperator::NotIn) {
                format!("(!({values}))")
            } else {
                format!("({values})")
            }
        }
        _ => {
            let right = emit_literal_value(feature_type, literal, string_codes);
            emit_operator_expr(comparison.op.clone(), &left, &right)
        }
    }
}

fn emit_wasm_derived_expression(
    derived: &DerivedFeatureDefinition,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
) -> String {
    let left =
        emit_wasm_feature_source(&derived.left_feature, feature_indexes, derived_identifiers);
    let right =
        emit_wasm_feature_source(&derived.right_feature, feature_indexes, derived_identifiers);
    match derived.op {
        DerivedFeatureOperator::Difference => format!("({left} - {right})"),
        DerivedFeatureOperator::Ratio => format!("ratio_num({left}, {right})"),
    }
}

fn emit_wasm_feature_source(
    feature_id: &str,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
) -> String {
    if let Some(index) = feature_indexes.get(feature_id) {
        return format!("slot(values, {index})");
    }
    derived_identifiers
        .get(feature_id)
        .cloned()
        .expect("derived feature should have generated identifier")
}

fn emit_operator_expr(op: ComparisonOperator, left: &str, right: &str) -> String {
    match op {
        ComparisonOperator::Eq => format!("eq_num({left}, {right})"),
        ComparisonOperator::Ne => format!("(!eq_num({left}, {right}))"),
        ComparisonOperator::Gt => format!("gt_num({left}, {right})"),
        ComparisonOperator::Gte => format!("gte_num({left}, {right})"),
        ComparisonOperator::Lt => format!("lt_num({left}, {right})"),
        ComparisonOperator::Lte => format!("lte_num({left}, {right})"),
        ComparisonOperator::In | ComparisonOperator::NotIn => unreachable!("handled earlier"),
    }
}

fn emit_literal_value(
    feature_type: &FeatureType,
    literal: &Value,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    match feature_type {
        FeatureType::Bool => {
            if literal.as_bool().unwrap_or(false) {
                "1.0".to_string()
            } else {
                "0.0".to_string()
            }
        }
        FeatureType::Int | FeatureType::Float => rust_f64_literal(
            literal
                .as_f64()
                .expect("numeric literal must be representable as f64"),
        ),
        FeatureType::String | FeatureType::Enum => {
            let key = string_key(literal);
            let code = string_codes
                .get(&key)
                .expect("string literal should have been assigned a wasm metadata code");
            rust_f64_literal(*code as f64)
        }
    }
}

fn rust_f64_literal(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        format!("{value:?}")
    }
}

fn build_string_codes(
    input_schema: &InputSchema,
    rules: &[WasmRuleView<'_>],
) -> BTreeMap<String, u32> {
    let mut values = BTreeMap::new();
    for feature in &input_schema.features {
        if matches!(
            feature.feature_type,
            FeatureType::String | FeatureType::Enum
        ) {
            if let Some(feature_values) = &feature.values {
                for value in feature_values {
                    let key = string_key(value);
                    let next = values.len() as u32;
                    values.entry(key).or_insert(next);
                }
            }
        }
    }
    for rule in rules {
        collect_expression_strings(rule.expression, &mut values);
    }
    values
}

fn collect_expression_strings(expression: &Expression, values: &mut BTreeMap<String, u32>) {
    match expression {
        Expression::Comparison(comparison) => {
            if let Some(literal) = comparison.value.literal() {
                collect_literal_strings(literal, values);
            }
        }
        Expression::All { all } => {
            for child in all {
                collect_expression_strings(child, values);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_expression_strings(child, values);
            }
        }
        Expression::Not { expr } => collect_expression_strings(expr, values),
    }
}

fn collect_literal_strings(literal: &Value, values: &mut BTreeMap<String, u32>) {
    match literal {
        Value::String(_) => {
            let key = string_key(literal);
            let next = values.len() as u32;
            values.entry(key).or_insert(next);
        }
        Value::Array(items) => {
            for item in items {
                collect_literal_strings(item, values);
            }
        }
        _ => {}
    }
}

fn string_key(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

pub(crate) fn is_rust_target_installed(target: &str) -> bool {
    std::process::Command::new("rustup")
        .arg("target")
        .arg("list")
        .arg("--installed")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.lines().any(|line| line.trim() == target))
        .unwrap_or(false)
}

fn load_named_artifact_manifest(path: &Path) -> Result<NamedArtifactManifest> {
    serde_json::from_str(
        &fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read artifact manifest")?,
    )
    .into_diagnostic()
    .wrap_err("artifact manifest is not valid JSON")
}

fn load_manifest_pearl_ir(path: &Path) -> Result<String> {
    let value: Value = serde_json::from_str(
        &fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read artifact manifest")?,
    )
    .into_diagnostic()
    .wrap_err("artifact manifest is not valid JSON")?;
    value
        .get("files")
        .and_then(|files| files.get("ir").or_else(|| files.get("pearl_ir")))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| miette::miette!("artifact manifest is missing files.ir"))
}

pub(crate) fn resolve_manifest_member_path(base_dir: &Path, raw_path: &str) -> Result<PathBuf> {
    let candidate = PathBuf::from(raw_path);
    let joined = resolve_manifest_member_relative_path(base_dir, &candidate, raw_path)?;
    if joined.exists() {
        return Ok(joined);
    }

    if let Some(relative) = manifest_member_without_base_prefix(base_dir, &candidate) {
        let repaired = resolve_manifest_member_relative_path(base_dir, &relative, raw_path)?;
        if repaired.exists() {
            return Ok(repaired);
        }
    }

    Ok(joined)
}

fn resolve_manifest_member_relative_path(
    base_dir: &Path,
    candidate: &Path,
    raw_path: &str,
) -> Result<PathBuf> {
    let relative = normalize_manifest_member_path(candidate, raw_path)?;
    let joined = base_dir.join(relative);
    ensure_existing_manifest_member_is_under_base(base_dir, &joined, raw_path)?;
    Ok(joined)
}

fn normalize_manifest_member_path(candidate: &Path, raw_path: &str) -> Result<PathBuf> {
    let mut parts = Vec::<OsString>::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(miette::miette!(
                        "artifact manifest member path escapes artifact directory: {raw_path}"
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(miette::miette!(
                    "artifact manifest member path must be relative to the artifact directory: {raw_path}"
                ));
            }
        }
    }

    if parts.is_empty() {
        return Err(miette::miette!(
            "artifact manifest member path is empty and must be relative to the artifact directory"
        ));
    }

    let mut normalized = PathBuf::new();
    for part in parts {
        normalized.push(part);
    }
    Ok(normalized)
}

fn ensure_existing_manifest_member_is_under_base(
    base_dir: &Path,
    path: &Path,
    raw_path: &str,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let canonical_base = fs::canonicalize(base_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to canonicalize artifact directory {}",
                base_dir.display()
            )
        })?;
    let canonical_path = fs::canonicalize(path).into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to canonicalize artifact manifest member {}",
            path.display()
        )
    })?;

    if !canonical_path.starts_with(&canonical_base) {
        return Err(miette::miette!(
            "artifact manifest member path escapes artifact directory: {raw_path}"
        ));
    }

    Ok(())
}

fn resolve_manifest_path(manifest_path: &Path, raw_path: &str) -> Result<PathBuf> {
    resolve_manifest_member_path(
        manifest_path.parent().unwrap_or_else(|| Path::new(".")),
        raw_path,
    )
}

fn artifact_file_stem(name: &str) -> String {
    let sanitized = sanitize_identifier(name);
    if sanitized.is_empty() {
        "pearl".to_string()
    } else {
        sanitized
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
}

fn generated_build_root(workspace_root: &Path) -> PathBuf {
    if has_workspace_sources(workspace_root) {
        workspace_root.join("target").join("generated")
    } else {
        std::env::temp_dir()
            .join("logicpearl")
            .join("target")
            .join("generated")
    }
}

fn cleanup_generated_build_dir(build_dir: &Path) {
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

fn unique_generated_crate_name(prefix: &str) -> String {
    static NEXT_GENERATED_BUILD_ID: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = NEXT_GENERATED_BUILD_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{}_{}_{}", std::process::id(), nanos, counter)
}

fn dependency_spec(workspace_root: &Path, crate_name: &str, relative_path: &str) -> String {
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

fn binary_file_name(base: &str, target_triple: Option<&str>) -> String {
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
        ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig, Expression,
        FeatureDefinition, FeatureType, GateType, InputSchema, LogicPearlActionIr,
        LogicPearlGateIr, RuleDefinition, RuleKind,
    };
    use serde_json::Value;
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
            parent_error.contains("escapes artifact directory"),
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
            error.contains("escapes artifact directory"),
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
                    semantics: None,
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
                    semantics: None,
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
