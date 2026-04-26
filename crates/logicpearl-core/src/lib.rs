// SPDX-License-Identifier: MIT
//! Shared primitives used across LogicPearl crates.
//!
//! This crate owns small cross-cutting contracts that should not live in the
//! CLI: common errors, artifact-manifest constants, path confinement helpers,
//! and the rule bitmask type. Higher-level crates build on these primitives
//! when loading, validating, and rendering LogicPearl artifacts.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::Digest;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Stable schema identifier for LogicPearl artifact bundle manifests.
pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: &str = "logicpearl.artifact_manifest.v1";

/// Render an error message as a short coaching card.
///
/// LogicPearl errors should leave users with three concrete answers: what the
/// command expected, what it found instead, and the next command to run. Keep
/// this string-only so low-level crates can use it without depending on the CLI
/// diagnostics stack.
pub fn coaching_error_message(
    message: impl AsRef<str>,
    expected: impl AsRef<str>,
    found: impl AsRef<str>,
    next: impl AsRef<str>,
) -> String {
    format!(
        "{}\n\nExpected: {}\nFound: {}\nNext: {}",
        message.as_ref(),
        expected.as_ref(),
        found.as_ref(),
        next.as_ref()
    )
}

/// Render a path for public reports without exposing local host-specific roots.
///
/// Relative paths are preserved. Absolute paths under the current working
/// directory are rendered as `./relative/path`; other absolute paths are
/// replaced with a stable digest of the path string.
pub fn provenance_safe_path(path: &Path) -> String {
    if !path.is_absolute() {
        return path.display().to_string();
    }

    if let Ok(current_dir) = std::env::current_dir() {
        for base in current_dir
            .ancestors()
            .filter(|base| base.parent().is_some())
        {
            let Ok(relative) = path.strip_prefix(base) else {
                continue;
            };
            if relative.as_os_str().is_empty() {
                return ".".to_string();
            }
            return format!("./{}", relative.display());
        }
    }

    format!(
        "<path:{}>",
        sha256_prefixed(path.to_string_lossy().as_bytes())
    )
}

/// Render a path-like string for public reports.
pub fn provenance_safe_path_string(value: &str) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        provenance_safe_path(path)
    } else {
        value.to_string()
    }
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut rendered = String::with_capacity("sha256:".len() + 64);
    rendered.push_str("sha256:");
    for byte in digest {
        write!(&mut rendered, "{byte:02x}").expect("writing to String cannot fail");
    }
    rendered
}

pub fn artifact_hash<T: Serialize>(artifact: &T) -> String {
    let value = serde_json::to_value(artifact)
        .expect("LogicPearl artifacts should serialize to canonical JSON bytes");
    let canonical = canonicalize_json_value(value);
    let bytes = serde_json::to_vec(&canonical)
        .expect("canonical LogicPearl artifact JSON should serialize");
    sha256_prefixed(&bytes)
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        Value::Object(map) => {
            let mut entries = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json_value(value)))
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut ordered = serde_json::Map::new();
            for (key, value) in entries {
                ordered.insert(key, value);
            }
            Value::Object(ordered)
        }
        other => other,
    }
}

/// Convenience alias for results returned by LogicPearl operations.
pub type Result<T> = std::result::Result<T, LogicPearlError>;

/// Errors produced by LogicPearl operations.
#[derive(Debug, Error)]
pub enum LogicPearlError {
    /// A freeform error message.
    #[error("{0}")]
    Message(String),
    /// An I/O error propagated from the standard library.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A JSON serialization or deserialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A CSV parsing error.
    #[error(transparent)]
    Csv(#[from] csv::Error),
}

impl LogicPearlError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

/// Resolve a manifest member path relative to a bundle directory.
///
/// Manifest member paths must be relative, must not traverse outside the bundle
/// directory, and existing members must not resolve through symlinks outside the
/// bundle.
pub fn resolve_manifest_member_path(base_dir: &Path, raw_path: &str) -> Result<PathBuf> {
    let candidate = PathBuf::from(raw_path);
    resolve_manifest_member_relative_path(base_dir, &candidate, raw_path)
}

/// Resolve a manifest member path relative to the manifest file's directory.
pub fn resolve_manifest_path(manifest_path: &Path, raw_path: &str) -> Result<PathBuf> {
    resolve_manifest_member_path(
        manifest_path.parent().unwrap_or_else(|| Path::new(".")),
        raw_path,
    )
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
                    return Err(LogicPearlError::message(format!(
                        "manifest member path escapes bundle directory: {raw_path}"
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(LogicPearlError::message(format!(
                    "manifest member path must be relative to the bundle directory: {raw_path}"
                )));
            }
        }
    }

    if parts.is_empty() {
        return Err(LogicPearlError::message(
            "manifest member path is empty and must be relative to the bundle directory",
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

    let canonical_base = fs::canonicalize(base_dir).map_err(|error| {
        LogicPearlError::message(format!(
            "failed to canonicalize bundle directory {}: {error}",
            base_dir.display()
        ))
    })?;
    let canonical_path = fs::canonicalize(path).map_err(|error| {
        LogicPearlError::message(format!(
            "failed to canonicalize manifest member {}: {error}",
            path.display()
        ))
    })?;

    if !canonical_path.starts_with(&canonical_base) {
        return Err(LogicPearlError::message(format!(
            "manifest member path escapes bundle directory: {raw_path}"
        )));
    }

    Ok(())
}

/// Renders an artifact value into a human-readable string.
pub trait ArtifactRenderer<T> {
    /// Produce a textual representation of `value`.
    fn render(&self, value: &T) -> Result<String>;
}

/// Stable kind names for public artifact manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Gate,
    Action,
    Pipeline,
}

/// Files declared by a LogicPearl artifact bundle manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactManifestFiles {
    /// Deterministic artifact definition: pearl.ir.json for gate/action artifacts,
    /// or a pipeline definition JSON file for pipeline artifacts.
    pub ir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_report: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_dictionary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<String>,
    /// Additional manifest-defined file roles.
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Versioned public contract for a LogicPearl artifact bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactManifestV1 {
    pub schema_version: String,
    pub artifact_id: String,
    pub artifact_kind: ArtifactKind,
    pub engine_version: String,
    pub ir_version: String,
    pub created_at: String,
    pub artifact_hash: String,
    pub files: ArtifactManifestFiles,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_dictionary_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_options_hash: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    /// Additional manifest metadata.
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Fully loaded artifact manifest plus its bundle-relative base directory.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedArtifactBundle {
    pub manifest_path: Option<PathBuf>,
    pub base_dir: PathBuf,
    pub manifest: ArtifactManifestV1,
    pub raw_manifest: Option<Value>,
}

impl LoadedArtifactBundle {
    /// Resolve `files.ir` through the manifest member confinement rules.
    pub fn ir_path(&self) -> Result<PathBuf> {
        resolve_manifest_member_path(&self.base_dir, &self.manifest.files.ir)
    }

    /// Resolve all declared files to local paths keyed by manifest role.
    pub fn resolved_files(&self) -> Result<BTreeMap<String, PathBuf>> {
        manifest_file_roles(&self.manifest.files)
            .into_iter()
            .map(|(role, path)| {
                let resolved = resolve_manifest_member_path(&self.base_dir, &path)?;
                Ok((role, resolved))
            })
            .collect()
    }
}

/// Load a LogicPearl artifact bundle, v1 artifact manifest, or direct artifact file.
///
/// This API is intentionally about artifact *resolution*, not evaluation. It
/// handles the public v1 manifest contract plus direct `pearl.ir.json` and
/// `pipeline.json` files. Callers can dispatch on `manifest.artifact_kind` and
/// then parse `ir_path()` with the appropriate IR type.
pub fn load_artifact_bundle(path: &Path) -> Result<LoadedArtifactBundle> {
    if path.is_dir() {
        let manifest_path = path.join("artifact.json");
        if manifest_path.exists() {
            return load_artifact_manifest_file(&manifest_path);
        }
        let pipeline_path = path.join("pipeline.json");
        if pipeline_path.exists() {
            return derive_artifact_bundle_from_file(&pipeline_path);
        }
        let ir_path = path.join("pearl.ir.json");
        if ir_path.exists() {
            return derive_artifact_bundle_from_file(&ir_path);
        }
        return Err(LogicPearlError::message(coaching_error_message(
            format!(
                "artifact directory {} is missing artifact.json, pipeline.json, and pearl.ir.json",
                path.display()
            ),
            "an artifact bundle directory containing artifact.json, pipeline.json, or pearl.ir.json",
            format!(
                "directory {} with none of those entrypoint files",
                path.display()
            ),
            format!(
                "build a bundle with `logicpearl build traces.csv --output-dir {}` or pass an existing artifact path",
                path.display()
            ),
        )));
    }

    if path.is_file() {
        let value = read_json_file(path)?;
        if path
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
            || value.get("schema_version").is_some()
        {
            return load_artifact_manifest_value(path, value);
        }
    }

    if !path.exists() {
        return Err(LogicPearlError::message(coaching_error_message(
            format!("artifact path {} does not exist", path.display()),
            "an artifact directory, artifact.json, pearl.ir.json, or pipeline.json",
            format!("no file or directory at {}", path.display()),
            "run `logicpearl build traces.csv --output-dir output`, then pass `output` to this command",
        )));
    }

    derive_artifact_bundle_from_file(path)
}

pub fn manifest_file_roles(files: &ArtifactManifestFiles) -> Vec<(String, String)> {
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

fn load_artifact_manifest_file(path: &Path) -> Result<LoadedArtifactBundle> {
    let raw_manifest = read_json_file(path)?;
    load_artifact_manifest_value(path, raw_manifest)
}

fn load_artifact_manifest_value(path: &Path, raw_manifest: Value) -> Result<LoadedArtifactBundle> {
    let base_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let schema_version = raw_manifest
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LogicPearlError::message(coaching_error_message(
                format!("artifact manifest {} is missing schema_version", path.display()),
                format!("schema_version: {ARTIFACT_MANIFEST_SCHEMA_VERSION:?}"),
                "an artifact manifest without schema_version",
                format!(
                    "run `logicpearl artifact verify {}` to check the bundle, or rebuild it with `logicpearl build ... --output-dir <dir>`",
                    path.display()
                ),
            ))
        })?;
    if schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION {
        return Err(LogicPearlError::message(coaching_error_message(
            format!(
                "unsupported artifact manifest schema_version {schema_version:?}; expected {ARTIFACT_MANIFEST_SCHEMA_VERSION}"
            ),
            format!("schema_version: {ARTIFACT_MANIFEST_SCHEMA_VERSION:?}"),
            format!("schema_version: {schema_version:?}"),
            "rebuild the bundle with this `logicpearl build` version, or update the CLI that reads it",
        )));
    }
    let manifest = serde_json::from_value(raw_manifest.clone())?;
    Ok(LoadedArtifactBundle {
        manifest_path: Some(path.to_path_buf()),
        base_dir,
        manifest,
        raw_manifest: Some(raw_manifest),
    })
}

fn derive_artifact_bundle_from_file(path: &Path) -> Result<LoadedArtifactBundle> {
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
        artifact_identity_from_value(&value);
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
    Ok(LoadedArtifactBundle {
        manifest_path: None,
        base_dir,
        manifest: ArtifactManifestV1 {
            schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
            artifact_id,
            artifact_kind,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            ir_version,
            created_at: "1970-01-01T00:00:00Z".to_string(),
            artifact_hash: artifact_hash_value.clone(),
            files: files.clone(),
            input_schema_hash,
            feature_dictionary_hash: None,
            build_options_hash: None,
            file_hashes,
            bundle_hash: Some(artifact_hash(&serde_json::json!({
                "artifact_hash": artifact_hash_value,
                "files": files,
            }))),
            extensions: BTreeMap::new(),
        },
        raw_manifest: None,
    })
}

fn read_json_file(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(|error| {
        LogicPearlError::message(coaching_error_message(
            format!("failed to read JSON file {}: {error}", path.display()),
            "a readable JSON file",
            format!("{} could not be read: {error}", path.display()),
            "check the path, or run `logicpearl build traces.csv --output-dir output` to create a fresh artifact",
        ))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        LogicPearlError::message(coaching_error_message(
            format!("JSON file is invalid: {}: {error}", path.display()),
            "valid JSON",
            format!("{} is not valid JSON: {error}", path.display()),
            format!(
                "run `jq empty {}` to validate the file, then rerun the LogicPearl command",
                path.display()
            ),
        ))
    })
}

fn artifact_identity_from_value(value: &Value) -> (ArtifactKind, String, String, Option<String>) {
    if value
        .get("schema_version")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema == "logicpearl.fanout_pipeline.v1")
    {
        return (
            ArtifactKind::Pipeline,
            value
                .get("pipeline_id")
                .and_then(Value::as_str)
                .unwrap_or("logicpearl_fanout")
                .to_string(),
            "logicpearl.fanout_pipeline.v1".to_string(),
            None,
        );
    }
    if value.get("pipeline_version").is_some() {
        return (
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
        );
    }
    if value.get("action_policy_id").is_some() {
        return (
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
        );
    }
    (
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
    )
}

fn hash_file_canonical_if_json(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|error| {
        LogicPearlError::message(format!(
            "failed to read file for hashing {}: {error}",
            path.display()
        ))
    })?;
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

/// Variable-width bitmask that tracks which rules matched during evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleMask {
    words: Vec<u64>,
}

impl RuleMask {
    /// Create an all-zeros mask (no rules matched).
    pub fn zero() -> Self {
        Self::default()
    }

    /// Returns `true` when no bits are set.
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Set the bit at position `bit`.
    pub fn set_bit(&mut self, bit: u32) {
        let word_index = bit as usize / 64;
        let bit_index = bit % 64;
        if self.words.len() <= word_index {
            self.words.resize(word_index + 1, 0);
        }
        self.words[word_index] |= 1_u64 << bit_index;
    }

    /// Returns `true` if the bit at position `bit` is set.
    pub fn test_bit(&self, bit: u32) -> bool {
        let word_index = bit as usize / 64;
        let bit_index = bit % 64;
        self.words
            .get(word_index)
            .map(|word| (word & (1_u64 << bit_index)) != 0)
            .unwrap_or(false)
    }

    /// If the mask fits in a single `u64`, return it; otherwise `None`.
    pub fn as_u64(&self) -> Option<u64> {
        match self.trimmed_words() {
            [] => Some(0),
            [single] => Some(*single),
            _ => None,
        }
    }

    /// Serialize this mask to a JSON number (single word) or array (multi-word).
    pub fn to_json_value(&self) -> Value {
        if let Some(single) = self.as_u64() {
            Value::Number(single.into())
        } else {
            Value::Array(
                self.trimmed_words()
                    .iter()
                    .map(|word| Value::Number((*word).into()))
                    .collect(),
            )
        }
    }

    /// Deserialize a mask from a JSON number or array of numbers.
    pub fn from_json_value(value: &Value) -> Result<Self> {
        match value {
            Value::Number(number) => number.as_u64().map(Self::from).ok_or_else(|| {
                LogicPearlError::message("bitmask number must be an unsigned integer")
            }),
            Value::Array(items) => {
                let mut words = Vec::with_capacity(items.len());
                for item in items {
                    let word = item.as_u64().ok_or_else(|| {
                        LogicPearlError::message("bitmask array items must be unsigned integers")
                    })?;
                    words.push(word);
                }
                Ok(Self::from_words(words))
            }
            _ => Err(LogicPearlError::message(
                "bitmask must be a JSON number or an array of JSON numbers",
            )),
        }
    }

    /// Build a mask from a raw vector of 64-bit words.
    pub fn from_words(words: Vec<u64>) -> Self {
        let mut mask = Self { words };
        mask.trim_trailing_zero_words();
        mask
    }

    fn trimmed_words(&self) -> &[u64] {
        let mut end = self.words.len();
        while end > 0 && self.words[end - 1] == 0 {
            end -= 1;
        }
        &self.words[..end]
    }

    fn trim_trailing_zero_words(&mut self) {
        while self.words.last().copied() == Some(0) {
            self.words.pop();
        }
    }
}

impl From<u64> for RuleMask {
    fn from(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self { words: vec![value] }
        }
    }
}

impl std::fmt::Display for RuleMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(single) = self.as_u64() {
            write!(f, "{single}")
        } else {
            write!(f, "{}", self.to_json_value())
        }
    }
}

impl Serialize for RuleMask {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(single) = self.as_u64() {
            serializer.serialize_u64(single)
        } else {
            self.trimmed_words().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RuleMask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_json_value(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{load_artifact_bundle, resolve_manifest_member_path, RuleMask};
    use serde_json::json;

    #[test]
    fn rule_mask_round_trips_small_and_wide_forms() {
        let mut wide = RuleMask::zero();
        wide.set_bit(0);
        wide.set_bit(72);
        assert_eq!(wide.to_json_value(), json!([1, 256]));
        let parsed: RuleMask = serde_json::from_value(json!([1, 256])).unwrap();
        assert_eq!(parsed, wide);

        let small: RuleMask = serde_json::from_value(json!(7)).unwrap();
        assert_eq!(small.as_u64(), Some(7));
    }

    #[test]
    fn manifest_member_paths_are_bundle_relative() {
        let dir = tempfile::tempdir().expect("temp dir");
        let bundle = dir.path().join("bundle");
        std::fs::create_dir_all(&bundle).expect("bundle dir");
        std::fs::write(bundle.join("pearl.ir.json"), "{}").expect("member file");

        assert_eq!(
            resolve_manifest_member_path(&bundle, "pearl.ir.json")
                .expect("bundle-relative member should resolve"),
            bundle.join("pearl.ir.json")
        );

        let outside = dir.path().join("outside.json");
        std::fs::write(&outside, "{}").expect("outside file");
        let absolute = resolve_manifest_member_path(&bundle, &outside.display().to_string())
            .expect_err("absolute paths should be rejected")
            .to_string();
        assert!(absolute.contains("must be relative"));

        let parent = resolve_manifest_member_path(&bundle, "../outside.json")
            .expect_err("parent escapes should be rejected")
            .to_string();
        assert!(parent.contains("escapes bundle directory"));
    }

    #[test]
    fn legacy_artifact_manifests_are_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("pearl.ir.json"), "{}").expect("ir file");
        std::fs::write(
            dir.path().join("artifact.json"),
            serde_json::to_string_pretty(&json!({
                "artifact_version": "1.0",
                "artifact_name": "legacy_gate",
                "gate_id": "legacy_gate",
                "files": {
                    "pearl_ir": "pearl.ir.json"
                }
            }))
            .expect("legacy manifest json"),
        )
        .expect("manifest file");

        let error = load_artifact_bundle(dir.path())
            .expect_err("legacy manifest should be rejected")
            .to_string();
        assert!(error.contains("missing schema_version"));
    }

    #[test]
    fn unsupported_artifact_manifest_versions_are_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join("artifact.json"),
            r#"{"schema_version":"legacy"}"#,
        )
        .expect("manifest file");

        let error = load_artifact_bundle(&dir.path().join("artifact.json"))
            .expect_err("unsupported manifest should be rejected")
            .to_string();
        assert!(error.contains("unsupported artifact manifest schema_version"));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_member_symlinks_cannot_escape_bundle() {
        let dir = tempfile::tempdir().expect("temp dir");
        let bundle = dir.path().join("bundle");
        let outside = dir.path().join("outside.json");
        let link = bundle.join("outside-link.json");
        std::fs::create_dir_all(&bundle).expect("bundle dir");
        std::fs::write(&outside, "{}").expect("outside file");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");

        let error = resolve_manifest_member_path(&bundle, "outside-link.json")
            .expect_err("symlink escapes should be rejected")
            .to_string();
        assert!(error.contains("escapes bundle directory"));
    }
}
