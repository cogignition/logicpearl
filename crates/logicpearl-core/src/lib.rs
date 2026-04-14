// SPDX-License-Identifier: MIT
//! Shared primitives used across LogicPearl crates.
//!
//! This crate owns small cross-cutting contracts that should not live in the
//! CLI: common errors, artifact-manifest constants, path confinement helpers,
//! and the rule bitmask type. Higher-level crates build on these primitives
//! when loading, validating, and rendering LogicPearl artifacts.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Stable schema identifier for LogicPearl artifact bundle manifests.
pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: &str = "logicpearl.artifact_manifest.v1";

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
/// bundle. A redundant leading bundle-directory component is accepted for
/// backward compatibility with older manifests.
pub fn resolve_manifest_member_path(base_dir: &Path, raw_path: &str) -> Result<PathBuf> {
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

/// Resolve a manifest member path relative to the manifest file's directory.
pub fn resolve_manifest_path(manifest_path: &Path, raw_path: &str) -> Result<PathBuf> {
    resolve_manifest_member_path(
        manifest_path.parent().unwrap_or_else(|| Path::new(".")),
        raw_path,
    )
}

/// Strip a redundant leading bundle-directory component from a manifest path.
pub fn manifest_member_without_base_prefix(base_dir: &Path, path: &Path) -> Option<PathBuf> {
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
    /// Backward-compatible aliases or future file roles.
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
    /// Backward-compatible aliases or future manifest metadata.
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
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
    use super::{resolve_manifest_member_path, RuleMask};
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
            resolve_manifest_member_path(&bundle, "bundle/pearl.ir.json")
                .expect("redundant bundle prefix should resolve"),
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
