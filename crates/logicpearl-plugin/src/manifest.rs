// SPDX-License-Identifier: MIT
use super::schema_subset::validate_declared_schema;
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const DEFAULT_PLUGIN_TIMEOUT_MS: u64 = 30_000;

/// The pipeline stage a plugin implements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginStage {
    Observer,
    TraceSource,
    Enricher,
    Verify,
    Render,
}

/// JSON manifest describing a plugin's entrypoint, capabilities, and schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    #[serde(default)]
    pub plugin_id: Option<String>,
    #[serde(default)]
    pub plugin_version: Option<String>,
    pub protocol_version: String,
    pub stage: PluginStage,
    pub entrypoint: Vec<String>,
    pub language: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub options_schema: Option<Value>,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(skip)]
    pub manifest_dir: Option<PathBuf>,
    #[serde(skip)]
    pub manifest_path: Option<PathBuf>,
}

/// Security policy controlling plugin execution privileges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginExecutionPolicy {
    pub default_timeout_ms: u64,
    pub allow_no_timeout: bool,
    pub allow_absolute_entrypoint: bool,
    pub allow_path_lookup: bool,
}

impl Default for PluginExecutionPolicy {
    fn default() -> Self {
        Self {
            default_timeout_ms: DEFAULT_PLUGIN_TIMEOUT_MS,
            allow_no_timeout: false,
            allow_absolute_entrypoint: false,
            allow_path_lookup: false,
        }
    }
}

impl PluginExecutionPolicy {
    #[must_use]
    pub fn trusted_local() -> Self {
        Self {
            allow_no_timeout: true,
            allow_absolute_entrypoint: true,
            allow_path_lookup: true,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_default_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.default_timeout_ms = timeout_ms;
        self
    }

    #[must_use]
    pub fn with_allow_no_timeout(mut self, allow: bool) -> Self {
        self.allow_no_timeout = allow;
        self
    }

    #[must_use]
    pub fn with_allow_absolute_entrypoint(mut self, allow: bool) -> Self {
        self.allow_absolute_entrypoint = allow;
        self
    }

    #[must_use]
    pub fn with_allow_path_lookup(mut self, allow: bool) -> Self {
        self.allow_path_lookup = allow;
        self
    }
}

impl PluginManifest {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut manifest: Self = serde_json::from_str(&content)?;
        manifest.manifest_dir = path.parent().map(Path::to_path_buf);
        manifest.manifest_path = Some(path.to_path_buf());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(LogicPearlError::message(
                "plugin manifest name must be non-empty",
            ));
        }
        if self
            .plugin_id
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(LogicPearlError::message(
                "plugin manifest plugin_id must be non-empty when present",
            ));
        }
        if self
            .plugin_version
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(LogicPearlError::message(
                "plugin manifest plugin_version must be non-empty when present",
            ));
        }
        if self.protocol_version != "1" {
            return Err(LogicPearlError::message(format!(
                "unsupported plugin protocol_version: {}",
                self.protocol_version
            )));
        }
        if self.entrypoint.is_empty() {
            return Err(LogicPearlError::message(
                "plugin manifest entrypoint must contain at least one command segment",
            ));
        }
        validate_declared_schema("input_schema", self.input_schema.as_ref())?;
        validate_declared_schema("options_schema", self.options_schema.as_ref())?;
        validate_declared_schema("output_schema", self.output_schema.as_ref())?;
        Ok(())
    }

    pub fn supports_capability(&self, capability: &str) -> bool {
        self.capabilities
            .as_ref()
            .map(|caps| caps.iter().any(|item| item == capability))
            .unwrap_or(false)
    }
}
