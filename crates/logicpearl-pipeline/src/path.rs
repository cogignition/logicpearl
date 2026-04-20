// SPDX-License-Identifier: MIT

use logicpearl_core::{resolve_manifest_member_path, LogicPearlError, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn resolve_relative_path(base_dir: &Path, value: &str) -> Result<PathBuf> {
    resolve_manifest_member_path(base_dir, value)
}

pub(crate) fn sanitize_stage_id(value: &str, index: usize) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        format!("stage_{}", index + 1)
    } else {
        out
    }
}

pub(crate) fn manifest_member_path_for_base(base_dir: &Path, path: &Path) -> Result<String> {
    let relative = if let Ok(relative) = path.strip_prefix(base_dir) {
        relative.to_path_buf()
    } else {
        let canonical_base = fs::canonicalize(base_dir).map_err(|error| {
            LogicPearlError::message(format!(
                "failed to canonicalize pipeline bundle directory {}: {error}",
                base_dir.display()
            ))
        })?;
        let canonical_path = fs::canonicalize(path).map_err(|error| {
            LogicPearlError::message(format!(
                "failed to canonicalize pipeline artifact {}: {error}",
                path.display()
            ))
        })?;
        canonical_path
            .strip_prefix(&canonical_base)
            .map(Path::to_path_buf)
            .map_err(|_| {
                LogicPearlError::message(format!(
                    "compose artifact must be inside the pipeline bundle directory: {}",
                    path.display()
                ))
            })?
    };

    let rendered = relative.display().to_string();
    resolve_manifest_member_path(base_dir, &rendered)?;
    Ok(rendered)
}

pub(crate) fn parse_document<T>(content: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    match serde_json::from_str(content) {
        Ok(value) => Ok(value),
        Err(json_error) => serde_norway::from_str(content).map_err(|yaml_error| {
            LogicPearlError::message(format!(
                "document is not valid JSON or YAML: JSON error: {json_error}; YAML error: {yaml_error}"
            ))
        }),
    }
}
