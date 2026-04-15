// SPDX-License-Identifier: MIT
use miette::{IntoDiagnostic, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub(super) fn path_from_json(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| miette::miette!("expected JSON string path, found {value}"))
}

pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_str(&fs::read_to_string(path).into_diagnostic()?).into_diagnostic()
}

pub(super) fn write_json_pretty(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(value).into_diagnostic()?
        ),
    )
    .into_diagnostic()?;
    Ok(())
}

pub(super) fn copy_dir_all(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).into_diagnostic()?;
    for entry in fs::read_dir(source).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let file_type = entry.file_type().into_diagnostic()?;
        let dest_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path).into_diagnostic()?;
        }
    }
    Ok(())
}

pub(super) fn copy_plugin_bundle(source_manifest: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let source_dir = source_manifest.parent().ok_or_else(|| {
        miette::miette!(
            "plugin manifest has no parent: {}",
            source_manifest.display()
        )
    })?;
    if dest_dir.exists() {
        fs::remove_dir_all(dest_dir).into_diagnostic()?;
    }
    copy_dir_all(source_dir, dest_dir)?;
    Ok(dest_dir.join("manifest.json"))
}

pub(super) fn build_artifact_hashes(bundle_dir: &Path) -> Result<Value> {
    let mut hashes = BTreeMap::new();
    for path in walk_files(bundle_dir)? {
        let relative = path.strip_prefix(bundle_dir).into_diagnostic()?;
        hashes.insert(relative.display().to_string(), sha256_file(&path)?);
    }
    serde_json::to_value(hashes).into_diagnostic()
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        let file_type = entry.file_type().into_diagnostic()?;
        if file_type.is_dir() {
            files.extend(walk_files(&path)?);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).into_diagnostic()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer).into_diagnostic()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub(super) fn read_jsonl_rows<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = File::open(path).into_diagnostic()?;
    let mut rows = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.into_diagnostic()?;
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(&line).into_diagnostic()?);
    }
    Ok(rows)
}
