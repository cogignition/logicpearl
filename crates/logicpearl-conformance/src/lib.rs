use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_runtime::evaluate_gate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFingerprint {
    pub path: String,
    pub size_bytes: u64,
    pub mtime_ns: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactManifest {
    pub manifest_version: String,
    pub generated_at: String,
    pub source_control: BTreeMap<String, String>,
    pub source_files: BTreeMap<String, FileFingerprint>,
    pub data_files: BTreeMap<String, FileFingerprint>,
    pub artifacts: BTreeMap<String, FileFingerprint>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FreshnessReport {
    pub fresh: bool,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuntimeParityReport {
    pub total_rows: usize,
    pub matching_rows: usize,
    pub parity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTraceRow {
    pub features: BTreeMap<String, Value>,
    pub allowed: bool,
}

pub fn status() -> Result<&'static str> {
    Ok("artifact manifest validation and runtime parity available")
}

pub fn fingerprint_path(path: &Path) -> Result<FileFingerprint> {
    let stat = path.metadata()?;
    Ok(FileFingerprint {
        path: path.display().to_string(),
        size_bytes: stat.len(),
        mtime_ns: stat
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| LogicPearlError::message(format!("could not fingerprint mtime: {err}")))?
            .as_nanos(),
    })
}

pub fn write_artifact_manifest(manifest: &ArtifactManifest, path: &Path) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(manifest)? + "\n")?;
    Ok(())
}

pub fn build_artifact_manifest(
    generated_at: String,
    source_control: BTreeMap<String, String>,
    source_files: BTreeMap<String, String>,
    data_files: BTreeMap<String, String>,
    artifacts: BTreeMap<String, String>,
) -> Result<ArtifactManifest> {
    Ok(ArtifactManifest {
        manifest_version: "1.0".to_string(),
        generated_at,
        source_control,
        source_files: fingerprint_group(source_files)?,
        data_files: fingerprint_group(data_files)?,
        artifacts: fingerprint_group(artifacts)?,
    })
}

pub fn load_artifact_manifest(path: &Path) -> Result<ArtifactManifest> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub fn validate_artifact_manifest(path: &Path) -> Result<FreshnessReport> {
    let manifest = load_artifact_manifest(path)?;
    let mut problems = Vec::new();
    validate_group("source_files", &manifest.source_files, &mut problems);
    validate_group("data_files", &manifest.data_files, &mut problems);
    validate_group("artifacts", &manifest.artifacts, &mut problems);
    Ok(FreshnessReport {
        fresh: problems.is_empty(),
        problems,
    })
}

pub fn compare_runtime_parity(gate: &LogicPearlGateIr, rows: &[DecisionTraceRow]) -> Result<RuntimeParityReport> {
    if rows.is_empty() {
        return Err(LogicPearlError::message(
            "runtime parity requires at least one labeled decision trace row",
        ));
    }
    let mut matching_rows = 0usize;
    for row in rows {
        let bitmask = evaluate_gate(gate, &row.features.iter().map(|(k, v)| (k.clone(), v.clone())).collect())?;
        let predicted_allowed = bitmask == 0;
        if predicted_allowed == row.allowed {
            matching_rows += 1;
        }
    }
    let parity = matching_rows as f64 / rows.len() as f64;
    Ok(RuntimeParityReport {
        total_rows: rows.len(),
        matching_rows,
        parity,
    })
}

fn validate_group(group_name: &str, fingerprints: &BTreeMap<String, FileFingerprint>, problems: &mut Vec<String>) {
    for (label, fingerprint) in fingerprints {
        let path = Path::new(&fingerprint.path);
        if !path.exists() {
            problems.push(format!("{group_name}:{label} missing: {}", path.display()));
            continue;
        }
        match fingerprint_path(path) {
            Ok(actual) => {
                if actual.size_bytes != fingerprint.size_bytes || actual.mtime_ns != fingerprint.mtime_ns {
                    problems.push(format!(
                        "{group_name}:{label} changed: {} (expected size={}, mtime_ns={}; found size={}, mtime_ns={})",
                        path.display(),
                        fingerprint.size_bytes,
                        fingerprint.mtime_ns,
                        actual.size_bytes,
                        actual.mtime_ns
                    ));
                }
            }
            Err(err) => {
                problems.push(format!(
                    "{group_name}:{label} could not be fingerprinted: {} ({err})",
                    path.display()
                ));
            }
        }
    }
}

fn fingerprint_group(entries: BTreeMap<String, String>) -> Result<BTreeMap<String, FileFingerprint>> {
    entries
        .into_iter()
        .map(|(label, path)| {
            let fingerprint = fingerprint_path(Path::new(&path))?;
            Ok((label, fingerprint))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        compare_runtime_parity, fingerprint_path, validate_artifact_manifest, ArtifactManifest, DecisionTraceRow,
    };
    use logicpearl_ir::LogicPearlGateIr;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    #[test]
    fn validates_fresh_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, "hello\n").unwrap();
        let manifest_path = dir.path().join("artifact_manifest.json");
        let fingerprint = fingerprint_path(&source).unwrap();
        let manifest = ArtifactManifest {
            manifest_version: "1.0".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            source_control: BTreeMap::new(),
            source_files: BTreeMap::from([("source".to_string(), fingerprint)]),
            data_files: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        };
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

        let report = validate_artifact_manifest(&manifest_path).unwrap();
        assert!(report.fresh);
        assert!(report.problems.is_empty());
    }

    #[test]
    fn runtime_parity_matches_simple_gate() {
        let gate = LogicPearlGateIr::from_json_str(
            &serde_json::to_string(&json!({
                "ir_version": "1.0",
                "gate_id": "demo",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [{"id": "flag", "type": "int", "description": null, "values": null, "min": null, "max": null, "editable": null}]
                },
                "rules": [{
                    "id": "rule_000",
                    "kind": "predicate",
                    "bit": 0,
                    "deny_when": {"feature": "flag", "op": ">", "value": 0},
                    "label": null,
                    "message": null,
                    "severity": null,
                    "counterfactual_hint": null,
                    "verification_status": "pipeline_unverified"
                }],
                "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
                "verification": null,
                "provenance": null
            }))
            .unwrap(),
        )
        .unwrap();
        let rows = vec![
            DecisionTraceRow {
                features: BTreeMap::from([("flag".to_string(), Value::from(0))]),
                allowed: true,
            },
            DecisionTraceRow {
                features: BTreeMap::from([("flag".to_string(), Value::from(1))]),
                allowed: false,
            },
        ];

        let report = compare_runtime_parity(&gate, &rows).unwrap();
        assert_eq!(report.total_rows, 2);
        assert_eq!(report.matching_rows, 2);
        assert_eq!(report.parity, 1.0);
    }
}
