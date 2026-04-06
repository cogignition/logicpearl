use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use logicpearl_core::{LogicPearlError, Result, RuleMask};
use logicpearl_ir::{ComparisonOperator, Expression, LogicPearlGateIr};
use logicpearl_runtime::{evaluate_gate, parse_input_payload};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSigningKeyFile {
    pub algorithm: String,
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPublicKeyFile {
    pub algorithm: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub receipt_version: String,
    pub generated_at: String,
    pub gate_id: String,
    pub pearl_ir_sha256: String,
    pub input_sha256: String,
    pub bitmasks: Vec<RuleMask>,
    pub all_allowed: bool,
    #[serde(default)]
    pub native_cross_check: Option<ReceiptNativeCrossCheck>,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptNativeCrossCheck {
    pub verified: bool,
    pub native_binary_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptVerificationReport {
    pub valid: bool,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCrossCheckRow {
    pub row_index: usize,
    pub runtime_bitmask: RuleMask,
    pub native_bitmask: RuleMask,
    pub expected_allowed: bool,
    pub features: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCrossCheckReport {
    pub total_rows: usize,
    pub runtime_matching_rows: usize,
    pub native_matching_rows: usize,
    pub runtime_parity: f64,
    pub native_parity: f64,
    pub runtime_native_matching_rows: usize,
    pub runtime_native_parity: f64,
    pub disagreements: Vec<RuntimeCrossCheckRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewPack {
    pub total_rows: usize,
    pub matching_rows: usize,
    pub parity: f64,
    pub mismatch_count: usize,
    pub mismatches: Vec<ReviewMismatch>,
    pub boundary_scenarios: Vec<BoundaryScenario>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewMismatch {
    pub row_index: usize,
    pub runtime_bitmask: RuleMask,
    pub expected_allowed: bool,
    pub predicted_allowed: bool,
    pub triggered_rule_ids: Vec<String>,
    pub features: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BoundaryScenario {
    pub scenario_id: String,
    pub rule_id: String,
    pub feature: String,
    pub rationale: String,
    pub features: BTreeMap<String, Value>,
    pub runtime_bitmask: RuleMask,
    pub triggered_rule_ids: Vec<String>,
}

pub fn status() -> Result<&'static str> {
    Ok("artifact manifest validation, signed receipts, review packs, and runtime cross-checks available")
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

pub fn compare_runtime_parity(
    gate: &LogicPearlGateIr,
    rows: &[DecisionTraceRow],
) -> Result<RuntimeParityReport> {
    if rows.is_empty() {
        return Err(LogicPearlError::message(
            "runtime parity requires at least one labeled decision trace row",
        ));
    }
    let runtime_bitmasks = evaluate_rows(gate, rows)?;
    let matching_rows = runtime_bitmasks
        .iter()
        .zip(rows)
        .filter(|(bitmask, row)| bitmask.is_zero() == row.allowed)
        .count();
    let parity = matching_rows as f64 / rows.len() as f64;
    Ok(RuntimeParityReport {
        total_rows: rows.len(),
        matching_rows,
        parity,
    })
}

pub fn cross_check_runtime_with_native_binary(
    gate: &LogicPearlGateIr,
    native_binary: &Path,
    rows: &[DecisionTraceRow],
) -> Result<RuntimeCrossCheckReport> {
    if rows.is_empty() {
        return Err(LogicPearlError::message(
            "runtime cross-check requires at least one labeled decision trace row",
        ));
    }

    let runtime_bitmasks = evaluate_rows(gate, rows)?;
    let native_bitmasks = evaluate_native_binary(native_binary, rows)?;
    if native_bitmasks.len() != rows.len() {
        return Err(LogicPearlError::message(format!(
            "native binary returned {} results for {} input rows",
            native_bitmasks.len(),
            rows.len()
        )));
    }

    let mut runtime_matching_rows = 0usize;
    let mut native_matching_rows = 0usize;
    let mut runtime_native_matching_rows = 0usize;
    let mut disagreements = Vec::new();

    for (index, ((runtime_bitmask, native_bitmask), row)) in runtime_bitmasks
        .iter()
        .zip(&native_bitmasks)
        .zip(rows.iter())
        .enumerate()
    {
        let runtime_allowed = runtime_bitmask.is_zero();
        let native_allowed = native_bitmask.is_zero();
        if runtime_allowed == row.allowed {
            runtime_matching_rows += 1;
        }
        if native_allowed == row.allowed {
            native_matching_rows += 1;
        }
        if runtime_bitmask == native_bitmask {
            runtime_native_matching_rows += 1;
        } else {
            disagreements.push(RuntimeCrossCheckRow {
                row_index: index,
                runtime_bitmask: runtime_bitmask.clone(),
                native_bitmask: native_bitmask.clone(),
                expected_allowed: row.allowed,
                features: row.features.clone(),
            });
        }
    }

    Ok(RuntimeCrossCheckReport {
        total_rows: rows.len(),
        runtime_matching_rows,
        native_matching_rows,
        runtime_parity: runtime_matching_rows as f64 / rows.len() as f64,
        native_parity: native_matching_rows as f64 / rows.len() as f64,
        runtime_native_matching_rows,
        runtime_native_parity: runtime_native_matching_rows as f64 / rows.len() as f64,
        disagreements,
    })
}

pub fn build_review_pack(
    gate: &LogicPearlGateIr,
    rows: &[DecisionTraceRow],
    max_boundary_scenarios: usize,
) -> Result<ReviewPack> {
    if rows.is_empty() {
        return Err(LogicPearlError::message(
            "review pack generation requires at least one labeled decision trace row",
        ));
    }

    let runtime_bitmasks = evaluate_rows(gate, rows)?;
    let matching_rows = runtime_bitmasks
        .iter()
        .zip(rows)
        .filter(|(bitmask, row)| bitmask.is_zero() == row.allowed)
        .count();

    let mismatches: Vec<ReviewMismatch> = runtime_bitmasks
        .iter()
        .zip(rows.iter())
        .enumerate()
        .filter_map(|(index, (bitmask, row))| {
            let predicted_allowed = bitmask.is_zero();
            if predicted_allowed == row.allowed {
                return None;
            }
            Some(ReviewMismatch {
                row_index: index,
                runtime_bitmask: bitmask.clone(),
                expected_allowed: row.allowed,
                predicted_allowed,
                triggered_rule_ids: triggered_rule_ids(gate, bitmask),
                features: row.features.clone(),
            })
        })
        .collect();

    let baseline = baseline_features(rows);
    let boundary_scenarios = generate_boundary_scenarios(gate, &baseline, max_boundary_scenarios)?;

    Ok(ReviewPack {
        total_rows: rows.len(),
        matching_rows,
        parity: matching_rows as f64 / rows.len() as f64,
        mismatch_count: mismatches.len(),
        mismatches,
        boundary_scenarios,
    })
}

pub fn generate_receipt_keypair() -> ReceiptSigningKeyFile {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    ReceiptSigningKeyFile {
        algorithm: "ed25519".to_string(),
        secret_key_hex: hex::encode(signing_key.to_bytes()),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
    }
}

pub fn public_key_from_signing_key(
    keypair: &ReceiptSigningKeyFile,
) -> Result<ReceiptPublicKeyFile> {
    validate_key_algorithm(&keypair.algorithm)?;
    let signing_key = signing_key_from_file(keypair)?;
    Ok(ReceiptPublicKeyFile {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
    })
}

pub fn create_signed_decision_receipt(
    gate: &LogicPearlGateIr,
    pearl_ir_path: &Path,
    input_payload: &Value,
    signing_key_file: &ReceiptSigningKeyFile,
    native_binary_path: Option<&Path>,
    generated_at: String,
) -> Result<DecisionReceipt> {
    validate_key_algorithm(&signing_key_file.algorithm)?;
    let signing_key = signing_key_from_file(signing_key_file)?;
    let inputs = parse_input_payload(input_payload.clone())?;
    let bitmasks = evaluate_payloads(gate, &inputs)?;
    let pearl_ir_sha256 = sha256_hex_path(pearl_ir_path)?;
    let input_sha256 = sha256_hex_bytes(&serde_json::to_vec(input_payload)?);
    let native_cross_check = if let Some(path) = native_binary_path {
        let native_bitmasks = evaluate_native_binary_payload(path, input_payload)?;
        if native_bitmasks != bitmasks {
            return Err(LogicPearlError::message(
                "native binary disagreed with the runtime while generating the receipt",
            ));
        }
        Some(ReceiptNativeCrossCheck {
            verified: true,
            native_binary_sha256: sha256_hex_path(path)?,
        })
    } else {
        None
    };

    let unsigned = UnsignedDecisionReceipt {
        receipt_version: "1.0".to_string(),
        generated_at,
        gate_id: gate.gate_id.clone(),
        pearl_ir_sha256,
        input_sha256,
        bitmasks,
        all_allowed: true,
        native_cross_check,
        signer_public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
    };
    let unsigned = UnsignedDecisionReceipt {
        all_allowed: unsigned.bitmasks.iter().all(RuleMask::is_zero),
        ..unsigned
    };
    let signature = signing_key.sign(&serde_json::to_vec(&unsigned)?);
    Ok(DecisionReceipt {
        receipt_version: unsigned.receipt_version,
        generated_at: unsigned.generated_at,
        gate_id: unsigned.gate_id,
        pearl_ir_sha256: unsigned.pearl_ir_sha256,
        input_sha256: unsigned.input_sha256,
        bitmasks: unsigned.bitmasks,
        all_allowed: unsigned.all_allowed,
        native_cross_check: unsigned.native_cross_check,
        signer_public_key_hex: unsigned.signer_public_key_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_decision_receipt(
    receipt: &DecisionReceipt,
    public_key: &ReceiptPublicKeyFile,
) -> Result<ReceiptVerificationReport> {
    validate_key_algorithm(&public_key.algorithm)?;
    let mut problems = Vec::new();
    if receipt.signer_public_key_hex != public_key.public_key_hex {
        problems
            .push("receipt signer public key did not match the provided public key".to_string());
    }

    let verifying_key = verifying_key_from_file(public_key)?;
    let signature_bytes = hex::decode(&receipt.signature_hex)
        .map_err(|err| LogicPearlError::message(format!("invalid signature hex: {err}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| LogicPearlError::message(format!("invalid signature bytes: {err}")))?;
    let unsigned = UnsignedDecisionReceipt {
        receipt_version: receipt.receipt_version.clone(),
        generated_at: receipt.generated_at.clone(),
        gate_id: receipt.gate_id.clone(),
        pearl_ir_sha256: receipt.pearl_ir_sha256.clone(),
        input_sha256: receipt.input_sha256.clone(),
        bitmasks: receipt.bitmasks.clone(),
        all_allowed: receipt.all_allowed,
        native_cross_check: receipt.native_cross_check.clone(),
        signer_public_key_hex: receipt.signer_public_key_hex.clone(),
    };

    if let Err(err) = verifying_key.verify(&serde_json::to_vec(&unsigned)?, &signature) {
        problems.push(format!("signature verification failed: {err}"));
    }

    Ok(ReceiptVerificationReport {
        valid: problems.is_empty(),
        problems,
    })
}

pub fn write_receipt_signing_key(keypair: &ReceiptSigningKeyFile, path: &Path) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(keypair)? + "\n")?;
    Ok(())
}

pub fn write_receipt_public_key(public_key: &ReceiptPublicKeyFile, path: &Path) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(public_key)? + "\n")?;
    Ok(())
}

pub fn load_receipt_signing_key(path: &Path) -> Result<ReceiptSigningKeyFile> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub fn load_receipt_public_key(path: &Path) -> Result<ReceiptPublicKeyFile> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub fn write_review_pack(review_pack: &ReviewPack, path: &Path) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(review_pack)? + "\n")?;
    Ok(())
}

fn evaluate_rows(gate: &LogicPearlGateIr, rows: &[DecisionTraceRow]) -> Result<Vec<RuleMask>> {
    rows.iter()
        .map(|row| {
            evaluate_gate(
                gate,
                &row.features.clone().into_iter().collect::<HashMap<_, _>>(),
            )
        })
        .collect()
}

fn evaluate_payloads(
    gate: &LogicPearlGateIr,
    inputs: &[HashMap<String, Value>],
) -> Result<Vec<RuleMask>> {
    inputs
        .iter()
        .map(|input| evaluate_gate(gate, input))
        .collect()
}

fn evaluate_native_binary(
    native_binary: &Path,
    rows: &[DecisionTraceRow],
) -> Result<Vec<RuleMask>> {
    let payload = Value::Array(
        rows.iter()
            .map(|row| {
                let mut object = Map::new();
                for (key, value) in &row.features {
                    object.insert(key.clone(), value.clone());
                }
                Value::Object(object)
            })
            .collect(),
    );
    evaluate_native_binary_payload(native_binary, &payload)
}

fn evaluate_native_binary_payload(native_binary: &Path, payload: &Value) -> Result<Vec<RuleMask>> {
    let mut temp = NamedTempFile::new()?;
    serde_json::to_writer_pretty(temp.as_file_mut(), payload)?;
    let output = Command::new(native_binary)
        .arg(temp.path())
        .output()
        .map_err(|err| {
            LogicPearlError::message(format!(
                "failed to execute native binary {}: {err}",
                native_binary.display()
            ))
        })?;
    if !output.status.success() {
        return Err(LogicPearlError::message(format!(
            "native binary {} failed: {}",
            native_binary.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_outputs = match payload {
        Value::Array(items) => items.len(),
        _ => 1,
    };
    parse_native_bitmask_output(stdout.trim(), expected_outputs)
}

fn parse_native_bitmask_output(raw: &str, expected_outputs: usize) -> Result<Vec<RuleMask>> {
    if raw.is_empty() {
        return Err(LogicPearlError::message(
            "native binary produced empty output",
        ));
    }
    let value: Value = serde_json::from_str(raw)?;
    if expected_outputs <= 1 {
        return Ok(vec![RuleMask::from_json_value(&value)?]);
    }
    let Value::Array(items) = value else {
        return Err(LogicPearlError::message(
            "native binary did not return a JSON array for batched evaluation",
        ));
    };
    items
        .iter()
        .map(RuleMask::from_json_value)
        .collect::<Result<Vec<_>>>()
}

fn baseline_features(rows: &[DecisionTraceRow]) -> BTreeMap<String, Value> {
    let mut baseline = BTreeMap::new();
    for row in rows {
        for (key, value) in &row.features {
            baseline.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    baseline
}

fn generate_boundary_scenarios(
    gate: &LogicPearlGateIr,
    baseline: &BTreeMap<String, Value>,
    max_boundary_scenarios: usize,
) -> Result<Vec<BoundaryScenario>> {
    let mut scenarios = Vec::new();
    let mut seen = BTreeSet::new();

    for rule in &gate.rules {
        let Expression::Comparison(comparison) = &rule.deny_when else {
            continue;
        };
        let Some(threshold) = comparison.value.literal().and_then(Value::as_f64) else {
            continue;
        };
        if !matches!(
            comparison.op,
            ComparisonOperator::Gt
                | ComparisonOperator::Gte
                | ComparisonOperator::Lt
                | ComparisonOperator::Lte
                | ComparisonOperator::Eq
        ) {
            continue;
        }

        for (candidate, rationale_suffix) in numeric_boundary_candidates(threshold) {
            let signature = format!("{}:{candidate}", rule.id);
            if !seen.insert(signature) {
                continue;
            }
            let mut features = baseline.clone();
            features.insert(comparison.feature.clone(), Value::from(candidate));
            let bitmask = evaluate_gate(
                gate,
                &features.clone().into_iter().collect::<HashMap<_, _>>(),
            )?;
            scenarios.push(BoundaryScenario {
                scenario_id: format!("{}-{}", rule.id, scenarios.len()),
                rule_id: rule.id.clone(),
                feature: comparison.feature.clone(),
                rationale: format!(
                    "Review {} around threshold {} ({})",
                    comparison.feature, threshold, rationale_suffix
                ),
                triggered_rule_ids: triggered_rule_ids(gate, &bitmask),
                runtime_bitmask: bitmask,
                features,
            });
            if scenarios.len() >= max_boundary_scenarios {
                return Ok(scenarios);
            }
        }
    }

    Ok(scenarios)
}

fn numeric_boundary_candidates(threshold: f64) -> Vec<(f64, &'static str)> {
    vec![
        (threshold - 1.0, "just below"),
        (threshold, "at threshold"),
        (threshold + 1.0, "just above"),
    ]
}

fn triggered_rule_ids(gate: &LogicPearlGateIr, bitmask: &RuleMask) -> Vec<String> {
    gate.rules
        .iter()
        .filter(|rule| bitmask.test_bit(rule.bit))
        .map(|rule| rule.id.clone())
        .collect()
}

fn validate_group(
    group_name: &str,
    fingerprints: &BTreeMap<String, FileFingerprint>,
    problems: &mut Vec<String>,
) {
    for (label, fingerprint) in fingerprints {
        let path = Path::new(&fingerprint.path);
        if !path.exists() {
            problems.push(format!("{group_name}:{label} missing: {}", path.display()));
            continue;
        }
        match fingerprint_path(path) {
            Ok(actual) => {
                if actual.size_bytes != fingerprint.size_bytes
                    || actual.mtime_ns != fingerprint.mtime_ns
                {
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

fn fingerprint_group(
    entries: BTreeMap<String, String>,
) -> Result<BTreeMap<String, FileFingerprint>> {
    entries
        .into_iter()
        .map(|(label, path)| {
            let fingerprint = fingerprint_path(Path::new(&path))?;
            Ok((label, fingerprint))
        })
        .collect()
}

fn validate_key_algorithm(algorithm: &str) -> Result<()> {
    if algorithm == "ed25519" {
        Ok(())
    } else {
        Err(LogicPearlError::message(format!(
            "unsupported receipt signing algorithm: {algorithm}"
        )))
    }
}

fn signing_key_from_file(keypair: &ReceiptSigningKeyFile) -> Result<SigningKey> {
    let secret = hex::decode(&keypair.secret_key_hex)
        .map_err(|err| LogicPearlError::message(format!("invalid secret key hex: {err}")))?;
    let bytes: [u8; 32] = secret
        .try_into()
        .map_err(|_| LogicPearlError::message("secret key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_file(public_key: &ReceiptPublicKeyFile) -> Result<VerifyingKey> {
    let public = hex::decode(&public_key.public_key_hex)
        .map_err(|err| LogicPearlError::message(format!("invalid public key hex: {err}")))?;
    let bytes: [u8; 32] = public
        .try_into()
        .map_err(|_| LogicPearlError::message("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|err| LogicPearlError::message(format!("invalid public key: {err}")))
}

fn sha256_hex_path(path: &Path) -> Result<String> {
    sha256_hex_bytes(&fs::read(path)?).pipe(Ok)
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Serialize)]
struct UnsignedDecisionReceipt {
    receipt_version: String,
    generated_at: String,
    gate_id: String,
    pearl_ir_sha256: String,
    input_sha256: String,
    bitmasks: Vec<RuleMask>,
    all_allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_cross_check: Option<ReceiptNativeCrossCheck>,
    signer_public_key_hex: String,
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use logicpearl_ir::LogicPearlGateIr;
    use serde_json::json;

    fn simple_gate() -> LogicPearlGateIr {
        LogicPearlGateIr::from_json_str(
            &serde_json::to_string(&json!({
                "ir_version": "1.0",
                "gate_id": "demo",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [
                        {"id": "flag", "type": "int", "description": null, "values": null, "min": null, "max": null, "editable": null}
                    ]
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
        .unwrap()
    }

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
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let report = validate_artifact_manifest(&manifest_path).unwrap();
        assert!(report.fresh);
        assert!(report.problems.is_empty());
    }

    #[test]
    fn runtime_parity_matches_simple_gate() {
        let gate = simple_gate();
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

    #[test]
    fn review_pack_includes_mismatches_and_boundary_cases() {
        let gate = simple_gate();
        let rows = vec![
            DecisionTraceRow {
                features: BTreeMap::from([("flag".to_string(), Value::from(0))]),
                allowed: false,
            },
            DecisionTraceRow {
                features: BTreeMap::from([("flag".to_string(), Value::from(1))]),
                allowed: false,
            },
        ];
        let review_pack = build_review_pack(&gate, &rows, 3).unwrap();
        assert_eq!(review_pack.mismatch_count, 1);
        assert!(!review_pack.boundary_scenarios.is_empty());
    }

    #[test]
    fn receipts_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let gate_path = dir.path().join("pearl.ir.json");
        let gate = simple_gate();
        std::fs::write(&gate_path, serde_json::to_string_pretty(&gate).unwrap()).unwrap();
        let keypair = generate_receipt_keypair();
        let public_key = public_key_from_signing_key(&keypair).unwrap();
        let receipt = create_signed_decision_receipt(
            &gate,
            &gate_path,
            &json!({"flag": 0}),
            &keypair,
            None,
            "unix:1".to_string(),
        )
        .unwrap();

        let report = verify_decision_receipt(&receipt, &public_key).unwrap();
        assert!(report.valid, "{:?}", report.problems);
    }
}
