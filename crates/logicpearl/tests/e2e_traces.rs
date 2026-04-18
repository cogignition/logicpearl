// SPDX-License-Identifier: MIT
use logicpearl_discovery::BuildResult;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn load_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(path.as_ref())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.as_ref().display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.as_ref().display()))
}

fn validate_json_schema(schema_path: impl AsRef<Path>, instance: &Value) {
    let schema = load_json(schema_path.as_ref());
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|err| panic!("schema is invalid: {err}"));
    let validator = jsonschema::draft202012::new(&schema)
        .unwrap_or_else(|err| panic!("failed to compile schema: {err}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema validation failed:\n{}\ninstance:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(instance).expect("instance should encode")
    );
}

#[test]
fn synthetic_trace_generator_emits_clean_dataset_that_builds() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp directory should exist");
    let spec = repo_root.join("examples/getting_started/synthetic_access_policy.tracegen.json");
    let traces_path = temp.path().join("synthetic_access_policy.jsonl");
    let artifact_dir = temp.path().join("artifact_bundle");

    let generate = Command::new(cli_bin)
        .arg("traces")
        .arg("generate")
        .arg(&spec)
        .arg("--output")
        .arg(&traces_path)
        .arg("--json")
        .output()
        .expect("trace generation should run");
    assert!(
        generate.status.success(),
        "logicpearl traces generate failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&generate.stdout),
        String::from_utf8_lossy(&generate.stderr)
    );

    let generate_report: Value =
        serde_json::from_slice(&generate.stdout).expect("generate output should be valid JSON");
    assert_eq!(generate_report["row_count"].as_u64(), Some(240));
    assert_eq!(
        generate_report["audit"]["suspicious_nuisance_fields"]
            .as_array()
            .map(|items| items.len()),
        Some(0)
    );

    let audit = Command::new(cli_bin)
        .arg("traces")
        .arg("audit")
        .arg(&traces_path)
        .arg("--spec")
        .arg(&spec)
        .arg("--fail-on-skew")
        .arg("--json")
        .output()
        .expect("trace audit should run");
    assert!(
        audit.status.success(),
        "logicpearl traces audit failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );

    let build = Command::new(cli_bin)
        .arg("build")
        .arg(&traces_path)
        .arg("--output-dir")
        .arg(&artifact_dir)
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        build.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let build_result: BuildResult =
        serde_json::from_slice(&build.stdout).expect("build output should be valid JSON");
    assert_eq!(build_result.label_column, "allowed");
    assert!(build_result.training_parity >= 0.95);
}

#[test]
fn observation_schema_contract_validates_and_is_discoverable() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let observation_schema =
        repo_root.join("fixtures/observations/valid/notification-observation-schema-v1.json");
    let public_schema = repo_root.join("schema/logicpearl-observation-schema-v1.schema.json");
    let payload = load_json(&observation_schema);
    validate_json_schema(public_schema, &payload);

    let output = Command::new(cli_bin)
        .arg("traces")
        .arg("observation-schema")
        .arg(&observation_schema)
        .arg("--json")
        .output()
        .expect("logicpearl traces observation-schema should run");
    assert!(
        output.status.success(),
        "logicpearl traces observation-schema failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("observation schema output is JSON");
    assert_eq!(
        report["schema_version"].as_str(),
        Some("logicpearl.observation_schema.v1")
    );
    assert_eq!(report["feature_count"].as_u64(), Some(3));
    assert_eq!(
        report["features"][0]["feature_id"].as_str(),
        Some("notification_sent_on_time")
    );
    assert_eq!(report["features"][0]["type"].as_str(), Some("boolean"));
    assert_eq!(report["features"][0]["operators"][0].as_str(), Some("eq"));
    assert_eq!(
        report["features"][0]["source_id"].as_str(),
        Some("policy_manual_2026_04")
    );
}

#[test]
fn build_progress_uses_stderr_without_corrupting_json_stdout() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp directory should exist");
    let traces = repo_root.join("examples/getting_started/decision_traces.csv");
    let artifact_dir = temp.path().join("progress_artifact");

    let output = Command::new(cli_bin)
        .arg("build")
        .arg(&traces)
        .arg("--output-dir")
        .arg(&artifact_dir)
        .arg("--json")
        .arg("--progress")
        .output()
        .expect("logicpearl build --progress should run");
    assert!(
        output.status.success(),
        "logicpearl build --progress failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should remain valid JSON");
    assert_eq!(report["gate_id"].as_str(), Some("decision_traces"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("candidate_generation: numeric predicates")
            || stderr.contains("candidate_generation: atomic features"),
        "stderr should contain candidate-generation subphase progress, got: {stderr:?}"
    );
    assert!(
        stderr.contains("greedy_selection: pass"),
        "stderr should contain greedy-selection subphase progress, got: {stderr:?}"
    );
}
