// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
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
        &fs::read_to_string(path.as_ref())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.as_ref().display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.as_ref().display()))
}

fn assert_sha256(value: &Value) {
    let value = value.as_str().expect("hash should be a string");
    assert!(
        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64,
        "expected sha256-prefixed hash, got {value:?}"
    );
}

fn validate_build_provenance(instance: &Value) {
    let schema = load_json(repo_root().join("schema/logicpearl-build-provenance-v1.schema.json"));
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|err| panic!("build provenance schema is invalid: {err}"));
    let validator = jsonschema::draft202012::new(&schema)
        .unwrap_or_else(|err| panic!("failed to compile build provenance schema: {err}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "build provenance validation failed:\n{}\ninstance:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(instance).expect("instance should encode")
    );
}

fn run_cli_json(args: &[String]) -> Value {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let output = Command::new(cli_bin)
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl command failed:\nargs: {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("logicpearl output should be JSON")
}

#[test]
fn file_backed_gate_build_records_v1_provenance() {
    let root = repo_root();
    let temp = tempdir().expect("temp dir should exist");
    let artifact_dir = temp.path().join("gate");
    let report = run_cli_json(&[
        "build".to_string(),
        root.join("examples/getting_started/decision_traces.csv")
            .display()
            .to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    let provenance = &report["provenance"];
    validate_build_provenance(provenance);
    assert_eq!(
        provenance["schema_version"],
        "logicpearl.build_provenance.v1"
    );
    assert_eq!(
        provenance["input_traces"][0]["row_count"].as_u64(),
        Some(12)
    );
    assert_sha256(&provenance["input_traces"][0]["hash"]);
    assert_sha256(&provenance["feature_dictionary"]["hash"]);
    assert!(provenance["plugins"].as_array().is_some_and(Vec::is_empty));
    assert_sha256(&provenance["build_options_hash"]);
    assert_sha256(&provenance["generated_files"]["pearl.ir.json"]);
    assert_sha256(&provenance["generated_files"]["feature_dictionary.generated.json"]);

    let persisted = load_json(artifact_dir.join("build_report.json"));
    assert_eq!(&persisted["provenance"], provenance);
}

#[test]
fn action_build_records_v1_provenance() {
    let root = repo_root();
    let temp = tempdir().expect("temp dir should exist");
    let artifact_dir = temp.path().join("action");
    let report = run_cli_json(&[
        "build".to_string(),
        root.join("examples/demos/garden_actions/traces.csv")
            .display()
            .to_string(),
        "--action-column".to_string(),
        "next_action".to_string(),
        "--default-action".to_string(),
        "do_nothing".to_string(),
        "--gate-id".to_string(),
        "garden_actions".to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    let provenance = &report["provenance"];
    validate_build_provenance(provenance);
    assert_eq!(
        provenance["input_traces"][0]["row_count"].as_u64(),
        Some(16)
    );
    assert_sha256(&provenance["input_traces"][0]["hash"]);
    assert_sha256(&provenance["generated_files"]["pearl.ir.json"]);
    assert_eq!(
        provenance["build_options"]["action_column"].as_str(),
        Some("next_action")
    );

    let persisted = load_json(artifact_dir.join("action_report.json"));
    assert_eq!(&persisted["provenance"], provenance);
}

#[test]
fn plugin_build_records_boundary_hashes_without_secret_values() {
    let root = repo_root();
    let temp = tempdir().expect("temp dir should exist");
    let artifact_dir = temp.path().join("plugin");
    let report = run_cli_json(&[
        "build".to_string(),
        "--trace-plugin-manifest".to_string(),
        root.join("examples/plugins/python_trace_source/manifest.json")
            .display()
            .to_string(),
        "--trace-plugin-input".to_string(),
        root.join("examples/getting_started/decision_traces.csv")
            .display()
            .to_string(),
        "--trace-plugin-option".to_string(),
        "label_column=allowed".to_string(),
        "--trace-plugin-option".to_string(),
        "api_key=supersecret".to_string(),
        "--source-ref".to_string(),
        "document_id=decision_traces_sample".to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    let provenance = &report["provenance"];
    validate_build_provenance(provenance);
    assert!(provenance["build_command"]["redacted"]
        .as_bool()
        .expect("redacted flag should be present"));
    let encoded = serde_json::to_string(provenance).expect("provenance should encode");
    assert!(!encoded.contains("supersecret"));

    let plugin = &provenance["plugins"][0];
    assert_eq!(plugin["stage"].as_str(), Some("trace_source"));
    assert_sha256(&plugin["manifest_hash"]);
    assert_sha256(&plugin["input_hash"]);
    assert_sha256(&plugin["input"]["hash"]);
    assert_sha256(&plugin["request_hash"]);
    assert_sha256(&plugin["output_hash"]);
    assert!(plugin["options"]["api_key"]
        .as_str()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));
    assert_eq!(
        provenance["source_references"]["document_id"].as_str(),
        Some("decision_traces_sample")
    );
}
