// SPDX-License-Identifier: MIT
use serde_json::{json, Value};
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

fn assert_no_local_path_leaks(value: &Value, temp_root: &Path) {
    let encoded = serde_json::to_string(value).expect("report should encode");
    let mut forbidden = vec![
        "/Users/".to_string(),
        "/home/".to_string(),
        "/var/folders/".to_string(),
        temp_root.display().to_string(),
    ];
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        if user.len() >= 4 {
            forbidden.push(user);
        }
    }

    for fragment in forbidden {
        if fragment.is_empty() {
            continue;
        }
        assert!(
            !encoded.contains(&fragment),
            "public build report leaked local path fragment {fragment:?}:\n{}",
            serde_json::to_string_pretty(value).expect("report should pretty encode")
        );
    }
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

fn validate_source_manifest(instance: &Value) {
    let schema = load_json(repo_root().join("schema/logicpearl-source-manifest-v1.schema.json"));
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|err| panic!("source manifest schema is invalid: {err}"));
    let validator = jsonschema::draft202012::new(&schema)
        .unwrap_or_else(|err| panic!("failed to compile source manifest schema: {err}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "source manifest validation failed:\n{}\ninstance:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(instance).expect("instance should encode")
    );
}

fn validate_plugin_run_provenance(instance: &Value) {
    let schema =
        load_json(repo_root().join("schema/logicpearl-plugin-run-provenance-v1.schema.json"));
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|err| panic!("plugin run provenance schema is invalid: {err}"));
    let validator = jsonschema::draft202012::new(&schema)
        .unwrap_or_else(|err| panic!("failed to compile plugin run provenance schema: {err}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "plugin run provenance validation failed:\n{}\ninstance:\n{}",
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

fn run_cli_output(args: &[String]) -> std::process::Output {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    Command::new(cli_bin)
        .args(args)
        .output()
        .expect("logicpearl command should run")
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

    assert_no_local_path_leaks(&report, temp.path());
    assert_eq!(
        report["source_csv"].as_str(),
        Some("./examples/getting_started/decision_traces.csv")
    );
    assert_eq!(report["output_files"]["artifact_dir"].as_str(), Some("."));
    assert_eq!(
        report["output_files"]["artifact_manifest"].as_str(),
        Some("artifact.json")
    );
    assert_eq!(
        report["output_files"]["pearl_ir"].as_str(),
        Some("pearl.ir.json")
    );
    assert_eq!(
        report["output_files"]["build_report"].as_str(),
        Some("build_report.json")
    );

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
    assert_no_local_path_leaks(&persisted, temp.path());
    assert_eq!(&persisted["provenance"], provenance);
    assert_eq!(persisted, report);
}

#[test]
fn absolute_trace_paths_are_redacted_in_public_build_reports() {
    let root = repo_root();
    let temp = tempdir().expect("temp dir should exist");
    let trace_path = temp.path().join("decision_traces.csv");
    let artifact_dir = temp.path().join("gate");
    fs::copy(
        root.join("examples/getting_started/decision_traces.csv"),
        &trace_path,
    )
    .expect("temp trace fixture should copy");

    let report = run_cli_json(&[
        "build".to_string(),
        trace_path.display().to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    assert_no_local_path_leaks(&report, temp.path());
    assert!(report["source_csv"]
        .as_str()
        .is_some_and(|value| value.starts_with("<path:sha256:")));
    assert!(report["provenance"]["decision_trace_source"]["value"]
        .as_str()
        .is_some_and(|value| value.starts_with("<path:sha256:")));
    assert!(report["provenance"]["input_traces"][0]["path"]
        .as_str()
        .is_some_and(|value| value.starts_with("<path:sha256:")));

    let persisted = load_json(artifact_dir.join("build_report.json"));
    assert_no_local_path_leaks(&persisted, temp.path());
    assert_eq!(persisted, report);
}

#[test]
fn source_manifest_is_validated_and_attached_to_provenance() {
    let root = repo_root();
    let temp = tempdir().expect("temp dir should exist");
    let artifact_dir = temp.path().join("gate");
    let source_manifest = temp.path().join("sources.json");
    let source_manifest_payload = json!({
        "schema_version": "logicpearl.source_manifest.v1",
        "sources": [
            {
                "source_id": "getting_started_fixture",
                "kind": "integration_policy_export",
                "title": "Getting started decision trace fixture",
                "uri": "repo:examples/getting_started/decision_traces.csv",
                "retrieved_at": "2026-04-12T00:00:00Z",
                "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "data_classification": "integration_private"
            }
        ]
    });
    validate_source_manifest(&source_manifest_payload);
    fs::write(
        &source_manifest,
        serde_json::to_string_pretty(&source_manifest_payload)
            .expect("source manifest should encode"),
    )
    .expect("source manifest should write");

    let report = run_cli_json(&[
        "build".to_string(),
        root.join("examples/getting_started/decision_traces.csv")
            .display()
            .to_string(),
        "--source-manifest".to_string(),
        source_manifest.display().to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    assert_no_local_path_leaks(&report, temp.path());
    let provenance = &report["provenance"];
    validate_build_provenance(provenance);
    assert_sha256(&provenance["source_manifest"]["hash"]);
    assert_eq!(
        provenance["source_manifest"]["sources"][0]["source_id"].as_str(),
        Some("getting_started_fixture")
    );
    assert_eq!(
        provenance["source_manifest"]["sources"][0]["kind"].as_str(),
        Some("integration_policy_export")
    );
    assert_eq!(
        provenance["source_manifest"]["sources"][0]["data_classification"].as_str(),
        Some("integration_private")
    );
    assert_eq!(
        provenance["build_options"]["source_manifest"]
            .as_str()
            .map(|value| value.starts_with("<redacted:sha256:")),
        Some(true)
    );
}

#[test]
fn invalid_source_manifest_is_rejected_before_build() {
    let root = repo_root();
    let temp = tempdir().expect("temp dir should exist");
    let source_manifest = temp.path().join("bad_sources.json");
    fs::write(
        &source_manifest,
        serde_json::to_string_pretty(&json!({
            "schema_version": "logicpearl.source_manifest.v1",
            "sources": [
                {
                    "source_id": "bad",
                    "kind": "public_url",
                    "title": "Bad source",
                    "content_hash": "not-a-sha",
                    "data_classification": "public"
                }
            ]
        }))
        .expect("source manifest should encode"),
    )
    .expect("source manifest should write");

    let output = run_cli_output(&[
        "build".to_string(),
        root.join("examples/getting_started/decision_traces.csv")
            .display()
            .to_string(),
        "--source-manifest".to_string(),
        source_manifest.display().to_string(),
        "--output-dir".to_string(),
        temp.path().join("out").display().to_string(),
        "--json".to_string(),
    ]);
    assert!(
        !output.status.success(),
        "invalid source manifest should fail:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid content_hash"),
        "stderr should explain source manifest hash failure:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
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

    assert_no_local_path_leaks(&report, temp.path());
    assert_eq!(
        report["source"].as_str(),
        Some("./examples/demos/garden_actions/traces.csv")
    );
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
    assert_no_local_path_leaks(&persisted, temp.path());
    assert_eq!(&persisted["provenance"], provenance);
    assert_eq!(persisted, report);
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
        "--trace-plugin-option".to_string(),
        "tenant=acme-health".to_string(),
        "--source-ref".to_string(),
        "document_id=decision_traces_sample".to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    assert_no_local_path_leaks(&report, temp.path());
    let provenance = &report["provenance"];
    validate_build_provenance(provenance);
    assert!(provenance["build_command"]["redacted"]
        .as_bool()
        .expect("redacted flag should be present"));
    let encoded = serde_json::to_string(provenance).expect("provenance should encode");
    assert!(!encoded.contains("supersecret"));
    assert!(!encoded.contains("acme-health"));
    assert!(!encoded.contains("decision_traces_sample"));

    let plugin = &provenance["plugins"][0];
    validate_plugin_run_provenance(plugin);
    assert_eq!(
        plugin["schema_version"].as_str(),
        Some("logicpearl.plugin_run_provenance.v1")
    );
    assert_eq!(plugin["stage"].as_str(), Some("trace_source"));
    assert_eq!(plugin["plugin_id"].as_str(), Some("python-trace-source"));
    assert_eq!(plugin["plugin_version"].as_str(), Some("0.1.0"));
    assert_sha256(&plugin["plugin_run_id"]);
    assert_sha256(&plugin["manifest_hash"]);
    assert_sha256(&plugin["entrypoint_hash"]);
    assert_sha256(&plugin["input_hash"]);
    assert_sha256(&plugin["input"]["hash"]);
    assert_sha256(&plugin["request_hash"]);
    assert_sha256(&plugin["output_hash"]);
    assert_eq!(plugin["rows_emitted"].as_u64(), Some(12));
    assert_eq!(
        plugin["timeout_policy"]["effective_timeout_ms"].as_u64(),
        Some(30_000)
    );
    assert_eq!(
        plugin["execution_policy"]["allow_path_lookup"].as_bool(),
        Some(false)
    );
    assert_eq!(plugin["access"]["network"].as_str(), Some("not_enforced"));
    assert_eq!(
        plugin["access"]["filesystem"].as_str(),
        Some("process_default")
    );
    assert!(plugin["stdio"]["stdout_hash"].as_str().is_some());
    assert!(plugin["stdio"]["stdout_summary"]
        .as_str()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));
    assert!(plugin["entrypoint"]["hashes"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(plugin["options"]["api_key"]
        .as_str()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));
    assert!(plugin["options"]["tenant"]
        .as_str()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));
    assert!(provenance["source_references"]["document_id"]
        .as_str()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));

    let persisted = load_json(artifact_dir.join("build_report.json"));
    assert_no_local_path_leaks(&persisted, temp.path());
    assert_eq!(persisted, report);
}
