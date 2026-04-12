// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn load_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_str(
        &fs::read_to_string(path.as_ref())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.as_ref().display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.as_ref().display()))
}

fn validate_against_schema(schema_name: &str, instance: &Value) {
    let schema = load_json(repo_root().join("schema").join(schema_name));
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|err| panic!("{schema_name} is not a valid Draft 2020-12 schema: {err}"));
    let validator = jsonschema::draft202012::new(&schema)
        .unwrap_or_else(|err| panic!("failed to compile {schema_name}: {err}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "{schema_name} validation failed:\n{}\ninstance:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(instance).expect("instance should encode")
    );
}

fn run_cli_json(args: &[String]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl {:?} failed:\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command stdout should be JSON")
}

fn run_cli(args: &[String]) {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl {:?} failed:\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn artifact_manifests_validate_and_artifact_commands_work() {
    let root = repo_root();
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let gate_dir = temp.path().join("gate");
    run_cli(&[
        "build".to_string(),
        root.join("examples/getting_started/decision_traces.csv")
            .display()
            .to_string(),
        "--output-dir".to_string(),
        gate_dir.display().to_string(),
        "--json".to_string(),
    ]);
    let gate_manifest = load_json(gate_dir.join("artifact.json"));
    validate_against_schema(
        "logicpearl-artifact-manifest-v1.schema.json",
        &gate_manifest,
    );
    assert_eq!(gate_manifest["artifact_kind"], "gate");
    assert_eq!(gate_manifest["files"]["ir"], "pearl.ir.json");
    assert!(gate_manifest["input_schema_hash"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));
    assert!(gate_manifest["build_options_hash"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));

    let gate_inspect = run_cli_json(&[
        "artifact".to_string(),
        "inspect".to_string(),
        gate_dir.display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(
        gate_inspect["manifest"]["artifact_hash"],
        gate_manifest["artifact_hash"]
    );
    let gate_digest = run_cli_json(&[
        "artifact".to_string(),
        "digest".to_string(),
        gate_dir.display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(gate_digest["artifact_hash"], gate_manifest["artifact_hash"]);
    let gate_verify = run_cli_json(&[
        "artifact".to_string(),
        "verify".to_string(),
        gate_dir.display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(gate_verify["ok"], true);

    let action_dir = temp.path().join("action");
    run_cli(&[
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
        action_dir.display().to_string(),
        "--json".to_string(),
    ]);
    let action_manifest = load_json(action_dir.join("artifact.json"));
    validate_against_schema(
        "logicpearl-artifact-manifest-v1.schema.json",
        &action_manifest,
    );
    assert_eq!(action_manifest["artifact_kind"], "action");
    assert_eq!(
        action_manifest["files"]["build_report"],
        "action_report.json"
    );
    let action_verify = run_cli_json(&[
        "artifact".to_string(),
        "verify".to_string(),
        action_dir.display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(action_verify["ok"], true);

    let pipeline_dir = temp.path().join("pipeline");
    fs::create_dir_all(&pipeline_dir).expect("pipeline dir should be created");
    run_cli(&[
        "compose".to_string(),
        "--pipeline-id".to_string(),
        "starter_authz".to_string(),
        "--output".to_string(),
        pipeline_dir.join("pipeline.json").display().to_string(),
        root.join("fixtures/ir/valid/auth-demo-v1.json")
            .display()
            .to_string(),
    ]);
    let pipeline_manifest = load_json(pipeline_dir.join("artifact.json"));
    validate_against_schema(
        "logicpearl-artifact-manifest-v1.schema.json",
        &pipeline_manifest,
    );
    assert_eq!(pipeline_manifest["artifact_kind"], "pipeline");
    assert_eq!(pipeline_manifest["files"]["ir"], "pipeline.json");
    let pipeline_verify = run_cli_json(&[
        "artifact".to_string(),
        "verify".to_string(),
        pipeline_dir.display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(pipeline_verify["ok"], true);
}

#[test]
fn artifact_manifest_schema_is_valid_draft_2020_12() {
    let schema = load_json(
        repo_root()
            .join("schema")
            .join("logicpearl-artifact-manifest-v1.schema.json"),
    );
    jsonschema::draft202012::meta::validate(&schema)
        .expect("artifact manifest schema should be valid Draft 2020-12");
}
