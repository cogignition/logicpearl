// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

#[test]
fn golden_runtime_fixtures_validate_against_committed_schemas() {
    let root = repo_root();
    let cases = [
        (
            "logicpearl-gate-result-v1.schema.json",
            "fixtures/runtime/gate_result_v1.json",
        ),
        (
            "logicpearl-action-result-v1.schema.json",
            "fixtures/runtime/action_result_v1.json",
        ),
        (
            "logicpearl-pipeline-result-v1.schema.json",
            "fixtures/runtime/pipeline_result_v1.json",
        ),
        (
            "logicpearl-artifact-error-v1.schema.json",
            "fixtures/runtime/artifact_error_v1.json",
        ),
    ];

    for (schema_name, fixture_path) in cases {
        validate_against_schema(schema_name, &load_json(root.join(fixture_path)));
    }
}

#[test]
fn runtime_schema_files_are_valid_draft_2020_12() {
    let schema_dir = repo_root().join("schema");
    let mut schema_paths = fs::read_dir(&schema_dir)
        .unwrap_or_else(|err| panic!("failed to list schema dir {}: {err}", schema_dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("failed to read schema dir entry: {err}"))
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    schema_paths.sort();
    assert!(
        !schema_paths.is_empty(),
        "schema directory should not be empty"
    );

    for schema_path in schema_paths {
        let schema_name = schema_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("schema filename should be valid UTF-8");
        let schema = load_json(&schema_path);
        jsonschema::draft202012::meta::validate(&schema).unwrap_or_else(|err| {
            panic!("{schema_name} is not a valid Draft 2020-12 schema: {err}")
        });
    }
}

#[test]
fn cli_runtime_json_outputs_validate_against_committed_schemas() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = repo_root();

    let mut gate_child = Command::new(cli_bin)
        .arg("run")
        .arg(root.join("fixtures/ir/valid/auth-demo-v1.json"))
        .arg("-")
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("logicpearl run should spawn");
    {
        use std::io::Write;
        let stdin = gate_child
            .stdin
            .as_mut()
            .expect("gate child should have stdin");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "action": "delete",
                "resource_archived": true,
                "user_role": "viewer",
                "failed_attempts": 99
            })
        )
        .expect("gate input should write");
    }
    let gate_output = gate_child
        .wait_with_output()
        .expect("logicpearl run should finish");
    assert!(
        gate_output.status.success(),
        "gate run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&gate_output.stdout),
        String::from_utf8_lossy(&gate_output.stderr)
    );
    let gate_json: Value =
        serde_json::from_slice(&gate_output.stdout).expect("gate output should be JSON");
    assert_eq!(gate_json["schema_version"], "logicpearl.gate_result.v1");
    validate_against_schema("logicpearl-gate-result-v1.schema.json", &gate_json);

    let temp = tempfile::tempdir().expect("tempdir should exist");
    let action_dir = temp.path().join("garden_actions");
    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(root.join("examples/demos/garden_actions/traces.csv"))
        .arg("--action-column")
        .arg("next_action")
        .arg("--default-action")
        .arg("do_nothing")
        .arg("--gate-id")
        .arg("garden_actions")
        .arg("--output-dir")
        .arg(&action_dir)
        .output()
        .expect("action artifact build should run");
    assert!(
        build_output.status.success(),
        "action build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );
    let action_output = Command::new(cli_bin)
        .arg("run")
        .arg(&action_dir)
        .arg(root.join("examples/demos/garden_actions/today.json"))
        .arg("--json")
        .output()
        .expect("action run should run");
    assert!(
        action_output.status.success(),
        "action run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&action_output.stdout),
        String::from_utf8_lossy(&action_output.stderr)
    );
    let action_json: Value =
        serde_json::from_slice(&action_output.stdout).expect("action output should be JSON");
    assert_eq!(action_json["schema_version"], "logicpearl.action_result.v1");
    validate_against_schema("logicpearl-action-result-v1.schema.json", &action_json);

    let pipeline_output = Command::new(cli_bin)
        .arg("pipeline")
        .arg("run")
        .arg(root.join("examples/pipelines/authz/pipeline.json"))
        .arg(root.join("examples/pipelines/authz/input.json"))
        .arg("--json")
        .output()
        .expect("pipeline run should run");
    assert!(
        pipeline_output.status.success(),
        "pipeline run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&pipeline_output.stdout),
        String::from_utf8_lossy(&pipeline_output.stderr)
    );
    let pipeline_json: Value =
        serde_json::from_slice(&pipeline_output.stdout).expect("pipeline output should be JSON");
    assert_eq!(
        pipeline_json["schema_version"],
        "logicpearl.pipeline_result.v1"
    );
    validate_against_schema("logicpearl-pipeline-result-v1.schema.json", &pipeline_json);
}
