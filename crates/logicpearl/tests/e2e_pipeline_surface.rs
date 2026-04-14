// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn run_cli_json(cli_bin: &str, args: &[String]) -> Value {
    let output = Command::new(cli_bin)
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl command failed:\nargs: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command output should be valid JSON")
}

fn json_array_contains(value: &Value, needle: &str) -> bool {
    value.as_array().is_some_and(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item == needle)
    })
}

#[test]
fn pipeline_validate_inspect_and_trace_expose_expected_stage_data() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let pipeline = repo_root.join("examples/pipelines/observer_membership_verify/pipeline.json");
    let input = repo_root.join("examples/pipelines/observer_membership_verify/input.json");

    let validate = run_cli_json(
        cli_bin,
        &[
            "pipeline".to_string(),
            "validate".to_string(),
            pipeline.display().to_string(),
            "--json".to_string(),
        ],
    );
    assert_eq!(
        validate["pipeline_id"].as_str(),
        Some("observer_membership_verify_pipeline")
    );
    assert_eq!(validate["stage_count"].as_u64(), Some(3));
    assert_eq!(
        validate["stages"][0]["kind"].as_str(),
        Some("observer_plugin")
    );
    assert_eq!(
        validate["stages"][2]["kind"].as_str(),
        Some("verify_plugin")
    );
    assert!(json_array_contains(&validate["exports"], "allow"));
    assert!(json_array_contains(&validate["exports"], "audit_status"));

    let inspect = run_cli_json(
        cli_bin,
        &[
            "pipeline".to_string(),
            "inspect".to_string(),
            pipeline.display().to_string(),
            "--json".to_string(),
        ],
    );
    assert_eq!(inspect["pipeline_id"], validate["pipeline_id"]);
    assert_eq!(inspect["stage_count"], validate["stage_count"]);
    assert!(inspect["stages"][1]["artifact"]
        .as_str()
        .is_some_and(|path| path.ends_with(
            "examples/pipelines/observer_membership_verify/artifacts/membership-demo-v1.json"
        )));
    assert!(inspect["stages"][2]["plugin_manifest"]
        .as_str()
        .is_some_and(
            |path| path.ends_with(
                "examples/pipelines/observer_membership_verify/plugins/python_pipeline_verify/manifest.json"
            )
        ));

    let trace = run_cli_json(
        cli_bin,
        &[
            "pipeline".to_string(),
            "trace".to_string(),
            pipeline.display().to_string(),
            input.display().to_string(),
            "--json".to_string(),
        ],
    );
    assert_eq!(
        trace["pipeline_id"].as_str(),
        Some("observer_membership_verify_pipeline")
    );
    assert_eq!(trace["output"]["allow"].as_bool(), Some(true));
    assert_eq!(trace["output"]["audit_status"].as_str(), Some("clean_pass"));
    assert_eq!(trace["output"]["consistent"].as_bool(), Some(true));

    let stages = trace["stages"]
        .as_array()
        .expect("pipeline trace should include stage executions");
    assert_eq!(stages.len(), 3);
    assert_eq!(stages[0]["id"].as_str(), Some("observer"));
    assert_eq!(stages[1]["id"].as_str(), Some("gate"));
    assert_eq!(stages[2]["id"].as_str(), Some("audit"));
    assert_eq!(stages[0]["skipped"].as_bool(), Some(false));
    assert_eq!(stages[1]["exports"]["allow"].as_bool(), Some(true));
    assert_eq!(
        stages[0]["raw_result"]["features"]["is_member"].as_i64(),
        Some(1)
    );
    assert_eq!(
        stages[0]["raw_result"]["plugin_run"]["plugin_id"].as_str(),
        Some("python-observer")
    );
    assert_eq!(
        stages[0]["raw_result"]["plugin_run"]["access"]["filesystem"].as_str(),
        Some("process_default")
    );
    assert_eq!(
        stages[2]["raw_result"]["summary"]["consistent"].as_bool(),
        Some(true)
    );
    assert_eq!(
        stages[2]["raw_result"]["plugin_run"]["plugin_id"].as_str(),
        Some("python-pipeline-verify")
    );
}
