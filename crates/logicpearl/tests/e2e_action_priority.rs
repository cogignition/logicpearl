// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

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

fn run_artifact_action(artifact_dir: &Path, input: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("run")
        .arg(artifact_dir)
        .arg("-")
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("logicpearl run should spawn");
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("stdin should be open");
        writeln!(stdin, "{input}").expect("input should write");
    }
    let output = child
        .wait_with_output()
        .expect("logicpearl run should exit");
    assert!(
        output.status.success(),
        "logicpearl run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("run stdout should be JSON")
}

#[test]
fn action_learning_uses_priority_residuals_and_count_generalization() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let traces_path = temp.path().join("traces.csv");
    fs::write(
        &traces_path,
        "\
pattern_count,severity_score,context_present,next_action
0,0,false,allow
0,1,true,allow
1,10,true,redact
2,10,true,redact
3,10,true,redact
4,10,true,redact
2,90,true,block
3,90,true,block
4,90,true,block
5,90,true,block
",
    )
    .expect("traces should write");
    let artifact_dir = temp.path().join("artifact");

    let report = run_cli_json(&[
        "build".to_string(),
        traces_path.display().to_string(),
        "--action-column".to_string(),
        "next_action".to_string(),
        "--default-action".to_string(),
        "allow".to_string(),
        "--gate-id".to_string(),
        "generic_actions".to_string(),
        "--action-priority".to_string(),
        "block,redact".to_string(),
        "--action-max-rules".to_string(),
        "2".to_string(),
        "--output-dir".to_string(),
        artifact_dir.display().to_string(),
        "--json".to_string(),
    ]);

    assert_eq!(report["training_parity"], 1.0);
    assert_eq!(report["rule_budget"]["requested_max_rules"], 2);
    assert_eq!(
        report["rule_budget"]["priority_order"],
        serde_json::json!(["block", "redact"])
    );
    assert_eq!(
        report["rules"]
            .as_array()
            .expect("rules should be array")
            .len(),
        2
    );
    assert_eq!(report["rules"][0]["action"], "block");
    assert_eq!(report["rules"][1]["action"], "redact");

    let direct_ir_inspect = run_cli_json(&[
        "inspect".to_string(),
        artifact_dir.join("pearl.ir.json").display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(direct_ir_inspect["artifact_kind"], "action");
    assert_eq!(direct_ir_inspect["action_policy_id"], "generic_actions");
    assert_eq!(direct_ir_inspect["rules"][0]["action"], "block");
    assert!(!direct_ir_inspect["rules"][0]["when"].is_null());

    let low_severity_two_count = run_artifact_action(
        &artifact_dir,
        serde_json::json!({
            "pattern_count": 2,
            "severity_score": 10,
            "context_present": true
        }),
    );
    assert_eq!(low_severity_two_count["action"], "redact");

    let low_severity_four_count = run_artifact_action(
        &artifact_dir,
        serde_json::json!({
            "pattern_count": 4,
            "severity_score": 10,
            "context_present": true
        }),
    );
    assert_eq!(low_severity_four_count["action"], "redact");

    let high_severity_multi_count = run_artifact_action(
        &artifact_dir,
        serde_json::json!({
            "pattern_count": 3,
            "severity_score": 90,
            "context_present": true
        }),
    );
    assert_eq!(high_severity_multi_count["action"], "block");
    assert_eq!(
        high_severity_multi_count["candidate_actions"],
        serde_json::json!(["block", "redact"])
    );

    let no_pattern = run_artifact_action(
        &artifact_dir,
        serde_json::json!({
            "pattern_count": 0,
            "severity_score": 0,
            "context_present": false
        }),
    );
    assert_eq!(no_pattern["action"], "allow");
    assert_eq!(no_pattern["defaulted"], true);
}
