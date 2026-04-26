// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn run_cli(args: &[String]) -> String {
    run_cli_in(None, args)
}

fn run_cli_in(cwd: Option<&Path>, args: &[String]) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_logicpearl"));
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl command failed:\nargs: {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_cli_json(args: &[String]) -> Value {
    serde_json::from_str(&run_cli(args)).expect("command output should be JSON")
}

fn write_gate_fixture(temp: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let traces = temp.join("traces.csv");
    let input = temp.join("input.json");
    let artifact = temp.join("artifact");
    fs::write(
        &traces,
        "risk_score,manual_override,allowed\n\
         90,0,denied\n\
         85,0,denied\n\
         15,0,allowed\n\
         20,1,allowed\n",
    )
    .expect("traces should write");
    fs::write(&input, "{\"risk_score\": 91, \"manual_override\": 0}\n")
        .expect("input should write");
    run_cli_in(
        Some(temp),
        &[
            "build".into(),
            "traces.csv".into(),
            "--target".into(),
            "allowed".into(),
            "--output-dir".into(),
            "artifact".into(),
            "--json".into(),
        ],
    );
    (traces, input, artifact)
}

#[test]
fn review_trace_and_refine_are_first_class_loop_commands() {
    let temp = tempdir().expect("temp dir should exist");
    let (traces, input, artifact) = write_gate_fixture(temp.path());

    let review = run_cli(&[
        "review".into(),
        artifact.display().to_string(),
        input.display().to_string(),
    ]);
    assert!(review.contains("Policy review"), "{review}");
    assert!(review.contains("Decision"), "{review}");
    assert!(review.contains("Evidence"), "{review}");

    let trace = run_cli_json(&[
        "trace".into(),
        artifact.display().to_string(),
        traces.display().to_string(),
        "--show-near-misses".into(),
        "--json".into(),
    ]);
    assert_eq!(
        trace["schema_version"].as_str(),
        Some("logicpearl.trace_replay.v1")
    );
    assert_eq!(trace["decision_kind"].as_str(), Some("gate"));
    assert_eq!(trace["rows"].as_u64(), Some(4));
    assert_eq!(trace["parity"].as_f64(), Some(1.0));

    let ir: Value = serde_json::from_str(
        &fs::read_to_string(artifact.join("pearl.ir.json")).expect("IR should be readable"),
    )
    .expect("IR should parse");
    let pinned = temp.path().join("rules.json");
    fs::write(
        &pinned,
        serde_json::to_string_pretty(&serde_json::json!({
            "rule_set_version": "1.0",
            "rule_set_id": "reviewed_rules",
            "rules": ir["rules"].as_array().expect("rules should exist")
        }))
        .unwrap(),
    )
    .expect("pinned rules should write");

    let refined = temp.path().join("artifact.refined");
    let refine = run_cli(&[
        "refine".into(),
        artifact.display().to_string(),
        "--pin".into(),
        pinned.display().to_string(),
        "--output-dir".into(),
        refined.display().to_string(),
    ]);
    assert!(
        refine.contains("Refining policy from reviewed evidence"),
        "{refine}"
    );
    assert!(refined.join("artifact.json").exists());
    assert!(refined.join("pearl.ir.json").exists());
}
