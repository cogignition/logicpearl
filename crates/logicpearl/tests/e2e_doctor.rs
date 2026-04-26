// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::process::Command;

fn run_doctor_json(path: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("doctor")
        .arg(path)
        .arg("--json")
        .output()
        .expect("logicpearl doctor should run");
    assert!(
        output.status.success(),
        "logicpearl doctor failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("doctor output should be JSON")
}

fn run_build_target(path: &std::path::Path, target: &str, output_dir: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("build")
        .arg(path)
        .arg("--target")
        .arg(target)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--json")
        .output()
        .expect("logicpearl build --target should run");
    assert!(
        output.status.success(),
        "logicpearl build --target failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("Inferred --target {target} as ")),
        "build --target should print inference to stderr, got:\n{stderr}"
    );
    serde_json::from_slice(&output.stdout).expect("build output should be JSON")
}

fn run_build_auto(path: &std::path::Path, output_dir: &std::path::Path) -> (Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("build")
        .arg(path)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("Inferred target "),
        "build should print automatic target inference to stderr, got:\n{stderr}"
    );
    (
        serde_json::from_slice(&output.stdout).expect("build output should be JSON"),
        stderr,
    )
}

#[test]
fn doctor_recommends_gate_action_and_fanout_builds() {
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let gate = temp.path().join("gate.csv");
    fs::write(
        &gate,
        "trace_id,score,segment,allowed\n\
r1,0.91,new,no\n\
r2,0.12,known,yes\n\
r3,0.81,new,no\n",
    )
    .expect("gate traces should write");
    let gate_report = run_doctor_json(&gate);
    assert_eq!(gate_report["recommendation"]["mode"], "gate");
    assert_eq!(gate_report["recommendation"]["target_column"], "allowed");
    assert!(gate_report["recommendation"]["command"]
        .as_str()
        .unwrap()
        .contains("--target allowed"));
    assert!(gate_report["recommendation"]["exclude_columns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "trace_id"));

    let action = temp.path().join("action.csv");
    fs::write(
        &action,
        "moisture,paleness,next_action\n\
0.12,1,water\n\
0.5,5,fertilize\n\
0.4,1,do_nothing\n",
    )
    .expect("action traces should write");
    let action_report = run_doctor_json(&action);
    assert_eq!(action_report["recommendation"]["mode"], "action");
    assert_eq!(
        action_report["recommendation"]["target_column"],
        "next_action"
    );
    assert!(action_report["recommendation"]["command"]
        .as_str()
        .unwrap()
        .contains("--target next_action"));

    let fanout = temp.path().join("fanout.csv");
    fs::write(
        &fanout,
        "moisture,pests,sun,applicable_actions\n\
low,yes,low,\"water,treat_pests,move_to_more_sun\"\n\
low,no,ok,water\n\
ok,yes,ok,treat_pests\n",
    )
    .expect("fanout traces should write");
    let fanout_report = run_doctor_json(&fanout);
    assert_eq!(fanout_report["recommendation"]["mode"], "fanout");
    assert_eq!(
        fanout_report["recommendation"]["target_column"],
        "applicable_actions"
    );
    let command = fanout_report["recommendation"]["command"].as_str().unwrap();
    assert!(command.contains("--target applicable_actions"));
}

#[test]
fn build_target_infers_gate_action_and_fanout_artifacts() {
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let gate = temp.path().join("gate.csv");
    fs::write(
        &gate,
        "trace_id,score,segment,allowed\n\
r1,0.91,new,no\n\
r2,0.12,known,yes\n\
r3,0.81,new,no\n\
r4,0.15,known,yes\n",
    )
    .expect("gate traces should write");
    let gate_dir = temp.path().join("gate_out");
    let gate_build = run_build_target(&gate, "allowed", &gate_dir);
    assert_eq!(gate_build["label_column"], "allowed");
    let gate_manifest: Value = serde_json::from_slice(
        &fs::read(gate_dir.join("artifact.json")).expect("gate manifest should exist"),
    )
    .expect("gate manifest should be JSON");
    assert_eq!(gate_manifest["artifact_kind"], "gate");

    let action = temp.path().join("action.csv");
    fs::write(
        &action,
        "moisture,paleness,next_action\n\
0.12,1,water\n\
0.10,1,water\n\
0.5,5,fertilize\n\
0.4,1,do_nothing\n\
0.45,1,do_nothing\n",
    )
    .expect("action traces should write");
    let action_dir = temp.path().join("action_out");
    let action_build = run_build_target(&action, "next_action", &action_dir);
    assert_eq!(action_build["action_column"], "next_action");
    assert_eq!(action_build["default_action"], "do_nothing");
    let action_manifest: Value = serde_json::from_slice(
        &fs::read(action_dir.join("artifact.json")).expect("action manifest should exist"),
    )
    .expect("action manifest should be JSON");
    assert_eq!(action_manifest["artifact_kind"], "action");

    let fanout = temp.path().join("fanout.csv");
    fs::write(
        &fanout,
        "moisture,pests,sun,applicable_actions\n\
low,yes,low,\"water,treat_pests,move_to_more_sun\"\n\
low,no,ok,water\n\
ok,yes,ok,treat_pests\n\
ok,no,low,move_to_more_sun\n",
    )
    .expect("fanout traces should write");
    let fanout_dir = temp.path().join("fanout_out");
    let fanout_build = run_build_target(&fanout, "applicable_actions", &fanout_dir);
    assert_eq!(fanout_build["fanout_column"], "applicable_actions");
    let fanout_manifest: Value = serde_json::from_slice(
        &fs::read(fanout_dir.join("artifact.json")).expect("fanout manifest should exist"),
    )
    .expect("fanout manifest should be JSON");
    assert_eq!(fanout_manifest["artifact_kind"], "pipeline");
}

#[test]
fn bare_build_uses_doctor_target_recommendation() {
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let action = temp.path().join("garden_actions.csv");
    fs::write(
        &action,
        "moisture,paleness,next_action\n\
0.12,1,water\n\
0.10,1,water\n\
0.5,5,fertilize\n\
0.4,1,do_nothing\n\
0.45,1,do_nothing\n",
    )
    .expect("action traces should write");
    let action_dir = temp.path().join("auto_action_out");
    let (action_build, action_stderr) = run_build_auto(&action, &action_dir);
    assert!(action_stderr.contains("Inferred target next_action as action"));
    assert_eq!(action_build["action_column"], "next_action");

    let fanout = temp.path().join("garden_fanout.csv");
    fs::write(
        &fanout,
        "moisture,pests,sun,applicable_actions\n\
low,yes,low,\"water,treat_pests,move_to_more_sun\"\n\
low,no,ok,water\n\
ok,yes,ok,treat_pests\n\
ok,no,low,move_to_more_sun\n",
    )
    .expect("fanout traces should write");
    let fanout_dir = temp.path().join("auto_fanout_out");
    let (fanout_build, fanout_stderr) = run_build_auto(&fanout, &fanout_dir);
    assert!(fanout_stderr.contains("Inferred target applicable_actions as fanout"));
    assert_eq!(fanout_build["fanout_column"], "applicable_actions");
}
