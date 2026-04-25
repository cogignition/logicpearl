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
        .contains("--label-column allowed"));
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
        .contains("--default-action do_nothing"));

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
    assert!(command.contains("--fanout-column applicable_actions"));
    assert!(command.contains("--fanout-actions"));
    assert!(command.contains("move_to_more_sun"));
}
