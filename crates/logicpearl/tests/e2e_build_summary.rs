// SPDX-License-Identifier: MIT
use std::fs;
use std::process::Command;

fn build_stdout(path: &std::path::Path, output_dir: &std::path::Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("build")
        .arg(path)
        .arg("--output-dir")
        .arg(output_dir)
        .output()
        .expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("build stdout should be UTF-8")
}

fn assert_summary_shape(stdout: &str, artifact_kind: &str) {
    assert!(
        stdout.contains(&format!("Built {artifact_kind}")),
        "summary should identify artifact kind:\n{stdout}"
    );
    for expected in [
        "Learned",
        "Metrics",
        "Top rules",
        "Bundle",
        "Next commands",
        "logicpearl run",
        "logicpearl inspect",
        "logicpearl diff old_artifact",
        "logicpearl compile",
        "logicpearl artifact verify",
    ] {
        assert!(
            stdout.contains(expected),
            "summary should contain {expected:?}:\n{stdout}"
        );
    }
}

#[test]
fn build_prints_first_artifact_summary_for_gate_action_and_fanout() {
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let gate = temp.path().join("gate.csv");
    fs::write(
        &gate,
        "risk,segment,allowed\n\
9,new,no\n\
8,new,no\n\
1,known,yes\n\
2,known,yes\n",
    )
    .expect("gate traces should write");
    let gate_stdout = build_stdout(&gate, &temp.path().join("gate_out"));
    assert_summary_shape(&gate_stdout, "gate");

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
    let action_stdout = build_stdout(&action, &temp.path().join("action_out"));
    assert_summary_shape(&action_stdout, "action artifact");

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
    let fanout_stdout = build_stdout(&fanout, &temp.path().join("fanout_out"));
    assert_summary_shape(&fanout_stdout, "fan-out pipeline");
}
