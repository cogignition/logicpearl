// SPDX-License-Identifier: MIT
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

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_coaching_error(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr_text(output)
    );
    let stderr = stderr_text(output);
    for section in ["Expected:", "Found:", "Next:"] {
        assert!(
            stderr.contains(section),
            "stderr should include {section:?}:\n{stderr}"
        );
    }
}

#[test]
fn missing_artifact_path_coaches_next_command() {
    let temp = tempdir().expect("temp dir");
    let missing_artifact = temp.path().join("missing_artifact");

    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("inspect")
        .arg(&missing_artifact)
        .output()
        .expect("logicpearl inspect should run");

    assert_coaching_error(&output);
    let stderr = stderr_text(&output);
    assert!(stderr.contains("logicpearl build traces.csv --output-dir output"));
}

#[test]
fn ambiguous_build_target_coaches_doctor_and_target() {
    let temp = tempdir().expect("temp dir");
    let traces = temp.path().join("metrics.csv");
    fs::write(
        &traces,
        "temperature,humidity,note\n71,0.40,ok\n83,0.55,warm\n",
    )
    .expect("traces csv");

    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("build")
        .arg(&traces)
        .arg("--output-dir")
        .arg(temp.path().join("artifact"))
        .output()
        .expect("logicpearl build should run");

    assert_coaching_error(&output);
    let stderr = stderr_text(&output);
    assert!(stderr.contains("logicpearl doctor"));
    assert!(stderr.contains("logicpearl build"));
    assert!(stderr.contains("--target"));
}

#[test]
fn invalid_run_input_json_coaches_validation() {
    let repo_root = repo_root();
    let temp = tempdir().expect("temp dir");
    let artifact_dir = temp.path().join("artifact");
    let invalid_input = temp.path().join("input.json");
    fs::write(&invalid_input, "{not json").expect("invalid input");

    let build = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("build")
        .arg(repo_root.join("examples/getting_started/decision_traces.csv"))
        .arg("--output-dir")
        .arg(&artifact_dir)
        .output()
        .expect("logicpearl build should run");
    assert!(
        build.status.success(),
        "build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        stderr_text(&build)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .arg("run")
        .arg(&artifact_dir)
        .arg(&invalid_input)
        .output()
        .expect("logicpearl run should run");

    assert_coaching_error(&output);
    let stderr = stderr_text(&output);
    assert!(stderr.contains("jq empty"));
}
