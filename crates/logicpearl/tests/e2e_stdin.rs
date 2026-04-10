use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn run_with_stdin(mut command: Command, stdin_payload: &str) -> std::process::Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("command should spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin pipe should exist")
        .write_all(stdin_payload.as_bytes())
        .expect("stdin payload should write");
    child.wait_with_output().expect("command should finish")
}

#[test]
fn run_accepts_stdin_and_dash_input() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let output_dir = tempdir().expect("temp output dir should be created");
    let artifact_dir = output_dir.path().join("artifact_bundle");
    let sample_csv = repo_root.join("examples/getting_started/decision_traces.csv");
    let sample_input = repo_root.join("examples/getting_started/new_input.json");
    let sample_input_text = fs::read_to_string(&sample_input).expect("sample input should read");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(&sample_csv)
        .arg("--output-dir")
        .arg(&artifact_dir)
        .output()
        .expect("logicpearl build should run");
    assert!(
        build_output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let file_output = Command::new(cli_bin)
        .arg("run")
        .arg(&artifact_dir)
        .arg(&sample_input)
        .output()
        .expect("logicpearl run should accept file input");
    assert!(file_output.status.success());

    let dash_output = run_with_stdin(
        {
            let mut command = Command::new(cli_bin);
            command.arg("run").arg(&artifact_dir).arg("-");
            command
        },
        &sample_input_text,
    );
    assert!(
        dash_output.status.success(),
        "logicpearl run with '-' failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dash_output.stdout),
        String::from_utf8_lossy(&dash_output.stderr)
    );

    let omitted_output = run_with_stdin(
        {
            let mut command = Command::new(cli_bin);
            command.arg("run").arg(&artifact_dir);
            command
        },
        &sample_input_text,
    );
    assert!(
        omitted_output.status.success(),
        "logicpearl run with stdin failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&omitted_output.stdout),
        String::from_utf8_lossy(&omitted_output.stderr)
    );

    assert_eq!(file_output.stdout, dash_output.stdout);
    assert_eq!(file_output.stdout, omitted_output.stdout);
}

#[test]
fn pipeline_run_accepts_stdin_and_dash_input() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let pipeline = repo_root.join("examples/pipelines/authz/pipeline.json");
    let input = repo_root.join("examples/pipelines/authz/input.json");
    let input_text = fs::read_to_string(&input).expect("pipeline input should read");

    let file_output = Command::new(cli_bin)
        .arg("pipeline")
        .arg("run")
        .arg(&pipeline)
        .arg(&input)
        .arg("--json")
        .output()
        .expect("logicpearl pipeline run should accept file input");
    assert!(file_output.status.success());

    let dash_output = run_with_stdin(
        {
            let mut command = Command::new(cli_bin);
            command
                .arg("pipeline")
                .arg("run")
                .arg(&pipeline)
                .arg("-")
                .arg("--json");
            command
        },
        &input_text,
    );
    assert!(
        dash_output.status.success(),
        "logicpearl pipeline run with '-' failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dash_output.stdout),
        String::from_utf8_lossy(&dash_output.stderr)
    );

    let omitted_output = run_with_stdin(
        {
            let mut command = Command::new(cli_bin);
            command
                .arg("pipeline")
                .arg("run")
                .arg(&pipeline)
                .arg("--json");
            command
        },
        &input_text,
    );
    assert!(
        omitted_output.status.success(),
        "logicpearl pipeline run with stdin failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&omitted_output.stdout),
        String::from_utf8_lossy(&omitted_output.stderr)
    );

    let file_json: Value =
        serde_json::from_slice(&file_output.stdout).expect("file output should be valid JSON");
    let dash_json: Value =
        serde_json::from_slice(&dash_output.stdout).expect("dash output should be valid JSON");
    let omitted_json: Value =
        serde_json::from_slice(&omitted_output.stdout).expect("stdin output should be valid JSON");

    assert_eq!(file_json, dash_json);
    assert_eq!(file_json, omitted_json);
}
