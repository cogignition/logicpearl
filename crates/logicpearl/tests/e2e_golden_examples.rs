// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn run_cli(args: &[String]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .args(args)
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl {:?} failed:\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout should be UTF-8")
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn rust_target_installed(target: &str) -> bool {
    Command::new("rustup")
        .arg("target")
        .arg("list")
        .arg("--installed")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.lines().any(|line| line.trim() == target))
        .unwrap_or(false)
}

fn run_native(artifact_dir: &Path, input_path: &Path) -> String {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join("artifact.json")).expect("manifest should read"),
    )
    .expect("manifest should parse");
    let native = artifact_dir.join(
        manifest["files"]["native"]
            .as_str()
            .expect("native compile should update manifest"),
    );
    let output = Command::new(native)
        .arg(input_path)
        .output()
        .expect("native runner should execute");
    assert!(
        output.status.success(),
        "native runner failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("native stdout should be UTF-8")
}

#[test]
fn golden_examples_build_run_diff_and_compile() {
    let root = repo_root();
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let gate_dir = temp.path().join("gate");
    let gate_v2_dir = temp.path().join("gate-v2");
    let gate_input = root.join("examples/golden/gate-approve-deny/input.json");
    run_cli(&[
        "build".into(),
        root.join("examples/golden/gate-approve-deny/traces.csv")
            .display()
            .to_string(),
        "--feature-dictionary".into(),
        root.join("examples/golden/gate-approve-deny/feature_dictionary.json")
            .display()
            .to_string(),
        "--output-dir".into(),
        gate_dir.display().to_string(),
    ]);
    let gate_inspect = run_cli(&["inspect".into(), gate_dir.display().to_string()]);
    assert!(gate_inspect.contains("Purchase amount at or above"));
    let gate_run = run_cli(&[
        "run".into(),
        gate_dir.display().to_string(),
        gate_input.display().to_string(),
        "--explain".into(),
    ]);
    assert!(gate_run.contains("bitmask:"), "{gate_run}");
    assert!(
        gate_run.contains("Purchase amount at or above"),
        "{gate_run}"
    );
    run_cli(&[
        "build".into(),
        root.join("examples/golden/gate-approve-deny/traces_v2.csv")
            .display()
            .to_string(),
        "--feature-dictionary".into(),
        root.join("examples/golden/gate-approve-deny/feature_dictionary.json")
            .display()
            .to_string(),
        "--output-dir".into(),
        gate_v2_dir.display().to_string(),
    ]);
    let gate_diff = run_cli(&[
        "diff".into(),
        gate_dir.display().to_string(),
        gate_v2_dir.display().to_string(),
    ]);
    assert!(gate_diff.contains("evidence_changed"), "{gate_diff}");

    let action_dir = temp.path().join("action");
    let action_v2_dir = temp.path().join("action-v2");
    let action_input = root.join("examples/golden/action-next-step/input.json");
    let action_build_args = |traces: &str, output_dir: &Path| -> Vec<String> {
        vec![
            "build".into(),
            root.join(traces).display().to_string(),
            "--feature-dictionary".into(),
            root.join("examples/golden/action-next-step/feature_dictionary.json")
                .display()
                .to_string(),
            "--output-dir".into(),
            output_dir.display().to_string(),
            "--action-column".into(),
            "next_action".into(),
            "--default-action".into(),
            "close".into(),
            "--action-priority".into(),
            "escalate_fraud,ask_for_info,refund".into(),
        ]
    };
    run_cli(&action_build_args(
        "examples/golden/action-next-step/traces.csv",
        &action_dir,
    ));
    let action_run = run_cli(&[
        "run".into(),
        action_dir.display().to_string(),
        action_input.display().to_string(),
        "--explain".into(),
    ]);
    assert!(
        action_run.contains("action: escalate_fraud"),
        "{action_run}"
    );
    run_cli(&action_build_args(
        "examples/golden/action-next-step/traces_v2.csv",
        &action_v2_dir,
    ));
    let action_diff = run_cli(&[
        "diff".into(),
        action_dir.display().to_string(),
        action_v2_dir.display().to_string(),
    ]);
    assert!(
        action_diff.contains("rule_predicate_changed"),
        "{action_diff}"
    );
    assert!(action_diff.contains("Days since purchase at or below 20.0"));

    let fanout_dir = temp.path().join("fanout");
    let fanout_v2_dir = temp.path().join("fanout-v2");
    let fanout_input = root.join("examples/golden/fanout-applicable-actions/input.json");
    let fanout_build_args = |traces: &str, output_dir: &Path| -> Vec<String> {
        vec![
            "build".into(),
            root.join(traces).display().to_string(),
            "--feature-dictionary".into(),
            root.join("examples/golden/fanout-applicable-actions/feature_dictionary.json")
                .display()
                .to_string(),
            "--output-dir".into(),
            output_dir.display().to_string(),
            "--fanout-column".into(),
            "applicable_actions".into(),
        ]
    };
    run_cli(&fanout_build_args(
        "examples/golden/fanout-applicable-actions/traces.csv",
        &fanout_dir,
    ));
    let fanout_run = run_cli(&[
        "pipeline".into(),
        "run".into(),
        fanout_dir.join("pipeline.json").display().to_string(),
        fanout_input.display().to_string(),
        "--json".into(),
    ]);
    let fanout_json: Value = serde_json::from_str(&fanout_run).expect("fanout run should be JSON");
    assert_eq!(fanout_json["decision_kind"], "fanout");
    assert!(fanout_json["applicable_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action == "scale_workers"));
    run_cli(&fanout_build_args(
        "examples/golden/fanout-applicable-actions/traces_v2.csv",
        &fanout_v2_dir,
    ));
    let fanout_diff = run_cli(&[
        "diff".into(),
        fanout_dir
            .join("actions/scale_workers/artifact.json")
            .display()
            .to_string(),
        fanout_v2_dir
            .join("actions/scale_workers/artifact.json")
            .display()
            .to_string(),
    ]);
    assert!(fanout_diff.contains("CPU utilization at or above 84.0"));

    for (artifact_dir, input_path) in [
        (&gate_dir, &gate_input),
        (&action_dir, &action_input),
        (&fanout_dir, &fanout_input),
    ] {
        run_cli(&["compile".into(), artifact_dir.display().to_string()]);
        let native = run_native(artifact_dir, input_path);
        assert!(!native.trim().is_empty());
    }

    if rust_target_installed("wasm32-unknown-unknown") && command_available("node") {
        run_cli(&[
            "compile".into(),
            action_dir.display().to_string(),
            "--target".into(),
            "wasm32-unknown-unknown".into(),
        ]);
        let browser = Command::new("node")
            .arg(root.join("examples/golden/browser-check.mjs"))
            .arg(&action_dir)
            .arg(&action_input)
            .output()
            .expect("browser check should run");
        assert!(
            browser.status.success(),
            "browser check failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&browser.stdout),
            String::from_utf8_lossy(&browser.stderr)
        );
        let browser_json: Value =
            serde_json::from_slice(&browser.stdout).expect("browser output should be JSON");
        assert_eq!(browser_json["decision_kind"], "action");
        assert_eq!(browser_json["action"], "escalate_fraud");
    }
}
