// SPDX-License-Identifier: MIT
use logicpearl_discovery::{BuildResult, SelectionPolicy};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn run_build_json(dataset: &Path, output_dir: &Path, extra_args: &[&str]) -> BuildResult {
    let mut command = Command::new(env!("CARGO_BIN_EXE_logicpearl"));
    command
        .arg("build")
        .arg(dataset)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--json");
    for arg in extra_args {
        command.arg(arg);
    }
    let output = command.output().expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("build output should be valid JSON")
}

fn run_build_value(dataset: &Path, output_dir: &Path, extra_args: &[&str]) -> serde_json::Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_logicpearl"));
    command
        .arg("build")
        .arg(dataset)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--json");
    for arg in extra_args {
        command.arg(arg);
    }
    let output = command.output().expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("build output should be valid JSON")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

#[test]
fn recall_biased_build_hits_requested_recall_within_cap() {
    let temp = tempdir().expect("temp dir should exist");
    let dataset = temp.path().join("selection_policy.csv");
    fs::write(
        &dataset,
        "signal_a,signal_b,allowed\n\
1,0,denied\n\
1,0,denied\n\
0,1,denied\n\
0,0,denied\n\
0,0,allowed\n\
0,0,allowed\n\
0,1,allowed\n\
0,0,allowed\n",
    )
    .expect("selection-policy fixture should write");

    let balanced = run_build_json(&dataset, &temp.path().join("balanced"), &[]);
    let recall = run_build_json(
        &dataset,
        &temp.path().join("recall"),
        &[
            "--selection-policy",
            "recall-biased",
            "--deny-recall-target",
            "0.75",
            "--max-false-positive-rate",
            "0.25",
        ],
    );

    assert!(matches!(
        balanced.selection_policy.configured,
        SelectionPolicy::Balanced
    ));

    assert!(matches!(
        recall.selection_policy.configured,
        SelectionPolicy::RecallBiased {
            deny_recall_target,
            max_false_positive_rate,
        } if (deny_recall_target - 0.75).abs() < f64::EPSILON
            && (max_false_positive_rate - 0.25).abs() < f64::EPSILON
    ));
    assert!(recall.selection_policy.constraints_satisfied);
    assert_eq!(recall.selection_policy.denied_examples, 4);
    assert_eq!(recall.selection_policy.allowed_examples, 4);
    assert_eq!(recall.selection_policy.false_negatives, 1);
    assert_eq!(recall.selection_policy.false_positives, 1);
    assert!((recall.selection_policy.denied_recall - 0.75).abs() < 1e-9);
    assert!((recall.selection_policy.false_positive_rate - 0.25).abs() < 1e-9);
}

#[test]
fn recall_biased_policy_reaches_action_and_fanout_build_wrappers() {
    let temp = tempdir().expect("temp dir should exist");
    let root = repo_root();
    let policy_args = [
        "--selection-policy",
        "recall-biased",
        "--deny-recall-target",
        "0.50",
        "--max-false-positive-rate",
        "0.50",
    ];

    let mut action_args = vec![
        "--action-column",
        "next_action",
        "--default-action",
        "close",
        "--action-priority",
        "escalate_fraud,ask_for_info,refund",
    ];
    action_args.extend(policy_args);
    let action_report = run_build_value(
        &root.join("examples/golden/action-next-step/traces.csv"),
        &temp.path().join("action"),
        &action_args,
    );
    assert_eq!(
        action_report["selection_policy"]["policy"].as_str(),
        Some("recall_biased")
    );

    let mut fanout_args = vec!["--fanout-column", "applicable_actions"];
    fanout_args.extend(policy_args);
    let fanout_report = run_build_value(
        &root.join("examples/golden/fanout-applicable-actions/traces.csv"),
        &temp.path().join("fanout"),
        &fanout_args,
    );
    assert_eq!(
        fanout_report["selection_policy"]["policy"].as_str(),
        Some("recall_biased")
    );
}
