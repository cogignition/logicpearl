// SPDX-License-Identifier: MIT
use logicpearl_discovery::BuildResult;
use serde_json::Value;
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

#[test]
fn synthetic_trace_generator_emits_clean_dataset_that_builds() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp directory should exist");
    let spec = repo_root.join("examples/getting_started/synthetic_access_policy.tracegen.json");
    let traces_path = temp.path().join("synthetic_access_policy.jsonl");
    let artifact_dir = temp.path().join("artifact_bundle");

    let generate = Command::new(cli_bin)
        .arg("traces")
        .arg("generate")
        .arg(&spec)
        .arg("--output")
        .arg(&traces_path)
        .arg("--json")
        .output()
        .expect("trace generation should run");
    assert!(
        generate.status.success(),
        "logicpearl traces generate failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&generate.stdout),
        String::from_utf8_lossy(&generate.stderr)
    );

    let generate_report: Value =
        serde_json::from_slice(&generate.stdout).expect("generate output should be valid JSON");
    assert_eq!(generate_report["row_count"].as_u64(), Some(240));
    assert_eq!(
        generate_report["audit"]["suspicious_nuisance_fields"]
            .as_array()
            .map(|items| items.len()),
        Some(0)
    );

    let audit = Command::new(cli_bin)
        .arg("traces")
        .arg("audit")
        .arg(&traces_path)
        .arg("--spec")
        .arg(&spec)
        .arg("--fail-on-skew")
        .arg("--json")
        .output()
        .expect("trace audit should run");
    assert!(
        audit.status.success(),
        "logicpearl traces audit failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );

    let build = Command::new(cli_bin)
        .arg("build")
        .arg(&traces_path)
        .arg("--output-dir")
        .arg(&artifact_dir)
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        build.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let build_result: BuildResult =
        serde_json::from_slice(&build.stdout).expect("build output should be valid JSON");
    assert_eq!(build_result.label_column, "allowed");
    assert!(build_result.training_parity >= 0.95);
}
