use logicpearl_discovery::BuildResult;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl-cli crate should live under workspace/crates/logicpearl-cli")
        .to_path_buf()
}

#[test]
fn sample_dataset_builds_artifact_bundle_and_runs_compiled_binary() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let output_dir = tempdir().expect("temp output dir should be created");
    let output_path = output_dir.path().join("artifact_bundle");
    let sample_csv = repo_root.join("examples/getting_started/decision_traces.csv");
    let sample_input = repo_root.join("examples/getting_started/new_input.json");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(&sample_csv)
        .arg("--output-dir")
        .arg(&output_path)
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        build_output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let build_result: BuildResult =
        serde_json::from_slice(&build_output.stdout).expect("build output should be valid JSON");
    assert_eq!(build_result.label_column, "allowed");
    assert!(Path::new(&build_result.output_files.artifact_manifest).exists());
    assert!(Path::new(&build_result.output_files.pearl_ir).exists());
    assert!(Path::new(&build_result.output_files.build_report).exists());
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&build_result.output_files.artifact_manifest)
            .expect("artifact manifest should be readable"),
    )
    .expect("artifact manifest should be valid JSON");
    assert_eq!(
        manifest["bundle"]["bundle_kind"].as_str(),
        Some("direct_pearl_bundle")
    );
    assert_eq!(
        manifest["bundle"]["cli_entrypoint"].as_str(),
        Some("artifact.json")
    );
    assert!(
        manifest["bundle"]["deployables"]
            .as_array()
            .is_some_and(|deployables| !deployables.is_empty()),
        "artifact manifest should describe deployable outputs"
    );

    let native_binary = build_result
        .output_files
        .native_binary
        .as_ref()
        .expect("build should emit a native binary");
    assert!(Path::new(native_binary).exists());

    let compiled_output = Command::new(native_binary)
        .arg(&sample_input)
        .output()
        .expect("compiled pearl binary should run");
    assert!(
        compiled_output.status.success(),
        "compiled pearl binary failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled_output.stdout),
        String::from_utf8_lossy(&compiled_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&compiled_output.stdout).trim(),
        "0",
        "compiled pearl binary should return the expected bitmask"
    );
}

#[test]
fn sample_dataset_passes_formal_spec_verification() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let output_dir = tempdir().expect("temp output dir should be created");
    let output_path = output_dir.path().join("artifact_bundle");
    let sample_csv = repo_root.join("examples/getting_started/decision_traces.csv");
    let sample_spec = repo_root.join("examples/getting_started/access_policy.spec.json");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(&sample_csv)
        .arg("--output-dir")
        .arg(&output_path)
        .output()
        .expect("logicpearl build should run");
    assert!(
        build_output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let verify_output = Command::new(cli_bin)
        .arg("conformance")
        .arg("spec-verify")
        .arg(&output_path)
        .arg(&sample_spec)
        .arg("--json")
        .output()
        .expect("logicpearl conformance spec-verify should run");
    assert!(
        verify_output.status.success(),
        "logicpearl conformance spec-verify failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify_output.stdout),
        String::from_utf8_lossy(&verify_output.stderr)
    );

    let report: Value = serde_json::from_slice(&verify_output.stdout)
        .expect("spec-verify output should be valid JSON");
    assert_eq!(report["spec_rule_count"].as_u64(), Some(1));
    assert!(report["complete"].as_bool().unwrap_or(false));
    assert!(report["no_spurious_rules"].as_bool().unwrap_or(false));
    assert!(report["fully_verified"].as_bool().unwrap_or(false));
}
