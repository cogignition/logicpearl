use logicpearl_discovery::{BuildResult, ExactSelectionBackend};
use serde_json::Value;
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

fn run_build_json_with_env(
    cli_bin: &str,
    dataset: &Path,
    output_dir: &Path,
    envs: &[(&str, &str)],
) -> BuildResult {
    let mut command = Command::new(cli_bin);
    command
        .arg("build")
        .arg(dataset)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--json");
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nenvs: {:?}\nstdout:\n{}\nstderr:\n{}",
        envs,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("build output should be valid JSON")
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

#[test]
fn build_mip_matches_smt_rule_artifact_on_large_exact_selection_fixture() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    let dataset = temp.path().join("large_exact_selection.csv");
    let smt_output = temp.path().join("smt_bundle");
    let mip_output = temp.path().join("mip_bundle");
    let csv = (1..=18)
        .map(|value| format!("{value},{}\n", if value == 18 { 1 } else { 0 }))
        .collect::<String>();
    fs::write(&dataset, format!("score,allowed\n{csv}"))
        .expect("large exact-selection fixture should be written");

    let smt_build = run_build_json_with_env(
        cli_bin,
        &dataset,
        &smt_output,
        &[("LOGICPEARL_DISCOVERY_SELECTION_BACKEND", "smt")],
    );
    let mip_build = run_build_json_with_env(
        cli_bin,
        &dataset,
        &mip_output,
        &[("LOGICPEARL_DISCOVERY_SELECTION_BACKEND", "mip")],
    );

    let smt_ir: Value = serde_json::from_str(
        &fs::read_to_string(&smt_build.output_files.pearl_ir)
            .expect("smt pearl ir should be readable"),
    )
    .expect("smt pearl ir should be valid JSON");
    let mip_ir: Value = serde_json::from_str(
        &fs::read_to_string(&mip_build.output_files.pearl_ir)
            .expect("mip pearl ir should be readable"),
    )
    .expect("mip pearl ir should be valid JSON");

    assert_eq!(
        smt_build.exact_selection.backend,
        Some(ExactSelectionBackend::Smt)
    );
    assert_eq!(
        mip_build.exact_selection.backend,
        Some(ExactSelectionBackend::Mip)
    );
    assert_eq!(smt_build.exact_selection.selected_candidates, 1);
    assert_eq!(mip_build.exact_selection.selected_candidates, 1);
    assert!(!smt_build.exact_selection.adopted);
    assert!(!mip_build.exact_selection.adopted);
    assert_eq!(
        smt_build.exact_selection.detail.as_deref(),
        Some("kept greedy plan because exact selection was not better")
    );
    assert_eq!(
        mip_build.exact_selection.detail.as_deref(),
        Some("kept greedy plan because exact selection was not better")
    );
    assert_eq!(mip_ir["rules"], smt_ir["rules"]);
}

#[test]
fn build_cache_respects_internal_discovery_selection_backend() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    let dataset = temp.path().join("large_exact_selection.csv");
    let output_dir = temp.path().join("shared_bundle");
    let csv = (1..=18)
        .map(|value| format!("{value},{}\n", if value == 18 { 1 } else { 0 }))
        .collect::<String>();
    fs::write(&dataset, format!("score,allowed\n{csv}"))
        .expect("large exact-selection fixture should be written");

    let smt_build = run_build_json_with_env(
        cli_bin,
        &dataset,
        &output_dir,
        &[("LOGICPEARL_DISCOVERY_SELECTION_BACKEND", "smt")],
    );
    let mip_build = run_build_json_with_env(
        cli_bin,
        &dataset,
        &output_dir,
        &[("LOGICPEARL_DISCOVERY_SELECTION_BACKEND", "mip")],
    );
    let mip_cached = run_build_json_with_env(
        cli_bin,
        &dataset,
        &output_dir,
        &[("LOGICPEARL_DISCOVERY_SELECTION_BACKEND", "mip")],
    );

    assert!(!smt_build.cache_hit);
    assert!(!mip_build.cache_hit);
    assert!(mip_cached.cache_hit);
    assert_eq!(
        smt_build.exact_selection.backend,
        Some(ExactSelectionBackend::Smt)
    );
    assert_eq!(
        mip_build.exact_selection.backend,
        Some(ExactSelectionBackend::Mip)
    );
    assert_eq!(
        mip_cached.exact_selection.backend,
        Some(ExactSelectionBackend::Mip)
    );
}
