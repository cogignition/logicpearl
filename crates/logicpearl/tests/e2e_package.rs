// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn run_cli(args: &[String]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl command failed:\nargs: {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn build_fixture(temp: &Path) -> std::path::PathBuf {
    let traces = temp.join("traces.csv");
    let artifact = temp.join("artifact");
    fs::write(
        &traces,
        "risk_score,allowed\n90,denied\n85,denied\n10,allowed\n20,allowed\n",
    )
    .expect("traces should write");
    run_cli(&[
        "build".into(),
        traces.display().to_string(),
        "--target".into(),
        "allowed".into(),
        "--output-dir".into(),
        artifact.display().to_string(),
        "--json".into(),
    ]);
    artifact
}

#[test]
fn package_native_writes_self_contained_deploy_bundle() {
    let temp = tempdir().expect("temp dir should exist");
    let artifact = build_fixture(temp.path());
    let package_dir = temp.path().join("native-package");
    let package_json = run_cli(&[
        "package".into(),
        artifact.display().to_string(),
        "--native".into(),
        "--output-dir".into(),
        package_dir.display().to_string(),
        "--json".into(),
    ]);
    let package: Value = serde_json::from_str(&package_json).expect("package output should parse");
    assert_eq!(
        package["schema_version"].as_str(),
        Some("logicpearl.deploy_package.v1")
    );
    assert_eq!(package["package_kind"].as_str(), Some("native"));
    let deployable = package["primary_deployable"]
        .as_str()
        .expect("deployable should be present");

    assert!(package_dir.join("artifact.json").exists());
    assert!(package_dir.join("pearl.ir.json").exists());
    assert!(package_dir.join(deployable).exists());
    assert!(package_dir.join("logicpearl.package.json").exists());
    assert!(package_dir.join("README.md").exists());

    run_cli(&[
        "artifact".into(),
        "verify".into(),
        package_dir.display().to_string(),
        "--json".into(),
    ]);
}
