// SPDX-License-Identifier: MIT
use serde::Deserialize;
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

fn fixture_root() -> PathBuf {
    repo_root().join("fixtures/contracts/revenue_recovery")
}

fn run_cli_output(cli_bin: &str, args: &[String]) -> std::process::Output {
    Command::new(cli_bin)
        .args(args)
        .output()
        .expect("logicpearl command should run")
}

fn run_cli_json(cli_bin: &str, args: &[String]) -> Value {
    let output = run_cli_output(cli_bin, args);
    assert!(
        output.status.success(),
        "logicpearl command failed:\nargs: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command output should be valid JSON")
}

#[derive(Debug, Deserialize)]
struct ContractManifest {
    artifacts: Vec<ArtifactContract>,
}

#[derive(Debug, Deserialize)]
struct ArtifactContract {
    artifact_id: String,
    title: String,
    bundle_dir: String,
    inspect_expectation: InspectExpectation,
    scenarios: Vec<ScenarioExpectation>,
    diff_expectation: Option<DiffExpectation>,
}

#[derive(Debug, Deserialize)]
struct InspectExpectation {
    gate_id: String,
    rules: u64,
    features: u64,
    rule_ids_in_order: Vec<String>,
    feature_ids_in_order: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ScenarioExpectation {
    name: String,
    feature_map: Value,
    expected_bitmask: u64,
    expected_missing_rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DiffExpectation {
    earlier_ir: String,
    current_ir: String,
    summary: DiffSummaryExpectation,
    changed_rule_ids: Vec<String>,
    added_rule_ids: Vec<String>,
    removed_rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DiffSummaryExpectation {
    changed_rules: u64,
    reordered_rules: u64,
    added_rules: u64,
    removed_rules: u64,
}

fn load_manifest() -> ContractManifest {
    serde_json::from_str(
        &fs::read_to_string(fixture_root().join("contract_manifest.json"))
            .expect("revenue contract manifest should read"),
    )
    .expect("revenue contract manifest should parse")
}

fn parse_run_output(output: &std::process::Output) -> u64 {
    assert!(
        output.status.success(),
        "logicpearl run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .expect("run output should be an integer bitmask")
}

#[test]
fn revenue_contract_artifacts_preserve_expected_runtime_behavior() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = fixture_root();
    let manifest = load_manifest();

    for artifact in manifest.artifacts {
        let bundle_dir = root.join(&artifact.bundle_dir);
        let pearl_ir = bundle_dir.join("pearl.ir.json");
        let artifact_manifest = bundle_dir.join("artifact.json");
        let pearl_ir_value: Value = serde_json::from_str(
            &fs::read_to_string(&pearl_ir).expect("frozen pearl ir should read"),
        )
        .expect("frozen pearl ir should parse");

        let inspect_bundle = run_cli_json(
            cli_bin,
            &[
                "inspect".to_string(),
                bundle_dir.display().to_string(),
                "--json".to_string(),
            ],
        );
        let inspect_manifest = run_cli_json(
            cli_bin,
            &[
                "inspect".to_string(),
                artifact_manifest.display().to_string(),
                "--json".to_string(),
            ],
        );
        let inspect_ir = run_cli_json(
            cli_bin,
            &[
                "inspect".to_string(),
                pearl_ir.display().to_string(),
                "--json".to_string(),
            ],
        );

        for report in [&inspect_bundle, &inspect_manifest, &inspect_ir] {
            assert_eq!(
                report["gate_id"].as_str(),
                Some(artifact.inspect_expectation.gate_id.as_str()),
                "inspect gate_id mismatch for {}",
                artifact.artifact_id
            );
            assert_eq!(
                report["rules"].as_u64(),
                Some(artifact.inspect_expectation.rules),
                "inspect rule count mismatch for {}",
                artifact.artifact_id
            );
            assert_eq!(
                report["features"].as_u64(),
                Some(artifact.inspect_expectation.features),
                "inspect feature count mismatch for {}",
                artifact.artifact_id
            );
        }

        let actual_rule_ids: Vec<String> = pearl_ir_value["rules"]
            .as_array()
            .expect("rules should be an array")
            .iter()
            .filter_map(|rule| rule["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(
            actual_rule_ids, artifact.inspect_expectation.rule_ids_in_order,
            "rule order mismatch for {} ({})",
            artifact.artifact_id, artifact.title
        );

        let actual_feature_ids: Vec<String> = pearl_ir_value["input_schema"]["features"]
            .as_array()
            .expect("input_schema.features should be an array")
            .iter()
            .filter_map(|feature| feature["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(
            actual_feature_ids, artifact.inspect_expectation.feature_ids_in_order,
            "feature order mismatch for {} ({})",
            artifact.artifact_id, artifact.title
        );

        for scenario in artifact.scenarios {
            let temp = tempdir().expect("temp directory should be created");
            let input_path = temp.path().join(format!("{}.input.json", scenario.name));
            fs::write(
                &input_path,
                serde_json::to_string_pretty(&scenario.feature_map)
                    .expect("feature map should serialize"),
            )
            .expect("scenario input should write");

            let bundle_output = run_cli_output(
                cli_bin,
                &[
                    "run".to_string(),
                    bundle_dir.display().to_string(),
                    input_path.display().to_string(),
                ],
            );
            let manifest_output = run_cli_output(
                cli_bin,
                &[
                    "run".to_string(),
                    artifact_manifest.display().to_string(),
                    input_path.display().to_string(),
                ],
            );
            let ir_output = run_cli_output(
                cli_bin,
                &[
                    "run".to_string(),
                    pearl_ir.display().to_string(),
                    input_path.display().to_string(),
                ],
            );

            let bundle_mask = parse_run_output(&bundle_output);
            let manifest_mask = parse_run_output(&manifest_output);
            let ir_mask = parse_run_output(&ir_output);

            assert_eq!(
                bundle_mask, scenario.expected_bitmask,
                "bundle runtime mismatch for {} scenario {}",
                artifact.artifact_id, scenario.name
            );
            assert_eq!(
                manifest_mask, scenario.expected_bitmask,
                "artifact manifest runtime mismatch for {} scenario {}",
                artifact.artifact_id, scenario.name
            );
            assert_eq!(
                ir_mask, scenario.expected_bitmask,
                "pearl ir runtime mismatch for {} scenario {}",
                artifact.artifact_id, scenario.name
            );

            let actual_missing_rule_ids: Vec<String> = pearl_ir_value["rules"]
                .as_array()
                .expect("rules should be an array")
                .iter()
                .filter(|rule| {
                    rule["bit"]
                        .as_u64()
                        .map(|bit| bundle_mask & (1_u64 << bit) != 0)
                        .unwrap_or(false)
                })
                .filter_map(|rule| rule["id"].as_str().map(ToOwned::to_owned))
                .collect();
            assert_eq!(
                actual_missing_rule_ids, scenario.expected_missing_rule_ids,
                "missing rule ids mismatch for {} scenario {}",
                artifact.artifact_id, scenario.name
            );
        }
    }
}

#[test]
fn revenue_contract_artifacts_report_expected_semantic_diffs() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = fixture_root();
    let manifest = load_manifest();

    for artifact in manifest.artifacts {
        let Some(diff_expectation) = artifact.diff_expectation else {
            continue;
        };
        let earlier_ir = root.join(&diff_expectation.earlier_ir);
        let current_ir = root.join(&diff_expectation.current_ir);
        let diff = run_cli_json(
            cli_bin,
            &[
                "diff".to_string(),
                earlier_ir.display().to_string(),
                current_ir.display().to_string(),
                "--json".to_string(),
            ],
        );

        assert_eq!(
            diff["summary"]["changed_rules"].as_u64(),
            Some(diff_expectation.summary.changed_rules),
            "changed_rules mismatch for {}",
            artifact.artifact_id
        );
        assert_eq!(
            diff["summary"]["reordered_rules"].as_u64(),
            Some(diff_expectation.summary.reordered_rules),
            "reordered_rules mismatch for {}",
            artifact.artifact_id
        );
        assert_eq!(
            diff["summary"]["added_rules"].as_u64(),
            Some(diff_expectation.summary.added_rules),
            "added_rules mismatch for {}",
            artifact.artifact_id
        );
        assert_eq!(
            diff["summary"]["removed_rules"].as_u64(),
            Some(diff_expectation.summary.removed_rules),
            "removed_rules mismatch for {}",
            artifact.artifact_id
        );

        let changed_rule_ids: Vec<String> = diff["changed_rules"]
            .as_array()
            .expect("changed_rules should be an array")
            .iter()
            .filter_map(|rule| rule["rule_id"].as_str().map(ToOwned::to_owned))
            .collect();
        let added_rule_ids: Vec<String> = diff["added_rules"]
            .as_array()
            .expect("added_rules should be an array")
            .iter()
            .filter_map(|rule| rule["id"].as_str().map(ToOwned::to_owned))
            .collect();
        let removed_rule_ids: Vec<String> = diff["removed_rules"]
            .as_array()
            .expect("removed_rules should be an array")
            .iter()
            .filter_map(|rule| rule["id"].as_str().map(ToOwned::to_owned))
            .collect();

        assert_eq!(
            changed_rule_ids, diff_expectation.changed_rule_ids,
            "changed rule ids mismatch for {}",
            artifact.artifact_id
        );
        assert_eq!(
            added_rule_ids, diff_expectation.added_rule_ids,
            "added rule ids mismatch for {}",
            artifact.artifact_id
        );
        assert_eq!(
            removed_rule_ids, diff_expectation.removed_rule_ids,
            "removed rule ids mismatch for {}",
            artifact.artifact_id
        );
    }
}
