// SPDX-License-Identifier: MIT
use logicpearl_discovery::BuildResult;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

const FEATURE_ID: &str =
    "requirement__req-003-transcutaneous-electrical-nerve-stimulation-prn-p1-001__satisfied";

fn run_build(cli_bin: &str, traces: &Path, output_dir: &Path, dictionary: Option<&Path>) {
    let mut command = Command::new(cli_bin);
    command
        .arg("build")
        .arg(traces)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--json");
    if let Some(dictionary) = dictionary {
        command.arg("--feature-dictionary").arg(dictionary);
    }
    let output = command.output().expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _: BuildResult =
        serde_json::from_slice(&output.stdout).expect("build output should be valid JSON");
}

fn run_bitmask(cli_bin: &str, artifact: &Path, input: &Path) -> String {
    let output = Command::new(cli_bin)
        .arg("run")
        .arg(artifact)
        .arg(input)
        .output()
        .expect("logicpearl run should run");
    assert!(
        output.status.success(),
        "logicpearl run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn inspect_nudges_raw_rules_toward_feature_dictionary_review() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp directory should exist");
    let traces = temp.path().join("traces.csv");
    let artifact = temp.path().join("raw");
    let starter_dictionary = temp.path().join("feature_dictionary.starter.json");

    fs::write(
        &traces,
        "risk_score,allowed\n90,denied\n85,denied\n10,allowed\n20,allowed\n",
    )
    .expect("traces should be writable");

    let build = Command::new(cli_bin)
        .arg("build")
        .arg(&traces)
        .arg("--output-dir")
        .arg(&artifact)
        .arg("--raw-feature-ids")
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        build.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let inspect_text = Command::new(cli_bin)
        .arg("inspect")
        .arg(&artifact)
        .output()
        .expect("logicpearl inspect should run");
    assert!(
        inspect_text.status.success(),
        "logicpearl inspect failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect_text.stdout),
        String::from_utf8_lossy(&inspect_text.stderr)
    );
    let inspect_stdout = String::from_utf8_lossy(&inspect_text.stdout);
    assert!(
        inspect_stdout.contains("These rules use raw feature ids"),
        "{inspect_stdout}"
    );
    assert!(
        inspect_stdout.contains("--write-feature-dictionary"),
        "{inspect_stdout}"
    );

    let inspect_json = Command::new(cli_bin)
        .arg("inspect")
        .arg(&artifact)
        .arg("--json")
        .output()
        .expect("logicpearl inspect --json should run");
    assert!(
        inspect_json.status.success(),
        "logicpearl inspect --json failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect_json.stdout),
        String::from_utf8_lossy(&inspect_json.stderr)
    );
    let inspect_value: Value =
        serde_json::from_slice(&inspect_json.stdout).expect("inspect output should parse");
    assert_eq!(
        inspect_value["review_advice"]["kind"].as_str(),
        Some("raw_feature_ids")
    );
    assert_eq!(
        inspect_value["review_advice"]["raw_features"][0].as_str(),
        Some("risk_score")
    );

    let generate = Command::new(cli_bin)
        .arg("inspect")
        .arg(&artifact)
        .arg("--write-feature-dictionary")
        .arg(&starter_dictionary)
        .output()
        .expect("logicpearl inspect --write-feature-dictionary should run");
    assert!(
        generate.status.success(),
        "logicpearl inspect --write-feature-dictionary failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&generate.stdout),
        String::from_utf8_lossy(&generate.stderr)
    );
    let dictionary: Value = serde_json::from_str(
        &fs::read_to_string(&starter_dictionary).expect("starter dictionary should be readable"),
    )
    .expect("starter dictionary should parse");
    assert_eq!(
        dictionary["features"]["risk_score"]["label"].as_str(),
        Some("Risk")
    );
    assert_eq!(
        dictionary["features"]["risk_score"]["kind"].as_str(),
        Some("score")
    );
}

#[test]
fn feature_dictionary_makes_artifacts_readable_without_changing_runtime() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp directory should exist");
    let traces = temp.path().join("traces.csv");
    let dictionary = temp.path().join("feature_dictionary.json");
    let input = temp.path().join("input.json");
    let plain_artifact = temp.path().join("plain");
    let annotated_artifact = temp.path().join("annotated");

    fs::write(
        &traces,
        format!("{FEATURE_ID},allowed\n0,denied\n0,denied\n1,allowed\n1,allowed\n"),
    )
    .expect("traces should be writable");
    let mut feature_entries = serde_json::Map::new();
    feature_entries.insert(
        FEATURE_ID.to_string(),
        serde_json::json!({
            "label": "Failed conservative therapy",
            "source_id": "req-003-transcutaneous-electrical-nerve-stimulation-prn-p1-001",
            "source_anchor": "page-1",
            "states": {
                "missing_lte": {
                    "when": {"op": "<=", "value": 0.0},
                    "label": "Failed conservative therapy is missing",
                    "message": "This rule fires when the packet does not support failed conservative therapy.",
                    "counterfactual_hint": "Add evidence showing failed conservative therapy."
                },
                "missing_lt": {
                    "when": {"op": "<", "value": 1.0},
                    "label": "Failed conservative therapy is missing",
                    "message": "This rule fires when the packet does not support failed conservative therapy.",
                    "counterfactual_hint": "Add evidence showing failed conservative therapy."
                },
                "missing_eq": {
                    "when": {"op": "==", "value": 0.0},
                    "label": "Failed conservative therapy is missing",
                    "message": "This rule fires when the packet does not support failed conservative therapy.",
                    "counterfactual_hint": "Add evidence showing failed conservative therapy."
                }
            }
        }),
    );
    fs::write(
        &dictionary,
        serde_json::to_string_pretty(&serde_json::json!({
            "feature_dictionary_version": "1.0",
            "features": feature_entries
        }))
        .unwrap(),
    )
    .expect("dictionary should be writable");
    fs::write(&input, format!("{{\"{FEATURE_ID}\":0}}\n")).expect("input should be writable");

    run_build(cli_bin, &traces, &plain_artifact, None);
    run_build(cli_bin, &traces, &annotated_artifact, Some(&dictionary));

    let annotated_ir: Value = serde_json::from_str(
        &fs::read_to_string(annotated_artifact.join("pearl.ir.json"))
            .expect("annotated IR should be readable"),
    )
    .expect("annotated IR should parse");
    let first_rule = &annotated_ir["rules"][0];
    assert_eq!(
        first_rule["deny_when"]["feature"].as_str(),
        Some(FEATURE_ID),
        "raw deterministic expression should stay visible"
    );
    assert_eq!(
        first_rule["label"].as_str(),
        Some("Failed conservative therapy is missing")
    );
    assert_eq!(
        first_rule["counterfactual_hint"].as_str(),
        Some("Add evidence showing failed conservative therapy.")
    );
    assert_eq!(
        annotated_ir["input_schema"]["features"][0]["semantics"]["label"].as_str(),
        Some("Failed conservative therapy")
    );

    let inspect = Command::new(cli_bin)
        .arg("inspect")
        .arg(&annotated_artifact)
        .arg("--json")
        .output()
        .expect("logicpearl inspect should run");
    assert!(
        inspect.status.success(),
        "logicpearl inspect failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_json: Value =
        serde_json::from_slice(&inspect.stdout).expect("inspect output should parse");
    assert_eq!(
        inspect_json["rule_details"][0]["feature_dictionary"][0]["label"].as_str(),
        Some("Failed conservative therapy")
    );

    let run_explain = Command::new(cli_bin)
        .arg("run")
        .arg(&annotated_artifact)
        .arg(&input)
        .arg("--json")
        .arg("--explain")
        .output()
        .expect("logicpearl run --json --explain should run");
    assert!(
        run_explain.status.success(),
        "logicpearl run --json --explain failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_explain.stdout),
        String::from_utf8_lossy(&run_explain.stderr)
    );
    let run_explain_json: Value =
        serde_json::from_slice(&run_explain.stdout).expect("runtime explain output should parse");
    assert_eq!(run_explain_json["decision_kind"].as_str(), Some("gate"));
    assert_eq!(run_explain_json["allow"].as_bool(), Some(false));
    assert_eq!(run_explain_json["defaulted"].as_bool(), Some(false));
    let feature_explanation = &run_explain_json["matched_rules"][0]["features"][0];
    assert_eq!(
        feature_explanation["feature_label"].as_str(),
        Some("Failed conservative therapy")
    );
    assert_eq!(
        feature_explanation["source_id"].as_str(),
        Some("req-003-transcutaneous-electrical-nerve-stimulation-prn-p1-001")
    );
    assert_eq!(
        feature_explanation["source_anchor"].as_str(),
        Some("page-1")
    );
    assert_eq!(
        feature_explanation["state_message"].as_str(),
        Some("This rule fires when the packet does not support failed conservative therapy.")
    );

    assert_eq!(
        run_bitmask(cli_bin, &plain_artifact, &input),
        run_bitmask(cli_bin, &annotated_artifact, &input)
    );
}
