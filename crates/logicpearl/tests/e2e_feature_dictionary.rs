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
