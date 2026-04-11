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
    repo_root().join("fixtures/contracts/healthcare_prior_auth")
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
    policies: Vec<PolicyContract>,
}

#[derive(Debug, Deserialize)]
struct PolicyContract {
    policy_id: String,
    title: String,
    bundle_dir: String,
    inspect_expectation: InspectExpectation,
    scenarios: Vec<ScenarioExpectation>,
    diff_expectation: DiffExpectation,
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
    source_schema_changed: bool,
    learned_rule_changed: bool,
    rule_explanation_changed: bool,
    changed_rules: u64,
    reordered_rules: u64,
    added_rules: u64,
    removed_rules: u64,
}

fn load_manifest() -> ContractManifest {
    serde_json::from_str(
        &fs::read_to_string(fixture_root().join("contract_manifest.json"))
            .expect("healthcare contract manifest should read"),
    )
    .expect("healthcare contract manifest should parse")
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

fn assert_non_empty_str<'a>(value: &'a Value, context: &str) -> &'a str {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{context} should be a string"));
    assert!(!text.trim().is_empty(), "{context} should be non-empty");
    text
}

fn same_json_value(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => (left - right).abs() < f64::EPSILON,
        _ => left == right,
    }
}

fn matching_state<'a>(semantics: &'a Value, deny_when: &Value, context: &str) -> &'a Value {
    let states = semantics["states"]
        .as_object()
        .unwrap_or_else(|| panic!("{context} semantics.states should be an object"));
    states
        .values()
        .find(|state| {
            state["when"]["op"] == deny_when["op"]
                && same_json_value(&state["when"]["value"], &deny_when["value"])
        })
        .unwrap_or_else(|| panic!("{context} should have a dictionary state matching deny_when"))
}

fn assert_rule_text_is_readable(rule: &Value, feature_id: &str, source_id: &str, context: &str) {
    for field in ["label", "message", "counterfactual_hint"] {
        let text = assert_non_empty_str(&rule[field], &format!("{context}.{field}"));
        assert!(
            !text.contains("Requirement Req-"),
            "{context}.{field} should not expose old raw requirement text: {text}"
        );
        assert!(
            !text.contains("requirement__"),
            "{context}.{field} should not expose raw feature ids: {text}"
        );
        assert!(
            !text.contains(feature_id),
            "{context}.{field} should not contain the raw feature id: {text}"
        );
        assert!(
            !text.contains(source_id),
            "{context}.{field} should not contain the raw source id: {text}"
        );
    }
}

fn assert_feature_dictionary_contract(
    policy: &PolicyContract,
    pearl_ir_value: &Value,
    inspect_reports: &[&Value],
) {
    let features = pearl_ir_value["input_schema"]["features"]
        .as_array()
        .expect("input_schema.features should be an array");
    let rules = pearl_ir_value["rules"]
        .as_array()
        .expect("rules should be an array");

    assert!(
        !features.is_empty(),
        "healthcare fixture {} should include features",
        policy.policy_id
    );
    for feature in features {
        let feature_id =
            assert_non_empty_str(&feature["id"], &format!("{} feature id", policy.policy_id));
        let semantics = feature
            .get("semantics")
            .unwrap_or_else(|| panic!("feature {feature_id} should embed dictionary semantics"));
        assert_non_empty_str(
            &semantics["label"],
            &format!("feature {feature_id} semantics.label"),
        );
        assert_non_empty_str(
            &semantics["source_id"],
            &format!("feature {feature_id} semantics.source_id"),
        );
        assert_non_empty_str(
            &semantics["source_anchor"],
            &format!("feature {feature_id} semantics.source_anchor"),
        );
        assert!(
            semantics["states"]
                .as_object()
                .is_some_and(|states| !states.is_empty()),
            "feature {feature_id} should define dictionary states"
        );
        for (state_id, state) in semantics["states"].as_object().unwrap() {
            assert_non_empty_str(
                &state["when"]["op"],
                &format!("feature {feature_id} state {state_id} op"),
            );
            assert!(
                !state["when"]["value"].is_null(),
                "feature {feature_id} state {state_id} should define a value"
            );
            assert_non_empty_str(
                &state["label"],
                &format!("feature {feature_id} state {state_id} label"),
            );
            assert_non_empty_str(
                &state["message"],
                &format!("feature {feature_id} state {state_id} message"),
            );
            assert_non_empty_str(
                &state["counterfactual_hint"],
                &format!("feature {feature_id} state {state_id} counterfactual_hint"),
            );
        }
    }

    for rule in rules {
        let rule_id = assert_non_empty_str(&rule["id"], "rule id");
        let deny_when = &rule["deny_when"];
        let feature_id = assert_non_empty_str(
            &deny_when["feature"],
            &format!("{rule_id} deny_when.feature"),
        );
        let feature = features
            .iter()
            .find(|feature| feature["id"].as_str() == Some(feature_id))
            .unwrap_or_else(|| panic!("rule {rule_id} should reference a declared feature"));
        let semantics = &feature["semantics"];
        let state = matching_state(semantics, deny_when, rule_id);
        assert_eq!(
            rule["label"], state["label"],
            "rule {rule_id} label should come from matching feature dictionary state"
        );
        assert_eq!(
            rule["message"], state["message"],
            "rule {rule_id} message should come from matching feature dictionary state"
        );
        assert_eq!(
            rule["counterfactual_hint"], state["counterfactual_hint"],
            "rule {rule_id} counterfactual should come from matching feature dictionary state"
        );
        let source_id = assert_non_empty_str(
            &semantics["source_id"],
            &format!("feature {feature_id} source_id"),
        );
        assert_rule_text_is_readable(rule, feature_id, source_id, rule_id);
    }

    for report in inspect_reports {
        assert_eq!(
            report["feature_dictionary"]["feature_count"].as_u64(),
            Some(features.len() as u64),
            "inspect should expose all healthcare dictionary features for {}",
            policy.policy_id
        );
        assert_eq!(
            report["rule_details"].as_array().map(std::vec::Vec::len),
            Some(rules.len()),
            "inspect should expose rule details for {}",
            policy.policy_id
        );
        for detail in report["rule_details"]
            .as_array()
            .expect("inspect rule_details should be an array")
        {
            let rule_id = assert_non_empty_str(&detail["id"], "inspect rule id");
            assert!(
                !detail["deny_when"].is_null(),
                "inspect {rule_id} should keep raw deny_when"
            );
            assert_non_empty_str(&detail["label"], &format!("inspect {rule_id} label"));
            assert_non_empty_str(&detail["message"], &format!("inspect {rule_id} message"));
            assert_non_empty_str(
                &detail["counterfactual_hint"],
                &format!("inspect {rule_id} counterfactual_hint"),
            );
            assert!(
                detail["feature_dictionary"]
                    .as_array()
                    .is_some_and(|features| !features.is_empty()),
                "inspect {rule_id} should include readable feature dictionary metadata"
            );
        }
    }
}

fn assert_rule_snapshot_has_readable_metadata(snapshot: &Value, context: &str) {
    assert_non_empty_str(&snapshot["id"], &format!("{context} id"));
    assert!(
        !snapshot["expression"].is_null(),
        "{context} should keep raw expression"
    );
    assert_non_empty_str(&snapshot["label"], &format!("{context} label"));
    assert_non_empty_str(&snapshot["message"], &format!("{context} message"));
    assert_non_empty_str(
        &snapshot["counterfactual_hint"],
        &format!("{context} counterfactual_hint"),
    );
    let feature_dictionary = snapshot["feature_dictionary"]
        .as_array()
        .unwrap_or_else(|| panic!("{context} feature_dictionary should be an array"));
    assert!(
        !feature_dictionary.is_empty(),
        "{context} should expose readable feature metadata"
    );
    for feature in feature_dictionary {
        assert_non_empty_str(&feature["id"], &format!("{context} feature id"));
        assert_non_empty_str(&feature["label"], &format!("{context} feature label"));
        assert_non_empty_str(
            &feature["source_id"],
            &format!("{context} feature source_id"),
        );
        assert_non_empty_str(
            &feature["source_anchor"],
            &format!("{context} feature source_anchor"),
        );
    }
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_string_pretty(value).expect("JSON should serialize") + "\n",
    )
    .expect("JSON fixture should write");
}

fn write_healthcare_trace_csv(
    path: &Path,
    feature_ids: &[String],
    scenarios: &[ScenarioExpectation],
) {
    let mut csv = String::new();
    csv.push_str(&feature_ids.join(","));
    csv.push_str(",allowed\n");
    for scenario in scenarios {
        let feature_map = scenario
            .feature_map
            .as_object()
            .expect("scenario feature_map should be an object");
        let values = feature_ids
            .iter()
            .map(|feature_id| {
                feature_map
                    .get(feature_id)
                    .unwrap_or_else(|| panic!("scenario should include feature {feature_id}"))
                    .to_string()
            })
            .collect::<Vec<_>>();
        csv.push_str(&values.join(","));
        csv.push(',');
        csv.push_str(if scenario.expected_bitmask == 0 {
            "allowed"
        } else {
            "denied"
        });
        csv.push('\n');
    }
    fs::write(path, csv).expect("healthcare trace CSV should write");
}

fn feature_dictionary_from_ir(pearl_ir_value: &Value) -> Value {
    let mut features = serde_json::Map::new();
    for feature in pearl_ir_value["input_schema"]["features"]
        .as_array()
        .expect("input_schema.features should be an array")
    {
        let feature_id = assert_non_empty_str(&feature["id"], "feature id");
        let semantics = feature
            .get("semantics")
            .unwrap_or_else(|| panic!("feature {feature_id} should have semantics"));
        features.insert(feature_id.to_string(), semantics.clone());
    }
    serde_json::json!({
        "feature_dictionary_version": "1.0",
        "features": features,
    })
}

#[test]
fn healthcare_contract_artifacts_preserve_expected_runtime_behavior() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = fixture_root();
    let manifest = load_manifest();

    for policy in manifest.policies {
        let bundle_dir = root.join(&policy.bundle_dir);
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
                Some(policy.inspect_expectation.gate_id.as_str()),
                "inspect gate_id mismatch for {}",
                policy.policy_id
            );
            assert_eq!(
                report["rules"].as_u64(),
                Some(policy.inspect_expectation.rules),
                "inspect rule count mismatch for {}",
                policy.policy_id
            );
            assert_eq!(
                report["features"].as_u64(),
                Some(policy.inspect_expectation.features),
                "inspect feature count mismatch for {}",
                policy.policy_id
            );
        }
        assert_feature_dictionary_contract(
            &policy,
            &pearl_ir_value,
            &[&inspect_bundle, &inspect_manifest, &inspect_ir],
        );

        let actual_rule_ids: Vec<String> = pearl_ir_value["rules"]
            .as_array()
            .expect("rules should be an array")
            .iter()
            .filter_map(|rule| rule["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(
            actual_rule_ids, policy.inspect_expectation.rule_ids_in_order,
            "rule order mismatch for {} ({})",
            policy.policy_id, policy.title
        );

        let actual_feature_ids: Vec<String> = pearl_ir_value["input_schema"]["features"]
            .as_array()
            .expect("input_schema.features should be an array")
            .iter()
            .filter_map(|feature| feature["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(
            actual_feature_ids, policy.inspect_expectation.feature_ids_in_order,
            "feature order mismatch for {} ({})",
            policy.policy_id, policy.title
        );

        for scenario in policy.scenarios {
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
                policy.policy_id, scenario.name
            );
            assert_eq!(
                manifest_mask, scenario.expected_bitmask,
                "artifact manifest runtime mismatch for {} scenario {}",
                policy.policy_id, scenario.name
            );
            assert_eq!(
                ir_mask, scenario.expected_bitmask,
                "pearl ir runtime mismatch for {} scenario {}",
                policy.policy_id, scenario.name
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
                policy.policy_id, scenario.name
            );
        }
    }
}

#[test]
fn healthcare_contract_builds_with_feature_dictionary_metadata() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = fixture_root();
    let manifest = load_manifest();

    for policy in manifest.policies {
        let temp = tempdir().expect("temp directory should be created");
        let bundle_dir = root.join(&policy.bundle_dir);
        let source_ir: Value = serde_json::from_str(
            &fs::read_to_string(bundle_dir.join("pearl.ir.json"))
                .expect("source pearl ir should read"),
        )
        .expect("source pearl ir should parse");
        let feature_ids = source_ir["input_schema"]["features"]
            .as_array()
            .expect("source features should be an array")
            .iter()
            .map(|feature| assert_non_empty_str(&feature["id"], "source feature id").to_string())
            .collect::<Vec<_>>();
        let traces_path = temp.path().join("healthcare_traces.csv");
        let dictionary_path = temp.path().join("feature_dictionary.json");
        let output_dir = temp.path().join("artifact");
        write_healthcare_trace_csv(&traces_path, &feature_ids, &policy.scenarios);
        write_json(&dictionary_path, &feature_dictionary_from_ir(&source_ir));

        let build_report = run_cli_json(
            cli_bin,
            &[
                "build".to_string(),
                traces_path.display().to_string(),
                "--feature-dictionary".to_string(),
                dictionary_path.display().to_string(),
                "--output-dir".to_string(),
                output_dir.display().to_string(),
                "--json".to_string(),
            ],
        );
        assert_eq!(
            build_report["training_parity"].as_f64(),
            Some(1.0),
            "dictionary-backed build should preserve training parity for {}",
            policy.policy_id
        );
        let generated_ir_path = output_dir.join("pearl.ir.json");
        let generated_ir: Value = serde_json::from_str(
            &fs::read_to_string(&generated_ir_path).expect("generated pearl ir should read"),
        )
        .expect("generated pearl ir should parse");
        let inspect = run_cli_json(
            cli_bin,
            &[
                "inspect".to_string(),
                output_dir.display().to_string(),
                "--json".to_string(),
            ],
        );
        assert_feature_dictionary_contract(&policy, &generated_ir, &[&inspect]);
    }
}

#[test]
fn healthcare_contract_artifacts_report_expected_semantic_diffs() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = fixture_root();
    let manifest = load_manifest();

    for policy in manifest.policies {
        let earlier_ir = root.join(&policy.diff_expectation.earlier_ir);
        let current_ir = root.join(&policy.diff_expectation.current_ir);
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
            diff["summary"]["source_schema_changed"].as_bool(),
            Some(policy.diff_expectation.summary.source_schema_changed),
            "source_schema_changed mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            diff["summary"]["learned_rule_changed"].as_bool(),
            Some(policy.diff_expectation.summary.learned_rule_changed),
            "learned_rule_changed mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            diff["summary"]["rule_explanation_changed"].as_bool(),
            Some(policy.diff_expectation.summary.rule_explanation_changed),
            "rule_explanation_changed mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            diff["summary"]["changed_rules"].as_u64(),
            Some(policy.diff_expectation.summary.changed_rules),
            "changed_rules mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            diff["summary"]["reordered_rules"].as_u64(),
            Some(policy.diff_expectation.summary.reordered_rules),
            "reordered_rules mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            diff["summary"]["added_rules"].as_u64(),
            Some(policy.diff_expectation.summary.added_rules),
            "added_rules mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            diff["summary"]["removed_rules"].as_u64(),
            Some(policy.diff_expectation.summary.removed_rules),
            "removed_rules mismatch for {}",
            policy.policy_id
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
            changed_rule_ids, policy.diff_expectation.changed_rule_ids,
            "changed rule ids mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            added_rule_ids, policy.diff_expectation.added_rule_ids,
            "added rule ids mismatch for {}",
            policy.policy_id
        );
        assert_eq!(
            removed_rule_ids, policy.diff_expectation.removed_rule_ids,
            "removed rule ids mismatch for {}",
            policy.policy_id
        );
        for change in diff["changed_rules"]
            .as_array()
            .expect("changed_rules should be an array")
        {
            assert_rule_snapshot_has_readable_metadata(
                &change["old_rule"],
                &format!("{} changed old_rule", policy.policy_id),
            );
            assert_rule_snapshot_has_readable_metadata(
                &change["new_rule"],
                &format!("{} changed new_rule", policy.policy_id),
            );
        }
        for snapshot in diff["added_rules"]
            .as_array()
            .expect("added_rules should be an array")
        {
            assert_rule_snapshot_has_readable_metadata(
                snapshot,
                &format!("{} added rule", policy.policy_id),
            );
        }
        for snapshot in diff["removed_rules"]
            .as_array()
            .expect("removed_rules should be an array")
        {
            assert_rule_snapshot_has_readable_metadata(
                snapshot,
                &format!("{} removed rule", policy.policy_id),
            );
        }
    }
}

#[test]
fn healthcare_contract_diff_separates_explanation_only_changes() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let root = fixture_root();
    let manifest = load_manifest();
    let policy = manifest
        .policies
        .first()
        .expect("healthcare manifest should contain at least one policy");
    let source_ir = root.join(&policy.diff_expectation.current_ir);
    let old_ir: Value =
        serde_json::from_str(&fs::read_to_string(&source_ir).expect("source IR should read"))
            .expect("source IR should parse");
    let mut new_ir = old_ir.clone();
    new_ir["rules"][0]["label"] = Value::String("Updated reviewer copy".to_string());
    new_ir["rules"][0]["message"] =
        Value::String("This explanation changed without changing the raw rule.".to_string());
    new_ir["rules"][0]["counterfactual_hint"] =
        Value::String("Keep the raw rule fixed while improving copy.".to_string());
    new_ir["input_schema"]["features"][0]["semantics"]["label"] =
        Value::String("Updated feature label".to_string());

    let temp = tempdir().expect("temp directory should be created");
    let old_path = temp.path().join("old.pearl.ir.json");
    let new_path = temp.path().join("new.pearl.ir.json");
    write_json(&old_path, &old_ir);
    write_json(&new_path, &new_ir);

    let diff = run_cli_json(
        cli_bin,
        &[
            "diff".to_string(),
            old_path.display().to_string(),
            new_path.display().to_string(),
            "--json".to_string(),
        ],
    );

    assert_eq!(
        diff["summary"]["source_schema_changed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        diff["summary"]["learned_rule_changed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        diff["summary"]["rule_explanation_changed"].as_bool(),
        Some(true)
    );
    assert_eq!(diff["summary"]["changed_rules"].as_u64(), Some(0));
    assert_eq!(diff["summary"]["added_rules"].as_u64(), Some(0));
    assert_eq!(diff["summary"]["removed_rules"].as_u64(), Some(0));
    assert_eq!(
        diff["reordered_rules"][0]["change_kind"].as_str(),
        Some("metadata_changed")
    );
    assert_eq!(
        diff["feature_dictionary_changes"]["changed"][0]["explanation_changed"].as_bool(),
        Some(true)
    );
}
