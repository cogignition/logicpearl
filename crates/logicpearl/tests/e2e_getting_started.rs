// SPDX-License-Identifier: MIT
use logicpearl_discovery::{
    BuildResult, ExactSelectionBackend, ProposalCandidateStatus, ProposalPhaseStatus,
};
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

fn report_output_path(artifact_dir: &Path, reported_path: &str) -> PathBuf {
    let path = Path::new(reported_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        artifact_dir.join(path)
    }
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
fn sample_dataset_builds_artifact_bundle_and_runs_explicit_compiled_binary() {
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
    let artifact_manifest =
        report_output_path(&output_path, &build_result.output_files.artifact_manifest);
    let pearl_ir = report_output_path(&output_path, &build_result.output_files.pearl_ir);
    let build_report = report_output_path(&output_path, &build_result.output_files.build_report);
    let proposal_report = report_output_path(
        &output_path,
        build_result
            .output_files
            .proposal_report
            .as_deref()
            .expect("proposal report path should be present"),
    );
    assert!(artifact_manifest.exists());
    assert!(pearl_ir.exists());
    assert!(build_report.exists());
    assert!(proposal_report.exists());
    assert_eq!(
        build_result.proposal_phase.status,
        ProposalPhaseStatus::Skipped
    );
    assert!(build_result
        .build_phases
        .iter()
        .any(|phase| phase.name == "proposal_phase"));
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&artifact_manifest).expect("artifact manifest should be readable"),
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
            .is_some_and(|deployables| deployables.is_empty()),
        "default build should not describe deployable outputs"
    );
    assert!(
        build_result.output_files.native_binary.is_none(),
        "default build should not emit a native binary"
    );
    assert!(
        build_result.output_files.wasm_module.is_none(),
        "default build should not emit a Wasm module"
    );

    let run_output = Command::new(cli_bin)
        .arg("run")
        .arg(&output_path)
        .arg(&sample_input)
        .output()
        .expect("logicpearl run should run");
    assert!(
        run_output.status.success(),
        "logicpearl run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_output.stdout),
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run_output.stdout).trim(), "0");

    let compile_output = Command::new(cli_bin)
        .arg("compile")
        .arg(&output_path)
        .env("PATH", "")
        .output()
        .expect("logicpearl compile should run");
    assert!(
        compile_output.status.success(),
        "logicpearl compile failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile_output.stdout),
        String::from_utf8_lossy(&compile_output.stderr)
    );
    let native_binary = output_path.join("decision_traces.pearl");
    assert!(native_binary.exists());
    let compiled_manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&artifact_manifest)
            .expect("compiled artifact manifest should be readable"),
    )
    .expect("compiled artifact manifest should be valid JSON");
    assert_eq!(
        compiled_manifest["files"]["native"].as_str(),
        Some("decision_traces.pearl")
    );
    assert!(compiled_manifest["file_hashes"]["native"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));

    let compiled_output = Command::new(&native_binary)
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
fn proposal_phase_example_runs_with_rule_budget_and_validates_candidates() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let output_dir = tempdir().expect("temp output dir should be created");
    let output_path = output_dir.path().join("proposal_bundle");
    let sample_csv = repo_root.join("examples/proposal_phase/traces.csv");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(&sample_csv)
        .arg("--output-dir")
        .arg(&output_path)
        .arg("--max-rules")
        .arg("1")
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
    let proposal_report = report_output_path(
        &output_path,
        build_result
            .output_files
            .proposal_report
            .as_deref()
            .expect("proposal report path should be present"),
    );

    assert!(proposal_report.exists());
    assert_eq!(build_result.training_parity, 1.0);
    assert!(build_result.rules_discovered > 1);
    assert_eq!(build_result.proposal_phase.status, ProposalPhaseStatus::Ran);
    assert_eq!(
        build_result.proposal_phase.acceptance_policy,
        "auto_adopt_safe"
    );
    assert_eq!(
        build_result.proposal_phase.diagnosis.as_deref(),
        Some("missing_relationship_feature")
    );
    assert_eq!(
        build_result
            .proposal_phase
            .recommended_next_phase
            .as_deref(),
        Some("promote_derived_feature_to_observer")
    );
    assert_eq!(build_result.proposal_phase.accepted_candidates, 1);
    assert_eq!(
        build_result.proposal_phase.accepted_candidate_ids,
        ["derived_ratio_debt_income_gte_pos_0_700000"]
    );
    assert!(
        build_result
            .proposal_phase
            .pre_adoption_training_parity
            .expect("pre-adoption parity should be reported")
            < build_result
                .proposal_phase
                .post_adoption_training_parity
                .expect("post-adoption parity should be reported")
    );
    assert!(build_result.proposal_phase.validated_candidates > 0);
    assert!(build_result
        .proposal_phase
        .candidates
        .iter()
        .any(|candidate| {
            candidate.status == ProposalCandidateStatus::Validated
                && candidate.source_stage == "derived_feature_search"
                && candidate.recommendation.as_deref() == Some("promote_to_observer_feature")
                && candidate.feature_expression.as_deref() == Some("debt / income")
                && candidate.validation.deterministic
                && candidate.validation.passed
                && candidate.evidence.introduced_mismatches == 0
        }));
    for stage_name in [
        "mismatch_mining",
        "subgroup_discovery",
        "derived_feature_search",
        "interpretable_model_search",
    ] {
        assert!(build_result
            .proposal_phase
            .stages
            .iter()
            .any(|stage| stage.name == stage_name));
    }
}

#[test]
fn proposal_phase_report_only_policy_does_not_modify_emitted_pearl() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let output_dir = tempdir().expect("temp output dir should be created");
    let output_path = output_dir.path().join("proposal_report_only_bundle");
    let sample_csv = repo_root.join("examples/proposal_phase/traces.csv");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(&sample_csv)
        .arg("--output-dir")
        .arg(&output_path)
        .arg("--max-rules")
        .arg("1")
        .arg("--proposal-policy")
        .arg("report-only")
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
    assert_eq!(build_result.proposal_phase.status, ProposalPhaseStatus::Ran);
    assert_eq!(build_result.proposal_phase.acceptance_policy, "report_only");
    assert_eq!(build_result.proposal_phase.accepted_candidates, 0);
    assert!(build_result.proposal_phase.validated_candidates > 0);
    assert_eq!(build_result.rules_discovered, 1);
    assert!(build_result.training_parity < 1.0);
    assert_eq!(
        build_result.proposal_phase.pre_adoption_training_parity,
        build_result.proposal_phase.post_adoption_training_parity
    );
}

#[test]
fn build_config_can_exclude_human_review_columns() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    fs::write(
        temp.path().join("traces.csv"),
        "age,source,note,source_id,source_anchor,source_citation,source_quote,allowed\n21,review_a,ok,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,allowed\n25,review_b,ok,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,allowed\n16,review_c,manual,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,denied\n15,review_d,manual,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,denied\n",
    )
    .expect("trace fixture should write");
    fs::write(
        temp.path().join("logicpearl.yaml"),
        "build:\n  traces: traces.csv\n  label_column: allowed\n  exclude_columns:\n    - source\n    - note\n    - source_id\n    - source_anchor\n    - source_citation\n    - source_quote\n  output_dir: output\n",
    )
    .expect("logicpearl config should write");

    let output = Command::new(cli_bin)
        .arg("build")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build from config failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let build_result: BuildResult =
        serde_json::from_slice(&output.stdout).expect("build output should be valid JSON");
    assert_eq!(
        build_result
            .provenance
            .as_ref()
            .and_then(|provenance| provenance.build_options.as_ref())
            .and_then(|options| options["exclude_columns"].as_array())
            .map(Vec::len),
        Some(6)
    );

    let pearl_ir = report_output_path(
        &temp.path().join("output"),
        &build_result.output_files.pearl_ir,
    );
    let ir: Value =
        serde_json::from_str(&fs::read_to_string(&pearl_ir).expect("pearl ir should be readable"))
            .expect("pearl ir should be valid JSON");
    let feature_ids = ir["input_schema"]["features"]
        .as_array()
        .expect("features should be an array")
        .iter()
        .map(|feature| feature["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(feature_ids, vec!["age"]);

    let inspect_output = Command::new(cli_bin)
        .arg("inspect")
        .arg(temp.path().join("output"))
        .arg("--show-provenance")
        .arg("--json")
        .output()
        .expect("logicpearl inspect should run");
    assert!(
        inspect_output.status.success(),
        "logicpearl inspect failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect_output.stdout),
        String::from_utf8_lossy(&inspect_output.stderr)
    );
    let inspect: Value =
        serde_json::from_slice(&inspect_output.stdout).expect("inspect output should be JSON");
    let evidence = &inspect["rule_details"][0]["evidence"];
    assert_eq!(
        evidence["schema_version"].as_str(),
        Some("logicpearl.rule_evidence.v2")
    );
    assert_eq!(evidence["support"]["denied_trace_count"].as_u64(), Some(2));
    assert_eq!(
        evidence["reliability"]["matched_trace_count"].as_u64(),
        Some(2)
    );
    assert_eq!(evidence["reliability"]["precision"].as_f64(), Some(1.0));
    let example_trace = &evidence["support"]["example_traces"][0];
    assert!(example_trace["trace_row_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert_eq!(example_trace["source_id"].as_str(), Some("foia"));
    assert_eq!(example_trace["source_anchor"].as_str(), Some("552b5"));
    assert_eq!(example_trace["citation"].as_str(), Some("5 USC 552(b)(5)"));
    assert!(example_trace["quote_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert!(
        !String::from_utf8_lossy(&inspect_output.stdout).contains("inter agency memo exemption"),
        "inspect provenance should hash raw trace quotes"
    );
}

#[test]
fn build_show_conflicts_writes_gate_conflict_report_for_unfit_traces() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    let traces = temp.path().join("contradictory.csv");
    let output_dir = temp.path().join("output");
    fs::write(
        &traces,
        "age,note,allowed\n16,review_a,denied\n16,review_b,allowed\n30,review_c,allowed\n",
    )
    .expect("trace fixture should write");

    let output = Command::new(cli_bin)
        .arg("build")
        .arg(&traces)
        .arg("--label-column")
        .arg("allowed")
        .arg("--exclude-columns")
        .arg("note")
        .arg("--show-conflicts")
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let build_json: Value =
        serde_json::from_slice(&output.stdout).expect("build output should be JSON");
    assert!(build_json["training_parity"].as_f64().unwrap_or(1.0) < 1.0);
    assert!(build_json["conflict_count"].as_u64().unwrap_or(0) > 0);
    let conflict_path = report_output_path(
        &output_dir,
        build_json["conflict_report"]
            .as_str()
            .expect("conflict report path should be present"),
    );
    let conflict_report: Value = serde_json::from_str(
        &fs::read_to_string(conflict_path).expect("conflict report should be readable"),
    )
    .expect("conflict report should be JSON");
    assert_eq!(
        conflict_report["schema_version"].as_str(),
        Some("logicpearl.build_conflicts.v1")
    );
    assert_eq!(conflict_report["decision_kind"].as_str(), Some("gate"));
    assert_eq!(
        conflict_report["conflict_count"].as_u64(),
        Some(
            conflict_report["conflicts"]
                .as_array()
                .expect("conflicts should be an array")
                .len() as u64
        )
    );
    let conflict = &conflict_report["conflicts"][0];
    assert!(conflict["trace_row_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert!(conflict["expected"]["allowed"].is_boolean());
    assert!(conflict["predicted"]["allowed"].is_boolean());
    assert!(
        !serde_json::to_string(conflict)
            .expect("conflict should serialize")
            .contains("review_"),
        "conflict report should only include rule-referenced features"
    );
}

#[test]
fn build_show_conflicts_writes_action_conflict_report_for_unfit_traces() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    let traces = temp.path().join("actions.csv");
    let output_dir = temp.path().join("actions_output");
    fs::write(
        &traces,
        "soil_moisture,next_action\n10,water\n10,wait\n40,wait\n",
    )
    .expect("trace fixture should write");

    let output = Command::new(cli_bin)
        .arg("build")
        .arg(&traces)
        .arg("--action-column")
        .arg("next_action")
        .arg("--default-action")
        .arg("wait")
        .arg("--show-conflicts")
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .expect("logicpearl action build should run");
    assert!(
        output.status.success(),
        "logicpearl action build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let build_json: Value =
        serde_json::from_slice(&output.stdout).expect("build output should be JSON");
    assert!(build_json["training_parity"].as_f64().unwrap_or(1.0) < 1.0);
    assert!(build_json["conflict_count"].as_u64().unwrap_or(0) > 0);
    let conflict_path = report_output_path(
        &output_dir,
        build_json["conflict_report"]
            .as_str()
            .expect("conflict report path should be present"),
    );
    let conflict_report: Value = serde_json::from_str(
        &fs::read_to_string(conflict_path).expect("conflict report should be readable"),
    )
    .expect("conflict report should be JSON");
    assert_eq!(conflict_report["decision_kind"].as_str(), Some("action"));
    let conflict = &conflict_report["conflicts"][0];
    assert!(conflict["expected"]["action"].is_string());
    assert!(conflict["predicted"]["action"].is_string());
    assert!(conflict["predicted"]["bitmask"].is_number());
}

#[test]
fn action_build_can_return_distinct_no_match_action() {
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    let traces = temp.path().join("actions.csv");
    let output_dir = temp.path().join("actions_output");
    let input = temp.path().join("input.json");
    fs::write(
        &traces,
        "soil_moisture,next_action\n10,water\n12,water\n40,releasable\n45,releasable\n",
    )
    .expect("trace fixture should write");
    fs::write(&input, r#"{"soil_moisture": 25}"#).expect("input fixture should write");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(&traces)
        .arg("--action-column")
        .arg("next_action")
        .arg("--default-action")
        .arg("releasable")
        .arg("--no-match-action")
        .arg("insufficient_context")
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .expect("logicpearl action build should run");
    assert!(
        build_output.status.success(),
        "logicpearl action build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );
    let build_json: Value =
        serde_json::from_slice(&build_output.stdout).expect("build output should be JSON");
    assert_eq!(
        build_json["no_match_action"].as_str(),
        Some("insufficient_context")
    );

    let run_output = Command::new(cli_bin)
        .arg("run")
        .arg(&output_dir)
        .arg(&input)
        .arg("--json")
        .output()
        .expect("logicpearl run should run");
    assert!(
        run_output.status.success(),
        "logicpearl run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_output.stdout),
        String::from_utf8_lossy(&run_output.stderr)
    );
    let run_json: Value =
        serde_json::from_slice(&run_output.stdout).expect("run output should be JSON");
    assert_eq!(run_json["action"].as_str(), Some("insufficient_context"));
    assert_eq!(run_json["default_action"].as_str(), Some("releasable"));
    assert_eq!(
        run_json["no_match_action"].as_str(),
        Some("insufficient_context")
    );
    assert_eq!(run_json["defaulted"].as_bool(), Some(true));
    assert_eq!(run_json["no_match"].as_bool(), Some(true));
    assert_eq!(run_json["matched_rules"].as_array().map(Vec::len), Some(0));
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
        &fs::read_to_string(report_output_path(
            &smt_output,
            &smt_build.output_files.pearl_ir,
        ))
        .expect("smt pearl ir should be readable"),
    )
    .expect("smt pearl ir should be valid JSON");
    let mip_ir: Value = serde_json::from_str(
        &fs::read_to_string(report_output_path(
            &mip_output,
            &mip_build.output_files.pearl_ir,
        ))
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
