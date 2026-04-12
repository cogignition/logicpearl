// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn run_cli_json(cli_bin: &str, args: &[&str]) -> Value {
    let output = Command::new(cli_bin)
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl command failed:\nargs: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command output should be valid JSON")
}

#[test]
fn waf_edge_demo_pipeline_runs_and_scores_cleanly() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let pipeline = repo_root.join("examples/waf_edge/waf_edge.pipeline.json");
    let allow_input = repo_root.join("examples/waf_edge/input_allow.json");
    let prompt_input = repo_root.join("examples/waf_edge/input_block_sqli.json");
    let sensitive_input = repo_root.join("examples/waf_edge/input_block_sensitive.json");
    let review_input = repo_root.join("examples/waf_edge/input_review_probe.json");
    let dev_cases = repo_root.join("examples/waf_edge/dev_cases.jsonl");

    let allow = run_cli_json(
        cli_bin,
        &[
            "pipeline",
            "run",
            pipeline.to_str().unwrap(),
            allow_input.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(allow["output"]["route_status"].as_str(), Some("allow"));
    assert_eq!(allow["output"]["allow"].as_bool(), Some(true));

    let deny_prompt = run_cli_json(
        cli_bin,
        &[
            "pipeline",
            "run",
            pipeline.to_str().unwrap(),
            prompt_input.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        deny_prompt["output"]["route_status"].as_str(),
        Some("deny_injection_payload")
    );

    let deny_sensitive = run_cli_json(
        cli_bin,
        &[
            "pipeline",
            "run",
            pipeline.to_str().unwrap(),
            sensitive_input.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        deny_sensitive["output"]["route_status"].as_str(),
        Some("deny_sensitive_surface")
    );

    let review = run_cli_json(
        cli_bin,
        &[
            "pipeline",
            "run",
            pipeline.to_str().unwrap(),
            review_input.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        review["output"]["route_status"].as_str(),
        Some("review_suspicious_request")
    );

    let benchmark = run_cli_json(
        cli_bin,
        &[
            "benchmark",
            "run",
            pipeline.to_str().unwrap(),
            dev_cases.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(benchmark["summary"]["total_cases"].as_u64(), Some(4));
    assert_eq!(benchmark["summary"]["matched_cases"].as_u64(), Some(4));
    assert_eq!(benchmark["summary"]["exact_match_rate"].as_f64(), Some(1.0));
}
