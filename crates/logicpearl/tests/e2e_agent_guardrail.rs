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
fn agent_guardrail_example_pipeline_runs_and_scores_cleanly() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let pipeline = repo_root
        .join("benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json");
    let attack_input =
        repo_root.join("benchmarks/guardrails/examples/agent_guardrail/input_attack.json");
    let benign_input =
        repo_root.join("benchmarks/guardrails/examples/agent_guardrail/input_benign.json");
    let dev_cases =
        repo_root.join("benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl");

    let attack = run_cli_json(
        cli_bin,
        &[
            "pipeline",
            "run",
            pipeline.to_str().unwrap(),
            attack_input.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        attack["output"]["route_status"].as_str(),
        Some("deny_untrusted_instruction")
    );
    assert_eq!(attack["output"]["allow"].as_bool(), Some(false));

    let benign = run_cli_json(
        cli_bin,
        &[
            "pipeline",
            "run",
            pipeline.to_str().unwrap(),
            benign_input.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(benign["output"]["route_status"].as_str(), Some("allow"));
    assert_eq!(benign["output"]["allow"].as_bool(), Some(true));

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
    assert_eq!(benchmark["summary"]["total_cases"].as_u64(), Some(5));
    assert_eq!(benchmark["summary"]["matched_cases"].as_u64(), Some(5));
    assert_eq!(benchmark["summary"]["exact_match_rate"].as_f64(), Some(1.0));
    assert_eq!(
        benchmark["summary"]["attack_catch_rate"].as_f64(),
        Some(1.0)
    );
    assert_eq!(benchmark["summary"]["benign_pass_rate"].as_f64(), Some(1.0));
}
