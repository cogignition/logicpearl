use logicpearl_discovery::BuildResult;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
        .to_path_buf()
}

fn run_cli_output(cli_bin: &str, args: &[String]) -> Output {
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

#[test]
fn artifact_entrypoints_resolve_consistently_across_cli_commands() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp output dir should be created");
    let artifact_dir = temp.path().join("artifact_bundle");
    let sample_csv = repo_root.join("examples/getting_started/decision_traces.csv");
    let sample_input = repo_root.join("examples/getting_started/new_input.json");

    let build_output = run_cli_output(
        cli_bin,
        &[
            "build".to_string(),
            sample_csv.display().to_string(),
            "--output-dir".to_string(),
            artifact_dir.display().to_string(),
            "--json".to_string(),
        ],
    );
    assert!(
        build_output.status.success(),
        "logicpearl build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let build_result: BuildResult =
        serde_json::from_slice(&build_output.stdout).expect("build output should be valid JSON");
    let artifact_manifest = PathBuf::from(&build_result.output_files.artifact_manifest);
    let pearl_ir = PathBuf::from(&build_result.output_files.pearl_ir);

    let entrypoints = [
        artifact_dir.display().to_string(),
        artifact_manifest.display().to_string(),
        pearl_ir.display().to_string(),
    ];

    let inspect_reports: Vec<Value> = entrypoints
        .iter()
        .map(|entrypoint| {
            run_cli_json(
                cli_bin,
                &[
                    "inspect".to_string(),
                    entrypoint.clone(),
                    "--json".to_string(),
                ],
            )
        })
        .collect();

    for report in &inspect_reports {
        assert_eq!(
            report["artifact_dir"].as_str(),
            Some(artifact_dir.to_string_lossy().as_ref())
        );
        assert_eq!(
            report["pearl_ir"].as_str(),
            Some(pearl_ir.to_string_lossy().as_ref())
        );
        assert_eq!(
            report["bundle"]["cli_entrypoint"].as_str(),
            Some("artifact.json")
        );
    }
    assert_eq!(inspect_reports[0]["gate_id"], inspect_reports[1]["gate_id"]);
    assert_eq!(inspect_reports[1]["gate_id"], inspect_reports[2]["gate_id"]);
    assert_eq!(inspect_reports[0]["rules"], inspect_reports[1]["rules"]);
    assert_eq!(inspect_reports[1]["rules"], inspect_reports[2]["rules"]);

    let run_outputs: Vec<String> = entrypoints
        .iter()
        .map(|entrypoint| {
            let output = run_cli_output(
                cli_bin,
                &[
                    "run".to_string(),
                    entrypoint.clone(),
                    sample_input.display().to_string(),
                ],
            );
            assert!(
                output.status.success(),
                "logicpearl run failed:\nentrypoint: {}\nstdout:\n{}\nstderr:\n{}",
                entrypoint,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        })
        .collect();
    assert_eq!(run_outputs[0], "0");
    assert_eq!(run_outputs[0], run_outputs[1]);
    assert_eq!(run_outputs[1], run_outputs[2]);

    let parity_reports: Vec<Value> = entrypoints
        .iter()
        .map(|entrypoint| {
            run_cli_json(
                cli_bin,
                &[
                    "conformance".to_string(),
                    "runtime-parity".to_string(),
                    entrypoint.clone(),
                    sample_csv.display().to_string(),
                    "--label-column".to_string(),
                    "allowed".to_string(),
                    "--json".to_string(),
                ],
            )
        })
        .collect();
    for report in &parity_reports {
        assert!(report["total_rows"].as_u64().unwrap_or(0) > 0);
        assert_eq!(report["matching_rows"], report["total_rows"]);
        assert_eq!(report["parity"].as_f64(), Some(1.0));
    }

    let diff_bundle_manifest = run_cli_json(
        cli_bin,
        &[
            "diff".to_string(),
            artifact_dir.display().to_string(),
            artifact_manifest.display().to_string(),
            "--json".to_string(),
        ],
    );
    assert_eq!(
        diff_bundle_manifest["summary"]["changed_rules"].as_u64(),
        Some(0)
    );
    assert_eq!(
        diff_bundle_manifest["summary"]["reordered_rules"].as_u64(),
        Some(0)
    );
    assert_eq!(
        diff_bundle_manifest["summary"]["added_rules"].as_u64(),
        Some(0)
    );
    assert_eq!(
        diff_bundle_manifest["summary"]["removed_rules"].as_u64(),
        Some(0)
    );

    let diff_manifest_ir = run_cli_json(
        cli_bin,
        &[
            "diff".to_string(),
            artifact_manifest.display().to_string(),
            pearl_ir.display().to_string(),
            "--json".to_string(),
        ],
    );
    assert_eq!(diff_manifest_ir["summary"], diff_bundle_manifest["summary"]);
}
