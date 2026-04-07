use logicpearl_discovery::BuildResult;
use serde_json::Value;
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

#[test]
fn generic_plugin_commands_validate_and_run_observer_and_trace_source() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let observer_manifest = repo_root.join("examples/plugins/python_observer/manifest.json");
    let observer_input = repo_root.join("examples/plugins/python_observer/raw_input.json");
    let trace_manifest = repo_root.join("examples/plugins/python_trace_source/manifest.json");
    let trace_source = repo_root.join("examples/getting_started/decision_traces.csv");

    let validate = Command::new(cli_bin)
        .arg("plugin")
        .arg("validate")
        .arg(&observer_manifest)
        .arg("--input")
        .arg(&observer_input)
        .arg("--json")
        .output()
        .expect("plugin validate should run");
    assert!(
        validate.status.success(),
        "logicpearl plugin validate failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr)
    );
    let validate_report: Value =
        serde_json::from_slice(&validate.stdout).expect("validate output should be valid JSON");
    assert_eq!(
        validate_report["manifest"]["stage"].as_str(),
        Some("observer")
    );
    assert_eq!(
        validate_report["canonical_contract"]["canonical_input"].as_str(),
        Some("payload.input")
    );
    assert_eq!(
        validate_report["canonical_contract"]["compatibility_alias"].as_str(),
        Some("payload.raw_input")
    );
    assert_eq!(
        validate_report["smoke"]["response"]["features"]["age"].as_i64(),
        Some(34)
    );

    let run_observer = Command::new(cli_bin)
        .arg("plugin")
        .arg("run")
        .arg(&observer_manifest)
        .arg("--input")
        .arg(&observer_input)
        .arg("--json")
        .output()
        .expect("plugin run should run");
    assert!(
        run_observer.status.success(),
        "logicpearl plugin run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_observer.stdout),
        String::from_utf8_lossy(&run_observer.stderr)
    );
    let observer_report: Value =
        serde_json::from_slice(&run_observer.stdout).expect("plugin run output should be JSON");
    assert_eq!(
        observer_report["request"]["payload"]["input"]["age"].as_i64(),
        Some(34)
    );
    assert_eq!(
        observer_report["request"]["payload"]["raw_input"]["age"].as_i64(),
        Some(34)
    );
    assert_eq!(
        observer_report["response"]["features"]["is_member"].as_i64(),
        Some(1)
    );

    let run_trace = Command::new(cli_bin)
        .arg("plugin")
        .arg("run")
        .arg(&trace_manifest)
        .arg("--input-literal")
        .arg(trace_source.display().to_string())
        .arg("--option")
        .arg("label_column=allowed")
        .arg("--json")
        .output()
        .expect("trace-source plugin run should run");
    assert!(
        run_trace.status.success(),
        "logicpearl plugin run for trace_source failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_trace.stdout),
        String::from_utf8_lossy(&run_trace.stderr)
    );
    let trace_report: Value =
        serde_json::from_slice(&run_trace.stdout).expect("trace plugin run output should be JSON");
    assert_eq!(
        trace_report["request"]["payload"]["input"].as_str(),
        Some(trace_source.to_string_lossy().as_ref())
    );
    assert_eq!(
        trace_report["request"]["payload"]["source"].as_str(),
        Some(trace_source.to_string_lossy().as_ref())
    );
    assert!(trace_report["response"]["decision_traces"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty()));
}

#[test]
fn build_report_records_plugin_provenance() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let trace_manifest = repo_root.join("examples/plugins/python_trace_source/manifest.json");
    let enricher_manifest = repo_root.join("examples/plugins/python_enricher/manifest.json");
    let trace_source = repo_root.join("examples/getting_started/decision_traces.csv");
    let output_dir = tempdir().expect("temp output dir should be created");
    let artifact_dir = output_dir.path().join("artifact_bundle");

    let build = Command::new(cli_bin)
        .arg("build")
        .arg("--trace-plugin-manifest")
        .arg(&trace_manifest)
        .arg("--trace-plugin-input")
        .arg(&trace_source)
        .arg("--enricher-plugin-manifest")
        .arg(&enricher_manifest)
        .arg("--source-ref")
        .arg("document_id=decision_traces_sample")
        .arg("--skip-compile")
        .arg("--output-dir")
        .arg(&artifact_dir)
        .arg("--json")
        .output()
        .expect("logicpearl build should run");
    assert!(
        build.status.success(),
        "logicpearl build with plugins failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let build_result: BuildResult =
        serde_json::from_slice(&build.stdout).expect("build output should be valid JSON");
    let provenance = build_result
        .provenance
        .expect("build provenance should be present");
    assert_eq!(
        provenance
            .decision_trace_source
            .as_ref()
            .map(|item| item.kind.as_str()),
        Some("trace_plugin")
    );
    assert_eq!(
        provenance
            .trace_plugin
            .as_ref()
            .map(|item| item.stage.as_str()),
        Some("trace_source")
    );
    assert_eq!(
        provenance
            .trace_plugin
            .as_ref()
            .and_then(|item| item.options.get("label_column"))
            .map(String::as_str),
        Some("allowed")
    );
    assert_eq!(
        provenance
            .source_references
            .get("document_id")
            .map(String::as_str),
        Some("decision_traces_sample")
    );

    let persisted: BuildResult = serde_json::from_str(
        &std::fs::read_to_string(&build_result.output_files.build_report)
            .expect("build report should be readable"),
    )
    .expect("build report should be valid JSON");
    assert!(persisted.provenance.is_some());
}
