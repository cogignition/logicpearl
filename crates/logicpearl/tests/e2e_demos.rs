use logicpearl_discovery::{load_decision_traces_auto, BuildResult};
use serde_json::{Map, Value};
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

#[derive(Debug)]
struct DemoCase {
    name: &'static str,
    traces: &'static str,
    allowed: bool,
}

fn parse_input_row(traces_path: &Path, expected_allowed: bool) -> Map<String, Value> {
    let loaded = load_decision_traces_auto(traces_path, None, None, None)
        .expect("demo dataset should normalize");
    let row = loaded
        .rows
        .into_iter()
        .find(|row| row.allowed == expected_allowed)
        .expect("expected to find row with matching label polarity");
    row.features.into_iter().collect()
}

fn run_compiled_binary(binary: &Path, payload: &Value, workdir: &Path) -> String {
    let input_path = workdir.join("input.json");
    fs::write(
        &input_path,
        serde_json::to_string_pretty(payload).expect("payload should serialize"),
    )
    .expect("input payload should write");

    let output = Command::new(binary)
        .arg(&input_path)
        .output()
        .expect("compiled demo pearl should run");
    assert!(
        output.status.success(),
        "compiled pearl binary failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn garden_actions_builds_single_action_policy_artifact() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let temp = tempdir().expect("temp directory should be created");
    let output_path = temp.path().join("garden_actions");

    let build_output = Command::new(cli_bin)
        .arg("build")
        .arg(repo_root.join("examples/demos/garden_actions/traces.csv"))
        .arg("--action-column")
        .arg("next_action")
        .arg("--default-action")
        .arg("do_nothing")
        .arg("--gate-id")
        .arg("garden_actions")
        .arg("--output-dir")
        .arg(&output_path)
        .output()
        .expect("logicpearl build should run");
    assert!(
        build_output.status.success(),
        "garden action build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );
    assert!(output_path.join("pearl.ir.json").exists());
    assert!(!output_path.join("action_policy.ir.json").exists());
    assert!(!output_path.join("actions").exists());

    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(output_path.join("artifact.json")).expect("manifest should read"),
    )
    .expect("manifest should parse");
    assert_eq!(manifest["artifact_kind"], "action_policy");
    assert_eq!(manifest["files"]["pearl_ir"], "pearl.ir.json");

    let inspect_output = Command::new(cli_bin)
        .arg("inspect")
        .arg(&output_path)
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .output()
        .expect("logicpearl inspect should run");
    assert!(
        inspect_output.status.success(),
        "garden action inspect failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect_output.stdout),
        String::from_utf8_lossy(&inspect_output.stderr)
    );
    let inspect_stdout = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_stdout.contains("Action rules:"), "{inspect_stdout}");
    assert!(!inspect_stdout.contains("bit 0:"), "{inspect_stdout}");

    let run_output = Command::new(cli_bin)
        .arg("run")
        .arg(&output_path)
        .arg(repo_root.join("examples/demos/garden_actions/today.json"))
        .arg("--explain")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .output()
        .expect("logicpearl run should run");
    assert!(
        run_output.status.success(),
        "garden action run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_output.stdout),
        String::from_utf8_lossy(&run_output.stderr)
    );
    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(run_stdout.contains("action:"), "{run_stdout}");
    assert!(run_stdout.contains("water"), "{run_stdout}");

    let run_json_output = Command::new(cli_bin)
        .arg("run")
        .arg(&output_path)
        .arg(repo_root.join("examples/demos/garden_actions/today.json"))
        .arg("--json")
        .output()
        .expect("logicpearl run --json should run");
    assert!(
        run_json_output.status.success(),
        "garden action run --json failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_json_output.stdout),
        String::from_utf8_lossy(&run_json_output.stderr)
    );
    let run_json: Value =
        serde_json::from_slice(&run_json_output.stdout).expect("run output should be JSON");
    assert_eq!(run_json["decision_kind"], "action");
    assert_eq!(run_json["action_policy_id"], "garden_actions");
    assert_eq!(run_json["action"], "water");
    assert_eq!(run_json["defaulted"], false);
    assert_eq!(run_json["bitmask"], 1);

    let direct_ir_run_output = Command::new(cli_bin)
        .arg("run")
        .arg(output_path.join("pearl.ir.json"))
        .arg(repo_root.join("examples/demos/garden_actions/today.json"))
        .arg("--json")
        .output()
        .expect("logicpearl action IR run should run");
    assert!(
        direct_ir_run_output.status.success(),
        "garden action direct IR run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&direct_ir_run_output.stdout),
        String::from_utf8_lossy(&direct_ir_run_output.stderr)
    );
    let direct_ir_run_json: Value =
        serde_json::from_slice(&direct_ir_run_output.stdout).expect("direct IR output JSON");
    assert_eq!(direct_ir_run_json["action"], "water");

    let plugin_output_path = temp.path().join("garden_actions_plugin");
    let plugin_build_output = Command::new(cli_bin)
        .arg("build")
        .arg("--trace-plugin-manifest")
        .arg(repo_root.join("examples/plugins/python_action_trace_source/manifest.json"))
        .arg("--trace-plugin-input")
        .arg(repo_root.join("examples/demos/garden_actions/traces.csv"))
        .arg("--action-column")
        .arg("next_action")
        .arg("--default-action")
        .arg("do_nothing")
        .arg("--gate-id")
        .arg("garden_actions_plugin")
        .arg("--output-dir")
        .arg(&plugin_output_path)
        .arg("--compile")
        .output()
        .expect("logicpearl action plugin build should run");
    assert!(
        plugin_build_output.status.success(),
        "garden action plugin build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&plugin_build_output.stdout),
        String::from_utf8_lossy(&plugin_build_output.stderr)
    );

    let plugin_manifest: Value = serde_json::from_str(
        &fs::read_to_string(plugin_output_path.join("artifact.json"))
            .expect("plugin manifest should read"),
    )
    .expect("plugin manifest should parse");
    assert_eq!(plugin_manifest["artifact_kind"], "action_policy");
    let native_binary = plugin_manifest["files"]["native_binary"]
        .as_str()
        .expect("action --compile should emit a native binary");
    let today: Value = serde_json::from_str(
        &fs::read_to_string(repo_root.join("examples/demos/garden_actions/today.json"))
            .expect("today input should read"),
    )
    .expect("today input should parse");
    let compiled_stdout =
        run_compiled_binary(&plugin_output_path.join(native_binary), &today, temp.path());
    let compiled_json: Value =
        serde_json::from_str(&compiled_stdout).expect("compiled action output should be JSON");
    assert_eq!(compiled_json["decision_kind"], "action");
    assert_eq!(compiled_json["action_policy_id"], "garden_actions_plugin");
    assert_eq!(compiled_json["action"], "water");
    assert_eq!(compiled_json["defaulted"], false);
    assert_eq!(compiled_json["bitmask"], 1);

    if let Some(wasm_module) = plugin_manifest["files"]["wasm_module"].as_str() {
        assert_eq!(wasm_module, "pearl.wasm");
        assert!(plugin_output_path.join("pearl.wasm").exists());
        assert!(plugin_output_path.join("pearl.wasm.meta.json").exists());
        let wasm_metadata: Value = serde_json::from_str(
            &fs::read_to_string(plugin_output_path.join("pearl.wasm.meta.json"))
                .expect("wasm metadata should read"),
        )
        .expect("wasm metadata should parse");
        assert_eq!(wasm_metadata["decision_kind"], "action");
        assert_eq!(wasm_metadata["action_policy_id"], "garden_actions_plugin");
        assert_eq!(wasm_metadata["default_action"], "do_nothing");
        assert_eq!(wasm_metadata["rules"][0]["action"], "water");
        assert!(wasm_metadata["rules"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("Soil Moisture")));
    }
}

#[test]
fn demo_datasets_build_to_perfect_parity_and_run_compiled_binaries() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let demos = [
        DemoCase {
            name: "access_control",
            traces: "examples/demos/access_control/traces.csv",
            allowed: true,
        },
        DemoCase {
            name: "content_moderation",
            traces: "examples/demos/content_moderation/traces.csv",
            allowed: true,
        },
        DemoCase {
            name: "loan_approval",
            traces: "examples/demos/loan_approval/traces.csv",
            allowed: true,
        },
        DemoCase {
            name: "access_control_json",
            traces: "examples/demos/access_control/traces.json",
            allowed: true,
        },
        DemoCase {
            name: "content_moderation_nested_json",
            traces: "examples/demos/content_moderation/traces_nested.json",
            allowed: true,
        },
        DemoCase {
            name: "loan_approval_jsonl",
            traces: "examples/demos/loan_approval/traces.jsonl",
            allowed: true,
        },
    ];

    for demo in demos {
        let traces_path = repo_root.join(demo.traces);
        let temp = tempdir().expect("temp directory should be created");
        let output_path = temp.path().join(demo.name);

        let build_output = Command::new(cli_bin)
            .arg("build")
            .arg(&traces_path)
            .arg("--output-dir")
            .arg(&output_path)
            .arg("--compile")
            .arg("--json")
            .output()
            .expect("logicpearl build should run");
        assert!(
            build_output.status.success(),
            "logicpearl build failed for {}:\nstdout:\n{}\nstderr:\n{}",
            demo.name,
            String::from_utf8_lossy(&build_output.stdout),
            String::from_utf8_lossy(&build_output.stderr)
        );

        let build_result: BuildResult = serde_json::from_slice(&build_output.stdout)
            .expect("build output should be valid JSON");
        assert_eq!(
            build_result.training_parity, 1.0,
            "{} should build to perfect parity",
            demo.name
        );

        let native_binary = Path::new(
            build_result
                .output_files
                .native_binary
                .as_deref()
                .expect("build should emit native binary"),
        );
        assert!(
            native_binary.exists(),
            "native binary should exist for {}",
            demo.name
        );

        let allowed_payload = Value::Object(parse_input_row(&traces_path, demo.allowed));
        let denied_payload = Value::Object(parse_input_row(&traces_path, !demo.allowed));

        let allowed_output = run_compiled_binary(native_binary, &allowed_payload, temp.path());
        assert_eq!(
            allowed_output, "0",
            "{} should allow known-allowed row",
            demo.name
        );

        let denied_output = run_compiled_binary(native_binary, &denied_payload, temp.path());
        assert_ne!(
            denied_output, "0",
            "{} should deny known-denied row",
            demo.name
        );
    }
}
