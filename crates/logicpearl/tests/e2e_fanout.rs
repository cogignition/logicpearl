// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::fs;
use std::process::Command;

fn run_cli_json(args: &[String]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_logicpearl"))
        .args(args)
        .output()
        .expect("logicpearl command should run");
    assert!(
        output.status.success(),
        "logicpearl {:?} failed:\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command stdout should be JSON")
}

#[test]
fn fanout_build_writes_typed_pipeline_and_runs_multiple_applicable_actions() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let traces = temp.path().join("traces.csv");
    fs::write(
        &traces,
        "moisture,pests,sun,applicable\n\
low,yes,low,\"water,treat_pests,move_to_more_sun\"\n\
low,no,ok,water\n\
ok,yes,ok,treat_pests\n\
ok,no,low,move_to_more_sun\n\
ok,no,ok,none\n",
    )
    .expect("trace fixture should write");
    let output_dir = temp.path().join("fanout");

    let build_report = run_cli_json(&[
        "build".to_string(),
        traces.display().to_string(),
        "--fanout-column".to_string(),
        "applicable".to_string(),
        "--fanout-actions".to_string(),
        "water,treat_pests,move_to_more_sun".to_string(),
        "--output-dir".to_string(),
        output_dir.display().to_string(),
        "--compile".to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(build_report["actions"].as_array().unwrap().len(), 3);
    assert_eq!(build_report["training_exact_set_match"].as_f64(), Some(0.8));

    let pipeline = serde_json::from_str::<Value>(
        &fs::read_to_string(output_dir.join("pipeline.json")).expect("pipeline should exist"),
    )
    .expect("pipeline should be JSON");
    assert_eq!(pipeline["schema_version"], "logicpearl.fanout_pipeline.v1");

    let input = temp.path().join("input.json");
    fs::write(&input, r#"{"moisture":"low","pests":"no","sun":"low"}"#)
        .expect("input should write");
    let result = run_cli_json(&[
        "pipeline".to_string(),
        "run".to_string(),
        output_dir.join("pipeline.json").display().to_string(),
        input.display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(result["schema_version"], "logicpearl.fanout_result.v1");
    assert_eq!(result["decision_kind"], "fanout");
    let applicable = result["applicable_actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(applicable.contains(&"water"), "{applicable:?}");
    assert!(applicable.contains(&"move_to_more_sun"), "{applicable:?}");
    assert!(!applicable.contains(&"treat_pests"), "{applicable:?}");

    let manifest = serde_json::from_str::<Value>(
        &fs::read_to_string(output_dir.join("artifact.json")).expect("manifest should exist"),
    )
    .expect("manifest should be JSON");
    if rust_target_installed("wasm32-unknown-unknown") {
        let wasm = manifest["files"]["wasm"]
            .as_str()
            .expect("fan-out build --compile should emit Wasm when wasm32 target is installed");
        let wasm_metadata = manifest["files"]["wasm_metadata"].as_str().expect(
            "fan-out build --compile should emit Wasm metadata when wasm32 target is installed",
        );
        assert!(output_dir.join(wasm).exists());
        let metadata: Value = serde_json::from_str(
            &fs::read_to_string(output_dir.join(wasm_metadata))
                .expect("fan-out wasm metadata should read"),
        )
        .expect("fan-out wasm metadata should parse");
        assert_eq!(metadata["decision_kind"], "fanout");
        assert_eq!(metadata["pipeline_id"], manifest["artifact_id"]);
        assert_eq!(metadata["actions"].as_array().unwrap().len(), 3);
        assert_eq!(
            metadata["actions"][0]["entrypoint"],
            "logicpearl_eval_bitmask_slots_f64_water"
        );
        if command_available("node") {
            let repo_root = repo_root();
            let browser_module = repo_root
                .join("packages/logicpearl-browser/src/index.js")
                .display()
                .to_string();
            let script_path = temp.path().join("fanout-browser-check.mjs");
            fs::write(
                &script_path,
                format!(
                    r#"
import {{ readFile }} from 'node:fs/promises';
import {{ loadArtifactFromBundle }} from 'file://{browser_module}';

const manifest = JSON.parse(await readFile('{manifest}', 'utf8'));
const wasmMetadata = JSON.parse(await readFile('{wasm_metadata}', 'utf8'));
const wasmModule = await readFile('{wasm}');
const artifact = await loadArtifactFromBundle({{
  manifest,
  wasmModule,
  wasmMetadata,
}});
const result = artifact.evaluateJson({{
  moisture: 'low',
  pests: 'no',
  sun: 'low',
}});
if (result.schema_version !== 'logicpearl.fanout_result.v1') {{
  throw new Error(`unexpected schema_version ${{result.schema_version}}`);
}}
if (!result.applicable_actions.includes('water') || !result.applicable_actions.includes('move_to_more_sun')) {{
  throw new Error(`unexpected applicable actions ${{JSON.stringify(result.applicable_actions)}}`);
}}
if (result.applicable_actions.includes('treat_pests')) {{
  throw new Error(`unexpected pest treatment ${{JSON.stringify(result.applicable_actions)}}`);
}}
"#,
                    browser_module = browser_module,
                    manifest = output_dir.join("artifact.json").display(),
                    wasm_metadata = output_dir.join(wasm_metadata).display(),
                    wasm = output_dir.join(wasm).display(),
                ),
            )
            .expect("browser integration script should write");
            let browser_output = Command::new("node")
                .arg(&script_path)
                .output()
                .expect("node fan-out browser check should run");
            assert!(
                browser_output.status.success(),
                "node fan-out browser check failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&browser_output.stdout),
                String::from_utf8_lossy(&browser_output.stderr)
            );
        }
    }
    let native = output_dir.join(
        manifest["files"]["native"]
            .as_str()
            .expect("fan-out build --compile should emit native runner"),
    );
    let compiled_output = Command::new(&native)
        .arg(&input)
        .output()
        .expect("compiled fan-out runner should run");
    assert!(
        compiled_output.status.success(),
        "compiled fan-out runner failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled_output.stdout),
        String::from_utf8_lossy(&compiled_output.stderr)
    );
    let compiled_result: Value =
        serde_json::from_slice(&compiled_output.stdout).expect("compiled output should be JSON");
    assert_eq!(compiled_result, result);

    let verify = run_cli_json(&[
        "artifact".to_string(),
        "verify".to_string(),
        output_dir.join("artifact.json").display().to_string(),
        "--json".to_string(),
    ]);
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["artifact_kind"], "pipeline");
    if manifest["files"]["wasm_metadata"].is_string() {
        let check_names = verify["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| check["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(check_names.contains(&"wasm_metadata.decision_kind"));
        assert!(check_names.contains(&"wasm_metadata.pipeline_id"));
        assert!(check_names
            .iter()
            .any(|name| name.starts_with("wasm_metadata.action.water.artifact_hash")));
    }
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(std::path::PathBuf::from)
        .expect("logicpearl crate should live under workspace/crates/logicpearl")
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn rust_target_installed(target: &str) -> bool {
    Command::new("rustup")
        .arg("target")
        .arg("list")
        .arg("--installed")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.lines().any(|line| line.trim() == target))
        .unwrap_or(false)
}
