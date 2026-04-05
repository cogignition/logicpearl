use logicpearl_discovery::BuildResult;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("logicpearl-cli crate should live under workspace/crates/logicpearl-cli")
        .to_path_buf()
}

#[derive(Debug)]
struct DemoCase {
    name: &'static str,
    csv: &'static str,
}

fn parse_input_row(csv_path: &Path, expected_label: &str) -> Map<String, Value> {
    let mut reader = csv::Reader::from_path(csv_path).expect("demo CSV should load");
    let headers = reader.headers().expect("headers should load").clone();
    for record in reader.records() {
        let record = record.expect("record should parse");
        let label = record
            .get(headers.len() - 1)
            .expect("label column should exist");
        if label != expected_label {
            continue;
        }
        let mut object = Map::new();
        for (header, value) in headers.iter().zip(record.iter()) {
            if header == "allowed" {
                continue;
            }
            if let Ok(integer) = value.parse::<i64>() {
                object.insert(header.to_string(), Value::from(integer));
            } else if let Ok(float_value) = value.parse::<f64>() {
                object.insert(header.to_string(), Value::from(float_value));
            } else {
                object.insert(header.to_string(), Value::from(value.to_string()));
            }
        }
        return object;
    }
    panic!("expected to find row with label {expected_label}");
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
fn demo_datasets_build_to_perfect_parity_and_run_compiled_binaries() {
    let repo_root = repo_root();
    let cli_bin = env!("CARGO_BIN_EXE_logicpearl");
    let demos = [
        DemoCase {
            name: "access_control",
            csv: "examples/demos/access_control/traces.csv",
        },
        DemoCase {
            name: "content_moderation",
            csv: "examples/demos/content_moderation/traces.csv",
        },
        DemoCase {
            name: "loan_approval",
            csv: "examples/demos/loan_approval/traces.csv",
        },
    ];

    for demo in demos {
        let csv_path = repo_root.join(demo.csv);
        let temp = tempdir().expect("temp directory should be created");
        let output_path = temp.path().join(demo.name);

        let build_output = Command::new(cli_bin)
            .arg("build")
            .arg(&csv_path)
            .arg("--output-dir")
            .arg(&output_path)
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

        let build_result: BuildResult =
            serde_json::from_slice(&build_output.stdout).expect("build output should be valid JSON");
        assert_eq!(build_result.training_parity, 1.0, "{} should build to perfect parity", demo.name);

        let native_binary = Path::new(
            build_result
                .output_files
                .native_binary
                .as_deref()
                .expect("build should emit native binary"),
        );
        assert!(native_binary.exists(), "native binary should exist for {}", demo.name);

        let allowed_payload = Value::Object(parse_input_row(&csv_path, "allowed"));
        let denied_payload = Value::Object(parse_input_row(&csv_path, "denied"));

        let allowed_output = run_compiled_binary(native_binary, &allowed_payload, temp.path());
        assert_eq!(allowed_output, "0", "{} should allow known-allowed row", demo.name);

        let denied_output = run_compiled_binary(native_binary, &denied_payload, temp.path());
        assert_ne!(denied_output, "0", "{} should deny known-denied row", demo.name);
    }
}
