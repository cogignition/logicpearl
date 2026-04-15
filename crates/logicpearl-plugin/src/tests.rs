// SPDX-License-Identifier: MIT
use super::contract::{validate_ok_plugin_response, validate_plugin_request_contract};
use super::process_runner::{read_limited, write_plugin_stdin};
use super::{
    run_plugin, run_plugin_with_policy, run_plugin_with_policy_and_metadata, PluginExecutionPolicy,
    PluginManifest, PluginRequest, PluginStage,
};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn validates_basic_manifest() {
    let manifest = PluginManifest {
        name: "demo".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
        language: Some("python".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: None,
        manifest_path: None,
    };
    assert!(manifest.validate().is_ok());
}

#[test]
fn validates_declared_input_options_and_output_schemas() {
    let manifest = PluginManifest {
        name: "demo".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
        language: Some("python".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: Some(json!({
            "type": "object",
            "required": ["age", "member"],
            "properties": {
                "age": { "type": "integer" },
                "member": { "type": "boolean" }
            },
            "additionalProperties": false
        })),
        options_schema: Some(json!({
            "type": ["object", "null"],
            "properties": {
                "mode": { "type": "string" }
            },
            "additionalProperties": false
        })),
        output_schema: Some(json!({
            "type": "object",
            "required": ["ok", "features"],
            "properties": {
                "ok": { "const": true },
                "features": {
                    "type": "object",
                    "required": ["age"],
                    "properties": {
                        "age": { "type": "integer" }
                    }
                }
            }
        })),
        manifest_dir: None,
        manifest_path: None,
    };
    assert!(manifest.validate().is_ok());

    let request = super::PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        payload: super::build_canonical_payload(
            &PluginStage::Observer,
            json!({"age": 34, "member": true}),
            Some(json!({"mode": "strict"})),
        ),
    };
    assert!(validate_plugin_request_contract(&manifest, &request).is_ok());

    let bad_request = super::PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        payload: super::build_canonical_payload(
            &PluginStage::Observer,
            json!({"age": "34", "member": true, "extra": 1}),
            None,
        ),
    };
    assert!(validate_plugin_request_contract(&manifest, &bad_request).is_err());

    let good_response = super::PluginResponse {
        ok: true,
        warnings: Vec::new(),
        error: None,
        extra: serde_json::Map::from_iter([("features".to_string(), json!({"age": 34}))]),
    };
    assert!(validate_ok_plugin_response(&manifest, &good_response).is_ok());

    let bad_response = super::PluginResponse {
        ok: true,
        warnings: Vec::new(),
        error: None,
        extra: serde_json::Map::new(),
    };
    assert!(validate_ok_plugin_response(&manifest, &bad_response).is_err());
}

#[test]
fn rejects_unsupported_schema_subset_keywords() {
    let manifest = PluginManifest {
        name: "demo".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
        language: Some("python".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: Some(json!({
            "type": "object",
            "properties": {
                "age": {
                    "type": "integer",
                    "minimum": 0
                }
            }
        })),
        options_schema: None,
        output_schema: None,
        manifest_dir: None,
        manifest_path: None,
    };

    let err = manifest.validate().unwrap_err();
    assert!(err
        .to_string()
        .contains("unsupported LogicPearl schema subset keyword \"minimum\""));
}

#[test]
fn accepts_schema_subset_annotation_keywords() {
    let manifest = PluginManifest {
        name: "demo".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
        language: Some("python".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: Some(json!({
            "$schema": "https://logicpearl.com/schema/plugin-contract-subset",
            "title": "Observer input",
            "description": "Annotation fields are accepted but do not add validation.",
            "type": "object"
        })),
        options_schema: None,
        output_schema: None,
        manifest_dir: None,
        manifest_path: None,
    };

    assert!(manifest.validate().is_ok());
}

#[cfg(unix)]
fn write_plugin_script(script_body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("plugin.sh");
    std::fs::write(&path, script_body).expect("write script");
    let mut permissions = std::fs::metadata(&path).expect("stat script").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod script");
    (dir, path)
}

#[cfg(unix)]
fn test_request() -> PluginRequest {
    PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        payload: super::build_canonical_payload(&PluginStage::Observer, json!({"value": 1}), None),
    }
}

#[cfg(unix)]
#[test]
fn enforces_plugin_timeout_when_declared() {
    let (dir, _script_path) =
        write_plugin_script("#!/bin/sh\nsleep 1\nprintf '{\"ok\":true}\\n'\n");
    let manifest = PluginManifest {
        name: "slow".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: Some(50),
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let error = run_plugin(&manifest, &test_request()).expect_err("plugin should time out");
    let message = error.to_string();
    assert!(message.contains("exceeded timeout_ms=50"), "{message}");
}

#[cfg(unix)]
#[test]
fn applies_policy_default_timeout_when_manifest_timeout_is_unset() {
    let (dir, _script_path) =
        write_plugin_script("#!/bin/sh\nsleep 1\nprintf '{\"ok\":true}\\n'\n");
    let manifest = PluginManifest {
        name: "slow-default".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let policy = PluginExecutionPolicy::default().with_default_timeout_ms(50);
    let error = run_plugin_with_policy(&manifest, &test_request(), &policy)
        .expect_err("policy default timeout should apply");
    let message = error.to_string();
    assert!(message.contains("exceeded timeout_ms=50"), "{message}");
}

#[cfg(unix)]
#[test]
fn rejects_no_timeout_manifest_without_policy_opt_in() {
    let (dir, _script_path) = write_plugin_script("#!/bin/sh\nprintf '{\"ok\":true}\\n'\n");
    let manifest = PluginManifest {
        name: "no-timeout".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: Some(0),
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let error = run_plugin(&manifest, &test_request()).expect_err("no timeout should reject");
    let message = error.to_string();
    assert!(message.contains("timeout_ms=0"), "{message}");
    assert!(message.contains("disables the plugin timeout"), "{message}");
}

#[cfg(unix)]
#[test]
fn allows_no_timeout_when_policy_opts_in() {
    let (dir, _script_path) = write_plugin_script(
        "#!/bin/sh\nsleep 0.1\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n",
    );
    let manifest = PluginManifest {
        name: "trusted-no-timeout".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: Some(0),
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let policy = PluginExecutionPolicy::default().with_allow_no_timeout(true);
    let response = run_plugin_with_policy(&manifest, &test_request(), &policy)
        .expect("trusted no-timeout plugin should succeed");
    assert!(response.ok);
    assert_eq!(response.extra.get("features"), Some(&json!({"value": 1})));
}

#[cfg(unix)]
#[test]
fn allows_known_interpreter_for_manifest_local_script() {
    let (dir, _script_path) =
        write_plugin_script("#!/bin/sh\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n");
    let manifest = PluginManifest {
        name: "shell-wrapper".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["sh".to_string(), "plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let response = run_plugin(&manifest, &test_request())
        .expect("known interpreter with manifest-local script should succeed");
    assert!(response.ok);
}

#[cfg(unix)]
#[test]
fn returns_redacted_plugin_run_metadata() {
    let (dir, _script_path) = write_plugin_script(
        "#!/bin/sh\nprintf 'debug secret\\n' >&2\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n",
    );
    let manifest = PluginManifest {
        name: "metadata".to_string(),
        plugin_id: Some("metadata-plugin".to_string()),
        plugin_version: Some("0.1.0".to_string()),
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: Some(vec!["feature_output".to_string()]),
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let execution = run_plugin_with_policy_and_metadata(
        &manifest,
        &test_request(),
        &PluginExecutionPolicy::default(),
    )
    .expect("plugin should run with metadata");

    assert!(execution.response.ok);
    assert_eq!(execution.run.plugin_id, "metadata-plugin");
    assert_eq!(execution.run.plugin_version.as_deref(), Some("0.1.0"));
    assert_eq!(execution.run.access.network, "not_enforced");
    assert_eq!(execution.run.access.filesystem, "process_default");
    assert_eq!(
        execution.run.timeout_policy.effective_timeout_ms,
        Some(30_000)
    );
    assert_eq!(
        execution.run.capabilities.allowed,
        vec!["feature_output".to_string()]
    );
    assert!(execution.run.plugin_run_id.starts_with("sha256:"));
    assert!(execution.run.entrypoint_hash.starts_with("sha256:"));
    assert_eq!(execution.run.entrypoint.hashes.len(), 1);
    assert!(execution
        .run
        .stdio
        .stdout_summary
        .as_deref()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));
    assert!(execution
        .run
        .stdio
        .stderr_summary
        .as_deref()
        .is_some_and(|value| value.starts_with("<redacted:sha256:")));
    assert_ne!(
        execution.run.stdio.stderr_summary.as_deref(),
        Some("debug secret")
    );
}

#[cfg(unix)]
#[test]
fn rejects_bare_path_lookup_by_default() {
    let dir = tempdir().expect("tempdir");
    let manifest = PluginManifest {
        name: "path-command".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["logicpearl-plugin-not-in-manifest".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let error = run_plugin(&manifest, &test_request()).expect_err("PATH lookup should reject");
    let message = error.to_string();
    assert!(message.contains("PATH lookup is disabled"), "{message}");
}

#[cfg(unix)]
#[test]
fn rejects_absolute_entrypoint_by_default() {
    let (dir, script_path) =
        write_plugin_script("#!/bin/sh\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n");
    let manifest = PluginManifest {
        name: "absolute".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec![script_path.display().to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let error =
        run_plugin(&manifest, &test_request()).expect_err("absolute entrypoint should reject");
    let message = error.to_string();
    assert!(message.contains("absolute program path"), "{message}");
}

#[cfg(unix)]
#[test]
fn allows_absolute_entrypoint_when_policy_opts_in() {
    let (dir, script_path) =
        write_plugin_script("#!/bin/sh\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n");
    let manifest = PluginManifest {
        name: "absolute".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec![script_path.display().to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: None,
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let policy = PluginExecutionPolicy::default().with_allow_absolute_entrypoint(true);
    let response = run_plugin_with_policy(&manifest, &test_request(), &policy)
        .expect("absolute entrypoint should run only under explicit policy");
    assert!(response.ok);
}

#[cfg(unix)]
#[test]
fn timeout_terminates_descendants_that_keep_output_pipes_open() {
    let (dir, _script_path) =
        write_plugin_script("#!/bin/sh\n(sh -c 'sleep 5') &\nsleep 5\nprintf '{\"ok\":true}\\n'\n");
    let manifest = PluginManifest {
        name: "tree".to_string(),
        plugin_id: None,
        plugin_version: None,
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        entrypoint: vec!["plugin.sh".to_string()],
        language: Some("shell".to_string()),
        capabilities: None,
        timeout_ms: Some(50),
        input_schema: None,
        options_schema: None,
        output_schema: None,
        manifest_dir: Some(dir.path().to_path_buf()),
        manifest_path: None,
    };

    let started_at = std::time::Instant::now();
    let error = run_plugin(&manifest, &test_request()).expect_err("plugin should time out");
    assert!(
        started_at.elapsed() < std::time::Duration::from_secs(2),
        "timeout should not wait for descendant sleep process"
    );
    let message = error.to_string();
    assert!(message.contains("exceeded timeout_ms=50"), "{message}");
}

#[test]
fn limited_reader_rejects_outputs_above_cap() {
    let mut reader = std::io::Cursor::new(vec![b'x'; 5]);
    let error = read_limited(&mut reader, 4).expect_err("reader should reject overflow");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(reader.position(), 5, "reader should drain capped streams");
}

#[test]
fn stdin_writer_treats_broken_pipe_as_early_plugin_exit() {
    struct BrokenPipeWriter;

    impl std::io::Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "plugin closed stdin",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = BrokenPipeWriter;
    write_plugin_stdin(&mut writer, br#"{"protocol_version":"1"}"#)
        .expect("broken pipe should be handled by process status and output validation");
}
