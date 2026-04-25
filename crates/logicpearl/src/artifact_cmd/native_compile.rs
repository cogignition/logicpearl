// SPDX-License-Identifier: MIT
use super::{
    binary_file_name, cleanup_generated_build_dir, dependency_spec, generated_build_root,
    native_artifact_output_path, resolve_manifest_member_path, unique_generated_crate_name,
    workspace_root, CompilablePearl,
};
use logicpearl_benchmark::sanitize_identifier;
use logicpearl_core::load_artifact_bundle;
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_pipeline::FanoutPipelineDefinition;
use miette::{IntoDiagnostic, Result, WrapErr};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const EMBEDDED_NATIVE_RUNNER_MAGIC: &[u8; 16] = b"LPEARL_RUNNER_V1";
const EMBEDDED_NATIVE_RUNNER_TRAILER_LEN: u64 = 24;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum EmbeddedNativePayload {
    Pearl(Value),
    Fanout(EmbeddedFanoutPayload),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct EmbeddedFanoutPayload {
    pipeline_id: String,
    artifact_hash: String,
    #[serde(default)]
    input: HashMap<String, Value>,
    gates: Vec<EmbeddedFanoutGate>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct EmbeddedFanoutGate {
    action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    gate: LogicPearlGateIr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input: Option<HashMap<String, Value>>,
}

pub(crate) fn compile_native_runner(
    pearl_ir: &Path,
    artifact_dir: &Path,
    gate_id: &str,
    name: Option<String>,
    target_triple: Option<String>,
    output: Option<PathBuf>,
) -> Result<PathBuf> {
    let pearl_name = name.unwrap_or_else(|| gate_id.to_string());
    let output_path = output.unwrap_or_else(|| {
        native_artifact_output_path(artifact_dir, &pearl_name, target_triple.as_deref())
    });
    if should_use_embedded_native_runner(target_triple.as_deref()) {
        return compile_embedded_native_runner(pearl_ir, &output_path);
    }

    let workspace_root = workspace_root();
    let generated_root = generated_build_root(&workspace_root);
    let crate_name = unique_generated_crate_name(&format!(
        "logicpearl_compiled_{}",
        sanitize_identifier(&pearl_name)
    ));
    let build_dir = generated_root.join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated compile directory")?;

    let logicpearl_ir_dep =
        dependency_spec(&workspace_root, "logicpearl-ir", "crates/logicpearl-ir");
    let logicpearl_runtime_dep = dependency_spec(
        &workspace_root,
        "logicpearl-runtime",
        "crates/logicpearl-runtime",
    );
    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nlogicpearl-ir = {logicpearl_ir_dep}\nlogicpearl-runtime = {logicpearl_runtime_dep}\nserde_json = \"1\"\n",
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated Cargo.toml")?;

    let escaped_pearl_path = pearl_ir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('\"', "\\\"");
    let main_rs = generated_native_runner_source(&escaped_pearl_path);
    fs::write(src_dir.join("main.rs"), main_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated runner source")?;

    let mut command = std::process::Command::new("cargo");
    command
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--manifest-path")
        .arg(build_dir.join("Cargo.toml"));
    if let Some(target_triple) = &target_triple {
        command.arg("--target").arg(target_triple);
    }
    let status = command
        .status()
        .into_diagnostic()
        .wrap_err(
            "failed to invoke cargo for cross-target native pearl compilation; install Rust/Cargo and make sure `cargo` is on PATH",
        )?;
    if !status.success() {
        return Err(miette::miette!(
            "cross-target native pearl compilation failed with status {status}\n\nHint: same-host native compile is self-contained. Non-host `--target` builds run `cargo build --offline --release`; make sure Rust/Cargo is installed, required crates are present in Cargo's local cache, and the requested target plus linker/toolchain is installed."
        ));
    }

    let built_binary = build_dir
        .join("target")
        .join(target_triple.as_deref().unwrap_or(""))
        .join("release")
        .join(binary_file_name(&crate_name, target_triple.as_deref()));
    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&built_binary, &output_path)
        .into_diagnostic()
        .wrap_err("failed to copy compiled pearl binary")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output_path)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl permissions")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&output_path, perms)
            .into_diagnostic()
            .wrap_err("failed to mark compiled pearl executable")?;
    }

    cleanup_generated_build_dir(&build_dir);
    Ok(output_path)
}

pub(crate) fn compile_native_fanout_runner(
    pipeline_path: &Path,
    artifact_dir: &Path,
    pipeline_id: &str,
    name: Option<String>,
    target_triple: Option<String>,
    output: Option<PathBuf>,
) -> Result<PathBuf> {
    let runner_name = name.unwrap_or_else(|| pipeline_id.to_string());
    let output_path = output.unwrap_or_else(|| {
        native_artifact_output_path(artifact_dir, &runner_name, target_triple.as_deref())
    });
    if should_use_embedded_native_runner(target_triple.as_deref()) {
        return compile_embedded_native_fanout_runner(pipeline_path, artifact_dir, &output_path);
    }
    Err(miette::miette!(
        "cross-target native fan-out compilation is not implemented yet; same-host fan-out compilation is self-contained"
    ))
}

fn compile_embedded_native_runner(pearl_ir: &Path, output_path: &Path) -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current LogicPearl executable for native compilation")?;
    let pearl_value: Value = serde_json::from_slice(
        &fs::read(pearl_ir)
            .into_diagnostic()
            .wrap_err("failed to read pearl IR for native runner payload")?,
    )
    .into_diagnostic()
    .wrap_err("pearl IR payload is not valid JSON")?;
    let pearl_payload = serde_json::to_vec(&EmbeddedNativePayload::Pearl(pearl_value))
        .into_diagnostic()
        .wrap_err("failed to encode native runner payload")?;

    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&current_exe, output_path)
        .into_diagnostic()
        .wrap_err("failed to copy LogicPearl executable as native pearl runner")?;

    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(output_path)
        .into_diagnostic()
        .wrap_err("failed to open native pearl runner for payload embedding")?;
    output
        .write_all(&pearl_payload)
        .into_diagnostic()
        .wrap_err("failed to write native pearl runner payload")?;
    output
        .write_all(&(pearl_payload.len() as u64).to_le_bytes())
        .into_diagnostic()
        .wrap_err("failed to write native pearl runner payload length")?;
    output
        .write_all(EMBEDDED_NATIVE_RUNNER_MAGIC)
        .into_diagnostic()
        .wrap_err("failed to write native pearl runner payload marker")?;

    mark_executable(output_path)?;
    Ok(output_path.to_path_buf())
}

fn compile_embedded_native_fanout_runner(
    pipeline_path: &Path,
    artifact_dir: &Path,
    output_path: &Path,
) -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current LogicPearl executable for native compilation")?;
    let payload = embedded_fanout_payload(pipeline_path, artifact_dir)?;

    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&current_exe, output_path)
        .into_diagnostic()
        .wrap_err("failed to copy LogicPearl executable as native fan-out runner")?;

    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(output_path)
        .into_diagnostic()
        .wrap_err("failed to open native fan-out runner for payload embedding")?;
    output
        .write_all(&payload)
        .into_diagnostic()
        .wrap_err("failed to write native fan-out runner payload")?;
    output
        .write_all(&(payload.len() as u64).to_le_bytes())
        .into_diagnostic()
        .wrap_err("failed to write native fan-out runner payload length")?;
    output
        .write_all(EMBEDDED_NATIVE_RUNNER_MAGIC)
        .into_diagnostic()
        .wrap_err("failed to write native fan-out runner payload marker")?;

    mark_executable(output_path)?;
    Ok(output_path.to_path_buf())
}

fn embedded_fanout_payload(pipeline_path: &Path, artifact_dir: &Path) -> Result<Vec<u8>> {
    let content = fs::read_to_string(pipeline_path)
        .into_diagnostic()
        .wrap_err("failed to read fan-out pipeline for native runner payload")?;
    let pipeline = FanoutPipelineDefinition::from_json_str(&content)
        .into_diagnostic()
        .wrap_err("fan-out pipeline is not valid")?;
    let pipeline_base = pipeline_path.parent().unwrap_or(artifact_dir);
    pipeline
        .validate(pipeline_base)
        .into_diagnostic()
        .wrap_err("fan-out pipeline did not validate")?;
    let gates = pipeline
        .actions
        .iter()
        .map(|action| {
            let artifact_path = resolve_manifest_member_path(pipeline_base, &action.artifact)?;
            let bundle = load_artifact_bundle(&artifact_path)
                .into_diagnostic()
                .wrap_err("failed to load fan-out action artifact")?;
            let gate = LogicPearlGateIr::from_path(
                bundle
                    .ir_path()
                    .into_diagnostic()
                    .wrap_err("failed to resolve fan-out action gate IR")?,
            )
            .into_diagnostic()
            .wrap_err("failed to parse fan-out action gate IR")?;
            Ok(EmbeddedFanoutGate {
                action: action.action.clone(),
                id: action.id.clone(),
                gate,
                input: action.input.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let payload = EmbeddedNativePayload::Fanout(EmbeddedFanoutPayload {
        artifact_hash: logicpearl_runtime::artifact_hash(&pipeline),
        pipeline_id: pipeline.pipeline_id,
        input: pipeline.input,
        gates,
    });
    serde_json::to_vec(&payload).into_diagnostic()
}

fn generated_native_runner_source(escaped_pearl_path: &str) -> String {
    format!(
        "use logicpearl_ir::{{LogicPearlActionIr, LogicPearlGateIr}};\nuse logicpearl_runtime::{{evaluate_action_policy, evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\nuse std::fs;\nuse std::io::Read;\nuse std::process::ExitCode;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn main() -> ExitCode {{\n    match run() {{\n        Ok(()) => ExitCode::SUCCESS,\n        Err(err) => {{\n            eprintln!(\"{{}}\", err);\n            ExitCode::FAILURE\n        }}\n    }}\n}}\n\nfn run() -> Result<(), Box<dyn std::error::Error>> {{\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() != 2 {{\n        return Err(\"usage: compiled-pearl <input.json>\".into());\n    }}\n    let input = if args[1] == \"-\" {{\n        let mut buffer = String::new();\n        std::io::stdin().read_to_string(&mut buffer)?;\n        buffer\n    }} else {{\n        fs::read_to_string(&args[1])?\n    }};\n    let payload: Value = serde_json::from_str(&input)?;\n    let parsed = parse_input_payload(payload)?;\n    let pearl_value: Value = serde_json::from_str(PEARL_JSON)?;\n    if pearl_value.get(\"action_policy_id\").is_some() {{\n        let policy = LogicPearlActionIr::from_json_str(PEARL_JSON)?;\n        let mut outputs = Vec::with_capacity(parsed.len());\n        for input in parsed {{\n            outputs.push(evaluate_action_policy(&policy, &input)?);\n        }}\n        if outputs.len() == 1 {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs[0])?);\n        }} else {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n        }}\n    }} else {{\n        let gate = LogicPearlGateIr::from_json_str(PEARL_JSON)?;\n        let mut outputs = Vec::with_capacity(parsed.len());\n        for input in parsed {{\n            outputs.push(evaluate_gate(&gate, &input)?);\n        }}\n        if outputs.len() == 1 {{\n            println!(\"{{}}\", outputs[0]);\n        }} else {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n        }}\n    }}\n    Ok(())\n}}\n"
    )
}

pub(crate) fn run_embedded_native_runner_if_present() -> Result<bool> {
    let Some(payload) = read_embedded_native_runner_payload()? else {
        return Ok(false);
    };
    let payload_json = std::str::from_utf8(&payload)
        .into_diagnostic()
        .wrap_err("embedded native runner payload is not valid UTF-8")?;
    let payload = parse_embedded_native_payload(payload_json)?;
    let args = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if args.len() != 1 {
        return Err(miette::miette!("usage: compiled-pearl <input.json>"));
    }
    if args[0].as_os_str() == "--help" || args[0].as_os_str() == "-h" {
        println!("usage: compiled-pearl <input.json>");
        return Ok(true);
    }

    let input = if args[0].as_os_str() == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl input JSON from stdin")?;
        buffer
    } else {
        fs::read_to_string(&args[0])
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl input JSON")?
    };
    let input_value: Value = serde_json::from_str(&input)
        .into_diagnostic()
        .wrap_err("compiled pearl input is not valid JSON")?;
    let parsed = logicpearl_runtime::parse_input_payload(input_value.clone())
        .into_diagnostic()
        .wrap_err("compiled pearl input does not match the expected payload shape")?;
    match payload {
        EmbeddedNativePayload::Pearl(pearl_value) => match CompilablePearl::from_json_str(
            &serde_json::to_string(&pearl_value).into_diagnostic()?,
        )
        .wrap_err("embedded pearl payload is not valid LogicPearl IR")?
        {
            CompilablePearl::Gate(gate) => {
                let mut outputs = Vec::with_capacity(parsed.len());
                for input in parsed {
                    outputs.push(
                        logicpearl_runtime::evaluate_gate(&gate, &input)
                            .into_diagnostic()
                            .wrap_err("failed to evaluate compiled pearl")?,
                    );
                }
                if outputs.len() == 1 {
                    println!("{}", outputs[0]);
                } else {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&outputs).into_diagnostic()?
                    );
                }
            }
            CompilablePearl::Action(policy) => {
                let mut outputs = Vec::with_capacity(parsed.len());
                for input in parsed {
                    outputs.push(
                        logicpearl_runtime::evaluate_action_policy(&policy, &input)
                            .into_diagnostic()
                            .wrap_err("failed to evaluate compiled action policy")?,
                    );
                }
                if outputs.len() == 1 {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
                    );
                } else {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&outputs).into_diagnostic()?
                    );
                }
            }
        },
        EmbeddedNativePayload::Fanout(fanout) => {
            let mut outputs = Vec::with_capacity(parsed.len());
            for input in parsed {
                outputs.push(evaluate_embedded_fanout(&fanout, &input)?);
            }
            if outputs.len() == 1 {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outputs).into_diagnostic()?
                );
            }
        }
    }
    Ok(true)
}

pub(super) fn parse_embedded_native_payload(payload_json: &str) -> Result<EmbeddedNativePayload> {
    match serde_json::from_str::<EmbeddedNativePayload>(payload_json) {
        Ok(payload) => Ok(payload),
        Err(tagged_error) => {
            let pearl_value: Value = serde_json::from_str(payload_json)
                .into_diagnostic()
                .wrap_err("embedded native runner payload is not valid JSON")?;
            CompilablePearl::from_json_str(payload_json).map_err(|_| {
                miette::miette!("embedded native runner payload is not valid: {tagged_error}")
            })?;
            Ok(EmbeddedNativePayload::Pearl(pearl_value))
        }
    }
}

fn read_embedded_native_runner_payload() -> Result<Option<Vec<u8>>> {
    let current_exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current executable")?;
    let mut file = fs::File::open(&current_exe)
        .into_diagnostic()
        .wrap_err("failed to open current executable")?;
    let executable_len = file
        .metadata()
        .into_diagnostic()
        .wrap_err("failed to read current executable metadata")?
        .len();
    if executable_len < EMBEDDED_NATIVE_RUNNER_TRAILER_LEN {
        return Ok(None);
    }

    file.seek(SeekFrom::End(-(EMBEDDED_NATIVE_RUNNER_TRAILER_LEN as i64)))
        .into_diagnostic()
        .wrap_err("failed to seek current executable payload trailer")?;
    let mut trailer = [0u8; EMBEDDED_NATIVE_RUNNER_TRAILER_LEN as usize];
    file.read_exact(&mut trailer)
        .into_diagnostic()
        .wrap_err("failed to read current executable payload trailer")?;
    if &trailer[8..] != EMBEDDED_NATIVE_RUNNER_MAGIC {
        return Ok(None);
    }

    let payload_len = u64::from_le_bytes(
        trailer[..8]
            .try_into()
            .expect("payload length trailer should be exactly 8 bytes"),
    );
    let max_payload_len = executable_len - EMBEDDED_NATIVE_RUNNER_TRAILER_LEN;
    if payload_len > max_payload_len {
        return Err(miette::miette!(
            "embedded pearl payload length exceeds executable size"
        ));
    }
    let payload_start = max_payload_len - payload_len;
    file.seek(SeekFrom::Start(payload_start))
        .into_diagnostic()
        .wrap_err("failed to seek embedded pearl payload")?;
    let mut payload = vec![0u8; payload_len as usize];
    file.read_exact(&mut payload)
        .into_diagnostic()
        .wrap_err("failed to read embedded pearl payload")?;
    Ok(Some(payload))
}

fn evaluate_embedded_fanout(
    fanout: &EmbeddedFanoutPayload,
    root_input: &HashMap<String, Value>,
) -> Result<Value> {
    let root_value = Value::Object(
        root_input
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let mut applicable_actions = Vec::new();
    let mut verdicts = BTreeMap::new();
    let mut stages = Vec::new();
    for (index, gate) in fanout.gates.iter().enumerate() {
        let input_map = gate.input.as_ref().unwrap_or(&fanout.input);
        let features = resolve_embedded_fanout_input(input_map, &root_value)?;
        let result = serde_json::to_value(
            logicpearl_runtime::evaluate_gate_with_explanation(&gate.gate, &features)
                .into_diagnostic()
                .wrap_err("failed to evaluate compiled fan-out gate")?,
        )
        .into_diagnostic()?;
        let applies = result.get("bitmask").is_some_and(rule_mask_value_nonzero)
            || result
                .get("matched_rules")
                .and_then(Value::as_array)
                .is_some_and(|rules| !rules.is_empty());
        if applies {
            applicable_actions.push(gate.action.clone());
        }
        let id = gate
            .id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| format!("action_{index:03}"));
        let verdict = serde_json::json!({
            "id": id,
            "action": gate.action,
            "applies": applies,
            "artifact_id": result.get("artifact_id").and_then(Value::as_str).unwrap_or(&gate.gate.gate_id),
            "artifact_hash": result.get("artifact_hash").and_then(Value::as_str).unwrap_or_default(),
            "bitmask": result.get("bitmask").cloned().unwrap_or(Value::Null),
            "matched_rules": result.get("matched_rules").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
            "result": result,
        });
        verdicts.insert(gate.action.clone(), verdict.clone());
        stages.push(verdict);
    }
    Ok(serde_json::json!({
        "schema_version": logicpearl_pipeline::FANOUT_RESULT_SCHEMA_VERSION,
        "engine_version": logicpearl_runtime::LOGICPEARL_ENGINE_VERSION,
        "artifact_id": fanout.pipeline_id,
        "artifact_hash": fanout.artifact_hash,
        "decision_kind": "fanout",
        "pipeline_id": fanout.pipeline_id,
        "ok": true,
        "applicable_actions": applicable_actions,
        "verdicts": verdicts,
        "output": {
            "applicable_actions": applicable_actions,
            "verdicts": verdicts,
        },
        "stages": stages,
    }))
}

fn resolve_embedded_fanout_input(
    input_map: &HashMap<String, Value>,
    root_input: &Value,
) -> Result<HashMap<String, Value>> {
    if input_map.is_empty() {
        let object = root_input.as_object().ok_or_else(|| {
            miette::miette!("compiled fan-out runner expected object pipeline input")
        })?;
        return Ok(object
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect());
    }
    input_map
        .iter()
        .map(|(key, value)| Ok((key.clone(), resolve_embedded_value(value, root_input)?)))
        .collect()
}

fn resolve_embedded_value(value: &Value, root_input: &Value) -> Result<Value> {
    match value {
        Value::String(reference) if reference.starts_with("$.") => {
            lookup_embedded_json_path(root_input, reference)
        }
        other => Ok(other.clone()),
    }
}

fn lookup_embedded_json_path(scope: &Value, reference: &str) -> Result<Value> {
    let mut current = scope;
    for segment in reference.trim_start_matches("$.").split('.') {
        if segment.is_empty() {
            continue;
        }
        current = current
            .as_object()
            .and_then(|object| object.get(segment))
            .ok_or_else(|| miette::miette!("path not found: {reference}"))?;
    }
    Ok(current.clone())
}

fn rule_mask_value_nonzero(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_u64().unwrap_or(0) != 0,
        Value::String(text) => text != "0" && !text.is_empty(),
        Value::Array(items) => items.iter().any(rule_mask_value_nonzero),
        _ => false,
    }
}

fn should_use_embedded_native_runner(target_triple: Option<&str>) -> bool {
    match target_triple {
        None => true,
        Some(target) => current_host_target_triple()
            .map(|host| host == target)
            .unwrap_or(false),
    }
}

fn current_host_target_triple() -> Option<&'static str> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        return Some("x86_64-unknown-linux-gnu");
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        return Some("aarch64-unknown-linux-gnu");
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        return Some("x86_64-apple-darwin");
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        return Some("aarch64-apple-darwin");
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    {
        return Some("x86_64-pc-windows-msvc");
    }
    #[cfg(all(target_arch = "aarch64", target_os = "windows", target_env = "msvc"))]
    {
        return Some("aarch64-pc-windows-msvc");
    }
    #[allow(unreachable_code)]
    None
}

fn mark_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl permissions")?
            .permissions();
        permissions.set_mode(permissions.mode() | 0o755);
        fs::set_permissions(path, permissions)
            .into_diagnostic()
            .wrap_err("failed to mark compiled pearl executable")?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
