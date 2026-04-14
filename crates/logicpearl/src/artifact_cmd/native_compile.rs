// SPDX-License-Identifier: MIT
use super::{
    binary_file_name, cleanup_generated_build_dir, dependency_spec, generated_build_root,
    native_artifact_output_path, unique_generated_crate_name, workspace_root, CompilablePearl,
};
use logicpearl_benchmark::sanitize_identifier;
use miette::{IntoDiagnostic, Result, WrapErr};
use serde_json::Value;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const EMBEDDED_NATIVE_RUNNER_MAGIC: &[u8; 16] = b"LPEARL_RUNNER_V1";
const EMBEDDED_NATIVE_RUNNER_TRAILER_LEN: u64 = 24;

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

fn compile_embedded_native_runner(pearl_ir: &Path, output_path: &Path) -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current LogicPearl executable for native compilation")?;
    let pearl_payload = fs::read(pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to read pearl IR for native runner payload")?;

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

fn generated_native_runner_source(escaped_pearl_path: &str) -> String {
    format!(
        "use logicpearl_ir::{{LogicPearlActionIr, LogicPearlGateIr}};\nuse logicpearl_runtime::{{evaluate_action_policy, evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\nuse std::fs;\nuse std::io::Read;\nuse std::process::ExitCode;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn main() -> ExitCode {{\n    match run() {{\n        Ok(()) => ExitCode::SUCCESS,\n        Err(err) => {{\n            eprintln!(\"{{}}\", err);\n            ExitCode::FAILURE\n        }}\n    }}\n}}\n\nfn run() -> Result<(), Box<dyn std::error::Error>> {{\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() != 2 {{\n        return Err(\"usage: compiled-pearl <input.json>\".into());\n    }}\n    let input = if args[1] == \"-\" {{\n        let mut buffer = String::new();\n        std::io::stdin().read_to_string(&mut buffer)?;\n        buffer\n    }} else {{\n        fs::read_to_string(&args[1])?\n    }};\n    let payload: Value = serde_json::from_str(&input)?;\n    let parsed = parse_input_payload(payload)?;\n    let pearl_value: Value = serde_json::from_str(PEARL_JSON)?;\n    if pearl_value.get(\"action_policy_id\").is_some() {{\n        let policy = LogicPearlActionIr::from_json_str(PEARL_JSON)?;\n        let mut outputs = Vec::with_capacity(parsed.len());\n        for input in parsed {{\n            outputs.push(evaluate_action_policy(&policy, &input)?);\n        }}\n        if outputs.len() == 1 {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs[0])?);\n        }} else {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n        }}\n    }} else {{\n        let gate = LogicPearlGateIr::from_json_str(PEARL_JSON)?;\n        let mut outputs = Vec::with_capacity(parsed.len());\n        for input in parsed {{\n            outputs.push(evaluate_gate(&gate, &input)?);\n        }}\n        if outputs.len() == 1 {{\n            println!(\"{{}}\", outputs[0]);\n        }} else {{\n            println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n        }}\n    }}\n    Ok(())\n}}\n"
    )
}

pub(crate) fn run_embedded_native_runner_if_present() -> Result<bool> {
    let Some(payload) = read_embedded_native_runner_payload()? else {
        return Ok(false);
    };
    let pearl_json = std::str::from_utf8(&payload)
        .into_diagnostic()
        .wrap_err("embedded pearl payload is not valid UTF-8")?;
    let pearl = CompilablePearl::from_json_str(pearl_json)
        .wrap_err("embedded pearl payload is not valid LogicPearl IR")?;
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
    let payload: Value = serde_json::from_str(&input)
        .into_diagnostic()
        .wrap_err("compiled pearl input is not valid JSON")?;
    let parsed = logicpearl_runtime::parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("compiled pearl input does not match the expected payload shape")?;
    match pearl {
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
    }
    Ok(true)
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
