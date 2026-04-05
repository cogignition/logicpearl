use logicpearl_benchmark::sanitize_identifier;
use logicpearl_discovery::{BuildResult, OutputFiles};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedArtifactManifest {
    artifact_version: String,
    artifact_name: String,
    gate_id: String,
    files: NamedArtifactFiles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedArtifactFiles {
    pearl_ir: String,
    build_report: String,
    native_binary: Option<String>,
    wasm_module: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedArtifactInput {
    pub(crate) artifact_dir: PathBuf,
    pub(crate) pearl_ir: PathBuf,
}

pub(crate) fn resolve_artifact_input(path: &Path) -> Result<ResolvedArtifactInput> {
    if path.is_dir() {
        let manifest_path = path.join("artifact.json");
        if manifest_path.exists() {
            let manifest = load_named_artifact_manifest(&manifest_path)?;
            return Ok(ResolvedArtifactInput {
                artifact_dir: path.to_path_buf(),
                pearl_ir: resolve_manifest_path(&manifest_path, &manifest.files.pearl_ir),
            });
        }

        let pearl_ir = path.join("pearl.ir.json");
        if pearl_ir.exists() {
            return Ok(ResolvedArtifactInput {
                artifact_dir: path.to_path_buf(),
                pearl_ir,
            });
        }

        return Err(miette::miette!(
            "artifact directory {} is missing artifact.json and pearl.ir.json\n\nHint: Pass a LogicPearl build output directory or a direct pearl.ir.json path.",
            path.display()
        ));
    }

    if path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new("artifact.json"))
    {
        let manifest = load_named_artifact_manifest(path)?;
        return Ok(ResolvedArtifactInput {
            artifact_dir: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            pearl_ir: resolve_manifest_path(path, &manifest.files.pearl_ir),
        });
    }

    Ok(ResolvedArtifactInput {
        artifact_dir: path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        pearl_ir: path.to_path_buf(),
    })
}

pub(crate) fn native_artifact_output_path(
    artifact_dir: &Path,
    artifact_name: &str,
    target_triple: Option<&str>,
) -> PathBuf {
    artifact_dir.join(binary_file_name(
        &format!("{}.pearl", artifact_file_stem(artifact_name)),
        target_triple,
    ))
}

pub(crate) fn wasm_artifact_output_path(artifact_dir: &Path, artifact_name: &str) -> PathBuf {
    artifact_dir.join(format!("{}.pearl.wasm", artifact_file_stem(artifact_name)))
}

pub(crate) fn write_named_artifact_manifest(
    output_dir: &Path,
    artifact_name: &str,
    gate_id: &str,
    output_files: &OutputFiles,
) -> Result<()> {
    let manifest = NamedArtifactManifest {
        artifact_version: "1.0".to_string(),
        artifact_name: artifact_name.to_string(),
        gate_id: gate_id.to_string(),
        files: NamedArtifactFiles {
            pearl_ir: PathBuf::from(&output_files.pearl_ir)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("pearl.ir.json"))
                .to_string_lossy()
                .into_owned(),
            build_report: PathBuf::from(&output_files.build_report)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("build_report.json"))
                .to_string_lossy()
                .into_owned(),
            native_binary: output_files.native_binary.as_ref().and_then(|path| {
                PathBuf::from(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            }),
            wasm_module: output_files.wasm_module.as_ref().and_then(|path| {
                PathBuf::from(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            }),
        },
    };
    fs::write(
        output_dir.join("artifact.json"),
        serde_json::to_string_pretty(&manifest).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write artifact manifest")?;
    Ok(())
}

pub(crate) fn persist_build_report(result: &BuildResult) -> Result<()> {
    fs::write(
        &result.output_files.build_report,
        serde_json::to_string_pretty(result).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to update build report")?;
    Ok(())
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
    let workspace_root = workspace_root();
    let crate_name = format!("logicpearl_compiled_{}", sanitize_identifier(&pearl_name));
    let build_dir = workspace_root
        .join("target")
        .join("generated")
        .join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated compile directory")?;

    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nlogicpearl-ir = {{ path = \"{}\" }}\nlogicpearl-runtime = {{ path = \"{}\" }}\nserde_json = \"1\"\n",
        workspace_root.join("crates/logicpearl-ir").display(),
        workspace_root.join("crates/logicpearl-runtime").display(),
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated Cargo.toml")?;

    let escaped_pearl_path = pearl_ir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('\"', "\\\"");
    let main_rs = format!(
        "use logicpearl_ir::LogicPearlGateIr;\nuse logicpearl_runtime::{{evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\nuse std::fs;\nuse std::process::ExitCode;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn main() -> ExitCode {{\n    match run() {{\n        Ok(()) => ExitCode::SUCCESS,\n        Err(err) => {{\n            eprintln!(\"{{}}\", err);\n            ExitCode::FAILURE\n        }}\n    }}\n}}\n\nfn run() -> Result<(), Box<dyn std::error::Error>> {{\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() != 2 {{\n        return Err(\"usage: compiled-pearl <input.json>\".into());\n    }}\n    let gate = LogicPearlGateIr::from_json_str(PEARL_JSON)?;\n    let payload: Value = serde_json::from_str(&fs::read_to_string(&args[1])?)?;\n    let parsed = parse_input_payload(payload)?;\n    let mut outputs = Vec::with_capacity(parsed.len());\n    for input in parsed {{\n        outputs.push(evaluate_gate(&gate, &input)?);\n    }}\n    if outputs.len() == 1 {{\n        println!(\"{{}}\", outputs[0]);\n    }} else {{\n        println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n    }}\n    Ok(())\n}}\n"
    );
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
        .wrap_err("failed to invoke cargo for native pearl compilation")?;
    if !status.success() {
        return Err(miette::miette!(
            "native pearl compilation failed with status {status}\n\nHint: If this is a cross-compile target, install the Rust target and any required linker/toolchain first."
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

    Ok(output_path)
}

pub(crate) fn compile_wasm_module(
    pearl_ir: &Path,
    artifact_dir: &Path,
    gate_id: &str,
    name: Option<String>,
    output: Option<PathBuf>,
) -> Result<PathBuf> {
    let pearl_name = name.unwrap_or_else(|| gate_id.to_string());
    let output_path =
        output.unwrap_or_else(|| wasm_artifact_output_path(artifact_dir, &pearl_name));
    let workspace_root = workspace_root();
    let crate_name = format!(
        "logicpearl_compiled_{}_wasm",
        sanitize_identifier(&pearl_name)
    );
    let build_dir = workspace_root
        .join("target")
        .join("generated")
        .join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated wasm compile directory")?;

    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[workspace]\n\n[dependencies]\nlogicpearl-ir = {{ path = \"{}\" }}\nlogicpearl-runtime = {{ path = \"{}\" }}\nserde_json = \"1\"\n",
        workspace_root.join("crates/logicpearl-ir").display(),
        workspace_root.join("crates/logicpearl-runtime").display(),
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm Cargo.toml")?;

    let escaped_pearl_path = pearl_ir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('\"', "\\\"");
    let lib_rs = format!(
        "use logicpearl_ir::LogicPearlGateIr;\nuse logicpearl_runtime::{{evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn evaluate_first_bitmask(input: &str) -> Result<u64, String> {{\n    let gate = LogicPearlGateIr::from_json_str(PEARL_JSON).map_err(|err| err.to_string())?;\n    let payload: Value = serde_json::from_str(input).map_err(|err| err.to_string())?;\n    let parsed = parse_input_payload(payload).map_err(|err| err.to_string())?;\n    let first = parsed\n        .into_iter()\n        .next()\n        .ok_or_else(|| \"input JSON must contain at least one feature object\".to_string())?;\n    evaluate_gate(&gate, &first).map_err(|err| err.to_string())\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_alloc(len: usize) -> *mut u8 {{\n    let mut bytes = Vec::<u8>::with_capacity(len);\n    let ptr = bytes.as_mut_ptr();\n    std::mem::forget(bytes);\n    ptr\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_dealloc(ptr: *mut u8, capacity: usize) {{\n    if ptr.is_null() {{\n        return;\n    }}\n    unsafe {{\n        let _ = Vec::from_raw_parts(ptr, 0, capacity);\n    }}\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_first_bitmask(ptr: *const u8, len: usize) -> u64 {{\n    if ptr.is_null() {{\n        return u64::MAX;\n    }}\n    let slice = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    let Ok(input) = std::str::from_utf8(slice) else {{\n        return u64::MAX;\n    }};\n    evaluate_first_bitmask(input).unwrap_or(u64::MAX)\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_first_allow(ptr: *const u8, len: usize) -> u32 {{\n    match logicpearl_eval_first_bitmask(ptr, len) {{\n        u64::MAX => 2,\n        0 => 1,\n        _ => 0,\n    }}\n}}\n"
    );
    fs::write(src_dir.join("lib.rs"), lib_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm runner source")?;

    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--manifest-path")
        .arg(build_dir.join("Cargo.toml"))
        .status()
        .into_diagnostic()
        .wrap_err("failed to invoke cargo for wasm pearl compilation")?;
    if !status.success() {
        return Err(miette::miette!(
            "wasm pearl compilation failed with status {status}\n\nHint: Install the target with `rustup target add wasm32-unknown-unknown` and retry."
        ));
    }

    let built_module = build_dir
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(format!("{crate_name}.wasm"));
    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new(".")))
        .into_diagnostic()
        .wrap_err("failed to create output directory")?;
    fs::copy(&built_module, &output_path)
        .into_diagnostic()
        .wrap_err("failed to copy compiled pearl wasm module")?;
    Ok(output_path)
}

pub(crate) fn is_rust_target_installed(target: &str) -> bool {
    std::process::Command::new("rustup")
        .arg("target")
        .arg("list")
        .arg("--installed")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.lines().any(|line| line.trim() == target))
        .unwrap_or(false)
}

fn load_named_artifact_manifest(path: &Path) -> Result<NamedArtifactManifest> {
    serde_json::from_str(
        &fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read artifact manifest")?,
    )
    .into_diagnostic()
    .wrap_err("artifact manifest is not valid JSON")
}

fn resolve_manifest_path(manifest_path: &Path, raw_path: &str) -> PathBuf {
    let candidate = PathBuf::from(raw_path);
    if candidate.is_absolute() {
        candidate
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn artifact_file_stem(name: &str) -> String {
    let sanitized = sanitize_identifier(name);
    if sanitized.is_empty() {
        "pearl".to_string()
    } else {
        sanitized
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("logicpearl-cli crate should live under workspace/crates/logicpearl-cli")
}

fn binary_file_name(base: &str, target_triple: Option<&str>) -> String {
    if target_is_windows(target_triple) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn target_is_windows(target_triple: Option<&str>) -> bool {
    target_triple
        .map(|target| target.contains("windows"))
        .unwrap_or(cfg!(target_os = "windows"))
}
