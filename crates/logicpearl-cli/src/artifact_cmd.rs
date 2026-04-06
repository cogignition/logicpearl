use logicpearl_benchmark::sanitize_identifier;
use logicpearl_discovery::{BuildResult, OutputFiles};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, Expression, FeatureDefinition, FeatureType,
    LogicPearlGateIr,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
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
    wasm_sidecar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmArtifactSidecar {
    artifact_version: String,
    gate_id: String,
    entrypoint: String,
    allow_entrypoint: String,
    feature_count: usize,
    missing_value: String,
    features: Vec<WasmFeatureDescriptor>,
    string_codes: BTreeMap<String, u32>,
    rules: Vec<WasmRuleMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmFeatureDescriptor {
    id: String,
    index: usize,
    #[serde(rename = "type")]
    feature_type: FeatureType,
    encoding: WasmFeatureEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WasmFeatureEncoding {
    Numeric,
    Boolean,
    StringCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmRuleMetadata {
    id: String,
    bit: u32,
    label: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    counterfactual_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct WasmArtifactOutput {
    pub(crate) module_path: PathBuf,
    pub(crate) sidecar_path: PathBuf,
}

#[derive(Debug, Clone, Copy, Default)]
struct UsedWasmOperators {
    eq: bool,
    gt: bool,
    gte: bool,
    lt: bool,
    lte: bool,
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

pub(crate) fn wasm_sidecar_output_path(artifact_dir: &Path, artifact_name: &str) -> PathBuf {
    artifact_dir.join(format!("{}.pearl.wasm.meta.json", artifact_file_stem(artifact_name)))
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
            wasm_sidecar: output_files.wasm_sidecar.as_ref().and_then(|path| {
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
) -> Result<WasmArtifactOutput> {
    let pearl_name = name.unwrap_or_else(|| gate_id.to_string());
    let output_path = output.unwrap_or_else(|| wasm_artifact_output_path(artifact_dir, &pearl_name));
    let sidecar_path = wasm_sidecar_output_path(artifact_dir, &pearl_name);
    let workspace_root = workspace_root();
    let crate_name = format!(
        "logicpearl_compiled_{}_wasm",
        sanitize_identifier(&pearl_name)
    );
    let gate = LogicPearlGateIr::from_path(pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load pearl IR for wasm compilation")?;
    let build_dir = workspace_root
        .join("target")
        .join("generated")
        .join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated wasm compile directory")?;

    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[workspace]\n\n[profile.release]\nopt-level = \"z\"\nlto = true\ncodegen-units = 1\npanic = \"abort\"\nstrip = \"symbols\"\n"
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm Cargo.toml")?;

    let lib_rs = generate_wasm_runner_source(&gate);
    fs::write(src_dir.join("lib.rs"), lib_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm runner source")?;
    write_wasm_sidecar(&sidecar_path, &gate)?;

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
    Ok(WasmArtifactOutput {
        module_path: output_path,
        sidecar_path,
    })
}

fn write_wasm_sidecar(path: &Path, gate: &LogicPearlGateIr) -> Result<()> {
    let string_codes = build_string_codes(gate);
    let sidecar = WasmArtifactSidecar {
        artifact_version: "1.0".to_string(),
        gate_id: gate.gate_id.clone(),
        entrypoint: "logicpearl_eval_bitmask_slots_f64".to_string(),
        allow_entrypoint: "logicpearl_eval_allow_slots_f64".to_string(),
        feature_count: gate.input_schema.features.len(),
        missing_value: "NaN".to_string(),
        features: gate
            .input_schema
            .features
            .iter()
            .enumerate()
            .map(|(index, feature)| WasmFeatureDescriptor {
                id: feature.id.clone(),
                index,
                feature_type: feature.feature_type.clone(),
                encoding: match feature.feature_type {
                    FeatureType::Bool => WasmFeatureEncoding::Boolean,
                    FeatureType::Int | FeatureType::Float => WasmFeatureEncoding::Numeric,
                    FeatureType::String | FeatureType::Enum => WasmFeatureEncoding::StringCode,
                },
            })
            .collect(),
        string_codes,
        rules: gate
            .rules
            .iter()
            .map(|rule| WasmRuleMetadata {
                id: rule.id.clone(),
                bit: rule.bit,
                label: rule.label.clone(),
                message: rule.message.clone(),
                severity: rule.severity.clone(),
                counterfactual_hint: rule.counterfactual_hint.clone(),
            })
            .collect(),
    };
    fs::write(
        path,
        serde_json::to_string_pretty(&sidecar).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write wasm sidecar metadata")?;
    Ok(())
}

fn generate_wasm_runner_source(gate: &LogicPearlGateIr) -> String {
    let feature_indexes: HashMap<&str, usize> = gate
        .input_schema
        .features
        .iter()
        .enumerate()
        .map(|(index, feature)| (feature.id.as_str(), index))
        .collect();
    let feature_defs: HashMap<&str, &FeatureDefinition> = gate
        .input_schema
        .features
        .iter()
        .map(|feature| (feature.id.as_str(), feature))
        .collect();
    let string_codes = build_string_codes(gate);
    let used_ops = collect_used_comparison_operators(gate);

    let mut rules = String::new();
    for rule in &gate.rules {
        let expression = emit_wasm_expression(&rule.deny_when, &feature_defs, &feature_indexes, &string_codes);
        rules.push_str(&format!(
            "    if {expression} {{ bitmask |= 1u64 << {}; }}\n",
            rule.bit
        ));
    }
    let mut helpers = String::from("#[inline]\nfn slot(values: &[f64], index: usize) -> f64 { values[index] }\n");
    if used_ops.eq {
        helpers.push_str(
            "\n#[inline]\nfn eq_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && (left - right).abs() < f64::EPSILON }\n",
        );
    }
    if used_ops.gt {
        helpers.push_str(
            "\n#[inline]\nfn gt_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left > right }\n",
        );
    }
    if used_ops.gte {
        helpers.push_str(
            "\n#[inline]\nfn gte_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left >= right }\n",
        );
    }
    if used_ops.lt {
        helpers.push_str(
            "\n#[inline]\nfn lt_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left < right }\n",
        );
    }
    if used_ops.lte {
        helpers.push_str(
            "\n#[inline]\nfn lte_num(left: f64, right: f64) -> bool { !left.is_nan() && !right.is_nan() && left <= right }\n",
        );
    }

    format!(
        "const FEATURE_COUNT: usize = {};\n\n{helpers}\n\nfn evaluate(values: &[f64]) -> u64 {{\n    let mut bitmask = 0u64;\n{rules}    bitmask\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_alloc(len: usize) -> *mut u8 {{\n    let mut bytes = Vec::<u8>::with_capacity(len);\n    let ptr = bytes.as_mut_ptr();\n    std::mem::forget(bytes);\n    ptr\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_dealloc(ptr: *mut u8, capacity: usize) {{\n    if ptr.is_null() {{\n        return;\n    }}\n    unsafe {{\n        let _ = Vec::from_raw_parts(ptr, 0, capacity);\n    }}\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_bitmask_slots_f64(ptr: *const f64, len: usize) -> u64 {{\n    if ptr.is_null() || len < FEATURE_COUNT {{\n        return u64::MAX;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    evaluate(values)\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_allow_slots_f64(ptr: *const f64, len: usize) -> u32 {{\n    match logicpearl_eval_bitmask_slots_f64(ptr, len) {{\n        u64::MAX => 2,\n        0 => 1,\n        _ => 0,\n    }}\n}}\n",
        gate.input_schema.features.len(),
        helpers = helpers,
    )
}

fn collect_used_comparison_operators(gate: &LogicPearlGateIr) -> UsedWasmOperators {
    let mut ops = UsedWasmOperators::default();
    for rule in &gate.rules {
        collect_expression_operators(&rule.deny_when, &mut ops);
    }
    ops
}

fn collect_expression_operators(
    expression: &Expression,
    ops: &mut UsedWasmOperators,
) {
    match expression {
        Expression::Comparison(comparison) => {
            match comparison.op {
                ComparisonOperator::Eq | ComparisonOperator::Ne | ComparisonOperator::In | ComparisonOperator::NotIn => {
                    ops.eq = true;
                }
                ComparisonOperator::Gt => ops.gt = true,
                ComparisonOperator::Gte => ops.gte = true,
                ComparisonOperator::Lt => ops.lt = true,
                ComparisonOperator::Lte => ops.lte = true,
            }
        }
        Expression::All { all } => {
            for child in all {
                collect_expression_operators(child, ops);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_expression_operators(child, ops);
            }
        }
        Expression::Not { expr } => collect_expression_operators(expr, ops),
    }
}

fn emit_wasm_expression(
    expression: &Expression,
    feature_defs: &HashMap<&str, &FeatureDefinition>,
    feature_indexes: &HashMap<&str, usize>,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    match expression {
        Expression::Comparison(comparison) => {
            emit_wasm_comparison(comparison, feature_defs, feature_indexes, string_codes)
        }
        Expression::All { all } => format!(
            "({})",
            all.iter()
                .map(|child| emit_wasm_expression(child, feature_defs, feature_indexes, string_codes))
                .collect::<Vec<_>>()
                .join(" && ")
        ),
        Expression::Any { any } => format!(
            "({})",
            any.iter()
                .map(|child| emit_wasm_expression(child, feature_defs, feature_indexes, string_codes))
                .collect::<Vec<_>>()
                .join(" || ")
        ),
        Expression::Not { expr } => format!(
            "(!{})",
            emit_wasm_expression(expr, feature_defs, feature_indexes, string_codes)
        ),
    }
}

fn emit_wasm_comparison(
    comparison: &ComparisonExpression,
    feature_defs: &HashMap<&str, &FeatureDefinition>,
    feature_indexes: &HashMap<&str, usize>,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    let left_index = feature_indexes[comparison.feature.as_str()];
    let left = format!("slot(values, {left_index})");
    let feature_type = &feature_defs[comparison.feature.as_str()].feature_type;

    if let Some(feature_ref) = comparison.value.feature_ref() {
        let right_index = feature_indexes[feature_ref];
        let right = format!("slot(values, {right_index})");
        return emit_operator_expr(comparison.op.clone(), &left, &right);
    }

    let literal = comparison
        .value
        .literal()
        .expect("literal comparison must provide a literal value");
    match comparison.op {
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let values = literal
                .as_array()
                .expect("in/not_in literal must be an array")
                .iter()
                .map(|item| emit_literal_value(feature_type, item, string_codes))
                .map(|item| format!("eq_num({left}, {item})"))
                .collect::<Vec<_>>()
                .join(" || ");
            if matches!(comparison.op, ComparisonOperator::NotIn) {
                format!("(!({values}))")
            } else {
                format!("({values})")
            }
        }
        _ => {
            let right = emit_literal_value(feature_type, literal, string_codes);
            emit_operator_expr(comparison.op.clone(), &left, &right)
        }
    }
}

fn emit_operator_expr(op: ComparisonOperator, left: &str, right: &str) -> String {
    match op {
        ComparisonOperator::Eq => format!("eq_num({left}, {right})"),
        ComparisonOperator::Ne => format!("(!eq_num({left}, {right}))"),
        ComparisonOperator::Gt => format!("gt_num({left}, {right})"),
        ComparisonOperator::Gte => format!("gte_num({left}, {right})"),
        ComparisonOperator::Lt => format!("lt_num({left}, {right})"),
        ComparisonOperator::Lte => format!("lte_num({left}, {right})"),
        ComparisonOperator::In | ComparisonOperator::NotIn => unreachable!("handled earlier"),
    }
}

fn emit_literal_value(
    feature_type: &FeatureType,
    literal: &Value,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    match feature_type {
        FeatureType::Bool => {
            if literal.as_bool().unwrap_or(false) {
                "1.0".to_string()
            } else {
                "0.0".to_string()
            }
        }
        FeatureType::Int | FeatureType::Float => rust_f64_literal(
            literal
                .as_f64()
                .expect("numeric literal must be representable as f64"),
        ),
        FeatureType::String | FeatureType::Enum => {
            let key = string_key(literal);
            let code = string_codes
                .get(&key)
                .expect("string literal should have been assigned a sidecar code");
            rust_f64_literal(*code as f64)
        }
    }
}

fn rust_f64_literal(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        format!("{value:?}")
    }
}

fn build_string_codes(gate: &LogicPearlGateIr) -> BTreeMap<String, u32> {
    let mut values = BTreeMap::new();
    for feature in &gate.input_schema.features {
        if matches!(feature.feature_type, FeatureType::String | FeatureType::Enum) {
            if let Some(feature_values) = &feature.values {
                for value in feature_values {
                    let key = string_key(value);
                    let next = values.len() as u32;
                    values.entry(key).or_insert(next);
                }
            }
        }
    }
    for rule in &gate.rules {
        collect_expression_strings(&rule.deny_when, &mut values);
    }
    values
}

fn collect_expression_strings(expression: &Expression, values: &mut BTreeMap<String, u32>) {
    match expression {
        Expression::Comparison(comparison) => {
            if let Some(literal) = comparison.value.literal() {
                collect_literal_strings(literal, values);
            }
        }
        Expression::All { all } => {
            for child in all {
                collect_expression_strings(child, values);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_expression_strings(child, values);
            }
        }
        Expression::Not { expr } => collect_expression_strings(expr, values),
    }
}

fn collect_literal_strings(literal: &Value, values: &mut BTreeMap<String, u32>) {
    match literal {
        Value::String(_) => {
            let key = string_key(literal);
            let next = values.len() as u32;
            values.entry(key).or_insert(next);
        }
        Value::Array(items) => {
            for item in items {
                collect_literal_strings(item, values);
            }
        }
        _ => {}
    }
}

fn string_key(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
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
