// SPDX-License-Identifier: MIT
use super::pearl::{CompilablePearl, WasmRuleView};
use super::wasm_metadata::{
    build_string_codes, string_key, wasm_metadata_path_for_module, write_wasm_metadata_for_fanout,
    write_wasm_metadata_for_pearl, FanoutWasmGateMetadata,
};
use super::{
    cleanup_generated_build_dir, generated_build_root, unique_generated_crate_name,
    wasm_artifact_output_path, workspace_root,
};
use logicpearl_benchmark::sanitize_identifier;
use logicpearl_core::load_artifact_bundle;
#[cfg(test)]
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_ir::{
    derived_feature_evaluation_order, ComparisonExpression, ComparisonOperator,
    DerivedFeatureDefinition, DerivedFeatureOperator, Expression, FeatureDefinition, FeatureType,
    InputSchema,
};
use logicpearl_pipeline::FanoutPipelineDefinition;
use miette::{IntoDiagnostic, Result, WrapErr};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct WasmArtifactOutput {
    pub(crate) module_path: PathBuf,
    pub(crate) metadata_path: PathBuf,
}

#[derive(Debug, Clone, Copy, Default)]
struct UsedWasmOperators {
    eq: bool,
    gt: bool,
    gte: bool,
    lt: bool,
    lte: bool,
    ratio: bool,
}

pub(crate) fn compile_wasm_module(
    pearl_ir: &Path,
    artifact_dir: &Path,
    artifact_id: &str,
    name: Option<String>,
    output: Option<PathBuf>,
) -> Result<WasmArtifactOutput> {
    let pearl_name = name.unwrap_or_else(|| artifact_id.to_string());
    let output_path =
        output.unwrap_or_else(|| wasm_artifact_output_path(artifact_dir, &pearl_name));
    let metadata_path = wasm_metadata_path_for_module(&output_path);
    let workspace_root = workspace_root();
    let generated_root = generated_build_root(&workspace_root);
    let crate_name = unique_generated_crate_name(&format!(
        "logicpearl_compiled_{}_wasm",
        sanitize_identifier(&pearl_name)
    ));
    let pearl = CompilablePearl::from_path(pearl_ir)
        .wrap_err("failed to load pearl IR for wasm compilation")?;
    if let Some(rule) = pearl.wasm_rules().into_iter().find(|rule| rule.bit >= 64) {
        return Err(miette::miette!(
            "wasm compilation currently supports only rule bits 0-63; artifact `{}` includes rule `{}` at bit {}\n\nHint: Use the native compile target for wider artifacts, or keep wasm-targeted artifacts at 64 rules or fewer for now.",
            pearl.artifact_id(),
            rule.id,
            rule.bit
        ));
    }
    let build_dir = generated_root.join(&crate_name);
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

    let lib_rs = generate_wasm_runner_source_for_pearl(&pearl)
        .into_diagnostic()
        .wrap_err("failed to generate wasm runner source")?;
    fs::write(src_dir.join("lib.rs"), lib_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated wasm runner source")?;
    write_wasm_metadata_for_pearl(&metadata_path, &pearl)?;

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
        .wrap_err(
            "failed to invoke cargo for wasm pearl compilation; install Rust/Cargo and make sure `cargo` is on PATH",
        )?;
    if !status.success() {
        return Err(miette::miette!(
            "wasm pearl compilation failed with status {status}\n\nHint: `logicpearl compile --target wasm32-unknown-unknown` runs `cargo build --offline --release --target wasm32-unknown-unknown`. Install Rust/Cargo, make sure required crates are present in Cargo's local cache, then install the target with `rustup target add wasm32-unknown-unknown`."
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
    cleanup_generated_build_dir(&build_dir);
    Ok(WasmArtifactOutput {
        module_path: output_path,
        metadata_path,
    })
}

pub(crate) fn compile_wasm_fanout_module(
    pipeline_ir: &Path,
    artifact_dir: &Path,
    artifact_id: &str,
    name: Option<String>,
    output: Option<PathBuf>,
) -> Result<WasmArtifactOutput> {
    let pipeline_name = name.unwrap_or_else(|| artifact_id.to_string());
    let output_path =
        output.unwrap_or_else(|| wasm_artifact_output_path(artifact_dir, &pipeline_name));
    let metadata_path = wasm_metadata_path_for_module(&output_path);
    let pipeline = FanoutPipelineDefinition::from_path(pipeline_ir)
        .into_diagnostic()
        .wrap_err("failed to load fan-out pipeline for wasm compilation")?;
    pipeline
        .validate(artifact_dir)
        .into_diagnostic()
        .wrap_err("fan-out pipeline is not valid for wasm compilation")?;
    let gates = load_fanout_compile_gates(&pipeline, artifact_dir)?;
    for gate in &gates {
        if let Some(rule) = gate
            .pearl
            .wasm_rules()
            .into_iter()
            .find(|rule| rule.bit >= 64)
        {
            return Err(miette::miette!(
                "wasm compilation currently supports only rule bits 0-63; fan-out action `{}` artifact `{}` includes rule `{}` at bit {}\n\nHint: Use the native compile target for wider fan-out artifacts, or keep wasm-targeted gates at 64 rules or fewer for now.",
                gate.action,
                gate.pearl.artifact_id(),
                rule.id,
                rule.bit
            ));
        }
    }

    let workspace_root = workspace_root();
    let generated_root = generated_build_root(&workspace_root);
    let crate_name = unique_generated_crate_name(&format!(
        "logicpearl_compiled_{}_fanout_wasm",
        sanitize_identifier(&pipeline_name)
    ));
    let build_dir = generated_root.join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated fan-out wasm compile directory")?;
    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[workspace]\n\n[profile.release]\nopt-level = \"z\"\nlto = true\ncodegen-units = 1\npanic = \"abort\"\nstrip = \"symbols\"\n"
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated fan-out wasm Cargo.toml")?;

    let lib_rs = generate_wasm_runner_source_for_fanout(&gates)
        .into_diagnostic()
        .wrap_err("failed to generate fan-out wasm runner source")?;
    fs::write(src_dir.join("lib.rs"), lib_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated fan-out wasm runner source")?;
    let metadata_inputs = gates
        .iter()
        .map(|gate| FanoutWasmGateMetadata {
            action: &gate.action,
            id: &gate.id,
            gate: match &gate.pearl {
                CompilablePearl::Gate(gate) => gate,
                CompilablePearl::Action(_) => unreachable!("fan-out gates must be gates"),
            },
            entrypoint: gate.bitmask_entrypoint.clone(),
            status_entrypoint: gate.status_entrypoint.clone(),
            allow_entrypoint: gate.allow_entrypoint.clone(),
        })
        .collect::<Vec<_>>();
    write_wasm_metadata_for_fanout(
        &metadata_path,
        &pipeline.pipeline_id,
        logicpearl_runtime::artifact_hash(&pipeline),
        &metadata_inputs,
    )?;

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
        .wrap_err(
            "failed to invoke cargo for fan-out wasm compilation; install Rust/Cargo and make sure `cargo` is on PATH",
        )?;
    if !status.success() {
        return Err(miette::miette!(
            "fan-out wasm compilation failed with status {status}\n\nHint: `logicpearl compile --target wasm32-unknown-unknown` runs `cargo build --offline --release --target wasm32-unknown-unknown`. Install Rust/Cargo, make sure required crates are present in Cargo's local cache, then install the target with `rustup target add wasm32-unknown-unknown`."
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
        .wrap_err("failed to copy compiled fan-out wasm module")?;
    cleanup_generated_build_dir(&build_dir);
    Ok(WasmArtifactOutput {
        module_path: output_path,
        metadata_path,
    })
}

#[derive(Debug, Clone)]
struct FanoutCompileGate {
    action: String,
    id: String,
    pearl: CompilablePearl,
    bitmask_entrypoint: String,
    status_entrypoint: String,
    allow_entrypoint: String,
}

fn load_fanout_compile_gates(
    pipeline: &FanoutPipelineDefinition,
    artifact_dir: &Path,
) -> Result<Vec<FanoutCompileGate>> {
    let mut used_suffixes = BTreeMap::<String, usize>::new();
    pipeline
        .actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let id = action
                .id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("action_{index:03}"));
            let artifact_path = artifact_dir.join(&action.artifact);
            let bundle = load_artifact_bundle(&artifact_path).map_err(|err| {
                miette::miette!("failed to load fan-out action artifact {id}: {err}")
            })?;
            let pearl = CompilablePearl::from_path(&bundle.ir_path().into_diagnostic()?)
                .wrap_err_with(|| format!("failed to load fan-out action gate `{id}`"))?;
            if !matches!(pearl, CompilablePearl::Gate(_)) {
                return Err(miette::miette!(
                    "fan-out action `{id}` must reference a gate artifact"
                ));
            }
            let base_suffix = sanitize_identifier(&id);
            let base_suffix = if base_suffix.is_empty() {
                format!("action_{index:03}")
            } else {
                base_suffix
            };
            let count = used_suffixes.entry(base_suffix.clone()).or_insert(0);
            let suffix = if *count == 0 {
                base_suffix.clone()
            } else {
                format!("{base_suffix}_{count}")
            };
            *count += 1;
            Ok(FanoutCompileGate {
                action: action.action.clone(),
                id,
                pearl,
                bitmask_entrypoint: format!("logicpearl_eval_bitmask_slots_f64_{suffix}"),
                status_entrypoint: format!("logicpearl_eval_status_slots_f64_{suffix}"),
                allow_entrypoint: format!("logicpearl_eval_allow_slots_f64_{suffix}"),
            })
        })
        .collect()
}

#[cfg(test)]
pub(super) fn generate_wasm_runner_source(gate: &LogicPearlGateIr) -> String {
    generate_wasm_runner_source_for_pearl(&CompilablePearl::Gate(gate.clone()))
        .expect("wasm runner source should generate")
}

#[cfg(test)]
pub(super) fn generate_wasm_fanout_runner_source(gates: &[(&str, LogicPearlGateIr)]) -> String {
    let compile_gates = gates
        .iter()
        .enumerate()
        .map(|(index, (id, gate))| FanoutCompileGate {
            action: (*id).to_string(),
            id: (*id).to_string(),
            pearl: CompilablePearl::Gate(gate.clone()),
            bitmask_entrypoint: format!("logicpearl_eval_bitmask_slots_f64_action_{index}"),
            status_entrypoint: format!("logicpearl_eval_status_slots_f64_action_{index}"),
            allow_entrypoint: format!("logicpearl_eval_allow_slots_f64_action_{index}"),
        })
        .collect::<Vec<_>>();
    generate_wasm_runner_source_for_fanout(&compile_gates)
        .expect("fan-out wasm runner source should generate")
}

fn generate_wasm_runner_source_for_pearl(
    pearl: &CompilablePearl,
) -> logicpearl_core::Result<String> {
    let wasm_rules = pearl.wasm_rules();
    let mut used_ops = collect_used_comparison_operators(&wasm_rules);
    collect_used_derived_operators(pearl.input_schema(), &mut used_ops);
    let evaluator = generate_wasm_evaluator_source(
        pearl,
        "pearl",
        "logicpearl_eval_bitmask_slots_f64",
        "logicpearl_eval_status_slots_f64",
        "logicpearl_eval_allow_slots_f64",
    )?;

    Ok(format!(
        "const LOGICPEARL_STATUS_OK: u32 = 0;\nconst LOGICPEARL_STATUS_NULL_PTR: u32 = 1;\nconst LOGICPEARL_STATUS_INSUFFICIENT_LEN: u32 = 2;\n\n{helpers}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_alloc(len: usize) -> *mut u8 {{\n    let mut bytes = Vec::<u8>::with_capacity(len);\n    let ptr = bytes.as_mut_ptr();\n    std::mem::forget(bytes);\n    ptr\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_dealloc(ptr: *mut u8, capacity: usize) {{\n    if ptr.is_null() {{\n        return;\n    }}\n    unsafe {{\n        let _ = Vec::from_raw_parts(ptr, 0, capacity);\n    }}\n}}\n\n{evaluator}",
        helpers = wasm_helper_source(used_ops),
        evaluator = evaluator,
    ))
}

fn generate_wasm_runner_source_for_fanout(
    gates: &[FanoutCompileGate],
) -> logicpearl_core::Result<String> {
    let mut used_ops = UsedWasmOperators::default();
    let mut evaluators = String::new();
    for gate in gates {
        let wasm_rules = gate.pearl.wasm_rules();
        collect_rule_operators(&wasm_rules, &mut used_ops);
        collect_used_derived_operators(gate.pearl.input_schema(), &mut used_ops);
        evaluators.push_str(&generate_wasm_evaluator_source(
            &gate.pearl,
            &sanitize_identifier(&gate.id),
            &gate.bitmask_entrypoint,
            &gate.status_entrypoint,
            &gate.allow_entrypoint,
        )?);
        evaluators.push('\n');
    }

    Ok(format!(
        "const LOGICPEARL_STATUS_OK: u32 = 0;\nconst LOGICPEARL_STATUS_NULL_PTR: u32 = 1;\nconst LOGICPEARL_STATUS_INSUFFICIENT_LEN: u32 = 2;\n\n{helpers}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_alloc(len: usize) -> *mut u8 {{\n    let mut bytes = Vec::<u8>::with_capacity(len);\n    let ptr = bytes.as_mut_ptr();\n    std::mem::forget(bytes);\n    ptr\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_dealloc(ptr: *mut u8, capacity: usize) {{\n    if ptr.is_null() {{\n        return;\n    }}\n    unsafe {{\n        let _ = Vec::from_raw_parts(ptr, 0, capacity);\n    }}\n}}\n\n{evaluators}",
        helpers = wasm_helper_source(used_ops),
        evaluators = evaluators,
    ))
}

fn generate_wasm_evaluator_source(
    pearl: &CompilablePearl,
    suffix: &str,
    bitmask_entrypoint: &str,
    status_entrypoint: &str,
    allow_entrypoint: &str,
) -> logicpearl_core::Result<String> {
    let wasm_rules = pearl.wasm_rules();
    let input_schema = pearl.input_schema();
    let input_features = input_schema
        .features
        .iter()
        .filter(|feature| feature.derived.is_none())
        .collect::<Vec<_>>();
    let feature_indexes: HashMap<&str, usize> = input_features
        .iter()
        .enumerate()
        .map(|(index, feature)| (feature.id.as_str(), index))
        .collect();
    let feature_defs: HashMap<&str, &FeatureDefinition> = input_schema
        .features
        .iter()
        .map(|feature| (feature.id.as_str(), feature))
        .collect();
    let derived_identifiers: HashMap<&str, String> = input_schema
        .features
        .iter()
        .filter(|feature| feature.derived.is_some())
        .map(|feature| {
            (
                feature.id.as_str(),
                format!("derived_{}", sanitize_identifier(&feature.id)),
            )
        })
        .collect();
    let string_codes = build_string_codes(input_schema, &wasm_rules);
    let derived_features = derived_feature_evaluation_order(&input_schema.features)?;
    let derived_assignments = derived_features
        .iter()
        .map(|feature| {
            let derived = feature
                .derived
                .as_ref()
                .expect("derived feature evaluation order should contain only derived features");
            let variable = derived_identifiers[feature.id.as_str()].clone();
            let expression =
                emit_wasm_derived_expression(derived, &feature_indexes, &derived_identifiers);
            format!("    let {variable} = {expression};\n")
        })
        .collect::<String>();

    let mut rule_source = String::new();
    for rule in &wasm_rules {
        let expression = emit_wasm_expression(
            rule.expression,
            &feature_defs,
            &feature_indexes,
            &derived_identifiers,
            &string_codes,
        );
        let condition = wasm_if_condition(&expression);
        rule_source.push_str(&format!(
            "    if {condition} {{ bitmask |= 1u64 << {}; }}\n",
            rule.bit
        ));
    }
    let suffix = sanitize_identifier(suffix);
    let feature_count_const = format!("FEATURE_COUNT_{}", suffix.to_ascii_uppercase());
    let evaluate_fn = format!("evaluate_{suffix}");
    let validate_fn = format!("validate_slots_{suffix}");
    Ok(format!(
        "const {feature_count_const}: usize = {feature_count};\n\nfn {evaluate_fn}(values: &[f64]) -> u64 {{\n    let mut bitmask = 0u64;\n{derived_assignments}{rules}    bitmask\n}}\n\n#[inline]\nfn {validate_fn}(ptr: *const f64, len: usize) -> u32 {{\n    if ptr.is_null() {{\n        return LOGICPEARL_STATUS_NULL_PTR;\n    }}\n    if len < {feature_count_const} {{\n        return LOGICPEARL_STATUS_INSUFFICIENT_LEN;\n    }}\n    LOGICPEARL_STATUS_OK\n}}\n\n#[no_mangle]\npub extern \"C\" fn {status_entrypoint}(ptr: *const f64, len: usize) -> u32 {{\n    {validate_fn}(ptr, len)\n}}\n\n#[no_mangle]\npub extern \"C\" fn {bitmask_entrypoint}(ptr: *const f64, len: usize) -> u64 {{\n    if {validate_fn}(ptr, len) != LOGICPEARL_STATUS_OK {{\n        return 0;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    {evaluate_fn}(values)\n}}\n\n#[no_mangle]\npub extern \"C\" fn {allow_entrypoint}(ptr: *const f64, len: usize) -> u32 {{\n    if {validate_fn}(ptr, len) != LOGICPEARL_STATUS_OK {{\n        return 2;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    if {evaluate_fn}(values) == 0 {{ 1 }} else {{ 0 }}\n}}\n",
        feature_count = input_features.len(),
        derived_assignments = derived_assignments,
        rules = rule_source,
    ))
}

fn wasm_helper_source(used_ops: UsedWasmOperators) -> String {
    let mut helpers =
        String::from("#[inline]\nfn slot(values: &[f64], index: usize) -> f64 { values[index] }\n");
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
    if used_ops.ratio {
        helpers.push_str(
            "\n#[inline]\nfn ratio_num(left: f64, right: f64) -> f64 {\n    if left.is_nan() || right.is_nan() || right.abs() < f64::EPSILON {\n        0.0\n    } else {\n        let value = left / right;\n        if value.is_finite() { value } else { 0.0 }\n    }\n}\n",
        );
    }
    helpers
}

fn wasm_if_condition(expression: &str) -> &str {
    expression
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(expression)
}

fn collect_used_comparison_operators(rules: &[WasmRuleView<'_>]) -> UsedWasmOperators {
    let mut ops = UsedWasmOperators::default();
    collect_rule_operators(rules, &mut ops);
    ops
}

fn collect_rule_operators(rules: &[WasmRuleView<'_>], ops: &mut UsedWasmOperators) {
    for rule in rules {
        collect_expression_operators(rule.expression, ops);
    }
}

fn collect_expression_operators(expression: &Expression, ops: &mut UsedWasmOperators) {
    match expression {
        Expression::Comparison(comparison) => match comparison.op {
            ComparisonOperator::Eq
            | ComparisonOperator::Ne
            | ComparisonOperator::In
            | ComparisonOperator::NotIn => {
                ops.eq = true;
            }
            ComparisonOperator::Gt => ops.gt = true,
            ComparisonOperator::Gte => ops.gte = true,
            ComparisonOperator::Lt => ops.lt = true,
            ComparisonOperator::Lte => ops.lte = true,
        },
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

fn collect_used_derived_operators(input_schema: &InputSchema, ops: &mut UsedWasmOperators) {
    for feature in &input_schema.features {
        match feature.derived.as_ref().map(|derived| &derived.op) {
            Some(DerivedFeatureOperator::Ratio) => ops.ratio = true,
            Some(DerivedFeatureOperator::Difference) | None => {}
        }
    }
}

fn emit_wasm_expression(
    expression: &Expression,
    feature_defs: &HashMap<&str, &FeatureDefinition>,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    match expression {
        Expression::Comparison(comparison) => emit_wasm_comparison(
            comparison,
            feature_defs,
            feature_indexes,
            derived_identifiers,
            string_codes,
        ),
        Expression::All { all } => format!(
            "({})",
            all.iter()
                .map(|child| emit_wasm_expression(
                    child,
                    feature_defs,
                    feature_indexes,
                    derived_identifiers,
                    string_codes
                ))
                .collect::<Vec<_>>()
                .join(" && ")
        ),
        Expression::Any { any } => format!(
            "({})",
            any.iter()
                .map(|child| emit_wasm_expression(
                    child,
                    feature_defs,
                    feature_indexes,
                    derived_identifiers,
                    string_codes
                ))
                .collect::<Vec<_>>()
                .join(" || ")
        ),
        Expression::Not { expr } => format!(
            "(!{})",
            emit_wasm_expression(
                expr,
                feature_defs,
                feature_indexes,
                derived_identifiers,
                string_codes,
            )
        ),
    }
}

fn emit_wasm_comparison(
    comparison: &ComparisonExpression,
    feature_defs: &HashMap<&str, &FeatureDefinition>,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
    string_codes: &BTreeMap<String, u32>,
) -> String {
    let left = emit_wasm_feature_source(&comparison.feature, feature_indexes, derived_identifiers);
    let feature_type = &feature_defs[comparison.feature.as_str()].feature_type;

    if let Some(feature_ref) = comparison.value.feature_ref() {
        let right = emit_wasm_feature_source(feature_ref, feature_indexes, derived_identifiers);
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

fn emit_wasm_derived_expression(
    derived: &DerivedFeatureDefinition,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
) -> String {
    let left =
        emit_wasm_feature_source(&derived.left_feature, feature_indexes, derived_identifiers);
    let right =
        emit_wasm_feature_source(&derived.right_feature, feature_indexes, derived_identifiers);
    match derived.op {
        DerivedFeatureOperator::Difference => format!("({left} - {right})"),
        DerivedFeatureOperator::Ratio => format!("ratio_num({left}, {right})"),
    }
}

fn emit_wasm_feature_source(
    feature_id: &str,
    feature_indexes: &HashMap<&str, usize>,
    derived_identifiers: &HashMap<&str, String>,
) -> String {
    if let Some(index) = feature_indexes.get(feature_id) {
        return format!("slot(values, {index})");
    }
    derived_identifiers
        .get(feature_id)
        .cloned()
        .expect("derived feature should have generated identifier")
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
                .expect("string literal should have been assigned a wasm metadata code");
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
