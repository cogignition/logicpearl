// SPDX-License-Identifier: MIT
use super::pearl::{CompilablePearl, WasmRuleView};
use super::wasm_metadata::{
    build_string_codes, string_key, wasm_metadata_path_for_module, write_wasm_metadata_for_pearl,
};
use super::{
    cleanup_generated_build_dir, generated_build_root, unique_generated_crate_name,
    wasm_artifact_output_path, workspace_root,
};
use logicpearl_benchmark::sanitize_identifier;
#[cfg(test)]
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_ir::{
    derived_feature_evaluation_order, ComparisonExpression, ComparisonOperator,
    DerivedFeatureDefinition, DerivedFeatureOperator, Expression, FeatureDefinition, FeatureType,
    InputSchema,
};
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

#[cfg(test)]
pub(super) fn generate_wasm_runner_source(gate: &LogicPearlGateIr) -> String {
    generate_wasm_runner_source_for_pearl(&CompilablePearl::Gate(gate.clone()))
        .expect("wasm runner source should generate")
}

fn generate_wasm_runner_source_for_pearl(
    pearl: &CompilablePearl,
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
    let mut used_ops = collect_used_comparison_operators(&wasm_rules);
    collect_used_derived_operators(input_schema, &mut used_ops);
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

    Ok(format!(
        "const FEATURE_COUNT: usize = {};\nconst LOGICPEARL_STATUS_OK: u32 = 0;\nconst LOGICPEARL_STATUS_NULL_PTR: u32 = 1;\nconst LOGICPEARL_STATUS_INSUFFICIENT_LEN: u32 = 2;\n\n{helpers}\n\nfn evaluate(values: &[f64]) -> u64 {{\n    let mut bitmask = 0u64;\n{derived_assignments}{rules}    bitmask\n}}\n\n#[inline]\nfn validate_slots(ptr: *const f64, len: usize) -> u32 {{\n    if ptr.is_null() {{\n        return LOGICPEARL_STATUS_NULL_PTR;\n    }}\n    if len < FEATURE_COUNT {{\n        return LOGICPEARL_STATUS_INSUFFICIENT_LEN;\n    }}\n    LOGICPEARL_STATUS_OK\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_alloc(len: usize) -> *mut u8 {{\n    let mut bytes = Vec::<u8>::with_capacity(len);\n    let ptr = bytes.as_mut_ptr();\n    std::mem::forget(bytes);\n    ptr\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_dealloc(ptr: *mut u8, capacity: usize) {{\n    if ptr.is_null() {{\n        return;\n    }}\n    unsafe {{\n        let _ = Vec::from_raw_parts(ptr, 0, capacity);\n    }}\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_status_slots_f64(ptr: *const f64, len: usize) -> u32 {{\n    validate_slots(ptr, len)\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_bitmask_slots_f64(ptr: *const f64, len: usize) -> u64 {{\n    if validate_slots(ptr, len) != LOGICPEARL_STATUS_OK {{\n        return 0;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    evaluate(values)\n}}\n\n#[no_mangle]\npub extern \"C\" fn logicpearl_eval_allow_slots_f64(ptr: *const f64, len: usize) -> u32 {{\n    if validate_slots(ptr, len) != LOGICPEARL_STATUS_OK {{\n        return 2;\n    }}\n    let values = unsafe {{ std::slice::from_raw_parts(ptr, len) }};\n    if evaluate(values) == 0 {{ 1 }} else {{ 0 }}\n}}\n",
        input_features.len(),
        helpers = helpers,
        derived_assignments = derived_assignments,
        rules = rule_source,
    ))
}

fn wasm_if_condition(expression: &str) -> &str {
    expression
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(expression)
}

fn collect_used_comparison_operators(rules: &[WasmRuleView<'_>]) -> UsedWasmOperators {
    let mut ops = UsedWasmOperators::default();
    for rule in rules {
        collect_expression_operators(rule.expression, &mut ops);
    }
    ops
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
