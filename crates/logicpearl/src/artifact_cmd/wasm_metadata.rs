// SPDX-License-Identifier: MIT
use super::pearl::{CompilablePearl, WasmRuleView};
#[cfg(test)]
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_ir::{
    derived_feature_evaluation_order, DerivedFeatureOperator, Expression, FeatureType, InputSchema,
};
use logicpearl_runtime::{explain_rule_features, RuleFeatureExplanation};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmArtifactMetadata {
    artifact_version: String,
    engine_version: String,
    artifact_hash: String,
    decision_kind: String,
    gate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_action: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    actions: Vec<String>,
    entrypoint: String,
    status_entrypoint: String,
    allow_entrypoint: String,
    feature_count: usize,
    missing_value: String,
    features: Vec<WasmFeatureDescriptor>,
    #[serde(default)]
    derived_features: Vec<WasmDerivedFeatureDescriptor>,
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
struct WasmDerivedFeatureDescriptor {
    id: String,
    op: DerivedFeatureOperator,
    left_feature: String,
    right_feature: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u32>,
    label: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    counterfactual_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    features: Vec<RuleFeatureExplanation>,
}

pub(super) fn wasm_metadata_path_for_module(module_path: &Path) -> PathBuf {
    let file_name = module_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pearl.wasm");
    let metadata_name = file_name
        .strip_suffix(".wasm")
        .map(|stem| format!("{stem}.wasm.meta.json"))
        .unwrap_or_else(|| format!("{file_name}.meta.json"));
    module_path.with_file_name(metadata_name)
}

#[cfg(test)]
pub(super) fn write_wasm_metadata(path: &Path, gate: &LogicPearlGateIr) -> Result<()> {
    write_wasm_metadata_for_pearl(path, &CompilablePearl::Gate(gate.clone()))
}

pub(super) fn write_wasm_metadata_for_pearl(path: &Path, pearl: &CompilablePearl) -> Result<()> {
    let wasm_rules = pearl.wasm_rules();
    let input_schema = pearl.input_schema();
    let derived_features = derived_feature_evaluation_order(&input_schema.features)
        .into_diagnostic()
        .wrap_err("failed to order derived features for wasm metadata")?;
    let string_codes = build_string_codes(input_schema, &wasm_rules);
    let input_features = pearl
        .input_schema()
        .features
        .iter()
        .filter(|feature| feature.derived.is_none())
        .collect::<Vec<_>>();
    let metadata = WasmArtifactMetadata {
        artifact_version: "1.0".to_string(),
        engine_version: logicpearl_runtime::LOGICPEARL_ENGINE_VERSION.to_string(),
        artifact_hash: match pearl {
            CompilablePearl::Gate(gate) => logicpearl_runtime::artifact_hash(gate),
            CompilablePearl::Action(policy) => logicpearl_runtime::artifact_hash(policy),
        },
        decision_kind: pearl.decision_kind().to_string(),
        gate_id: pearl.artifact_id().to_string(),
        action_policy_id: matches!(pearl, CompilablePearl::Action(_))
            .then(|| pearl.artifact_id().to_string()),
        default_action: pearl.default_action().map(ToOwned::to_owned),
        actions: pearl.actions().to_vec(),
        entrypoint: "logicpearl_eval_bitmask_slots_f64".to_string(),
        status_entrypoint: "logicpearl_eval_status_slots_f64".to_string(),
        allow_entrypoint: "logicpearl_eval_allow_slots_f64".to_string(),
        feature_count: input_features.len(),
        missing_value: "NaN".to_string(),
        features: input_features
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
        derived_features: derived_features
            .iter()
            .map(|feature| {
                let derived = feature.derived.as_ref().expect(
                    "derived feature evaluation order should contain only derived features",
                );
                WasmDerivedFeatureDescriptor {
                    id: feature.id.clone(),
                    op: derived.op.clone(),
                    left_feature: derived.left_feature.clone(),
                    right_feature: derived.right_feature.clone(),
                }
            })
            .collect(),
        string_codes,
        rules: wasm_rules
            .iter()
            .map(|rule| WasmRuleMetadata {
                id: rule.id.to_string(),
                bit: rule.bit,
                action: rule.action.map(ToOwned::to_owned),
                priority: rule.priority,
                label: rule.label.cloned(),
                message: rule.message.cloned(),
                severity: rule.severity.cloned(),
                counterfactual_hint: rule.counterfactual_hint.cloned(),
                features: explain_rule_features(input_schema, rule.expression),
            })
            .collect(),
    };
    fs::write(
        path,
        serde_json::to_string_pretty(&metadata).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write wasm metadata")?;
    Ok(())
}

pub(super) fn build_string_codes(
    input_schema: &InputSchema,
    rules: &[WasmRuleView<'_>],
) -> BTreeMap<String, u32> {
    let mut values = BTreeMap::new();
    for feature in &input_schema.features {
        if matches!(
            feature.feature_type,
            FeatureType::String | FeatureType::Enum
        ) {
            if let Some(feature_values) = &feature.values {
                for value in feature_values {
                    let key = string_key(value);
                    let next = values.len() as u32;
                    values.entry(key).or_insert(next);
                }
            }
        }
    }
    for rule in rules {
        collect_expression_strings(rule.expression, &mut values);
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

pub(super) fn string_key(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}
