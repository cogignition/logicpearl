// SPDX-License-Identifier: MIT
use super::{
    builtin_adapter_config, first_string_field, stable_value_id, BenchmarkAdaptDefaults,
    BenchmarkAdapterConfig, BenchmarkAdapterInputFieldMode, BenchmarkAdapterProfile, BenchmarkCase,
    SaladSubsetKind,
};
use crate::parsers::parse_rows_for_parser;
use crate::projection::boolish;
use logicpearl_core::{LogicPearlError, Result};
use serde_json::Value;

pub fn adapt_profile_dataset(
    profile: BenchmarkAdapterProfile,
    raw: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    let config = builtin_adapter_config(profile).ok_or_else(|| {
        LogicPearlError::message(format!(
            "profile {:?} does not have a built-in adapter config",
            profile
        ))
    })?;
    adapt_dataset_with_config(raw, defaults, &config)
}

pub fn adapt_salad_dataset(
    raw_json: &str,
    subset: SaladSubsetKind,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    let profile = match subset {
        SaladSubsetKind::BaseSet => BenchmarkAdapterProfile::SaladBaseSet,
        SaladSubsetKind::AttackEnhancedSet => BenchmarkAdapterProfile::SaladAttackEnhancedSet,
    };
    adapt_profile_dataset(profile, raw_json, defaults)
}

pub fn adapt_safearena_dataset(
    raw_json: &str,
    safe_split: bool,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(
        if safe_split {
            BenchmarkAdapterProfile::SafearenaSafe
        } else {
            BenchmarkAdapterProfile::SafearenaHarm
        },
        raw_json,
        defaults,
    )
}

pub fn adapt_alert_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::Alert, raw_json, defaults)
}

pub fn adapt_jailbreakbench_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::JailbreakBench, raw_json, defaults)
}

pub fn adapt_promptshield_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::PromptShield, raw_json, defaults)
}

pub fn adapt_rogue_security_prompt_injections_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(
        BenchmarkAdapterProfile::RogueSecurityPromptInjections,
        raw_json,
        defaults,
    )
}

pub fn adapt_chatgpt_jailbreak_prompts_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(
        BenchmarkAdapterProfile::ChatgptJailbreakPrompts,
        raw_json,
        defaults,
    )
}

pub fn adapt_openagentsafety_s26_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(
        BenchmarkAdapterProfile::OpenAgentSafetyS26,
        raw_json,
        defaults,
    )
}

pub fn adapt_mcpmark_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::McpMark, raw_json, defaults)
}

pub fn adapt_squad_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::Squad, raw_json, defaults)
}

pub fn adapt_vigil_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::Vigil, raw_json, defaults)
}

pub fn adapt_noeti_toxicqa_dataset(
    raw_json: &str,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    adapt_profile_dataset(BenchmarkAdapterProfile::NoetiToxicQa, raw_json, defaults)
}

fn adapt_dataset_with_config(
    raw: &str,
    defaults: &BenchmarkAdaptDefaults,
    config: &BenchmarkAdapterConfig,
) -> Result<Vec<BenchmarkCase>> {
    let rows = parse_rows_for_parser(raw, config.source.parser)?;
    if rows.is_empty() {
        return Err(LogicPearlError::message(format!(
            "raw {} dataset is empty",
            config.id
        )));
    }

    let prompt_keys = config
        .source
        .prompt_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let category_keys = config
        .source
        .category_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            build_case_from_row(row, index, defaults, config, &prompt_keys, &category_keys)
        })
        .collect()
}

fn build_case_from_row(
    row: &serde_json::Map<String, Value>,
    index: usize,
    defaults: &BenchmarkAdaptDefaults,
    config: &BenchmarkAdapterConfig,
    prompt_keys: &[&str],
    category_keys: &[&str],
) -> Result<BenchmarkCase> {
    let prompt = first_string_field(row, prompt_keys).ok_or_else(|| {
        LogicPearlError::message(format!(
            "{} row {} is missing a prompt-like text field",
            config.id,
            index + 1
        ))
    })?;

    let id = config
        .source
        .id_fields
        .iter()
        .find_map(|field| row.get(field))
        .map(|value| {
            format!(
                "{}_{}",
                config.output.id_prefix,
                stable_value_id(value, index)
            )
        })
        .unwrap_or_else(|| format!("{}_{index:06}", config.output.id_prefix));

    let expected_route = if let Some(routes) = &config.output.boolean_label_routes {
        let label_value = config
            .source
            .label_fields
            .iter()
            .find_map(|field| row.get(field))
            .ok_or_else(|| {
                LogicPearlError::message(format!(
                    "{} row {} is missing a boolean label field",
                    config.id,
                    index + 1
                ))
            })?;
        if boolish(Some(label_value)) {
            routes.true_route.clone()
        } else {
            routes.false_route.clone()
        }
    } else {
        config.output.expected_route.clone().ok_or_else(|| {
            LogicPearlError::message(format!(
                "{} adapter config must define output.expected_route or output.boolean_label_routes",
                config.id
            ))
        })?
    };

    let category = first_string_field(row, category_keys);
    let mut input = serde_json::Map::new();
    input.insert("prompt".to_string(), Value::String(prompt));
    input.insert(
        "requested_tool".to_string(),
        Value::String(defaults.requested_tool.clone()),
    );
    input.insert(
        "requested_action".to_string(),
        Value::String(defaults.requested_action.clone()),
    );
    input.insert("scope".to_string(), Value::String(defaults.scope.clone()));
    for field in &config.source.input_fields {
        if let Some(value) = row.get(&field.source) {
            input.insert(
                field.target.clone(),
                transform_input_field(value, field.mode),
            );
        }
    }
    for (key, value) in &config.output.static_input {
        input.insert(key.clone(), value.clone());
    }

    Ok(BenchmarkCase {
        id,
        input: Value::Object(input),
        expected_route,
        category: category.or_else(|| config.output.default_category.clone()),
    })
}

fn transform_input_field(value: &Value, mode: BenchmarkAdapterInputFieldMode) -> Value {
    match mode {
        BenchmarkAdapterInputFieldMode::Raw => value.clone(),
        BenchmarkAdapterInputFieldMode::FirstString => match value {
            Value::Array(items) => items
                .iter()
                .find_map(Value::as_str)
                .map(|text| Value::String(text.to_string()))
                .unwrap_or(Value::Null),
            Value::String(text) => Value::String(text.clone()),
            _ => Value::Null,
        },
    }
}
