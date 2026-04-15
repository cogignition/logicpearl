// SPDX-License-Identifier: MIT
//! Benchmark adapters and scoring helpers.
//!
//! This crate keeps benchmark ingestion, trace projection, and score reporting
//! separate from the deterministic runtime. It is for reproducible evaluation
//! workflows around public or generated cases, not for adding domain-specific
//! parsing behavior to the core engine.

use serde_json::Value;

mod case_io;
mod configured;
mod detection;
mod mt_agentrisk;
mod parsers;
mod profiles;
mod projection;
mod types;
mod waf;

pub use case_io::{
    load_benchmark_cases, load_synthesis_case_rows, load_synthesis_cases,
    write_benchmark_cases_jsonl,
};
pub use configured::{
    adapt_alert_dataset, adapt_chatgpt_jailbreak_prompts_dataset, adapt_jailbreakbench_dataset,
    adapt_mcpmark_dataset, adapt_noeti_toxicqa_dataset, adapt_openagentsafety_s26_dataset,
    adapt_profile_dataset, adapt_promptshield_dataset,
    adapt_rogue_security_prompt_injections_dataset, adapt_safearena_dataset, adapt_salad_dataset,
    adapt_squad_dataset, adapt_vigil_dataset,
};
pub use detection::detect_benchmark_adapter_profile;
pub use mt_agentrisk::adapt_mt_agentrisk_dataset;
pub use profiles::{benchmark_adapter_registry, builtin_adapter_config};
pub use projection::{
    emit_trace_tables, load_trace_projection_config, BinaryTargetProjection, ProjectionPredicate,
    TraceEmitSummary, TraceProjectionConfig,
};
pub use types::{
    BenchmarkAdaptDefaults, BenchmarkAdapterConfig, BenchmarkAdapterDescriptor,
    BenchmarkAdapterInputField, BenchmarkAdapterInputFieldMode, BenchmarkAdapterOutputConfig,
    BenchmarkAdapterParser, BenchmarkAdapterProfile, BenchmarkAdapterSourceConfig, BenchmarkCase,
    BooleanLabelRouteConfig, ObservedBenchmarkCase, SaladAttackCase, SaladBaseCase,
    SaladSubsetKind, SquadArticle, SquadDataset, SquadParagraph, SquadQuestion, SynthesisCase,
    SynthesisCaseRow,
};
pub use waf::{adapt_csic_http_2010_dataset, adapt_modsecurity_owasp_2025_dataset};

pub fn first_string_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

pub fn stable_value_id(value: &serde_json::Value, fallback_index: usize) -> String {
    match value {
        serde_json::Value::String(text) => sanitize_identifier(text),
        serde_json::Value::Number(number) => number.to_string(),
        _ => format!("{fallback_index:06}"),
    }
}

pub fn sanitize_identifier(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "pearl".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests;
