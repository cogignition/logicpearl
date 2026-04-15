// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

use super::mt_agentrisk::is_mt_agentrisk_root;
use super::parsers::parse_json_object_rows;
use super::types::{BenchmarkAdapterProfile, SaladAttackCase, SaladBaseCase, SquadDataset};
use super::waf::{is_csic_http_2010_root, is_modsecurity_owasp_root};

pub fn detect_benchmark_adapter_profile(path: &Path) -> Result<BenchmarkAdapterProfile> {
    if path.is_dir() {
        if is_csic_http_2010_root(path) {
            return Ok(BenchmarkAdapterProfile::CsicHttp2010);
        }
        if is_modsecurity_owasp_root(path) {
            return Ok(BenchmarkAdapterProfile::ModsecurityOwasp2025);
        }
        if is_mt_agentrisk_root(path) {
            return Ok(BenchmarkAdapterProfile::MtAgentRisk);
        }
        return Err(LogicPearlError::message(format!(
            "could not auto-detect a built-in benchmark adapter profile for {}",
            path.display()
        )));
    }

    let raw = fs::read_to_string(path)?;
    if let Ok(dataset) = serde_json::from_str::<SquadDataset>(&raw) {
        if !dataset.data.is_empty() {
            return Ok(BenchmarkAdapterProfile::Squad);
        }
    }

    if let Ok(base_rows) = serde_json::from_str::<Vec<SaladBaseCase>>(&raw) {
        if !base_rows.is_empty() {
            return Ok(BenchmarkAdapterProfile::SaladBaseSet);
        }
    }

    if let Ok(attack_rows) = serde_json::from_str::<Vec<SaladAttackCase>>(&raw) {
        if !attack_rows.is_empty() {
            return Ok(BenchmarkAdapterProfile::SaladAttackEnhancedSet);
        }
    }

    if let Ok(rows) = parse_json_object_rows(&raw) {
        if !rows.is_empty() {
            let first = &rows[0];
            if first.contains_key("Prompt")
                || first.contains_key("Jailbreak Score")
                || first.contains_key("Votes")
            {
                return Ok(BenchmarkAdapterProfile::ChatgptJailbreakPrompts);
            }
            if first
                .get("source_dataset")
                .and_then(Value::as_str)
                .map(|value| value == "jailbreakbench")
                .unwrap_or(false)
            {
                return Ok(BenchmarkAdapterProfile::JailbreakBench);
            }
            if first
                .get("source_dataset")
                .and_then(Value::as_str)
                .map(|value| value == "promptshield")
                .unwrap_or(false)
            {
                return Ok(BenchmarkAdapterProfile::PromptShield);
            }
            if first
                .get("source_dataset")
                .and_then(Value::as_str)
                .map(|value| value == "rogue-security-prompt-injections")
                .unwrap_or(false)
            {
                return Ok(BenchmarkAdapterProfile::RogueSecurityPromptInjections);
            }
            if first.contains_key("intent")
                && first.contains_key("intent_template")
                && first.contains_key("task_id")
                && first.contains_key("sites")
            {
                let category = first
                    .get("category")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                return Ok(if category.eq_ignore_ascii_case("safe") {
                    BenchmarkAdapterProfile::SafearenaSafe
                } else {
                    BenchmarkAdapterProfile::SafearenaHarm
                });
            }
            if first.contains_key("problem_statement")
                && first.contains_key("instance_id")
                && first.contains_key("environment")
            {
                return Ok(BenchmarkAdapterProfile::OpenAgentSafetyS26);
            }
            if first.contains_key("task_id")
                && first.contains_key("instruction")
                && first.contains_key("mcp")
                && first.contains_key("task_path")
            {
                return Ok(BenchmarkAdapterProfile::McpMark);
            }
            if first.contains_key("text")
                && (first.contains_key("embeddings") || first.contains_key("embedding"))
            {
                return Ok(BenchmarkAdapterProfile::Vigil);
            }
            if first.contains_key("prompt")
                && (first.contains_key("majortopic")
                    || first.contains_key("topic")
                    || first.contains_key("subtopics")
                    || first.contains_key("conversations"))
            {
                return Ok(BenchmarkAdapterProfile::NoetiToxicQa);
            }
            if first.contains_key("prompt")
                || first.contains_key("instruction")
                || first.contains_key("text")
                || first.contains_key("question")
                || first.contains_key("input")
                || first.contains_key("content")
            {
                return Ok(BenchmarkAdapterProfile::Alert);
            }
        }
    }

    Err(LogicPearlError::message(format!(
        "could not auto-detect a built-in benchmark adapter profile for {}",
        path.display()
    )))
}
