// SPDX-License-Identifier: MIT
use super::{sanitize_identifier, BenchmarkAdaptDefaults, BenchmarkCase};
use logicpearl_core::{LogicPearlError, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

mod classification;
mod http;

use classification::classify_modsecurity_transaction;
pub(crate) use classification::classify_waf_route_family;
pub(crate) use http::ParsedHttpRequest;
use http::{parse_http_request_block, split_http_request_blocks};

pub fn adapt_csic_http_2010_dataset(
    dataset_root: &Path,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    if !is_csic_http_2010_root(dataset_root) {
        return Err(LogicPearlError::message(format!(
            "CSIC HTTP 2010 dataset root is missing expected files: {}",
            dataset_root.display()
        )));
    }

    let mut cases = Vec::new();
    cases.extend(adapt_csic_http_2010_file(
        &dataset_root.join("normalTrafficTraining.txt"),
        true,
        defaults,
    )?);
    cases.extend(adapt_csic_http_2010_file(
        &dataset_root.join("anomalousTrafficTest.txt"),
        false,
        defaults,
    )?);
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(cases)
}

pub fn adapt_modsecurity_owasp_2025_dataset(
    dataset_root: &Path,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    if !is_modsecurity_owasp_root(dataset_root) {
        return Err(LogicPearlError::message(format!(
            "ModSecurity dataset root is missing expected audit logs: {}",
            dataset_root.display()
        )));
    }

    let mut logs = Vec::new();
    collect_modsecurity_logs(dataset_root, &mut logs)?;
    logs.sort();

    let mut cases = Vec::new();
    for log_path in logs {
        let raw = fs::read_to_string(&log_path)?;
        for transaction in parse_modsecurity_transactions(&raw) {
            let Some(request_block) = transaction.sections.get("B") else {
                continue;
            };
            let Some(request) = parse_http_request_block(request_block) else {
                continue;
            };
            let meta = transaction.sections.get("H").cloned().unwrap_or_default();
            let (expected_route, category) = classify_modsecurity_transaction(&request, &meta);
            let tx_id = transaction
                .id
                .clone()
                .unwrap_or_else(|| format!("tx_{:06}", cases.len() + 1));
            cases.push(build_waf_case(
                format!("modsecurity_{}", sanitize_identifier(&tx_id)),
                &request,
                expected_route,
                category,
                defaults,
                serde_json::json!({
                    "waf_dataset": "modsecurity-owasp-2025",
                    "modsecurity_meta": meta,
                    "source_log": log_path.display().to_string(),
                }),
            ));
        }
    }

    if cases.is_empty() {
        return Err(LogicPearlError::message(format!(
            "ModSecurity dataset contains no parseable audit transactions at {}",
            dataset_root.display()
        )));
    }

    cases.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(cases)
}

pub(super) fn is_csic_http_2010_root(path: &Path) -> bool {
    path.is_dir()
        && path.join("normalTrafficTraining.txt").is_file()
        && path.join("anomalousTrafficTest.txt").is_file()
}

pub(super) fn is_modsecurity_owasp_root(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    let mut logs = Vec::new();
    collect_modsecurity_logs(path, &mut logs).is_ok() && !logs.is_empty()
}

fn collect_modsecurity_logs(root: &Path, logs: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_modsecurity_logs(&path, logs)?;
        } else if path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value == "modsec_audit.anon.log")
            .unwrap_or(false)
        {
            logs.push(path);
        }
    }
    Ok(())
}

fn adapt_csic_http_2010_file(
    dataset_path: &Path,
    allow_rows: bool,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    let raw = fs::read_to_string(dataset_path)?;
    let blocks = split_http_request_blocks(&raw);
    if blocks.is_empty() {
        return Err(LogicPearlError::message(format!(
            "CSIC dataset file contains no request blocks: {}",
            dataset_path.display()
        )));
    }

    let id_prefix = if allow_rows {
        "csic_allow"
    } else {
        "csic_attack"
    };
    let mut cases = Vec::new();
    for (index, block) in blocks.into_iter().enumerate() {
        let Some(request) = parse_http_request_block(&block) else {
            continue;
        };
        let (expected_route, category) = if allow_rows {
            ("allow".to_string(), "waf:benign".to_string())
        } else {
            classify_waf_route_family(&request, None)
        };
        cases.push(build_waf_case(
            format!("{id_prefix}_{index:06}"),
            &request,
            expected_route,
            category,
            defaults,
            serde_json::json!({
                "waf_dataset": "csic-http-2010",
                "source_file": dataset_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default(),
            }),
        ));
    }
    Ok(cases)
}

fn build_waf_case(
    id: String,
    request: &ParsedHttpRequest,
    expected_route: String,
    category: String,
    defaults: &BenchmarkAdaptDefaults,
    extra: Value,
) -> BenchmarkCase {
    let mut input = serde_json::Map::new();
    input.insert("method".to_string(), Value::String(request.method.clone()));
    input.insert("path".to_string(), Value::String(request.path.clone()));
    input.insert(
        "source_zone".to_string(),
        Value::String("public_web".to_string()),
    );
    input.insert(
        "headers".to_string(),
        Value::Object(request.headers.clone()),
    );
    input.insert("query".to_string(), Value::Object(request.query.clone()));
    input.insert("body".to_string(), Value::Object(request.body.clone()));
    input.insert(
        "raw_request".to_string(),
        Value::String(request.raw_request.clone()),
    );
    input.insert(
        "request_uri".to_string(),
        Value::String(request.request_uri.clone()),
    );
    input.insert(
        "http_version".to_string(),
        Value::String(request.http_version.clone()),
    );
    input.insert(
        "requested_tool".to_string(),
        Value::String(defaults.requested_tool.clone()),
    );
    input.insert(
        "requested_action".to_string(),
        Value::String(defaults.requested_action.clone()),
    );
    input.insert("scope".to_string(), Value::String(defaults.scope.clone()));

    if let Some(extra_object) = extra.as_object() {
        for (key, value) in extra_object {
            input.insert(key.clone(), value.clone());
        }
    }
    input
        .entry("modsecurity_meta".to_string())
        .or_insert_with(|| Value::String(String::new()));
    input
        .entry("source_log".to_string())
        .or_insert_with(|| Value::String(String::new()));

    BenchmarkCase {
        id,
        input: Value::Object(input),
        expected_route,
        category: Some(category),
    }
}

#[derive(Debug, Clone)]
struct ModSecurityTransaction {
    id: Option<String>,
    sections: BTreeMap<String, String>,
}

fn parse_modsecurity_transactions(raw: &str) -> Vec<ModSecurityTransaction> {
    let normalized = raw.replace("\r\n", "\n");
    let mut transactions = Vec::new();
    let mut current: Option<ModSecurityTransaction> = None;
    let mut current_section: Option<String> = None;
    let mut section_lines = Vec::new();

    for line in normalized.lines() {
        if line.starts_with("--") && line.ends_with("--") && line.len() >= 6 {
            let trimmed = line.trim_matches('-');
            let section = trimmed.chars().last().unwrap_or('Z').to_string();
            let tx_id = trimmed
                .strip_suffix(&section)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| trimmed.to_string());

            if let Some(tx) = current.as_mut() {
                if let Some(section_name) = current_section.take() {
                    tx.sections
                        .insert(section_name, section_lines.join("\n").trim().to_string());
                    section_lines.clear();
                }
            }

            if section == "A" {
                if let Some(tx) = current.take() {
                    transactions.push(tx);
                }
                current = Some(ModSecurityTransaction {
                    id: Some(tx_id),
                    sections: BTreeMap::new(),
                });
                current_section = Some(section);
            } else if section == "Z" {
                if let Some(tx) = current.take() {
                    transactions.push(tx);
                }
            } else if current.is_some() {
                current_section = Some(section);
            }
            continue;
        }

        if current_section.is_some() {
            section_lines.push(line.to_string());
        }
    }

    if let Some(tx) = current {
        transactions.push(tx);
    }

    transactions
}
