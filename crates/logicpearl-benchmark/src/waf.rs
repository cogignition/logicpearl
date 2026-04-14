// SPDX-License-Identifier: MIT
use super::{sanitize_identifier, BenchmarkAdaptDefaults, BenchmarkCase};
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct ParsedHttpRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) request_uri: String,
    pub(crate) http_version: String,
    pub(crate) headers: serde_json::Map<String, Value>,
    pub(crate) query: serde_json::Map<String, Value>,
    pub(crate) body: serde_json::Map<String, Value>,
    pub(crate) raw_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WafRouteClass {
    expected_route: String,
    category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WafRouteClasses {
    automation_probe: WafRouteClass,
    command_injection: WafRouteClass,
    php_injection: WafRouteClass,
    path_traversal: WafRouteClass,
    sensitive_surface: WafRouteClass,
    protocol_review: WafRouteClass,
    sqli: WafRouteClass,
    xss: WafRouteClass,
    data_exfiltration: WafRouteClass,
    modsecurity_default: WafRouteClass,
    csic_default: WafRouteClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WafRoutePatterns {
    route_classes: WafRouteClasses,
    scanner_markers: Vec<String>,
    scanner_meta_markers: Vec<String>,
    protocol_review_meta_markers: Vec<String>,
    command_injection_meta_patterns: Vec<String>,
    php_injection_markers: Vec<String>,
    php_injection_meta_patterns: Vec<String>,
    server_include_patterns: Vec<String>,
    sqli_markers: Vec<String>,
    sqli_meta_markers: Vec<String>,
    xss_markers: Vec<String>,
    xss_meta_markers: Vec<String>,
    restricted_markers: Vec<String>,
    path_traversal_markers: Vec<String>,
    path_traversal_meta_markers: Vec<String>,
    restricted_meta_markers: Vec<String>,
    restricted_extensions: Vec<String>,
    export_markers: Vec<String>,
}

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

fn split_http_request_blocks(raw: &str) -> Vec<String> {
    let normalized = raw.replace("\r\n", "\n");
    let mut blocks = Vec::new();
    let mut current = Vec::new();

    for line in normalized.lines() {
        if looks_like_http_request_line(line) && !current.is_empty() {
            let block = current.join("\n");
            let trimmed = block.trim();
            if !trimmed.is_empty() {
                blocks.push(trimmed.to_string());
            }
            current.clear();
        }
        current.push(line.to_string());
    }

    let trailing = current.join("\n");
    let trimmed = trailing.trim();
    if !trimmed.is_empty() {
        blocks.push(trimmed.to_string());
    }

    blocks
}

fn looks_like_http_request_line(line: &str) -> bool {
    let methods = [
        "GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ",
    ];
    methods.iter().any(|method| line.starts_with(method)) && line.contains(" HTTP/")
}

fn parse_http_request_block(block: &str) -> Option<ParsedHttpRequest> {
    let normalized = block.replace("\r\n", "\n");
    let mut lines = normalized.lines();
    let request_line = lines.next()?.trim();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?.to_string();
    let request_uri = request_parts.next()?.to_string();
    let http_version = request_parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut header_lines = Vec::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        if !in_body && line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body_lines.push(line);
        } else {
            header_lines.push(line);
        }
    }

    let mut headers = serde_json::Map::new();
    for line in header_lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(
                name.trim().to_ascii_lowercase(),
                Value::String(value.trim().to_string()),
            );
        }
    }

    let (path, raw_query) = split_request_uri(&request_uri);
    let content_type = headers
        .get("content-type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let body_text = body_lines.join("\n");

    Some(ParsedHttpRequest {
        method,
        path,
        request_uri,
        http_version,
        headers,
        query: parse_kv_payload(&raw_query, true),
        body: parse_kv_payload(
            &body_text,
            content_type.contains("application/x-www-form-urlencoded"),
        ),
        raw_request: normalized,
    })
}

fn split_request_uri(uri: &str) -> (String, String) {
    let path_and_query = if let Some(rest) = uri.strip_prefix("http://") {
        rest.split_once('/')
            .map(|(_, tail)| format!("/{tail}"))
            .unwrap_or_else(|| "/".to_string())
    } else if let Some(rest) = uri.strip_prefix("https://") {
        rest.split_once('/')
            .map(|(_, tail)| format!("/{tail}"))
            .unwrap_or_else(|| "/".to_string())
    } else {
        uri.to_string()
    };

    if let Some((path, query)) = path_and_query.split_once('?') {
        (path.to_string(), query.to_string())
    } else {
        (path_and_query, String::new())
    }
}

fn parse_kv_payload(raw: &str, split_pairs: bool) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return out;
    }

    if split_pairs {
        for pair in trimmed.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            out.insert(
                percent_decode_component(key),
                Value::String(percent_decode_component(value)),
            );
        }
    } else {
        out.insert(
            "raw".to_string(),
            Value::String(percent_decode_component(trimmed)),
        );
    }
    out
}

fn percent_decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(decoded) = u8::from_str_radix(hex, 16) {
                    out.push(decoded as char);
                    index += 3;
                    continue;
                }
                out.push('%');
                index += 1;
            }
            byte => {
                out.push(byte as char);
                index += 1;
            }
        }
    }
    out
}

fn classify_modsecurity_transaction(request: &ParsedHttpRequest, meta: &str) -> (String, String) {
    classify_waf_route_family(request, Some(meta))
}

fn route_class(classification: &WafRouteClass) -> (String, String) {
    (
        classification.expected_route.clone(),
        classification.category.clone(),
    )
}

pub(crate) fn classify_waf_route_family(
    request: &ParsedHttpRequest,
    meta: Option<&str>,
) -> (String, String) {
    let meta_text = meta.unwrap_or_default().to_ascii_lowercase();
    let request_text = waf_request_text(request);
    let request_path = request.path.to_ascii_lowercase();
    let patterns = waf_route_patterns();

    if contains_any_marker(&request_text, &patterns.scanner_markers)
        || contains_any_marker(&meta_text, &patterns.scanner_meta_markers)
    {
        return route_class(&patterns.route_classes.automation_probe);
    }

    if contains_any_marker(&request_text, &patterns.server_include_patterns)
        || contains_any_marker(&meta_text, &patterns.command_injection_meta_patterns)
    {
        return route_class(&patterns.route_classes.command_injection);
    }

    if contains_any_marker(&request_text, &patterns.php_injection_markers)
        || contains_any_marker(&meta_text, &patterns.php_injection_meta_patterns)
    {
        return route_class(&patterns.route_classes.php_injection);
    }

    if contains_any_marker(&request_text, &patterns.path_traversal_markers)
        || contains_any_marker(&meta_text, &patterns.path_traversal_meta_markers)
    {
        return route_class(&patterns.route_classes.path_traversal);
    }

    if contains_any_marker(&request_text, &patterns.restricted_markers)
        || contains_any_marker(&meta_text, &patterns.restricted_meta_markers)
        || patterns
            .restricted_extensions
            .iter()
            .any(|suffix| request_path.ends_with(suffix))
    {
        return route_class(&patterns.route_classes.sensitive_surface);
    }

    if contains_any_marker(&meta_text, &patterns.protocol_review_meta_markers) {
        return route_class(&patterns.route_classes.protocol_review);
    }

    if contains_any_marker(&request_text, &patterns.sqli_markers)
        || contains_any_marker(&meta_text, &patterns.sqli_meta_markers)
    {
        return route_class(&patterns.route_classes.sqli);
    }

    if contains_any_marker(&request_text, &patterns.xss_markers)
        || contains_any_marker(&meta_text, &patterns.xss_meta_markers)
    {
        return route_class(&patterns.route_classes.xss);
    }

    if contains_any_marker(&request_text, &patterns.export_markers) {
        return route_class(&patterns.route_classes.data_exfiltration);
    }

    if meta.is_some() {
        route_class(&patterns.route_classes.modsecurity_default)
    } else {
        route_class(&patterns.route_classes.csic_default)
    }
}

fn waf_request_text(request: &ParsedHttpRequest) -> String {
    let mut parts = vec![
        request.method.to_ascii_lowercase(),
        request.path.to_ascii_lowercase(),
        request.request_uri.to_ascii_lowercase(),
        request.raw_request.to_ascii_lowercase(),
    ];

    for value in request.headers.values() {
        if let Some(text) = value.as_str() {
            parts.push(text.to_ascii_lowercase());
        }
    }
    for value in request.query.values() {
        if let Some(text) = value.as_str() {
            parts.push(text.to_ascii_lowercase());
        }
    }
    for value in request.body.values() {
        if let Some(text) = value.as_str() {
            parts.push(text.to_ascii_lowercase());
        }
    }

    parts.join(" ")
}

fn contains_any_marker(haystack: &str, markers: &[String]) -> bool {
    markers.iter().any(|marker| haystack.contains(marker))
}

fn waf_route_patterns() -> &'static WafRoutePatterns {
    static ROUTE_PATTERNS: std::sync::OnceLock<WafRoutePatterns> = std::sync::OnceLock::new();
    ROUTE_PATTERNS.get_or_init(|| {
        serde_json::from_str(include_str!("../data/route_patterns.json"))
            .expect("built-in WAF route patterns must be valid JSON")
    })
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
