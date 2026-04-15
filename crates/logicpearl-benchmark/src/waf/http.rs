// SPDX-License-Identifier: MIT
use serde_json::Value;

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

pub(super) fn split_http_request_blocks(raw: &str) -> Vec<String> {
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

pub(super) fn parse_http_request_block(block: &str) -> Option<ParsedHttpRequest> {
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
