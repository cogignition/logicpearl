// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};

use super::http::ParsedHttpRequest;

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

pub(super) fn classify_modsecurity_transaction(
    request: &ParsedHttpRequest,
    meta: &str,
) -> (String, String) {
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
        serde_json::from_str(include_str!("../../data/route_patterns.json"))
            .expect("built-in WAF route patterns must be valid JSON")
    })
}
