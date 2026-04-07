import json
import re
import sys
from urllib.parse import unquote_plus
from pathlib import Path

CONFIG = json.loads((Path(__file__).with_name("patterns.json")).read_text())


def contains_any(text: str, phrases) -> bool:
    return any(phrase in text for phrase in phrases)


def count_matches(text: str, phrases) -> int:
    return sum(1 for phrase in phrases if phrase in text)


def normalize_text(value: str) -> str:
    lowered = unquote_plus(value).lower()
    collapsed = re.sub(r"\s+", " ", lowered)
    return collapsed.strip()


def flatten_text(value) -> str:
    parts = []

    def visit(node) -> None:
        if isinstance(node, dict):
            for key, child in sorted(node.items()):
                visit(str(key))
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)
        elif node is None:
            return
        else:
            text = normalize_text(str(node))
            if text:
                parts.append(text)

    visit(value)
    return " ".join(parts)


def observe_raw_input(raw) -> dict:
    method = normalize_text(str(raw.get("method", "")))
    path = normalize_text(str(raw.get("path", "")))
    source_zone = normalize_text(str(raw.get("source_zone", "")))
    raw_request = normalize_text(str(raw.get("raw_request", "")))
    modsecurity_meta = normalize_text(str(raw.get("modsecurity_meta", "")))
    headers = raw.get("headers", {}) if isinstance(raw.get("headers", {}), dict) else {}
    query = raw.get("query", {}) if isinstance(raw.get("query", {}), dict) else {}
    body = raw.get("body", {}) if isinstance(raw.get("body", {}), dict) else {}

    tenant_scope = normalize_text(str(headers.get("tenant_scope", "")))
    user_agent = normalize_text(str(headers.get("user_agent", headers.get("user-agent", ""))))
    query_text = flatten_text(query)
    body_text = flatten_text(body)
    combined_text = " ".join(
        part
        for part in (
            path,
            query_text,
            body_text,
            tenant_scope,
            user_agent,
            raw_request,
            modsecurity_meta,
        )
        if part
    )

    contains_sqli_signature = contains_any(combined_text, CONFIG["sqli_patterns"])
    contains_xss_signature = contains_any(combined_text, CONFIG["xss_patterns"])
    contains_path_traversal = contains_any(combined_text, CONFIG["traversal_patterns"])
    contains_server_include = contains_any(combined_text, CONFIG["server_include_patterns"])
    contains_php_injection = contains_any(combined_text, CONFIG["php_injection_patterns"])
    sqli_marker_count = count_matches(combined_text, CONFIG["sqli_patterns"])
    xss_marker_count = count_matches(combined_text, CONFIG["xss_patterns"])
    traversal_marker_count = count_matches(combined_text, CONFIG["traversal_patterns"])
    php_injection_marker_count = count_matches(combined_text, CONFIG["php_injection_patterns"])
    sensitive_route_marker_count = count_matches(path, CONFIG["sensitive_route_patterns"])
    scanner_marker_count = count_matches(user_agent, CONFIG["scanner_patterns"])
    targets_sensitive_route = (
        path.startswith("/admin")
        or path.startswith("/internal")
        or contains_any(path, CONFIG["sensitive_route_patterns"])
        or contains_any(combined_text, CONFIG["sensitive_meta_markers"])
    )
    path_targets_admin = path.startswith("/admin") or path.startswith("/internal")
    path_targets_hidden = any(marker in path for marker in ["/.git", "/.env", "/phpmyadmin", "/wp-admin"])
    contains_restricted_extension = any(path.endswith(ext) for ext in CONFIG["restricted_extensions"])
    origin_outside_trust_zone = source_zone in {"public_web", "untrusted_browser"}
    has_scanner_fingerprint = contains_any(user_agent, CONFIG["scanner_patterns"]) or path in {"/.env", "/wp-admin/install.php", "/phpmyadmin"}
    has_malformed_encoding = "%25" in combined_text or "%2f%2e" in combined_text or "%%" in combined_text
    meta_reports_sqli = contains_any(modsecurity_meta, CONFIG["sqli_meta_patterns"])
    meta_reports_xss = contains_any(modsecurity_meta, CONFIG["xss_meta_patterns"])
    meta_reports_restricted_resource = contains_any(modsecurity_meta, CONFIG["sensitive_meta_markers"])
    meta_reports_bad_bot = contains_any(modsecurity_meta, CONFIG["bad_bot_meta_patterns"])
    meta_reports_protocol_violation = contains_any(modsecurity_meta, CONFIG["protocol_meta_patterns"])
    meta_reports_command_injection = contains_any(
        modsecurity_meta, CONFIG["command_injection_meta_patterns"]
    )
    meta_reports_php_injection = contains_any(
        modsecurity_meta, CONFIG["php_injection_meta_patterns"]
    )
    contains_waitfor_delay = "waitfor delay" in combined_text or "sleep(" in combined_text
    contains_union_select = "union select" in combined_text
    contains_quote = "'" in combined_text or '"' in combined_text
    contains_comment_sequence = "--" in combined_text or "/*" in combined_text or "*/" in combined_text or "#" in combined_text
    contains_script_tag = "<script" in combined_text or "javascript:" in combined_text
    contains_event_handler = "onerror=" in combined_text or "onload=" in combined_text
    contains_dotdot = "../" in combined_text or "..\\" in combined_text or "%2e%2e" in combined_text
    request_has_query = bool(query)
    request_has_body = bool(body)
    path_depth = max(0, len([segment for segment in path.split("/") if segment]))
    query_key_count = len(query)
    body_key_count = len(body)
    percent_encoding_count = raw_request.count("%")
    suspicious_token_count = sum(
        int(flag)
        for flag in (
            contains_sqli_signature,
            contains_xss_signature,
            contains_path_traversal,
            contains_server_include,
            contains_php_injection,
            targets_sensitive_route,
            has_scanner_fingerprint,
            has_malformed_encoding,
            meta_reports_sqli,
            meta_reports_xss,
            meta_reports_restricted_resource,
            meta_reports_bad_bot,
            meta_reports_protocol_violation,
            meta_reports_command_injection,
            meta_reports_php_injection,
        )
    )

    likely_benign_request = (
        contains_any(combined_text, CONFIG["benign_patterns"])
        and not contains_sqli_signature
        and not contains_xss_signature
        and not contains_path_traversal
        and not targets_sensitive_route
    )

    risk_score = 0.03
    if contains_sqli_signature:
        risk_score += 0.24
    if contains_xss_signature:
        risk_score += 0.22
    if contains_path_traversal:
        risk_score += 0.24
    if contains_server_include:
        risk_score += 0.2
    if contains_php_injection:
        risk_score += 0.24
    if targets_sensitive_route:
        risk_score += 0.14
    if origin_outside_trust_zone:
        risk_score += 0.1
    if has_scanner_fingerprint:
        risk_score += 0.46
    if has_malformed_encoding:
        risk_score += 0.28
    if meta_reports_command_injection:
        risk_score += 0.28
    if meta_reports_php_injection:
        risk_score += 0.24
    if likely_benign_request:
        risk_score = min(risk_score, 0.12)
    risk_score = round(max(0.0, min(1.0, risk_score)), 2)

    return {
        "ok": True,
        "features": {
            "contains_sqli_signature": contains_sqli_signature,
            "contains_xss_signature": contains_xss_signature,
            "contains_path_traversal": contains_path_traversal,
            "contains_server_include": contains_server_include,
            "contains_php_injection": contains_php_injection,
            "sqli_marker_count": sqli_marker_count,
            "xss_marker_count": xss_marker_count,
            "traversal_marker_count": traversal_marker_count,
            "php_injection_marker_count": php_injection_marker_count,
            "sensitive_route_marker_count": sensitive_route_marker_count,
            "scanner_marker_count": scanner_marker_count,
            "targets_sensitive_route": targets_sensitive_route,
            "path_targets_admin": path_targets_admin,
            "path_targets_hidden": path_targets_hidden,
            "contains_restricted_extension": contains_restricted_extension,
            "origin_outside_trust_zone": origin_outside_trust_zone,
            "has_scanner_fingerprint": has_scanner_fingerprint,
            "has_malformed_encoding": has_malformed_encoding,
            "meta_reports_sqli": meta_reports_sqli,
            "meta_reports_xss": meta_reports_xss,
            "meta_reports_restricted_resource": meta_reports_restricted_resource,
            "meta_reports_bad_bot": meta_reports_bad_bot,
            "meta_reports_protocol_violation": meta_reports_protocol_violation,
            "meta_reports_command_injection": meta_reports_command_injection,
            "meta_reports_php_injection": meta_reports_php_injection,
            "contains_waitfor_delay": contains_waitfor_delay,
            "contains_union_select": contains_union_select,
            "contains_quote": contains_quote,
            "contains_comment_sequence": contains_comment_sequence,
            "contains_script_tag": contains_script_tag,
            "contains_event_handler": contains_event_handler,
            "contains_dotdot": contains_dotdot,
            "request_has_query": request_has_query,
            "request_has_body": request_has_body,
            "path_depth": path_depth,
            "query_key_count": query_key_count,
            "body_key_count": body_key_count,
            "percent_encoding_count": percent_encoding_count,
            "suspicious_token_count": suspicious_token_count,
            "likely_benign_request": likely_benign_request,
            "risk_score": risk_score,
        },
        "warnings": [],
    }


def main() -> int:
    request = json.load(sys.stdin)
    if "payloads" in request:
        responses = []
        for payload in request.get("payloads", []):
            responses.append(observe_raw_input(payload.get("raw_input", {})))
        json.dump({"ok": True, "responses": responses, "warnings": []}, sys.stdout)
        sys.stdout.write("\n")
        return 0

    raw = request.get("payload", {}).get("raw_input", {})
    response = observe_raw_input(raw)

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
