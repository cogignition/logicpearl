import json
import re
import sys
from urllib.parse import unquote_plus
from pathlib import Path

CONFIG = json.loads((Path(__file__).with_name("patterns.json")).read_text())


def contains_any(text: str, phrases) -> bool:
    return any(phrase in text for phrase in phrases)


def normalize_text(value: str) -> str:
    lowered = unquote_plus(value).lower()
    collapsed = re.sub(r"\s+", " ", lowered)
    return collapsed.strip()


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
    query_text = normalize_text(json.dumps(query, sort_keys=True))
    body_text = normalize_text(json.dumps(body, sort_keys=True))
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
    targets_sensitive_route = (
        path.startswith("/admin")
        or path.startswith("/internal")
        or contains_any(path, CONFIG["sensitive_route_patterns"])
        or contains_any(combined_text, CONFIG["sensitive_meta_markers"])
    )
    origin_outside_trust_zone = source_zone in {"public_web", "untrusted_browser"}
    has_scanner_fingerprint = contains_any(user_agent, CONFIG["scanner_patterns"]) or path in {"/.env", "/wp-admin/install.php", "/phpmyadmin"}
    has_malformed_encoding = "%25" in combined_text or "%2f%2e" in combined_text or "%%" in combined_text

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
    if targets_sensitive_route:
        risk_score += 0.14
    if origin_outside_trust_zone:
        risk_score += 0.1
    if has_scanner_fingerprint:
        risk_score += 0.46
    if has_malformed_encoding:
        risk_score += 0.28
    if likely_benign_request:
        risk_score = min(risk_score, 0.12)
    risk_score = round(max(0.0, min(1.0, risk_score)), 2)

    return {
        "ok": True,
        "features": {
            "contains_sqli_signature": contains_sqli_signature,
            "contains_xss_signature": contains_xss_signature,
            "contains_path_traversal": contains_path_traversal,
            "targets_sensitive_route": targets_sensitive_route,
            "origin_outside_trust_zone": origin_outside_trust_zone,
            "has_scanner_fingerprint": has_scanner_fingerprint,
            "has_malformed_encoding": has_malformed_encoding,
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
