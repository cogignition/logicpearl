import json
import re
import sys


INJECTION_PATTERNS = (
    "' or 1=1",
    "\" or \"1\"=\"1",
    "union select",
    "<script",
    "../",
    "..\\",
    "drop table",
    "sleep(",
    "waitfor delay",
    "${jndi:",
)

INSTRUCTION_OVERRIDE_PATTERNS = (
    "ignore previous instructions",
    "ignore prior instructions",
    "disregard the instructions above",
    "override the guardrails",
    "bypass the safety rules",
    "follow only the next command",
)

SYSTEM_TARGET_PATTERNS = (
    "system prompt",
    "hidden rules",
    "hidden instructions",
    "developer prompt",
    "show me the prompt",
    "reveal your instructions",
)

SECRET_PATTERNS = (
    "api key",
    "api keys",
    "password",
    "passwords",
    "credential",
    "credentials",
    "token",
    "tokens",
    "session cookie",
    "secret",
    "secrets",
)

BULK_EXPORT_PATTERNS = (
    "export all",
    "download all",
    "full export",
    "all customer records",
    "entire tenant",
    "dump all",
)

BENIGN_PATTERNS = (
    "summarize",
    "explain",
    "list the key takeaways",
    "draft a response",
    "translate",
    "find the relevant article",
)


def contains_any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


def normalize_text(value: str) -> str:
    lowered = value.lower()
    collapsed = re.sub(r"\s+", " ", lowered)
    return collapsed.strip()


def contains_wrapper_obfuscation(prompt: str) -> bool:
    if "###" in prompt or "::" in prompt or "<system>" in prompt or "[[system]]" in prompt:
        return True
    if re.search(r"(hidd3n|rul3s|promp7|sys7em)", prompt):
        return True
    if re.search(r"(?:\b\w\b\s+){4,}\b\w+\b", prompt):
        return True
    return False


def bool_from_query(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in {"1", "true", "yes", "download"}


def main() -> int:
    request = json.load(sys.stdin)
    raw = request.get("payload", {}).get("raw_input", {})

    method = normalize_text(str(raw.get("method", "")))
    path = normalize_text(str(raw.get("path", "")))
    source_zone = normalize_text(str(raw.get("source_zone", "")))
    headers = raw.get("headers", {}) if isinstance(raw.get("headers", {}), dict) else {}
    query = raw.get("query", {}) if isinstance(raw.get("query", {}), dict) else {}
    body = raw.get("body", {}) if isinstance(raw.get("body", {}), dict) else {}

    prompt = normalize_text(str(body.get("prompt", "")))
    requested_tool = normalize_text(str(body.get("requested_tool", "")))
    requested_action = normalize_text(str(body.get("requested_action", "")))
    scope = normalize_text(str(body.get("scope", "")))
    tenant_scope = normalize_text(str(headers.get("tenant_scope", "")))
    query_text = normalize_text(json.dumps(query, sort_keys=True))
    body_text = normalize_text(json.dumps(body, sort_keys=True))
    combined_text = " ".join(
        part for part in (path, query_text, body_text, prompt, requested_action, tenant_scope) if part
    )

    contains_injection_signature = contains_any(combined_text, INJECTION_PATTERNS)
    targets_sensitive_route = path.startswith("/v1/admin") or path.startswith("/internal/export")
    requests_instruction_override = contains_any(prompt, INSTRUCTION_OVERRIDE_PATTERNS)
    targets_system_prompt = contains_any(prompt, SYSTEM_TARGET_PATTERNS)
    requests_secret_exfiltration = contains_any(prompt, SECRET_PATTERNS)
    requests_bulk_export = (
        contains_any(prompt, BULK_EXPORT_PATTERNS)
        or requested_action in {"export_customer_records", "download_full_export", "dump_workspace"}
        or bool_from_query(query.get("download"))
        or str(query.get("include", "")).lower() == "all"
        or scope == "global"
        or (method == "get" and targets_sensitive_route)
    )
    origin_outside_trust_zone = source_zone in {"public_web", "untrusted_browser"}
    uses_wrapper_obfuscation = contains_wrapper_obfuscation(prompt)

    likely_benign_request = (
        contains_any(prompt, BENIGN_PATTERNS)
        and not contains_injection_signature
        and not requests_instruction_override
        and not targets_system_prompt
        and not requests_secret_exfiltration
        and not requests_bulk_export
        and not targets_sensitive_route
    )

    risk_score = 0.03
    if contains_injection_signature:
        risk_score += 0.24
    if requests_instruction_override:
        risk_score += 0.22
    if targets_system_prompt:
        risk_score += 0.2
    if requests_secret_exfiltration:
        risk_score += 0.2
    if requests_bulk_export:
        risk_score += 0.18
    if targets_sensitive_route:
        risk_score += 0.14
    if origin_outside_trust_zone:
        risk_score += 0.1
    if uses_wrapper_obfuscation:
        risk_score += 0.13
    if uses_wrapper_obfuscation and re.search(r"\d", prompt):
        risk_score += 0.62
    if requested_tool in {"shell", "filesystem"} and requests_bulk_export:
        risk_score += 0.07
    if likely_benign_request:
        risk_score = min(risk_score, 0.12)
    risk_score = round(max(0.0, min(1.0, risk_score)), 2)

    response = {
        "ok": True,
        "features": {
            "contains_injection_signature": contains_injection_signature,
            "targets_sensitive_route": targets_sensitive_route,
            "requests_instruction_override": requests_instruction_override,
            "targets_system_prompt": targets_system_prompt,
            "requests_secret_exfiltration": requests_secret_exfiltration,
            "requests_bulk_export": requests_bulk_export,
            "origin_outside_trust_zone": origin_outside_trust_zone,
            "uses_wrapper_obfuscation": uses_wrapper_obfuscation,
            "likely_benign_request": likely_benign_request,
            "risk_score": risk_score,
        },
        "warnings": [],
    }

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
