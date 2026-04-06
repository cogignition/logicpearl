import json
import sys


def audit_payload(payload: dict) -> dict:
    allow = bool(payload.get("allow", False))
    bitmask = int(payload.get("bitmask", 0))
    injection_payload = int(payload.get("injection_payload_bitmask", 0))
    sensitive_surface = int(payload.get("sensitive_surface_bitmask", 0))
    has_scanner_fingerprint = bool(payload.get("has_scanner_fingerprint", False))
    has_malformed_encoding = bool(payload.get("has_malformed_encoding", False))
    risk_score = float(payload.get("risk_score", 0.0))
    likely_benign = bool(payload.get("likely_benign_request", False))

    if allow:
        route_status = "allow"
        decision_basis = "no_waf_family_triggered"
        explanation = "The request looks like normal application traffic and no denial pearl fired."
        counterfactual = "No changes required."
    elif injection_payload > 0:
        route_status = "deny_injection_payload"
        decision_basis = "injection_payload"
        explanation = "The request contains SQL injection, XSS, or path traversal content."
        counterfactual = "Remove the exploit payload and keep parameters in their expected application format."
    elif sensitive_surface > 0:
        route_status = "deny_sensitive_surface"
        decision_basis = "sensitive_surface"
        explanation = "The request targets a sensitive route from an untrusted zone."
        counterfactual = "Move privileged traffic behind the trusted boundary and keep public requests off admin and export paths."
    elif bitmask & (1 << 1):
        route_status = "review_suspicious_request"
        decision_basis = "scanner_or_probe"
        explanation = "The request looks scanner-like or malformed enough to warrant review without treating it as a hard exploit match."
        counterfactual = "Use standard browser-style requests and remove scanner fingerprints or malformed encodings."
    else:
        route_status = "deny"
        decision_basis = "route_status"
        explanation = "The route pearl denied the request."
        counterfactual = "Reduce risk features until the request stays inside the allowed traffic shape."

    return {
        "ok": True,
        "route_status": route_status,
        "decision_basis": decision_basis,
        "explanation": explanation,
        "counterfactual": counterfactual,
        "summary": {
            "allow": allow,
            "bitmask": bitmask,
            "has_scanner_fingerprint": has_scanner_fingerprint,
            "has_malformed_encoding": has_malformed_encoding,
            "risk_score": risk_score,
            "likely_benign_request": likely_benign,
            "consistent": (allow and bitmask == 0) or ((not allow) and bitmask != 0),
        },
        "warnings": [],
    }


def main() -> int:
    request = json.load(sys.stdin)
    if "payloads" in request:
        responses = [audit_payload(payload) for payload in request.get("payloads", [])]
        json.dump({"ok": True, "responses": responses, "warnings": []}, sys.stdout)
        sys.stdout.write("\n")
        return 0

    payload = request.get("payload", {})
    response = audit_payload(payload)

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
