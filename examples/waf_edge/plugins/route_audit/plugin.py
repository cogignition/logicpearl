import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})

    allow = bool(payload.get("allow", False))
    bitmask = int(payload.get("bitmask", 0))
    request_abuse = int(payload.get("request_abuse_bitmask", 0))
    instruction_boundary = int(payload.get("instruction_boundary_bitmask", 0))
    data_exfiltration = int(payload.get("data_exfiltration_bitmask", 0))
    risk_score = float(payload.get("risk_score", 0.0))
    likely_benign = bool(payload.get("likely_benign_request", False))

    if allow:
        route_status = "allow"
        decision_basis = "no_guardrail_triggered"
        explanation = "The request stays inside the tenant-scoped support workflow and no denial pearl fired."
        counterfactual = "No changes required."
    elif request_abuse > 0:
        route_status = "deny_request_abuse"
        decision_basis = "request_abuse"
        explanation = "The request hit a sensitive route from an untrusted zone or carried a classic injection signature."
        counterfactual = "Keep the request on the public support route and remove injection or traversal patterns."
    elif instruction_boundary > 0:
        route_status = "deny_instruction_boundary"
        decision_basis = "instruction_boundary"
        explanation = "The prompt tries to override trusted instructions or expose hidden system behavior."
        counterfactual = "Ask for the allowed support task directly without requesting hidden prompts, rules, or overrides."
    elif data_exfiltration > 0:
        route_status = "deny_data_exfiltration"
        decision_basis = "data_exfiltration"
        explanation = "The request asks for secrets or a bulk export that does not belong on the public edge."
        counterfactual = "Restrict the request to tenant-scoped records and remove credential or full-export asks."
    elif bitmask & (1 << 1):
        route_status = "review_suspicious_request"
        decision_basis = "high_risk_probe"
        explanation = "No deny pearl fired, but the request is still obfuscated or unusual enough to warrant human review."
        counterfactual = "Rewrite the request in plain language and remove wrapper tokens or hidden-rule references."
    else:
        route_status = "deny"
        decision_basis = "route_status"
        explanation = "The route pearl denied the request."
        counterfactual = "Reduce risk features until the request stays inside the allowed support workflow."

    response = {
        "ok": True,
        "route_status": route_status,
        "decision_basis": decision_basis,
        "explanation": explanation,
        "counterfactual": counterfactual,
        "summary": {
            "allow": allow,
            "bitmask": bitmask,
            "risk_score": risk_score,
            "likely_benign_request": likely_benign,
            "consistent": (allow and bitmask == 0) or ((not allow) and bitmask != 0),
        },
        "warnings": [],
    }

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
