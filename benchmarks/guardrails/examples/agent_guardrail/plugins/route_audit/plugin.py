import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})
    canonical_input = payload.get("input", {})

    allow = bool(canonical_input.get("allow", False))
    bitmask = int(canonical_input.get("bitmask", 0))
    tool = int(canonical_input.get("tool_authorization_bitmask", 0))
    boundary = int(canonical_input.get("instruction_boundary_bitmask", 0))
    exfil = int(canonical_input.get("data_exfiltration_bitmask", 0))
    attack_confidence = float(canonical_input.get("attack_confidence", 0.0))
    benign = bool(canonical_input.get("is_likely_benign_question", False))

    if allow:
        route_status = "allow"
        decision_basis = "no_guardrail_triggered"
    elif boundary > 0:
        route_status = "deny_untrusted_instruction"
        decision_basis = "instruction_boundary"
    elif tool > 0:
        route_status = "deny_tool_use"
        decision_basis = "tool_authorization"
    elif exfil > 0:
        route_status = "deny_exfiltration_risk"
        decision_basis = "data_exfiltration"
    elif attack_confidence >= 0.85 and not benign:
        route_status = "needs_human_review"
        decision_basis = "high_attack_confidence"
    else:
        route_status = "deny"
        decision_basis = "route_status_gate"

    response = {
        "ok": True,
        "route_status": route_status,
        "decision_basis": decision_basis,
        "summary": {
            "allow": allow,
            "bitmask": bitmask,
            "consistent": (allow and bitmask == 0) or ((not allow) and bitmask != 0),
        },
        "warnings": [],
    }

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
