import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})
    canonical_input = payload.get("input", {})
    bitmask = int(canonical_input.get("bitmask", 0))
    allow = bool(canonical_input.get("allow", False))

    if allow and bitmask == 0:
        audit_status = "clean_pass"
    elif allow and bitmask != 0:
        audit_status = "inconsistent_allow"
    else:
        audit_status = "denied_or_flagged"

    response = {
        "ok": True,
        "audit_status": audit_status,
        "summary": {
            "bitmask": bitmask,
            "allow": allow,
            "consistent": (allow and bitmask == 0) or ((not allow) and bitmask != 0),
        },
        "warnings": [],
    }
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
