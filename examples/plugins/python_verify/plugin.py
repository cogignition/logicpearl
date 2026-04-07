import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})
    pearl_ir = payload.get("input", payload.get("pearl_ir", {}))
    rules = pearl_ir.get("rules", [])

    statuses = []
    summary = {}
    for rule in rules:
        status = rule.get("verification_status") or "pipeline_unverified"
        statuses.append(
            {
                "rule_id": rule.get("id"),
                "status": status,
            }
        )
        summary[status] = summary.get(status, 0) + 1

    response = {
        "ok": True,
        "rule_statuses": statuses,
        "summary": summary,
        "warnings": [],
    }
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
