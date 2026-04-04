import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    records = request.get("payload", {}).get("records", [])

    enriched = []
    for record in records:
        features = dict(record.get("features", {}))
        age = features.get("age")
        if isinstance(age, (int, float)):
            features["is_adult"] = 1 if age >= 18 else 0
        enriched.append(
            {
                "features": features,
                "allowed": record.get("allowed", False),
            }
        )

    response = {
        "ok": True,
        "records": enriched,
        "warnings": [],
    }
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
