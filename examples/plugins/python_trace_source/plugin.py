import csv
import json
import sys


def parse_allowed(raw: str) -> bool:
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "allow", "allowed"}:
        return True
    if value in {"0", "false", "no", "n", "deny", "denied"}:
        return False
    raise ValueError(f"unsupported label value: {raw!r}")


def parse_scalar(raw: str):
    value = raw.strip()
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})
    source = payload["source"]
    options = payload.get("options", {})
    label_column = options.get("label_column", "allowed")

    with open(source, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            features = {}
            for key, value in row.items():
                if key == label_column:
                    continue
                features[key] = parse_scalar(value)
            rows.append(
                {
                    "features": features,
                    "allowed": parse_allowed(row[label_column]),
                }
            )

    response = {
        "ok": True,
        "decision_traces": rows,
        "warnings": [],
    }
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
