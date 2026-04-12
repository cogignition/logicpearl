import csv
import json
import sys


def parse_scalar(raw: str):
    value = raw.strip()
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    is_percent = value.endswith("%")
    numeric = value[:-1].strip() if is_percent else value
    numeric = numeric.replace(",", "")
    if numeric[:1] in "$€£¥":
        numeric = numeric[1:].strip()
    try:
        parsed = int(numeric)
        return parsed / 100 if is_percent else parsed
    except ValueError:
        try:
            parsed = float(numeric)
            return parsed / 100 if is_percent else parsed
        except ValueError:
            return value


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})
    source = payload.get("input")
    if source is None:
        raise KeyError("payload.input")

    with open(source, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        records = [
            {key: parse_scalar(value) for key, value in row.items()}
            for row in reader
        ]

    json.dump({"ok": True, "records": records, "warnings": []}, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
