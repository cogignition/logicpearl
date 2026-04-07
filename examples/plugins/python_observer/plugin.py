import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    payload = request.get("payload", {})
    raw = payload.get("input", payload.get("raw_input", {}))

    response = {
        "ok": True,
        "features": {
            "age": raw.get("age"),
            "is_member": 1 if raw.get("member") else 0,
            "country": raw.get("country"),
        },
        "warnings": [],
    }

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
