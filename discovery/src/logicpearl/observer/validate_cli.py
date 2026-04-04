from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validation import load_observer_eval_cases, validate_observer_cases


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an observer spec against shared raw-input fixtures."
    )
    parser.add_argument("eval_fixture", type=Path, help="Path to the observer eval fixture JSON file")
    args = parser.parse_args()

    observer, gate, cases = load_observer_eval_cases(args.eval_fixture)
    report = validate_observer_cases(observer, gate, cases)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
