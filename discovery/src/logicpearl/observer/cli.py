from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .loaders import load_observer_spec
from .runner import execute_observer


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a LogicPearl observer spec against a raw-input JSON file."
    )
    parser.add_argument("observer", type=Path, help="Path to the observer spec JSON file")
    parser.add_argument("input", type=Path, help="Path to the raw input JSON file")
    args = parser.parse_args()

    observer = load_observer_spec(args.observer)
    raw_input = load_input_payload(args.input)
    features = execute_observer(observer, raw_input)
    print(json.dumps(features, indent=2, sort_keys=True))
    return 0


def load_input_payload(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("input JSON must be an object")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
