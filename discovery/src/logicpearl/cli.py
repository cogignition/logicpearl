from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .ir import evaluate_gate, load_gate_ir


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a LogicPearl Gate IR against an input JSON file.")
    parser.add_argument("gate", type=Path, help="Path to the gate IR JSON file")
    parser.add_argument("input", type=Path, help="Path to the input feature JSON file")
    args = parser.parse_args()

    gate = load_gate_ir(args.gate)
    features = load_input_features(args.input)
    bitmask = evaluate_gate(gate, features)
    print(bitmask)
    return 0


def load_input_features(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("input JSON must be an object mapping feature names to values")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
