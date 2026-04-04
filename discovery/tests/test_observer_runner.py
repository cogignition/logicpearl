from __future__ import annotations

import json
from pathlib import Path

from logicpearl.ir import evaluate_gate, load_gate_ir
from logicpearl.observer import load_observer_spec
from logicpearl.observer.runner import execute_observer, validate_feature_payload


V3_ROOT = Path(__file__).resolve().parents[2]
EVAL_FIXTURE = V3_ROOT / "fixtures" / "observer" / "eval" / "auth-observer-v1-cases.json"


def test_observer_eval_cases() -> None:
    payload = json.loads(EVAL_FIXTURE.read_text(encoding="utf-8"))
    observer = load_observer_spec(V3_ROOT / "fixtures" / payload["observer_fixture"])
    gate = load_gate_ir(V3_ROOT / "fixtures" / payload["gate_fixture"])

    for case in payload["cases"]:
        features = execute_observer(observer, case["raw_input"])
        validate_feature_payload(features, observer.to_feature_contract())
        bitmask = evaluate_gate(gate, features)

        assert features == case["expected_features"]
        assert bitmask == case["expected_bitmask"]
