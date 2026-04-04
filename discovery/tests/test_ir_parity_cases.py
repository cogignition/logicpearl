import json
from pathlib import Path

from logicpearl.ir import evaluate_gate, load_gate_ir


V3_ROOT = Path(__file__).resolve().parents[2]
EVAL_FIXTURE = V3_ROOT / "fixtures" / "ir" / "eval" / "auth-demo-v1-cases.json"


def test_eval_cases_match_expected_bitmasks() -> None:
    payload = json.loads(EVAL_FIXTURE.read_text(encoding="utf-8"))
    gate = load_gate_ir(V3_ROOT / "fixtures" / payload["gate_fixture"])

    for case in payload["cases"]:
        assert evaluate_gate(gate, case["input"]) == case["expected_bitmask"], case["id"]
