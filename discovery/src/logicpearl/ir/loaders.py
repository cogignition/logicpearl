from __future__ import annotations

import json
from pathlib import Path

from .models import LogicPearlGateIR


def load_gate_ir(path: str | Path) -> LogicPearlGateIR:
    ir_path = Path(path)
    with ir_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return LogicPearlGateIR.model_validate(payload)


def dump_gate_ir(gate: LogicPearlGateIR, path: str | Path, *, indent: int = 2) -> None:
    ir_path = Path(path)
    ir_path.parent.mkdir(parents=True, exist_ok=True)
    with ir_path.open("w", encoding="utf-8") as handle:
        json.dump(gate.model_dump(mode="json", by_alias=True), handle, indent=indent)
        handle.write("\n")
