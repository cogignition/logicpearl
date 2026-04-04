from __future__ import annotations

import json
from pathlib import Path

from .models import ObserverSpec


def load_observer_spec(path: str | Path) -> ObserverSpec:
    spec_path = Path(path)
    with spec_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return ObserverSpec.model_validate(payload)


def dump_observer_spec(spec: ObserverSpec, path: str | Path, *, indent: int = 2) -> None:
    spec_path = Path(path)
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    with spec_path.open("w", encoding="utf-8") as handle:
        json.dump(spec.model_dump(mode="json", by_alias=True), handle, indent=indent)
        handle.write("\n")
