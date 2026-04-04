from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import DiscoveryPipelineConfig, compile_gate, discover_rules, serialize_rules_to_gate_ir
from .ir import dump_gate_ir


@dataclass(frozen=True)
class DecisionTraceRow:
    features: dict[str, Any]
    allowed: bool


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a LogicPearl artifact from labeled decision traces in CSV form."
    )
    parser.add_argument("decision_traces", type=Path, help="Path to a CSV file of labeled decision traces")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to write pearl.ir.json and build_report.json into (defaults to <csv-dir>/output/<stem>)",
    )
    parser.add_argument(
        "--gate-id",
        default=None,
        help="Gate ID to embed in the emitted pearl (defaults to the CSV file stem)",
    )
    parser.add_argument(
        "--label-column",
        default="allowed",
        help="Column name for the decision label (default: allowed)",
    )
    parser.add_argument("--max-depth", type=int, default=4, help="Max tree depth during discovery")
    parser.add_argument("--min-samples-leaf", type=int, default=1, help="Minimum samples per leaf during discovery")
    parser.add_argument("--max-rules", type=int, default=30, help="Maximum number of discovered rules")
    args = parser.parse_args()

    output_dir = args.output_dir or args.decision_traces.parent / "output" / args.decision_traces.stem
    result = build_pearl_from_csv(
        args.decision_traces,
        output_dir=output_dir,
        gate_id=args.gate_id or args.decision_traces.stem,
        label_column=args.label_column,
        config=DiscoveryPipelineConfig(
            max_depth=args.max_depth,
            min_samples_leaf=args.min_samples_leaf,
            max_rules=args.max_rules,
        ),
    )

    print(f"Decision traces: {args.decision_traces}")
    print(f"Rows: {result['rows']}")
    print(f"Rules discovered: {result['rules_discovered']}")
    print(f"Training parity: {result['training_parity']:.1%}")
    print(f"Pearl IR: {result['pearl_ir_path']}")
    print(f"Build report: {result['build_report_path']}")
    return 0


def build_pearl_from_csv(
    csv_path: Path,
    *,
    output_dir: Path,
    gate_id: str,
    label_column: str = "allowed",
    config: DiscoveryPipelineConfig | None = None,
) -> dict[str, Any]:
    rows = load_decision_traces(csv_path, label_column=label_column)
    if not rows:
        raise ValueError("decision trace CSV is empty")

    labeled_cases = [
        ({key: float(value) for key, value in row.features.items()}, "allowed" if row.allowed else "denied")
        for row in rows
    ]
    discovery_result = discover_rules(labeled_cases, config=config)
    gate = compile_gate(discovery_result.rules)

    feature_sample = rows[0].features
    pearl_ir = serialize_rules_to_gate_ir(
        discovery_result.rules,
        gate_id=gate_id,
        feature_sample=feature_sample,
        generator="logicpearl.build_pearl_cli",
        generator_version="0.1.0",
        correctness_scope=f"training parity against {len(rows)} decision traces",
        verification_summary={"pipeline_unverified": len(discovery_result.rules)},
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    pearl_ir_path = output_dir / "pearl.ir.json"
    dump_gate_ir(pearl_ir, pearl_ir_path)

    correct = 0
    for row in rows:
        allowed = gate.is_allowed({key: float(value) for key, value in row.features.items()})
        if allowed == row.allowed:
            correct += 1
    training_parity = correct / len(rows)

    build_report = {
        "source_csv": str(csv_path),
        "gate_id": gate_id,
        "rows": len(rows),
        "label_column": label_column,
        "rules_discovered": len(discovery_result.rules),
        "selected_features": discovery_result.selected_features,
        "training_parity": training_parity,
        "output_files": {
            "pearl_ir": str(pearl_ir_path),
        },
    }
    build_report_path = output_dir / "build_report.json"
    build_report_path.write_text(json.dumps(build_report, indent=2) + "\n", encoding="utf-8")

    return {
        "rows": len(rows),
        "rules_discovered": len(discovery_result.rules),
        "training_parity": training_parity,
        "pearl_ir_path": str(pearl_ir_path),
        "build_report_path": str(build_report_path),
    }


def load_decision_traces(csv_path: Path, *, label_column: str = "allowed") -> list[DecisionTraceRow]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("decision trace CSV must include a header row")
        if label_column not in reader.fieldnames:
            raise ValueError(f"decision trace CSV is missing required label column: {label_column!r}")

        rows: list[DecisionTraceRow] = []
        for index, raw_row in enumerate(reader, start=2):
            features: dict[str, Any] = {}
            for key, value in raw_row.items():
                if key == label_column:
                    continue
                if value is None or value == "":
                    raise ValueError(f"row {index} has an empty value for feature {key!r}")
                features[key] = _parse_scalar(value)
            rows.append(
                DecisionTraceRow(
                    features=features,
                    allowed=_parse_allowed_label(raw_row[label_column], row_number=index, label_column=label_column),
                )
            )
    return rows


def _parse_allowed_label(raw: str | None, *, row_number: int, label_column: str) -> bool:
    if raw is None:
        raise ValueError(f"row {row_number} is missing label column {label_column!r}")
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "allow", "allowed"}:
        return True
    if value in {"0", "false", "no", "n", "deny", "denied"}:
        return False
    raise ValueError(
        f"row {row_number} has unsupported label value {raw!r} in column {label_column!r}; "
        "use allowed/denied or 1/0"
    )


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        if "." not in value and "e" not in lowered:
            return int(value)
        return float(value)
    except ValueError:
        return value


if __name__ == "__main__":
    raise SystemExit(main())
