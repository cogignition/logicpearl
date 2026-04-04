from pathlib import Path

from logicpearl.build_pearl_cli import build_pearl_from_csv, load_decision_traces
from logicpearl.ir import load_gate_ir


def test_load_decision_traces_parses_allowed_column(tmp_path: Path) -> None:
    csv_path = tmp_path / "decision_traces.csv"
    csv_path.write_text(
        "age,is_member,allowed\n"
        "21,1,allowed\n"
        "15,1,denied\n",
        encoding="utf-8",
    )

    rows = load_decision_traces(csv_path)

    assert len(rows) == 2
    assert rows[0].features == {"age": 21, "is_member": 1}
    assert rows[0].allowed is True
    assert rows[1].allowed is False


def test_build_pearl_from_csv_emits_gate_ir_and_report(tmp_path: Path) -> None:
    csv_path = tmp_path / "decision_traces.csv"
    csv_path.write_text(
        "age,is_member,allowed\n"
        "21,1,allowed\n"
        "25,0,allowed\n"
        "30,1,allowed\n"
        "35,0,allowed\n"
        "16,1,denied\n"
        "15,0,denied\n"
        "14,1,denied\n"
        "13,0,denied\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"

    result = build_pearl_from_csv(csv_path, output_dir=output_dir, gate_id="age_gate")

    gate_ir = load_gate_ir(output_dir / "pearl.ir.json")

    assert result["rows"] == 8
    assert result["rules_discovered"] >= 1
    assert result["training_parity"] == 1.0
    assert gate_ir.gate_id == "age_gate"
    assert gate_ir.rules
    assert (output_dir / "build_report.json").exists()
