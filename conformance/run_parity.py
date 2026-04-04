from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


V3_ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_DIR = V3_ROOT / "discovery"
RUNTIME_DIR = V3_ROOT / "runtime"
FIXTURES_DIR = V3_ROOT / "fixtures"
EVAL_FIXTURES_DIR = FIXTURES_DIR / "ir" / "eval"


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    expected_bitmask: int
    discovery_bitmask: int
    runtime_bitmask: int


def main() -> int:
    eval_files = sorted(EVAL_FIXTURES_DIR.glob("*-cases.json"))
    if not eval_files:
        print("No evaluation fixtures found.", file=sys.stderr)
        return 1

    all_results: list[CaseResult] = []
    for eval_file in eval_files:
        all_results.extend(run_eval_fixture(eval_file))

    for result in all_results:
        print(
            f"{result.case_id}: expected={result.expected_bitmask} "
            f"discovery={result.discovery_bitmask} runtime={result.runtime_bitmask}"
        )

    print(f"Conformance passed for {len(all_results)} cases.")
    return 0


def run_eval_fixture(eval_file: Path) -> list[CaseResult]:
    payload = json.loads(eval_file.read_text(encoding="utf-8"))
    gate_path = FIXTURES_DIR / payload["gate_fixture"]
    cases = payload["cases"]

    results: list[CaseResult] = []
    for case in cases:
        case_input_path = write_case_input(eval_file.stem, case["id"], case["input"])
        discovery_bitmask = run_discovery_cli(gate_path, case_input_path)
        runtime_bitmask = run_runtime_cli(gate_path, case_input_path)
        expected_bitmask = int(case["expected_bitmask"])

        if discovery_bitmask != expected_bitmask:
            raise SystemExit(
                f"Discovery mismatch for {case['id']}: expected {expected_bitmask}, got {discovery_bitmask}"
            )
        if runtime_bitmask != expected_bitmask:
            raise SystemExit(
                f"Runtime mismatch for {case['id']}: expected {expected_bitmask}, got {runtime_bitmask}"
            )
        if discovery_bitmask != runtime_bitmask:
            raise SystemExit(
                f"Implementation mismatch for {case['id']}: "
                f"discovery={discovery_bitmask}, runtime={runtime_bitmask}"
            )

        results.append(
            CaseResult(
                case_id=case["id"],
                expected_bitmask=expected_bitmask,
                discovery_bitmask=discovery_bitmask,
                runtime_bitmask=runtime_bitmask,
            )
        )

    return results


def write_case_input(eval_fixture_stem: str, case_id: str, payload: dict[str, object]) -> Path:
    inputs_dir = EVAL_FIXTURES_DIR / ".generated-inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    output_path = inputs_dir / f"{eval_fixture_stem}--{case_id}.json"
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return output_path


def run_discovery_cli(gate_path: Path, input_path: Path) -> int:
    proc = subprocess.run(
        [
            "uv",
            "run",
            "logicpearl-discovery",
            str(gate_path),
            str(input_path),
        ],
        cwd=DISCOVERY_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_bitmask(proc.stdout)


def run_runtime_cli(gate_path: Path, input_path: Path) -> int:
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--",
            str(gate_path),
            str(input_path),
        ],
        cwd=RUNTIME_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_bitmask(proc.stdout)


def parse_bitmask(stdout: str) -> int:
    stripped = stdout.strip()
    if not stripped:
        raise ValueError("CLI returned empty output")
    return int(stripped.splitlines()[-1])


if __name__ == "__main__":
    raise SystemExit(main())
