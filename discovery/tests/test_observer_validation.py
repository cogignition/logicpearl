from __future__ import annotations

from pathlib import Path

from logicpearl.observer.validation import (
    load_observer_eval_cases,
    validate_observer_cases,
)


V3_ROOT = Path(__file__).resolve().parents[2]
EVAL_FIXTURE = V3_ROOT / "fixtures" / "observer" / "eval" / "auth-observer-v1-cases.json"


def test_validation_report_has_full_coverage_and_kills_mutants() -> None:
    observer, gate, cases = load_observer_eval_cases(EVAL_FIXTURE)
    report = validate_observer_cases(observer, gate, cases)

    assert report.exact_match_passed is True
    assert report.uncovered_mappings == []
    assert report.killed_mutants == report.total_mutants
    assert report.mutation_score == 1.0
