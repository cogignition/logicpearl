from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from logicpearl.ir import LogicPearlGateIR, evaluate_gate, load_gate_ir

from .loaders import load_observer_spec
from .models import MappingKind, ObserverSpec, RawFieldDefinition
from .runner import execute_observer, validate_feature_payload


@dataclass(frozen=True)
class ObserverEvalCase:
    case_id: str
    raw_input: dict[str, Any]
    expected_features: dict[str, Any]
    expected_bitmask: int


@dataclass(frozen=True)
class MappingCoverage:
    feature_id: str
    kind: str
    cases_seen: int
    distinct_outputs: int
    true_outputs: int | None
    false_outputs: int | None
    fully_exercised: bool


@dataclass(frozen=True)
class MutationResult:
    mutant_id: str
    killed: bool
    reason: str


@dataclass(frozen=True)
class ObserverValidationReport:
    observer_id: str
    case_count: int
    exact_match_passed: bool
    uncovered_mappings: list[str]
    coverage: list[MappingCoverage]
    mutation_score: float
    killed_mutants: int
    total_mutants: int
    mutation_results: list[MutationResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "observer_id": self.observer_id,
            "case_count": self.case_count,
            "exact_match_passed": self.exact_match_passed,
            "uncovered_mappings": self.uncovered_mappings,
            "coverage": [asdict(item) for item in self.coverage],
            "mutation_score": self.mutation_score,
            "killed_mutants": self.killed_mutants,
            "total_mutants": self.total_mutants,
            "mutation_results": [asdict(item) for item in self.mutation_results],
        }


def load_observer_eval_cases(path: str | Path) -> tuple[ObserverSpec, LogicPearlGateIR, list[ObserverEvalCase]]:
    eval_path = Path(path)
    v3_root = eval_path.resolve().parents[2]
    payload = json.loads(eval_path.read_text(encoding="utf-8"))
    observer = load_observer_spec(v3_root / payload["observer_fixture"])
    gate = load_gate_ir(v3_root / payload["gate_fixture"])
    cases = [
        ObserverEvalCase(
            case_id=case["id"],
            raw_input=case["raw_input"],
            expected_features=case["expected_features"],
            expected_bitmask=int(case["expected_bitmask"]),
        )
        for case in payload["cases"]
    ]
    return observer, gate, cases


def validate_observer_cases(
    spec: ObserverSpec,
    gate: LogicPearlGateIR,
    cases: list[ObserverEvalCase],
) -> ObserverValidationReport:
    exact_match_passed = True
    for case in cases:
        features = execute_observer(spec, case.raw_input)
        validate_feature_payload(features, spec.to_feature_contract())
        bitmask = evaluate_gate(gate, features)
        if features != case.expected_features or bitmask != case.expected_bitmask:
            exact_match_passed = False
            break

    coverage = summarize_mapping_coverage(spec, cases)
    uncovered_mappings = [item.feature_id for item in coverage if not item.fully_exercised]
    mutation_results = run_mutation_analysis(spec, gate, cases)
    killed_mutants = sum(1 for result in mutation_results if result.killed)
    total_mutants = len(mutation_results)
    mutation_score = 1.0 if total_mutants == 0 else killed_mutants / total_mutants

    return ObserverValidationReport(
        observer_id=spec.observer_id,
        case_count=len(cases),
        exact_match_passed=exact_match_passed,
        uncovered_mappings=uncovered_mappings,
        coverage=coverage,
        mutation_score=mutation_score,
        killed_mutants=killed_mutants,
        total_mutants=total_mutants,
        mutation_results=mutation_results,
    )


def summarize_mapping_coverage(
    spec: ObserverSpec,
    cases: list[ObserverEvalCase],
) -> list[MappingCoverage]:
    coverage: list[MappingCoverage] = []

    for mapping in spec.mappings:
        outputs = [case.expected_features[mapping.feature_id] for case in cases]
        distinct_outputs = len({json.dumps(value, sort_keys=True) for value in outputs})
        true_outputs = None
        false_outputs = None
        fully_exercised = True

        if all(isinstance(output, bool) for output in outputs):
            true_outputs = sum(1 for output in outputs if output is True)
            false_outputs = sum(1 for output in outputs if output is False)
            fully_exercised = true_outputs > 0 and false_outputs > 0
        elif mapping.kind == MappingKind.FIELD_COPY:
            raw_field = _find_raw_field(spec, mapping.raw_field)
            fully_exercised = _field_copy_is_exercised(raw_field, distinct_outputs)
        else:
            fully_exercised = distinct_outputs > 1

        coverage.append(
            MappingCoverage(
                feature_id=mapping.feature_id,
                kind=str(mapping.kind),
                cases_seen=len(cases),
                distinct_outputs=distinct_outputs,
                true_outputs=true_outputs,
                false_outputs=false_outputs,
                fully_exercised=fully_exercised,
            )
        )

    return coverage


def run_mutation_analysis(
    spec: ObserverSpec,
    gate: LogicPearlGateIR,
    cases: list[ObserverEvalCase],
) -> list[MutationResult]:
    results: list[MutationResult] = []
    raw_fields = {field.id: field for field in spec.raw_schema.fields}

    for mapping_index, mapping in enumerate(spec.mappings):
        mutant_payload = spec.model_dump(mode="json", by_alias=True)
        mutated_mapping = mutant_payload["mappings"][mapping_index]
        mutant_id_prefix = f"{mapping.feature_id}:{mapping.kind}"

        if mapping.kind == MappingKind.FIELD_EQUALS and mapping.raw_field is not None:
            replacement = _pick_alternate_value(raw_fields[mapping.raw_field], mapping.value)
            if replacement is None:
                continue
            mutated_mapping["value"] = replacement
            results.append(
                _score_mutant(
                    mutant_payload,
                    gate,
                    cases,
                    mutant_id=f"{mutant_id_prefix}:replace_value",
                )
            )
        elif mapping.kind == MappingKind.FIELD_IN_SET and mapping.raw_field is not None:
            replacement_values = _mutate_value_set(raw_fields[mapping.raw_field], mapping.values or [])
            if replacement_values is None:
                continue
            mutated_mapping["values"] = replacement_values
            results.append(
                _score_mutant(
                    mutant_payload,
                    gate,
                    cases,
                    mutant_id=f"{mutant_id_prefix}:mutate_set",
                )
            )
        elif mapping.kind == MappingKind.FEATURE_ALL_TRUE:
            mutated_mapping["kind"] = MappingKind.FEATURE_ANY_TRUE.value
            results.append(
                _score_mutant(
                    mutant_payload,
                    gate,
                    cases,
                    mutant_id=f"{mutant_id_prefix}:swap_to_any",
                )
            )
        elif mapping.kind == MappingKind.FEATURE_ANY_TRUE:
            mutated_mapping["kind"] = MappingKind.FEATURE_ALL_TRUE.value
            results.append(
                _score_mutant(
                    mutant_payload,
                    gate,
                    cases,
                    mutant_id=f"{mutant_id_prefix}:swap_to_all",
                )
            )

    return results


def _score_mutant(
    mutant_payload: dict[str, Any],
    gate: LogicPearlGateIR,
    cases: list[ObserverEvalCase],
    *,
    mutant_id: str,
) -> MutationResult:
    mutant_spec = ObserverSpec.model_validate(mutant_payload)

    for case in cases:
        features = execute_observer(mutant_spec, case.raw_input)
        bitmask = evaluate_gate(gate, features)
        if features != case.expected_features:
            return MutationResult(mutant_id=mutant_id, killed=True, reason=f"feature drift on {case.case_id}")
        if bitmask != case.expected_bitmask:
            return MutationResult(mutant_id=mutant_id, killed=True, reason=f"bitmask drift on {case.case_id}")

    return MutationResult(mutant_id=mutant_id, killed=False, reason="survived all cases")


def _find_raw_field(spec: ObserverSpec, raw_field_id: str | None) -> RawFieldDefinition | None:
    if raw_field_id is None:
        return None
    for field in spec.raw_schema.fields:
        if field.id == raw_field_id:
            return field
    return None


def _field_copy_is_exercised(raw_field: RawFieldDefinition | None, distinct_outputs: int) -> bool:
    if raw_field is None:
        return False
    if raw_field.type == "bool":
        return distinct_outputs >= 2
    if raw_field.type == "enum" and raw_field.values is not None:
        return distinct_outputs >= min(2, len(raw_field.values))
    return distinct_outputs >= 2


def _pick_alternate_value(field: RawFieldDefinition, current_value: Any) -> Any | None:
    if field.type == "bool":
        return not bool(current_value)
    if field.type == "enum":
        for candidate in field.values or []:
            if candidate != current_value:
                return candidate
        return None
    if field.type == "string":
        return "__mutated__" if current_value != "__mutated__" else "__mutated_alt__"
    if field.type == "int":
        candidate = int(current_value) + 1
        if field.max is not None and candidate > field.max:
            candidate = int(current_value) - 1
        if field.min is not None and candidate < field.min:
            return None
        return candidate
    if field.type == "float":
        candidate = float(current_value) + 1.0
        if field.max is not None and candidate > field.max:
            candidate = float(current_value) - 1.0
        if field.min is not None and candidate < field.min:
            return None
        return candidate
    return None


def _mutate_value_set(field: RawFieldDefinition, values: list[Any]) -> list[Any] | None:
    if field.type == "enum":
        allowed = list(field.values or [])
        if not allowed:
            return None
        if len(values) > 1:
            return values[:-1]
        for candidate in allowed:
            if candidate not in values:
                return [candidate]
        return None
    if field.type == "bool":
        return [not bool(values[0])] if values else [True]
    alternate = _pick_alternate_value(field, values[0] if values else None)
    return None if alternate is None else [alternate]
