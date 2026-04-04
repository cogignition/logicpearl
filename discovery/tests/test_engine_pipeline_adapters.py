from dataclasses import dataclass

from logicpearl.engine import (
    Condition,
    DiscoveryPipelineConfig,
    DiscoveryPipelineResult,
    VerificationStatus,
    WasmCompilationResult,
    compile_ensemble_to_circuit,
    compile_gate,
    compile_gate_to_wasm,
    discover_rules,
    coerce_discovery_result,
)


@dataclass
class FakeBackendRule:
    conditions: list[Condition]


@dataclass
class FakeBackendGate:
    rules: list[FakeBackendRule]


@dataclass
class FakeBackendResult:
    gate: FakeBackendGate
    z3_valid: list[bool]
    selected_features: list[str]
    correctness: str


def test_coerce_discovery_result_normalizes_backend_result() -> None:
    backend = FakeBackendResult(
        gate=FakeBackendGate(rules=[FakeBackendRule(conditions=[Condition("late_filing", ">", 0.5)])]),
        z3_valid=[True],
        selected_features=["late_filing"],
        correctness="ok",
    )

    result = coerce_discovery_result(backend)

    assert isinstance(result, DiscoveryPipelineResult)
    assert result.verification_statuses == [VerificationStatus.Z3_VERIFIED]
    assert result.selected_features == ["late_filing"]
    assert result.correctness == "ok"
    assert len(result.rules) == 1
    assert result.rules[0].conditions[0].feature == "late_filing"
    assert result.rules[0].verification_status is VerificationStatus.Z3_VERIFIED


def test_wasm_result_dataclass_shape() -> None:
    result = WasmCompilationResult(rust_source="fn main() {}", wasm_size_bytes=1234)
    assert result.rust_source.startswith("fn")
    assert result.wasm_size_bytes == 1234


def test_compile_gate_to_wasm_generates_rust_source() -> None:
    gate = compile_gate([FakeBackendRule(conditions=[Condition("late_filing", ">", 0.5)])])
    result = compile_gate_to_wasm(gate)

    assert "pub extern \"C\" fn evaluate" in result.rust_source
    assert "late_filing" in result.rust_source


def test_compile_ensemble_to_circuit_runs_natively_for_sklearn_tree() -> None:
    from sklearn.tree import DecisionTreeClassifier

    feature_names = ["late_filing", "in_hmo"]
    model = DecisionTreeClassifier(max_depth=2, random_state=42)
    model.fit(
        [
            [1.0, 0.0],
            [1.0, 1.0],
            [0.0, 0.0],
            [0.0, 1.0],
        ],
        [1, 1, 0, 0],
    )

    circuit = compile_ensemble_to_circuit(model, feature_names, threshold=0.5, model_type="sklearn")

    assert circuit.n_trees == 1
    assert circuit.n_paths >= 2
    assert circuit.evaluate_fast({"late_filing": 1.0, "in_hmo": 0.0}) is True
    assert circuit.evaluate_fast({"late_filing": 0.0, "in_hmo": 1.0}) is False


def test_discover_rules_runs_natively_without_backend_result() -> None:
    @dataclass
    class Obs:
        late_filing: float = 0.0
        in_hmo: float = 0.0

    labeled = [
        (Obs(late_filing=1.0, in_hmo=0.0), "denied"),
        (Obs(late_filing=1.0, in_hmo=1.0), "denied"),
        (Obs(late_filing=0.0, in_hmo=0.0), "allowed"),
        (Obs(late_filing=0.0, in_hmo=1.0), "allowed"),
        (Obs(late_filing=0.0, in_hmo=0.0), "allowed"),
        (Obs(late_filing=1.0, in_hmo=0.0), "denied"),
    ]

    result = discover_rules(
        labeled,
        DiscoveryPipelineConfig(
            max_depth=2,
            min_samples_leaf=1,
            max_rules=4,
            soundness_threshold=0.95,
        ),
    )

    assert isinstance(result, DiscoveryPipelineResult)
    assert result.backend_result is None
    assert result.selected_features == ["in_hmo", "late_filing"]
    assert result.rules
    assert any(rule.conditions[0].feature == "late_filing" for rule in result.rules)
    assert all(status is VerificationStatus.PIPELINE_UNVERIFIED for status in result.verification_statuses)
