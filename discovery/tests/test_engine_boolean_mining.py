from logicpearl.engine import (
    BooleanMiningConfig,
    mine_exact_boolean_rules,
    mine_targeted_exact_boolean_rules,
)


def _trace(features: dict[str, float], label: str) -> tuple[dict[str, float], str, dict]:
    return (features, label, {})


def test_mine_exact_boolean_rules_finds_negated_conjunction() -> None:
    traces = [
        _trace({"a": 1.0, "b": 1.0, "c": 0.0, "noise": 1.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 0.0, "noise": 0.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 1.0, "noise": 0.0}, "allowed"),
        _trace({"a": 1.0, "b": 0.0, "c": 0.0, "noise": 0.0}, "allowed"),
        _trace({"a": 0.0, "b": 1.0, "c": 0.0, "noise": 0.0}, "allowed"),
    ]

    rules = mine_exact_boolean_rules(
        traces,
        config=BooleanMiningConfig(
            min_literal_support=1,
            min_literal_precision=0.4,
            min_denied_support=2,
            max_features=8,
            max_literals=3,
            beam_size=16,
            max_rules=4,
            min_incremental_denied=1,
        ),
    )

    signatures = {
        tuple((condition.feature, condition.operator) for condition in rule.conditions)
        for rule in rules
    }

    assert (("a", ">"), ("b", ">"), ("c", "<=")) in signatures


def test_mine_exact_boolean_rules_can_use_medium_precision_literal_in_exact_combo() -> None:
    traces = [
        _trace({"a": 1.0, "b": 1.0, "c": 1.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 1.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 0.0}, "allowed"),
        _trace({"a": 1.0, "b": 0.0, "c": 1.0}, "allowed"),
        _trace({"a": 0.0, "b": 1.0, "c": 1.0}, "allowed"),
        _trace({"a": 0.0, "b": 0.0, "c": 0.0}, "allowed"),
    ]

    rules = mine_exact_boolean_rules(
        traces,
        config=BooleanMiningConfig(
            min_literal_support=1,
            min_literal_precision=0.7,
            exploration_min_precision=0.45,
            min_denied_support=2,
            max_features=8,
            max_literals=3,
            beam_size=16,
            max_rules=4,
            min_incremental_denied=1,
        ),
    )

    signatures = {
        tuple((condition.feature, condition.operator) for condition in rule.conditions)
        for rule in rules
    }

    assert (("a", ">"), ("b", ">"), ("c", ">")) in signatures


def test_mine_exact_boolean_rules_prefers_distinct_exact_cohorts() -> None:
    traces = [
        _trace({"a": 1.0, "b": 1.0, "c": 0.0, "d": 0.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 0.0, "d": 0.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 0.0, "d": 0.0}, "denied"),
        _trace({"a": 1.0, "b": 1.0, "c": 1.0, "d": 0.0}, "denied"),
        _trace({"a": 0.0, "b": 0.0, "c": 1.0, "d": 1.0}, "denied"),
        _trace({"a": 0.0, "b": 0.0, "c": 1.0, "d": 1.0}, "denied"),
        _trace({"a": 1.0, "b": 0.0, "c": 0.0, "d": 0.0}, "allowed"),
        _trace({"a": 0.0, "b": 1.0, "c": 0.0, "d": 0.0}, "allowed"),
        _trace({"a": 0.0, "b": 0.0, "c": 1.0, "d": 0.0}, "allowed"),
        _trace({"a": 0.0, "b": 0.0, "c": 0.0, "d": 1.0}, "allowed"),
    ]

    rules = mine_exact_boolean_rules(
        traces,
        config=BooleanMiningConfig(
            min_literal_support=1,
            min_literal_precision=0.55,
            exploration_min_precision=0.45,
            min_denied_support=2,
            max_features=8,
            max_literals=3,
            beam_size=16,
            max_rules=2,
            min_incremental_denied=2,
        ),
    )

    signatures = {
        tuple((condition.feature, condition.operator) for condition in rule.conditions)
        for rule in rules
    }

    assert (("a", ">"), ("b", ">")) in signatures
    assert (("c", ">"), ("d", ">")) in signatures


def test_mine_targeted_exact_boolean_rules_finds_low_precision_exact_combo() -> None:
    traces = []
    for _ in range(25):
        traces.append(_trace({"a": 1.0, "b": 1.0, "c": 1.0}, "denied"))
    for _ in range(400):
        traces.append(_trace({"a": 1.0, "b": 0.0, "c": 0.0}, "allowed"))
    for _ in range(400):
        traces.append(_trace({"a": 0.0, "b": 1.0, "c": 0.0}, "allowed"))
    for _ in range(400):
        traces.append(_trace({"a": 0.0, "b": 0.0, "c": 1.0}, "allowed"))
    for _ in range(80):
        traces.append(_trace({"a": 1.0, "b": 1.0, "c": 0.0}, "allowed"))
    for _ in range(80):
        traces.append(_trace({"a": 1.0, "b": 0.0, "c": 1.0}, "allowed"))
    for _ in range(80):
        traces.append(_trace({"a": 0.0, "b": 1.0, "c": 1.0}, "allowed"))

    rules = mine_targeted_exact_boolean_rules(
        traces,
        config=BooleanMiningConfig(
            min_literal_support=20,
            exploration_min_precision=0.001,
            min_denied_support=20,
            targeted_max_features=8,
            targeted_max_literals=3,
            max_rules=4,
            min_incremental_denied=20,
        ),
    )

    signatures = {
        tuple((condition.feature, condition.operator) for condition in rule.conditions)
        for rule in rules
    }

    assert (("a", ">"), ("b", ">"), ("c", ">")) in signatures
