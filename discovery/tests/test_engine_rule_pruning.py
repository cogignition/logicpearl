from dataclasses import dataclass

from logicpearl.engine import RuleSource, prune_redundant_rules, prune_rules_by_marginal_accuracy


@dataclass(frozen=True)
class FakeCondition:
    feature: str
    operator: str
    threshold: float

    def evaluate(self, features: dict[str, float]) -> bool:
        value = features.get(self.feature, 0.0)
        if self.operator == ">":
            return value > self.threshold
        return value <= self.threshold


@dataclass
class FakeRule:
    conditions: list[FakeCondition]
    source: RuleSource = RuleSource.DISCOVERED

    def matches(self, features: dict[str, float]) -> bool:
        return all(condition.evaluate(features) for condition in self.conditions)


def _trace(features: dict[str, float], label: str) -> tuple[dict[str, float], str, dict]:
    return (features, label, {})


def test_prune_redundant_rules_prefers_base_rule_over_interaction_proxy() -> None:
    traces = [
        _trace({"base": 1.0, "x_base_x_context": 1.0}, "denied"),
        _trace({"base": 1.0, "x_base_x_context": 1.0}, "denied"),
        _trace({"base": 1.0, "x_base_x_context": 0.0}, "denied"),
        _trace({"base": 0.0, "x_base_x_context": 0.0}, "allowed"),
    ]
    base_rule = FakeRule([FakeCondition("base", ">", 0.5)])
    interaction_rule = FakeRule([FakeCondition("x_base_x_context", ">", 0.5)])

    kept = prune_redundant_rules(
        [interaction_rule, base_rule],
        traces,
        dominance_threshold=0.95,
        min_incremental_denied=1,
    )

    assert base_rule in kept
    assert interaction_rule not in kept


def test_prune_redundant_rules_keeps_distinct_incremental_rule() -> None:
    traces = [
        _trace({"base": 1.0, "other": 0.0}, "denied"),
        _trace({"base": 1.0, "other": 0.0}, "denied"),
        _trace({"base": 0.0, "other": 1.0}, "denied"),
        _trace({"base": 0.0, "other": 0.0}, "allowed"),
    ]
    base_rule = FakeRule([FakeCondition("base", ">", 0.5)])
    distinct_rule = FakeRule([FakeCondition("other", ">", 0.5)])

    kept = prune_redundant_rules(
        [base_rule, distinct_rule],
        traces,
        dominance_threshold=0.95,
        min_incremental_denied=1,
    )

    assert base_rule in kept
    assert distinct_rule in kept


def test_prune_redundant_rules_prefers_indicator_rule_over_numeric_proxy() -> None:
    traces = [
        _trace({"late_filing": 1.0, "days_since_service": 400.0}, "denied"),
        _trace({"late_filing": 1.0, "days_since_service": 390.0}, "denied"),
        _trace({"late_filing": 0.0, "days_since_service": 120.0}, "allowed"),
    ]
    indicator_rule = FakeRule([FakeCondition("late_filing", ">", 0.5)])
    numeric_rule = FakeRule([FakeCondition("days_since_service", ">", 365.5)])

    kept = prune_redundant_rules(
        [numeric_rule, indicator_rule],
        traces,
        dominance_threshold=0.95,
        min_incremental_denied=1,
    )

    assert indicator_rule in kept
    assert numeric_rule not in kept


def test_prune_redundant_rules_preserves_exact_indicator_rule_even_if_redundant() -> None:
    traces = [
        _trace({"broad": 1.0, "exact": 1.0}, "denied"),
        _trace({"broad": 1.0, "exact": 1.0}, "denied"),
        _trace({"broad": 1.0, "exact": 1.0}, "denied"),
        _trace({"broad": 1.0, "exact": 0.0}, "denied"),
        _trace({"broad": 0.0, "exact": 0.0}, "allowed"),
    ]
    broad_rule = FakeRule([FakeCondition("broad", ">", 0.5)])
    exact_rule = FakeRule([FakeCondition("exact", ">", 0.5)])

    kept = prune_redundant_rules(
        [broad_rule, exact_rule],
        traces,
        dominance_threshold=0.95,
        min_incremental_denied=10,
        min_exact_indicator_denied=2,
    )

    assert broad_rule in kept
    assert exact_rule in kept


def test_prune_rules_by_marginal_accuracy_drops_harmful_proxy_rule() -> None:
    traces = [
        _trace({"good": 1.0, "proxy": 1.0}, "denied"),
        _trace({"good": 1.0, "proxy": 0.0}, "denied"),
        _trace({"good": 0.0, "proxy": 1.0}, "allowed"),
        _trace({"good": 0.0, "proxy": 1.0}, "allowed"),
    ]
    stable_rule = FakeRule([FakeCondition("good", ">", 0.5)])
    harmful_proxy = FakeRule([FakeCondition("proxy", ">", 0.5)])

    kept = prune_rules_by_marginal_accuracy([stable_rule, harmful_proxy], traces)

    assert stable_rule in kept
    assert harmful_proxy not in kept


def test_prune_rules_by_marginal_accuracy_preserves_pinned_rule() -> None:
    traces = [
        _trace({"pinned": 1.0}, "allowed"),
        _trace({"pinned": 0.0}, "allowed"),
    ]
    pinned_rule = FakeRule([FakeCondition("pinned", ">", 0.5)], source=RuleSource.PINNED)

    kept = prune_rules_by_marginal_accuracy([pinned_rule], traces)

    assert kept == [pinned_rule]
