from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .feature_governance import FeatureTier, classify_feature_tier
from .rules import RuleSource


@dataclass(frozen=True)
class RuleSupport:
    rule: Any
    denied_hits: frozenset[int]
    allowed_hits: frozenset[int]

    @property
    def condition_count(self) -> int:
        return len(getattr(self.rule, "conditions", []))

    @property
    def denied_coverage(self) -> int:
        return len(self.denied_hits)

    @property
    def allowed_coverage(self) -> int:
        return len(self.allowed_hits)

    @property
    def total_coverage(self) -> int:
        return self.denied_coverage + self.allowed_coverage

    @property
    def precision(self) -> float:
        if self.total_coverage == 0:
            return 0.0
        return self.denied_coverage / self.total_coverage

    @property
    def feature_tier_rank(self) -> int:
        tiers = [classify_feature_tier(condition.feature) for condition in getattr(self.rule, "conditions", [])]
        if FeatureTier.INTERACTION in tiers:
            return 1
        return 0

    @property
    def threshold_style_rank(self) -> int:
        conditions = getattr(self.rule, "conditions", [])
        if not conditions:
            return 1
        if all(_looks_like_indicator_condition(condition) for condition in conditions):
            return 0
        return 1


def prune_redundant_rules(
    rules: list[Any],
    traces: list[tuple[dict[str, float], str, dict]],
    *,
    dominance_threshold: float = 0.98,
    min_incremental_denied: int = 25,
    preserve_exact_indicator_rules: bool = True,
    min_exact_indicator_denied: int = 50,
) -> list[Any]:
    if not rules or not traces:
        return rules

    supports = [_compute_support(rule, traces) for rule in rules]
    supports.sort(
        key=lambda item: (
            item.feature_tier_rank,
            item.threshold_style_rank,
            item.condition_count,
            -round(item.precision, 6),
            -item.denied_coverage,
            item.allowed_coverage,
        )
    )

    kept: list[RuleSupport] = []
    covered_denied: set[int] = set()
    covered_allowed: set[int] = set()

    for support in supports:
        if support.denied_coverage == 0:
            continue

        new_denied = support.denied_hits - covered_denied
        denied_overlap_ratio = _overlap_ratio(support.denied_hits, covered_denied)
        allowed_overlap_ratio = _overlap_ratio(support.allowed_hits, covered_allowed)

        if preserve_exact_indicator_rules and _is_exact_indicator_rule(
            support,
            min_denied_coverage=min_exact_indicator_denied,
        ):
            kept.append(support)
            covered_denied.update(support.denied_hits)
            covered_allowed.update(support.allowed_hits)
            continue

        if (
            denied_overlap_ratio >= dominance_threshold
            and len(new_denied) < min_incremental_denied
            and allowed_overlap_ratio >= dominance_threshold
        ):
            continue

        kept.append(support)
        covered_denied.update(support.denied_hits)
        covered_allowed.update(support.allowed_hits)

    return [item.rule for item in kept]


def prune_rules_by_marginal_accuracy(
    rules: list[Any],
    traces: list[tuple[dict[str, float], str, dict]],
    *,
    keep_sources: tuple[RuleSource, ...] = (RuleSource.PINNED, RuleSource.OVERRIDE),
) -> list[Any]:
    if not rules or not traces:
        return rules

    current_rules = list(rules)
    current_score = _accuracy_score(current_rules, traces)

    changed = True
    while changed:
        changed = False
        best_index = None
        best_score = current_score

        for index, rule in enumerate(current_rules):
            if _rule_source(rule) in keep_sources:
                continue

            candidate_rules = current_rules[:index] + current_rules[index + 1 :]
            candidate_score = _accuracy_score(candidate_rules, traces)
            if candidate_score > best_score:
                best_score = candidate_score
                best_index = index

        if best_index is not None:
            current_rules.pop(best_index)
            current_score = best_score
            changed = True

    return current_rules


def _compute_support(
    rule: Any,
    traces: list[tuple[dict[str, float], str, dict]],
) -> RuleSupport:
    denied_hits: set[int] = set()
    allowed_hits: set[int] = set()
    for index, (features, label, _meta) in enumerate(traces):
        if not rule.matches(features):
            continue
        if label == "denied":
            denied_hits.add(index)
        else:
            allowed_hits.add(index)
    return RuleSupport(rule=rule, denied_hits=frozenset(denied_hits), allowed_hits=frozenset(allowed_hits))


def _accuracy_score(
    rules: list[Any],
    traces: list[tuple[dict[str, float], str, dict]],
) -> tuple[int, int]:
    correct = 0
    denied_correct = 0
    for features, label, _meta in traces:
        predicted_denied = any(rule.matches(features) for rule in rules)
        actual_denied = label == "denied"
        if predicted_denied == actual_denied:
            correct += 1
            if actual_denied:
                denied_correct += 1
    return (correct, denied_correct)


def _rule_source(rule: Any) -> RuleSource:
    source = getattr(rule, "source", RuleSource.DISCOVERED)
    if isinstance(source, RuleSource):
        return source
    return RuleSource(source)


def _overlap_ratio(hits: frozenset[int], covered: set[int]) -> float:
    if not hits:
        return 1.0
    return len(hits & covered) / len(hits)


def _looks_like_indicator_condition(condition: Any) -> bool:
    return condition.operator in {"<=", ">"} and abs(float(condition.threshold) - 0.5) < 1e-9


def _is_exact_indicator_rule(
    support: RuleSupport,
    *,
    min_denied_coverage: int,
) -> bool:
    return (
        support.feature_tier_rank == 0
        and support.threshold_style_rank == 0
        and support.condition_count == 1
        and support.allowed_coverage == 0
        and support.denied_coverage >= min_denied_coverage
    )
