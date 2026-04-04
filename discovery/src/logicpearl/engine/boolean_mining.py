from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from .feature_governance import FeatureTier, classify_feature_tier
from .rules import Condition, Rule, VerificationStatus


@dataclass(frozen=True)
class BooleanMiningConfig:
    min_literal_support: int = 25
    min_literal_precision: float = 0.55
    exploration_min_precision: float = 0.45
    min_denied_support: int = 20
    exact_precision: float = 1.0
    max_features: int = 18
    max_literals: int = 4
    beam_size: int = 64
    max_rules: int = 8
    min_incremental_denied: int = 20
    targeted_max_literals: int = 4
    targeted_max_features: int = 16


@dataclass(frozen=True)
class _LiteralSupport:
    feature: str
    positive: bool
    denied_hits: frozenset[int]
    allowed_hits: frozenset[int]

    @property
    def total_hits(self) -> int:
        return len(self.denied_hits) + len(self.allowed_hits)

    @property
    def precision(self) -> float:
        total = self.total_hits
        if total == 0:
            return 0.0
        return len(self.denied_hits) / total

    @property
    def score(self) -> tuple[float, int, int]:
        return (self.precision, len(self.denied_hits), -len(self.allowed_hits))


@dataclass(frozen=True)
class _CandidateRule:
    literals: tuple[_LiteralSupport, ...]
    denied_hits: frozenset[int]
    allowed_hits: frozenset[int]

    @property
    def precision(self) -> float:
        total = len(self.denied_hits) + len(self.allowed_hits)
        if total == 0:
            return 0.0
        return len(self.denied_hits) / total

    @property
    def score(self) -> tuple[float, int, int, int]:
        return (self.precision, len(self.denied_hits), -len(self.allowed_hits), -len(self.literals))


def mine_exact_boolean_rules(
    traces: list[tuple[dict[str, float], str, dict]],
    *,
    config: BooleanMiningConfig | None = None,
) -> list[Rule]:
    if config is None:
        config = BooleanMiningConfig()
    if not traces:
        return []

    literal_pool = _build_literal_pool(traces, config)
    if not literal_pool:
        return []

    beams = [
        _CandidateRule(
            literals=(literal,),
            denied_hits=literal.denied_hits,
            allowed_hits=literal.allowed_hits,
        )
        for literal in literal_pool
    ]
    exact_rules: list[_CandidateRule] = []
    seen_signatures: set[tuple[tuple[str, bool], ...]] = set()

    for width in range(2, config.max_literals + 1):
        expanded: list[_CandidateRule] = []
        for candidate in beams:
            used_features = {literal.feature for literal in candidate.literals}
            for literal in literal_pool:
                if literal.feature in used_features:
                    continue
                denied_hits = candidate.denied_hits & literal.denied_hits
                if len(denied_hits) < config.min_denied_support:
                    continue
                allowed_hits = candidate.allowed_hits & literal.allowed_hits
                next_candidate = _CandidateRule(
                    literals=tuple(sorted(candidate.literals + (literal,), key=lambda item: item.feature)),
                    denied_hits=denied_hits,
                    allowed_hits=allowed_hits,
                )
                signature = tuple((item.feature, item.positive) for item in next_candidate.literals)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                if next_candidate.precision < config.exploration_min_precision:
                    continue
                expanded.append(next_candidate)
                if not next_candidate.allowed_hits and next_candidate.precision >= config.exact_precision:
                    exact_rules.append(next_candidate)

        if not expanded:
            break
        expanded.sort(key=lambda item: item.score, reverse=True)
        beams = expanded[: config.beam_size]

    exact_rules.sort(key=lambda item: item.score, reverse=True)
    selected: list[_CandidateRule] = []
    covered_denied: set[int] = set()
    for candidate in exact_rules:
        new_denied = candidate.denied_hits - covered_denied
        if len(new_denied) < config.min_incremental_denied:
            continue
        selected.append(candidate)
        covered_denied.update(candidate.denied_hits)
        if len(selected) >= config.max_rules:
            break

    return [_candidate_to_rule(candidate) for candidate in selected]


def mine_targeted_exact_boolean_rules(
    traces: list[tuple[dict[str, float], str, dict]],
    *,
    config: BooleanMiningConfig | None = None,
) -> list[Rule]:
    if config is None:
        config = BooleanMiningConfig()
    if not traces:
        return []

    literal_pool = _build_targeted_literal_pool(traces, config)
    if not literal_pool:
        return []

    candidates: list[_CandidateRule] = []
    for width in range(1, config.targeted_max_literals + 1):
        for literal_combo in combinations(literal_pool, width):
            denied_hits = set.intersection(*(set(literal.denied_hits) for literal in literal_combo))
            if len(denied_hits) < config.min_denied_support:
                continue
            allowed_hits = set.intersection(*(set(literal.allowed_hits) for literal in literal_combo))
            if allowed_hits:
                continue
            candidates.append(
                _CandidateRule(
                    literals=tuple(sorted(literal_combo, key=lambda item: item.feature)),
                    denied_hits=frozenset(denied_hits),
                    allowed_hits=frozenset(),
                )
            )

    candidates.sort(
        key=lambda item: (len(item.denied_hits), -len(item.literals)),
        reverse=True,
    )
    selected: list[_CandidateRule] = []
    covered_denied: set[int] = set()
    seen_signatures: set[tuple[tuple[str, bool], ...]] = set()
    for candidate in candidates:
        signature = tuple((item.feature, item.positive) for item in candidate.literals)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        new_denied = candidate.denied_hits - covered_denied
        if len(new_denied) < config.min_incremental_denied:
            continue
        selected.append(candidate)
        covered_denied.update(candidate.denied_hits)
        if len(selected) >= config.max_rules:
            break

    return [_candidate_to_rule(candidate) for candidate in selected]


def _build_literal_pool(
    traces: list[tuple[dict[str, float], str, dict]],
    config: BooleanMiningConfig,
) -> list[_LiteralSupport]:
    literals = _build_all_eligible_literals(traces, config)
    literals.sort(key=lambda item: item.score, reverse=True)
    return literals[: config.max_features]


def _build_targeted_literal_pool(
    traces: list[tuple[dict[str, float], str, dict]],
    config: BooleanMiningConfig,
) -> list[_LiteralSupport]:
    literals = _build_all_eligible_literals(traces, config)
    literals.sort(
        key=lambda item: (len(item.denied_hits), -len(item.allowed_hits), item.precision),
        reverse=True,
    )
    return literals[: config.targeted_max_features]


def _build_all_eligible_literals(
    traces: list[tuple[dict[str, float], str, dict]],
    config: BooleanMiningConfig,
) -> list[_LiteralSupport]:
    feature_names = sorted(traces[0][0].keys())
    eligible = []
    for feature_name in feature_names:
        if classify_feature_tier(feature_name) != FeatureTier.BASE:
            continue
        if not _looks_boolean(traces, feature_name):
            continue
        eligible.append(feature_name)

    literals: list[_LiteralSupport] = []
    for feature_name in eligible:
        positive_denied: set[int] = set()
        positive_allowed: set[int] = set()
        negative_denied: set[int] = set()
        negative_allowed: set[int] = set()

        for index, (features, label, _meta) in enumerate(traces):
            is_positive = features.get(feature_name, 0.0) > 0.5
            if is_positive:
                if label == "denied":
                    positive_denied.add(index)
                else:
                    positive_allowed.add(index)
            else:
                if label == "denied":
                    negative_denied.add(index)
                else:
                    negative_allowed.add(index)

        for positive, denied_hits, allowed_hits in (
            (True, frozenset(positive_denied), frozenset(positive_allowed)),
            (False, frozenset(negative_denied), frozenset(negative_allowed)),
        ):
            literal = _LiteralSupport(
                feature=feature_name,
                positive=positive,
                denied_hits=denied_hits,
                allowed_hits=allowed_hits,
            )
            if literal.total_hits < config.min_literal_support:
                continue
            if len(literal.denied_hits) < config.min_denied_support:
                continue
            if literal.precision < config.exploration_min_precision:
                continue
            literals.append(literal)
    return literals


def _candidate_to_rule(candidate: _CandidateRule) -> Rule:
    conditions = []
    for literal in candidate.literals:
        conditions.append(
            Condition(
                feature=literal.feature,
                operator=">" if literal.positive else "<=",
                threshold=0.5,
            )
        )
    return Rule(
        conditions=conditions,
        soundness_score=1.0,
        denied_coverage=len(candidate.denied_hits),
        verification_status=VerificationStatus.HEURISTIC_UNVERIFIED,
    )


def _looks_boolean(traces: list[tuple[dict[str, float], str, dict]], feature_name: str) -> bool:
    for features, _label, _meta in traces:
        value = features.get(feature_name, 0.0)
        if value not in (0, 0.0, 1, 1.0):
            return False
    return True
