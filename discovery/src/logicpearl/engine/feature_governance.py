from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class FeatureTier(str, Enum):
    BASE = "base"
    INTERACTION = "interaction"


@dataclass(frozen=True)
class FeatureStats:
    total_hits: int
    denied_hits: int
    allowed_hits: int

    @property
    def precision(self) -> float:
        if self.total_hits == 0:
            return 0.0
        return self.denied_hits / self.total_hits


@dataclass(frozen=True)
class FeatureGovernanceConfig:
    min_support: int = 30
    min_denied_support: int = 25
    exact_base_min_support: int = 20
    min_precision_gain: float = 0.05
    max_interactions: int | None = 64
    high_precision_threshold_base: float = 0.95
    high_precision_threshold_interaction: float = 0.995
    high_precision_min_denied_interaction: int = 500


@dataclass
class FeatureGovernanceReport:
    selected_interactions: list[str] = field(default_factory=list)
    excluded_interactions: dict[str, str] = field(default_factory=dict)
    feature_tiers: dict[str, FeatureTier] = field(default_factory=dict)


def classify_feature_tier(feature_name: str) -> FeatureTier:
    if _parse_interaction_name(feature_name) is not None:
        return FeatureTier.INTERACTION
    return FeatureTier.BASE


def compute_feature_governance_report(
    features: list[dict[str, float]],
    labels: list[int],
    *,
    config: FeatureGovernanceConfig | None = None,
) -> FeatureGovernanceReport:
    if config is None:
        config = FeatureGovernanceConfig()
    if not features:
        return FeatureGovernanceReport()

    feature_names = sorted(features[0].keys())
    interaction_names = [name for name in feature_names if classify_feature_tier(name) == FeatureTier.INTERACTION]
    feature_tiers = {name: classify_feature_tier(name) for name in feature_names}
    if not interaction_names:
        return FeatureGovernanceReport(feature_tiers=feature_tiers)

    required_feature_names = set(interaction_names)
    for name in interaction_names:
        left, right = _parse_interaction_name(name) or ("", "")
        required_feature_names.add(left)
        required_feature_names.add(right)

    stats = _compute_feature_stats_batch(features, labels, required_feature_names)
    scored: list[tuple[float, str]] = []
    excluded: dict[str, str] = {}

    for name in interaction_names:
        parsed = _parse_interaction_name(name)
        if parsed is None:
            excluded[name] = "unparseable interaction name"
            continue
        left, right = parsed
        interaction_stats = stats[name]

        if interaction_stats.total_hits < config.min_support:
            excluded[name] = f"support below minimum ({interaction_stats.total_hits} < {config.min_support})"
            continue
        if interaction_stats.denied_hits < config.min_denied_support:
            excluded[name] = (
                f"denied support below minimum ({interaction_stats.denied_hits} < {config.min_denied_support})"
            )
            continue

        left_stats = stats[left]
        right_stats = stats[right]
        source_precision = max(left_stats.precision, right_stats.precision)
        precision_gain = interaction_stats.precision - source_precision
        allowed_reduction = min(left_stats.allowed_hits, right_stats.allowed_hits) - interaction_stats.allowed_hits

        if precision_gain < config.min_precision_gain:
            excluded[name] = (
                f"precision gain too small ({precision_gain:.3f} < {config.min_precision_gain:.3f})"
            )
            continue
        if allowed_reduction <= 0:
            excluded[name] = "does not reduce allowed coverage versus source features"
            continue

        score = precision_gain * 1000 + interaction_stats.denied_hits - interaction_stats.allowed_hits
        scored.append((score, name))

    scored.sort(reverse=True)
    if config.max_interactions is not None:
        kept = [name for _, name in scored[:config.max_interactions]]
        for _, name in scored[config.max_interactions:]:
            excluded[name] = f"ranked below top {config.max_interactions} interactions"
    else:
        kept = [name for _, name in scored]

    return FeatureGovernanceReport(
        selected_interactions=sorted(kept),
        excluded_interactions=excluded,
        feature_tiers=feature_tiers,
    )


def should_scan_feature(
    feature_name: str,
    *,
    denied_hits: int,
    precision: float,
    allowed_hits: int = 0,
    config: FeatureGovernanceConfig | None = None,
) -> bool:
    if config is None:
        config = FeatureGovernanceConfig()

    tier = classify_feature_tier(feature_name)
    if tier == FeatureTier.BASE:
        if precision >= 1.0 and allowed_hits == 0 and denied_hits >= config.exact_base_min_support:
            return True
        return precision >= config.high_precision_threshold_base
    return (
        precision >= config.high_precision_threshold_interaction
        and denied_hits >= config.high_precision_min_denied_interaction
    )


def _parse_interaction_name(name: str) -> tuple[str, str] | None:
    if not name.startswith("x_"):
        return None
    body = name[2:]
    if "_x_" not in body:
        return None
    left, right = body.split("_x_", 1)
    if not left or not right:
        return None
    return left, right


def _compute_feature_stats_batch(
    features: list[dict[str, float]],
    labels: list[int],
    required_feature_names: set[str],
) -> dict[str, FeatureStats]:
    total_hits: dict[str, int] = defaultdict(int)
    denied_hits: dict[str, int] = defaultdict(int)
    allowed_hits: dict[str, int] = defaultdict(int)

    for feature_dict, label in zip(features, labels):
        for feature_name, value in feature_dict.items():
            if feature_name not in required_feature_names or value <= 0.5:
                continue
            total_hits[feature_name] += 1
            if label == 0:
                denied_hits[feature_name] += 1
            else:
                allowed_hits[feature_name] += 1

    return {
        feature_name: FeatureStats(
            total_hits=total_hits[feature_name],
            denied_hits=denied_hits[feature_name],
            allowed_hits=allowed_hits[feature_name],
        )
        for feature_name in required_feature_names
    }
