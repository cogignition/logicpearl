from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from itertools import combinations
from typing import Any

import numpy as np
from sklearn.tree import DecisionTreeClassifier

from .rules import Condition, Rule, VerificationStatus, coerce_rule


@dataclass(frozen=True)
class DiscoveryPipelineConfig:
    soundness_threshold: float = 0.95
    noise_tolerance: float = 0.05
    max_noise: float = 0.20
    max_depth: int = 4
    min_samples_leaf: int = 5
    max_rules: int = 30
    ordinal_registry: dict[str, Any] | None = None
    skip_z3: bool = False
    exclude_features: list[str] | None = None


@dataclass
class DiscoveryPipelineResult:
    rules: list[Rule]
    verification_statuses: list[VerificationStatus]
    selected_features: list[str] | None = None
    correctness: Any | None = None
    backend_result: Any | None = None


def discover_rules(
    labeled_cases: list[Any],
    config: DiscoveryPipelineConfig | None = None,
) -> DiscoveryPipelineResult:
    if config is None:
        config = DiscoveryPipelineConfig()
    if not labeled_cases:
        return DiscoveryPipelineResult(rules=[], verification_statuses=[], selected_features=[])

    feature_dicts = [_request_to_feature_dict(request) for request, _label in labeled_cases]
    labels = [1 if label == "allowed" else 0 for _request, label in labeled_cases]
    selected_features = _select_feature_names(feature_dicts, config.exclude_features)
    discovery_features = _filter_features_by_names(feature_dicts, selected_features)

    all_rules = _discover_sequential_covering_rules(
        discovery_features,
        labels,
        max_depth=config.max_depth,
        min_samples_leaf=config.min_samples_leaf,
        noise_tolerance=config.noise_tolerance,
        max_rules=config.max_rules,
    )

    allowed_features = [features for features, label in zip(discovery_features, labels) if label == 1]
    strong_rules = _filter_rules_by_soundness(
        all_rules,
        allowed_features,
        threshold=config.soundness_threshold,
    )
    decomposed_rules = _decompose_rules(
        strong_rules,
        allowed_features,
        soundness_threshold=config.soundness_threshold,
    )

    verification_statuses = [VerificationStatus.PIPELINE_UNVERIFIED for _ in decomposed_rules]
    for rule, status in zip(decomposed_rules, verification_statuses):
        rule.verification_status = status

    return DiscoveryPipelineResult(
        rules=decomposed_rules,
        verification_statuses=verification_statuses,
        selected_features=selected_features,
        correctness=None,
        backend_result=None,
    )


def coerce_discovery_result(backend_result: Any) -> DiscoveryPipelineResult:
    gate = getattr(backend_result, "gate", None)
    backend_rules = getattr(gate, "rules", []) if gate is not None else []
    z3_valid = list(getattr(backend_result, "z3_valid", []))
    coerced_rules = []
    verification_statuses: list[VerificationStatus] = []
    for index, backend_rule in enumerate(backend_rules):
        rule = coerce_rule(backend_rule)
        is_z3_verified = index < len(z3_valid) and bool(z3_valid[index])
        status = VerificationStatus.Z3_VERIFIED if is_z3_verified else VerificationStatus.PIPELINE_UNVERIFIED
        rule.verification_status = status
        coerced_rules.append(rule)
        verification_statuses.append(status)
    return DiscoveryPipelineResult(
        rules=coerced_rules,
        verification_statuses=verification_statuses,
        selected_features=getattr(backend_result, "selected_features", None),
        correctness=getattr(backend_result, "correctness", None),
        backend_result=backend_result,
    )


def _request_to_feature_dict(request: Any) -> dict[str, float]:
    if isinstance(request, dict):
        raw = request
    elif is_dataclass(request):
        raw = asdict(request)
    else:
        raw = vars(request)
    return {key: float(value) for key, value in raw.items()}


def _select_feature_names(
    feature_dicts: list[dict[str, float]],
    exclude_features: list[str] | None,
) -> list[str]:
    feature_names = sorted(feature_dicts[0].keys()) if feature_dicts else []
    if not exclude_features:
        return feature_names
    exclude = set(exclude_features)
    return [name for name in feature_names if name not in exclude]


def _filter_features_by_names(
    feature_dicts: list[dict[str, float]],
    selected_features: list[str],
) -> list[dict[str, float]]:
    selected = set(selected_features)
    return [{key: value for key, value in feature_dict.items() if key in selected} for feature_dict in feature_dicts]


def _discover_sequential_covering_rules(
    features: list[dict[str, float]],
    labels: list[int],
    *,
    max_depth: int,
    min_samples_leaf: int,
    noise_tolerance: float,
    max_rules: int,
    min_denied_coverage: int = 2,
) -> list[Rule]:
    if not features or not any(label == 0 for label in labels):
        return []

    feature_names = sorted(features[0].keys())
    discovered: list[Rule] = []
    remaining_features = list(features)
    remaining_labels = list(labels)

    for _ in range(max_rules):
        denied_count = sum(1 for label in remaining_labels if label == 0)
        if denied_count < min_denied_coverage:
            break

        matrix = np.array([[feature_dict.get(name, 0.0) for name in feature_names] for feature_dict in remaining_features])
        targets = np.array(remaining_labels)

        effective_min_leaf = max(min(min_samples_leaf, max(denied_count // 2, 1)), 1)
        tree = DecisionTreeClassifier(
            max_depth=max_depth,
            min_samples_leaf=effective_min_leaf,
            random_state=42,
        )
        tree.fit(matrix, targets)

        best_rule = _extract_best_denial_rule(
            tree,
            feature_names,
            remaining_features,
            remaining_labels,
            noise_tolerance=noise_tolerance,
        )
        if best_rule is None or best_rule.denied_coverage < min_denied_coverage:
            break

        discovered.append(best_rule)

        next_features = []
        next_labels = []
        for feature_dict, label in zip(remaining_features, remaining_labels):
            if label == 0 and best_rule.matches(feature_dict):
                continue
            next_features.append(feature_dict)
            next_labels.append(label)
        remaining_features = next_features
        remaining_labels = next_labels

    return discovered


def _extract_best_denial_rule(
    tree: DecisionTreeClassifier,
    feature_names: list[str],
    features: list[dict[str, float]],
    labels: list[int],
    *,
    noise_tolerance: float,
) -> Rule | None:
    best_rule: Rule | None = None
    best_denied_coverage = 0

    denied_features = [feature_dict for feature_dict, label in zip(features, labels) if label == 0]
    allowed_features = [feature_dict for feature_dict, label in zip(features, labels) if label == 1]

    for conditions, leaf_values in _tree_paths(tree, feature_names):
        total_in_leaf = sum(leaf_values)
        if total_in_leaf == 0:
            continue
        denied_in_leaf = leaf_values[0]
        deny_ratio = denied_in_leaf / total_in_leaf
        if deny_ratio < (1.0 - noise_tolerance):
            continue

        rule = Rule(conditions=conditions, label=0)
        denied_coverage = rule.coverage(denied_features)
        allowed_false_positives = rule.coverage(allowed_features)

        if allowed_features and allowed_false_positives / len(allowed_features) > noise_tolerance:
            continue
        if denied_coverage > best_denied_coverage:
            best_denied_coverage = denied_coverage
            rule.denied_coverage = denied_coverage
            best_rule = rule

    return best_rule


def _tree_paths(
    tree: DecisionTreeClassifier,
    feature_names: list[str],
) -> list[tuple[list[Condition], list[float]]]:
    sklearn_tree = tree.tree_
    paths: list[tuple[list[Condition], list[float]]] = []

    def walk(node_id: int, conditions: list[Condition]) -> None:
        left = sklearn_tree.children_left[node_id]
        right = sklearn_tree.children_right[node_id]
        if left == right:
            paths.append((list(conditions), sklearn_tree.value[node_id][0].tolist()))
            return

        feature_name = feature_names[sklearn_tree.feature[node_id]]
        threshold = float(sklearn_tree.threshold[node_id])
        walk(left, conditions + [Condition(feature_name, "<=", threshold)])
        walk(right, conditions + [Condition(feature_name, ">", threshold)])

    walk(0, [])
    return paths


def _filter_rules_by_soundness(
    rules: list[Rule],
    allowed_features: list[dict[str, float]],
    *,
    threshold: float,
) -> list[Rule]:
    strong_rules: list[Rule] = []
    for rule in rules:
        if not allowed_features:
            rule.soundness_score = 1.0
            strong_rules.append(rule)
            continue
        false_positives = sum(1 for features in allowed_features if rule.matches(features))
        soundness = 1.0 - (false_positives / len(allowed_features))
        rule.soundness_score = soundness
        if soundness >= threshold:
            strong_rules.append(rule)
    return strong_rules


def _decompose_rules(
    rules: list[Rule],
    allowed_features: list[dict[str, float]],
    *,
    soundness_threshold: float,
) -> list[Rule]:
    decomposed: list[Rule] = []
    for rule in rules:
        if len(rule.conditions) <= 1:
            decomposed.append(rule)
            continue

        shortest_sound: list[Rule] = []
        for length in range(1, len(rule.conditions)):
            for combo in combinations(rule.conditions, length):
                sub_rule = Rule(conditions=list(combo))
                if not allowed_features:
                    soundness = 1.0
                else:
                    false_positives = sum(1 for features in allowed_features if sub_rule.matches(features))
                    soundness = 1.0 - (false_positives / len(allowed_features))
                if soundness < soundness_threshold:
                    continue
                if any(_rule_conditions_subset(existing.conditions, sub_rule.conditions) for existing in shortest_sound):
                    continue
                sub_rule.soundness_score = soundness
                shortest_sound.append(sub_rule)
            if shortest_sound:
                break

        if shortest_sound:
            decomposed.extend(shortest_sound)
        else:
            decomposed.append(rule)

    return _deduplicate_rules(decomposed)


def _rule_conditions_subset(shorter: list[Condition], longer: list[Condition]) -> bool:
    shorter_set = {(condition.feature, condition.operator, condition.threshold) for condition in shorter}
    longer_set = {(condition.feature, condition.operator, condition.threshold) for condition in longer}
    return shorter_set.issubset(longer_set)


def _deduplicate_rules(rules: list[Rule]) -> list[Rule]:
    seen: set[frozenset[tuple[str, str, float]]] = set()
    unique: list[Rule] = []
    for rule in rules:
        key = frozenset(
            (condition.feature, condition.operator, float(condition.threshold))
            for condition in rule.conditions
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(rule)
    return unique
