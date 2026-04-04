from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Condition:
    feature: str
    threshold: float
    go_left: bool

    def evaluate(self, features: dict[str, float]) -> bool:
        value = features.get(self.feature, 0.0)
        if self.go_left:
            return value <= self.threshold
        return value > self.threshold


@dataclass(frozen=True)
class TreePath:
    conditions: list[Condition]
    leaf_value: float
    tree_index: int = 0
    leaf_index: int = 0

    def evaluate(self, features: dict[str, float]) -> bool:
        return all(condition.evaluate(features) for condition in self.conditions)


@dataclass
class CompiledCircuit:
    paths: list[TreePath]
    feature_names: list[str]
    threshold: float
    n_trees: int
    n_paths: int
    _path_conditions: list[list[Condition]] = field(default_factory=list, repr=False)

    def evaluate(self, features: dict[str, float]) -> tuple[bool, int, float]:
        score = 0.0
        path_mask = 0
        for index, path in enumerate(self.paths):
            if path.evaluate(features):
                score += path.leaf_value
                if index < 64:
                    path_mask |= 1 << index
        return score >= self.threshold, path_mask, score

    def evaluate_fast(self, features: dict[str, float]) -> bool:
        score = 0.0
        for path in self.paths:
            if path.evaluate(features):
                score += path.leaf_value
        return score >= self.threshold

    def active_paths(self, features: dict[str, float]) -> list[tuple[int, TreePath, float]]:
        active: list[tuple[int, TreePath, float]] = []
        for index, path in enumerate(self.paths):
            if path.evaluate(features):
                active.append((index, path, path.leaf_value))
        return active

    def explain(self, features: dict[str, float]) -> str:
        is_denied, _mask, score = self.evaluate(features)
        active = self.active_paths(features)
        lines = [
            f"Decision: {'DENIED' if is_denied else 'PAID'} (score={score:.4f}, threshold={self.threshold:.4f})",
            f"Active paths: {len(active)} of {len(self.paths)}",
        ]
        active.sort(key=lambda item: -abs(item[2]))
        for path_index, path, value in active[:10]:
            direction = "DENY" if value > 0 else "ALLOW"
            condition_str = " AND ".join(_format_condition(condition) for condition in path.conditions)
            lines.append(f"  Path {path_index} [{direction} {value:+.4f}]: {condition_str}")
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        return {
            "n_trees": self.n_trees,
            "n_paths": self.n_paths,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "paths": [
                {
                    "conditions": [
                        {
                            "feature": condition.feature,
                            "threshold": condition.threshold,
                            "go_left": condition.go_left,
                        }
                        for condition in path.conditions
                    ],
                    "leaf_value": path.leaf_value,
                    "tree_index": path.tree_index,
                }
                for path in self.paths
            ],
        }


def _format_condition(condition: Condition) -> str:
    operator = "<=" if condition.go_left else ">"
    return f"{condition.feature} {operator} {condition.threshold:.4f}"


def compile_ensemble_to_circuit(
    model: Any,
    feature_names: list[str],
    *,
    threshold: float = 0.0,
    model_type: str = "auto",
) -> CompiledCircuit:
    if model_type == "auto":
        model_type = _detect_model_type(model)

    if model_type == "lightgbm":
        paths = _extract_paths_from_lightgbm(model, feature_names)
        n_trees = model.num_trees()
    elif model_type == "sklearn":
        paths = _extract_paths_from_sklearn(model, feature_names)
        n_trees = 1
    else:
        raise ValueError(f"Unsupported model type: {model_type}")

    paths = _factor_paths(paths)
    return CompiledCircuit(
        paths=paths,
        feature_names=feature_names,
        threshold=threshold,
        n_trees=n_trees,
        n_paths=len(paths),
    )


def verify_circuit_equivalence(
    circuit: CompiledCircuit,
    model: Any,
    feature_dicts: list[dict[str, float]],
    *,
    model_type: str = "lightgbm",
) -> tuple[int, int, int]:
    import numpy as np

    total = len(feature_dicts)
    matches = 0
    mismatches = 0
    feature_names = circuit.feature_names

    if model_type == "lightgbm":
        matrix = np.array([[features.get(name, 0.0) for name in feature_names] for features in feature_dicts])
        model_scores = model.predict(matrix)
        model_binary = (model_scores >= circuit.threshold).astype(int)
        for index, features in enumerate(feature_dicts):
            circuit_pred, _mask, _score = circuit.evaluate(features)
            if circuit_pred == bool(model_binary[index]):
                matches += 1
            else:
                mismatches += 1
        return total, matches, mismatches

    raise ValueError(f"Unsupported model_type for verification: {model_type}")


def _detect_model_type(model: Any) -> str:
    cls_name = type(model).__name__
    if "Booster" in cls_name:
        return "lightgbm"
    if "DecisionTree" in cls_name or "RandomForest" in cls_name:
        return "sklearn"
    raise ValueError(f"Cannot auto-detect model type: {cls_name}")


def _extract_paths_from_lightgbm(model: Any, feature_names: list[str]) -> list[TreePath]:
    dump = model.dump_model()
    trees = dump["tree_info"]
    all_paths: list[TreePath] = []
    for tree_index, tree_info in enumerate(trees):
        _extract_paths_recursive(
            tree_info["tree_structure"],
            [],
            tree_index,
            feature_names,
            all_paths,
        )
    return all_paths


def _extract_paths_recursive(
    node: dict[str, Any],
    current_conditions: list[Condition],
    tree_index: int,
    feature_names: list[str],
    all_paths: list[TreePath],
) -> None:
    if "leaf_value" in node:
        all_paths.append(
            TreePath(
                conditions=list(current_conditions),
                leaf_value=float(node["leaf_value"]),
                tree_index=tree_index,
                leaf_index=len(all_paths),
            )
        )
        return

    split_feature = node.get("split_feature")
    threshold = float(node.get("threshold"))
    if isinstance(split_feature, int):
        feature_name = feature_names[split_feature] if split_feature < len(feature_names) else f"f{split_feature}"
    else:
        feature_name = str(split_feature)

    _extract_paths_recursive(
        node["left_child"],
        current_conditions + [Condition(feature=feature_name, threshold=threshold, go_left=True)],
        tree_index,
        feature_names,
        all_paths,
    )
    _extract_paths_recursive(
        node["right_child"],
        current_conditions + [Condition(feature=feature_name, threshold=threshold, go_left=False)],
        tree_index,
        feature_names,
        all_paths,
    )


def _extract_paths_from_sklearn(model: Any, feature_names: list[str]) -> list[TreePath]:
    tree = model.tree_
    all_paths: list[TreePath] = []

    def recurse(node_id: int, conditions: list[Condition]) -> None:
        if tree.children_left[node_id] == -1:
            values = tree.value[node_id].flatten()
            leaf_value = values[1] / values.sum() if values.sum() > 0 and len(values) > 1 else 0.0
            all_paths.append(
                TreePath(
                    conditions=list(conditions),
                    leaf_value=float(leaf_value),
                    tree_index=0,
                    leaf_index=len(all_paths),
                )
            )
            return

        feature_name = feature_names[tree.feature[node_id]]
        threshold = float(tree.threshold[node_id])
        recurse(
            tree.children_left[node_id],
            conditions + [Condition(feature=feature_name, threshold=threshold, go_left=True)],
        )
        recurse(
            tree.children_right[node_id],
            conditions + [Condition(feature=feature_name, threshold=threshold, go_left=False)],
        )

    recurse(0, [])
    return all_paths


def _factor_paths(paths: list[TreePath]) -> list[TreePath]:
    return paths
