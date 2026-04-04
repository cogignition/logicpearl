from __future__ import annotations

from dataclasses import dataclass

from .rules import Rule, coerce_rules


@dataclass
class CompiledGate:
    rules: list[Rule]
    invariant_names: list[str]

    def evaluate(self, features: dict[str, float]) -> int:
        failed = 0
        for index, rule in enumerate(self.rules):
            if rule.matches(features):
                failed |= 1 << index
        return failed

    def failed_invariant_names(self, bitmask: int) -> list[str]:
        return [
            name for index, name in enumerate(self.invariant_names)
            if bitmask & (1 << index)
        ]

    def is_allowed(self, features: dict[str, float]) -> bool:
        return self.evaluate(features) == 0


def compile_gate(rules: list[Rule]) -> CompiledGate:
    coerced_rules = coerce_rules(rules)
    invariant_names = []
    for rule in coerced_rules:
        if rule.rule_id:
            invariant_names.append(rule.rule_id)
            continue
        parts = [f"{condition.feature}{condition.operator}{condition.threshold}" for condition in rule.conditions]
        invariant_names.append(" AND ".join(parts) if parts else "unknown")
    return CompiledGate(rules=coerced_rules, invariant_names=invariant_names)
