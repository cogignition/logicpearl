from __future__ import annotations

from typing import Any

from .models import (
    LogicPearlGateIR,
    ComparisonExpression,
    ComparisonOperator,
    Expression,
    LogicalAllExpression,
    LogicalAnyExpression,
    LogicalNotExpression,
)


def evaluate_gate(gate: LogicPearlGateIR, features: dict[str, Any]) -> int:
    bitmask = 0
    for rule in gate.rules:
        if evaluate_expression(rule.deny_when, features):
            bitmask |= 1 << rule.bit
    return bitmask


def evaluate_expression(expression: Expression, features: dict[str, Any]) -> bool:
    if isinstance(expression, ComparisonExpression):
        return evaluate_comparison(expression, features)
    if isinstance(expression, LogicalAllExpression):
        return all(evaluate_expression(child, features) for child in expression.all)
    if isinstance(expression, LogicalAnyExpression):
        return any(evaluate_expression(child, features) for child in expression.any)
    if isinstance(expression, LogicalNotExpression):
        return not evaluate_expression(expression.not_, features)
    raise TypeError(f"unsupported expression type: {type(expression)!r}")


def evaluate_comparison(expression: ComparisonExpression, features: dict[str, Any]) -> bool:
    left = features[expression.feature]
    right = expression.value
    op = expression.op

    if op == ComparisonOperator.EQ:
        return left == right
    if op == ComparisonOperator.NE:
        return left != right
    if op == ComparisonOperator.GT:
        return left > right
    if op == ComparisonOperator.GTE:
        return left >= right
    if op == ComparisonOperator.LT:
        return left < right
    if op == ComparisonOperator.LTE:
        return left <= right
    if op == ComparisonOperator.IN:
        return left in right
    if op == ComparisonOperator.NOT_IN:
        return left not in right
    raise ValueError(f"unsupported operator: {op}")
