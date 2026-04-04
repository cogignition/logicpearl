use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{ComparisonExpression, ComparisonOperator, Expression, LogicPearlGateIr};
use serde_json::Value;
use std::collections::HashMap;

pub fn evaluate_gate(gate: &LogicPearlGateIr, features: &HashMap<String, Value>) -> Result<u64> {
    let mut bitmask = 0_u64;
    for rule in &gate.rules {
        if evaluate_expression(&rule.deny_when, features)? {
            bitmask |= 1_u64 << rule.bit;
        }
    }
    Ok(bitmask)
}

pub fn parse_input_payload(payload: Value) -> Result<Vec<HashMap<String, Value>>> {
    match payload {
        Value::Object(object) => Ok(vec![object.into_iter().collect()]),
        Value::Array(items) => {
            let mut parsed = Vec::with_capacity(items.len());
            for item in items {
                let object = item.as_object().ok_or_else(|| {
                    LogicPearlError::message("input JSON array must contain only feature objects")
                })?;
                parsed.push(object.clone().into_iter().collect());
            }
            Ok(parsed)
        }
        _ => Err(LogicPearlError::message(
            "input JSON must be an object or an array of feature objects",
        )),
    }
}

fn evaluate_expression(expression: &Expression, features: &HashMap<String, Value>) -> Result<bool> {
    match expression {
        Expression::Comparison(comparison) => evaluate_comparison(comparison, features),
        Expression::All { all } => {
            for child in all {
                if !evaluate_expression(child, features)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Expression::Any { any } => {
            for child in any {
                if evaluate_expression(child, features)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Expression::Not { expr } => Ok(!evaluate_expression(expr, features)?),
    }
}

fn evaluate_comparison(expression: &ComparisonExpression, features: &HashMap<String, Value>) -> Result<bool> {
    let left = features.get(&expression.feature).ok_or_else(|| {
        LogicPearlError::message(format!("missing runtime feature: {}", expression.feature))
    })?;
    let right = &expression.value;

    match expression.op {
        ComparisonOperator::Eq => Ok(left == right),
        ComparisonOperator::Ne => Ok(left != right),
        ComparisonOperator::Gt => compare_numbers(left, right, |l, r| l > r),
        ComparisonOperator::Gte => compare_numbers(left, right, |l, r| l >= r),
        ComparisonOperator::Lt => compare_numbers(left, right, |l, r| l < r),
        ComparisonOperator::Lte => compare_numbers(left, right, |l, r| l <= r),
        ComparisonOperator::In => value_in(left, right),
        ComparisonOperator::NotIn => Ok(!value_in(left, right)?),
    }
}

fn compare_numbers(left: &Value, right: &Value, predicate: impl Fn(f64, f64) -> bool) -> Result<bool> {
    let left = left
        .as_f64()
        .ok_or_else(|| LogicPearlError::message("runtime numeric comparison requires number"))?;
    let right = right
        .as_f64()
        .ok_or_else(|| LogicPearlError::message("runtime numeric comparison requires number"))?;
    Ok(predicate(left, right))
}

fn value_in(left: &Value, right: &Value) -> Result<bool> {
    let items = right
        .as_array()
        .ok_or_else(|| LogicPearlError::message("runtime membership comparison requires array"))?;
    Ok(items.iter().any(|item| item == left))
}
