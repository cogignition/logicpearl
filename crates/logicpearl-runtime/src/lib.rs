use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{ComparisonExpression, ComparisonOperator, ComparisonValue, Expression, LogicPearlGateIr};
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
    let right = resolve_comparison_value(&expression.value, features)?;

    match expression.op {
        ComparisonOperator::Eq => Ok(values_equal(left, right)),
        ComparisonOperator::Ne => Ok(!values_equal(left, right)),
        ComparisonOperator::Gt => compare_numbers(left, right, |l, r| l > r),
        ComparisonOperator::Gte => compare_numbers(left, right, |l, r| l >= r),
        ComparisonOperator::Lt => compare_numbers(left, right, |l, r| l < r),
        ComparisonOperator::Lte => compare_numbers(left, right, |l, r| l <= r),
        ComparisonOperator::In => value_in(left, right),
        ComparisonOperator::NotIn => Ok(!value_in(left, right)?),
    }
}

fn resolve_comparison_value<'a>(
    value: &'a ComparisonValue,
    features: &'a HashMap<String, Value>,
) -> Result<&'a Value> {
    match value {
        ComparisonValue::Literal(literal) => Ok(literal),
        ComparisonValue::FeatureRef { feature_ref } => features.get(feature_ref).ok_or_else(|| {
            LogicPearlError::message(format!("missing runtime feature: {}", feature_ref))
        }),
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

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(l), Some(r)) => (l - r).abs() < f64::EPSILON,
        _ => left == right,
    }
}

fn value_in(left: &Value, right: &Value) -> Result<bool> {
    let items = right
        .as_array()
        .ok_or_else(|| LogicPearlError::message("runtime membership comparison requires array"))?;
    Ok(items.iter().any(|item| values_equal(item, left)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use logicpearl_ir::{
        EvaluationConfig, FeatureDefinition, FeatureType, InputSchema, Provenance, RuleDefinition, RuleKind,
        RuleVerificationStatus, VerificationConfig,
    };
    use serde_json::json;

    fn gate_for_eq_test(value: Value) -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "eq_test".to_string(),
            gate_type: "bitmask_gate".to_string(),
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "flag".to_string(),
                    feature_type: FeatureType::Int,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                }],
            },
            rules: vec![RuleDefinition {
                id: "rule_000".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "flag".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(value),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            }],
            evaluation: EvaluationConfig {
                combine: "bitwise_or".to_string(),
                allow_when_bitmask: 0,
            },
            verification: Some(VerificationConfig {
                domain_constraints: None,
                correctness_scope: None,
                verification_summary: Some(std::collections::HashMap::new()),
            }),
            provenance: Some(Provenance {
                generator: Some("test".to_string()),
                generator_version: Some("test".to_string()),
                source_commit: None,
                created_at: None,
            }),
        }
    }

    #[test]
    fn numeric_equality_matches_int_and_float_forms() {
        let gate = gate_for_eq_test(json!(1.0));
        let features = HashMap::from([("flag".to_string(), json!(1))]);
        let bitmask = evaluate_gate(&gate, &features).expect("runtime evaluation should succeed");
        assert_eq!(bitmask, 1);
    }

    #[test]
    fn numeric_membership_matches_int_and_float_forms() {
        let mut features = HashMap::new();
        features.insert("flag".to_string(), json!(2));
        let expression = ComparisonExpression {
            feature: "flag".to_string(),
            op: ComparisonOperator::In,
            value: ComparisonValue::Literal(json!([1.0, 2.0])),
        };
        assert!(evaluate_comparison(&expression, &features).expect("membership should evaluate"));
    }

    #[test]
    fn numeric_feature_reference_comparison_evaluates() {
        let expression = ComparisonExpression {
            feature: "clearance".to_string(),
            op: ComparisonOperator::Lt,
            value: ComparisonValue::FeatureRef {
                feature_ref: "sensitivity".to_string(),
            },
        };
        let features = HashMap::from([
            ("clearance".to_string(), json!(2)),
            ("sensitivity".to_string(), json!(4)),
        ]);
        assert!(evaluate_comparison(&expression, &features).expect("feature ref comparison should evaluate"));
    }
}
