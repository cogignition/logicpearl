// SPDX-License-Identifier: MIT
//! Criterion latency benchmarks for the logicpearl-runtime evaluation hot path.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use logicpearl_ir::{
    CombineStrategy, ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig,
    Expression, FeatureDefinition, FeatureType, GateType, InputSchema, LogicPearlGateIr,
    Provenance, RuleDefinition, RuleKind,
};
use logicpearl_runtime::{evaluate_gate, parse_input_payload};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Build a feature definition with no optional fields.
fn feature(id: &str, feature_type: FeatureType) -> FeatureDefinition {
    FeatureDefinition {
        id: id.to_string(),
        feature_type,
        description: None,
        values: None,
        min: None,
        max: None,
        editable: None,
        semantics: None,
        governance: None,
        derived: None,
    }
}

/// Build a single rule that compares `feature_id` with the given operator and literal value.
fn comparison_rule(
    id: &str,
    bit: u32,
    feature_id: &str,
    op: ComparisonOperator,
    value: Value,
) -> RuleDefinition {
    RuleDefinition {
        id: id.to_string(),
        kind: RuleKind::Predicate,
        bit,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: feature_id.to_string(),
            op,
            value: ComparisonValue::Literal(value),
        }),
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: None,
        evidence: None,
    }
}

/// Build a gate with the given features and rules.
fn make_gate(
    id: &str,
    features: Vec<FeatureDefinition>,
    rules: Vec<RuleDefinition>,
) -> LogicPearlGateIr {
    LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: id.to_string(),
        gate_type: GateType::BitmaskGate,
        input_schema: InputSchema { features },
        rules,
        evaluation: EvaluationConfig {
            combine: CombineStrategy::BitwiseOr,
            allow_when_bitmask: 0,
        },
        verification: None,
        provenance: Some(Provenance {
            generator: Some("bench".to_string()),
            generator_version: Some("0.1.0".to_string()),
            source_commit: None,
            created_at: None,
        }),
    }
}

// ---------------------------------------------------------------------------
// Gate: 1 rule, 2 features (one numeric comparison, one string equality)
// ---------------------------------------------------------------------------
fn gate_1_rule() -> (LogicPearlGateIr, HashMap<String, Value>) {
    let features_def = vec![
        feature("age", FeatureType::Int),
        feature("region", FeatureType::String),
    ];
    let rules = vec![RuleDefinition {
        id: "r0".to_string(),
        kind: RuleKind::Predicate,
        bit: 0,
        deny_when: Expression::All {
            all: vec![
                Expression::Comparison(ComparisonExpression {
                    feature: "age".to_string(),
                    op: ComparisonOperator::Lt,
                    value: ComparisonValue::Literal(json!(18)),
                }),
                Expression::Comparison(ComparisonExpression {
                    feature: "region".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(json!("US")),
                }),
            ],
        },
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: None,
        evidence: None,
    }];
    let gate = make_gate("bench_1rule", features_def, rules);
    let input = HashMap::from([
        ("age".to_string(), json!(25)),
        ("region".to_string(), json!("US")),
    ]);
    (gate, input)
}

// ---------------------------------------------------------------------------
// Gate: 5 rules, 5 features (mix of numeric and string comparisons)
// ---------------------------------------------------------------------------
fn gate_5_rules() -> (LogicPearlGateIr, HashMap<String, Value>) {
    let features_def = vec![
        feature("credit_score", FeatureType::Int),
        feature("income", FeatureType::Float),
        feature("debt_ratio", FeatureType::Float),
        feature("employment_status", FeatureType::String),
        feature("account_age_months", FeatureType::Int),
    ];
    let rules = vec![
        comparison_rule("r0", 0, "credit_score", ComparisonOperator::Lt, json!(580)),
        comparison_rule("r1", 1, "income", ComparisonOperator::Lt, json!(25000.0)),
        comparison_rule("r2", 2, "debt_ratio", ComparisonOperator::Gte, json!(0.45)),
        comparison_rule(
            "r3",
            3,
            "employment_status",
            ComparisonOperator::Eq,
            json!("unemployed"),
        ),
        comparison_rule(
            "r4",
            4,
            "account_age_months",
            ComparisonOperator::Lt,
            json!(6),
        ),
    ];
    let gate = make_gate("bench_5rules", features_def, rules);
    let input = HashMap::from([
        ("credit_score".to_string(), json!(720)),
        ("income".to_string(), json!(65000.0)),
        ("debt_ratio".to_string(), json!(0.32)),
        ("employment_status".to_string(), json!("employed")),
        ("account_age_months".to_string(), json!(24)),
    ]);
    (gate, input)
}

// ---------------------------------------------------------------------------
// Gate: 10 rules, 10 features
// ---------------------------------------------------------------------------
fn gate_10_rules() -> (LogicPearlGateIr, HashMap<String, Value>) {
    let features_def = vec![
        feature("credit_score", FeatureType::Int),
        feature("income", FeatureType::Float),
        feature("debt_ratio", FeatureType::Float),
        feature("employment_status", FeatureType::String),
        feature("account_age_months", FeatureType::Int),
        feature("num_late_payments", FeatureType::Int),
        feature("loan_amount", FeatureType::Float),
        feature("property_type", FeatureType::String),
        feature("down_payment_pct", FeatureType::Float),
        feature("years_at_address", FeatureType::Int),
    ];
    let rules = vec![
        comparison_rule("r0", 0, "credit_score", ComparisonOperator::Lt, json!(580)),
        comparison_rule("r1", 1, "income", ComparisonOperator::Lt, json!(25000.0)),
        comparison_rule("r2", 2, "debt_ratio", ComparisonOperator::Gte, json!(0.45)),
        comparison_rule(
            "r3",
            3,
            "employment_status",
            ComparisonOperator::Eq,
            json!("unemployed"),
        ),
        comparison_rule(
            "r4",
            4,
            "account_age_months",
            ComparisonOperator::Lt,
            json!(6),
        ),
        comparison_rule(
            "r5",
            5,
            "num_late_payments",
            ComparisonOperator::Gte,
            json!(3),
        ),
        comparison_rule(
            "r6",
            6,
            "loan_amount",
            ComparisonOperator::Gt,
            json!(500000.0),
        ),
        comparison_rule(
            "r7",
            7,
            "property_type",
            ComparisonOperator::Eq,
            json!("vacant_land"),
        ),
        comparison_rule(
            "r8",
            8,
            "down_payment_pct",
            ComparisonOperator::Lt,
            json!(0.05),
        ),
        comparison_rule(
            "r9",
            9,
            "years_at_address",
            ComparisonOperator::Lt,
            json!(1),
        ),
    ];
    let gate = make_gate("bench_10rules", features_def, rules);
    let input = HashMap::from([
        ("credit_score".to_string(), json!(720)),
        ("income".to_string(), json!(65000.0)),
        ("debt_ratio".to_string(), json!(0.32)),
        ("employment_status".to_string(), json!("employed")),
        ("account_age_months".to_string(), json!(24)),
        ("num_late_payments".to_string(), json!(0)),
        ("loan_amount".to_string(), json!(250000.0)),
        ("property_type".to_string(), json!("single_family")),
        ("down_payment_pct".to_string(), json!(0.20)),
        ("years_at_address".to_string(), json!(5)),
    ]);
    (gate, input)
}

fn bench_evaluate_gate(c: &mut Criterion) {
    let (gate1, input1) = gate_1_rule();
    c.bench_function("evaluate_gate_1_rule", |b| {
        b.iter(|| evaluate_gate(black_box(&gate1), black_box(&input1)))
    });

    let (gate5, input5) = gate_5_rules();
    c.bench_function("evaluate_gate_5_rules", |b| {
        b.iter(|| evaluate_gate(black_box(&gate5), black_box(&input5)))
    });

    let (gate10, input10) = gate_10_rules();
    c.bench_function("evaluate_gate_10_rules", |b| {
        b.iter(|| evaluate_gate(black_box(&gate10), black_box(&input10)))
    });
}

fn bench_parse_input_payload(c: &mut Criterion) {
    let payload = json!({
        "credit_score": 720,
        "income": 65000.0,
        "debt_ratio": 0.32,
        "employment_status": "employed",
        "account_age_months": 24,
        "num_late_payments": 0,
        "loan_amount": "$250,000",
        "property_type": "single_family",
        "down_payment_pct": "20%",
        "years_at_address": 5
    });
    c.bench_function("parse_input_payload", |b| {
        b.iter(|| parse_input_payload(black_box(payload.clone())))
    });
}

criterion_group!(benches, bench_evaluate_gate, bench_parse_input_payload);
criterion_main!(benches);
