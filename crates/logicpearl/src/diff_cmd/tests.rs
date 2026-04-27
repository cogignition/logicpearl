// SPDX-License-Identifier: MIT
use super::compare::*;
use crate::artifact_cmd;
use logicpearl_ir::{
    ActionEvaluationConfig, ActionRuleDefinition, ActionSelectionStrategy, CombineStrategy,
    ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig, Expression,
    FeatureDefinition, FeatureType, GateType, InputSchema, LogicPearlActionIr, LogicPearlGateIr,
    RuleDefinition, RuleEvidence, RuleKind, RuleSupportEvidence, RuleTraceEvidence,
};
use serde_json::{json, Value};
use std::path::PathBuf;

fn gate_with_rules(rules: Vec<RuleDefinition>) -> LogicPearlGateIr {
    LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: "demo".to_string(),
        gate_type: GateType::BitmaskGate,
        input_schema: InputSchema {
            features: vec![FeatureDefinition {
                id: "age".to_string(),
                feature_type: FeatureType::Int,
                description: None,
                values: None,
                min: None,
                max: None,
                editable: None,
                semantics: None,
                governance: None,
                derived: None,
            }],
        },
        rules,
        evaluation: EvaluationConfig {
            combine: CombineStrategy::BitwiseOr,
            allow_when_bitmask: 0,
        },
        verification: None,
        provenance: None,
    }
}

fn predicate_rule(id: &str, bit: u32, op: ComparisonOperator, value: Value) -> RuleDefinition {
    RuleDefinition {
        id: id.to_string(),
        kind: RuleKind::Predicate,
        bit,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: "age".to_string(),
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

fn expression_rule(id: &str, bit: u32, deny_when: Expression) -> RuleDefinition {
    RuleDefinition {
        id: id.to_string(),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: None,
        evidence: None,
    }
}

fn action_policy_with_rules(
    default_action: &str,
    actions: Vec<&str>,
    rules: Vec<ActionRuleDefinition>,
) -> LogicPearlActionIr {
    LogicPearlActionIr {
        ir_version: "1.0".to_string(),
        action_policy_id: "demo_actions".to_string(),
        action_policy_type: "priority_rules".to_string(),
        action_column: "next_action".to_string(),
        default_action: default_action.to_string(),
        no_match_action: None,
        actions: actions.into_iter().map(ToOwned::to_owned).collect(),
        input_schema: InputSchema {
            features: vec![FeatureDefinition {
                id: "age".to_string(),
                feature_type: FeatureType::Int,
                description: None,
                values: None,
                min: None,
                max: None,
                editable: None,
                semantics: None,
                governance: None,
                derived: None,
            }],
        },
        rules,
        evaluation: ActionEvaluationConfig {
            selection: ActionSelectionStrategy::FirstMatch,
        },
        verification: None,
        provenance: None,
    }
}

fn action_rule(
    id: &str,
    bit: u32,
    action: &str,
    priority: u32,
    op: ComparisonOperator,
    value: Value,
) -> ActionRuleDefinition {
    ActionRuleDefinition {
        id: id.to_string(),
        bit,
        action: action.to_string(),
        priority,
        predicate: Expression::Comparison(ComparisonExpression {
            feature: "age".to_string(),
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

fn resolved_inputs() -> (
    artifact_cmd::ResolvedArtifactInput,
    artifact_cmd::ResolvedArtifactInput,
) {
    (
        artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/old"),
            pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
        },
        artifact_cmd::ResolvedArtifactInput {
            artifact_dir: PathBuf::from("/tmp/new"),
            pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
        },
    )
}

fn rule_evidence(trace_hash: &str) -> RuleEvidence {
    RuleEvidence {
        schema_version: "logicpearl.rule_evidence.v1".to_string(),
        support: RuleSupportEvidence {
            denied_trace_count: 1,
            allowed_trace_count: 0,
            example_traces: vec![RuleTraceEvidence {
                trace_row_hash: trace_hash.to_string(),
                source_id: Some("policy".to_string()),
                source_anchor: Some("section-1".to_string()),
                citation: Some("Policy section 1".to_string()),
                quote_hash: Some(trace_hash.to_string()),
            }],
        },
    }
}

fn feature_semantics(
    label: &str,
    source_anchor: &str,
    state_label: &str,
) -> logicpearl_ir::FeatureSemantics {
    serde_json::from_value(json!({
        "label": label,
        "source_id": "policy-1",
        "source_anchor": source_anchor,
        "states": {
            "minor": {
                "when": {"op": "<", "value": 18},
                "label": state_label,
                "message": format!("This rule fires when {state_label}."),
                "counterfactual_hint": "Raise applicant age."
            }
        }
    }))
    .unwrap()
}

#[test]
fn diff_treats_same_semantics_with_new_bits_as_reordered() {
    let old_gate = gate_with_rules(vec![
        predicate_rule("rule_a", 0, ComparisonOperator::Lt, json!(18)),
        predicate_rule("rule_b", 1, ComparisonOperator::Gte, json!(65)),
    ]);
    let new_gate = gate_with_rules(vec![
        predicate_rule("rule_b2", 0, ComparisonOperator::Gte, json!(65)),
        predicate_rule("rule_a2", 1, ComparisonOperator::Lt, json!(18)),
    ]);
    let old_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/old"),
        pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
    };
    let new_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/new"),
        pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
    };

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert_eq!(report.summary.changed_rules, 0);
    assert_eq!(report.summary.reordered_rules, 2);
    assert_eq!(report.summary.added_rules, 0);
    assert_eq!(report.summary.removed_rules, 0);
    assert!(!report.summary.learned_rule_changed);
}

#[test]
fn diff_treats_same_id_with_new_threshold_as_changed() {
    let old_gate = gate_with_rules(vec![predicate_rule(
        "missing_docs",
        0,
        ComparisonOperator::Lt,
        json!(18),
    )]);
    let new_gate = gate_with_rules(vec![predicate_rule(
        "missing_docs",
        0,
        ComparisonOperator::Lt,
        json!(21),
    )]);
    let old_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/old"),
        pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
    };
    let new_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/new"),
        pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
    };

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert_eq!(report.summary.changed_rules, 1);
    assert_eq!(report.changed_rules[0].rule_id, "missing_docs");
    assert!(report.summary.learned_rule_changed);
    assert!(!report.summary.source_schema_changed);
    assert!(!report.summary.rule_explanation_changed);
}

#[test]
fn diff_action_policies_reports_action_specific_changes() {
    let old_policy = action_policy_with_rules(
        "do_nothing",
        vec!["do_nothing", "water"],
        vec![
            action_rule(
                "rule_water",
                0,
                "water",
                0,
                ComparisonOperator::Lt,
                json!(18),
            ),
            action_rule("rule_old", 1, "water", 1, ComparisonOperator::Gt, json!(70)),
            action_rule(
                "rule_priority",
                2,
                "water",
                2,
                ComparisonOperator::Gte,
                json!(40),
            ),
        ],
    );
    let mut new_priority_rule = action_rule(
        "rule_priority",
        2,
        "water",
        5,
        ComparisonOperator::Gte,
        json!(40),
    );
    new_priority_rule.label = Some("Priority changed only".to_string());
    let new_policy = action_policy_with_rules(
        "wait",
        vec!["wait", "water", "fertilize"],
        vec![
            action_rule(
                "rule_water",
                0,
                "water",
                0,
                ComparisonOperator::Lt,
                json!(21),
            ),
            new_priority_rule,
            action_rule(
                "rule_new",
                3,
                "fertilize",
                3,
                ComparisonOperator::Gte,
                json!(80),
            ),
        ],
    );
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_action_policies(&old_policy, &new_policy, &old_resolved, &new_resolved)
        .expect("action diff should succeed");

    assert!(report.summary.action_set_changed);
    assert!(report.summary.default_action_changed);
    assert!(report.summary.rule_predicate_changed);
    assert!(report.summary.rule_priority_changed);
    assert!(report.summary.learned_rule_changed);
    assert_eq!(report.action_changes.added, vec!["fertilize", "wait"]);
    assert_eq!(report.action_changes.removed, vec!["do_nothing"]);
    assert_eq!(report.summary.changed_rules, 1);
    assert_eq!(
        report.changed_rules[0].change_kind,
        "rule_predicate_changed"
    );
    assert_eq!(report.summary.reordered_rules, 1);
    assert_eq!(
        report.reordered_rules[0].change_kind,
        "rule_priority_changed"
    );
    assert_eq!(report.summary.added_rules, 1);
    assert_eq!(report.summary.removed_rules, 1);
    assert_eq!(report.added_rules[0].action.as_deref(), Some("fertilize"));
}

#[test]
fn diff_action_policies_separates_no_match_action_changes() {
    let old_policy = action_policy_with_rules(
        "do_nothing",
        vec!["do_nothing", "water", "insufficient_context"],
        vec![action_rule(
            "rule_water",
            0,
            "water",
            0,
            ComparisonOperator::Lt,
            json!(21),
        )],
    );
    let mut new_policy = old_policy.clone();
    new_policy.no_match_action = Some("insufficient_context".to_string());
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_action_policies(&old_policy, &new_policy, &old_resolved, &new_resolved)
        .expect("action diff should succeed");

    assert!(report.summary.no_match_action_changed);
    assert!(!report.summary.action_set_changed);
    assert!(!report.summary.learned_rule_changed);
    assert!(!report.summary.rule_explanation_changed);
    assert_eq!(report.old_no_match_action, None);
    assert_eq!(
        report.new_no_match_action.as_deref(),
        Some("insufficient_context")
    );
}

#[test]
fn diff_action_policies_separates_rule_evidence_only_changes() {
    let mut old_policy = action_policy_with_rules(
        "do_nothing",
        vec!["do_nothing", "water"],
        vec![action_rule(
            "rule_water",
            0,
            "water",
            0,
            ComparisonOperator::Lt,
            json!(18),
        )],
    );
    let mut new_policy = old_policy.clone();
    old_policy.rules[0].evidence = Some(rule_evidence(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ));
    new_policy.rules[0].evidence = Some(rule_evidence(
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    ));
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_action_policies(&old_policy, &new_policy, &old_resolved, &new_resolved)
        .expect("action diff should succeed");

    assert!(!report.summary.source_schema_changed);
    assert!(!report.summary.learned_rule_changed);
    assert!(!report.summary.rule_explanation_changed);
    assert!(report.summary.rule_evidence_changed);
    assert_eq!(report.summary.evidence_changed_rules, 1);
    assert_eq!(report.evidence_changed_rules[0].rule_id, "rule_water");
}

#[test]
fn diff_reports_added_and_removed_rules() {
    let old_gate = gate_with_rules(vec![predicate_rule(
        "rule_a",
        0,
        ComparisonOperator::Lt,
        json!(18),
    )]);
    let new_gate = gate_with_rules(vec![predicate_rule(
        "rule_b",
        0,
        ComparisonOperator::Gte,
        json!(65),
    )]);
    let old_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/old"),
        pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
    };
    let new_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/new"),
        pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
    };

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert_eq!(report.summary.added_rules, 1);
    assert_eq!(report.summary.removed_rules, 1);
}

#[test]
fn diff_rule_snapshots_include_readable_artifact_semantics() {
    let mut old_gate = gate_with_rules(vec![predicate_rule(
        "minor_guard",
        0,
        ComparisonOperator::Lt,
        json!(18.0),
    )]);
    old_gate.rules[0].label = Some("Applicant age below 18".to_string());
    old_gate.input_schema.features[0].semantics = Some(feature_semantics(
        "Applicant age",
        "page-1",
        "Applicant is a minor",
    ));
    let new_gate = gate_with_rules(vec![]);
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");

    assert_eq!(report.summary.removed_rules, 1);
    let snapshot = &report.removed_rules[0];
    assert_eq!(snapshot.change_kind.as_deref(), Some("removed_rule"));
    assert_eq!(snapshot.meaning.as_deref(), Some("Applicant is a minor"));
    assert_eq!(snapshot.raw_expression, snapshot.expression);
    assert_eq!(snapshot.raw_expression["feature"].as_str(), Some("age"));
    assert_eq!(snapshot.raw_expression["op"].as_str(), Some("<"));
    assert_eq!(snapshot.raw_expression["value"].as_f64(), Some(18.0));
    let feature = snapshot.feature.as_ref().expect("primary feature");
    assert_eq!(feature.id, "age");
    assert_eq!(feature.label.as_deref(), Some("Applicant age"));
    assert_eq!(feature.source_id.as_deref(), Some("policy-1"));
    assert_eq!(feature.source_anchor.as_deref(), Some("page-1"));
}

#[test]
fn diff_normalizes_semantically_equivalent_boolean_expressions() {
    let old_gate = gate_with_rules(vec![expression_rule(
        "age_guard",
        0,
        Expression::Not {
            expr: Box::new(Expression::Not {
                expr: Box::new(Expression::Comparison(ComparisonExpression {
                    feature: "age".to_string(),
                    op: ComparisonOperator::In,
                    value: ComparisonValue::Literal(json!([18, 21, 18])),
                })),
            }),
        },
    )]);
    let new_gate = gate_with_rules(vec![expression_rule(
        "age_guard",
        0,
        Expression::Comparison(ComparisonExpression {
            feature: "age".to_string(),
            op: ComparisonOperator::In,
            value: ComparisonValue::Literal(json!([21, 18])),
        }),
    )]);
    let old_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/old"),
        pearl_ir: PathBuf::from("/tmp/old/pearl.ir.json"),
    };
    let new_resolved = artifact_cmd::ResolvedArtifactInput {
        artifact_dir: PathBuf::from("/tmp/new"),
        pearl_ir: PathBuf::from("/tmp/new/pearl.ir.json"),
    };

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert_eq!(report.summary.changed_rules, 0);
    assert_eq!(report.summary.reordered_rules, 0);
    assert!(report.changed_rules.is_empty());
    assert!(report.reordered_rules.is_empty());
}

#[test]
fn diff_separates_explanation_only_changes() {
    let mut old_gate = gate_with_rules(vec![predicate_rule(
        "age_guard",
        0,
        ComparisonOperator::Lt,
        json!(18),
    )]);
    let mut new_gate = old_gate.clone();
    old_gate.rules[0].label = Some("Applicant age below 18".to_string());
    new_gate.rules[0].label = Some("Applicant is a minor".to_string());
    old_gate.input_schema.features[0].semantics = Some(feature_semantics(
        "Applicant age",
        "page-1",
        "Applicant age below 18",
    ));
    new_gate.input_schema.features[0].semantics = Some(feature_semantics(
        "Applicant age",
        "page-1",
        "Applicant is a minor",
    ));
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert!(!report.summary.source_schema_changed);
    assert!(!report.summary.learned_rule_changed);
    assert!(report.summary.rule_explanation_changed);
    assert_eq!(report.feature_dictionary_changes.changed.len(), 1);
    assert!(report.feature_dictionary_changes.changed[0].explanation_changed);
}

#[test]
fn diff_separates_rule_evidence_only_changes() {
    let mut old_gate = gate_with_rules(vec![predicate_rule(
        "age_guard",
        0,
        ComparisonOperator::Lt,
        json!(18),
    )]);
    let mut new_gate = old_gate.clone();
    old_gate.rules[0].evidence = Some(rule_evidence(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ));
    new_gate.rules[0].evidence = Some(rule_evidence(
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    ));
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert!(!report.summary.source_schema_changed);
    assert!(!report.summary.learned_rule_changed);
    assert!(!report.summary.rule_explanation_changed);
    assert!(report.summary.rule_evidence_changed);
    assert_eq!(report.summary.evidence_changed_rules, 1);
    assert_eq!(report.evidence_changed_rules[0].rule_id, "age_guard");
}

#[test]
fn diff_separates_source_schema_changes() {
    let mut old_gate = gate_with_rules(vec![predicate_rule(
        "age_guard",
        0,
        ComparisonOperator::Lt,
        json!(18),
    )]);
    let mut new_gate = old_gate.clone();
    old_gate.input_schema.features[0].semantics = Some(feature_semantics(
        "Applicant age",
        "page-1",
        "Applicant age below 18",
    ));
    new_gate.input_schema.features[0].semantics = Some(feature_semantics(
        "Applicant age",
        "page-2",
        "Applicant age below 18",
    ));
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert!(report.summary.source_schema_changed);
    assert!(!report.summary.learned_rule_changed);
    assert!(!report.summary.rule_explanation_changed);
    assert!(report.feature_dictionary_changes.changed[0].source_changed);
}

#[test]
fn diff_treats_dictionary_addition_as_explanation_only() {
    let old_gate = gate_with_rules(vec![predicate_rule(
        "age_guard",
        0,
        ComparisonOperator::Lt,
        json!(18),
    )]);
    let mut new_gate = old_gate.clone();
    new_gate.input_schema.features[0].semantics = Some(feature_semantics(
        "Applicant age",
        "page-1",
        "Applicant age below 18",
    ));
    let (old_resolved, new_resolved) = resolved_inputs();

    let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
        .expect("diff should succeed");
    assert!(!report.summary.source_schema_changed);
    assert!(!report.summary.learned_rule_changed);
    assert!(report.summary.rule_explanation_changed);
    assert_eq!(report.feature_dictionary_changes.added.len(), 1);
}
