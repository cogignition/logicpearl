// SPDX-License-Identifier: MIT
use super::{
    generate_wasm_runner_source, relative_manifest_file, resolve_manifest_member_path,
    unique_generated_crate_name, write_wasm_metadata, write_wasm_metadata_for_pearl,
    CompilablePearl,
};
use logicpearl_ir::{
    ActionEvaluationConfig, ActionRuleDefinition, ActionSelectionStrategy, CombineStrategy,
    ComparisonExpression, ComparisonOperator, ComparisonValue, DerivedFeatureDefinition,
    DerivedFeatureOperator, EvaluationConfig, Expression, FeatureDefinition, FeatureSemantics,
    FeatureStatePredicate, FeatureStateSemantics, FeatureType, GateType, InputSchema,
    LogicPearlActionIr, LogicPearlGateIr, RuleDefinition, RuleKind,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn generated_crate_names_are_isolated_per_invocation() {
    let first = unique_generated_crate_name("logicpearl_compiled_demo");
    let second = unique_generated_crate_name("logicpearl_compiled_demo");
    assert_ne!(first, second);
    assert!(first.starts_with("logicpearl_compiled_demo_"));
    assert!(second.starts_with("logicpearl_compiled_demo_"));
}

#[test]
fn manifest_paths_do_not_double_prefix_relative_output_dirs() {
    assert_eq!(
        relative_manifest_file(
            Path::new("gate"),
            Path::new("gate/pearl.ir.json"),
            "pearl.ir.json"
        ),
        "pearl.ir.json"
    );
    assert_eq!(
        relative_manifest_file(
            Path::new("/tmp/project/gate"),
            Path::new("gate/pearl.ir.json"),
            "pearl.ir.json"
        ),
        "pearl.ir.json"
    );

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let artifact_dir = temp_dir.path().join("gate");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
    std::fs::write(artifact_dir.join("pearl.ir.json"), "{}").expect("pearl file");

    assert_eq!(
        resolve_manifest_member_path(&artifact_dir, "gate/pearl.ir.json")
            .expect("relative manifest member should resolve under the bundle"),
        artifact_dir.join("gate/pearl.ir.json")
    );
}

#[test]
fn manifest_member_paths_cannot_escape_artifact_dir() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let artifact_dir = temp_dir.path().join("artifact");
    let outside = temp_dir.path().join("outside.json");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
    std::fs::write(&outside, "{}").expect("outside file");

    let absolute_error =
        resolve_manifest_member_path(&artifact_dir, &outside.display().to_string())
            .expect_err("absolute manifest paths should be rejected")
            .to_string();
    assert!(
        absolute_error.contains("must be relative"),
        "unexpected error: {absolute_error}"
    );

    let parent_error = resolve_manifest_member_path(&artifact_dir, "../outside.json")
        .expect_err("parent escapes should be rejected")
        .to_string();
    assert!(
        parent_error.contains("escapes bundle directory"),
        "unexpected error: {parent_error}"
    );
}

#[cfg(unix)]
#[test]
fn manifest_member_symlinks_cannot_escape_artifact_dir() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let artifact_dir = temp_dir.path().join("artifact");
    let outside = temp_dir.path().join("outside.json");
    let link = artifact_dir.join("outside-link.json");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
    std::fs::write(&outside, "{}").expect("outside file");
    std::os::unix::fs::symlink(&outside, &link).expect("symlink should be created");

    let error = resolve_manifest_member_path(&artifact_dir, "outside-link.json")
        .expect_err("symlink escapes should be rejected")
        .to_string();
    assert!(
        error.contains("escapes bundle directory"),
        "unexpected error: {error}"
    );
}

#[test]
fn generated_wasm_bitmask_abi_does_not_reserve_u64_max() {
    let gate = gate_with_rule_count(64);
    let source = generate_wasm_runner_source(&gate);

    assert!(source.contains("pub extern \"C\" fn logicpearl_eval_status_slots_f64"));
    assert!(source.contains("bitmask |= 1u64 << 63;"));
    assert!(source.contains("return 0;"));
    assert!(!source.contains("u64::MAX"));
}

#[test]
fn generated_wasm_orders_derived_assignments_by_dependency() {
    let gate = gate_with_out_of_order_derived_chain();
    let source = generate_wasm_runner_source(&gate);

    let dependency = source
        .find("let derived_debt_to_income")
        .expect("dependency assignment should be generated");
    let dependent = source
        .find("let derived_risk_margin")
        .expect("dependent assignment should be generated");
    assert!(dependency < dependent);
    assert!(source.contains("let derived_risk_margin = (derived_debt_to_income -"));
}

#[test]
fn wasm_metadata_orders_derived_features_by_dependency() {
    let gate = gate_with_out_of_order_derived_chain();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let path = temp_dir.path().join("pearl.wasm.meta.json");

    write_wasm_metadata(&path, &gate).expect("write wasm metadata");

    let metadata: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read generated wasm metadata"))
            .expect("parse generated wasm metadata");
    let derived_ids = metadata["derived_features"]
        .as_array()
        .expect("derived feature metadata should be an array")
        .iter()
        .map(|feature| {
            feature["id"]
                .as_str()
                .expect("derived id should be a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(derived_ids, vec!["debt_to_income", "risk_margin"]);
}

#[test]
fn wasm_metadata_declares_explicit_status_entrypoint() {
    let gate = gate_with_rule_count(1);
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let path = temp_dir.path().join("pearl.wasm.meta.json");

    write_wasm_metadata(&path, &gate).expect("write wasm metadata");

    let metadata: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read generated wasm metadata"))
            .expect("parse generated wasm metadata");
    assert_eq!(
        metadata["entrypoint"].as_str(),
        Some("logicpearl_eval_bitmask_slots_f64")
    );
    assert_eq!(
        metadata["status_entrypoint"].as_str(),
        Some("logicpearl_eval_status_slots_f64")
    );
    assert_eq!(
        metadata["allow_entrypoint"].as_str(),
        Some("logicpearl_eval_allow_slots_f64")
    );
}

#[test]
fn wasm_metadata_includes_runtime_feature_explanations() {
    let mut gate = gate_with_rule_count(1);
    gate.input_schema.features[0].semantics = Some(enabled_semantics());
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let path = temp_dir.path().join("pearl.wasm.meta.json");

    write_wasm_metadata(&path, &gate).expect("write wasm metadata");

    let metadata: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read generated wasm metadata"))
            .expect("parse generated wasm metadata");
    assert_eq!(metadata["rules"][0]["features"][0]["feature_id"], "enabled");
    assert_eq!(
        metadata["rules"][0]["features"][0]["feature_label"],
        "Enabled flag"
    );
    assert_eq!(
        metadata["rules"][0]["features"][0]["source_id"],
        "source_policy"
    );
    assert_eq!(
        metadata["rules"][0]["features"][0]["source_anchor"],
        "enabled"
    );
    assert_eq!(
        metadata["rules"][0]["features"][0]["state_label"],
        "Enabled"
    );
    assert_eq!(
        metadata["rules"][0]["features"][0]["state_message"],
        "Enabled items are denied."
    );
    assert_eq!(
        metadata["rules"][0]["features"][0]["counterfactual_hint"],
        "Disable the item."
    );
}

#[test]
fn action_wasm_metadata_declares_policy_selection_metadata() {
    let policy = action_policy();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let path = temp_dir.path().join("pearl.wasm.meta.json");

    write_wasm_metadata_for_pearl(&path, &CompilablePearl::Action(policy))
        .expect("write action wasm metadata");

    let metadata: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read generated wasm metadata"))
            .expect("parse generated wasm metadata");
    assert_eq!(metadata["decision_kind"], "action");
    assert_eq!(metadata["action_policy_id"], "garden_actions");
    assert_eq!(metadata["default_action"], "do_nothing");
    assert_eq!(metadata["rules"][0]["bit"], 0);
    assert_eq!(metadata["rules"][0]["action"], "water");
    assert_eq!(metadata["rules"][0]["priority"], 0);
    assert_eq!(metadata["rules"][0]["features"][0]["feature_id"], "enabled");
    assert_eq!(
        metadata["rules"][0]["features"][0]["feature_label"],
        "Enabled flag"
    );
}

fn enabled_semantics() -> FeatureSemantics {
    FeatureSemantics {
        label: Some("Enabled flag".to_string()),
        kind: None,
        unit: None,
        higher_is_better: None,
        source_id: Some("source_policy".to_string()),
        source_anchor: Some("enabled".to_string()),
        states: BTreeMap::from([(
            "enabled".to_string(),
            FeatureStateSemantics {
                predicate: FeatureStatePredicate {
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Bool(true)),
                },
                label: Some("Enabled".to_string()),
                message: Some("Enabled items are denied.".to_string()),
                counterfactual_hint: Some("Disable the item.".to_string()),
            },
        )]),
    }
}

fn gate_with_rule_count(rule_count: u32) -> LogicPearlGateIr {
    LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: "test_gate".to_string(),
        gate_type: GateType::BitmaskGate,
        input_schema: InputSchema {
            features: vec![FeatureDefinition {
                id: "enabled".to_string(),
                feature_type: FeatureType::Bool,
                description: None,
                values: None,
                min: None,
                max: None,
                editable: None,
                semantics: Some(enabled_semantics()),
                governance: None,
                derived: None,
            }],
        },
        rules: (0..rule_count)
            .map(|bit| RuleDefinition {
                id: format!("rule_{bit}"),
                kind: RuleKind::Predicate,
                bit,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "enabled".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Bool(true)),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: None,
            })
            .collect(),
        evaluation: EvaluationConfig {
            combine: CombineStrategy::BitwiseOr,
            allow_when_bitmask: 0,
        },
        verification: None,
        provenance: None,
    }
}

fn gate_with_out_of_order_derived_chain() -> LogicPearlGateIr {
    LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: "derived_chain".to_string(),
        gate_type: GateType::BitmaskGate,
        input_schema: InputSchema {
            features: vec![
                FeatureDefinition {
                    id: "risk_margin".to_string(),
                    feature_type: FeatureType::Float,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: Some(DerivedFeatureDefinition {
                        op: DerivedFeatureOperator::Difference,
                        left_feature: "debt_to_income".to_string(),
                        right_feature: "limit".to_string(),
                    }),
                },
                FeatureDefinition {
                    id: "debt_to_income".to_string(),
                    feature_type: FeatureType::Float,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: Some(DerivedFeatureDefinition {
                        op: DerivedFeatureOperator::Ratio,
                        left_feature: "debt".to_string(),
                        right_feature: "income".to_string(),
                    }),
                },
                FeatureDefinition {
                    id: "limit".to_string(),
                    feature_type: FeatureType::Float,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                },
                FeatureDefinition {
                    id: "debt".to_string(),
                    feature_type: FeatureType::Float,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                },
                FeatureDefinition {
                    id: "income".to_string(),
                    feature_type: FeatureType::Float,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                },
            ],
        },
        rules: vec![RuleDefinition {
            id: "rule_000".to_string(),
            kind: RuleKind::Predicate,
            bit: 0,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "risk_margin".to_string(),
                op: ComparisonOperator::Gte,
                value: ComparisonValue::Literal(json!(0.0)),
            }),
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: None,
        }],
        evaluation: EvaluationConfig {
            combine: CombineStrategy::BitwiseOr,
            allow_when_bitmask: 0,
        },
        verification: None,
        provenance: None,
    }
}

fn action_policy() -> LogicPearlActionIr {
    LogicPearlActionIr {
        ir_version: "1.0".to_string(),
        action_policy_id: "garden_actions".to_string(),
        action_policy_type: "priority_rules".to_string(),
        action_column: "next_action".to_string(),
        default_action: "do_nothing".to_string(),
        actions: vec!["do_nothing".to_string(), "water".to_string()],
        input_schema: InputSchema {
            features: vec![FeatureDefinition {
                id: "enabled".to_string(),
                feature_type: FeatureType::Bool,
                description: None,
                values: None,
                min: None,
                max: None,
                editable: None,
                semantics: Some(enabled_semantics()),
                governance: None,
                derived: None,
            }],
        },
        rules: vec![ActionRuleDefinition {
            id: "rule_0".to_string(),
            bit: 0,
            action: "water".to_string(),
            priority: 0,
            predicate: Expression::Comparison(ComparisonExpression {
                feature: "enabled".to_string(),
                op: ComparisonOperator::Eq,
                value: ComparisonValue::Literal(Value::Bool(true)),
            }),
            label: Some("Water enabled plants".to_string()),
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: None,
        }],
        evaluation: ActionEvaluationConfig {
            selection: ActionSelectionStrategy::FirstMatch,
        },
        verification: None,
        provenance: None,
    }
}
