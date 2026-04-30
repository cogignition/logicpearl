// SPDX-License-Identifier: MIT
use super::{
    build_pearl_from_csv, build_pearl_from_rows, canonicalize_rules, dedupe_rules_by_signature,
    discover_from_csv, discover_residual_rules, discovery_selection_env_lock, gate_from_rules,
    load_decision_traces, load_decision_traces_auto,
    load_decision_traces_auto_with_feature_selection, load_observation_schema,
    merge_discovered_and_pinned_rules, prune_redundant_rules, rule_from_candidate, BuildOptions,
    CandidateRule, DecisionTraceRow, DiscoverOptions, DiscoveryDecisionMode,
    FeatureColumnSelection, ObservationFeatureType, ObservationOperator, PinnedRuleSet,
    ProposalCandidateStatus, ProposalPhaseStatus, ProposalPolicy, ProposalStageStatus,
    ResidualPassOptions, ResidualRecoveryState, SelectionPolicy, SelectionPolicyReport,
};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, ComparisonValue, Expression, LogicPearlGateIr,
    RuleDefinition, RuleKind, RuleVerificationStatus,
};
use logicpearl_solver::{check_sat, SolverSettings};
use serde_json::{Number, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

fn solver_available() -> bool {
    check_sat("(check-sat)\n", &SolverSettings::default()).is_ok()
}

#[test]
fn observation_schema_loader_accepts_discoverable_feature_contract() {
    let dir = tempfile::tempdir().unwrap();
    let schema_path = dir.path().join("observation_schema.json");
    std::fs::write(
        &schema_path,
        r#"{
  "schema_version": "logicpearl.observation_schema.v1",
  "features": [
    {
      "feature_id": "notification_sent_on_time",
      "type": "boolean",
      "label": "Notification sent on time",
      "source_id": "policy_manual_2026_04",
      "source_anchor": "section-3.2",
      "operators": ["eq"],
      "description": "Whether the notification was sent within the required window."
    },
    {
      "feature_id": "notice_days",
      "type": "integer",
      "operators": ["eq", "gte", "lte"]
    }
  ]
}"#,
    )
    .unwrap();

    let schema = load_observation_schema(&schema_path).unwrap();
    assert_eq!(schema.features.len(), 2);
    assert_eq!(schema.features[0].feature_id, "notification_sent_on_time");
    assert_eq!(
        schema.features[0].feature_type,
        ObservationFeatureType::Boolean
    );
    assert_eq!(schema.features[0].operators, vec![ObservationOperator::Eq]);
}

#[test]
fn observation_schema_loader_rejects_policy_impossible_operator() {
    let dir = tempfile::tempdir().unwrap();
    let schema_path = dir.path().join("bad_observation_schema.json");
    std::fs::write(
        &schema_path,
        r#"{
  "schema_version": "logicpearl.observation_schema.v1",
  "features": [
    {
      "feature_id": "notification_sent_on_time",
      "type": "boolean",
      "operators": ["gt"]
    }
  ]
}"#,
    )
    .unwrap();

    let err = load_observation_schema(&schema_path).unwrap_err();
    assert!(err.to_string().contains("does not support operator"));
}

#[test]
fn selection_policy_recommendation_suggests_recall_biased_for_rare_low_recall_target() {
    let report = SelectionPolicyReport {
        configured: SelectionPolicy::Balanced,
        denied_examples: 8,
        allowed_examples: 92,
        false_negatives: 5,
        false_positives: 1,
        denied_recall: 0.375,
        false_positive_rate: 1.0 / 92.0,
        constraints_satisfied: true,
    };

    let recommendation = super::selection_policy_recommendation(&report)
        .expect("rare low-recall gate should get a recommendation");

    assert_eq!(recommendation.kind, "try_recall_biased");
    assert_eq!(recommendation.current_policy, SelectionPolicy::Balanced);
    assert_eq!(recommendation.support_rate, 0.08);
    assert_eq!(recommendation.suggested_recall_target, 0.80);
    assert!(matches!(
        recommendation.suggested_policy,
        SelectionPolicy::RecallBiased { .. }
    ));
    assert!(
        recommendation
            .reason
            .contains("if false positives are reviewable"),
        "recommendation should explain the product precondition: {}",
        recommendation.reason
    );
}

#[test]
fn selection_policy_recommendation_stays_quiet_for_balanced_high_recall_target() {
    let report = SelectionPolicyReport {
        configured: SelectionPolicy::Balanced,
        denied_examples: 8,
        allowed_examples: 92,
        false_negatives: 1,
        false_positives: 1,
        denied_recall: 0.875,
        false_positive_rate: 1.0 / 92.0,
        constraints_satisfied: true,
    };

    assert!(super::selection_policy_recommendation(&report).is_none());
}

#[test]
fn load_decision_traces_parses_allowed_column() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "age,is_member,allowed\n21,1,allowed\n15,1,denied\n",
    )
    .unwrap();

    let rows = load_decision_traces(&csv_path, "allowed").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].features["age"], 21);
    assert_eq!(rows[0].features["is_member"], 1);
    assert!(rows[0].allowed);
    assert!(!rows[1].allowed);
}

#[test]
fn load_decision_traces_auto_prefers_allowed_name() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "age,is_member,allowed\n21,1,allowed\n15,0,denied\n",
    )
    .unwrap();

    let loaded = load_decision_traces_auto(&csv_path, None, None, None).unwrap();
    assert_eq!(loaded.label_column, "allowed");
    assert_eq!(loaded.rows.len(), 2);
}

#[test]
fn load_decision_traces_auto_supports_realistic_binary_labels() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "credit_score,approved\n780,approved\n570,denied\n",
    )
    .unwrap();

    let loaded = load_decision_traces_auto(&csv_path, None, None, None).unwrap();
    assert_eq!(loaded.label_column, "approved");
    assert!(loaded.rows[0].allowed);
    assert!(!loaded.rows[1].allowed);
}

#[test]
fn load_decision_traces_normalizes_formatted_scalars() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "annual_income,debt_ratio,mfa_enabled,approved\n\"$95,000\",22%,Yes,approved\n\"$31,000\",61%,No,denied\n",
    )
    .unwrap();

    let loaded = load_decision_traces_auto(&csv_path, None, None, None).unwrap();
    assert_eq!(loaded.rows[0].features["annual_income"], 95_000);
    assert_eq!(
        loaded.rows[0].features["debt_ratio"],
        Value::Number(Number::from_f64(0.22).unwrap())
    );
    assert_eq!(loaded.rows[0].features["mfa_enabled"], Value::Bool(true));
    assert_eq!(loaded.rows[1].features["mfa_enabled"], Value::Bool(false));
}

#[test]
fn load_decision_traces_auto_supports_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let jsonl_path = dir.path().join("decision_traces.jsonl");
    std::fs::write(
        &jsonl_path,
        "{\"credit_score\":780,\"annual_income\":\"$95,000\",\"approved\":\"approved\"}\n{\"credit_score\":570,\"annual_income\":\"$48,000\",\"approved\":\"denied\"}\n",
    )
    .unwrap();

    let loaded = load_decision_traces_auto(&jsonl_path, None, None, None).unwrap();
    assert_eq!(loaded.label_column, "approved");
    assert_eq!(loaded.rows[0].features["annual_income"], 95_000);
    assert!(loaded.rows[0].allowed);
    assert!(!loaded.rows[1].allowed);
}

#[test]
fn load_decision_traces_auto_supports_nested_json() {
    let dir = tempfile::tempdir().unwrap();
    let json_path = dir.path().join("decision_traces.json");
    std::fs::write(
        &json_path,
        r#"[
  {
"account": {"age_days": 730, "verified": "Yes"},
"signals": {"toxicity_score": 0.05, "spam_likelihood": 0.10},
"result": {"verdict": "pass"}
  },
  {
"account": {"age_days": 12, "verified": "No"},
"signals": {"toxicity_score": 0.82, "spam_likelihood": 0.91},
"result": {"verdict": "flagged"}
  }
]"#,
    )
    .unwrap();

    let loaded = load_decision_traces_auto(&json_path, None, None, None).unwrap();
    assert_eq!(loaded.label_column, "result.verdict");
    assert_eq!(loaded.rows[0].features["account.age_days"], 730);
    assert_eq!(
        loaded.rows[0].features["account.verified"],
        Value::Bool(true)
    );
    assert_eq!(
        loaded.rows[1].features["signals.spam_likelihood"],
        Value::Number(Number::from_f64(0.91).unwrap())
    );
    assert!(loaded.rows[0].allowed);
    assert!(!loaded.rows[1].allowed);
}

#[test]
fn decision_trace_loader_errors_explain_normalization_boundary() {
    let dir = tempfile::tempdir().unwrap();

    let csv_path = dir.path().join("empty_value.csv");
    std::fs::write(&csv_path, "age,allowed\n,yes\n").unwrap();
    let err = load_decision_traces_auto(&csv_path, None, None, None).unwrap_err();
    assert!(err.to_string().contains("empty value"));
    assert!(err
        .to_string()
        .contains("normalized rectangular decision traces"));

    let json_path = dir.path().join("null_value.json");
    std::fs::write(
        &json_path,
        r#"[{"age":21,"allowed":"yes"},{"age":null,"allowed":"no"}]"#,
    )
    .unwrap();
    let err = load_decision_traces_auto(&json_path, None, None, None).unwrap_err();
    assert!(err.to_string().contains("contains null"));
    assert!(err.to_string().contains("trace_source plugin"));

    let ragged_path = dir.path().join("ragged.jsonl");
    std::fs::write(
        &ragged_path,
        "{\"age\":21,\"allowed\":\"yes\"}\n{\"score\":9,\"allowed\":\"no\"}\n",
    )
    .unwrap();
    let err = load_decision_traces_auto(&ragged_path, None, None, None).unwrap_err();
    assert!(err.to_string().contains("different schema"));
    assert!(err.to_string().contains("adapter before discovery"));
}

#[test]
fn load_decision_traces_requires_explicit_mapping_for_unknown_binary_labels() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(&csv_path, "score,status\n1,alpha\n0,beta\n").unwrap();

    let err = load_decision_traces_auto(&csv_path, Some("status"), None, None).unwrap_err();
    assert!(err
        .to_string()
        .contains("pass --default-label or --rule-label explicitly"));

    let loaded = load_decision_traces_auto(&csv_path, Some("status"), Some("alpha"), None).unwrap();
    assert!(loaded.rows[0].allowed);
    assert!(!loaded.rows[1].allowed);
}

#[test]
fn load_decision_traces_auto_rejects_ambiguous_binary_columns() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(&csv_path, "is_member,is_urgent\n1,0\n0,1\n").unwrap();

    let err = load_decision_traces_auto(&csv_path, None, None, None).unwrap_err();
    assert!(err
        .to_string()
        .contains("multiple possible binary label fields"));
    assert!(err.to_string().contains("is_member"));
    assert!(err.to_string().contains("is_urgent"));
}

#[test]
fn load_decision_traces_filters_feature_columns() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "age,is_member,source,note,allowed\n21,1,review_a,ok,allowed\n15,1,review_b,manual,denied\n",
    )
    .unwrap();

    let loaded = load_decision_traces_auto_with_feature_selection(
        &csv_path,
        None,
        None,
        None,
        &FeatureColumnSelection {
            feature_columns: Some(vec!["is_member".to_string(), "age".to_string()]),
            exclude_columns: Vec::new(),
        },
    )
    .unwrap();

    assert_eq!(loaded.label_column, "allowed");
    assert_eq!(loaded.rows[0].features.len(), 2);
    assert_eq!(loaded.rows[0].features["age"], 21);
    assert_eq!(loaded.rows[0].features["is_member"], 1);
    assert!(!loaded.rows[0].features.contains_key("source"));
    assert!(!loaded.rows[0].features.contains_key("note"));
}

#[test]
fn load_decision_traces_excludes_non_feature_columns() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "age,is_member,source,note,allowed\n21,1,review_a,ok,allowed\n15,1,review_b,manual,denied\n",
    )
    .unwrap();

    let loaded = load_decision_traces_auto_with_feature_selection(
        &csv_path,
        Some("allowed"),
        None,
        None,
        &FeatureColumnSelection {
            feature_columns: None,
            exclude_columns: vec!["source".to_string(), "note".to_string()],
        },
    )
    .unwrap();

    assert_eq!(loaded.rows[0].features.len(), 2);
    assert!(loaded.rows[0].features.contains_key("age"));
    assert!(loaded.rows[0].features.contains_key("is_member"));
    assert!(!loaded.rows[0].features.contains_key("source"));
    assert!(!loaded.rows[0].features.contains_key("note"));
}

#[test]
fn feature_column_selection_rejects_reserved_or_missing_columns() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(&csv_path, "age,allowed\n21,allowed\n15,denied\n").unwrap();

    let reserved = load_decision_traces_auto_with_feature_selection(
        &csv_path,
        Some("allowed"),
        None,
        None,
        &FeatureColumnSelection {
            feature_columns: Some(vec!["age".to_string(), "allowed".to_string()]),
            exclude_columns: Vec::new(),
        },
    )
    .unwrap_err();
    assert!(reserved.to_string().contains("reserved"));

    let missing = load_decision_traces_auto_with_feature_selection(
        &csv_path,
        Some("allowed"),
        None,
        None,
        &FeatureColumnSelection {
            feature_columns: None,
            exclude_columns: vec!["note".to_string()],
        },
    )
    .unwrap_err();
    assert!(missing.to_string().contains("missing column"));
}

#[test]
fn build_pearl_from_csv_emits_gate_ir_and_report() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "age,is_member,allowed\n21,1,allowed\n25,0,allowed\n30,1,allowed\n35,0,allowed\n16,1,denied\n15,0,denied\n14,1,denied\n13,0,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "age_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.rows, 8);
    assert_eq!(result.rules_discovered, 1);
    assert_eq!(result.training_parity, 1.0);
    assert_eq!(result.proposal_phase.status, ProposalPhaseStatus::Skipped);
    assert!(result
        .build_phases
        .iter()
        .any(|phase| phase.name == "proposal_phase"));
    assert_eq!(
        result.residual_recovery.state,
        ResidualRecoveryState::Disabled
    );
    assert!(output_dir.join("pearl.ir.json").exists());
    assert!(output_dir.join("build_report.json").exists());
    assert!(output_dir.join("proposal_report.json").exists());
}

#[test]
fn build_pearl_auto_proposes_on_training_mismatch_cluster() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "income,debt,requested_limit,requested_amount,approved\n100000,20000,10000,8000,approved\n80000,30000,12000,9000,approved\n50000,10000,12000,10000,approved\n60000,20000,15000,13000,approved\n40000,30000,10000,7000,denied\n50000,35000,12000,9000,denied\n90000,20000,10000,14000,denied\n120000,20000,15000,18000,denied\n90000,20000,10000,7000,approved\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "proposal_gate".to_string(),
            label_column: "approved".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: Some(1),
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert!(result.training_parity < 1.0);
    assert_eq!(result.proposal_phase.status, ProposalPhaseStatus::Ran);
    assert_eq!(
        result.proposal_phase.trigger.as_deref(),
        Some("training_mismatch_cluster")
    );
    assert_eq!(
        result.proposal_phase.diagnosis.as_deref(),
        Some("missing_relationship_feature")
    );
    assert_eq!(
        result.proposal_phase.recommended_next_phase.as_deref(),
        Some("promote_derived_feature_to_observer")
    );
    assert!(result.proposal_phase.stages.iter().any(|stage| {
        stage.name == "mismatch_mining" && stage.status == ProposalStageStatus::Completed
    }));
    assert!(result
        .proposal_phase
        .stages
        .iter()
        .any(|stage| stage.name == "subgroup_discovery" && stage.candidates_produced > 0));
    assert!(result
        .proposal_phase
        .stages
        .iter()
        .any(|stage| { stage.name == "derived_feature_search" && stage.candidates_produced > 0 }));
    assert!(result.proposal_phase.stages.iter().any(|stage| {
        stage.name == "interpretable_model_search" && stage.candidates_produced > 0
    }));
    assert!(result.proposal_phase.candidates_tested > 0);
    assert!(result.proposal_phase.candidates.iter().any(|candidate| {
        candidate.status == ProposalCandidateStatus::Validated
            && candidate.source_stage == "derived_feature_search"
    }));
    assert!(result.proposal_phase.candidates.iter().any(|candidate| {
        candidate.source_stage == "derived_feature_search"
            && candidate.validation.deterministic
            && candidate.validation.validator == "training_replay"
            && candidate.recommendation.as_deref() == Some("promote_to_observer_feature")
            && candidate.feature_expression.is_some()
    }));
    assert!(result.proposal_phase.candidates.iter().any(|candidate| {
        candidate.source_stage == "interpretable_model_search"
            && candidate.validation.deterministic
            && candidate.evidence.fixed_mismatches > 0
    }));
    let proposal_report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("proposal_report.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(proposal_report["status"].as_str(), Some("ran"));
    assert!(proposal_report["stages"].as_array().is_some_and(|stages| {
        stages
            .iter()
            .any(|stage| stage["name"].as_str() == Some("derived_feature_search"))
    }));
}

#[test]
fn build_pearl_routes_exact_trace_conflicts_before_proposals() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "route,risk,burst,allowed\nadmin,1,5,denied\nadmin,1,5,allowed\npublic,0,1,allowed\npublic,1,1,allowed\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "conflict_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.proposal_phase.status, ProposalPhaseStatus::Ran);
    assert_eq!(
        result.proposal_phase.trigger.as_deref(),
        Some("exact_trace_conflict")
    );
    assert_eq!(
        result.proposal_phase.diagnosis.as_deref(),
        Some("exact_trace_conflict")
    );
    assert_eq!(
        result.proposal_phase.recommended_next_phase.as_deref(),
        Some("add_missing_feature_or_adjudicate_labels")
    );
    assert_eq!(result.proposal_phase.candidates_tested, 0);
    assert!(result.proposal_phase.candidates.is_empty());
    assert_eq!(result.proposal_phase.exact_trace_conflicts.len(), 1);
    assert_eq!(
        result.proposal_phase.exact_trace_conflicts[0].row_indexes,
        vec![0, 1]
    );
}

#[test]
fn build_pearl_validates_safe_proposal_under_rule_budget() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "case_id,score,unit,allowed\nlow_block,1,1,denied\nmiddle_pass,2,1,allowed\nhigh_block,3,1,denied\nbaseline_pass,0,1,allowed\nupper_pass,4,1,allowed\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "budgeted_proposal_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: Some(1),
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert!(result.training_parity < 1.0);
    assert_eq!(result.proposal_phase.status, ProposalPhaseStatus::Ran);
    assert!(result.proposal_phase.validated_candidates > 0);
    assert!(result.proposal_phase.candidates.iter().any(|candidate| {
        candidate.status == ProposalCandidateStatus::Validated
            && candidate.validation.deterministic
            && candidate.validation.passed
            && candidate.evidence.fixed_mismatches > 0
            && candidate.evidence.introduced_mismatches == 0
    }));
    assert!(!result.proposal_phase.candidates.iter().any(|candidate| {
        candidate.status == ProposalCandidateStatus::Validated
            && candidate
                .suggested_region
                .get("feature")
                .and_then(Value::as_str)
                == Some("case_id")
    }));
}

#[test]
fn build_pearl_records_rule_evidence_from_trace_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "age,source_id,source_anchor,source_citation,source_quote,allowed\n21,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,allowed\n25,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,allowed\n16,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,denied\n15,foia,552b5,5 USC 552(b)(5),inter agency memo exemption,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "evidence_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection {
                feature_columns: None,
                exclude_columns: vec![
                    "source_id".to_string(),
                    "source_anchor".to_string(),
                    "source_citation".to_string(),
                    "source_quote".to_string(),
                ],
            },
        },
    )
    .unwrap();

    assert_eq!(result.rules_discovered, 1);
    let ir = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let evidence = ir.rules[0]
        .evidence
        .as_ref()
        .expect("learned rule should carry evidence");
    assert_eq!(evidence.schema_version, "logicpearl.rule_evidence.v2");
    assert_eq!(evidence.support.denied_trace_count, 2);
    assert_eq!(evidence.support.allowed_trace_count, 0);
    assert_eq!(evidence.reliability.matched_trace_count, 2);
    assert_eq!(evidence.reliability.precision, 1.0);
    assert_eq!(evidence.reliability.false_positive_rate, 0.0);
    assert!(!evidence.support.example_traces.is_empty());
    let example = &evidence.support.example_traces[0];
    assert!(example.trace_row_hash.starts_with("sha256:"));
    assert_eq!(example.source_id.as_deref(), Some("foia"));
    assert_eq!(example.source_anchor.as_deref(), Some("552b5"));
    assert_eq!(example.citation.as_deref(), Some("5 USC 552(b)(5)"));
    assert!(example
        .quote_hash
        .as_deref()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    let ir_text = std::fs::read_to_string(output_dir.join("pearl.ir.json")).unwrap();
    assert!(!ir_text.contains("inter agency memo exemption"));
}

#[test]
fn build_pearl_from_jsonl_emits_gate_ir_and_report() {
    let dir = tempfile::tempdir().unwrap();
    let jsonl_path = dir.path().join("decision_traces.jsonl");
    std::fs::write(
        &jsonl_path,
        "{\"age\":21,\"is_member\":1,\"allowed\":\"allowed\"}\n{\"age\":25,\"is_member\":0,\"allowed\":\"allowed\"}\n{\"age\":16,\"is_member\":1,\"allowed\":\"denied\"}\n{\"age\":15,\"is_member\":0,\"allowed\":\"denied\"}\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &jsonl_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "age_gate_jsonl".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.rows, 4);
    assert_eq!(result.training_parity, 1.0);
    assert!(output_dir.join("pearl.ir.json").exists());
}

#[test]
fn canonicalize_rules_merges_adjacent_numeric_intervals() {
    let rules = vec![
        RuleDefinition {
            id: "rule_a".to_string(),
            kind: RuleKind::Predicate,
            bit: 0,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "toxicity".to_string(),
                op: ComparisonOperator::Eq,
                value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
            }),
            label: Some("deny".to_string()),
            message: Some("deny toxic content".to_string()),
            severity: Some("high".to_string()),
            counterfactual_hint: Some("lower toxicity".to_string()),
            verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            evidence: None,
        },
        RuleDefinition {
            id: "rule_b".to_string(),
            kind: RuleKind::Predicate,
            bit: 1,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "toxicity".to_string(),
                op: ComparisonOperator::Gt,
                value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
            }),
            label: Some("deny".to_string()),
            message: Some("deny toxic content".to_string()),
            severity: Some("high".to_string()),
            counterfactual_hint: Some("lower toxicity".to_string()),
            verification_status: Some(RuleVerificationStatus::RefinedUnverified),
            evidence: None,
        },
    ];

    let canonicalized = canonicalize_rules(rules);
    assert_eq!(canonicalized.len(), 1);
    assert_eq!(
        canonicalized[0].verification_status,
        Some(RuleVerificationStatus::RefinedUnverified)
    );
    assert_eq!(
        canonicalized[0].deny_when,
        Expression::Comparison(ComparisonExpression {
            feature: "toxicity".to_string(),
            op: ComparisonOperator::Gte,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
        })
    );
}

#[test]
fn canonicalize_rules_preserves_distinct_messages() {
    let rules = vec![
        RuleDefinition {
            id: "rule_a".to_string(),
            kind: RuleKind::Predicate,
            bit: 0,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "toxicity".to_string(),
                op: ComparisonOperator::Eq,
                value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
            }),
            label: None,
            message: Some("exact threshold".to_string()),
            severity: None,
            counterfactual_hint: None,
            verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            evidence: None,
        },
        RuleDefinition {
            id: "rule_b".to_string(),
            kind: RuleKind::Predicate,
            bit: 1,
            deny_when: Expression::Comparison(ComparisonExpression {
                feature: "toxicity".to_string(),
                op: ComparisonOperator::Gt,
                value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.71).unwrap())),
            }),
            label: None,
            message: Some("strictly above threshold".to_string()),
            severity: None,
            counterfactual_hint: None,
            verification_status: Some(RuleVerificationStatus::PipelineUnverified),
            evidence: None,
        },
    ];

    let canonicalized = canonicalize_rules(rules);
    assert_eq!(canonicalized.len(), 2);
}

#[test]
fn discover_from_csv_emits_artifact_set_and_reports() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("multi_target.csv");
    std::fs::write(
        &csv_path,
        "signal_a,signal_b,target_a,target_b\n0,0,allowed,allowed\n1,0,denied,allowed\n0,1,allowed,denied\n1,1,denied,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("discovered");

    let result = discover_from_csv(
        &csv_path,
        &DiscoverOptions {
            output_dir: output_dir.clone(),
            artifact_set_id: "multi_target_demo".to_string(),
            target_columns: vec!["target_a".to_string(), "target_b".to_string()],
            feature_selection: FeatureColumnSelection::default(),
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
        },
    )
    .unwrap();

    assert_eq!(result.targets.len(), 2);
    assert_eq!(result.artifacts.len(), 2);
    assert!(output_dir.join("artifact_set.json").exists());
    assert!(output_dir.join("discover_report.json").exists());
    assert!(output_dir.join("artifacts/target_a/pearl.ir.json").exists());
    assert!(output_dir.join("artifacts/target_b/pearl.ir.json").exists());
    assert!(result.skipped_targets.is_empty());
}

#[test]
fn discover_from_csv_respects_feature_column_selection() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("multi_target.csv");
    std::fs::write(
        &csv_path,
        "signal,source,note,target_a,target_b\n0,review_a,ok,allowed,allowed\n1,review_b,manual,denied,denied\n0,review_c,ok,allowed,allowed\n1,review_d,manual,denied,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("discovered");

    let result = discover_from_csv(
        &csv_path,
        &DiscoverOptions {
            output_dir,
            artifact_set_id: "filtered_multi_target_demo".to_string(),
            target_columns: vec!["target_a".to_string(), "target_b".to_string()],
            feature_selection: FeatureColumnSelection {
                feature_columns: None,
                exclude_columns: vec!["source".to_string(), "note".to_string()],
            },
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
        },
    )
    .unwrap();

    assert_eq!(result.features, vec!["signal"]);
    assert!(result
        .artifacts
        .iter()
        .all(|artifact| artifact.selected_features == vec!["signal"]));
}

#[test]
fn build_prefers_higher_parity_rule_over_tiny_zero_fp_fragment() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "signal_flag,confidence,allowed\n0,0.02,allowed\n0,0.02,allowed\n0,0.02,allowed\n1,0.02,allowed\n1,0.02,denied\n1,0.02,denied\n1,0.02,denied\n1,0.21,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "approximate_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    let pearl_ir = std::fs::read_to_string(output_dir.join("pearl.ir.json")).unwrap();
    assert!(pearl_ir.contains("signal_flag"));
    assert!(result.training_parity > 0.8);
}

#[test]
fn build_residual_pass_recovers_missed_boolean_slice() {
    if !solver_available() {
        return;
    }

    let rows = vec![
        row(&[("seed", 1), ("a", 1), ("b", 1)], false),
        row(&[("seed", 0), ("a", 1), ("b", 1)], false),
        row(&[("seed", 0), ("a", 1), ("b", 1)], false),
        row(&[("seed", 0), ("a", 1), ("b", 0)], true),
        row(&[("seed", 0), ("a", 0), ("b", 1)], true),
        row(&[("seed", 0), ("a", 0), ("b", 0)], true),
    ];
    let first_pass_gate = gate_from_rules(
        &rows,
        &rows,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        "residual_gate",
        vec![rule_from_candidate(
            0,
            &CandidateRule::new(
                Expression::Comparison(ComparisonExpression {
                    feature: "seed".to_string(),
                    op: ComparisonOperator::Gt,
                    value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                }),
                1,
                0,
            ),
        )],
    )
    .unwrap();

    let residual_rules = discover_residual_rules(
        &rows,
        &first_pass_gate,
        &BTreeMap::new(),
        &ResidualPassOptions {
            max_conditions: 2,
            min_positive_support: 2,
            max_negative_hits: 0,
            max_rules: 1,
        },
    )
    .unwrap();

    assert_eq!(residual_rules.len(), 1);
    match &residual_rules[0].deny_when {
        Expression::All { all } => {
            assert_eq!(all.len(), 2);
            let rendered = serde_json::to_string(&all).unwrap();
            assert!(rendered.contains("\"feature\":\"a\""));
            assert!(rendered.contains("\"feature\":\"b\""));
        }
        other => panic!("expected residual all-expression, got {other:?}"),
    }
}

#[test]
fn build_refine_tightens_uniquely_overbroad_rule() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "signal,guard,allowed\n1,1,denied\n1,1,denied\n1,0,allowed\n0,1,allowed\n0,0,allowed\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "refined_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: true,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.refined_rules_applied, 1);
    assert_eq!(result.training_parity, 1.0);

    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let gate_json = serde_json::to_string_pretty(&gate).unwrap();
    assert!(gate_json.contains("\"all\""));
    assert!(gate_json.contains("\"feature\": \"signal\""));
    assert!(gate_json.contains("\"feature\": \"guard\""));
}

#[test]
fn build_recall_biased_policy_uses_bottom_up_broad_conjunction() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("output");
    let mut rows = Vec::new();
    for index in 0..60 {
        rows.push(row_values(
            &[
                ("plant", Value::String("fern".to_string())),
                ("light_level", Value::Number(Number::from(3))),
                ("humidity", Value::Number(Number::from(index))),
            ],
            false,
        ));
    }
    for index in 0..6 {
        rows.push(row_values(
            &[
                ("plant", Value::String("fern".to_string())),
                ("light_level", Value::Number(Number::from(3))),
                ("humidity", Value::Number(Number::from(index))),
            ],
            true,
        ));
    }
    for index in 0..100 {
        rows.push(row_values(
            &[
                ("plant", Value::String("fern".to_string())),
                ("light_level", Value::Number(Number::from(1))),
                ("humidity", Value::Number(Number::from(index % 60))),
            ],
            true,
        ));
    }
    for index in 0..100 {
        rows.push(row_values(
            &[
                ("plant", Value::String("succulent".to_string())),
                ("light_level", Value::Number(Number::from(3))),
                ("humidity", Value::Number(Number::from(index % 60))),
            ],
            true,
        ));
    }
    for index in 0..300 {
        rows.push(row_values(
            &[
                ("plant", Value::String("succulent".to_string())),
                ("light_level", Value::Number(Number::from(1))),
                ("humidity", Value::Number(Number::from(index % 60))),
            ],
            true,
        ));
    }

    let result = build_pearl_from_rows(
        &rows,
        "bottom_up_garden".to_string(),
        &BuildOptions {
            output_dir: PathBuf::from(&output_dir),
            gate_id: "bottom_up_garden".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: true,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::RecallBiased {
                deny_recall_target: 1.0,
                max_false_positive_rate: 0.02,
            },
            max_rules: Some(3),
            max_conditions: Some(3),
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert!(result.rules_discovered <= 3);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let rendered = serde_json::to_string(&gate.rules).unwrap();
    assert!(
        rendered.contains("\"feature\":\"plant\""),
        "expected plant predicate in rules: {rendered}"
    );
    assert!(
        rendered.contains("\"feature\":\"light_level\""),
        "expected light predicate in rules: {rendered}"
    );
    assert!(
        !rendered.contains("\"feature\":\"humidity\""),
        "bottom-up broad conjunction should not depend on one-off humidity fragments: {rendered}"
    );
}

#[test]
fn regression_fixture_broad_signal_beats_narrow_fragments() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("broad_signal");
    let result = build_pearl_from_csv(
        &regression_fixture("broad_signal_beats_narrow_fragments.csv"),
        &regression_build_options(
            output_dir.clone(),
            "regression_broad_signal",
            crate::SelectionPolicy::Balanced,
        ),
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    assert!(
        gate_has_rule_with_features(&gate, &["plant", "light_level"]),
        "expected a broad plant/light rule, got {}",
        render_rules(&gate)
    );
    assert!(
        !gate_mentions_feature(&gate, "humidity"),
        "broad signal fixture should not learn humidity fragments: {}",
        render_rules(&gate)
    );
}

#[test]
fn regression_fixture_imbalanced_prior_rejects_baseline_only_rules() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("imbalanced_prior");
    let result = build_pearl_from_csv(
        &regression_fixture("imbalanced_prior_rejects_baseline_only_rules.csv"),
        &regression_build_options(
            output_dir.clone(),
            "regression_imbalanced_prior",
            crate::SelectionPolicy::Balanced,
        ),
    )
    .unwrap();

    assert_eq!(result.rules_discovered, 1);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    assert!(
        gate_mentions_feature(&gate, "pest_visible"),
        "expected pest signal rule, got {}",
        render_rules(&gate)
    );
    assert!(
        !gate_mentions_feature(&gate, "prior_flag"),
        "baseline-only prior rule should be rejected: {}",
        render_rules(&gate)
    );
}

#[test]
fn regression_fixture_recall_biased_accepts_controlled_false_positives() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("recall_biased");
    let result = build_pearl_from_csv(
        &regression_fixture("recall_biased_accepts_controlled_false_positives.csv"),
        &regression_build_options(
            output_dir.clone(),
            "regression_recall_biased",
            crate::SelectionPolicy::RecallBiased {
                deny_recall_target: 1.0,
                max_false_positive_rate: 0.10,
            },
        ),
    )
    .unwrap();

    assert!(
        result.training_parity > 0.90 && result.training_parity < 1.0,
        "controlled false positives should preserve high but imperfect parity, got {}",
        result.training_parity
    );
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    assert!(
        gate_has_rule_with_features(&gate, &["plant", "light_level"]),
        "expected a recall-biased plant/light rule, got {}",
        render_rules(&gate)
    );
    assert!(
        gate.rules
            .iter()
            .any(|rule| rule_allowed_support(rule) == 2),
        "expected the selected broad rule to carry two controlled false positives: {}",
        render_rules(&gate)
    );
}

#[test]
fn regression_fixture_balanced_preserves_zero_fp_exact_policies() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("balanced_zero_fp");
    let result = build_pearl_from_csv(
        &regression_fixture("balanced_preserves_zero_fp_exact_policies.csv"),
        &regression_build_options(
            output_dir.clone(),
            "regression_balanced_zero_fp",
            crate::SelectionPolicy::Balanced,
        ),
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    assert!(
        gate_mentions_feature(&gate, "signal_a") || gate_mentions_feature(&gate, "signal_b"),
        "expected signal rules, got {}",
        render_rules(&gate)
    );
    assert!(
        gate.rules
            .iter()
            .all(|rule| rule_allowed_support(rule) == 0),
        "balanced fixture should preserve zero-false-positive rules: {}",
        render_rules(&gate)
    );
}

#[test]
fn regression_fixture_shared_prefix_shards_collapse_to_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("shared_prefix");
    let result = build_pearl_from_csv(
        &regression_fixture("shared_prefix_shards_collapse_to_prefix.csv"),
        &regression_build_options(
            output_dir.clone(),
            "regression_shared_prefix",
            crate::SelectionPolicy::Balanced,
        ),
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    assert_eq!(
        gate.rules.len(),
        1,
        "shared prefix shards should collapse to one rule: {}",
        render_rules(&gate)
    );
    assert!(
        gate_mentions_feature(&gate, "pest_visible"),
        "expected pest prefix rule, got {}",
        render_rules(&gate)
    );
    assert!(
        !gate_mentions_feature(&gate, "root_bound") && !gate_mentions_feature(&gate, "leaf_curl"),
        "prefix rule should not keep shard predicates: {}",
        render_rules(&gate)
    );
}

#[test]
fn build_residual_pass_recovers_policy_style_conjunction_rules() {
    if !solver_available() {
        return;
    }

    let rows = vec![
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(1)),
                ("action_read", Value::from(0)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(1)),
                ("action_read", Value::from(0)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(1)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(1)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(0)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(1)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(0)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(1)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(0)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(0)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(0)),
                ("sensitivity", Value::from(2)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(0)),
                ("sensitivity", Value::from(1)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            false,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            true,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(1)),
            ],
            true,
        ),
        row_values(
            &[
                ("is_admin", Value::from(1)),
                ("action_delete", Value::from(1)),
                ("action_read", Value::from(0)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            true,
        ),
        row_values(
            &[
                ("is_admin", Value::from(1)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(1)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            true,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(1)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(0)),
                ("is_public", Value::from(1)),
                ("is_contractor", Value::from(0)),
            ],
            true,
        ),
        row_values(
            &[
                ("is_admin", Value::from(0)),
                ("action_delete", Value::from(0)),
                ("action_read", Value::from(1)),
                ("archived", Value::from(0)),
                ("is_authenticated", Value::from(0)),
                ("sensitivity", Value::from(0)),
                ("team_match", Value::from(1)),
                ("is_public", Value::from(0)),
                ("is_contractor", Value::from(0)),
            ],
            true,
        ),
    ];

    let dir = tempfile::tempdir().unwrap();
    let coarse_output = dir.path().join("coarse");
    let recovered_output = dir.path().join("recovered");

    let coarse = build_pearl_from_rows(
        &rows,
        "policy_style".to_string(),
        &BuildOptions {
            output_dir: coarse_output.clone(),
            gate_id: "policy_style".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();
    assert!(coarse.training_parity < 1.0);
    assert_eq!(
        coarse.residual_recovery.state,
        ResidualRecoveryState::Disabled
    );

    let recovered = build_pearl_from_rows(
        &rows,
        "policy_style".to_string(),
        &BuildOptions {
            output_dir: recovered_output.clone(),
            gate_id: "policy_style".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: true,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    let gate = LogicPearlGateIr::from_path(recovered_output.join("pearl.ir.json")).unwrap();
    let rendered = serde_json::to_string(&gate.rules).unwrap();
    assert_eq!(
        recovered.training_parity, 1.0,
        "unexpected recovered rules: {rendered}"
    );
    assert_eq!(
        recovered.residual_recovery.state,
        ResidualRecoveryState::Applied
    );
    assert!(rendered.contains("\"all\""));
    assert!(rendered.contains("\"feature\":\"action_read\""));
    assert!(rendered.contains("\"feature\":\"is_admin\""));
    assert!(rendered.contains("\"feature\":\"archived\""));
    assert!(rendered.contains("\"feature\":\"team_match\""));
    assert!(rendered.contains("\"feature\":\"sensitivity\""));
}

#[test]
fn build_discovers_boolean_feature_predicate() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(
        &csv_path,
        "mfa_enabled,approved\nYes,approved\nYes,approved\nYes,approved\nNo,denied\nNo,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: output_dir.clone(),
            gate_id: "bool_gate".to_string(),
            label_column: "approved".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let rendered = serde_json::to_string(&gate).unwrap();
    assert!(rendered.contains("\"feature\":\"mfa_enabled\""));
    assert!(rendered.contains("\"value\":false"));
}

#[test]
fn build_learns_numeric_feature_relationships() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("access_control.csv");
    std::fs::write(
        &csv_path,
        "clearance_level,resource_sensitivity,allowed\n\
5,2,allowed\n\
4,1,allowed\n\
3,2,allowed\n\
2,1,allowed\n\
4,5,denied\n\
3,4,denied\n\
2,3,denied\n\
1,2,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: output_dir.clone(),
            gate_id: "access_control".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let rendered = serde_json::to_string(&gate).unwrap();
    assert!(rendered.contains("\"feature_ref\":\"resource_sensitivity\""));
}

#[test]
fn build_prefers_zero_false_positive_multi_rule_completion() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("content.csv");
    std::fs::write(
        &csv_path,
        "toxicity,spam,account_age,report_count,allowed\n\
0.05,0.10,730,0,allowed\n\
0.12,0.08,1200,1,allowed\n\
0.20,0.15,365,0,allowed\n\
0.08,0.22,540,1,allowed\n\
0.15,0.18,900,0,allowed\n\
0.03,0.05,2000,0,allowed\n\
0.18,0.12,450,1,allowed\n\
0.10,0.30,180,0,allowed\n\
0.22,0.25,60,2,allowed\n\
0.06,0.11,1500,0,allowed\n\
0.25,0.20,300,1,allowed\n\
0.14,0.35,90,1,allowed\n\
0.28,0.40,45,2,allowed\n\
0.80,0.15,800,0,denied\n\
0.82,0.20,1200,1,denied\n\
0.90,0.10,600,0,denied\n\
0.78,0.25,365,0,denied\n\
0.18,0.85,180,0,denied\n\
0.12,0.90,365,1,denied\n\
0.22,0.82,540,0,denied\n\
0.15,0.18,10,0,denied\n\
0.08,0.25,5,1,denied\n\
0.20,0.22,20,0,denied\n\
0.18,0.20,730,5,denied\n\
0.10,0.18,900,6,denied\n\
0.22,0.25,540,7,denied\n\
0.78,0.88,8,9,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("output");

    let result = build_pearl_from_csv(
        &csv_path,
        &BuildOptions {
            output_dir: output_dir.clone(),
            gate_id: "content_gate".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let rendered = serde_json::to_string(&gate).unwrap();
    assert!(rendered.contains("\"feature\":\"spam\""));
    assert!(rendered.contains("\"feature\":\"toxicity\""));
    assert!(!rendered.contains("\"feature\":\"toxicity\",\"op\":\">\",\"value\":0.15"));
}

#[test]
fn prune_redundant_rules_drops_exact_match_shards() {
    let rows = vec![
        row_values(
            &[
                ("annual_income", Value::Number(Number::from(85000))),
                ("debt_ratio", Value::Number(Number::from_f64(0.56).unwrap())),
                ("credit_score", Value::Number(Number::from(680))),
            ],
            false,
        ),
        row_values(
            &[
                ("annual_income", Value::Number(Number::from(62000))),
                ("debt_ratio", Value::Number(Number::from_f64(0.55).unwrap())),
                ("credit_score", Value::Number(Number::from(680))),
            ],
            false,
        ),
        row_values(
            &[
                ("annual_income", Value::Number(Number::from(48000))),
                ("debt_ratio", Value::Number(Number::from_f64(0.61).unwrap())),
                ("credit_score", Value::Number(Number::from(650))),
            ],
            false,
        ),
        row_values(
            &[
                ("annual_income", Value::Number(Number::from(45000))),
                ("debt_ratio", Value::Number(Number::from_f64(0.35).unwrap())),
                ("credit_score", Value::Number(Number::from(650))),
            ],
            true,
        ),
        row_values(
            &[
                ("annual_income", Value::Number(Number::from(72000))),
                ("debt_ratio", Value::Number(Number::from_f64(0.31).unwrap())),
                ("credit_score", Value::Number(Number::from(720))),
            ],
            true,
        ),
    ];
    let rules = vec![
        rule_from_candidate(
            0,
            &CandidateRule::new(
                Expression::Comparison(ComparisonExpression {
                    feature: "annual_income".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Number(Number::from(85000))),
                }),
                1,
                0,
            ),
        ),
        rule_from_candidate(
            1,
            &CandidateRule::new(
                Expression::Comparison(ComparisonExpression {
                    feature: "credit_score".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::Number(Number::from(680))),
                }),
                2,
                0,
            ),
        ),
        rule_from_candidate(
            2,
            &CandidateRule::new(
                Expression::Comparison(ComparisonExpression {
                    feature: "debt_ratio".to_string(),
                    op: ComparisonOperator::Gte,
                    value: ComparisonValue::Literal(Value::Number(Number::from_f64(0.55).unwrap())),
                }),
                3,
                0,
            ),
        ),
    ];

    let pruned = prune_redundant_rules(&rows, rules);
    let rendered = serde_json::to_string(&pruned).unwrap();
    assert_eq!(pruned.len(), 1);
    assert!(rendered.contains("\"feature\":\"debt_ratio\""));
    assert!(!rendered.contains("\"feature\":\"annual_income\""));
    assert!(!rendered.contains("\"feature\":\"credit_score\""));
}

#[test]
fn build_reuses_cached_output_when_rows_and_options_match() {
    let _guard = discovery_selection_env_lock()
        .lock()
        .expect("env lock should be available");
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("decision_traces.csv");
    std::fs::write(&csv_path, "flag,allowed\n0,allowed\n1,denied\n1,denied\n").unwrap();
    let output_dir = dir.path().join("output");
    let options = BuildOptions {
        output_dir: output_dir.clone(),
        gate_id: "cached_gate".to_string(),
        label_column: "allowed".to_string(),
        positive_label: None,
        negative_label: None,
        residual_pass: false,
        refine: false,
        pinned_rules: None,
        feature_dictionary: None,
        feature_governance: None,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: crate::SelectionPolicy::Balanced,
        max_rules: None,
        max_conditions: None,
        proposal_policy: ProposalPolicy::ReportOnly,
        feature_selection: FeatureColumnSelection::default(),
    };

    let first = build_pearl_from_csv(&csv_path, &options).unwrap();
    let second = build_pearl_from_csv(&csv_path, &options).unwrap();

    assert!(!first.cache_hit);
    assert!(second.cache_hit);
    assert_eq!(second.rules_discovered, first.rules_discovered);
    assert!(output_dir.join(".logicpearl-cache.json").exists());
}

#[test]
fn dedupe_prefers_stronger_verification_for_same_rule() {
    let pipeline_rule = RuleDefinition {
        id: "rule_a".to_string(),
        kind: RuleKind::Predicate,
        bit: 5,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: "flag".to_string(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
        }),
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: Some(RuleVerificationStatus::PipelineUnverified),
        evidence: None,
    };
    let refined_rule = RuleDefinition {
        id: "rule_b".to_string(),
        kind: RuleKind::Predicate,
        bit: 9,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: "flag".to_string(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
        }),
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: Some(RuleVerificationStatus::RefinedUnverified),
        evidence: None,
    };

    let deduped = dedupe_rules_by_signature(vec![pipeline_rule, refined_rule]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(
        deduped[0].verification_status,
        Some(RuleVerificationStatus::RefinedUnverified)
    );
    assert_eq!(deduped[0].bit, 0);
    assert_eq!(deduped[0].id, "rule_000");
}

#[test]
fn merge_applies_pinned_rule_layer() {
    let discovered = vec![RuleDefinition {
        id: "rule_000".to_string(),
        kind: RuleKind::Predicate,
        bit: 0,
        deny_when: Expression::Comparison(ComparisonExpression {
            feature: "signal".to_string(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
        }),
        label: None,
        message: None,
        severity: None,
        counterfactual_hint: None,
        verification_status: Some(RuleVerificationStatus::PipelineUnverified),
        evidence: None,
    }];
    let pinned = PinnedRuleSet {
        rule_set_version: "1.0".to_string(),
        rule_set_id: "pinned_rules".to_string(),
        rules: vec![RuleDefinition {
            id: "claims_r05".to_string(),
            kind: RuleKind::Predicate,
            bit: 99,
            deny_when: Expression::All {
                all: vec![
                    Expression::Comparison(ComparisonExpression {
                        feature: "signal".to_string(),
                        op: ComparisonOperator::Gt,
                        value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    }),
                    Expression::Comparison(ComparisonExpression {
                        feature: "guard".to_string(),
                        op: ComparisonOperator::Gt,
                        value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    }),
                ],
            },
            label: None,
            message: None,
            severity: None,
            counterfactual_hint: None,
            verification_status: Some(RuleVerificationStatus::RefinedUnverified),
            evidence: None,
        }],
    };

    let merged = merge_discovered_and_pinned_rules(discovered, &pinned);
    assert_eq!(merged.len(), 2);
    let rendered = serde_json::to_string(&merged).unwrap();
    assert!(rendered.contains("\"feature\":\"guard\""));
}

#[test]
fn discover_reuses_cached_output_when_dataset_and_options_match() {
    let _guard = discovery_selection_env_lock()
        .lock()
        .expect("env lock should be available");
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("multi_target.csv");
    std::fs::write(
        &csv_path,
        "signal_a,signal_b,target_a,target_b\n0,0,allowed,allowed\n1,0,denied,allowed\n0,1,allowed,denied\n1,1,denied,denied\n",
    )
    .unwrap();
    let output_dir = dir.path().join("discovered");
    let options = DiscoverOptions {
        output_dir: output_dir.clone(),
        artifact_set_id: "multi_target_demo".to_string(),
        target_columns: vec!["target_a".to_string(), "target_b".to_string()],
        feature_selection: FeatureColumnSelection::default(),
        residual_pass: false,
        refine: false,
        pinned_rules: None,
        feature_dictionary: None,
        feature_governance: None,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: crate::SelectionPolicy::Balanced,
    };

    let first = discover_from_csv(&csv_path, &options).unwrap();
    let persisted_report: Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("discover_report.json")).unwrap(),
    )
    .unwrap();
    let persisted_report_json = serde_json::to_string(&persisted_report).unwrap();
    assert!(
        !persisted_report_json.contains(&dir.path().display().to_string()),
        "discover report should not leak temp paths: {persisted_report_json}"
    );
    assert!(persisted_report["source_csv"]
        .as_str()
        .is_some_and(|value| value.starts_with("<path:sha256:")));
    assert_eq!(
        persisted_report["output_files"]["artifact_set"],
        "artifact_set.json"
    );
    assert_eq!(
        persisted_report["output_files"]["discover_report"],
        "discover_report.json"
    );
    assert!(
        persisted_report["artifacts"][0]["output_files"]["artifact_dir"]
            .as_str()
            .is_some_and(|value| value.starts_with("artifacts/"))
    );

    let second = discover_from_csv(&csv_path, &options).unwrap();

    assert!(!first.cache_hit);
    assert!(!first.artifacts.iter().any(|artifact| artifact.cache_hit));
    assert!(second.cache_hit);
    assert_eq!(second.cached_artifacts, 2);
    assert!(second.artifacts.iter().all(|artifact| artifact.cache_hit));
    assert!(PathBuf::from(&second.output_files.artifact_set).is_absolute());
    assert!(PathBuf::from(&second.artifacts[0].output_files.artifact_dir).is_absolute());
    assert!(output_dir.join(".logicpearl-cache.json").exists());
}

fn row(features: &[(&str, i64)], allowed: bool) -> DecisionTraceRow {
    DecisionTraceRow {
        features: features
            .iter()
            .map(|(name, value)| ((*name).to_string(), Value::Number(Number::from(*value))))
            .collect::<HashMap<_, _>>(),
        allowed,
        trace_provenance: None,
    }
}

fn regression_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("regression")
        .join(name)
}

fn regression_build_options(
    output_dir: PathBuf,
    gate_id: &str,
    selection_policy: crate::SelectionPolicy,
) -> BuildOptions {
    BuildOptions {
        output_dir,
        gate_id: gate_id.to_string(),
        label_column: "allowed".to_string(),
        positive_label: None,
        negative_label: None,
        residual_pass: true,
        refine: false,
        pinned_rules: None,
        feature_dictionary: None,
        feature_governance: None,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy,
        max_rules: Some(4),
        max_conditions: Some(3),
        proposal_policy: ProposalPolicy::ReportOnly,
        feature_selection: FeatureColumnSelection::default(),
    }
}

fn gate_has_rule_with_features(gate: &LogicPearlGateIr, features: &[&str]) -> bool {
    gate.rules.iter().any(|rule| {
        features
            .iter()
            .all(|feature| expression_mentions_feature(&rule.deny_when, feature))
    })
}

fn gate_mentions_feature(gate: &LogicPearlGateIr, feature: &str) -> bool {
    gate.rules
        .iter()
        .any(|rule| expression_mentions_feature(&rule.deny_when, feature))
}

fn expression_mentions_feature(expression: &Expression, feature: &str) -> bool {
    match expression {
        Expression::Comparison(comparison) => comparison.feature == feature,
        Expression::All { all } => all
            .iter()
            .any(|child| expression_mentions_feature(child, feature)),
        Expression::Any { any } => any
            .iter()
            .any(|child| expression_mentions_feature(child, feature)),
        Expression::Not { expr } => expression_mentions_feature(expr, feature),
    }
}

fn rule_allowed_support(rule: &RuleDefinition) -> usize {
    rule.evidence
        .as_ref()
        .map(|evidence| evidence.support.allowed_trace_count)
        .unwrap_or_default()
}

fn render_rules(gate: &LogicPearlGateIr) -> String {
    serde_json::to_string(&gate.rules).unwrap()
}

fn row_values(features: &[(&str, Value)], allowed: bool) -> DecisionTraceRow {
    DecisionTraceRow {
        features: features
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect::<HashMap<_, _>>(),
        allowed,
        trace_provenance: None,
    }
}

#[test]
fn build_discovers_ratio_interaction_feature_when_axis_rules_are_insufficient() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("ratio_gate");
    let rows = vec![
        row_values(
            &[("debt", Value::from(50.0)), ("income", Value::from(100.0))],
            false,
        ),
        row_values(
            &[("debt", Value::from(60.0)), ("income", Value::from(120.0))],
            false,
        ),
        row_values(
            &[("debt", Value::from(45.0)), ("income", Value::from(80.0))],
            false,
        ),
        row_values(
            &[("debt", Value::from(30.0)), ("income", Value::from(50.0))],
            false,
        ),
        row_values(
            &[("debt", Value::from(50.0)), ("income", Value::from(150.0))],
            true,
        ),
        row_values(
            &[("debt", Value::from(60.0)), ("income", Value::from(200.0))],
            true,
        ),
        row_values(
            &[("debt", Value::from(30.0)), ("income", Value::from(80.0))],
            true,
        ),
        row_values(
            &[("debt", Value::from(45.0)), ("income", Value::from(120.0))],
            true,
        ),
    ];
    let result = build_pearl_from_rows(
        &rows,
        "ratio_demo".to_string(),
        &BuildOptions {
            output_dir: output_dir.clone(),
            gate_id: "ratio_demo".to_string(),
            label_column: "allowed".to_string(),
            positive_label: None,
            negative_label: None,
            residual_pass: false,
            refine: false,
            pinned_rules: None,
            feature_dictionary: None,
            feature_governance: None,
            decision_mode: DiscoveryDecisionMode::Standard,
            selection_policy: crate::SelectionPolicy::Balanced,
            max_rules: None,
            max_conditions: None,
            proposal_policy: ProposalPolicy::ReportOnly,
            feature_selection: FeatureColumnSelection::default(),
        },
    )
    .unwrap();

    assert_eq!(result.training_parity, 1.0);
    let gate = LogicPearlGateIr::from_path(output_dir.join("pearl.ir.json")).unwrap();
    let derived_feature = gate
        .input_schema
        .features
        .iter()
        .find(|feature| feature.id.contains("debt__over__income"))
        .expect("ratio feature should be emitted into the schema");
    assert!(derived_feature.derived.is_some());
    let rendered_rules = serde_json::to_string(&gate.rules).unwrap();
    assert!(rendered_rules.contains(&derived_feature.id));
}
