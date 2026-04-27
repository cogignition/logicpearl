// SPDX-License-Identifier: MIT
use super::{
    candidate_allowed_for_mode, candidate_as_comparison, candidate_complexity_penalty,
    candidate_from_expression_for_selection, candidate_rules, compare_candidate_priority,
    compare_candidate_set_score, compare_candidate_set_score_with_policy,
    conjunction_candidate_rules, generalize_candidate_plan, recover_rare_rules,
    rule_from_candidate, score_candidate_set, select_candidate_rules_exact, training_indices,
    CandidateMatchCache, CandidateRule, CandidateSelectionContext, CandidateSetScore,
    DISCOVERY_SELECTION_BACKEND_ENV,
};
use crate::{
    discovery_selection_env_lock, DecisionTraceRow, DiscoveryDecisionMode, ResidualPassOptions,
    SelectionPolicy,
};
use logicpearl_ir::{ComparisonExpression, ComparisonOperator, ComparisonValue, Expression};
use logicpearl_solver::{check_sat, SolverSettings};
use serde_json::{Number, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

fn solver_available() -> bool {
    check_sat("(check-sat)\n", &SolverSettings::default()).is_ok()
}

fn with_discovery_selection_backend<T>(backend: &str, test: impl FnOnce() -> T) -> T {
    let _guard = discovery_selection_env_lock()
        .lock()
        .expect("env lock should be available");
    let saved = std::env::var(DISCOVERY_SELECTION_BACKEND_ENV).ok();
    std::env::set_var(DISCOVERY_SELECTION_BACKEND_ENV, backend);
    let result = test();
    match saved {
        Some(value) => std::env::set_var(DISCOVERY_SELECTION_BACKEND_ENV, value),
        None => std::env::remove_var(DISCOVERY_SELECTION_BACKEND_ENV),
    }
    result
}

#[test]
fn exact_selection_prefers_minimal_general_rule_over_equal_singletons() {
    if !solver_available() {
        return;
    }

    let rows = vec![
        row(1.0, false),
        row(2.0, false),
        row(3.0, true),
        row(4.0, true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let candidates = vec![
        numeric_candidate("score", ComparisonOperator::Eq, 1.0),
        numeric_candidate("score", ComparisonOperator::Eq, 2.0),
        numeric_candidate("score", ComparisonOperator::Lte, 2.0),
    ];

    let selected = select_candidate_rules_exact(
        &rows,
        &denied_indices,
        &allowed_indices,
        &candidates,
        SelectionPolicy::Balanced,
    )
    .unwrap()
    .0
    .unwrap();
    assert_eq!(selected.len(), 1);
    let comparison = candidate_as_comparison(&selected[0]).unwrap();
    assert_eq!(comparison.op, ComparisonOperator::Lte);
    assert_eq!(
        comparison.value.literal().and_then(Value::as_f64),
        Some(2.0)
    );
}

#[test]
fn mip_exact_selection_matches_smt_choice_beyond_bruteforce_limit() {
    if !solver_available() {
        return;
    }

    let rows = (1..=18)
        .map(|value| row(value as f64, value == 18))
        .collect::<Vec<_>>();
    let denied_indices = (0..17).collect::<Vec<_>>();
    let allowed_indices = vec![17usize];
    let mut candidates = (1..=17)
        .map(|value| numeric_candidate("score", ComparisonOperator::Eq, value as f64))
        .collect::<Vec<_>>();
    candidates.push(numeric_candidate("score", ComparisonOperator::Lte, 17.0));

    let smt_selection = with_discovery_selection_backend("smt", || {
        select_candidate_rules_exact(
            &rows,
            &denied_indices,
            &allowed_indices,
            &candidates,
            SelectionPolicy::Balanced,
        )
        .expect("smt exact selection should find a solution")
        .0
        .expect("smt exact selection should return a rule set")
    });
    let mip_selection = with_discovery_selection_backend("mip", || {
        select_candidate_rules_exact(
            &rows,
            &denied_indices,
            &allowed_indices,
            &candidates,
            SelectionPolicy::Balanced,
        )
        .expect("mip exact selection should find a solution")
        .0
        .expect("mip exact selection should return a rule set")
    });

    assert_eq!(smt_selection.len(), 1);
    let smt_comparison = candidate_as_comparison(&smt_selection[0]).unwrap();
    assert_eq!(smt_comparison.op, ComparisonOperator::Lte);
    assert_eq!(
        smt_comparison.value.literal().and_then(Value::as_f64),
        Some(17.0)
    );

    assert_eq!(mip_selection.len(), smt_selection.len());
    let mip_comparison = candidate_as_comparison(&mip_selection[0]).unwrap();
    assert_eq!(mip_comparison.op, smt_comparison.op);
    assert_eq!(
        mip_comparison.value.literal().and_then(Value::as_f64),
        smt_comparison.value.literal().and_then(Value::as_f64)
    );
}

#[test]
fn invalid_discovery_selection_backend_is_rejected() {
    let rows = (1..=18)
        .map(|value| row(value as f64, value == 18))
        .collect::<Vec<_>>();
    let denied_indices = (0..17).collect::<Vec<_>>();
    let allowed_indices = vec![17usize];
    let mut candidates = (1..=17)
        .map(|value| numeric_candidate("score", ComparisonOperator::Eq, value as f64))
        .collect::<Vec<_>>();
    candidates.push(numeric_candidate("score", ComparisonOperator::Lte, 17.0));

    let err = with_discovery_selection_backend("not-a-backend", || {
        select_candidate_rules_exact(
            &rows,
            &denied_indices,
            &allowed_indices,
            &candidates,
            SelectionPolicy::Balanced,
        )
        .expect_err("invalid discovery selection backend should fail loudly")
    });

    assert!(
        err.to_string()
            .contains("unsupported discovery selection backend"),
        "unexpected error: {err}"
    );
}

#[test]
fn candidate_set_score_prefers_fewer_false_positives_after_equal_total_error() {
    let better = CandidateSetScore {
        total_errors: 2,
        false_positives: 0,
        false_negatives: 2,
        validation_total_errors: 0,
        validation_false_positives: 0,
        validation_false_negatives: 0,
        rule_count: 2,
        complexity_penalty: 0,
    };
    let worse = CandidateSetScore {
        total_errors: 2,
        false_positives: 1,
        false_negatives: 1,
        validation_total_errors: 0,
        validation_false_positives: 0,
        validation_false_negatives: 0,
        rule_count: 1,
        complexity_penalty: 0,
    };
    assert_eq!(
        compare_candidate_set_score(&better, &worse),
        std::cmp::Ordering::Less
    );
}

#[test]
fn recall_biased_candidate_set_score_prefers_target_hitting_plan_within_cap() {
    let recall_biased = SelectionPolicy::RecallBiased {
        deny_recall_target: 0.75,
        max_false_positive_rate: 0.25,
    };
    let better = CandidateSetScore {
        total_errors: 4,
        false_positives: 1,
        false_negatives: 1,
        validation_total_errors: 1,
        validation_false_positives: 0,
        validation_false_negatives: 1,
        rule_count: 2,
        complexity_penalty: 0,
    };
    let worse = CandidateSetScore {
        total_errors: 2,
        false_positives: 0,
        false_negatives: 2,
        validation_total_errors: 0,
        validation_false_positives: 0,
        validation_false_negatives: 0,
        rule_count: 1,
        complexity_penalty: 0,
    };
    assert_eq!(
        compare_candidate_set_score_with_policy(&better, &worse, recall_biased, 4, 4),
        std::cmp::Ordering::Less
    );
}

#[test]
fn candidate_priority_prefers_positive_signal_over_base_rate_coverage() {
    let informative = CandidateRule::new_with_population(
        Expression::Comparison(ComparisonExpression {
            feature: "pest_visible".to_string(),
            op: ComparisonOperator::Eq,
            value: ComparisonValue::Literal(Value::String("aphids".to_string())),
        }),
        851,
        0,
        4200,
        800,
    );
    let broad_prior = CandidateRule::new_with_population(
        Expression::Comparison(ComparisonExpression {
            feature: "days_since_fertilized".to_string(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(-1))),
        }),
        4183,
        817,
        4200,
        800,
    );

    assert_eq!(
        compare_candidate_priority(&informative, &broad_prior),
        std::cmp::Ordering::Less
    );
}

#[test]
fn bottom_up_conjunction_generation_keeps_broad_signal_rules() {
    let mut rows = Vec::new();
    for index in 0..157 {
        rows.push(garden_light_row(
            "fern",
            3.0,
            if index < 17 { "moderate" } else { "low" },
            false,
        ));
    }
    for _ in 0..23 {
        rows.push(garden_light_row("fern", 3.0, "dry", true));
    }
    for _ in 0..980 {
        rows.push(garden_light_row("succulent", 1.0, "moderate", true));
    }
    let denied_indices = (0usize..157usize).collect::<Vec<_>>();
    let allowed_indices = (157usize..rows.len()).collect::<Vec<_>>();
    let atomic = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );

    let conjunctions = conjunction_candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &atomic,
        &ResidualPassOptions {
            max_conditions: 3,
            min_positive_support: 2,
            max_negative_hits: 0,
            max_rules: 8,
        },
        None,
    );

    let broad = conjunctions.iter().find(|candidate| {
        expression_has_comparison(
            &candidate.expression,
            "plant",
            ComparisonOperator::Eq,
            Some(Value::String("fern".to_string())),
        ) && expression_has_comparison(
            &candidate.expression,
            "light_level",
            ComparisonOperator::Gte,
            Some(Value::Number(Number::from_f64(3.0).unwrap())),
        ) && !expression_mentions_feature(&candidate.expression, "humidity")
    });

    let broad = broad.expect("bottom-up search should retain the broad fern/light rule");
    assert_eq!(broad.denied_coverage, 157);
    assert_eq!(broad.false_positives, 23);
}

#[test]
fn selected_candidate_generalization_drops_redundant_conjuncts() {
    let rows = vec![
        garden_light_row("fern", 3.0, "moderate", false),
        garden_light_row("fern", 3.0, "moderate", false),
        garden_light_row("fern", 1.0, "moderate", true),
        garden_light_row("succulent", 3.0, "moderate", true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let feature_governance = BTreeMap::new();
    let selection_context = CandidateSelectionContext {
        rows: &rows,
        denied_indices: &denied_indices,
        allowed_indices: &allowed_indices,
        training_indices: training_indices(&rows, &[]),
        validation_indices: &[],
        training_denied_count: denied_indices.len(),
        training_allowed_count: allowed_indices.len(),
        feature_governance: &feature_governance,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: SelectionPolicy::Balanced,
        residual_options: None,
        match_cache: Arc::new(CandidateMatchCache::new(&rows)),
    };
    let overspecified = candidate_from_expression_for_selection(
        &selection_context,
        Expression::All {
            all: vec![
                Expression::Comparison(ComparisonExpression {
                    feature: "plant".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("fern".to_string())),
                }),
                Expression::Comparison(ComparisonExpression {
                    feature: "light_level".to_string(),
                    op: ComparisonOperator::Gte,
                    value: ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
                }),
                Expression::Comparison(ComparisonExpression {
                    feature: "humidity".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("moderate".to_string())),
                }),
            ],
        },
    );

    let generalized = generalize_candidate_plan(&selection_context, vec![overspecified]);
    assert_eq!(generalized.len(), 1);
    assert!(expression_has_comparison(
        &generalized[0].expression,
        "plant",
        ComparisonOperator::Eq,
        Some(Value::String("fern".to_string())),
    ));
    assert!(expression_has_comparison(
        &generalized[0].expression,
        "light_level",
        ComparisonOperator::Gte,
        Some(Value::Number(Number::from_f64(3.0).unwrap())),
    ));
    assert!(!expression_mentions_feature(
        &generalized[0].expression,
        "humidity"
    ));
}

#[test]
fn selected_candidate_generalization_drops_subsumed_atomic_rule() {
    let rows = vec![
        garden_light_row("fern", 5.0, "moderate", false),
        garden_light_row("fern", 6.0, "moderate", false),
        garden_light_row("fern", 4.0, "moderate", true),
        garden_light_row("succulent", 1.0, "dry", true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let feature_governance = BTreeMap::new();
    let selection_context = CandidateSelectionContext {
        rows: &rows,
        denied_indices: &denied_indices,
        allowed_indices: &allowed_indices,
        training_indices: training_indices(&rows, &[]),
        validation_indices: &[],
        training_denied_count: denied_indices.len(),
        training_allowed_count: allowed_indices.len(),
        feature_governance: &feature_governance,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: SelectionPolicy::Balanced,
        residual_options: None,
        match_cache: Arc::new(CandidateMatchCache::new(&rows)),
    };
    let broad = candidate_from_expression_for_selection(
        &selection_context,
        Expression::Comparison(ComparisonExpression {
            feature: "light_level".to_string(),
            op: ComparisonOperator::Gte,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
        }),
    );
    let narrow = candidate_from_expression_for_selection(
        &selection_context,
        Expression::Comparison(ComparisonExpression {
            feature: "light_level".to_string(),
            op: ComparisonOperator::Gte,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(5.0).unwrap())),
        }),
    );

    let generalized = generalize_candidate_plan(&selection_context, vec![broad, narrow]);
    assert_eq!(generalized.len(), 1);
    assert!(expression_has_comparison(
        &generalized[0].expression,
        "light_level",
        ComparisonOperator::Gte,
        Some(Value::Number(Number::from_f64(3.0).unwrap())),
    ));
}

#[test]
fn selected_candidate_generalization_collapses_shared_prefix_group() {
    let rows = vec![
        garden_light_row("aphids", 5.0, "bound", false),
        garden_light_row("aphids", 5.0, "curl", false),
        garden_light_row("none", 1.0, "bound", true),
        garden_light_row("none", 1.0, "curl", true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let feature_governance = BTreeMap::new();
    let selection_context = CandidateSelectionContext {
        rows: &rows,
        denied_indices: &denied_indices,
        allowed_indices: &allowed_indices,
        training_indices: training_indices(&rows, &[]),
        validation_indices: &[],
        training_denied_count: denied_indices.len(),
        training_allowed_count: allowed_indices.len(),
        feature_governance: &feature_governance,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: SelectionPolicy::Balanced,
        residual_options: None,
        match_cache: Arc::new(CandidateMatchCache::new(&rows)),
    };
    let root_bound_shard = candidate_from_expression_for_selection(
        &selection_context,
        Expression::All {
            all: vec![
                Expression::Comparison(ComparisonExpression {
                    feature: "plant".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("aphids".to_string())),
                }),
                Expression::Comparison(ComparisonExpression {
                    feature: "humidity".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("bound".to_string())),
                }),
            ],
        },
    );
    let leaf_curl_shard = candidate_from_expression_for_selection(
        &selection_context,
        Expression::All {
            all: vec![
                Expression::Comparison(ComparisonExpression {
                    feature: "plant".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("aphids".to_string())),
                }),
                Expression::Comparison(ComparisonExpression {
                    feature: "humidity".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("curl".to_string())),
                }),
            ],
        },
    );

    let generalized =
        generalize_candidate_plan(&selection_context, vec![root_bound_shard, leaf_curl_shard]);
    assert_eq!(generalized.len(), 1);
    assert!(expression_has_comparison(
        &generalized[0].expression,
        "plant",
        ComparisonOperator::Eq,
        Some(Value::String("aphids".to_string())),
    ));
    assert!(!expression_mentions_feature(
        &generalized[0].expression,
        "humidity"
    ));
}

#[test]
fn selected_candidate_generalization_uses_validation_signal() {
    let rows = vec![
        garden_light_row("aphids", 5.0, "bound", false),
        garden_light_row("aphids", 5.0, "bound", false),
        garden_light_row("aphids", 1.0, "free", true),
        garden_light_row("none", 1.0, "bound", true),
        garden_light_row("aphids", 5.0, "free", false),
        garden_light_row("aphids", 5.0, "free", false),
        garden_light_row("none", 1.0, "free", true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let validation_indices = vec![4usize, 5usize, 6usize];
    let feature_governance = BTreeMap::new();
    let selection_context = CandidateSelectionContext {
        rows: &rows,
        denied_indices: &denied_indices,
        allowed_indices: &allowed_indices,
        training_indices: training_indices(&rows, &validation_indices),
        validation_indices: &validation_indices,
        training_denied_count: denied_indices.len(),
        training_allowed_count: allowed_indices.len(),
        feature_governance: &feature_governance,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: SelectionPolicy::Balanced,
        residual_options: None,
        match_cache: Arc::new(CandidateMatchCache::new(&rows)),
    };
    let overfit = candidate_from_expression_for_selection(
        &selection_context,
        Expression::All {
            all: vec![
                Expression::Comparison(ComparisonExpression {
                    feature: "plant".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("aphids".to_string())),
                }),
                Expression::Comparison(ComparisonExpression {
                    feature: "humidity".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(Value::String("bound".to_string())),
                }),
            ],
        },
    );

    let generalized = generalize_candidate_plan(&selection_context, vec![overfit]);

    assert_eq!(generalized.len(), 1);
    assert!(expression_has_comparison(
        &generalized[0].expression,
        "plant",
        ComparisonOperator::Eq,
        Some(Value::String("aphids".to_string())),
    ));
    assert!(!expression_mentions_feature(
        &generalized[0].expression,
        "humidity"
    ));
}

#[test]
fn recall_biased_exact_selection_uses_cap_limited_max_recall_when_target_is_infeasible() {
    let rows = vec![
        dual_signal_row(1.0, 0.0, false),
        dual_signal_row(1.0, 0.0, false),
        dual_signal_row(0.0, 1.0, false),
        dual_signal_row(0.0, 0.0, true),
        dual_signal_row(1.0, 0.0, true),
        dual_signal_row(0.0, 1.0, true),
    ];
    let denied_indices = vec![0usize, 1usize, 2usize];
    let allowed_indices = vec![3usize, 4usize, 5usize];
    let candidates = vec![
        candidate_with_metrics(
            "signal_a",
            ComparisonOperator::Eq,
            ComparisonValue::Literal(Value::Number(Number::from(1))),
            2,
            1,
        ),
        candidate_with_metrics(
            "signal_b",
            ComparisonOperator::Eq,
            ComparisonValue::Literal(Value::Number(Number::from(1))),
            1,
            1,
        ),
    ];

    let (selected, report) = select_candidate_rules_exact(
        &rows,
        &denied_indices,
        &allowed_indices,
        &candidates,
        SelectionPolicy::RecallBiased {
            deny_recall_target: 1.0,
            max_false_positive_rate: 0.34,
        },
    )
    .expect("exact selection should complete");
    let selected = selected.expect("exact selection should return a rule set");

    assert_eq!(selected.len(), 1);
    assert_eq!(
        candidate_as_comparison(&selected[0]).unwrap().feature,
        "signal_a"
    );
    assert!(report
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("not feasible")));
}

#[test]
fn candidate_set_score_counts_selected_set_union_errors() {
    let rows = vec![
        row(1.0, false),
        row(2.0, false),
        row(3.0, true),
        row(4.0, true),
    ];
    let candidate_a = numeric_candidate("score", ComparisonOperator::Eq, 1.0);
    let candidate_b = numeric_candidate("score", ComparisonOperator::Gte, 3.0);
    let score = score_candidate_set(&rows, &[candidate_a, candidate_b], None);
    assert_eq!(score.false_negatives, 1);
    assert_eq!(score.false_positives, 2);
    assert_eq!(score.total_errors, 3);
}

#[test]
fn candidate_rules_skip_feature_refs_for_binary_numeric_features() {
    let rows = vec![
        binary_pair_row(1.0, 0.0, false),
        binary_pair_row(0.0, 1.0, false),
        binary_pair_row(0.0, 0.0, true),
        binary_pair_row(1.0, 1.0, true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );
    assert!(
        !candidates.iter().any(|candidate| matches!(
            candidate_as_comparison(candidate).map(|comparison| &comparison.value),
            Some(ComparisonValue::FeatureRef { .. })
        )),
        "binary numeric features should not produce feature-ref candidates"
    );
}

#[test]
fn candidate_rules_limit_feature_refs_to_ordered_numeric_comparisons() {
    let rows = vec![
        binary_pair_row(0.0, 2.0, false),
        binary_pair_row(1.0, 3.0, false),
        binary_pair_row(2.0, 1.0, true),
        binary_pair_row(3.0, 0.0, true),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize];
    let candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );
    assert!(
        candidates
            .iter()
            .filter(|candidate| matches!(
                candidate_as_comparison(candidate).map(|comparison| &comparison.value),
                Some(ComparisonValue::FeatureRef { .. })
            ))
            .all(|candidate| matches!(
                candidate_as_comparison(candidate).unwrap().op,
                ComparisonOperator::Lt
                    | ComparisonOperator::Lte
                    | ComparisonOperator::Gt
                    | ComparisonOperator::Gte
            )),
        "feature-ref candidates should stay ordered comparisons"
    );
}

#[test]
fn high_cardinality_numeric_features_skip_exact_match_candidates() {
    let rows = (0..24)
        .map(|value| row(value as f64, value >= 12))
        .collect::<Vec<_>>();
    let denied_indices = (0usize..12usize).collect::<Vec<_>>();
    let allowed_indices = (12usize..24usize).collect::<Vec<_>>();

    let candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );

    assert!(
        !candidates.iter().any(|candidate| {
            let Some(comparison) = candidate_as_comparison(candidate) else {
                return false;
            };
            comparison.feature == "score" && comparison.op == ComparisonOperator::Eq
        }),
        "continuous/high-cardinality numeric features should not emit exact-match candidates"
    );
}

#[test]
fn low_cardinality_numeric_features_can_still_emit_exact_match_candidates() {
    let rows = vec![
        row(0.0, false),
        row(0.0, false),
        row(0.0, false),
        row(1.0, true),
        row(1.0, true),
        row(1.0, true),
    ];
    let denied_indices = vec![0usize, 1usize, 2usize];
    let allowed_indices = vec![3usize, 4usize, 5usize];

    let candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );

    assert!(
        candidates.iter().any(|candidate| {
            let Some(comparison) = candidate_as_comparison(candidate) else {
                return false;
            };
            comparison.feature == "score"
                && comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64) == Some(0.0)
        }),
        "binary/low-cardinality numeric features should still support exact matches"
    );
}

#[test]
fn numeric_exact_match_candidates_require_minimum_support() {
    let rows = vec![
        row(0.0, false),
        row(1.0, false),
        row(2.0, false),
        row(9.0, true),
        row(9.0, true),
        row(9.0, true),
    ];
    let denied_indices = vec![0usize, 1usize, 2usize];
    let allowed_indices = vec![3usize, 4usize, 5usize];

    let candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );

    assert!(
        !candidates.iter().any(|candidate| {
            let Some(comparison) = candidate_as_comparison(candidate) else {
                return false;
            };
            comparison.feature == "score" && comparison.op == ComparisonOperator::Eq
        }),
        "singleton numeric exact-match candidates should be filtered by support floor"
    );
    assert!(
        candidates.iter().any(|candidate| {
            let Some(comparison) = candidate_as_comparison(candidate) else {
                return false;
            };
            comparison.feature == "score" && comparison.op == ComparisonOperator::Lte
        }),
        "threshold candidates should remain available"
    );
}

#[test]
fn rare_rule_recovery_adds_uncovered_zero_fp_rule() {
    let rows = vec![
        triad_row(1.0, 0.0, 0.0, false),
        triad_row(2.0, 0.0, 0.0, false),
        triad_row(3.0, 0.0, 0.0, false),
        triad_row(9.0, 1.0, 0.0, false),
        triad_row(3.0, 0.0, 0.0, true),
        triad_row(7.0, 0.0, 0.0, true),
        triad_row(8.0, 0.0, 0.0, true),
    ];
    let denied_indices = vec![0usize, 1usize, 2usize, 3usize];
    let allowed_indices = vec![4usize, 5usize, 6usize];
    let selected = vec![candidate_with_metrics(
        "score",
        ComparisonOperator::Lte,
        ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
        3,
        1,
    )];

    let feature_governance = BTreeMap::new();
    let selection_context = CandidateSelectionContext {
        rows: &rows,
        denied_indices: &denied_indices,
        allowed_indices: &allowed_indices,
        training_indices: training_indices(&rows, &[]),
        validation_indices: &[],
        training_denied_count: denied_indices.len(),
        training_allowed_count: allowed_indices.len(),
        feature_governance: &feature_governance,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: SelectionPolicy::Balanced,
        residual_options: None,
        match_cache: Arc::new(CandidateMatchCache::new(&rows)),
    };
    let recovered = recover_rare_rules(&selection_context, selected, None).unwrap();
    assert_eq!(recovered.len(), 2);
    let score = score_candidate_set(&rows, &recovered, None);
    assert_eq!(score.false_negatives, 0);
    assert_eq!(score.false_positives, 1);
}

#[test]
fn rare_rule_recovery_skips_rules_that_only_add_false_positives() {
    let rows = vec![
        triad_row(1.0, 0.0, 0.0, false),
        triad_row(2.0, 0.0, 0.0, false),
        triad_row(3.0, 0.0, 0.0, false),
        triad_row(8.0, 1.0, 1.0, false),
        triad_row(3.0, 0.0, 0.0, true),
        triad_row(8.0, 1.0, 1.0, true),
        triad_row(8.0, 0.0, 0.0, true),
    ];
    let denied_indices = vec![0usize, 1usize, 2usize, 3usize];
    let allowed_indices = vec![4usize, 5usize, 6usize];
    let selected = vec![candidate_with_metrics(
        "score",
        ComparisonOperator::Lte,
        ComparisonValue::Literal(Value::Number(Number::from_f64(3.0).unwrap())),
        3,
        1,
    )];

    let feature_governance = BTreeMap::new();
    let selection_context = CandidateSelectionContext {
        rows: &rows,
        denied_indices: &denied_indices,
        allowed_indices: &allowed_indices,
        training_indices: training_indices(&rows, &[]),
        validation_indices: &[],
        training_denied_count: denied_indices.len(),
        training_allowed_count: allowed_indices.len(),
        feature_governance: &feature_governance,
        decision_mode: DiscoveryDecisionMode::Standard,
        selection_policy: SelectionPolicy::Balanced,
        residual_options: None,
        match_cache: Arc::new(CandidateMatchCache::new(&rows)),
    };
    let recovered = recover_rare_rules(&selection_context, selected, None).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        candidate_as_comparison(&recovered[0]).unwrap().feature,
        "score"
    );
    let score = score_candidate_set(&rows, &recovered, None);
    assert_eq!(score.false_negatives, 1);
    assert_eq!(score.false_positives, 1);
}

#[test]
fn conjunction_candidate_rules_emit_real_multi_condition_rules() {
    if !solver_available() {
        return;
    }

    let rows = vec![
        authz_row(0.0, 1.0, 0.0, 0.0, 1.0, 0.0, true),
        authz_row(0.0, 1.0, 0.0, 0.0, 1.0, 1.0, true),
        authz_row(1.0, 1.0, 0.0, 0.0, 1.0, 0.0, false),
        authz_row(0.0, 0.0, 1.0, 0.0, 1.0, 0.0, false),
        authz_row(0.0, 0.0, 1.0, 0.0, 0.0, 0.0, false),
    ];
    let denied_indices = vec![0usize, 1usize];
    let allowed_indices = vec![2usize, 3usize, 4usize];
    let atomic_candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );

    let compounds = conjunction_candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &atomic_candidates,
        &ResidualPassOptions {
            max_conditions: 3,
            min_positive_support: 2,
            max_negative_hits: 0,
            max_rules: 4,
        },
        None,
    );

    assert!(compounds.iter().any(|candidate| {
        matches!(
            &candidate.expression,
            Expression::All { all }
                if all.iter().any(|expr| matches!(
                    expr,
                    Expression::Comparison(ComparisonExpression { feature, .. })
                        if feature == "action_delete"
                )) && all.iter().any(|expr| matches!(
                    expr,
                    Expression::Comparison(ComparisonExpression { feature, .. })
                        if feature == "is_admin"
                ))
        )
    }));
}

#[test]
fn conjunction_candidate_rules_cover_policy_style_dataset() {
    if !solver_available() {
        return;
    }

    let rows = vec![
        policy_style_row(PolicyStyleRowSpec {
            action_delete: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_delete: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            archived: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            archived: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            is_authenticated: 1.0,
            team_match: 1.0,
            is_contractor: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            is_authenticated: 1.0,
            team_match: 1.0,
            is_contractor: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            is_authenticated: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            is_authenticated: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            sensitivity: 2.0,
            team_match: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            sensitivity: 1.0,
            team_match: 1.0,
            denied: true,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: false,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            is_contractor: 1.0,
            denied: false,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            is_admin: 1.0,
            action_delete: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: false,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            is_admin: 1.0,
            action_read: 1.0,
            archived: 1.0,
            is_authenticated: 1.0,
            team_match: 1.0,
            denied: false,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            is_authenticated: 1.0,
            is_public: 1.0,
            denied: false,
            ..Default::default()
        }),
        policy_style_row(PolicyStyleRowSpec {
            action_read: 1.0,
            team_match: 1.0,
            denied: false,
            ..Default::default()
        }),
    ];
    let denied_indices = (0usize..10usize).collect::<Vec<_>>();
    let allowed_indices = (10usize..16usize).collect::<Vec<_>>();
    let atomic_candidates = candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &BTreeMap::new(),
        DiscoveryDecisionMode::Standard,
        None,
        None,
    );

    let compounds = conjunction_candidate_rules(
        &rows,
        &denied_indices,
        &allowed_indices,
        &atomic_candidates,
        &ResidualPassOptions {
            max_conditions: 3,
            min_positive_support: 2,
            max_negative_hits: 0,
            max_rules: 8,
        },
        None,
    );

    let (selected, _) = select_candidate_rules_exact(
        &rows,
        &denied_indices,
        &allowed_indices,
        &compounds,
        SelectionPolicy::Balanced,
    )
    .expect("exact selection should run");
    let selected = selected.expect("exact selection should find a rule set");
    let score = score_candidate_set(&rows, &selected, None);
    assert_eq!(score.total_errors, 0);
}

#[test]
fn candidate_set_score_prefers_better_validation_when_training_is_equal() {
    let better = CandidateSetScore {
        total_errors: 1,
        false_positives: 0,
        false_negatives: 1,
        validation_total_errors: 0,
        validation_false_positives: 0,
        validation_false_negatives: 0,
        rule_count: 2,
        complexity_penalty: 0,
    };
    let worse = CandidateSetScore {
        total_errors: 1,
        false_positives: 0,
        false_negatives: 1,
        validation_total_errors: 1,
        validation_false_positives: 1,
        validation_false_negatives: 0,
        rule_count: 1,
        complexity_penalty: 0,
    };
    assert_eq!(
        compare_candidate_set_score(&better, &worse),
        std::cmp::Ordering::Less
    );
}

#[test]
fn discovered_rule_gets_generated_label_and_counterfactual() {
    let rule = rule_from_candidate(
        0,
        &candidate_with_metrics(
            "contains_xss_signature",
            ComparisonOperator::Eq,
            ComparisonValue::Literal(Value::Bool(true)),
            3,
            0,
        ),
    );

    assert_eq!(rule.label.as_deref(), Some("XSS Signature Detected"));
    assert_eq!(
        rule.counterfactual_hint.as_deref(),
        Some("Remove XSS Signature")
    );
}

#[test]
fn numeric_exact_match_rules_get_extra_complexity_penalty() {
    let exact = candidate_with_metrics(
        "suspicious_token_count",
        ComparisonOperator::Eq,
        ComparisonValue::Literal(Value::Number(Number::from(1))),
        5,
        0,
    );
    let threshold = candidate_with_metrics(
        "suspicious_token_count",
        ComparisonOperator::Gte,
        ComparisonValue::Literal(Value::Number(Number::from(1))),
        5,
        0,
    );

    assert!(
        candidate_complexity_penalty(&exact, DiscoveryDecisionMode::Standard)
            > candidate_complexity_penalty(&threshold, DiscoveryDecisionMode::Standard)
    );
}

#[test]
fn review_mode_rejects_numeric_exact_matches() {
    let exact = candidate_with_metrics(
        "suspicious_token_count",
        ComparisonOperator::Eq,
        ComparisonValue::Literal(Value::Number(Number::from(13))),
        5,
        0,
    );
    let threshold = candidate_with_metrics(
        "suspicious_token_count",
        ComparisonOperator::Gte,
        ComparisonValue::Literal(Value::Number(Number::from(13))),
        5,
        0,
    );

    assert!(!candidate_allowed_for_mode(
        &exact,
        DiscoveryDecisionMode::Review
    ));
    assert!(candidate_allowed_for_mode(
        &threshold,
        DiscoveryDecisionMode::Review
    ));
}

#[test]
fn review_mode_still_allows_derived_numeric_thresholds() {
    let candidate = candidate_with_metrics(
        "derived__query_key_count__minus__suspicious_token_count",
        ComparisonOperator::Gte,
        ComparisonValue::Literal(Value::Number(Number::from(13))),
        5,
        0,
    );

    assert!(candidate_allowed_for_mode(
        &candidate,
        DiscoveryDecisionMode::Review
    ));
}

fn row(score: f64, allowed: bool) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert(
        "score".to_string(),
        Value::Number(Number::from_f64(score).unwrap()),
    );
    DecisionTraceRow {
        features,
        allowed,
        trace_provenance: None,
    }
}

fn numeric_candidate(feature: &str, op: ComparisonOperator, value: f64) -> CandidateRule {
    CandidateRule::new(
        Expression::Comparison(ComparisonExpression {
            feature: feature.to_string(),
            op,
            value: ComparisonValue::Literal(Value::Number(Number::from_f64(value).unwrap())),
        }),
        0,
        0,
    )
}

fn candidate_with_metrics(
    feature: &str,
    op: ComparisonOperator,
    value: ComparisonValue,
    denied_coverage: usize,
    false_positives: usize,
) -> CandidateRule {
    CandidateRule::new(
        Expression::Comparison(ComparisonExpression {
            feature: feature.to_string(),
            op,
            value,
        }),
        denied_coverage,
        false_positives,
    )
}

fn binary_pair_row(left: f64, right: f64, allowed: bool) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert(
        "left".to_string(),
        Value::Number(Number::from_f64(left).unwrap()),
    );
    features.insert(
        "right".to_string(),
        Value::Number(Number::from_f64(right).unwrap()),
    );
    DecisionTraceRow {
        features,
        allowed,
        trace_provenance: None,
    }
}

fn triad_row(score: f64, rare_flag: f64, noisy_flag: f64, allowed: bool) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert(
        "score".to_string(),
        Value::Number(Number::from_f64(score).unwrap()),
    );
    features.insert(
        "rare_flag".to_string(),
        Value::Number(Number::from_f64(rare_flag).unwrap()),
    );
    features.insert(
        "noisy_flag".to_string(),
        Value::Number(Number::from_f64(noisy_flag).unwrap()),
    );
    DecisionTraceRow {
        features,
        allowed,
        trace_provenance: None,
    }
}

fn dual_signal_row(signal_a: f64, signal_b: f64, allowed: bool) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert("signal_a".to_string(), Value::from(signal_a));
    features.insert("signal_b".to_string(), Value::from(signal_b));
    DecisionTraceRow {
        features,
        allowed,
        trace_provenance: None,
    }
}

fn garden_light_row(
    plant: &str,
    light_level: f64,
    humidity: &str,
    allowed: bool,
) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert("plant".to_string(), Value::String(plant.to_string()));
    features.insert(
        "light_level".to_string(),
        Value::Number(Number::from_f64(light_level).unwrap()),
    );
    features.insert("humidity".to_string(), Value::String(humidity.to_string()));
    DecisionTraceRow {
        features,
        allowed,
        trace_provenance: None,
    }
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

fn expression_has_comparison(
    expression: &Expression,
    feature: &str,
    op: ComparisonOperator,
    value: Option<Value>,
) -> bool {
    match expression {
        Expression::Comparison(comparison) => {
            comparison.feature == feature
                && comparison.op == op
                && value
                    .as_ref()
                    .is_none_or(|expected| comparison.value.literal() == Some(expected))
        }
        Expression::All { all } => all
            .iter()
            .any(|child| expression_has_comparison(child, feature, op.clone(), value.clone())),
        Expression::Any { any } => any
            .iter()
            .any(|child| expression_has_comparison(child, feature, op.clone(), value.clone())),
        Expression::Not { expr } => expression_has_comparison(expr, feature, op, value),
    }
}

fn authz_row(
    is_admin: f64,
    action_delete: f64,
    action_read: f64,
    is_contractor: f64,
    is_authenticated: f64,
    sensitivity: f64,
    denied: bool,
) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert("is_admin".to_string(), Value::from(is_admin));
    features.insert("action_delete".to_string(), Value::from(action_delete));
    features.insert("action_read".to_string(), Value::from(action_read));
    features.insert("is_contractor".to_string(), Value::from(is_contractor));
    features.insert(
        "is_authenticated".to_string(),
        Value::from(is_authenticated),
    );
    features.insert("sensitivity".to_string(), Value::from(sensitivity));
    DecisionTraceRow {
        features,
        allowed: !denied,
        trace_provenance: None,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PolicyStyleRowSpec {
    is_admin: f64,
    action_delete: f64,
    action_read: f64,
    archived: f64,
    is_authenticated: f64,
    sensitivity: f64,
    team_match: f64,
    is_public: f64,
    is_contractor: f64,
    denied: bool,
}

fn policy_style_row(spec: PolicyStyleRowSpec) -> DecisionTraceRow {
    let mut features = HashMap::new();
    features.insert("is_admin".to_string(), Value::from(spec.is_admin));
    features.insert("action_delete".to_string(), Value::from(spec.action_delete));
    features.insert("action_read".to_string(), Value::from(spec.action_read));
    features.insert("archived".to_string(), Value::from(spec.archived));
    features.insert(
        "is_authenticated".to_string(),
        Value::from(spec.is_authenticated),
    );
    features.insert("sensitivity".to_string(), Value::from(spec.sensitivity));
    features.insert("team_match".to_string(), Value::from(spec.team_match));
    features.insert("is_public".to_string(), Value::from(spec.is_public));
    features.insert("is_contractor".to_string(), Value::from(spec.is_contractor));
    DecisionTraceRow {
        features,
        allowed: !spec.denied,
        trace_provenance: None,
    }
}
