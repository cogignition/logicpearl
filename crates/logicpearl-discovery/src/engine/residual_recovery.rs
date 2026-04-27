// SPDX-License-Identifier: MIT
use super::super::canonicalize::{comparison_matches, expression_matches};
use super::super::features::{
    boolean_feature_map, infer_binary_feature_names, rule_contains_feature,
    rule_with_added_condition,
};
use super::super::rule_text::RuleTextContext;
use super::super::{DecisionTraceRow, ResidualPassOptions, UniqueCoverageRefinementOptions};
use super::candidates::residual_rule_from_candidate;
use logicpearl_core::Result;
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, ComparisonValue, LogicPearlGateIr, RuleDefinition,
};
use logicpearl_runtime::evaluate_gate;
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionSearchOptions, BooleanSearchExample,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub(crate) fn discover_residual_rules(
    rows: &[DecisionTraceRow],
    gate: &LogicPearlGateIr,
    feature_semantics: &BTreeMap<String, logicpearl_ir::FeatureSemantics>,
    options: &ResidualPassOptions,
) -> Result<Vec<RuleDefinition>> {
    let binary_features = infer_binary_feature_names(rows);
    if binary_features.is_empty() {
        return Ok(Vec::new());
    }

    let derived_feature_ids = gate
        .input_schema
        .features
        .iter()
        .filter_map(|feature| feature.derived.as_ref().map(|_| feature.id.as_str()))
        .collect::<BTreeSet<_>>();
    let mut examples = Vec::new();
    for row in rows {
        let runtime_features = source_runtime_features(&derived_feature_ids, &row.features);
        let predicted_deny = !evaluate_gate(gate, &runtime_features)?.is_zero();
        if !row.allowed && !predicted_deny {
            examples.push(BooleanSearchExample {
                features: boolean_feature_map(&row.features, &binary_features),
                positive: true,
            });
        } else if row.allowed {
            examples.push(BooleanSearchExample {
                features: boolean_feature_map(&row.features, &binary_features),
                positive: false,
            });
        }
    }

    if examples.iter().filter(|example| example.positive).count() < options.min_positive_support {
        return Ok(Vec::new());
    }

    let candidates = synthesize_boolean_conjunctions(
        &examples,
        &BooleanConjunctionSearchOptions {
            min_conditions: 1,
            max_conditions: options.max_conditions,
            min_positive_support: options.min_positive_support,
            max_negative_hits: options.max_negative_hits,
            max_rules: options.max_rules,
        },
    )?;

    Ok(candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            residual_rule_from_candidate(
                gate.rules.len() as u32 + index as u32,
                candidate,
                &RuleTextContext::with_feature_semantics(feature_semantics),
            )
        })
        .collect())
}

fn source_runtime_features(
    derived_feature_ids: &BTreeSet<&str>,
    features: &HashMap<String, Value>,
) -> HashMap<String, Value> {
    if derived_feature_ids.is_empty() {
        return features.clone();
    }
    features
        .iter()
        .filter(|(feature, _)| !derived_feature_ids.contains(feature.as_str()))
        .map(|(feature, value)| (feature.clone(), value.clone()))
        .collect()
}

pub(crate) fn tighten_rules_unique_coverage(
    rows: &[DecisionTraceRow],
    rules: &[RuleDefinition],
    options: &UniqueCoverageRefinementOptions,
) -> Result<(Vec<RuleDefinition>, usize)> {
    let binary_features = infer_binary_feature_names(rows);
    if binary_features.is_empty() || rules.is_empty() {
        return Ok((rules.to_vec(), 0));
    }

    let mut tightened = Vec::with_capacity(rules.len());
    let mut tightened_rules_applied = 0usize;

    for (rule_index, rule) in rules.iter().enumerate() {
        let mut unique_positive_rows = Vec::new();
        let mut unique_negative_rows = Vec::new();

        for row in rows {
            if !expression_matches(&rule.deny_when, &row.features) {
                continue;
            }
            let matched_by_other = rules.iter().enumerate().any(|(other_index, other)| {
                other_index != rule_index && expression_matches(&other.deny_when, &row.features)
            });
            if matched_by_other {
                continue;
            }
            if row.allowed {
                unique_negative_rows.push(row);
            } else {
                unique_positive_rows.push(row);
            }
        }

        if unique_negative_rows.len() < options.min_unique_false_positives
            || unique_positive_rows.is_empty()
        {
            tightened.push(rule.clone());
            continue;
        }

        let current_negative_hits = unique_negative_rows.len();
        let current_positive_hits = unique_positive_rows.len();
        let mut best_addition: Option<(ComparisonExpression, usize, usize)> = None;

        for feature in &binary_features {
            if rule_contains_feature(rule, feature) {
                continue;
            }
            for op in [ComparisonOperator::Gt, ComparisonOperator::Lte] {
                let candidate = ComparisonExpression {
                    feature: feature.clone(),
                    op: op.clone(),
                    value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                };
                let positive_hits = unique_positive_rows
                    .iter()
                    .filter(|row| comparison_matches(&candidate, &row.features))
                    .count();
                if positive_hits == 0 {
                    continue;
                }
                let retained = positive_hits as f64 / current_positive_hits as f64;
                if retained < options.min_true_positive_retention {
                    continue;
                }
                let negative_hits = unique_negative_rows
                    .iter()
                    .filter(|row| comparison_matches(&candidate, &row.features))
                    .count();
                if negative_hits >= current_negative_hits {
                    continue;
                }

                let better = match &best_addition {
                    None => true,
                    Some((_best, best_positive_hits, best_negative_hits)) => {
                        let candidate_reduction =
                            current_negative_hits.saturating_sub(negative_hits);
                        let best_reduction =
                            current_negative_hits.saturating_sub(*best_negative_hits);
                        match candidate_reduction.cmp(&best_reduction) {
                            Ordering::Greater => true,
                            Ordering::Less => false,
                            Ordering::Equal => match positive_hits.cmp(best_positive_hits) {
                                Ordering::Greater => true,
                                Ordering::Less => false,
                                Ordering::Equal => negative_hits < *best_negative_hits,
                            },
                        }
                    }
                };
                if better {
                    best_addition = Some((candidate, positive_hits, negative_hits));
                }
            }
        }

        if let Some((addition, _positive_hits, _negative_hits)) = best_addition {
            tightened.push(rule_with_added_condition(rule, addition));
            tightened_rules_applied += 1;
        } else {
            tightened.push(rule.clone());
        }
    }

    Ok((tightened, tightened_rules_applied))
}
