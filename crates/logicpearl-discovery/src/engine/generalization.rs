// SPDX-License-Identifier: MIT
use super::candidates::{
    candidate_allowed_for_mode, compare_candidate_priority, CandidateMatchCache,
};
use super::scoring::{
    compare_candidate_set_score_with_policy_for_generalization, score_candidate_set_cached,
    CandidateSetScore,
};
use super::{dedupe_candidate_rules_by_signature, CandidateSelectionContext};
use crate::CandidateRule;
use logicpearl_ir::{Expression, RuleSimplificationEvidence};
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Post-selection generalization keeps the selected policy plan simple.
///
/// Candidate generation and selection are free to consider highly specific
/// conjunctions. Once a plan is chosen, this pass removes individual conjuncts
/// and selected rules that are subsumed by broader selected rules when the
/// whole-plan score is no worse under the active selection policy.
pub(super) fn generalize_candidate_plan(
    selection_context: &CandidateSelectionContext<'_>,
    mut candidates: Vec<CandidateRule>,
) -> Vec<CandidateRule> {
    loop {
        let Some(replacement) = best_generalizing_plan_replacement(selection_context, &candidates)
        else {
            break;
        };
        candidates = replacement;
    }
    remove_subsumed_candidates(selection_context, candidates)
}

fn best_generalizing_plan_replacement(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
) -> Option<Vec<CandidateRule>> {
    let current_score = score_candidate_set_cached(
        candidates,
        &selection_context.training_indices,
        selection_context.validation_indices,
        &selection_context.match_cache,
    );
    let mut best: Option<(Vec<CandidateRule>, CandidateRule, CandidateSetScore)> = None;

    for candidate in candidates {
        for expression in one_atom_generalizations(&candidate.expression) {
            let mut replacement =
                candidate_from_expression_for_selection(selection_context, expression);
            if replacement.denied_coverage == 0
                || !candidate_allowed_for_mode(&replacement, selection_context.decision_mode)
            {
                continue;
            }
            let covered_indices =
                indices_subsumed_by_replacement(selection_context, candidates, &replacement);
            if covered_indices.is_empty()
                || !replacement_strictly_generalizes_group(
                    selection_context,
                    candidates,
                    &replacement,
                    &covered_indices,
                )
            {
                continue;
            }
            replacement.simplifications =
                simplifications_for_covered_candidates(candidates, &covered_indices);
            let mut trial = candidates
                .iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    (!covered_indices.contains(&index)).then_some(candidate.clone())
                })
                .collect::<Vec<_>>();
            trial.push(replacement.clone());
            trial = dedupe_candidate_rules_by_signature(trial);
            let trial_score = score_candidate_set_cached(
                &trial,
                &selection_context.training_indices,
                selection_context.validation_indices,
                &selection_context.match_cache,
            );
            if compare_candidate_set_score_with_policy_for_generalization(
                &trial_score,
                &current_score,
                selection_context.selection_policy,
                selection_context.training_denied_count,
                selection_context.training_allowed_count,
            ) == Ordering::Greater
            {
                continue;
            }
            replacement.simplifications.push(generalization_evidence(
                selection_context,
                candidates,
                &covered_indices,
                &replacement,
                &current_score,
                &trial_score,
                trial.len(),
            ));
            let mut trial_with_evidence = candidates
                .iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    (!covered_indices.contains(&index)).then_some(candidate.clone())
                })
                .collect::<Vec<_>>();
            trial_with_evidence.push(replacement.clone());
            trial_with_evidence = dedupe_candidate_rules_by_signature(trial_with_evidence);
            let better = best.as_ref().is_none_or(|(_, best_candidate, best_score)| {
                compare_candidate_set_score_with_policy_for_generalization(
                    &trial_score,
                    best_score,
                    selection_context.selection_policy,
                    selection_context.training_denied_count,
                    selection_context.training_allowed_count,
                ) == Ordering::Less
                    || (trial_score == *best_score
                        && compare_candidate_priority(&replacement, best_candidate)
                            == Ordering::Less)
            });
            if better {
                best = Some((trial_with_evidence, replacement, trial_score));
            }
        }
    }

    best.map(|(trial, _, _)| trial)
}

pub(super) fn candidate_from_expression_for_selection(
    selection_context: &CandidateSelectionContext<'_>,
    expression: Expression,
) -> CandidateRule {
    candidate_from_expression(
        &selection_context.match_cache,
        selection_context.denied_indices,
        selection_context.allowed_indices,
        expression,
    )
}

fn candidate_from_expression(
    match_cache: &CandidateMatchCache<'_>,
    denied_indices: &[usize],
    allowed_indices: &[usize],
    expression: Expression,
) -> CandidateRule {
    CandidateRule::new_with_population(
        expression.clone(),
        match_cache.coverage_for_expression(denied_indices, &expression),
        match_cache.coverage_for_expression(allowed_indices, &expression),
        denied_indices.len(),
        allowed_indices.len(),
    )
}

fn one_atom_generalizations(expression: &Expression) -> Vec<Expression> {
    let Expression::All { all } = expression else {
        return Vec::new();
    };
    if all.len() <= 1 {
        return Vec::new();
    }
    (0..all.len())
        .map(|drop_index| {
            let kept = all
                .iter()
                .enumerate()
                .filter_map(|(index, child)| (index != drop_index).then_some(child.clone()))
                .collect::<Vec<_>>();
            if kept.len() == 1 {
                kept.into_iter().next().expect("single kept expression")
            } else {
                Expression::All { all: kept }
            }
        })
        .collect()
}

fn indices_subsumed_by_replacement(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
    replacement: &CandidateRule,
) -> Vec<usize> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            candidate_subsumes_on_indices(
                selection_context,
                replacement,
                candidate,
                &selection_context.training_indices,
            )
            .then_some(index)
        })
        .collect()
}

fn replacement_strictly_generalizes_group(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
    replacement: &CandidateRule,
    covered_indices: &[usize],
) -> bool {
    if covered_indices.len() > 1 {
        return true;
    }
    covered_indices.iter().any(|index| {
        candidate_strictly_subsumes_on_indices(
            selection_context,
            replacement,
            &candidates[*index],
            &selection_context.training_indices,
        ) || compare_candidate_priority(replacement, &candidates[*index]) == Ordering::Less
    })
}

fn remove_subsumed_candidates(
    selection_context: &CandidateSelectionContext<'_>,
    mut candidates: Vec<CandidateRule>,
) -> Vec<CandidateRule> {
    loop {
        let Some((remove_index, broader_index, trial_score, current_score)) =
            best_subsumed_candidate_removal(selection_context, &candidates)
        else {
            break;
        };
        let broader = candidates[broader_index].clone();
        let removed = candidates[remove_index].clone();
        let evidence = subsumed_rule_evidence(
            &candidates,
            &removed,
            &broader,
            &current_score,
            &trial_score,
        );
        candidates[broader_index].simplifications.push(evidence);
        candidates.remove(remove_index);
    }
    candidates
}

fn best_subsumed_candidate_removal(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
) -> Option<(usize, usize, CandidateSetScore, CandidateSetScore)> {
    if candidates.len() <= 1 {
        return None;
    }
    let current_score = score_candidate_set_cached(
        candidates,
        &selection_context.training_indices,
        selection_context.validation_indices,
        &selection_context.match_cache,
    );
    let mut best: Option<(usize, usize, CandidateSetScore)> = None;

    for remove_index in 0..candidates.len() {
        let Some(broader_index) =
            best_subsuming_candidate_index(selection_context, candidates, remove_index)
        else {
            continue;
        };
        let trial = candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| (index != remove_index).then_some(candidate.clone()))
            .collect::<Vec<_>>();
        let trial_score = score_candidate_set_cached(
            &trial,
            &selection_context.training_indices,
            selection_context.validation_indices,
            &selection_context.match_cache,
        );
        if compare_candidate_set_score_with_policy_for_generalization(
            &trial_score,
            &current_score,
            selection_context.selection_policy,
            selection_context.training_denied_count,
            selection_context.training_allowed_count,
        ) == Ordering::Greater
        {
            continue;
        }
        let better = best.as_ref().is_none_or(|(_, _, best_score)| {
            compare_candidate_set_score_with_policy_for_generalization(
                &trial_score,
                best_score,
                selection_context.selection_policy,
                selection_context.training_denied_count,
                selection_context.training_allowed_count,
            ) == Ordering::Less
        });
        if better {
            best = Some((remove_index, broader_index, trial_score));
        }
    }

    best.map(|(remove_index, broader_index, trial_score)| {
        (remove_index, broader_index, trial_score, current_score)
    })
}

fn best_subsuming_candidate_index(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
    narrower_index: usize,
) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(broader_index, broader)| {
            (broader_index != narrower_index
                && candidate_strictly_subsumes_on_indices(
                    selection_context,
                    broader,
                    &candidates[narrower_index],
                    &selection_context.training_indices,
                ))
            .then_some((broader_index, broader))
        })
        .min_by(|(_, left), (_, right)| compare_candidate_priority(left, right))
        .map(|(index, _)| index)
}

fn candidate_strictly_subsumes_on_indices(
    selection_context: &CandidateSelectionContext<'_>,
    broader: &CandidateRule,
    narrower: &CandidateRule,
    indices: &[usize],
) -> bool {
    let mut broader_has_extra_match = false;
    for index in indices {
        let narrower_matches = selection_context
            .match_cache
            .matches_candidate(*index, narrower);
        let broader_matches = selection_context
            .match_cache
            .matches_candidate(*index, broader);
        if narrower_matches && !broader_matches {
            return false;
        }
        if broader_matches && !narrower_matches {
            broader_has_extra_match = true;
        }
    }
    broader_has_extra_match
}

fn candidate_subsumes_on_indices(
    selection_context: &CandidateSelectionContext<'_>,
    broader: &CandidateRule,
    narrower: &CandidateRule,
    indices: &[usize],
) -> bool {
    indices.iter().all(|index| {
        !selection_context
            .match_cache
            .matches_candidate(*index, narrower)
            || selection_context
                .match_cache
                .matches_candidate(*index, broader)
    })
}

fn simplifications_for_covered_candidates(
    candidates: &[CandidateRule],
    covered_indices: &[usize],
) -> Vec<RuleSimplificationEvidence> {
    covered_indices
        .iter()
        .flat_map(|index| candidates[*index].simplifications.clone())
        .collect()
}

fn generalization_evidence(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
    covered_indices: &[usize],
    replacement: &CandidateRule,
    current_score: &CandidateSetScore,
    trial_score: &CandidateSetScore,
    after_rule_count: usize,
) -> RuleSimplificationEvidence {
    let (denied_before, allowed_before) =
        group_support(selection_context, candidates, covered_indices);
    RuleSimplificationEvidence {
        kind: if covered_indices.len() > 1 {
            "shared_prefix_generalization".to_string()
        } else {
            "dropped_conjunct".to_string()
        },
        reason: simplification_reason(current_score, trial_score),
        dropped_predicates: dropped_predicate_labels(candidates, covered_indices, replacement),
        before_rule_count: candidates.len(),
        after_rule_count,
        removed_rule_count: covered_indices.len().saturating_sub(1),
        training_total_errors_before: current_score.total_errors,
        training_total_errors_after: trial_score.total_errors,
        validation_total_errors_before: current_score.validation_total_errors,
        validation_total_errors_after: trial_score.validation_total_errors,
        denied_trace_count_before: denied_before,
        denied_trace_count_after: replacement.denied_coverage,
        allowed_trace_count_before: allowed_before,
        allowed_trace_count_after: replacement.false_positives,
    }
}

fn subsumed_rule_evidence(
    candidates: &[CandidateRule],
    removed: &CandidateRule,
    broader: &CandidateRule,
    current_score: &CandidateSetScore,
    trial_score: &CandidateSetScore,
) -> RuleSimplificationEvidence {
    RuleSimplificationEvidence {
        kind: "subsumed_rule_removed".to_string(),
        reason: simplification_reason(current_score, trial_score),
        dropped_predicates: vec![expression_label(&removed.expression)],
        before_rule_count: candidates.len(),
        after_rule_count: candidates.len().saturating_sub(1),
        removed_rule_count: 1,
        training_total_errors_before: current_score.total_errors,
        training_total_errors_after: trial_score.total_errors,
        validation_total_errors_before: current_score.validation_total_errors,
        validation_total_errors_after: trial_score.validation_total_errors,
        denied_trace_count_before: removed.denied_coverage,
        denied_trace_count_after: broader.denied_coverage,
        allowed_trace_count_before: removed.false_positives,
        allowed_trace_count_after: broader.false_positives,
    }
}

fn simplification_reason(
    current_score: &CandidateSetScore,
    trial_score: &CandidateSetScore,
) -> String {
    if trial_score.validation_total_errors < current_score.validation_total_errors {
        "validation errors decreased".to_string()
    } else if trial_score.validation_total_errors == current_score.validation_total_errors
        && trial_score.total_errors <= current_score.total_errors
    {
        "validation errors unchanged and training errors did not increase".to_string()
    } else if trial_score.validation_total_errors == current_score.validation_total_errors {
        "validation errors unchanged; simpler rule accepted by generalization policy".to_string()
    } else {
        "accepted by generalization policy".to_string()
    }
}

fn group_support(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
    covered_indices: &[usize],
) -> (usize, usize) {
    let denied = selection_context
        .denied_indices
        .iter()
        .filter(|row_index| {
            covered_indices.iter().any(|candidate_index| {
                selection_context
                    .match_cache
                    .matches_candidate(**row_index, &candidates[*candidate_index])
            })
        })
        .count();
    let allowed = selection_context
        .allowed_indices
        .iter()
        .filter(|row_index| {
            covered_indices.iter().any(|candidate_index| {
                selection_context
                    .match_cache
                    .matches_candidate(**row_index, &candidates[*candidate_index])
            })
        })
        .count();
    (denied, allowed)
}

fn dropped_predicate_labels(
    candidates: &[CandidateRule],
    covered_indices: &[usize],
    replacement: &CandidateRule,
) -> Vec<String> {
    let replacement_atoms = expression_atom_labels(&replacement.expression);
    covered_indices
        .iter()
        .flat_map(|index| expression_atom_labels(&candidates[*index].expression))
        .filter(|atom| !replacement_atoms.contains(atom))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn expression_atom_labels(expression: &Expression) -> BTreeSet<String> {
    match expression {
        Expression::All { all } => all.iter().map(expression_label).collect(),
        _ => [expression_label(expression)].into_iter().collect(),
    }
}

fn expression_label(expression: &Expression) -> String {
    serde_json::to_string(expression).unwrap_or_else(|_| format!("{expression:?}"))
}
