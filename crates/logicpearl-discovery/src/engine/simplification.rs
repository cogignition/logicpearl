// SPDX-License-Identifier: MIT
use super::candidates::{
    candidate_allowed_for_mode, compare_candidate_priority, CandidateMatchCache,
};
use super::scoring::{
    compare_candidate_set_score_with_policy, score_candidate_set_cached, CandidateSetScore,
};
use super::{dedupe_candidate_rules_by_signature, CandidateSelectionContext};
use crate::CandidateRule;
use logicpearl_ir::Expression;
use std::cmp::Ordering;

/// Post-selection generalization keeps the selected policy plan simple.
///
/// Candidate generation and selection are free to consider highly specific
/// conjunctions. Once a plan is chosen, this pass removes individual conjuncts
/// when the whole-plan score is no worse under the active selection policy.
pub(super) fn simplify_candidate_plan(
    selection_context: &CandidateSelectionContext<'_>,
    mut candidates: Vec<CandidateRule>,
) -> Vec<CandidateRule> {
    loop {
        let Some((candidate_index, replacement)) =
            best_simplifying_replacement(selection_context, &candidates)
        else {
            break;
        };
        candidates[candidate_index] = replacement;
        candidates = dedupe_candidate_rules_by_signature(candidates);
    }
    candidates
}

fn best_simplifying_replacement(
    selection_context: &CandidateSelectionContext<'_>,
    candidates: &[CandidateRule],
) -> Option<(usize, CandidateRule)> {
    let current_score = score_candidate_set_cached(
        candidates,
        &selection_context.training_indices,
        selection_context.validation_indices,
        &selection_context.match_cache,
    );
    let mut best: Option<(usize, CandidateRule, CandidateSetScore)> = None;

    for (candidate_index, candidate) in candidates.iter().enumerate() {
        for expression in one_atom_simplifications(&candidate.expression) {
            let replacement =
                candidate_from_expression_for_selection(selection_context, expression);
            if replacement.denied_coverage == 0
                || !candidate_allowed_for_mode(&replacement, selection_context.decision_mode)
            {
                continue;
            }
            let mut trial = candidates.to_vec();
            trial[candidate_index] = replacement.clone();
            trial = dedupe_candidate_rules_by_signature(trial);
            let trial_score = score_candidate_set_cached(
                &trial,
                &selection_context.training_indices,
                selection_context.validation_indices,
                &selection_context.match_cache,
            );
            if compare_candidate_set_score_with_policy(
                &trial_score,
                &current_score,
                selection_context.selection_policy,
                selection_context.training_denied_count,
                selection_context.training_allowed_count,
            ) == Ordering::Greater
            {
                continue;
            }
            let better = best.as_ref().is_none_or(|(_, best_candidate, best_score)| {
                compare_candidate_set_score_with_policy(
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
                best = Some((candidate_index, replacement, trial_score));
            }
        }
    }

    best.map(|(candidate_index, replacement, _)| (candidate_index, replacement))
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

fn one_atom_simplifications(expression: &Expression) -> Vec<Expression> {
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
