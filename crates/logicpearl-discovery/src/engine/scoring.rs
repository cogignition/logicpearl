// SPDX-License-Identifier: MIT
#[cfg(test)]
use super::candidates::matches_candidate;
use super::candidates::{
    candidate_complexity_penalty, candidate_memorization_penalty, CandidateMatchCache,
};
#[cfg(test)]
use super::DecisionTraceRow;
use super::{CandidateRule, DiscoveryDecisionMode, SelectionPolicy};
use std::cmp::Ordering;
#[cfg(test)]
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CandidateSetScore {
    pub(super) total_errors: usize,
    pub(super) false_positives: usize,
    pub(super) false_negatives: usize,
    pub(super) validation_total_errors: usize,
    pub(super) validation_false_positives: usize,
    pub(super) validation_false_negatives: usize,
    pub(super) rule_count: usize,
    pub(super) complexity_penalty: usize,
}

pub(super) fn compare_candidate_set_score(
    left: &CandidateSetScore,
    right: &CandidateSetScore,
) -> Ordering {
    left.total_errors
        .cmp(&right.total_errors)
        .then_with(|| {
            left.validation_total_errors
                .cmp(&right.validation_total_errors)
        })
        .then_with(|| left.false_positives.cmp(&right.false_positives))
        .then_with(|| {
            left.validation_false_positives
                .cmp(&right.validation_false_positives)
        })
        .then_with(|| left.rule_count.cmp(&right.rule_count))
        .then_with(|| left.complexity_penalty.cmp(&right.complexity_penalty))
        .then_with(|| left.false_negatives.cmp(&right.false_negatives))
        .then_with(|| {
            left.validation_false_negatives
                .cmp(&right.validation_false_negatives)
        })
}

pub(super) fn compare_candidate_set_score_with_policy(
    left: &CandidateSetScore,
    right: &CandidateSetScore,
    selection_policy: SelectionPolicy,
    denied_count: usize,
    allowed_count: usize,
) -> Ordering {
    match selection_policy {
        SelectionPolicy::Balanced => compare_candidate_set_score(left, right),
        SelectionPolicy::RecallBiased { .. } => {
            let left_under_cap =
                left.false_positives <= selection_policy.max_allowed_false_positives(allowed_count);
            let right_under_cap = right.false_positives
                <= selection_policy.max_allowed_false_positives(allowed_count);
            right_under_cap.cmp(&left_under_cap).then_with(|| {
                if left_under_cap && right_under_cap {
                    let left_hits_target = denied_count.saturating_sub(left.false_negatives)
                        >= selection_policy.required_denied_hits(denied_count);
                    let right_hits_target = denied_count.saturating_sub(right.false_negatives)
                        >= selection_policy.required_denied_hits(denied_count);
                    right_hits_target.cmp(&left_hits_target).then_with(|| {
                        if left_hits_target && right_hits_target {
                            left.false_positives
                                .cmp(&right.false_positives)
                                .then_with(|| {
                                    left.validation_false_positives
                                        .cmp(&right.validation_false_positives)
                                })
                                .then_with(|| {
                                    left.validation_total_errors
                                        .cmp(&right.validation_total_errors)
                                })
                                .then_with(|| left.rule_count.cmp(&right.rule_count))
                                .then_with(|| {
                                    left.complexity_penalty.cmp(&right.complexity_penalty)
                                })
                                .then_with(|| left.false_negatives.cmp(&right.false_negatives))
                        } else {
                            left.false_negatives
                                .cmp(&right.false_negatives)
                                .then_with(|| left.false_positives.cmp(&right.false_positives))
                                .then_with(|| {
                                    left.validation_total_errors
                                        .cmp(&right.validation_total_errors)
                                })
                                .then_with(|| left.rule_count.cmp(&right.rule_count))
                                .then_with(|| {
                                    left.complexity_penalty.cmp(&right.complexity_penalty)
                                })
                        }
                    })
                } else {
                    left.false_positives
                        .cmp(&right.false_positives)
                        .then_with(|| left.false_negatives.cmp(&right.false_negatives))
                        .then_with(|| {
                            left.validation_total_errors
                                .cmp(&right.validation_total_errors)
                        })
                        .then_with(|| left.rule_count.cmp(&right.rule_count))
                        .then_with(|| left.complexity_penalty.cmp(&right.complexity_penalty))
                }
            })
        }
    }
}

#[cfg(test)]
pub(super) fn score_candidate_set(
    rows: &[DecisionTraceRow],
    candidates: &[CandidateRule],
    validation_indices: Option<&[usize]>,
) -> CandidateSetScore {
    let validation_set = validation_indices
        .map(|indices| indices.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let training_indices = rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| (!validation_set.contains(&index)).then_some(index))
        .collect::<Vec<_>>();
    let training_score = score_candidate_subset(rows, candidates, &training_indices);
    let validation_score =
        score_candidate_subset(rows, candidates, validation_indices.unwrap_or(&[]));
    let complexity_penalty = candidates.iter().map(candidate_total_penalty).sum();
    CandidateSetScore {
        total_errors: training_score.total_errors,
        false_positives: training_score.false_positives,
        false_negatives: training_score.false_negatives,
        validation_total_errors: validation_score.total_errors,
        validation_false_positives: validation_score.false_positives,
        validation_false_negatives: validation_score.false_negatives,
        rule_count: candidates.len(),
        complexity_penalty,
    }
}

pub(super) fn score_candidate_set_cached(
    candidates: &[CandidateRule],
    training_indices: &[usize],
    validation_indices: &[usize],
    match_cache: &CandidateMatchCache<'_>,
) -> CandidateSetScore {
    let training_score = score_candidate_subset_cached(candidates, training_indices, match_cache);
    let validation_score =
        score_candidate_subset_cached(candidates, validation_indices, match_cache);
    let complexity_penalty = candidates
        .iter()
        .map(|candidate| candidate_total_penalty_cached(candidate, match_cache))
        .sum();
    CandidateSetScore {
        total_errors: training_score.total_errors,
        false_positives: training_score.false_positives,
        false_negatives: training_score.false_negatives,
        validation_total_errors: validation_score.total_errors,
        validation_false_positives: validation_score.false_positives,
        validation_false_negatives: validation_score.false_negatives,
        rule_count: candidates.len(),
        complexity_penalty,
    }
}

#[cfg(test)]
pub(super) fn score_candidate_subset(
    rows: &[DecisionTraceRow],
    candidates: &[CandidateRule],
    indices: &[usize],
) -> CandidateSubsetScore {
    let false_positives = indices
        .iter()
        .filter(|index| {
            rows[**index].allowed
                && candidates
                    .iter()
                    .any(|rule| matches_candidate(&rows[**index].features, rule))
        })
        .count();
    let false_negatives = indices
        .iter()
        .filter(|index| {
            !rows[**index].allowed
                && !candidates
                    .iter()
                    .any(|rule| matches_candidate(&rows[**index].features, rule))
        })
        .count();
    CandidateSubsetScore {
        total_errors: false_positives + false_negatives,
        false_positives,
        false_negatives,
    }
}

pub(super) fn score_candidate_subset_cached(
    candidates: &[CandidateRule],
    indices: &[usize],
    match_cache: &CandidateMatchCache<'_>,
) -> CandidateSubsetScore {
    let false_positives = indices
        .iter()
        .filter(|index| {
            match_cache.rows()[**index].allowed
                && candidates
                    .iter()
                    .any(|rule| match_cache.matches_candidate(**index, rule))
        })
        .count();
    let false_negatives = indices
        .iter()
        .filter(|index| {
            !match_cache.rows()[**index].allowed
                && !candidates
                    .iter()
                    .any(|rule| match_cache.matches_candidate(**index, rule))
        })
        .count();
    CandidateSubsetScore {
        total_errors: false_positives + false_negatives,
        false_positives,
        false_negatives,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CandidateSubsetScore {
    pub(super) total_errors: usize,
    pub(super) false_positives: usize,
    pub(super) false_negatives: usize,
}

pub(super) fn candidate_total_penalty(candidate: &CandidateRule) -> usize {
    candidate_complexity_penalty(candidate, DiscoveryDecisionMode::Standard)
        + candidate_memorization_penalty(candidate)
}

fn candidate_total_penalty_cached(
    candidate: &CandidateRule,
    match_cache: &CandidateMatchCache<'_>,
) -> usize {
    match_cache.complexity_penalty(candidate, DiscoveryDecisionMode::Standard)
        + candidate_memorization_penalty(candidate)
}
