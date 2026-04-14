// SPDX-License-Identifier: MIT
use super::candidates::{
    candidate_complexity_penalty, candidate_memorization_penalty, matches_candidate,
};
use super::{CandidateRule, DecisionTraceRow, DiscoveryDecisionMode};
use std::cmp::Ordering;
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
