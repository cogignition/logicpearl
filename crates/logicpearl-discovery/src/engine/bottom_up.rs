// SPDX-License-Identifier: MIT
use super::candidates::{
    candidate_as_comparison, candidate_complexity_penalty, candidate_from_expression,
    candidate_signal_score, compare_candidate_priority, CandidateMatchCache,
};
use super::{
    BOTTOM_UP_CONJUNCTION_LEVEL_FRONTIER_LIMIT, BOTTOM_UP_CONJUNCTION_TOTAL_LIMIT,
    CONJUNCTION_ATOM_FRONTIER_LIMIT,
};
use crate::{
    report_progress, CandidateRule, DecisionTraceRow, DiscoveryDecisionMode, ProgressCallback,
    ResidualPassOptions,
};
use logicpearl_ir::{ComparisonExpression, Expression};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};

/// Bottom-up conjunction search keeps compound rules understandable.
///
/// Atomic candidates are ranked by signal, then expanded level-by-level. Each
/// level keeps only the strongest frontier, so larger conjunctions are explored
/// as refinements of useful simpler predicates instead of as opaque solver
/// fragments.
pub(super) fn conjunction_candidate_rules_with_cache(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    atomic_candidates: &[CandidateRule],
    options: &ResidualPassOptions,
    progress: Option<&ProgressCallback<'_>>,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> Vec<CandidateRule> {
    let mut prioritized_atoms = atomic_candidates
        .iter()
        .filter(|candidate| candidate_as_comparison(candidate).is_some())
        .collect::<Vec<_>>();
    prioritized_atoms.sort_by(|left, right| compare_conjunction_atom_priority(left, right));
    let atoms = prioritized_atoms
        .into_iter()
        .take(CONJUNCTION_ATOM_FRONTIER_LIMIT)
        .filter_map(|candidate| {
            Some(BottomUpAtom {
                index: 0,
                comparison: candidate_as_comparison(candidate)?.clone(),
                signature: candidate.signature().to_string(),
            })
        })
        .collect::<Vec<_>>();
    if atoms.len() < 2 || options.max_conditions < 2 {
        return Vec::new();
    }
    let atoms = atoms
        .into_iter()
        .enumerate()
        .map(|(index, mut atom)| {
            atom.index = index;
            atom
        })
        .collect::<Vec<_>>();
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: bottom-up conjunction search from {} atoms (max_conditions={}, max_rules={})",
            atoms.len(),
            options.max_conditions,
            options.max_rules
        ),
    );

    let conjunctions = bottom_up_conjunction_candidates(
        rows,
        denied_indices,
        allowed_indices,
        &atoms,
        options,
        progress,
        match_cache,
    );
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: bottom-up conjunction search retained {} candidates",
            conjunctions.len()
        ),
    );

    conjunctions
        .into_iter()
        .map(|candidate| candidate.candidate)
        .collect()
}

#[derive(Debug, Clone)]
struct BottomUpAtom {
    index: usize,
    comparison: ComparisonExpression,
    signature: String,
}

#[derive(Debug, Clone)]
struct BottomUpConjunction {
    atom_indices: Vec<usize>,
    atom_signatures: HashSet<String>,
    comparisons: Vec<ComparisonExpression>,
    candidate: CandidateRule,
}

fn bottom_up_conjunction_candidates(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    atoms: &[BottomUpAtom],
    options: &ResidualPassOptions,
    progress: Option<&ProgressCallback<'_>>,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> Vec<BottomUpConjunction> {
    let max_conditions = options.max_conditions.max(2);
    let level_limit = BOTTOM_UP_CONJUNCTION_LEVEL_FRONTIER_LIMIT
        .max(options.max_rules.saturating_mul(16))
        .min(BOTTOM_UP_CONJUNCTION_TOTAL_LIMIT);
    let total_limit = BOTTOM_UP_CONJUNCTION_TOTAL_LIMIT
        .max(options.max_rules.saturating_mul(32))
        .min(BOTTOM_UP_CONJUNCTION_TOTAL_LIMIT);

    let mut accepted_by_signature = BTreeSet::new();
    let mut all_retained = Vec::<BottomUpConjunction>::new();
    let mut previous_level = Vec::<BottomUpConjunction>::new();

    for left_index in 0..atoms.len() {
        for right_index in (left_index + 1)..atoms.len() {
            let Some(candidate) = bottom_up_candidate_from_atoms(
                rows,
                denied_indices,
                allowed_indices,
                &[atoms[left_index].clone(), atoms[right_index].clone()],
                options,
                match_cache,
            ) else {
                continue;
            };
            if accepted_by_signature.insert(candidate.candidate.signature().to_string()) {
                previous_level.push(candidate.clone());
                all_retained.push(candidate);
            }
        }
    }
    sort_bottom_up_conjunctions(&mut previous_level);
    previous_level.truncate(level_limit);
    sort_bottom_up_conjunctions(&mut all_retained);
    all_retained.truncate(total_limit);
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: bottom-up conjunction level 2 retained {} candidates",
            previous_level.len()
        ),
    );

    for size in 3..=max_conditions {
        if previous_level.is_empty() || all_retained.len() >= total_limit {
            break;
        }
        let mut next_level = Vec::<BottomUpConjunction>::new();
        for parent in &previous_level {
            let Some(last_index) = parent.atom_indices.last().copied() else {
                continue;
            };
            for atom in atoms.iter().skip(last_index + 1) {
                if parent.atom_signatures.contains(&atom.signature) {
                    continue;
                }
                let mut candidate_atoms = parent
                    .atom_indices
                    .iter()
                    .map(|index| atoms[*index].clone())
                    .collect::<Vec<_>>();
                candidate_atoms.push(atom.clone());
                let Some(candidate) = bottom_up_candidate_from_atoms(
                    rows,
                    denied_indices,
                    allowed_indices,
                    &candidate_atoms,
                    options,
                    match_cache,
                ) else {
                    continue;
                };
                if accepted_by_signature.insert(candidate.candidate.signature().to_string()) {
                    next_level.push(candidate.clone());
                    all_retained.push(candidate);
                    if all_retained.len() >= total_limit {
                        break;
                    }
                }
            }
            if all_retained.len() >= total_limit {
                break;
            }
        }
        sort_bottom_up_conjunctions(&mut next_level);
        next_level.truncate(level_limit);
        report_progress(
            progress,
            "candidate_generation",
            format!(
                "candidate_generation: bottom-up conjunction level {size} retained {} candidates",
                next_level.len()
            ),
        );
        previous_level = next_level;
    }

    sort_bottom_up_conjunctions(&mut all_retained);
    all_retained.truncate(total_limit);
    all_retained
}

fn bottom_up_candidate_from_atoms(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    atoms: &[BottomUpAtom],
    options: &ResidualPassOptions,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> Option<BottomUpConjunction> {
    let mut atom_indices = atoms.iter().map(|atom| atom.index).collect::<Vec<_>>();
    atom_indices.sort_unstable();
    let atom_signatures = atoms
        .iter()
        .map(|atom| atom.signature.clone())
        .collect::<HashSet<_>>();
    let comparisons = atoms
        .iter()
        .map(|atom| atom.comparison.clone())
        .collect::<Vec<_>>();
    let candidate = candidate_from_expression(
        rows,
        denied_indices,
        allowed_indices,
        conjunction_expression(comparisons.clone()),
        match_cache,
    );
    if candidate.denied_coverage < options.min_positive_support {
        return None;
    }
    if candidate_signal_score(&candidate) <= 0.0 {
        return None;
    }
    Some(BottomUpConjunction {
        atom_indices,
        atom_signatures,
        comparisons,
        candidate,
    })
}

fn sort_bottom_up_conjunctions(conjunctions: &mut [BottomUpConjunction]) {
    conjunctions.sort_by(|left, right| {
        compare_candidate_priority(&left.candidate, &right.candidate)
            .then_with(|| left.comparisons.len().cmp(&right.comparisons.len()))
            .then_with(|| left.candidate.signature().cmp(right.candidate.signature()))
    });
}

fn compare_conjunction_atom_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
    candidate_signal_score(right)
        .total_cmp(&candidate_signal_score(left))
        .then_with(|| left.false_positives.cmp(&right.false_positives))
        .then_with(|| right.denied_coverage.cmp(&left.denied_coverage))
        .then_with(|| {
            candidate_complexity_penalty(left, DiscoveryDecisionMode::Standard).cmp(
                &candidate_complexity_penalty(right, DiscoveryDecisionMode::Standard),
            )
        })
        .then_with(|| left.signature().cmp(right.signature()))
}

fn comparison_sort_key(c: &ComparisonExpression) -> (String, String, String) {
    (
        c.feature.clone(),
        format!("{:?}", c.op),
        serde_json::to_string(&c.value).unwrap_or_default(),
    )
}

fn conjunction_expression(mut comparisons: Vec<ComparisonExpression>) -> Expression {
    comparisons.sort_by_key(comparison_sort_key);
    if comparisons.len() == 1 {
        return Expression::Comparison(comparisons.pop().expect("single comparison"));
    }
    Expression::All {
        all: comparisons
            .into_iter()
            .map(Expression::Comparison)
            .collect(),
    }
}
