// SPDX-License-Identifier: MIT
use good_lp::{
    constraint, microlp, variable, variables, Expression as LpExpression, ResolutionError,
    Solution, SolverModel, Variable,
};
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_solver::{
    resolve_backend, solve_keep_bools_lexicographic, LexObjective, SatStatus, SolverSettings,
};
use std::collections::BTreeSet;
use std::env;
use std::time::Instant;

use super::super::{
    CandidateRule, DecisionTraceRow, ExactSelectionBackend, ExactSelectionReport, SelectionPolicy,
};
use super::candidates::{candidate_is_compound, compare_candidate_priority, matches_candidate};
use super::scoring::candidate_total_penalty;

const EXACT_SELECTION_COMPOUND_FRONTIER_LIMIT: usize = 24;
const EXACT_SELECTION_BRUTE_FORCE_LIMIT: usize = 16;

pub(crate) const DISCOVERY_SELECTION_BACKEND_ENV: &str = "LOGICPEARL_DISCOVERY_SELECTION_BACKEND";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoverySelectionBackend {
    Smt,
    Mip,
}

struct DiscoverySelectionSettings {
    backend: DiscoverySelectionBackend,
}

impl DiscoverySelectionSettings {
    fn from_env() -> Result<Self> {
        let backend = env::var(DISCOVERY_SELECTION_BACKEND_ENV)
            .ok()
            .map(|raw| parse_discovery_selection_backend(&raw))
            .transpose()?
            .unwrap_or(DiscoverySelectionBackend::Smt);
        Ok(Self { backend })
    }
}

fn parse_discovery_selection_backend(raw: &str) -> Result<DiscoverySelectionBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "smt" => Ok(DiscoverySelectionBackend::Smt),
        "mip" => Ok(DiscoverySelectionBackend::Mip),
        other => Err(LogicPearlError::message(format!(
            "unsupported discovery selection backend `{other}` in {DISCOVERY_SELECTION_BACKEND_ENV}; expected `smt` or `mip`"
        ))),
    }
}

pub(super) fn current_solver_backend() -> Result<Option<String>> {
    let settings = SolverSettings::from_env()?;
    Ok(Some(resolve_backend(&settings)?.as_str().to_string()))
}

pub(super) fn exact_selection_shortlist(
    all_candidates: &[CandidateRule],
    greedy_plan: &[CandidateRule],
    limit: usize,
) -> Vec<CandidateRule> {
    let mut shortlisted: Vec<CandidateRule> = all_candidates.iter().take(limit).cloned().collect();
    let mut signatures: BTreeSet<String> = shortlisted
        .iter()
        .map(|c| c.signature().to_string())
        .collect();
    for candidate in all_candidates
        .iter()
        .filter(|candidate| candidate_is_compound(candidate))
        .take(EXACT_SELECTION_COMPOUND_FRONTIER_LIMIT)
    {
        let signature = candidate.signature().to_string();
        if signatures.insert(signature) {
            shortlisted.push(candidate.clone());
        }
    }
    for candidate in greedy_plan {
        let signature = candidate.signature().to_string();
        if signatures.insert(signature) {
            shortlisted.push(candidate.clone());
        }
    }
    shortlisted.sort_by(compare_candidate_priority);
    shortlisted
}

pub(super) fn select_candidate_rules_exact(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    candidates: &[CandidateRule],
    selection_policy: SelectionPolicy,
) -> Result<(Option<Vec<CandidateRule>>, ExactSelectionReport)> {
    let started = Instant::now();
    let mut report = ExactSelectionReport {
        shortlisted_candidates: candidates.len(),
        ..Default::default()
    };
    if candidates.is_empty() {
        report.duration_ms = Some(started.elapsed().as_millis() as u64);
        return Ok((Some(Vec::new()), report));
    }
    let denied_matches: Vec<Vec<usize>> = denied_indices
        .iter()
        .map(|index| {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(candidate_index, candidate)| {
                    matches_candidate(&rows[*index].features, candidate).then_some(candidate_index)
                })
                .collect()
        })
        .collect();
    let allowed_matches: Vec<Vec<usize>> = allowed_indices
        .iter()
        .map(|index| {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(candidate_index, candidate)| {
                    matches_candidate(&rows[*index].features, candidate).then_some(candidate_index)
                })
                .collect()
        })
        .collect();

    if candidates.len() <= EXACT_SELECTION_BRUTE_FORCE_LIMIT {
        let (selected, detail) = select_candidate_rules_bruteforce(
            candidates,
            &denied_matches,
            &allowed_matches,
            selection_policy,
        );
        report.backend = Some(ExactSelectionBackend::BruteForce);
        report.selected_candidates = selected.len();
        report.detail = detail;
        report.duration_ms = Some(started.elapsed().as_millis() as u64);
        return Ok((Some(selected), report));
    }

    let selection_settings = DiscoverySelectionSettings::from_env()?;
    report.backend = Some(match selection_settings.backend {
        DiscoverySelectionBackend::Smt => ExactSelectionBackend::Smt,
        DiscoverySelectionBackend::Mip => ExactSelectionBackend::Mip,
    });
    let selection_result = match selection_settings.backend {
        DiscoverySelectionBackend::Smt => solve_selected_rule_indexes_for_policy(
            ExactSelectionBackend::Smt,
            candidates,
            &denied_matches,
            &allowed_matches,
            selection_policy,
        ),
        DiscoverySelectionBackend::Mip => solve_selected_rule_indexes_for_policy(
            ExactSelectionBackend::Mip,
            candidates,
            &denied_matches,
            &allowed_matches,
            selection_policy,
        ),
    };
    let (selected_indexes, detail) = match selection_result {
        Ok(result) => result,
        Err(err) => {
            report.detail = Some(format!(
                "falling back to greedy after {:?} exact selection failed: {err}",
                report.backend.as_ref().expect("backend should be set")
            ));
            report.duration_ms = Some(started.elapsed().as_millis() as u64);
            return Ok((None, report));
        }
    };
    report.selected_candidates = selected_indexes.len();
    report.detail = detail;
    report.duration_ms = Some(started.elapsed().as_millis() as u64);
    Ok((
        Some(
            selected_indexes
                .into_iter()
                .map(|index| candidates[index].clone())
                .collect(),
        ),
        report,
    ))
}

#[derive(Debug, Clone, Copy, Default)]
struct ExactSelectionConstraints {
    max_denied_misses: Option<usize>,
    max_allowed_hits: Option<usize>,
}

fn solve_selected_rule_indexes_for_policy(
    backend: ExactSelectionBackend,
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    selection_policy: SelectionPolicy,
) -> Result<(Vec<usize>, Option<String>)> {
    match selection_policy {
        SelectionPolicy::Balanced => {
            let indexes = solve_selected_rule_indexes_with_backend(
                backend,
                candidates,
                denied_matches,
                allowed_matches,
                ExactSelectionConstraints::default(),
                &[
                    RuleSelectionObjective::TotalErrors,
                    RuleSelectionObjective::AllowedHits,
                    RuleSelectionObjective::KeepCount,
                    RuleSelectionObjective::ComplexityWeight,
                    RuleSelectionObjective::KeepIndexSum,
                ],
            )?;
            Ok((indexes, None))
        }
        SelectionPolicy::RecallBiased {
            deny_recall_target,
            max_false_positive_rate,
        } => {
            let strict_constraints =
                ExactSelectionConstraints {
                    max_denied_misses: Some(denied_matches.len().saturating_sub(
                        selection_policy.required_denied_hits(denied_matches.len()),
                    )),
                    max_allowed_hits: Some(
                        selection_policy.max_allowed_false_positives(allowed_matches.len()),
                    ),
                };
            let strict = solve_selected_rule_indexes_with_backend(
                backend,
                candidates,
                denied_matches,
                allowed_matches,
                strict_constraints,
                &[
                    RuleSelectionObjective::AllowedHits,
                    RuleSelectionObjective::KeepCount,
                    RuleSelectionObjective::ComplexityWeight,
                    RuleSelectionObjective::KeepIndexSum,
                ],
            )?;
            if selected_indexes_satisfy_constraints(
                &strict,
                denied_matches,
                allowed_matches,
                strict_constraints,
            ) {
                return Ok((strict, None));
            }

            let relaxed = solve_selected_rule_indexes_with_backend(
                backend,
                candidates,
                denied_matches,
                allowed_matches,
                ExactSelectionConstraints {
                    max_denied_misses: None,
                    max_allowed_hits: strict_constraints.max_allowed_hits,
                },
                &[
                    RuleSelectionObjective::DeniedMisses,
                    RuleSelectionObjective::AllowedHits,
                    RuleSelectionObjective::KeepCount,
                    RuleSelectionObjective::ComplexityWeight,
                    RuleSelectionObjective::KeepIndexSum,
                ],
            )?;
            Ok((
                relaxed,
                Some(format!(
                    "recall target {:.1}% was not feasible under false-positive cap {:.1}%; returned best recall within cap",
                    deny_recall_target * 100.0,
                    max_false_positive_rate * 100.0
                )),
            ))
        }
    }
}

fn solve_selected_rule_indexes_with_backend(
    backend: ExactSelectionBackend,
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    constraints: ExactSelectionConstraints,
    objectives: &[RuleSelectionObjective],
) -> Result<Vec<usize>> {
    match backend {
        ExactSelectionBackend::BruteForce => unreachable!("brute force is handled separately"),
        ExactSelectionBackend::Smt => {
            let (smt, lex_objectives) = build_exact_selection_problem(
                candidates,
                denied_matches,
                allowed_matches,
                constraints,
                objectives,
            );
            solve_selected_rule_indexes(candidates.len(), &smt, &lex_objectives)
        }
        ExactSelectionBackend::Mip => solve_selected_rule_indexes_mip(
            candidates,
            denied_matches,
            allowed_matches,
            constraints,
            objectives,
        ),
    }
}

fn build_exact_selection_problem(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    constraints: ExactSelectionConstraints,
    objectives: &[RuleSelectionObjective],
) -> (String, Vec<LexObjective>) {
    let mut smt = String::new();
    for index in 0..candidates.len() {
        smt.push_str(&format!("(declare-fun keep_{index} () Bool)\n"));
    }

    for (index, matches) in denied_matches.iter().enumerate() {
        smt.push_str(&format!("(declare-fun deny_hit_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= deny_hit_{index} {}))\n",
            match_expression_for(matches)
        ));
    }
    for (index, matches) in allowed_matches.iter().enumerate() {
        smt.push_str(&format!("(declare-fun allow_hit_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= allow_hit_{index} {}))\n",
            match_expression_for(matches)
        ));
    }
    if let Some(max_denied_misses) = constraints.max_denied_misses {
        smt.push_str(&format!(
            "(assert (<= {} {}))\n",
            hit_sum("deny_hit", denied_matches.len(), false),
            max_denied_misses
        ));
    }
    if let Some(max_allowed_hits) = constraints.max_allowed_hits {
        smt.push_str(&format!(
            "(assert (<= {} {}))\n",
            hit_sum("allow_hit", allowed_matches.len(), true),
            max_allowed_hits
        ));
    }

    let objectives = objectives
        .iter()
        .map(|objective| {
            LexObjective::minimize(rule_selection_objective_smt(
                *objective,
                candidates,
                denied_matches.len(),
                allowed_matches.len(),
            ))
        })
        .collect();
    (smt, objectives)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExactSelectionScore {
    denied_misses: usize,
    total_errors: usize,
    allowed_hits: usize,
    rule_count: usize,
    complexity_weight: usize,
    index_weight: usize,
}

struct CandidateMatchMasks {
    denied: Vec<usize>,
    allowed: Vec<usize>,
}

fn select_candidate_rules_bruteforce(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    selection_policy: SelectionPolicy,
) -> (Vec<CandidateRule>, Option<String>) {
    let match_masks = candidate_match_masks(candidates.len(), denied_matches, allowed_matches);
    let upper_bound = 1usize << candidates.len();
    let mut best_mask = 0usize;
    let mut best_score = exact_selection_score(0, candidates, &match_masks);
    let mut found_strict = false;
    let constraints = match selection_policy {
        SelectionPolicy::Balanced => ExactSelectionConstraints::default(),
        SelectionPolicy::RecallBiased { .. } => ExactSelectionConstraints {
            max_denied_misses: Some(
                denied_matches
                    .len()
                    .saturating_sub(selection_policy.required_denied_hits(denied_matches.len())),
            ),
            max_allowed_hits: Some(
                selection_policy.max_allowed_false_positives(allowed_matches.len()),
            ),
        },
    };

    for mask in 0..upper_bound {
        let score = exact_selection_score(mask, candidates, &match_masks);
        match selection_policy {
            SelectionPolicy::Balanced => {
                if score < best_score {
                    best_score = score;
                    best_mask = mask;
                }
            }
            SelectionPolicy::RecallBiased {
                deny_recall_target,
                max_false_positive_rate,
            } => {
                let satisfies = exact_selection_score_satisfies_constraints(score, constraints);
                if satisfies {
                    if !found_strict
                        || compare_exact_selection_score(
                            score,
                            best_score,
                            selection_policy,
                            denied_matches.len(),
                            allowed_matches.len(),
                        ) == std::cmp::Ordering::Less
                    {
                        found_strict = true;
                        best_score = score;
                        best_mask = mask;
                    }
                } else if !found_strict
                    && compare_exact_selection_score(
                        score,
                        best_score,
                        SelectionPolicy::RecallBiased {
                            deny_recall_target,
                            max_false_positive_rate,
                        },
                        denied_matches.len(),
                        allowed_matches.len(),
                    ) == std::cmp::Ordering::Less
                {
                    best_score = score;
                    best_mask = mask;
                }
            }
        }
    }

    let detail = match selection_policy {
        SelectionPolicy::Balanced => None,
        SelectionPolicy::RecallBiased {
            deny_recall_target,
            max_false_positive_rate,
        } if !found_strict => Some(format!(
            "recall target {:.1}% was not feasible under false-positive cap {:.1}%; returned best recall within cap",
            deny_recall_target * 100.0,
            max_false_positive_rate * 100.0
        )),
        SelectionPolicy::RecallBiased { .. } => None,
    };
    (
        candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| {
                ((best_mask & (1usize << index)) != 0).then_some(candidate.clone())
            })
            .collect(),
        detail,
    )
}

fn candidate_match_masks(
    candidate_count: usize,
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> CandidateMatchMasks {
    let to_mask = |matches: &[usize]| {
        matches.iter().fold(0usize, |mask, index| {
            debug_assert!(*index < candidate_count);
            mask | (1usize << index)
        })
    };

    CandidateMatchMasks {
        denied: denied_matches
            .iter()
            .map(|matches| to_mask(matches))
            .collect(),
        allowed: allowed_matches
            .iter()
            .map(|matches| to_mask(matches))
            .collect(),
    }
}

fn exact_selection_score(
    mask: usize,
    candidates: &[CandidateRule],
    match_masks: &CandidateMatchMasks,
) -> ExactSelectionScore {
    let denied_misses = match_masks
        .denied
        .iter()
        .filter(|row_mask| (**row_mask & mask) == 0)
        .count();
    let allowed_hits = match_masks
        .allowed
        .iter()
        .filter(|row_mask| (**row_mask & mask) != 0)
        .count();
    let (rule_count, complexity_weight, index_weight) = candidates
        .iter()
        .enumerate()
        .filter(|(index, _)| (mask & (1usize << index)) != 0)
        .fold(
            (0usize, 0usize, 0usize),
            |(count, complexity, index_sum), (index, candidate)| {
                (
                    count + 1,
                    complexity + candidate_total_penalty(candidate),
                    index_sum + index + 1,
                )
            },
        );

    ExactSelectionScore {
        denied_misses,
        total_errors: denied_misses + allowed_hits,
        allowed_hits,
        rule_count,
        complexity_weight,
        index_weight,
    }
}

fn exact_selection_score_satisfies_constraints(
    score: ExactSelectionScore,
    constraints: ExactSelectionConstraints,
) -> bool {
    constraints
        .max_denied_misses
        .is_none_or(|max_denied_misses| score.denied_misses <= max_denied_misses)
        && constraints
            .max_allowed_hits
            .is_none_or(|max_allowed_hits| score.allowed_hits <= max_allowed_hits)
}

fn compare_exact_selection_score(
    left: ExactSelectionScore,
    right: ExactSelectionScore,
    selection_policy: SelectionPolicy,
    denied_count: usize,
    allowed_count: usize,
) -> std::cmp::Ordering {
    match selection_policy {
        SelectionPolicy::Balanced => left.cmp(&right),
        SelectionPolicy::RecallBiased { .. } => {
            let left_under_cap =
                left.allowed_hits <= selection_policy.max_allowed_false_positives(allowed_count);
            let right_under_cap =
                right.allowed_hits <= selection_policy.max_allowed_false_positives(allowed_count);
            right_under_cap.cmp(&left_under_cap).then_with(|| {
                if left_under_cap && right_under_cap {
                    let left_hits_target = denied_count.saturating_sub(left.denied_misses)
                        >= selection_policy.required_denied_hits(denied_count);
                    let right_hits_target = denied_count.saturating_sub(right.denied_misses)
                        >= selection_policy.required_denied_hits(denied_count);
                    right_hits_target.cmp(&left_hits_target).then_with(|| {
                        if left_hits_target && right_hits_target {
                            left.allowed_hits
                                .cmp(&right.allowed_hits)
                                .then_with(|| left.rule_count.cmp(&right.rule_count))
                                .then_with(|| left.complexity_weight.cmp(&right.complexity_weight))
                                .then_with(|| left.index_weight.cmp(&right.index_weight))
                                .then_with(|| left.denied_misses.cmp(&right.denied_misses))
                        } else {
                            left.denied_misses
                                .cmp(&right.denied_misses)
                                .then_with(|| left.allowed_hits.cmp(&right.allowed_hits))
                                .then_with(|| left.rule_count.cmp(&right.rule_count))
                                .then_with(|| left.complexity_weight.cmp(&right.complexity_weight))
                                .then_with(|| left.index_weight.cmp(&right.index_weight))
                        }
                    })
                } else {
                    left.allowed_hits
                        .cmp(&right.allowed_hits)
                        .then_with(|| left.denied_misses.cmp(&right.denied_misses))
                        .then_with(|| left.rule_count.cmp(&right.rule_count))
                        .then_with(|| left.complexity_weight.cmp(&right.complexity_weight))
                        .then_with(|| left.index_weight.cmp(&right.index_weight))
                }
            })
        }
    }
}

fn match_expression_for(matches: &[usize]) -> String {
    if matches.is_empty() {
        return "false".to_string();
    }
    if matches.len() == 1 {
        return format!("keep_{}", matches[0]);
    }
    format!(
        "(or {})",
        matches
            .iter()
            .map(|index| format!("keep_{index}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn hit_sum(prefix: &str, count: usize, when_true: bool) -> String {
    solver_sum(
        (0..count)
            .map(|index| {
                if when_true {
                    format!("(ite {prefix}_{index} 1 0)")
                } else {
                    format!("(ite {prefix}_{index} 0 1)")
                }
            })
            .collect(),
    )
}

fn keep_sum(count: usize) -> String {
    solver_sum(
        (0..count)
            .map(|index| format!("(ite keep_{index} 1 0)"))
            .collect(),
    )
}

fn keep_index_sum(count: usize) -> String {
    solver_sum(
        (0..count)
            .map(|index| format!("(ite keep_{index} {} 0)", index + 1))
            .collect(),
    )
}

fn weighted_keep_sum(candidates: &[CandidateRule]) -> String {
    solver_sum(
        candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                format!(
                    "(ite keep_{index} {} 0)",
                    candidate_total_penalty(candidate)
                )
            })
            .collect(),
    )
}

fn solver_sum(terms: Vec<String>) -> String {
    match terms.len() {
        0 => "0".to_string(),
        1 => terms.into_iter().next().expect("single term should exist"),
        _ => format!("(+ {})", terms.join(" ")),
    }
}

fn solve_selected_rule_indexes(
    candidate_count: usize,
    preamble: &str,
    objectives: &[LexObjective],
) -> Result<Vec<usize>> {
    let solver_settings = SolverSettings::from_env()?;
    let result = solve_keep_bools_lexicographic(
        preamble,
        objectives,
        "keep",
        candidate_count,
        &solver_settings,
    )
    .map_err(|err| {
        LogicPearlError::message(format!("exact rule selection solver failed: {err}"))
    })?;
    match result.status {
        SatStatus::Sat => Ok(result.selected),
        SatStatus::Unsat => Ok(Vec::new()),
        SatStatus::Unknown => Err(LogicPearlError::message(format!(
            "{} returned unknown while solving exact rule selection",
            result.report.backend_used.as_str()
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSelectionObjective {
    DeniedMisses,
    TotalErrors,
    AllowedHits,
    KeepCount,
    ComplexityWeight,
    KeepIndexSum,
}

fn rule_selection_objective_smt(
    objective: RuleSelectionObjective,
    candidates: &[CandidateRule],
    denied_count: usize,
    allowed_count: usize,
) -> String {
    match objective {
        RuleSelectionObjective::DeniedMisses => hit_sum("deny_hit", denied_count, false),
        RuleSelectionObjective::TotalErrors => format!(
            "(+ {} {})",
            hit_sum("deny_hit", denied_count, false),
            hit_sum("allow_hit", allowed_count, true)
        ),
        RuleSelectionObjective::AllowedHits => hit_sum("allow_hit", allowed_count, true),
        RuleSelectionObjective::KeepCount => keep_sum(candidates.len()),
        RuleSelectionObjective::ComplexityWeight => weighted_keep_sum(candidates),
        RuleSelectionObjective::KeepIndexSum => keep_index_sum(candidates.len()),
    }
}

fn solve_selected_rule_indexes_mip(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    constraints: ExactSelectionConstraints,
    objectives: &[RuleSelectionObjective],
) -> Result<Vec<usize>> {
    let mut locked = Vec::new();
    let mut selected = Vec::new();
    for objective in objectives {
        let stage = solve_selected_rule_indexes_mip_stage(
            candidates,
            denied_matches,
            allowed_matches,
            *objective,
            constraints,
            &locked,
        )?;
        let objective_value = rule_selection_objective_value(
            *objective,
            &stage,
            candidates,
            denied_matches,
            allowed_matches,
        );
        selected = stage;
        locked.push((*objective, objective_value));
    }
    Ok(selected)
}

fn solve_selected_rule_indexes_mip_stage(
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    objective: RuleSelectionObjective,
    constraints: ExactSelectionConstraints,
    locked: &[(RuleSelectionObjective, usize)],
) -> Result<Vec<usize>> {
    let mut vars = variables!();
    let keep_vars: Vec<Variable> = (0..candidates.len())
        .map(|_| vars.add(variable().binary()))
        .collect();
    let deny_hit_vars: Vec<Variable> = denied_matches
        .iter()
        .map(|_| vars.add(variable().binary()))
        .collect();
    let allow_hit_vars: Vec<Variable> = allowed_matches
        .iter()
        .map(|_| vars.add(variable().binary()))
        .collect();

    let mut model = vars
        .minimise(rule_selection_objective_expression(
            objective,
            &keep_vars,
            &deny_hit_vars,
            &allow_hit_vars,
            candidates,
            denied_matches.len(),
        ))
        .using(microlp);
    model = add_rule_selection_constraints(
        model,
        &keep_vars,
        &deny_hit_vars,
        &allow_hit_vars,
        denied_matches,
        allowed_matches,
        constraints,
    );

    for (locked_objective, value) in locked {
        model = model.with(constraint!(
            rule_selection_objective_expression(
                *locked_objective,
                &keep_vars,
                &deny_hit_vars,
                &allow_hit_vars,
                candidates,
                denied_matches.len(),
            ) == *value as f64
        ));
    }

    let solution = match model.solve() {
        Ok(solution) => solution,
        Err(ResolutionError::Infeasible) => return Ok(Vec::new()),
        Err(ResolutionError::Unbounded) => {
            return Err(LogicPearlError::message(
                "discovery exact rule selection MIP solve was unexpectedly unbounded",
            ));
        }
        Err(err) => {
            return Err(LogicPearlError::message(format!(
                "exact rule selection MIP solver failed: {err}"
            )));
        }
    };

    Ok(selected_keep_indexes(&solution, &keep_vars))
}

fn add_rule_selection_constraints<M: SolverModel>(
    mut model: M,
    keep_vars: &[Variable],
    deny_hit_vars: &[Variable],
    allow_hit_vars: &[Variable],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    constraints: ExactSelectionConstraints,
) -> M {
    for (index, matches) in denied_matches.iter().enumerate() {
        model = add_match_indicator_constraints(model, deny_hit_vars[index], keep_vars, matches);
    }
    for (index, matches) in allowed_matches.iter().enumerate() {
        model = add_match_indicator_constraints(model, allow_hit_vars[index], keep_vars, matches);
    }
    if let Some(max_denied_misses) = constraints.max_denied_misses {
        model = model.with(constraint!(
            (denied_matches.len() as f64) - sum_vars(deny_hit_vars) <= max_denied_misses as f64
        ));
    }
    if let Some(max_allowed_hits) = constraints.max_allowed_hits {
        model = model.with(constraint!(
            sum_vars(allow_hit_vars) <= max_allowed_hits as f64
        ));
    }
    model
}

fn add_match_indicator_constraints<M: SolverModel>(
    mut model: M,
    indicator: Variable,
    keep_vars: &[Variable],
    matches: &[usize],
) -> M {
    if matches.is_empty() {
        return model.with(constraint!(indicator == 0.0));
    }

    model = model.with(constraint!(indicator <= sum_keep_vars(keep_vars, matches)));
    for matched in matches {
        model = model.with(constraint!(indicator >= keep_vars[*matched]));
    }
    model
}

fn rule_selection_objective_expression(
    objective: RuleSelectionObjective,
    keep_vars: &[Variable],
    deny_hit_vars: &[Variable],
    allow_hit_vars: &[Variable],
    candidates: &[CandidateRule],
    denied_count: usize,
) -> LpExpression {
    match objective {
        RuleSelectionObjective::DeniedMisses => (denied_count as f64) - sum_vars(deny_hit_vars),
        RuleSelectionObjective::TotalErrors => {
            (denied_count as f64) - sum_vars(deny_hit_vars) + sum_vars(allow_hit_vars)
        }
        RuleSelectionObjective::AllowedHits => sum_vars(allow_hit_vars),
        RuleSelectionObjective::KeepCount => sum_vars(keep_vars),
        RuleSelectionObjective::ComplexityWeight => keep_vars.iter().zip(candidates.iter()).fold(
            LpExpression::from(0.0),
            |expression, (variable, candidate)| {
                expression + (candidate_total_penalty(candidate) as f64) * *variable
            },
        ),
        RuleSelectionObjective::KeepIndexSum => keep_vars
            .iter()
            .enumerate()
            .fold(LpExpression::from(0.0), |expression, (index, variable)| {
                expression + ((index + 1) as f64) * *variable
            }),
    }
}

fn rule_selection_objective_value(
    objective: RuleSelectionObjective,
    selected: &[usize],
    candidates: &[CandidateRule],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
) -> usize {
    match objective {
        RuleSelectionObjective::DeniedMisses => denied_matches
            .iter()
            .filter(|matches| !matches.iter().any(|index| selected.contains(index)))
            .count(),
        RuleSelectionObjective::TotalErrors => {
            let denied_misses = denied_matches
                .iter()
                .filter(|matches| !matches.iter().any(|index| selected.contains(index)))
                .count();
            let allowed_hits = allowed_matches
                .iter()
                .filter(|matches| matches.iter().any(|index| selected.contains(index)))
                .count();
            denied_misses + allowed_hits
        }
        RuleSelectionObjective::AllowedHits => allowed_matches
            .iter()
            .filter(|matches| matches.iter().any(|index| selected.contains(index)))
            .count(),
        RuleSelectionObjective::KeepCount => selected.len(),
        RuleSelectionObjective::ComplexityWeight => selected
            .iter()
            .map(|index| candidate_total_penalty(&candidates[*index]))
            .sum(),
        RuleSelectionObjective::KeepIndexSum => selected.iter().map(|index| index + 1).sum(),
    }
}

fn selected_indexes_satisfy_constraints(
    selected: &[usize],
    denied_matches: &[Vec<usize>],
    allowed_matches: &[Vec<usize>],
    constraints: ExactSelectionConstraints,
) -> bool {
    constraints
        .max_denied_misses
        .is_none_or(|max_denied_misses| {
            rule_selection_objective_value(
                RuleSelectionObjective::DeniedMisses,
                selected,
                &[],
                denied_matches,
                allowed_matches,
            ) <= max_denied_misses
        })
        && constraints.max_allowed_hits.is_none_or(|max_allowed_hits| {
            rule_selection_objective_value(
                RuleSelectionObjective::AllowedHits,
                selected,
                &[],
                denied_matches,
                allowed_matches,
            ) <= max_allowed_hits
        })
}

fn sum_keep_vars(keep_vars: &[Variable], matches: &[usize]) -> LpExpression {
    matches
        .iter()
        .fold(LpExpression::from(0.0), |expression, matched| {
            expression + keep_vars[*matched]
        })
}

fn sum_vars(vars: &[Variable]) -> LpExpression {
    vars.iter()
        .fold(LpExpression::from(0.0), |expression, variable| {
            expression + *variable
        })
}

fn selected_keep_indexes<S: Solution>(solution: &S, keep_vars: &[Variable]) -> Vec<usize> {
    keep_vars
        .iter()
        .enumerate()
        .filter_map(|(index, variable)| (solution.value(*variable) >= 0.5).then_some(index))
        .collect()
}
