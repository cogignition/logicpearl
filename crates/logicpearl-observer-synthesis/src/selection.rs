// SPDX-License-Identifier: MIT
use good_lp::{
    constraint, microlp, variable, variables, Expression, ResolutionError, Solution, SolverModel,
    Variable,
};
use logicpearl_core::{LogicPearlError, Result};
use logicpearl_solver::{
    keep_bool_index_sum, solve_keep_bools_lexicographic, solver_sum, LexObjective, SatStatus,
    SolverBackend, SolverSettings,
};
use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObserverSelectionBackend {
    Smt,
    Mip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhraseSelectionMode {
    PreferCoverage,
    RequireCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhraseSelectionBackend {
    Solver(SolverBackend),
    Mip,
}

impl PhraseSelectionBackend {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Solver(backend) => backend.as_str(),
            Self::Mip => "mip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhraseSelectionStatus {
    Sat,
    Unsat,
    Unknown,
    Optimal,
    Infeasible,
}

impl PhraseSelectionStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sat => "sat",
            Self::Unsat => "unsat",
            Self::Unknown => "unknown",
            Self::Optimal => "optimal",
            Self::Infeasible => "infeasible",
        }
    }

    pub(crate) fn is_success(self) -> bool {
        matches!(self, Self::Sat | Self::Optimal)
    }
}

#[derive(Debug)]
pub(crate) struct PhraseSelectionOutcome {
    pub(crate) selected: Vec<usize>,
    pub(crate) backend_used: PhraseSelectionBackend,
    pub(crate) status: PhraseSelectionStatus,
}

struct ObserverSelectionSettings {
    backend: ObserverSelectionBackend,
}

impl ObserverSelectionSettings {
    fn from_env() -> Result<Self> {
        let backend = env::var(OBSERVER_SELECTION_BACKEND_ENV)
            .ok()
            .map(|raw| parse_observer_selection_backend(&raw))
            .transpose()?
            .unwrap_or(ObserverSelectionBackend::Mip);
        Ok(Self { backend })
    }
}

const OBSERVER_SELECTION_BACKEND_ENV: &str = "LOGICPEARL_OBSERVER_SELECTION_BACKEND";

#[cfg(test)]
pub(crate) fn with_selection_backend_for_test<T>(backend: &str, test: impl FnOnce() -> T) -> T {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("env lock should be available");
    let saved = env::var(OBSERVER_SELECTION_BACKEND_ENV).ok();
    env::set_var(OBSERVER_SELECTION_BACKEND_ENV, backend);
    let result = test();
    match saved {
        Some(value) => env::set_var(OBSERVER_SELECTION_BACKEND_ENV, value),
        None => env::remove_var(OBSERVER_SELECTION_BACKEND_ENV),
    }
    result
}

fn parse_observer_selection_backend(raw: &str) -> Result<ObserverSelectionBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "smt" => Ok(ObserverSelectionBackend::Smt),
        "mip" => Ok(ObserverSelectionBackend::Mip),
        other => Err(LogicPearlError::message(format!(
            "unsupported observer selection backend `{other}` in {OBSERVER_SELECTION_BACKEND_ENV}; expected `smt` or `mip`"
        ))),
    }
}

pub fn count_phrase_hits(constraints: &[Vec<usize>]) -> usize {
    constraints.len()
}

pub fn count_selected_hits(selected: &[usize], constraints: &[Vec<usize>]) -> usize {
    constraints
        .iter()
        .filter(|matched| matched.iter().any(|index| selected.contains(index)))
        .count()
}

pub(crate) fn select_phrase_subset(
    phrases: &[String],
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
    mode: PhraseSelectionMode,
) -> Result<PhraseSelectionOutcome> {
    let selection_settings = ObserverSelectionSettings::from_env()?;
    match selection_settings.backend {
        ObserverSelectionBackend::Mip => mip_select_phrase_subset(
            phrases.len(),
            positive_constraints,
            negative_constraints,
            mode,
        ),
        ObserverSelectionBackend::Smt => smt_select_phrase_subset(
            phrases.len(),
            positive_constraints,
            negative_constraints,
            mode,
        ),
    }
}

fn smt_select_phrase_subset(
    phrase_count: usize,
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
    mode: PhraseSelectionMode,
) -> Result<PhraseSelectionOutcome> {
    match mode {
        PhraseSelectionMode::PreferCoverage => smt_select_with_preferred_coverage(
            phrase_count,
            positive_constraints,
            negative_constraints,
        ),
        PhraseSelectionMode::RequireCoverage => smt_select_with_required_coverage(
            phrase_count,
            positive_constraints,
            negative_constraints,
        ),
    }
}

fn smt_select_with_preferred_coverage(
    phrase_count: usize,
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
) -> Result<PhraseSelectionOutcome> {
    let mut smt = String::new();
    for index in 0..phrase_count {
        smt.push_str(&format!("(declare-fun keep_{index} () Bool)\n"));
    }
    for (index, matches) in positive_constraints.iter().enumerate() {
        smt.push_str(&format!("(declare-fun pos_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= pos_{index} {}))\n",
            solver_or(matches)
        ));
    }
    for (index, matches) in negative_constraints.iter().enumerate() {
        smt.push_str(&format!("(declare-fun neg_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= neg_{index} {}))\n",
            solver_or(matches)
        ));
    }
    let missed_terms = if positive_constraints.is_empty() {
        "0".to_string()
    } else {
        solver_sum(
            positive_constraints
                .iter()
                .enumerate()
                .map(|(index, _)| format!("(ite pos_{index} 0 1)")),
        )
    };
    let negative_terms = if negative_constraints.is_empty() {
        "0".to_string()
    } else {
        solver_sum(
            negative_constraints
                .iter()
                .enumerate()
                .map(|(index, _)| format!("(ite neg_{index} 1 0)")),
        )
    };
    let keep_terms = if phrase_count == 0 {
        "0".to_string()
    } else {
        solver_sum((0..phrase_count).map(|index| format!("(ite keep_{index} 1 0)")))
    };
    let objectives = vec![
        LexObjective::minimize(missed_terms),
        LexObjective::minimize(negative_terms),
        LexObjective::minimize(keep_terms),
        LexObjective::minimize(keep_bool_index_sum("keep", phrase_count)),
    ];
    smt_select_phrase_indexes(phrase_count, &smt, &objectives)
}

fn smt_select_with_required_coverage(
    phrase_count: usize,
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
) -> Result<PhraseSelectionOutcome> {
    let mut smt = String::new();
    for index in 0..phrase_count {
        smt.push_str(&format!("(declare-fun keep_{index} () Bool)\n"));
    }
    for matches in positive_constraints {
        smt.push_str(&format!("(assert {})\n", solver_or(matches)));
    }
    for (index, matches) in negative_constraints.iter().enumerate() {
        smt.push_str(&format!("(declare-fun neg_{index} () Bool)\n"));
        smt.push_str(&format!(
            "(assert (= neg_{index} {}))\n",
            solver_or(matches)
        ));
    }
    let negative_terms = if negative_constraints.is_empty() {
        "0".to_string()
    } else {
        solver_sum(
            negative_constraints
                .iter()
                .enumerate()
                .map(|(index, _)| format!("(ite neg_{index} 1 0)")),
        )
    };
    let keep_terms = if phrase_count == 0 {
        "0".to_string()
    } else {
        solver_sum((0..phrase_count).map(|index| format!("(ite keep_{index} 1 0)")))
    };
    let objectives = vec![
        LexObjective::minimize(negative_terms),
        LexObjective::minimize(keep_terms),
        LexObjective::minimize(keep_bool_index_sum("keep", phrase_count)),
    ];
    smt_select_phrase_indexes(phrase_count, &smt, &objectives)
}

fn smt_select_phrase_indexes(
    phrase_count: usize,
    preamble: &str,
    objectives: &[LexObjective],
) -> Result<PhraseSelectionOutcome> {
    let solver_settings = SolverSettings::from_env()?;
    let result = solve_keep_bools_lexicographic(
        preamble,
        objectives,
        "keep",
        phrase_count,
        &solver_settings,
    )
    .map_err(|err| {
        LogicPearlError::message(format!("observer phrase subset solver failed: {err}"))
    })?;
    Ok(PhraseSelectionOutcome {
        selected: result.selected,
        backend_used: PhraseSelectionBackend::Solver(result.report.backend_used),
        status: phrase_selection_status_from_sat(result.status),
    })
}

fn solver_or(indices: &[usize]) -> String {
    if indices.is_empty() {
        "false".to_string()
    } else if indices.len() == 1 {
        format!("keep_{}", indices[0])
    } else {
        format!(
            "(or {})",
            indices
                .iter()
                .map(|index| format!("keep_{index}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

fn phrase_selection_status_from_sat(status: SatStatus) -> PhraseSelectionStatus {
    match status {
        SatStatus::Sat => PhraseSelectionStatus::Sat,
        SatStatus::Unsat => PhraseSelectionStatus::Unsat,
        SatStatus::Unknown => PhraseSelectionStatus::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhraseSelectionObjective {
    MissedPositives,
    NegativeMatches,
    KeepCount,
    KeepIndexSum,
}

fn mip_select_phrase_subset(
    phrase_count: usize,
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
    mode: PhraseSelectionMode,
) -> Result<PhraseSelectionOutcome> {
    let (require_positive_coverage, objectives): (bool, &[PhraseSelectionObjective]) = match mode {
        PhraseSelectionMode::PreferCoverage => (
            false,
            &[
                PhraseSelectionObjective::MissedPositives,
                PhraseSelectionObjective::NegativeMatches,
                PhraseSelectionObjective::KeepCount,
                PhraseSelectionObjective::KeepIndexSum,
            ],
        ),
        PhraseSelectionMode::RequireCoverage => (
            true,
            &[
                PhraseSelectionObjective::NegativeMatches,
                PhraseSelectionObjective::KeepCount,
                PhraseSelectionObjective::KeepIndexSum,
            ],
        ),
    };
    mip_select_phrase_subset_internal(
        phrase_count,
        positive_constraints,
        negative_constraints,
        require_positive_coverage,
        objectives,
    )
}

fn mip_select_phrase_subset_internal(
    phrase_count: usize,
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
    require_positive_coverage: bool,
    objectives: &[PhraseSelectionObjective],
) -> Result<PhraseSelectionOutcome> {
    if require_positive_coverage
        && positive_constraints
            .iter()
            .any(|matched| matched.is_empty())
    {
        return Ok(PhraseSelectionOutcome {
            selected: Vec::new(),
            backend_used: PhraseSelectionBackend::Mip,
            status: PhraseSelectionStatus::Infeasible,
        });
    }

    let mut locked = Vec::new();
    let mut selected = Vec::new();
    for objective in objectives {
        let stage = mip_select_phrase_subset_stage(
            phrase_count,
            positive_constraints,
            negative_constraints,
            require_positive_coverage,
            *objective,
            &locked,
        )?;
        if stage.status != PhraseSelectionStatus::Optimal {
            return Ok(stage);
        }
        let objective_value = objective_value(
            *objective,
            &stage.selected,
            positive_constraints,
            negative_constraints,
        );
        selected = stage.selected;
        locked.push((*objective, objective_value));
    }

    Ok(PhraseSelectionOutcome {
        selected,
        backend_used: PhraseSelectionBackend::Mip,
        status: PhraseSelectionStatus::Optimal,
    })
}

fn mip_select_phrase_subset_stage(
    phrase_count: usize,
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
    require_positive_coverage: bool,
    objective: PhraseSelectionObjective,
    locked: &[(PhraseSelectionObjective, usize)],
) -> Result<PhraseSelectionOutcome> {
    let mut vars = variables!();
    let keep_vars: Vec<Variable> = (0..phrase_count)
        .map(|_| vars.add(variable().binary()))
        .collect();
    let pos_vars: Vec<Variable> = if require_positive_coverage {
        Vec::new()
    } else {
        positive_constraints
            .iter()
            .map(|_| vars.add(variable().binary()))
            .collect()
    };
    let neg_vars: Vec<Variable> = negative_constraints
        .iter()
        .map(|_| vars.add(variable().binary()))
        .collect();

    let mut model = vars
        .minimise(objective_expression(
            objective,
            &keep_vars,
            &pos_vars,
            &neg_vars,
            positive_constraints.len(),
        ))
        .using(microlp);
    model = add_base_phrase_selection_constraints(
        model,
        &keep_vars,
        &pos_vars,
        &neg_vars,
        positive_constraints,
        negative_constraints,
        require_positive_coverage,
    );

    for (locked_objective, value) in locked {
        model = model.with(constraint!(
            objective_expression(
                *locked_objective,
                &keep_vars,
                &pos_vars,
                &neg_vars,
                positive_constraints.len(),
            ) == *value as f64
        ));
    }

    let solution = match model.solve() {
        Ok(solution) => solution,
        Err(ResolutionError::Infeasible) => {
            return Ok(PhraseSelectionOutcome {
                selected: Vec::new(),
                backend_used: PhraseSelectionBackend::Mip,
                status: PhraseSelectionStatus::Infeasible,
            });
        }
        Err(ResolutionError::Unbounded) => {
            return Err(LogicPearlError::message(
                "observer phrase subset MIP solve was unexpectedly unbounded",
            ));
        }
        Err(err) => {
            return Err(LogicPearlError::message(format!(
                "observer phrase subset MIP solve failed: {err}"
            )));
        }
    };

    Ok(PhraseSelectionOutcome {
        selected: selected_keep_indexes(&solution, &keep_vars),
        backend_used: PhraseSelectionBackend::Mip,
        status: PhraseSelectionStatus::Optimal,
    })
}

fn add_base_phrase_selection_constraints<M: SolverModel>(
    mut model: M,
    keep_vars: &[Variable],
    pos_vars: &[Variable],
    neg_vars: &[Variable],
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
    require_positive_coverage: bool,
) -> M {
    for (index, matches) in positive_constraints.iter().enumerate() {
        if require_positive_coverage {
            model = model.with(constraint!(sum_keep_vars(keep_vars, matches) >= 1.0));
        } else {
            model = add_match_indicator_constraints(model, pos_vars[index], keep_vars, matches);
        }
    }
    for (index, matches) in negative_constraints.iter().enumerate() {
        model = add_match_indicator_constraints(model, neg_vars[index], keep_vars, matches);
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

fn objective_expression(
    objective: PhraseSelectionObjective,
    keep_vars: &[Variable],
    pos_vars: &[Variable],
    neg_vars: &[Variable],
    positive_constraint_count: usize,
) -> Expression {
    match objective {
        PhraseSelectionObjective::MissedPositives => {
            (positive_constraint_count as f64) - sum_vars(pos_vars)
        }
        PhraseSelectionObjective::NegativeMatches => sum_vars(neg_vars),
        PhraseSelectionObjective::KeepCount => sum_vars(keep_vars),
        PhraseSelectionObjective::KeepIndexSum => keep_vars
            .iter()
            .enumerate()
            .fold(Expression::from(0.0), |expression, (index, variable)| {
                expression + ((index + 1) as f64) * *variable
            }),
    }
}

fn objective_value(
    objective: PhraseSelectionObjective,
    selected: &[usize],
    positive_constraints: &[Vec<usize>],
    negative_constraints: &[Vec<usize>],
) -> usize {
    match objective {
        PhraseSelectionObjective::MissedPositives => {
            positive_constraints.len() - count_selected_hits(selected, positive_constraints)
        }
        PhraseSelectionObjective::NegativeMatches => {
            count_selected_hits(selected, negative_constraints)
        }
        PhraseSelectionObjective::KeepCount => selected.len(),
        PhraseSelectionObjective::KeepIndexSum => selected.iter().map(|index| index + 1).sum(),
    }
}

fn sum_keep_vars(keep_vars: &[Variable], matches: &[usize]) -> Expression {
    matches
        .iter()
        .fold(Expression::from(0.0), |expression, matched| {
            expression + keep_vars[*matched]
        })
}

fn sum_vars(vars: &[Variable]) -> Expression {
    vars.iter()
        .fold(Expression::from(0.0), |expression, variable| {
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
