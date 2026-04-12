// SPDX-License-Identifier: MIT
mod backend;
mod parse;

pub use backend::{
    is_backend_available, resolve_backend, SolverBackend, SolverMode, SolverSettings,
    SOLVER_BACKEND_ENV, SOLVER_DIR_ENV, SOLVER_TIMEOUT_MS_ENV,
};
pub use parse::{parse_sat_status, parse_selected_bool_indexes, parse_value_bindings};

use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use tempfile::NamedTempFile;

/// Satisfiability status returned by an SMT solver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SatStatus {
    Sat,
    Unsat,
    Unknown,
}

/// Diagnostic report from a single solver invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverRunReport {
    pub backend_used: SolverBackend,
    pub status: SatStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
}

/// Result of a satisfiability check, including the solver run report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatResult {
    pub status: SatStatus,
    pub report: SolverRunReport,
}

/// Result of a satisfiability check that also extracts variable bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueResult {
    pub status: SatStatus,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_values: Option<String>,
    pub report: SolverRunReport,
}

/// Result of a boolean-selection solve, listing which boolean variables are true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoolSelectionResult {
    pub status: SatStatus,
    #[serde(default)]
    pub selected: Vec<usize>,
    pub report: SolverRunReport,
}

/// Whether to minimize or maximize an objective expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveDirection {
    Minimize,
    Maximize,
}

/// A single objective in a lexicographic optimization sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexObjective {
    pub direction: ObjectiveDirection,
    pub expr: String,
}

impl LexObjective {
    pub fn minimize(expr: impl Into<String>) -> Self {
        Self {
            direction: ObjectiveDirection::Minimize,
            expr: expr.into(),
        }
    }

    pub fn maximize(expr: impl Into<String>) -> Self {
        Self {
            direction: ObjectiveDirection::Maximize,
            expr: expr.into(),
        }
    }
}

/// Run an SMT script and return whether the formula is satisfiable.
pub fn check_sat(script: &str, settings: &SolverSettings) -> Result<SatResult> {
    let output = run_solver_script(script, settings, false)?;
    Ok(SatResult {
        status: output.status,
        report: output.report(),
    })
}

/// Run an SMT script and extract variable bindings when satisfiable.
pub fn check_sat_with_values(script: &str, settings: &SolverSettings) -> Result<ValueResult> {
    let output = run_solver_script(script, settings, true)?;
    let raw_values = stdout_tail(&output.stdout);
    let values = if output.status == SatStatus::Sat {
        parse_value_bindings(&output.stdout)?
    } else {
        BTreeMap::new()
    };
    Ok(ValueResult {
        status: output.status,
        values,
        raw_values,
        report: output.report(),
    })
}

/// Solve and return which boolean variables with the given prefix are true.
pub fn solve_keep_bools(
    script: &str,
    keep_prefix: &str,
    keep_count: usize,
    settings: &SolverSettings,
) -> Result<BoolSelectionResult> {
    let backend_used = backend::resolve_backend(settings)?;
    solve_keep_bools_with_backend(
        script,
        keep_prefix,
        keep_count,
        backend_used,
        settings.timeout_ms,
    )
}

/// Solve with lexicographic objectives and return selected boolean variables.
pub fn solve_keep_bools_lexicographic(
    preamble: &str,
    objectives: &[LexObjective],
    keep_prefix: &str,
    keep_count: usize,
    settings: &SolverSettings,
) -> Result<BoolSelectionResult> {
    let backend_used = backend::resolve_backend(settings)?;
    match backend_used {
        SolverBackend::Z3 => {
            let script = build_z3_optimization_script(preamble, objectives);
            solve_keep_bools_with_backend(
                &script,
                keep_prefix,
                keep_count,
                backend_used,
                settings.timeout_ms,
            )
        }
        SolverBackend::Cvc5 => solve_keep_bools_lexicographic_with_cvc5(
            preamble,
            objectives,
            keep_prefix,
            keep_count,
            settings.timeout_ms,
        ),
    }
}

struct RawSolverOutput {
    backend_used: SolverBackend,
    status: SatStatus,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

impl RawSolverOutput {
    fn report(&self) -> SolverRunReport {
        SolverRunReport {
            backend_used: self.backend_used,
            status: self.status,
            exit_code: self.exit_code,
            stderr: self.stderr.clone(),
        }
    }
}

fn run_solver_script(
    script: &str,
    settings: &SolverSettings,
    needs_model: bool,
) -> Result<RawSolverOutput> {
    let backend_used = backend::resolve_backend(settings)?;
    run_solver_script_with_backend(script, backend_used, settings.timeout_ms, needs_model)
}

fn solve_keep_bools_with_backend(
    script: &str,
    keep_prefix: &str,
    keep_count: usize,
    backend_used: SolverBackend,
    timeout_ms: Option<u64>,
) -> Result<BoolSelectionResult> {
    let output = run_solver_script_with_backend(script, backend_used, timeout_ms, true)?;
    let selected = if output.status == SatStatus::Sat {
        parse_selected_bool_indexes(&output.stdout, keep_prefix, keep_count)
    } else {
        Vec::new()
    };
    Ok(BoolSelectionResult {
        status: output.status,
        selected,
        report: output.report(),
    })
}

fn check_sat_with_values_on_backend(
    script: &str,
    backend_used: SolverBackend,
    timeout_ms: Option<u64>,
) -> Result<ValueResult> {
    let output = run_solver_script_with_backend(script, backend_used, timeout_ms, true)?;
    let raw_values = stdout_tail(&output.stdout);
    let values = if output.status == SatStatus::Sat {
        parse_value_bindings(&output.stdout)?
    } else {
        BTreeMap::new()
    };
    Ok(ValueResult {
        status: output.status,
        values,
        raw_values,
        report: output.report(),
    })
}

fn run_solver_script_with_backend(
    script: &str,
    backend_used: SolverBackend,
    timeout_ms: Option<u64>,
    needs_model: bool,
) -> Result<RawSolverOutput> {
    let normalized_script = normalize_script_for_backend(script, backend_used);
    let mut temp_script = NamedTempFile::with_suffix(".smt2").map_err(|err| {
        LogicPearlError::message(format!("failed to create temp solver script: {err}"))
    })?;
    temp_script
        .write_all(normalized_script.as_bytes())
        .map_err(|err| {
            LogicPearlError::message(format!("failed to write temp solver script: {err}"))
        })?;
    let script_path = temp_script.path();

    let output = backend::command_for_backend(backend_used, script_path, timeout_ms, needs_model)
        .output()
        .map_err(|err| {
            LogicPearlError::message(format!("failed to launch {}: {err}", backend_used.as_str()))
        })?;

    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        LogicPearlError::message(format!("solver stdout was not valid UTF-8: {err}"))
    })?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let status = parse_sat_status(&stdout)?;
    if !output.status.success() && status != SatStatus::Unsat {
        return Err(LogicPearlError::message(format!(
            "{} failed with exit code {:?}: stderr=`{}` stdout=`{}`",
            backend_used.as_str(),
            output.status.code(),
            stderr,
            stdout.trim()
        )));
    }

    Ok(RawSolverOutput {
        backend_used,
        status,
        stdout,
        stderr,
        exit_code: output.status.code(),
    })
}

fn normalize_script_for_backend(script: &str, backend_used: SolverBackend) -> String {
    if backend_used == SolverBackend::Cvc5 && !script.contains("(set-logic") {
        format!("(set-logic ALL)\n{script}")
    } else {
        script.to_string()
    }
}

fn build_z3_optimization_script(preamble: &str, objectives: &[LexObjective]) -> String {
    let mut script = String::from("(set-option :opt.priority lex)\n");
    push_script_block(&mut script, preamble);
    for objective in objectives {
        match objective.direction {
            ObjectiveDirection::Minimize => {
                script.push_str(&format!("(minimize {})\n", objective.expr));
            }
            ObjectiveDirection::Maximize => {
                script.push_str(&format!("(maximize {})\n", objective.expr));
            }
        }
    }
    script.push_str("(check-sat)\n(get-model)\n");
    script
}

fn solve_keep_bools_lexicographic_with_cvc5(
    preamble: &str,
    objectives: &[LexObjective],
    keep_prefix: &str,
    keep_count: usize,
    timeout_ms: Option<u64>,
) -> Result<BoolSelectionResult> {
    let objective_symbols = objectives
        .iter()
        .enumerate()
        .map(|(index, _)| objective_symbol(index))
        .collect::<Vec<_>>();
    let mut base_script = String::new();
    push_script_block(&mut base_script, preamble);
    for (index, objective) in objectives.iter().enumerate() {
        let symbol = objective_symbols[index].clone();
        base_script.push_str(&format!("(declare-fun {symbol} () Int)\n"));
        base_script.push_str(&format!("(assert (= {symbol} {}))\n", objective.expr));
    }

    let mut fixed_assertions = Vec::new();
    for (index, objective) in objectives.iter().enumerate() {
        let symbol = &objective_symbols[index];
        let mut current_best =
            current_objective_value(&base_script, &fixed_assertions, symbol, timeout_ms)?;
        loop {
            let improvement = match objective.direction {
                ObjectiveDirection::Minimize => format!("(< {symbol} {current_best})"),
                ObjectiveDirection::Maximize => format!("(> {symbol} {current_best})"),
            };
            match current_objective_value_with_extra(
                &base_script,
                &fixed_assertions,
                &improvement,
                symbol,
                timeout_ms,
            )? {
                Some(candidate) => current_best = candidate,
                None => {
                    fixed_assertions.push(format!("(= {symbol} {current_best})"));
                    break;
                }
            }
        }
    }

    let final_script = build_model_query_script(&base_script, &fixed_assertions);
    solve_keep_bools_with_backend(
        &final_script,
        keep_prefix,
        keep_count,
        SolverBackend::Cvc5,
        timeout_ms,
    )
}

fn current_objective_value(
    base_script: &str,
    fixed_assertions: &[String],
    symbol: &str,
    timeout_ms: Option<u64>,
) -> Result<i64> {
    let query = build_value_query_script(base_script, fixed_assertions, &[symbol.to_string()]);
    let result = check_sat_with_values_on_backend(&query, SolverBackend::Cvc5, timeout_ms)?;
    match result.status {
        SatStatus::Sat => parse_objective_value(&result.values, symbol),
        SatStatus::Unsat => Err(LogicPearlError::message(format!(
            "cvc5 reported unsat while evaluating objective {symbol}"
        ))),
        SatStatus::Unknown => Err(LogicPearlError::message(format!(
            "cvc5 returned unknown while evaluating objective {symbol}"
        ))),
    }
}

fn current_objective_value_with_extra(
    base_script: &str,
    fixed_assertions: &[String],
    extra_assertion: &str,
    symbol: &str,
    timeout_ms: Option<u64>,
) -> Result<Option<i64>> {
    let mut assertions = fixed_assertions.to_vec();
    assertions.push(extra_assertion.to_string());
    let query = build_value_query_script(base_script, &assertions, &[symbol.to_string()]);
    let result = check_sat_with_values_on_backend(&query, SolverBackend::Cvc5, timeout_ms)?;
    match result.status {
        SatStatus::Sat => parse_objective_value(&result.values, symbol).map(Some),
        SatStatus::Unsat => Ok(None),
        SatStatus::Unknown => Err(LogicPearlError::message(format!(
            "cvc5 returned unknown while improving objective {symbol}"
        ))),
    }
}

fn parse_objective_value(values: &BTreeMap<String, String>, symbol: &str) -> Result<i64> {
    let raw_value = values.get(symbol).ok_or_else(|| {
        LogicPearlError::message(format!(
            "solver did not return a binding for objective {symbol}"
        ))
    })?;
    parse_int_value(raw_value)
}

fn parse_int_value(value: &str) -> Result<i64> {
    let trimmed = value.trim();
    if let Ok(parsed) = trimmed.parse::<i64>() {
        return Ok(parsed);
    }
    if let Some(inner) = trimmed
        .strip_prefix("(- ")
        .and_then(|inner| inner.strip_suffix(')'))
    {
        return inner
            .trim()
            .parse::<i64>()
            .map(|parsed| -parsed)
            .map_err(|err| {
                LogicPearlError::message(format!(
                    "failed to parse negative integer solver value `{trimmed}`: {err}"
                ))
            });
    }
    if let Some(inner) = trimmed
        .strip_prefix("(/ ")
        .and_then(|inner| inner.strip_suffix(')'))
    {
        let parts = inner.split_whitespace().collect::<Vec<_>>();
        if parts.len() == 2 && parts[1] == "1" {
            return parts[0].parse::<i64>().map_err(|err| {
                LogicPearlError::message(format!(
                    "failed to parse rational solver value `{trimmed}`: {err}"
                ))
            });
        }
    }
    Err(LogicPearlError::message(format!(
        "unsupported integer solver value `{trimmed}`"
    )))
}

fn build_value_query_script(
    base_script: &str,
    assertions: &[String],
    symbols: &[String],
) -> String {
    let mut script = String::new();
    push_script_block(&mut script, base_script);
    for assertion in assertions {
        script.push_str(&format!("(assert {assertion})\n"));
    }
    script.push_str("(check-sat)\n");
    if !symbols.is_empty() {
        script.push_str(&format!("(get-value ({}))\n", symbols.join(" ")));
    }
    script
}

fn build_model_query_script(base_script: &str, assertions: &[String]) -> String {
    let mut script = String::new();
    push_script_block(&mut script, base_script);
    for assertion in assertions {
        script.push_str(&format!("(assert {assertion})\n"));
    }
    script.push_str("(check-sat)\n(get-model)\n");
    script
}

fn objective_symbol(index: usize) -> String {
    format!("lp_objective_{index}")
}

fn push_script_block(script: &mut String, block: &str) {
    script.push_str(block);
    if !block.is_empty() && !block.ends_with('\n') {
        script.push('\n');
    }
}

fn stdout_tail(stdout: &str) -> Option<String> {
    let tail = stdout.lines().skip(1).collect::<Vec<_>>().join("\n");
    let trimmed = tail.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

#[cfg(test)]
mod tests {
    use super::{
        check_sat, check_sat_with_values, solve_keep_bools, SatStatus, SolverMode, SolverSettings,
    };
    use crate::SolverBackend;

    fn z3_available() -> bool {
        check_sat("(check-sat)\n", &SolverSettings::default()).is_ok()
    }

    #[test]
    fn check_sat_runs_live_z3_script_when_available() {
        if !z3_available() {
            return;
        }
        let result = check_sat("(check-sat)\n", &SolverSettings::default())
            .expect("z3 should solve a trivial satisfiable script");
        assert_eq!(result.status, SatStatus::Sat);
        assert_eq!(result.report.backend_used, SolverBackend::Z3);
    }

    #[test]
    fn solve_keep_bools_reads_live_model_when_available() {
        if !z3_available() {
            return;
        }
        let script = "\
(declare-fun keep_0 () Bool)\n\
(declare-fun keep_1 () Bool)\n\
(assert keep_1)\n\
(check-sat)\n\
(get-model)\n";
        let result = solve_keep_bools(script, "keep", 2, &SolverSettings::default())
            .expect("z3 should produce a simple model");
        assert_eq!(result.status, SatStatus::Sat);
        assert_eq!(result.selected, vec![1]);
    }

    #[test]
    fn check_sat_with_values_reads_live_bindings_when_available() {
        if !z3_available() {
            return;
        }
        let script = "\
(declare-fun x () Real)\n\
(assert (= x 21.0))\n\
(check-sat)\n\
(get-value (x))\n";
        let result = check_sat_with_values(script, &SolverSettings::default())
            .expect("z3 should provide get-value output");
        assert_eq!(result.status, SatStatus::Sat);
        assert_eq!(result.values.get("x").map(String::as_str), Some("21.0"));
    }

    #[test]
    fn explicit_z3_mode_matches_default_backend() {
        let settings = SolverSettings {
            mode: SolverMode::Require(SolverBackend::Z3),
            timeout_ms: Some(1_000),
        };
        let default_result = check_sat("(check-sat)\n", &SolverSettings::default());
        let explicit_result = check_sat("(check-sat)\n", &settings);
        if let (Ok(default_result), Ok(explicit_result)) = (default_result, explicit_result) {
            assert_eq!(
                explicit_result.report.backend_used,
                default_result.report.backend_used
            );
        }
    }
}
