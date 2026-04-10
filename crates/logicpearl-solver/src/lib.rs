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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SatStatus {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverRunReport {
    pub backend_used: SolverBackend,
    pub status: SatStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatResult {
    pub status: SatStatus,
    pub report: SolverRunReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueResult {
    pub status: SatStatus,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_values: Option<String>,
    pub report: SolverRunReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoolSelectionResult {
    pub status: SatStatus,
    #[serde(default)]
    pub selected: Vec<usize>,
    pub report: SolverRunReport,
}

pub fn check_sat(script: &str, settings: &SolverSettings) -> Result<SatResult> {
    let output = run_solver_script(script, settings, false)?;
    Ok(SatResult {
        status: output.status,
        report: output.report(),
    })
}

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

pub fn solve_keep_bools(
    script: &str,
    keep_prefix: &str,
    keep_count: usize,
    settings: &SolverSettings,
) -> Result<BoolSelectionResult> {
    let output = run_solver_script(script, settings, true)?;
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
    let mut temp_script = NamedTempFile::with_suffix(".smt2").map_err(|err| {
        LogicPearlError::message(format!("failed to create temp solver script: {err}"))
    })?;
    temp_script.write_all(script.as_bytes()).map_err(|err| {
        LogicPearlError::message(format!("failed to write temp solver script: {err}"))
    })?;
    let script_path = temp_script.path();

    let output =
        backend::command_for_backend(backend_used, script_path, settings.timeout_ms, needs_model)
            .output()
            .map_err(|err| {
                LogicPearlError::message(format!(
                    "failed to launch {}: {err}",
                    backend_used.as_str()
                ))
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
