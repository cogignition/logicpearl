// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::types::{BenchmarkCase, SynthesisCase, SynthesisCaseRow};

pub fn load_benchmark_cases(path: &Path) -> Result<Vec<BenchmarkCase>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: BenchmarkCase = serde_json::from_str(trimmed).map_err(|err| {
            LogicPearlError::message(format!(
                "invalid benchmark case JSON on line {}. Each line must contain id, input, and expected_route ({err})",
                line_no + 1
            ))
        })?;
        cases.push(case);
    }
    Ok(cases)
}

pub fn load_synthesis_case_rows(path: &Path) -> Result<Vec<SynthesisCaseRow>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|err| {
            LogicPearlError::message(format!("invalid JSON on line {} ({err})", line_no + 1))
        })?;
        let object = value.as_object().ok_or_else(|| {
            LogicPearlError::message(format!(
                "invalid synthesis row on line {}; each row must be a benchmark case or observed benchmark case object",
                line_no + 1
            ))
        })?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("row_{:06}", line_no + 1));

        let prompt = object
            .get("input")
            .and_then(Value::as_object)
            .and_then(|input| input.get("prompt"))
            .and_then(Value::as_str)
            .map(|prompt| prompt.to_ascii_lowercase())
            .ok_or_else(|| {
                LogicPearlError::message(format!(
                    "synthesis row {} is missing input.prompt",
                    line_no + 1
                ))
            })?;
        let expected_route = object
            .get("expected_route")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                LogicPearlError::message(format!(
                    "synthesis row {} is missing expected_route",
                    line_no + 1
                ))
            })?;
        let features = object.get("features").and_then(Value::as_object).cloned();

        cases.push(SynthesisCaseRow {
            id,
            case: SynthesisCase {
                prompt,
                expected_route,
                features,
            },
        });
    }
    Ok(cases)
}

pub fn load_synthesis_cases(path: &Path) -> Result<Vec<SynthesisCase>> {
    Ok(load_synthesis_case_rows(path)?
        .into_iter()
        .map(|row| row.case)
        .collect())
}

pub fn write_benchmark_cases_jsonl(cases: &[BenchmarkCase], output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::new();
    for case in cases {
        out.push_str(&serde_json::to_string(case).map_err(|err| {
            LogicPearlError::message(format!("could not serialize benchmark case ({err})"))
        })?);
        out.push('\n');
    }
    fs::write(output, out)?;
    Ok(())
}
