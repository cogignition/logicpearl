// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_core::{load_artifact_bundle, ArtifactKind};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use logicpearl_runtime::{
    evaluate_action_policy, evaluate_gate, explain_gate_result, parse_input_payload,
    GateEvaluationResult,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde_json::Value;
use std::path::{Path, PathBuf};

use super::config::{configured_run_defaults, resolve_config_path};
use super::{guidance, RunArgs};
use crate::read_json_input_argument;

pub(crate) fn run_eval(args: RunArgs) -> Result<()> {
    let (artifact, input_json) = resolve_run_arguments(&args)?;
    let bundle = load_artifact_bundle(&artifact)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve artifact {}", artifact.display()))?;
    let pearl_ir = bundle.ir_path().into_diagnostic()?;
    if bundle.manifest.artifact_kind == ArtifactKind::Action {
        return run_action_eval(&pearl_ir, input_json.as_ref(), args.explain, args.json);
    }
    if bundle.manifest.artifact_kind == ArtifactKind::Pipeline {
        return Err(guidance(
            "run received a pipeline artifact",
            "Use `logicpearl pipeline run` for pipeline artifacts.",
        ));
    }
    let gate = LogicPearlGateIr::from_path(&pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let payload = read_json_input_argument(input_json.as_ref(), "input")?;

    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("runtime input shape is invalid")?;
    let mut outputs = Vec::with_capacity(parsed.len());
    for input in parsed {
        let bitmask = evaluate_gate(&gate, &input)
            .into_diagnostic()
            .wrap_err("failed to evaluate pearl")?;
        if args.explain || args.json {
            outputs
                .push(serde_json::to_value(explain_gate_output(&gate, bitmask)).into_diagnostic()?);
        } else {
            outputs.push(bitmask.to_json_value());
        }
    }
    if args.json {
        if outputs.len() == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs).into_diagnostic()?
            );
        }
    } else if args.explain {
        if outputs.len() == 1 {
            print_explained_gate_output(&outputs[0])?;
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs).into_diagnostic()?
            );
        }
    } else if outputs.len() == 1 {
        println!("{}", outputs[0]);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&outputs).into_diagnostic()?
        );
    }
    Ok(())
}

fn resolve_run_arguments(args: &RunArgs) -> Result<(PathBuf, Option<PathBuf>)> {
    let configured = configured_run_defaults()?;
    match (&args.pearl_ir, &args.input_json) {
        (Some(artifact), Some(input)) => Ok((artifact.clone(), Some(input.clone()))),
        (Some(first), None) => {
            if let Some((config_path, run)) = configured {
                if let Some(config_artifact) = run.artifact {
                    if !looks_like_artifact_path(first) {
                        return Ok((
                            resolve_config_path(&config_path, config_artifact),
                            Some(resolve_config_path(&config_path, first.clone())),
                        ));
                    }
                }
                let input = run
                    .example_input
                    .map(|path| resolve_config_path(&config_path, path));
                Ok((first.clone(), input))
            } else {
                Ok((first.clone(), None))
            }
        }
        (None, None) => {
            let Some((config_path, run)) = configured else {
                return Err(guidance(
                    "run is missing an artifact",
                    "Pass an artifact path, or set run.artifact in logicpearl.yaml.",
                ));
            };
            let artifact = run.artifact.ok_or_else(|| {
                guidance(
                    "run.artifact is missing in logicpearl.yaml",
                    "Set run.artifact to an artifact directory such as /tmp/garden-actions.",
                )
            })?;
            let input = run
                .example_input
                .map(|path| resolve_config_path(&config_path, path));
            Ok((resolve_config_path(&config_path, artifact), input))
        }
        (None, Some(_)) => unreachable!("clap cannot fill the second positional first"),
    }
}

fn looks_like_artifact_path(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("artifact.json").exists()
            || path.join("pearl.ir.json").exists()
            || path.join("pipeline.json").exists();
    }
    path.file_name().is_some_and(|name| {
        name == std::ffi::OsStr::new("artifact.json")
            || name == std::ffi::OsStr::new("pearl.ir.json")
            || name == std::ffi::OsStr::new("pipeline.json")
    })
}

fn run_action_eval(
    action_policy_path: &Path,
    input_json: Option<&PathBuf>,
    explain: bool,
    json: bool,
) -> Result<()> {
    let action_policy = LogicPearlActionIr::from_path(action_policy_path)
        .into_diagnostic()
        .wrap_err("could not load action policy IR")?;
    run_action_policy_eval(&action_policy, input_json, explain, json)
}

fn run_action_policy_eval(
    action_policy: &LogicPearlActionIr,
    input_json: Option<&PathBuf>,
    explain: bool,
    json: bool,
) -> Result<()> {
    let payload = read_json_input_argument(input_json, "input")?;
    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("runtime input shape is invalid")?;
    let mut outputs = Vec::with_capacity(parsed.len());
    for input in parsed {
        outputs.push(
            evaluate_action_policy(action_policy, &input)
                .into_diagnostic()
                .wrap_err("failed to evaluate action policy")?,
        );
    }

    if json {
        if outputs.len() == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs[0]).into_diagnostic()?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&outputs).into_diagnostic()?
            );
        }
        return Ok(());
    }

    if outputs.len() != 1 {
        println!(
            "{}",
            serde_json::to_string_pretty(&outputs).into_diagnostic()?
        );
        return Ok(());
    }

    let output = &outputs[0];
    if explain {
        println!("action: {}", output.action.bold());
        if output.selected_rules.is_empty() {
            if output.no_match_action.is_some() {
                println!("reason: no rule matched; using no-match action");
            } else {
                println!("reason: no rule matched; using default action");
            }
        } else {
            println!("reason:");
            for reason in &output.selected_rules {
                println!(
                    "  - {}",
                    reason
                        .label
                        .as_deref()
                        .or(reason.message.as_deref())
                        .unwrap_or(&reason.id)
                );
            }
        }
        if let Some(ambiguity) = &output.ambiguity {
            println!("note: {ambiguity}");
        }
    } else {
        println!("{}", output.action);
    }
    Ok(())
}

fn explain_gate_output(
    gate: &LogicPearlGateIr,
    bitmask: logicpearl_core::RuleMask,
) -> GateEvaluationResult {
    explain_gate_result(gate, bitmask)
}

fn print_explained_gate_output(value: &Value) -> Result<()> {
    let output: GateEvaluationResult = serde_json::from_value(value.clone())
        .into_diagnostic()
        .wrap_err("failed to render explained output")?;
    println!("bitmask: {}", output.bitmask);
    if output.matched_rules.is_empty() {
        println!("matched: none");
    } else {
        println!("matched:");
        for rule in output.matched_rules {
            println!(
                "  bit {}: {}",
                rule.bit,
                rule.label
                    .as_deref()
                    .or(rule.message.as_deref())
                    .unwrap_or(&rule.id)
            );
        }
    }
    Ok(())
}
