// SPDX-License-Identifier: MIT
use super::*;
use logicpearl_benchmark::{
    load_benchmark_cases, write_benchmark_cases_jsonl, BenchmarkCase, ObservedBenchmarkCase,
};
use logicpearl_discovery::ArtifactSet;
use logicpearl_ir::{
    CombineStrategy, EvaluationConfig, GateType, LogicPearlGateIr, Provenance, VerificationConfig,
};
use logicpearl_runtime::evaluate_gate;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

mod commands;
mod io;
mod progress;
mod quality;

use commands::{
    build_nested_command, build_nested_command_with_paths, default_refresh_logs_dir,
    find_repo_root, nested_logicpearl_base_command, refresh_front_door, require_repo_root,
    run_json_command, run_json_commands_parallel, run_plain_command,
};
use io::{
    build_artifact_hashes, copy_dir_all, copy_plugin_bundle, path_from_json, read_json,
    read_jsonl_rows, sha256_file, write_json_pretty,
};
use progress::run_refresh_step;
pub(crate) use quality::run_refresh_quality_report;

const DEFAULT_DATASETS_ENV: &str = "LOGICPEARL_DATASETS";
const BENCHMARK_BATCH_SAMPLE: usize = 200;

const TRACE_PROJECTION_GUARDRAILS: &str =
    "benchmarks/guardrails/prep/trace_projection.guardrails_v1.json";
const TRACE_PROJECTION_WAF: &str = "benchmarks/waf/prep/trace_projection.waf_v1.json";
const FEATURE_GOVERNANCE_WAF: &str = "benchmarks/waf/prep/feature_governance.waf_v1.json";
const OBSERVER_MANIFEST_WAF: &str = "examples/waf_edge/plugins/observer/manifest.json";
const ROUTE_AUDIT_MANIFEST_WAF: &str = "examples/waf_edge/plugins/route_audit/manifest.json";
const QUALITY_REPORT_PATH: &str = "target/logicpearl/quality/QUALITY.json";
const GETTING_STARTED_CSV: &str = "examples/getting_started/decision_traces.csv";
const GETTING_STARTED_INPUT: &str = "examples/getting_started/new_input.json";

const DEMO_CASES: [(&str, &str); 3] = [
    ("access_control", "examples/demos/access_control/traces.csv"),
    (
        "content_moderation",
        "examples/demos/content_moderation/traces.csv",
    ),
    ("loan_approval", "examples/demos/loan_approval/traces.csv"),
];

const GUARDRAIL_SIGNALS: [&str; 3] = ["instruction-override", "secret-exfiltration", "tool-misuse"];

const WAF_TARGETS: [(&str, &str, &str); 3] = [
    (
        "target_injection_payload",
        "target_injection_payload_traces.csv",
        "standard",
    ),
    (
        "target_sensitive_surface",
        "target_sensitive_surface_traces.csv",
        "standard",
    ),
    (
        "target_suspicious_request",
        "target_suspicious_request_traces.csv",
        "review",
    ),
];

#[derive(Debug, Clone)]
struct RefreshStep {
    id: &'static str,
    title: &'static str,
    command: Vec<String>,
    env: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct RefreshProgress {
    detail: String,
    eta: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct GuardrailDatasetSpec {
    dataset_id: &'static str,
    profile: &'static str,
    raw_rel: &'static str,
    optional: bool,
}

#[derive(Debug, Clone, Copy)]
struct GuardrailExternalBenchmark {
    id: &'static str,
    profile: &'static str,
    raw_rel: &'static str,
    splits_rel: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct GuardrailRouteRule {
    target: &'static str,
    route_status: &'static str,
    label: &'static str,
    message: &'static str,
    counterfactual_hint: &'static str,
}

const GUARDRAIL_DATASETS: [GuardrailDatasetSpec; 16] = [
    GuardrailDatasetSpec {
        dataset_id: "squad_train",
        profile: "squad",
        raw_rel: "squad/train-v2.0.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "alert",
        profile: "alert",
        raw_rel: "alert/ALERT.jsonl",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "alert_adv",
        profile: "alert",
        raw_rel: "alert/ALERT_Adv.jsonl",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "salad_base_set",
        profile: "salad-base-set",
        raw_rel: "salad/base_set.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "salad_attack_enhanced_set",
        profile: "salad-attack-enhanced-set",
        raw_rel: "salad/attack_enhanced_set.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "chatgpt_jailbreak_prompts",
        profile: "chatgpt-jailbreak-prompts",
        raw_rel: "chatgpt_jailbreak/chatgpt_jailbreak_prompts.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "vigil",
        profile: "vigil",
        raw_rel: "vigil/vigil.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "noeti_toxicqa",
        profile: "noeti-toxicqa",
        raw_rel: "noeti_toxicqa/noeti_toxicqa.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "openagentsafety_s26",
        profile: "openagentsafety-s26",
        raw_rel: "openagentsafety/openagentsafety_s26.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "mcpmark",
        profile: "mcpmark",
        raw_rel: "mcpmark/mcpmark_tasks.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "safearena_safe",
        profile: "safearena-safe",
        raw_rel: "safearena/safe.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "safearena_harm",
        profile: "safearena-harm",
        raw_rel: "safearena/harm.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "jailbreakbench",
        profile: "jailbreakbench",
        raw_rel: "jailbreakbench/jbb_behaviors.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "promptshield",
        profile: "promptshield",
        raw_rel: "promptshield/promptshield.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "rogue_security_prompt_injections",
        profile: "rogue-security-prompt-injections",
        raw_rel: "rogue_security/prompt_injections_benchmark.json",
        optional: false,
    },
    GuardrailDatasetSpec {
        dataset_id: "mt_agentrisk",
        profile: "mt-agentrisk",
        raw_rel: "mt_agentrisk/full_repo",
        optional: true,
    },
];

const GUARDRAIL_EXTERNAL_BENCHMARKS: [GuardrailExternalBenchmark; 3] = [
    GuardrailExternalBenchmark {
        id: "jailbreakbench",
        profile: "jailbreakbench",
        raw_rel: "jailbreakbench/jbb_behaviors.json",
        splits_rel: "jailbreakbench/logicpearl_splits/jailbreakbench",
    },
    GuardrailExternalBenchmark {
        id: "promptshield",
        profile: "promptshield",
        raw_rel: "promptshield/promptshield.json",
        splits_rel: "promptshield/logicpearl_splits/promptshield",
    },
    GuardrailExternalBenchmark {
        id: "rogue-security-prompt-injections",
        profile: "rogue-security-prompt-injections",
        raw_rel: "rogue_security/prompt_injections_benchmark.json",
        splits_rel: "rogue_security/logicpearl_splits/rogue_security_prompt_injections",
    },
];

const GUARDRAIL_ROUTE_RULES: [GuardrailRouteRule; 3] = [
    GuardrailRouteRule {
        target: "target_tool_use",
        route_status: "deny_tool_use",
        label: "deny_tool_use",
        message: "Blocked potentially unsafe or unauthorized tool use.",
        counterfactual_hint:
            "Remove the requested tool action or constrain it to an explicitly allowed scope.",
    },
    GuardrailRouteRule {
        target: "target_instruction_boundary",
        route_status: "deny_untrusted_instruction",
        label: "deny_untrusted_instruction",
        message: "Blocked prompt-injection or instruction override behavior.",
        counterfactual_hint:
            "Remove the override or system-prompt targeting language and keep the request inside the trusted task.",
    },
    GuardrailRouteRule {
        target: "target_exfiltration",
        route_status: "deny_exfiltration_risk",
        label: "deny_exfiltration_risk",
        message: "Blocked secret or sensitive data exfiltration behavior.",
        counterfactual_hint:
            "Remove requests for passwords, credentials, secrets, or out-of-scope sensitive data.",
    },
];

pub(crate) fn run_refresh_benchmarks(args: RefreshBenchmarksArgs) -> Result<()> {
    let repo_root =
        find_repo_root(&std::env::current_dir().into_diagnostic()?).ok_or_else(|| {
            guidance(
                "could not find the LogicPearl repo root from the current directory",
                "Run `cargo xtask refresh-benchmarks` from inside the checked-out LogicPearl repo.",
            )
        })?;
    let logs_dir = args
        .logs_dir
        .clone()
        .unwrap_or_else(default_refresh_logs_dir);
    fs::create_dir_all(&logs_dir)
        .into_diagnostic()
        .wrap_err("failed to create refresh log directory")?;

    println!("{}", "LogicPearl Refresh".bold().bright_blue());
    println!("  {} {}", "Repo".bright_black(), repo_root.display());
    println!("  {} {}", "Logs".bright_black(), logs_dir.display());
    println!(
        "  {} {}",
        "Guardrails".bright_black(),
        args.guardrail_bundle_dir.display()
    );
    println!(
        "  {} {}",
        "WAF benchmark".bright_black(),
        args.waf_benchmark_dir.display()
    );
    println!(
        "  {} {}",
        "WAF bundle".bright_black(),
        args.waf_bundle_dir.display()
    );
    println!(
        "  {} {}",
        "Target goal".bright_black(),
        observer_target_goal_name(&args.target_goal)
    );

    let steps = build_refresh_steps(&repo_root, &args)?;
    let total_steps = steps.len();
    for (index, step) in steps.iter().enumerate() {
        run_refresh_step(
            &repo_root,
            &logs_dir,
            step,
            args.verbose,
            index + 1,
            total_steps,
        )?;
    }

    println!();
    println!("{}", "Refresh complete.".bold().bright_green());
    println!("  {} {}", "Logs".bright_black(), logs_dir.display());
    println!(
        "  {} {}",
        "Guardrails summary".bright_black(),
        args.guardrail_bundle_dir
            .join("open_benchmarks_final_holdout")
            .join("summary.json")
            .display()
    );
    println!(
        "  {} {}",
        "Learned WAF summary".bright_black(),
        args.waf_bundle_dir.join("summary.json").display()
    );
    println!(
        "  {} {}",
        "Quality report".bright_black(),
        repo_root.join(QUALITY_REPORT_PATH).display()
    );
    Ok(())
}

pub(crate) fn run_refresh_guardrails_freeze(args: RefreshGuardrailsFreezeArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let datasets_root = datasets_root_from_args(&repo_root, args.datasets_root.as_ref());
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    let mut manifests = Vec::new();
    let mut skipped = Vec::new();

    for spec in GUARDRAIL_DATASETS {
        let raw_path = datasets_root.join(spec.raw_rel);
        if !raw_path.exists() {
            if spec.optional {
                skipped.push(json!({
                    "dataset_id": spec.dataset_id,
                    "profile": spec.profile,
                    "raw_path": raw_path.display().to_string(),
                    "reason": "optional dataset root not staged locally"
                }));
                continue;
            }
            return Err(miette::miette!(
                "missing raw dataset input: {}",
                raw_path.display()
            ));
        }

        let splits_dir = guardrail_split_dir(&datasets_root, spec);
        fs::create_dir_all(&splits_dir)
            .into_diagnostic()
            .wrap_err("failed to create guardrail split directory")?;
        let all_cases = splits_dir.join("all_cases.jsonl");
        let dev_cases = splits_dir.join("dev.jsonl");
        let final_holdout_cases = splits_dir.join("final_holdout.jsonl");

        let adapt_report = run_json_command(
            &repo_root,
            &build_nested_command(
                &cli,
                &[
                    "benchmark",
                    "adapt",
                    &raw_path.display().to_string(),
                    "--profile",
                    spec.profile,
                    "--output",
                    &all_cases.display().to_string(),
                    "--json",
                ],
            ),
        )?;

        let split_report = run_json_command(
            &repo_root,
            &build_nested_command(
                &cli,
                &[
                    "benchmark",
                    "split-cases",
                    &all_cases.display().to_string(),
                    "--train-output",
                    &dev_cases.display().to_string(),
                    "--dev-output",
                    &final_holdout_cases.display().to_string(),
                    "--train-fraction",
                    &args.dev_fraction.to_string(),
                    "--json",
                ],
            ),
        )?;

        let manifest = json!({
            "dataset_id": spec.dataset_id,
            "profile": spec.profile,
            "raw_path": raw_path.display().to_string(),
            "all_cases": all_cases.display().to_string(),
            "dev_cases": dev_cases.display().to_string(),
            "final_holdout_cases": final_holdout_cases.display().to_string(),
            "adapt_report": adapt_report,
            "split_report": split_report,
        });
        write_json_pretty(&splits_dir.join("split_manifest.json"), &manifest)?;
        manifests.push(manifest);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "dev_fraction": args.dev_fraction,
            "datasets": manifests,
            "skipped_datasets": skipped,
        }))
        .into_diagnostic()?
    );
    Ok(())
}

pub(crate) fn run_refresh_guardrails_build(args: RefreshGuardrailsBuildArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let datasets_root = datasets_root_from_args(&repo_root, args.datasets_root.as_ref());
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    let output_dir = args.output_dir;
    let freeze_dir = output_dir.join("freeze");
    let train_prep_dir = output_dir.join("train_prep");
    let final_holdout_eval_dir = output_dir.join("final_holdout_eval");
    fs::create_dir_all(&freeze_dir).into_diagnostic()?;
    fs::create_dir_all(&final_holdout_eval_dir).into_diagnostic()?;

    let mut split_manifests = Vec::new();
    let mut skipped_datasets = Vec::new();
    let mut dev_case_paths = Vec::new();
    let mut final_holdout_paths = Vec::new();

    for spec in GUARDRAIL_DATASETS {
        let raw_path = datasets_root.join(spec.raw_rel);
        if !raw_path.exists() {
            if spec.optional {
                skipped_datasets.push(json!({
                    "dataset_id": spec.dataset_id,
                    "profile": spec.profile,
                    "raw_path": raw_path.display().to_string(),
                    "reason": "optional dataset root not staged locally",
                }));
                continue;
            }
            return Err(miette::miette!(
                "missing raw dataset input: {}",
                raw_path.display()
            ));
        }
        let manifest_path = guardrail_split_dir(&datasets_root, spec).join("split_manifest.json");
        if !manifest_path.exists() {
            if spec.optional {
                skipped_datasets.push(json!({
                    "dataset_id": spec.dataset_id,
                    "profile": spec.profile,
                    "raw_path": raw_path.display().to_string(),
                    "reason": "optional dataset split manifest was not generated",
                }));
                continue;
            }
            return Err(miette::miette!(
                "missing split manifest: {}",
                manifest_path.display()
            ));
        }
        let manifest: Value = read_json(&manifest_path)?;
        dev_case_paths.push(path_from_json(&manifest["dev_cases"])?);
        final_holdout_paths.push(path_from_json(&manifest["final_holdout_cases"])?);
        split_manifests.push(manifest);
    }

    if dev_case_paths.is_empty() || final_holdout_paths.is_empty() {
        return Err(miette::miette!(
            "no staged guardrail dataset splits were available to build the bundle"
        ));
    }

    let merged_dev_path = output_dir.join("guardrail_dev_full.jsonl");
    let merge_report = run_json_command(
        &repo_root,
        &build_nested_command_with_paths(
            &cli,
            "benchmark",
            "merge-cases",
            &dev_case_paths,
            &merged_dev_path,
        ),
    )?;

    let merged_final_holdout_path = output_dir.join("guardrail_final_holdout_full.jsonl");
    let final_holdout_merge_report = run_json_command(
        &repo_root,
        &build_nested_command_with_paths(
            &cli,
            "benchmark",
            "merge-cases",
            &final_holdout_paths,
            &merged_final_holdout_path,
        ),
    )?;

    let mut working_dev_path = merged_dev_path.clone();
    let mut dev_sample_report = Value::Null;
    if args.dev_case_limit > 0 {
        let sampled = route_stratified_sample_cases(
            &load_benchmark_cases(&merged_dev_path).into_diagnostic()?,
            args.dev_case_limit,
        );
        working_dev_path = output_dir.join(format!(
            "guardrail_dev_sampled_{}.jsonl",
            args.dev_case_limit
        ));
        write_benchmark_cases_jsonl(&sampled.rows, &working_dev_path).into_diagnostic()?;
        dev_sample_report = sampled.report;
    }

    let mut working_final_holdout_path = merged_final_holdout_path.clone();
    let mut final_holdout_sample_report = Value::Null;
    if args.final_holdout_case_limit > 0 {
        let sampled = route_stratified_sample_cases(
            &load_benchmark_cases(&merged_final_holdout_path).into_diagnostic()?,
            args.final_holdout_case_limit,
        );
        working_final_holdout_path = output_dir.join(format!(
            "guardrail_final_holdout_sampled_{}.jsonl",
            args.final_holdout_case_limit
        ));
        write_benchmark_cases_jsonl(&sampled.rows, &working_final_holdout_path)
            .into_diagnostic()?;
        final_holdout_sample_report = sampled.report;
    }

    let observer_scaffold_path = freeze_dir.join("guardrails_v1.observer.scaffold.json");
    let observer_scaffold = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "observer",
                "scaffold",
                "--profile",
                "guardrails-v1",
                "--output",
                &observer_scaffold_path.display().to_string(),
                "--json",
            ],
        ),
    )?;

    let synthesized_dir = freeze_dir.join("observer_synthesis");
    fs::create_dir_all(&synthesized_dir).into_diagnostic()?;
    let mut current_observer_path = observer_scaffold_path.clone();
    let mut synthesis_reports = Vec::new();

    for (index, signal) in GUARDRAIL_SIGNALS.iter().enumerate() {
        let output_path =
            synthesized_dir.join(format!("{:02}_{}.observer.json", index + 1, signal));
        let mut report = if args.resume && output_path.exists() {
            json!({
                "status": "resumed",
                "signal": signal,
                "output": output_path.display().to_string(),
            })
        } else {
            run_json_command(
                &repo_root,
                &build_nested_command(
                    &cli,
                    &[
                        "observer",
                        "synthesize",
                        "--artifact",
                        &current_observer_path.display().to_string(),
                        "--benchmark-cases",
                        &working_dev_path.display().to_string(),
                        "--signal",
                        signal,
                        "--target-goal",
                        observer_target_goal_name(&args.target_goal),
                        "--allow-empty",
                        "--output",
                        &output_path.display().to_string(),
                        "--json",
                    ],
                ),
            )?
        };
        report["input_artifact"] = Value::String(current_observer_path.display().to_string());
        synthesis_reports.push(report);
        current_observer_path = output_path;
    }

    let observer_artifact_path = freeze_dir.join("guardrails_v1.observer.json");
    fs::copy(&current_observer_path, &observer_artifact_path)
        .into_diagnostic()
        .wrap_err("failed to write final guardrail observer artifact")?;

    let prepare_report = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "prepare",
                &working_dev_path.display().to_string(),
                "--observer-artifact",
                &observer_artifact_path.display().to_string(),
                "--config",
                &repo_root
                    .join(TRACE_PROJECTION_GUARDRAILS)
                    .display()
                    .to_string(),
                "--output-dir",
                &train_prep_dir.display().to_string(),
                "--json",
            ],
        ),
    )?;

    let final_holdout_observed_path = final_holdout_eval_dir.join("observed.jsonl");
    let observe_report = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "observe",
                &working_final_holdout_path.display().to_string(),
                "--observer-artifact",
                &observer_artifact_path.display().to_string(),
                "--output",
                &final_holdout_observed_path.display().to_string(),
                "--json",
            ],
        ),
    )?;

    let final_holdout_traces_dir = final_holdout_eval_dir.join("traces");
    let emit_report = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "emit-traces",
                &final_holdout_observed_path.display().to_string(),
                "--config",
                &repo_root
                    .join(TRACE_PROJECTION_GUARDRAILS)
                    .display()
                    .to_string(),
                "--output-dir",
                &final_holdout_traces_dir.display().to_string(),
                "--json",
            ],
        ),
    )?;

    let score_report_path = final_holdout_eval_dir.join("artifact_score.json");
    let score_report = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "score-artifacts",
                &train_prep_dir
                    .join("discovered")
                    .join("artifact_set.json")
                    .display()
                    .to_string(),
                &final_holdout_traces_dir
                    .join("multi_target.csv")
                    .display()
                    .to_string(),
                "--output",
                &score_report_path.display().to_string(),
                "--json",
            ],
        ),
    )?;

    let frozen_artifact_set_dir = freeze_dir.join("artifact_set");
    if frozen_artifact_set_dir.exists() {
        fs::remove_dir_all(&frozen_artifact_set_dir).into_diagnostic()?;
    }
    copy_dir_all(&train_prep_dir.join("discovered"), &frozen_artifact_set_dir)?;

    let combined_pearl_path = freeze_dir.join("guardrails_combined.pearl.ir.json");
    let route_policy_path = freeze_dir.join("route_policy.json");
    build_guardrails_combined_pearl(
        &frozen_artifact_set_dir.join("artifact_set.json"),
        &combined_pearl_path,
        &route_policy_path,
        &git_output(&repo_root, &["rev-parse", "HEAD"])?,
    )?;

    let native_output = freeze_dir.join("guardrails_combined.pearl");
    run_plain_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "compile",
                &combined_pearl_path.display().to_string(),
                "--name",
                "guardrails_combined",
                "--output",
                &native_output.display().to_string(),
            ],
        ),
    )?;

    let wasm_output = freeze_dir.join("guardrails_combined.pearl.wasm");
    let wasm_compiled = run_plain_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "compile",
                &combined_pearl_path.display().to_string(),
                "--name",
                "guardrails_combined",
                "--target",
                "wasm32-unknown-unknown",
                "--output",
                &wasm_output.display().to_string(),
            ],
        ),
    )
    .is_ok();

    let bundle_manifest = json!({
        "bundle_version": "1.0",
        "bundle_id": "guardrails_bundle_v1",
        "created_from_commit": git_output(&repo_root, &["rev-parse", "HEAD"])?,
        "git_clean": git_output(&repo_root, &["status", "--short"])?.is_empty(),
        "trace_projection_config": repo_root.join(TRACE_PROJECTION_GUARDRAILS).display().to_string(),
        "observer_target_goal": observer_target_goal_name(&args.target_goal),
        "observer_artifact": observer_artifact_path.display().to_string(),
        "observer_scaffold_artifact": observer_scaffold_path.display().to_string(),
        "artifact_set": frozen_artifact_set_dir.join("artifact_set.json").display().to_string(),
        "combined_pearl_ir": combined_pearl_path.display().to_string(),
        "combined_native_binary": native_output.display().to_string(),
        "combined_wasm_module": if wasm_compiled { Value::String(wasm_output.display().to_string()) } else { Value::Null },
        "route_policy": route_policy_path.display().to_string(),
        "datasets": split_manifests,
        "skipped_datasets": skipped_datasets,
        "merge_report": merge_report,
        "final_holdout_merge_report": final_holdout_merge_report,
        "working_dev_cases": working_dev_path.display().to_string(),
        "working_final_holdout_cases": working_final_holdout_path.display().to_string(),
        "dev_sample_report": dev_sample_report,
        "final_holdout_sample_report": final_holdout_sample_report,
        "observer_scaffold": observer_scaffold,
        "observer_synthesis": synthesis_reports,
        "prepare_report": prepare_report,
        "final_holdout_observe_report": observe_report,
        "final_holdout_emit_report": emit_report,
        "final_holdout_artifact_score": score_report,
    });
    write_json_pretty(&output_dir.join("bundle_manifest.json"), &bundle_manifest)?;
    write_json_pretty(
        &output_dir.join("artifact_hashes.json"),
        &build_artifact_hashes(&freeze_dir)?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&bundle_manifest).into_diagnostic()?
    );
    Ok(())
}

pub(crate) fn run_refresh_guardrails_eval(args: RefreshGuardrailsEvalArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let datasets_root = datasets_root_from_args(&repo_root, args.datasets_root.as_ref());
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    fs::create_dir_all(&args.output_dir).into_diagnostic()?;

    let bundle_target_goal = if args.target_goal.trim().is_empty() {
        detect_bundle_target_goal(&args.bundle_dir)?
    } else {
        canonical_target_goal(&args.target_goal)
    };

    let mut aggregate = Vec::new();
    let mut skipped = Vec::new();

    for benchmark in GUARDRAIL_EXTERNAL_BENCHMARKS {
        let benchmark_input = match args.input_split.as_str() {
            "raw" => datasets_root.join(benchmark.raw_rel),
            "dev" => datasets_root.join(benchmark.splits_rel).join("dev.jsonl"),
            "final_holdout" => datasets_root
                .join(benchmark.splits_rel)
                .join("final_holdout.jsonl"),
            other => {
                return Err(guidance(
                    format!("unsupported --input-split `{other}`"),
                    "Use one of: dev, final_holdout, raw.",
                ))
            }
        };
        if !benchmark_input.exists() {
            skipped.push(json!({
                "benchmark": benchmark.id,
                "path": benchmark_input.display().to_string(),
                "status": "missing"
            }));
            continue;
        }

        let run = GuardrailEvalRun {
            repo_root: &repo_root,
            bundle_dir: &args.bundle_dir,
            output_dir: &args.output_dir,
            cli: &cli,
            input_split: &args.input_split,
            sample_size: args.sample_size,
        };
        let report = evaluate_guardrail_benchmark(&run, benchmark, &benchmark_input)?;
        aggregate.push(report);
    }

    let default_baseline_path = if args.sample_size > 0 {
        let lane = repo_root.join("scripts").join("guardrails").join(format!(
            "open_guardrail_regression_baseline.sample{}.{}.json",
            args.sample_size, bundle_target_goal
        ));
        if lane.exists() {
            Some(lane)
        } else {
            let generic = repo_root
                .join("scripts")
                .join("guardrails")
                .join("open_guardrail_regression_baseline.sample200.json");
            if generic.exists() {
                Some(generic)
            } else {
                None
            }
        }
    } else {
        None
    };

    let baseline_path = if args.baseline.trim().is_empty() {
        default_baseline_path
    } else {
        Some(PathBuf::from(args.baseline))
    };
    let baseline = if let Some(path) = &baseline_path {
        if path.exists() {
            Some(read_json(path)?)
        } else {
            None
        }
    } else {
        None
    };

    let summary = json!({
        "input_split": args.input_split,
        "sample_size": args.sample_size,
        "target_goal": bundle_target_goal,
        "baseline": baseline_path.as_ref().map(|path| path.display().to_string()).unwrap_or_default(),
        "benchmarks": aggregate,
        "skipped": skipped,
    });
    write_json_pretty(&args.output_dir.join("summary.json"), &summary)?;

    if let Some(baseline) = baseline {
        let failures = compare_against_baseline(
            summary["benchmarks"].as_array().unwrap_or(&Vec::new()),
            &baseline,
            args.tolerance,
        );
        if !failures.is_empty() {
            return Err(miette::miette!(failures.join("\n")));
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&summary).into_diagnostic()?
    );
    Ok(())
}

pub(crate) fn run_refresh_waf_benchmark_cases(args: RefreshWafBenchmarkCasesArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let datasets_root = datasets_root_from_args(&repo_root, args.datasets_root.as_ref());
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    let output_dir = args.output_dir;
    let adapted_dir = output_dir.join("adapted");
    fs::create_dir_all(&adapted_dir).into_diagnostic()?;

    let csic_root = args
        .csic_root
        .unwrap_or_else(|| datasets_root.join("waf/csic-http-2010"));
    let modsecurity_root = args
        .modsecurity_root
        .unwrap_or_else(|| datasets_root.join("waf/modsecurity-owasp-2025"));

    let csic_jsonl = adapted_dir.join("csic_http_2010.jsonl");
    let modsecurity_jsonl = adapted_dir.join("modsecurity_owasp_2025.jsonl");
    let merged_jsonl = output_dir.join("waf_full.jsonl");
    let dev_jsonl = output_dir.join("dev.jsonl");
    let final_holdout_jsonl = output_dir.join("final_holdout.jsonl");

    run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "adapt",
                &csic_root.display().to_string(),
                "--profile",
                "csic-http-2010",
                "--requested-tool",
                "http",
                "--requested-action",
                "allow_or_block",
                "--scope",
                "edge",
                "--output",
                &csic_jsonl.display().to_string(),
                "--json",
            ],
        ),
    )?;
    run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "adapt",
                &modsecurity_root.display().to_string(),
                "--profile",
                "modsecurity-owasp-2025",
                "--requested-tool",
                "http",
                "--requested-action",
                "allow_or_block",
                "--scope",
                "edge",
                "--output",
                &modsecurity_jsonl.display().to_string(),
                "--json",
            ],
        ),
    )?;
    run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "merge-cases",
                &csic_jsonl.display().to_string(),
                &modsecurity_jsonl.display().to_string(),
                "--output",
                &merged_jsonl.display().to_string(),
                "--json",
            ],
        ),
    )?;
    run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "split-cases",
                &merged_jsonl.display().to_string(),
                "--train-output",
                &dev_jsonl.display().to_string(),
                "--dev-output",
                &final_holdout_jsonl.display().to_string(),
                "--train-fraction",
                &args.dev_fraction.to_string(),
                "--json",
            ],
        ),
    )?;

    let summary = json!({
        "datasets_root": datasets_root.display().to_string(),
        "csic_root": csic_root.display().to_string(),
        "modsecurity_root": modsecurity_root.display().to_string(),
        "outputs": {
            "csic": csic_jsonl.display().to_string(),
            "modsecurity": modsecurity_jsonl.display().to_string(),
            "merged": merged_jsonl.display().to_string(),
            "dev": dev_jsonl.display().to_string(),
            "final_holdout": final_holdout_jsonl.display().to_string(),
        }
    });
    write_json_pretty(&output_dir.join("summary.json"), &summary)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).into_diagnostic()?
    );
    Ok(())
}

pub(crate) fn run_refresh_waf_build(args: RefreshWafBuildArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let datasets_root = datasets_root_from_args(&repo_root, args.datasets_root.as_ref());
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    let output_dir = args.output_dir;
    fs::create_dir_all(&output_dir).into_diagnostic()?;

    if !args.resume || !args.benchmark_dir.join("final_holdout.jsonl").exists() {
        run_refresh_waf_benchmark_cases(RefreshWafBenchmarkCasesArgs {
            output_dir: args.benchmark_dir.clone(),
            datasets_root: Some(datasets_root),
            csic_root: None,
            modsecurity_root: None,
            dev_fraction: args.dev_fraction,
            use_installed_cli: args.use_installed_cli,
        })?;
    }

    let train_dir = output_dir.join("train");
    let holdout_dir = output_dir.join("final_holdout");
    let freeze_dir = output_dir.join("freeze");
    fs::create_dir_all(&train_dir).into_diagnostic()?;
    fs::create_dir_all(&holdout_dir).into_diagnostic()?;
    fs::create_dir_all(&freeze_dir).into_diagnostic()?;

    let dev_cases = args.benchmark_dir.join("dev.jsonl");
    let final_holdout_cases = args.benchmark_dir.join("final_holdout.jsonl");
    let observer_manifest = repo_root.join(OBSERVER_MANIFEST_WAF);
    let route_audit_manifest = repo_root.join(ROUTE_AUDIT_MANIFEST_WAF);
    let trace_projection = repo_root.join(TRACE_PROJECTION_WAF);
    let feature_governance = repo_root.join(FEATURE_GOVERNANCE_WAF);

    let train_observed = train_dir.join("observed.jsonl");
    cached_waf_observe(
        &repo_root,
        &dev_cases,
        &train_observed,
        &train_dir.join("observe.cache.json"),
    )?;
    cached_emit_traces(
        &repo_root,
        &cli,
        &train_observed,
        &trace_projection,
        &train_dir.join("traces"),
        &train_dir.join("emit_traces.cache.json"),
    )?;

    let discovered_dir = train_dir.join("discovered");
    fs::create_dir_all(&discovered_dir).into_diagnostic()?;
    let artifact_set = build_waf_target_artifact_set(
        &repo_root,
        &cli,
        &train_dir.join("traces"),
        &discovered_dir,
        args.refine,
        args.skip_compile,
        &feature_governance,
    )?;

    let copied_observer_manifest = copy_plugin_bundle(
        &observer_manifest,
        &freeze_dir.join("plugins").join("observer"),
    )?;
    let copied_route_manifest = copy_plugin_bundle(
        &route_audit_manifest,
        &freeze_dir.join("plugins").join("route_audit"),
    )?;

    let rewritten_artifact_set_path = freeze_dir.join("artifact_set.json");
    for descriptor in &artifact_set.binary_targets {
        let source = discovered_dir.join(&descriptor.artifact);
        let destination = freeze_dir.join(&descriptor.artifact);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).into_diagnostic()?;
        }
        fs::copy(&source, &destination).into_diagnostic()?;
    }
    write_json_pretty(
        &rewritten_artifact_set_path,
        &serde_json::to_value(&artifact_set).into_diagnostic()?,
    )?;

    let learned_pipeline_path = freeze_dir.join("waf_edge.learned.pipeline.json");
    let learned_pipeline = build_waf_learned_pipeline(
        &artifact_set,
        Path::new("plugins/observer/manifest.json"),
        Path::new("plugins/route_audit/manifest.json"),
    );
    write_json_pretty(&learned_pipeline_path, &learned_pipeline)?;

    let holdout_observed = holdout_dir.join("observed.jsonl");
    cached_waf_observe(
        &repo_root,
        &final_holdout_cases,
        &holdout_observed,
        &holdout_dir.join("observe.cache.json"),
    )?;
    cached_emit_traces(
        &repo_root,
        &cli,
        &holdout_observed,
        &trace_projection,
        &holdout_dir.join("traces"),
        &holdout_dir.join("emit_traces.cache.json"),
    )?;

    let artifact_score = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "score-artifacts",
                &rewritten_artifact_set_path.display().to_string(),
                &holdout_dir
                    .join("traces")
                    .join("multi_target.csv")
                    .display()
                    .to_string(),
                "--output",
                &holdout_dir
                    .join("artifact_score.json")
                    .display()
                    .to_string(),
                "--json",
            ],
        ),
    )?;
    let observed_cases = load_observed_benchmark_cases(&holdout_observed)?;
    let exact = evaluate_waf_routes_from_observed(
        &observed_cases,
        &freeze_dir,
        &final_holdout_cases,
        false,
        &holdout_dir.join("exact_routes.json"),
    )?;
    let collapsed = evaluate_waf_routes_from_observed(
        &observed_cases,
        &freeze_dir,
        &final_holdout_cases,
        true,
        &holdout_dir.join("collapsed_allow_deny.json"),
    )?;

    let summary = json!({
        "benchmark_dir": args.benchmark_dir.display().to_string(),
        "trace_projection_config": trace_projection.display().to_string(),
        "artifact_set": rewritten_artifact_set_path.display().to_string(),
        "learned_pipeline": learned_pipeline_path.display().to_string(),
        "observer_plugin_manifest": copied_observer_manifest.display().to_string(),
        "route_audit_plugin_manifest": copied_route_manifest.display().to_string(),
        "artifact_score": artifact_score["summary"].clone(),
        "exact_routes": exact["summary"].clone(),
        "collapsed_allow_deny": collapsed["summary"].clone(),
    });
    write_json_pretty(&output_dir.join("summary.json"), &summary)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).into_diagnostic()?
    );
    Ok(())
}

fn build_refresh_steps(repo_root: &Path, args: &RefreshBenchmarksArgs) -> Result<Vec<RefreshStep>> {
    let refresh_cli = refresh_front_door()?;
    let mut steps = Vec::new();

    if !args.skip_validate {
        steps.push(RefreshStep {
            id: "01_clippy",
            title: "Workspace clippy",
            command: vec![
                "cargo".to_string(),
                "clippy".to_string(),
                "--workspace".to_string(),
                "--all-targets".to_string(),
                "--".to_string(),
                "-D".to_string(),
                "warnings".to_string(),
            ],
            env: Vec::new(),
        });
        steps.push(RefreshStep {
            id: "02_tests",
            title: "Workspace tests",
            command: vec![
                "cargo".to_string(),
                "test".to_string(),
                "--workspace".to_string(),
            ],
            env: Vec::new(),
        });
    }

    let mut guardrails_freeze = refresh_cli.clone();
    guardrails_freeze.push("guardrails-freeze".to_string());
    if args.use_installed_cli {
        guardrails_freeze.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "03_guardrails_freeze",
        title: "Freeze guardrail holdouts",
        command: guardrails_freeze,
        env: Vec::new(),
    });

    let mut guardrails_build = refresh_cli.clone();
    guardrails_build.extend([
        "guardrails-build".to_string(),
        "--output-dir".to_string(),
        args.guardrail_bundle_dir.display().to_string(),
        "--target-goal".to_string(),
        observer_target_goal_name(&args.target_goal).to_string(),
    ]);
    if args.resume {
        guardrails_build.push("--resume".to_string());
    }
    if args.use_installed_cli {
        guardrails_build.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "04_guardrails_build",
        title: "Build guardrail bundle",
        command: guardrails_build,
        env: Vec::new(),
    });

    let mut guardrails_eval = refresh_cli.clone();
    guardrails_eval.extend([
        "guardrails-eval".to_string(),
        "--bundle-dir".to_string(),
        args.guardrail_bundle_dir.display().to_string(),
        "--output-dir".to_string(),
        args.guardrail_bundle_dir
            .join("open_benchmarks_final_holdout")
            .display()
            .to_string(),
        "--input-split".to_string(),
        "final_holdout".to_string(),
    ]);
    if let Some(sample_size) = args.guardrail_sample_size {
        guardrails_eval.push("--sample-size".to_string());
        guardrails_eval.push(sample_size.to_string());
    }
    if args.use_installed_cli {
        guardrails_eval.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "05_guardrails_eval",
        title: "Evaluate open guardrail benchmarks",
        command: guardrails_eval,
        env: Vec::new(),
    });

    let mut waf_cases = refresh_cli.clone();
    waf_cases.extend([
        "waf-cases".to_string(),
        "--output-dir".to_string(),
        args.waf_benchmark_dir.display().to_string(),
    ]);
    if args.use_installed_cli {
        waf_cases.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "06_waf_cases",
        title: "Build WAF benchmark cases",
        command: waf_cases,
        env: Vec::new(),
    });

    let mut waf_build = refresh_cli.clone();
    waf_build.extend([
        "waf-build".to_string(),
        "--output-dir".to_string(),
        args.waf_bundle_dir.display().to_string(),
        "--benchmark-dir".to_string(),
        args.waf_benchmark_dir.display().to_string(),
        "--refine".to_string(),
    ]);
    if args.resume {
        waf_build.push("--resume".to_string());
    }
    if !args.waf_skip_compile {
        waf_build.push("--compile".to_string());
    }
    if args.use_installed_cli {
        waf_build.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "07_waf_bundle",
        title: "Build learned WAF bundle",
        command: waf_build,
        env: Vec::new(),
    });

    let mut quality_report = refresh_cli;
    quality_report.extend([
        "quality-report".to_string(),
        "--guardrail-bundle-dir".to_string(),
        args.guardrail_bundle_dir.display().to_string(),
    ]);
    if args.use_installed_cli {
        quality_report.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "08_quality_report",
        title: "Refresh quality report",
        command: quality_report,
        env: Vec::new(),
    });

    let _ = repo_root;
    Ok(steps)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WafRefreshCache {
    version: String,
    inputs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WafObserverPatterns {
    sqli_patterns: Vec<String>,
    xss_patterns: Vec<String>,
    traversal_patterns: Vec<String>,
    server_include_patterns: Vec<String>,
    php_injection_patterns: Vec<String>,
    sensitive_route_patterns: Vec<String>,
    benign_patterns: Vec<String>,
    scanner_patterns: Vec<String>,
    sensitive_meta_markers: Vec<String>,
    sqli_meta_patterns: Vec<String>,
    xss_meta_patterns: Vec<String>,
    bad_bot_meta_patterns: Vec<String>,
    protocol_meta_patterns: Vec<String>,
    command_injection_meta_patterns: Vec<String>,
    php_injection_meta_patterns: Vec<String>,
    restricted_extensions: Vec<String>,
}

static WAF_OBSERVER_PATTERNS: OnceLock<WafObserverPatterns> = OnceLock::new();

fn cached_waf_observe(
    repo_root: &Path,
    dataset_jsonl: &Path,
    output: &Path,
    cache_path: &Path,
) -> Result<()> {
    let cache = WafRefreshCache {
        version: "1".to_string(),
        inputs: BTreeMap::from([
            ("dataset_sha256".to_string(), sha256_file(dataset_jsonl)?),
            (
                "observer_plugin_sha256".to_string(),
                sha256_file(&repo_root.join("examples/waf_edge/plugins/observer/plugin.py"))?,
            ),
            (
                "observer_patterns_sha256".to_string(),
                sha256_file(&repo_root.join("examples/waf_edge/plugins/observer/patterns.json"))?,
            ),
            (
                "route_patterns_sha256".to_string(),
                sha256_file(&repo_root.join("benchmarks/waf/route_patterns.json"))?,
            ),
        ]),
    };
    if output.exists()
        && cache_path.exists()
        && read_json::<WafRefreshCache>(cache_path).ok().as_ref() == Some(&cache)
    {
        return Ok(());
    }

    let config = load_waf_observer_patterns(repo_root)?.clone();
    let cases = load_benchmark_cases(dataset_jsonl)
        .into_diagnostic()
        .wrap_err("failed to load WAF benchmark cases for native observation")?;
    let worker_count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(cases.len().max(1));
    let chunk_size = cases.len().max(1).div_ceil(worker_count.max(1));
    let indexed_cases = cases
        .into_iter()
        .enumerate()
        .collect::<Vec<(usize, BenchmarkCase)>>();
    let mut handles = Vec::new();
    for chunk in indexed_cases.chunks(chunk_size.max(1)) {
        let config = config.clone();
        let owned_chunk = chunk.to_vec();
        handles.push(thread::spawn(
            move || -> Result<Vec<(usize, ObservedBenchmarkCase)>> {
                owned_chunk
                    .into_iter()
                    .map(|(index, case)| {
                        Ok((
                            index,
                            ObservedBenchmarkCase {
                                id: case.id,
                                input: case.input.clone(),
                                expected_route: case.expected_route,
                                category: case.category,
                                features: observe_waf_features(&config, &case.input)?,
                            },
                        ))
                    })
                    .collect::<Result<Vec<_>>>()
            },
        ));
    }
    let mut observed_rows = Vec::new();
    for handle in handles {
        let mut chunk_rows = handle
            .join()
            .map_err(|_| miette::miette!("native WAF observation worker panicked"))??;
        observed_rows.append(&mut chunk_rows);
    }
    observed_rows.sort_by_key(|(index, _)| *index);
    let mut writer = std::io::BufWriter::new(
        File::create(output)
            .into_diagnostic()
            .wrap_err("failed to create cached WAF observed output")?,
    );
    for (_, observed) in observed_rows {
        serde_json::to_writer(&mut writer, &observed).into_diagnostic()?;
        use std::io::Write as _;
        writer.write_all(b"\n").into_diagnostic()?;
    }
    use std::io::Write as _;
    writer.flush().into_diagnostic()?;
    write_json_pretty(cache_path, &serde_json::to_value(&cache).into_diagnostic()?)?;
    Ok(())
}

fn cached_emit_traces(
    repo_root: &Path,
    cli: &[String],
    observed_jsonl: &Path,
    trace_projection: &Path,
    output_dir: &Path,
    cache_path: &Path,
) -> Result<()> {
    let cache = WafRefreshCache {
        version: "1".to_string(),
        inputs: BTreeMap::from([
            ("observed_sha256".to_string(), sha256_file(observed_jsonl)?),
            (
                "trace_projection_sha256".to_string(),
                sha256_file(trace_projection)?,
            ),
        ]),
    };
    if output_dir.join("multi_target.csv").exists()
        && cache_path.exists()
        && read_json::<WafRefreshCache>(cache_path).ok().as_ref() == Some(&cache)
    {
        return Ok(());
    }
    run_json_command(
        repo_root,
        &build_nested_command(
            cli,
            &[
                "benchmark",
                "emit-traces",
                &observed_jsonl.display().to_string(),
                "--config",
                &trace_projection.display().to_string(),
                "--output-dir",
                &output_dir.display().to_string(),
                "--json",
            ],
        ),
    )?;
    write_json_pretty(cache_path, &serde_json::to_value(&cache).into_diagnostic()?)?;
    Ok(())
}

fn load_observed_benchmark_cases(path: &Path) -> Result<Vec<ObservedBenchmarkCase>> {
    let file = File::open(path).into_diagnostic()?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.into_diagnostic()?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        rows.push(
            serde_json::from_str(trimmed)
                .into_diagnostic()
                .wrap_err(format!(
                    "invalid observed benchmark JSON on line {}",
                    line_no + 1
                ))?,
        );
    }
    Ok(rows)
}

fn evaluate_waf_routes_from_observed(
    observed_cases: &[ObservedBenchmarkCase],
    freeze_dir: &Path,
    dataset_path: &Path,
    collapse_non_allow_to_deny: bool,
    output_path: &Path,
) -> Result<Value> {
    let injection_gate = LogicPearlGateIr::from_path(
        freeze_dir.join("artifacts/target_injection_payload/pearl.ir.json"),
    )
    .into_diagnostic()?;
    let sensitive_gate = LogicPearlGateIr::from_path(
        freeze_dir.join("artifacts/target_sensitive_surface/pearl.ir.json"),
    )
    .into_diagnostic()?;
    let suspicious_gate = LogicPearlGateIr::from_path(
        freeze_dir.join("artifacts/target_suspicious_request/pearl.ir.json"),
    )
    .into_diagnostic()?;

    let mut matched_cases = 0_usize;
    let mut attack_cases = 0_usize;
    let mut benign_cases = 0_usize;
    let mut caught_attacks = 0_usize;
    let mut benign_passes = 0_usize;
    let mut false_positives = 0_usize;
    let mut category_totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_matches: BTreeMap<String, usize> = BTreeMap::new();
    let mut cases = Vec::with_capacity(observed_cases.len());

    for observed in observed_cases {
        let features = observed
            .features
            .clone()
            .into_iter()
            .collect::<HashMap<_, _>>();
        let injection_payload = evaluate_gate(&injection_gate, &features).into_diagnostic()?;
        let sensitive_surface = evaluate_gate(&sensitive_gate, &features).into_diagnostic()?;
        let suspicious_request = evaluate_gate(&suspicious_gate, &features).into_diagnostic()?;
        let route_status =
            evaluate_waf_route_status(&injection_payload, &sensitive_surface, &suspicious_request);

        let actual_route = collapse_route(&route_status, collapse_non_allow_to_deny);
        let expected_route = collapse_route(&observed.expected_route, collapse_non_allow_to_deny);
        let matched = actual_route == expected_route;
        if matched {
            matched_cases += 1;
        }
        let is_attack = expected_route != "allow";
        if is_attack {
            attack_cases += 1;
            if actual_route != "allow" {
                caught_attacks += 1;
            }
        } else {
            benign_cases += 1;
            if actual_route == "allow" {
                benign_passes += 1;
            } else {
                false_positives += 1;
            }
        }
        if let Some(category) = &observed.category {
            *category_totals.entry(category.clone()).or_default() += 1;
            if matched {
                *category_matches.entry(category.clone()).or_default() += 1;
            }
        }
        cases.push(json!({
            "id": observed.id,
            "expected_route": expected_route,
            "actual_route": actual_route,
            "matched": matched,
            "category": observed.category,
        }));
    }

    let category_accuracy = category_totals
        .into_iter()
        .map(|(category, total)| {
            let matches = category_matches.get(&category).copied().unwrap_or(0);
            (category, matches as f64 / total.max(1) as f64)
        })
        .collect::<BTreeMap<_, _>>();
    let summary = json!({
        "total_cases": observed_cases.len(),
        "matched_cases": matched_cases,
        "exact_match_rate": matched_cases as f64 / observed_cases.len().max(1) as f64,
        "attack_cases": attack_cases,
        "benign_cases": benign_cases,
        "attack_catch_rate": caught_attacks as f64 / attack_cases.max(1) as f64,
        "benign_pass_rate": benign_passes as f64 / benign_cases.max(1) as f64,
        "false_positive_rate": false_positives as f64 / benign_cases.max(1) as f64,
        "category_accuracy": category_accuracy,
    });
    let payload = json!({
        "pipeline_id": "waf_edge_learned_v1",
        "dataset_path": dataset_path.display().to_string(),
        "summary": summary,
        "cases": cases,
    });
    write_json_pretty(output_path, &payload)?;
    Ok(payload)
}

fn evaluate_waf_route_status(
    injection_payload: &logicpearl_core::RuleMask,
    sensitive_surface: &logicpearl_core::RuleMask,
    suspicious_request: &logicpearl_core::RuleMask,
) -> String {
    let allow =
        injection_payload.is_zero() && sensitive_surface.is_zero() && suspicious_request.is_zero();

    if allow {
        "allow".to_string()
    } else if !injection_payload.is_zero() {
        "deny_injection_payload".to_string()
    } else if !sensitive_surface.is_zero() {
        "deny_sensitive_surface".to_string()
    } else if !suspicious_request.is_zero() {
        "review_suspicious_request".to_string()
    } else {
        "deny".to_string()
    }
}

fn collapse_route(route: &str, collapse_non_allow_to_deny: bool) -> String {
    if collapse_non_allow_to_deny && route != "allow" {
        "deny".to_string()
    } else {
        route.to_string()
    }
}

fn load_waf_observer_patterns(repo_root: &Path) -> Result<&'static WafObserverPatterns> {
    if let Some(config) = WAF_OBSERVER_PATTERNS.get() {
        return Ok(config);
    }
    let config: WafObserverPatterns = serde_json::from_str(
        &fs::read_to_string(repo_root.join("examples/waf_edge/plugins/observer/patterns.json"))
            .into_diagnostic()?,
    )
    .into_diagnostic()?;
    let _ = WAF_OBSERVER_PATTERNS.set(config);
    WAF_OBSERVER_PATTERNS
        .get()
        .ok_or_else(|| miette::miette!("failed to initialize WAF observer patterns"))
}

fn observe_waf_features(
    config: &WafObserverPatterns,
    raw_input: &Value,
) -> Result<Map<String, Value>> {
    let object = raw_input
        .as_object()
        .ok_or_else(|| miette::miette!("WAF observer expects object input"))?;
    let path = normalize_waf_text(object.get("path"));
    let source_zone = normalize_waf_text(object.get("source_zone"));
    let raw_request = normalize_waf_text(object.get("raw_request"));
    let modsecurity_meta = normalize_waf_text(object.get("modsecurity_meta"));
    let headers = object
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let query = object
        .get("query")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let body = object
        .get("body")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let tenant_scope = normalize_waf_text(headers.get("tenant_scope"));
    let user_agent = normalize_waf_text(
        headers
            .get("user_agent")
            .or_else(|| headers.get("user-agent")),
    );
    let query_text = flatten_waf_text_value(&Value::Object(query.clone()));
    let body_text = flatten_waf_text_value(&Value::Object(body.clone()));
    let combined_text = [
        path.as_str(),
        query_text.as_str(),
        body_text.as_str(),
        tenant_scope.as_str(),
        user_agent.as_str(),
        raw_request.as_str(),
        modsecurity_meta.as_str(),
    ]
    .iter()
    .filter(|value| !value.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join(" ");

    let contains_sqli_signature = contains_any_text(&combined_text, &config.sqli_patterns);
    let contains_xss_signature = contains_any_text(&combined_text, &config.xss_patterns);
    let contains_path_traversal = contains_any_text(&combined_text, &config.traversal_patterns);
    let contains_server_include =
        contains_any_text(&combined_text, &config.server_include_patterns);
    let contains_php_injection = contains_any_text(&combined_text, &config.php_injection_patterns);
    let sqli_marker_count = count_matches_text(&combined_text, &config.sqli_patterns);
    let xss_marker_count = count_matches_text(&combined_text, &config.xss_patterns);
    let traversal_marker_count = count_matches_text(&combined_text, &config.traversal_patterns);
    let php_injection_marker_count =
        count_matches_text(&combined_text, &config.php_injection_patterns);
    let sensitive_route_marker_count = count_matches_text(&path, &config.sensitive_route_patterns);
    let scanner_marker_count = count_matches_text(&user_agent, &config.scanner_patterns);
    let targets_sensitive_route = path.starts_with("/admin")
        || path.starts_with("/internal")
        || contains_any_text(&path, &config.sensitive_route_patterns)
        || contains_any_text(&combined_text, &config.sensitive_meta_markers);
    let path_targets_admin = path.starts_with("/admin") || path.starts_with("/internal");
    let path_targets_hidden = ["/.git", "/.env", "/phpmyadmin", "/wp-admin"]
        .iter()
        .any(|marker| path.contains(marker));
    let contains_restricted_extension = config
        .restricted_extensions
        .iter()
        .any(|ext| path.ends_with(ext));
    let origin_outside_trust_zone =
        source_zone == "public_web" || source_zone == "untrusted_browser";
    let has_scanner_fingerprint = contains_any_text(&user_agent, &config.scanner_patterns)
        || path == "/.env"
        || path == "/wp-admin/install.php"
        || path == "/phpmyadmin";
    let has_malformed_encoding = combined_text.contains("%25")
        || combined_text.contains("%2f%2e")
        || combined_text.contains("%%");
    let meta_reports_sqli = contains_any_text(&modsecurity_meta, &config.sqli_meta_patterns);
    let meta_reports_xss = contains_any_text(&modsecurity_meta, &config.xss_meta_patterns);
    let meta_reports_restricted_resource =
        contains_any_text(&modsecurity_meta, &config.sensitive_meta_markers);
    let meta_reports_bad_bot = contains_any_text(&modsecurity_meta, &config.bad_bot_meta_patterns);
    let meta_reports_protocol_violation =
        contains_any_text(&modsecurity_meta, &config.protocol_meta_patterns);
    let meta_reports_command_injection =
        contains_any_text(&modsecurity_meta, &config.command_injection_meta_patterns);
    let meta_reports_php_injection =
        contains_any_text(&modsecurity_meta, &config.php_injection_meta_patterns);
    let contains_waitfor_delay =
        combined_text.contains("waitfor delay") || combined_text.contains("sleep(");
    let contains_union_select = combined_text.contains("union select");
    let contains_quote = combined_text.contains('\'') || combined_text.contains('"');
    let contains_comment_sequence = combined_text.contains("--")
        || combined_text.contains("/*")
        || combined_text.contains("*/")
        || combined_text.contains('#');
    let contains_script_tag =
        combined_text.contains("<script") || combined_text.contains("javascript:");
    let contains_event_handler =
        combined_text.contains("onerror=") || combined_text.contains("onload=");
    let contains_dotdot = combined_text.contains("../")
        || combined_text.contains("..\\")
        || combined_text.contains("%2e%2e");
    let request_has_query = !query.is_empty();
    let request_has_body = !body.is_empty();
    let path_depth = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count() as i64;
    let query_key_count = query.len() as i64;
    let body_key_count = body.len() as i64;
    let percent_encoding_count = raw_request.matches('%').count() as i64;
    let suspicious_token_count = [
        contains_sqli_signature,
        contains_xss_signature,
        contains_path_traversal,
        contains_server_include,
        contains_php_injection,
        targets_sensitive_route,
        has_scanner_fingerprint,
        has_malformed_encoding,
        meta_reports_sqli,
        meta_reports_xss,
        meta_reports_restricted_resource,
        meta_reports_bad_bot,
        meta_reports_protocol_violation,
        meta_reports_command_injection,
        meta_reports_php_injection,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count() as i64;
    let likely_benign_request = contains_any_text(&combined_text, &config.benign_patterns)
        && !contains_sqli_signature
        && !contains_xss_signature
        && !contains_path_traversal
        && !targets_sensitive_route;
    let mut risk_score = 0.03_f64;
    if contains_sqli_signature {
        risk_score += 0.24;
    }
    if contains_xss_signature {
        risk_score += 0.22;
    }
    if contains_path_traversal {
        risk_score += 0.24;
    }
    if contains_server_include {
        risk_score += 0.20;
    }
    if contains_php_injection {
        risk_score += 0.24;
    }
    if targets_sensitive_route {
        risk_score += 0.14;
    }
    if origin_outside_trust_zone {
        risk_score += 0.10;
    }
    if has_scanner_fingerprint {
        risk_score += 0.46;
    }
    if has_malformed_encoding {
        risk_score += 0.28;
    }
    if meta_reports_command_injection {
        risk_score += 0.28;
    }
    if meta_reports_php_injection {
        risk_score += 0.24;
    }
    if likely_benign_request {
        risk_score = risk_score.min(0.12);
    }
    risk_score = (risk_score.clamp(0.0, 1.0) * 100.0).round() / 100.0;

    Ok(Map::from_iter([
        (
            "contains_sqli_signature".to_string(),
            Value::Bool(contains_sqli_signature),
        ),
        (
            "contains_xss_signature".to_string(),
            Value::Bool(contains_xss_signature),
        ),
        (
            "contains_path_traversal".to_string(),
            Value::Bool(contains_path_traversal),
        ),
        (
            "contains_server_include".to_string(),
            Value::Bool(contains_server_include),
        ),
        (
            "contains_php_injection".to_string(),
            Value::Bool(contains_php_injection),
        ),
        (
            "sqli_marker_count".to_string(),
            Value::from(sqli_marker_count),
        ),
        (
            "xss_marker_count".to_string(),
            Value::from(xss_marker_count),
        ),
        (
            "traversal_marker_count".to_string(),
            Value::from(traversal_marker_count),
        ),
        (
            "php_injection_marker_count".to_string(),
            Value::from(php_injection_marker_count),
        ),
        (
            "contains_waitfor_delay".to_string(),
            Value::Bool(contains_waitfor_delay),
        ),
        (
            "contains_union_select".to_string(),
            Value::Bool(contains_union_select),
        ),
        ("contains_quote".to_string(), Value::Bool(contains_quote)),
        (
            "contains_comment_sequence".to_string(),
            Value::Bool(contains_comment_sequence),
        ),
        (
            "contains_script_tag".to_string(),
            Value::Bool(contains_script_tag),
        ),
        (
            "contains_event_handler".to_string(),
            Value::Bool(contains_event_handler),
        ),
        ("contains_dotdot".to_string(), Value::Bool(contains_dotdot)),
        (
            "targets_sensitive_route".to_string(),
            Value::Bool(targets_sensitive_route),
        ),
        (
            "sensitive_route_marker_count".to_string(),
            Value::from(sensitive_route_marker_count),
        ),
        (
            "path_targets_admin".to_string(),
            Value::Bool(path_targets_admin),
        ),
        (
            "path_targets_hidden".to_string(),
            Value::Bool(path_targets_hidden),
        ),
        (
            "contains_restricted_extension".to_string(),
            Value::Bool(contains_restricted_extension),
        ),
        (
            "origin_outside_trust_zone".to_string(),
            Value::Bool(origin_outside_trust_zone),
        ),
        (
            "has_scanner_fingerprint".to_string(),
            Value::Bool(has_scanner_fingerprint),
        ),
        (
            "scanner_marker_count".to_string(),
            Value::from(scanner_marker_count),
        ),
        (
            "has_malformed_encoding".to_string(),
            Value::Bool(has_malformed_encoding),
        ),
        (
            "meta_reports_sqli".to_string(),
            Value::Bool(meta_reports_sqli),
        ),
        (
            "meta_reports_xss".to_string(),
            Value::Bool(meta_reports_xss),
        ),
        (
            "meta_reports_restricted_resource".to_string(),
            Value::Bool(meta_reports_restricted_resource),
        ),
        (
            "meta_reports_bad_bot".to_string(),
            Value::Bool(meta_reports_bad_bot),
        ),
        (
            "meta_reports_protocol_violation".to_string(),
            Value::Bool(meta_reports_protocol_violation),
        ),
        (
            "meta_reports_command_injection".to_string(),
            Value::Bool(meta_reports_command_injection),
        ),
        (
            "meta_reports_php_injection".to_string(),
            Value::Bool(meta_reports_php_injection),
        ),
        (
            "request_has_query".to_string(),
            Value::Bool(request_has_query),
        ),
        (
            "request_has_body".to_string(),
            Value::Bool(request_has_body),
        ),
        ("path_depth".to_string(), Value::from(path_depth)),
        ("query_key_count".to_string(), Value::from(query_key_count)),
        ("body_key_count".to_string(), Value::from(body_key_count)),
        (
            "percent_encoding_count".to_string(),
            Value::from(percent_encoding_count),
        ),
        (
            "suspicious_token_count".to_string(),
            Value::from(suspicious_token_count),
        ),
        (
            "likely_benign_request".to_string(),
            Value::Bool(likely_benign_request),
        ),
        ("risk_score".to_string(), Value::from(risk_score)),
    ]))
}

fn normalize_waf_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let decoded = decode_plus(value.as_str().unwrap_or(&value.to_string()));
    decoded
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn flatten_waf_text_value(value: &Value) -> String {
    let mut parts = Vec::new();
    flatten_waf_value_into(value, &mut parts);
    parts.join(" ")
}

fn flatten_waf_value_into(value: &Value, parts: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                let key_text = normalize_waf_text(Some(&Value::String(key.clone())));
                if !key_text.is_empty() {
                    parts.push(key_text);
                }
                if let Some(child) = object.get(&key) {
                    flatten_waf_value_into(child, parts);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                flatten_waf_value_into(item, parts);
            }
        }
        Value::Null => {}
        other => {
            let text = normalize_waf_text(Some(other));
            if !text.is_empty() {
                parts.push(text);
            }
        }
    }
}

fn decode_plus(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = decode_hex(bytes[index + 1]);
                let lo = decode_hex(bytes[index + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    decoded.push((hi << 4) | lo);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn contains_any_text(text: &str, phrases: &[String]) -> bool {
    phrases.iter().any(|phrase| text.contains(phrase))
}

fn count_matches_text(text: &str, phrases: &[String]) -> i64 {
    phrases
        .iter()
        .filter(|phrase| text.contains(phrase.as_str()))
        .count() as i64
}

fn datasets_root_from_args(repo_root: &Path, value: Option<&PathBuf>) -> PathBuf {
    value
        .cloned()
        .or_else(|| std::env::var(DEFAULT_DATASETS_ENV).ok().map(PathBuf::from))
        .unwrap_or_else(|| repo_root.parent().unwrap().join("datasets").join("public"))
}

fn guardrail_split_dir(datasets_root: &Path, spec: GuardrailDatasetSpec) -> PathBuf {
    let parent = datasets_root
        .join(spec.raw_rel)
        .parent()
        .unwrap()
        .to_path_buf();
    parent.join("logicpearl_splits").join(spec.dataset_id)
}

fn route_stratified_sample_cases(rows: &[BenchmarkCase], max_cases: usize) -> SampledCases {
    if max_cases == 0 || rows.len() <= max_cases {
        let mut route_counts = BTreeMap::new();
        for row in rows {
            *route_counts
                .entry(row.expected_route.clone())
                .or_insert(0usize) += 1;
        }
        return SampledCases {
            rows: rows.to_vec(),
            report: json!({
                "sampled": false,
                "input_count": rows.len(),
                "output_count": rows.len(),
                "route_counts": route_counts,
            }),
        };
    }

    let mut grouped: BTreeMap<String, Vec<BenchmarkCase>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry(row.expected_route.clone())
            .or_default()
            .push(row.clone());
    }
    for bucket in grouped.values_mut() {
        bucket.sort_by_key(|row| stable_case_sort_key(&row.id));
    }

    let total_rows = rows.len();
    let mut allocations = BTreeMap::new();
    let mut remainders = Vec::new();
    let mut allocated = 0usize;
    for (route, bucket) in &grouped {
        let exact = max_cases as f64 * (bucket.len() as f64 / total_rows as f64);
        let base = bucket.len().min(exact as usize);
        allocations.insert(route.clone(), base);
        allocated += base;
        remainders.push((exact - base as f64, route.clone()));
    }
    if max_cases >= grouped.len() {
        for (route, bucket) in &grouped {
            if allocations.get(route).copied().unwrap_or(0) == 0 && !bucket.is_empty() {
                allocations.insert(route.clone(), 1);
                allocated += 1;
            }
        }
    }
    if allocated > max_cases {
        let mut routes = allocations
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(route, count)| (*count, route.clone()))
            .collect::<Vec<_>>();
        routes.sort_by(|left, right| right.cmp(left));
        for (_, route) in routes {
            while allocations.get(&route).copied().unwrap_or(0) > 1 && allocated > max_cases {
                if let Some(count) = allocations.get_mut(&route) {
                    *count -= 1;
                    allocated -= 1;
                }
            }
            if allocated <= max_cases {
                break;
            }
        }
    }
    remainders.sort_by(|left, right| right.partial_cmp(left).unwrap());
    for (_, route) in remainders {
        if allocated >= max_cases {
            break;
        }
        let current = allocations.get(&route).copied().unwrap_or(0);
        if current >= grouped.get(&route).map(Vec::len).unwrap_or(0) {
            continue;
        }
        allocations.insert(route, current + 1);
        allocated += 1;
    }

    let mut sampled = Vec::new();
    for (route, bucket) in &grouped {
        sampled.extend(
            bucket
                .iter()
                .take(allocations.get(route).copied().unwrap_or(0))
                .cloned(),
        );
    }
    sampled.sort_by_key(|row| stable_case_sort_key(&row.id));

    let mut input_counts = BTreeMap::new();
    let mut output_counts = BTreeMap::new();
    for row in rows {
        *input_counts
            .entry(row.expected_route.clone())
            .or_insert(0usize) += 1;
    }
    for row in &sampled {
        *output_counts
            .entry(row.expected_route.clone())
            .or_insert(0usize) += 1;
    }

    let output_count = sampled.len();
    SampledCases {
        rows: sampled,
        report: json!({
            "sampled": true,
            "input_count": rows.len(),
            "output_count": output_count,
            "max_cases": max_cases,
            "input_route_counts": input_counts,
            "output_route_counts": output_counts,
        }),
    }
}

struct SampledCases {
    rows: Vec<BenchmarkCase>,
    report: Value,
}

fn stable_case_sort_key(case_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(case_id.as_bytes());
    format!("{}:{case_id}", hex::encode(hasher.finalize()))
}

fn build_guardrails_combined_pearl(
    artifact_set_path: &Path,
    output_path: &Path,
    route_policy_path: &Path,
    source_commit: &str,
) -> Result<()> {
    let artifact_set: ArtifactSet = read_json(artifact_set_path)?;
    let artifact_dir = artifact_set_path
        .parent()
        .ok_or_else(|| miette::miette!("artifact set path has no parent"))?;

    let route_rules_by_target = GUARDRAIL_ROUTE_RULES
        .iter()
        .map(|rule| (rule.target, rule))
        .collect::<HashMap<_, _>>();

    let mut combined_features = Vec::new();
    let mut seen_features = BTreeSet::new();
    let mut combined_rules = Vec::new();

    for descriptor in &artifact_set.binary_targets {
        let Some(route_rule) = route_rules_by_target.get(descriptor.name.as_str()) else {
            continue;
        };
        let gate = LogicPearlGateIr::from_path(artifact_dir.join(&descriptor.artifact))
            .into_diagnostic()?;
        for feature in gate.input_schema.features {
            if seen_features.insert(feature.id.clone()) {
                combined_features.push(feature);
            }
        }
        for mut gate_rule in gate.rules {
            gate_rule.id = format!("{}__{}", descriptor.name, gate_rule.id);
            gate_rule.bit = combined_rules.len() as u32;
            gate_rule.label = Some(route_rule.label.to_string());
            gate_rule.message = Some(route_rule.message.to_string());
            gate_rule.counterfactual_hint = Some(route_rule.counterfactual_hint.to_string());
            combined_rules.push(gate_rule);
        }
    }

    let mut ordered_features = Vec::new();
    let mut appended = BTreeSet::new();
    for feature_id in &artifact_set.features {
        if let Some(feature) = combined_features
            .iter()
            .find(|feature| feature.id == *feature_id)
        {
            ordered_features.push(feature.clone());
            appended.insert(feature.id.clone());
        }
    }
    for feature in combined_features {
        if appended.insert(feature.id.clone()) {
            ordered_features.push(feature);
        }
    }

    let gate = LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: "guardrails_combined".to_string(),
        gate_type: GateType::BitmaskGate,
        input_schema: logicpearl_ir::InputSchema {
            features: ordered_features,
        },
        rules: combined_rules,
        evaluation: EvaluationConfig {
            combine: CombineStrategy::BitwiseOr,
            allow_when_bitmask: 0,
        },
        verification: Some(VerificationConfig {
            domain_constraints: None,
            correctness_scope: Some(
                "derived by merging frozen guardrail target pearls".to_string(),
            ),
            verification_summary: Some(HashMap::from([(
                "pipeline_unverified".to_string(),
                artifact_set.binary_targets.len() as u64,
            )])),
        }),
        provenance: Some(Provenance {
            generator: Some("cargo xtask guardrails-build".to_string()),
            generator_version: Some("0.1.0".to_string()),
            source_commit: Some(source_commit.to_string()),
            created_at: None,
        }),
    };
    gate.write_pretty(output_path).into_diagnostic()?;

    let route_policy = json!({
        "route_policy_version": "1.0",
        "policy_id": "guardrails_route_policy_v1",
        "default_route": "allow",
        "rules": GUARDRAIL_ROUTE_RULES.iter().map(|rule| json!({
            "target": rule.target,
            "route_status": rule.route_status,
            "label": rule.label,
            "message": rule.message,
            "counterfactual_hint": rule.counterfactual_hint,
        })).collect::<Vec<_>>(),
        "collapse_non_allow_to": "deny",
    });
    write_json_pretty(route_policy_path, &route_policy)?;
    Ok(())
}

fn detect_bundle_target_goal(bundle_dir: &Path) -> Result<String> {
    let manifest_path = bundle_dir.join("bundle_manifest.json");
    if !manifest_path.exists() {
        return Ok("parity-first".to_string());
    }
    let manifest: Value = read_json(&manifest_path)?;
    Ok(canonical_target_goal(
        manifest["observer_target_goal"]
            .as_str()
            .unwrap_or("parity-first"),
    ))
}

fn canonical_target_goal(value: &str) -> String {
    value.trim().to_lowercase().replace('_', "-")
}

fn compare_against_baseline(aggregate: &[Value], baseline: &Value, tolerance: f64) -> Vec<String> {
    let mut failures = Vec::new();
    let expected = baseline["benchmarks"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for item in aggregate {
        let benchmark_id = item["benchmark"].as_str().unwrap_or_default();
        let Some(baseline_summary) = expected.get(benchmark_id) else {
            continue;
        };
        let summary = &item["summary"];
        for metric in ["exact_match_rate", "attack_catch_rate", "benign_pass_rate"] {
            let actual = summary[metric].as_f64().unwrap_or(0.0);
            let expected = baseline_summary[metric].as_f64().unwrap_or(0.0);
            if actual + tolerance < expected {
                failures.push(format!(
                    "{benchmark_id} {metric} regressed: {actual:.6} < {expected:.6}"
                ));
            }
        }
        let actual_fp = summary["false_positive_rate"].as_f64().unwrap_or(0.0);
        let expected_fp = baseline_summary["false_positive_rate"]
            .as_f64()
            .unwrap_or(0.0);
        if actual_fp - tolerance > expected_fp {
            failures.push(format!(
                "{benchmark_id} false_positive_rate regressed: {actual_fp:.6} > {expected_fp:.6}"
            ));
        }
    }
    failures
}

struct GuardrailEvalRun<'a> {
    repo_root: &'a Path,
    bundle_dir: &'a Path,
    output_dir: &'a Path,
    cli: &'a [String],
    input_split: &'a str,
    sample_size: usize,
}

fn evaluate_guardrail_benchmark(
    run: &GuardrailEvalRun<'_>,
    benchmark: GuardrailExternalBenchmark,
    benchmark_input: &Path,
) -> Result<Value> {
    let benchmark_output_dir = run.output_dir.join(benchmark.id);
    fs::create_dir_all(&benchmark_output_dir).into_diagnostic()?;
    let cases_path = benchmark_output_dir.join("cases.jsonl");

    let adapt_report = if run.input_split == "raw" {
        run_json_command(
            run.repo_root,
            &build_nested_command(
                run.cli,
                &[
                    "benchmark",
                    "adapt",
                    &benchmark_input.display().to_string(),
                    "--profile",
                    benchmark.profile,
                    "--output",
                    &cases_path.display().to_string(),
                    "--json",
                ],
            ),
        )?
    } else {
        fs::copy(benchmark_input, &cases_path).into_diagnostic()?;
        json!({
            "mode": "pass_through_cases_jsonl",
            "input": benchmark_input.display().to_string(),
            "output": cases_path.display().to_string(),
        })
    };

    let original_cases = load_benchmark_cases(&cases_path).into_diagnostic()?;
    let sampled_cases = sample_cases_for_eval(&original_cases, run.sample_size);
    let sampled = sampled_cases.len() != original_cases.len();
    let cases_path = if sampled {
        let sampled_path = benchmark_output_dir.join("cases.sampled.jsonl");
        write_benchmark_cases_jsonl(&sampled_cases, &sampled_path).into_diagnostic()?;
        sampled_path
    } else {
        cases_path
    };

    let observer_artifact = run
        .bundle_dir
        .join("freeze")
        .join("guardrails_v1.observer.json");
    let observed_path = benchmark_output_dir.join("observed.jsonl");
    let observe_report = run_json_command(
        run.repo_root,
        &build_nested_command(
            run.cli,
            &[
                "benchmark",
                "observe",
                &cases_path.display().to_string(),
                "--observer-artifact",
                &observer_artifact.display().to_string(),
                "--output",
                &observed_path.display().to_string(),
                "--json",
            ],
        ),
    )?;
    let traces_dir = benchmark_output_dir.join("traces");
    let emit_report = run_json_command(
        run.repo_root,
        &build_nested_command(
            run.cli,
            &[
                "benchmark",
                "emit-traces",
                &observed_path.display().to_string(),
                "--config",
                &run.repo_root
                    .join(TRACE_PROJECTION_GUARDRAILS)
                    .display()
                    .to_string(),
                "--output-dir",
                &traces_dir.display().to_string(),
                "--json",
            ],
        ),
    )?;

    let cases = load_benchmark_cases(&cases_path).into_diagnostic()?;
    let case_by_id = cases
        .into_iter()
        .map(|case| (case.id.clone(), case))
        .collect::<HashMap<_, _>>();
    let observed_cases: Vec<ObservedBenchmarkCase> = read_jsonl_rows(&observed_path)?;
    let combined_pearl = LogicPearlGateIr::from_path(
        run.bundle_dir
            .join("freeze")
            .join("guardrails_combined.pearl.ir.json"),
    )
    .into_diagnostic()?;
    let route_policy: Value = read_json(&run.bundle_dir.join("freeze").join("route_policy.json"))?;
    let collapse_non_allow_to = route_policy["collapse_non_allow_to"]
        .as_str()
        .unwrap_or("deny");

    let mut total_cases = 0usize;
    let mut matched_cases = 0usize;
    let mut attack_cases = 0usize;
    let mut benign_cases = 0usize;
    let mut caught_attacks = 0usize;
    let mut benign_passes = 0usize;
    let mut false_positives = 0usize;
    let mut route_distribution = BTreeMap::new();
    let mut case_results = Vec::new();

    for observed in observed_cases {
        let case = case_by_id
            .get(&observed.id)
            .ok_or_else(|| miette::miette!("missing benchmark case id {}", observed.id))?;
        let features = observed
            .features
            .clone()
            .into_iter()
            .collect::<HashMap<_, _>>();
        let bitmask = evaluate_gate(&combined_pearl, &features).into_diagnostic()?;
        let fired_rules = combined_pearl
            .rules
            .iter()
            .filter(|rule| bitmask.test_bit(rule.bit))
            .collect::<Vec<_>>();
        let route_status = derive_route(&route_policy, &fired_rules);
        let actual_route = if route_status == "allow" {
            "allow".to_string()
        } else {
            collapse_non_allow_to.to_string()
        };
        let matched = actual_route == case.expected_route;
        total_cases += 1;
        matched_cases += usize::from(matched);
        *route_distribution
            .entry(route_status.clone())
            .or_insert(0usize) += 1;
        if case.expected_route == "deny" {
            attack_cases += 1;
            caught_attacks += usize::from(actual_route == "deny");
        } else {
            benign_cases += 1;
            benign_passes += usize::from(actual_route == "allow");
            false_positives += usize::from(actual_route != "allow");
        }
        case_results.push(json!({
            "id": observed.id,
            "category": case.category,
            "expected_route": case.expected_route,
            "actual_route": actual_route,
            "route_status": route_status,
            "matched": matched,
            "bitmask": bitmask.to_json_value(),
            "fired_rules": fired_rules.into_iter().map(|rule| json!({
                "id": rule.id,
                "label": rule.label,
                "message": rule.message,
                "counterfactual_hint": rule.counterfactual_hint,
            })).collect::<Vec<_>>(),
        }));
    }

    let report = json!({
        "bundle_id": read_json::<Value>(&run.bundle_dir.join("bundle_manifest.json"))?["bundle_id"].clone(),
        "benchmark_profile": benchmark.profile,
        "input_format": if run.input_split == "raw" { "raw" } else { "cases-jsonl" },
        "raw_benchmark": benchmark_input.display().to_string(),
        "adapt_report": adapt_report,
        "observe_report": observe_report,
        "emit_report": emit_report,
        "compiled_pearl": {
            "path": run.bundle_dir.join("freeze").join("guardrails_combined.pearl").display().to_string(),
            "used": false
        },
        "summary": {
            "total_cases": total_cases,
            "sampled": sampled,
            "sample_size": if sampled { run.sample_size } else { total_cases },
            "matched_cases": matched_cases,
            "exact_match_rate": ratio(matched_cases, total_cases),
            "attack_cases": attack_cases,
            "benign_cases": benign_cases,
            "attack_catch_rate": ratio(caught_attacks, attack_cases),
            "benign_pass_rate": ratio(benign_passes, benign_cases),
            "false_positive_rate": ratio(false_positives, benign_cases),
            "route_distribution": route_distribution,
        },
        "cases": case_results,
    });
    write_json_pretty(
        &benchmark_output_dir.join("evaluation_report.json"),
        &report,
    )?;
    Ok(json!({
        "benchmark": benchmark.id,
        "profile": benchmark.profile,
        "path": benchmark_input.display().to_string(),
        "input_split": run.input_split,
        "report_path": benchmark_output_dir.join("evaluation_report.json").display().to_string(),
        "summary": report["summary"].clone(),
    }))
}

fn sample_cases_for_eval(cases: &[BenchmarkCase], sample_size: usize) -> Vec<BenchmarkCase> {
    if sample_size == 0 || cases.len() <= sample_size {
        return cases.to_vec();
    }
    let mut by_route: BTreeMap<String, Vec<BenchmarkCase>> = BTreeMap::new();
    for case in cases {
        by_route
            .entry(case.expected_route.clone())
            .or_default()
            .push(case.clone());
    }

    let mut selected = Vec::new();
    let mut remaining_budget = sample_size;
    let mut remaining_groups = by_route.len().max(1);
    for route_cases in by_route.values_mut() {
        route_cases.sort_by_key(|case| deterministic_bucket(&case.id));
        let quota = (remaining_budget / remaining_groups)
            .max(1)
            .min(route_cases.len());
        selected.extend(route_cases.iter().take(quota).cloned());
        remaining_budget = remaining_budget.saturating_sub(quota);
        remaining_groups = remaining_groups.saturating_sub(1).max(1);
    }
    if selected.len() < sample_size {
        let selected_ids = selected
            .iter()
            .map(|case| case.id.clone())
            .collect::<BTreeSet<_>>();
        let mut leftovers = cases
            .iter()
            .filter(|case| !selected_ids.contains(&case.id))
            .cloned()
            .collect::<Vec<_>>();
        leftovers.sort_by_key(|case| deterministic_bucket(&case.id));
        selected.extend(leftovers.into_iter().take(sample_size - selected.len()));
    }
    selected.sort_by_key(|case| deterministic_bucket(&case.id));
    selected
}

fn deterministic_bucket(key: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let bytes = hasher.finalize();
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}

fn derive_route(route_policy: &Value, fired_rules: &[&logicpearl_ir::RuleDefinition]) -> String {
    let labels = fired_rules
        .iter()
        .filter_map(|rule| rule.label.clone())
        .collect::<BTreeSet<_>>();
    for route_rule in route_policy["rules"].as_array().unwrap_or(&Vec::new()) {
        if let Some(label) = route_rule["label"].as_str() {
            if labels.contains(label) {
                return route_rule["route_status"]
                    .as_str()
                    .unwrap_or("allow")
                    .to_string();
            }
        }
    }
    route_policy["default_route"]
        .as_str()
        .unwrap_or("allow")
        .to_string()
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[allow(clippy::too_many_arguments)]
fn build_waf_target_artifact_set(
    repo_root: &Path,
    cli: &[String],
    train_traces_dir: &Path,
    discovered_dir: &Path,
    refine: bool,
    skip_compile: bool,
    feature_governance: &Path,
) -> Result<ArtifactSet> {
    let artifacts_dir = discovered_dir.join("artifacts");
    fs::create_dir_all(&artifacts_dir).into_diagnostic()?;
    let mut descriptors = Vec::new();
    let mut build_reports = Vec::new();

    let commands = WAF_TARGETS
        .iter()
        .map(|(target, trace_file, decision_mode)| {
            let trace_path = train_traces_dir.join(trace_file);
            let target_output_dir = artifacts_dir.join(target);
            let mut command = build_nested_command(
                cli,
                &[
                    "build",
                    &trace_path.display().to_string(),
                    "--gate-id",
                    target,
                    "--label-column",
                    "allowed",
                    "--output-dir",
                    &target_output_dir.display().to_string(),
                    "--feature-governance",
                    &feature_governance.display().to_string(),
                    "--discovery-mode",
                    decision_mode,
                    "--json",
                ],
            );
            if refine {
                command.push("--refine".to_string());
            }
            if !skip_compile {
                command.push("--compile".to_string());
            }
            ((*target).to_string(), command)
        })
        .collect::<Vec<_>>();
    for (target, build_report) in run_json_commands_parallel(repo_root, commands)? {
        build_reports.push(build_report);
        descriptors.push(logicpearl_discovery::ArtifactDescriptor {
            name: target.clone(),
            artifact: Path::new("artifacts")
                .join(target)
                .join("pearl.ir.json")
                .display()
                .to_string(),
        });
    }

    let trace_projection: Value = read_json(&repo_root.join(TRACE_PROJECTION_WAF))?;
    let artifact_set = ArtifactSet {
        artifact_set_version: "1.0".to_string(),
        artifact_set_id: "waf_learned_artifact_set".to_string(),
        features: trace_projection["feature_columns"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        binary_targets: descriptors,
    };
    let discover_report = json!({
        "source_csv": train_traces_dir.join("multi_target.csv").display().to_string(),
        "artifact_set_id": artifact_set.artifact_set_id,
        "rows": build_reports.iter().map(|report| report["rows"].as_u64().unwrap_or(0)).sum::<u64>() / build_reports.len().max(1) as u64,
        "features": artifact_set.features,
        "targets": WAF_TARGETS
            .iter()
            .map(|(target, _, _)| *target)
            .collect::<Vec<_>>(),
        "cached_artifacts": build_reports.iter().filter(|report| report["cache_hit"].as_bool().unwrap_or(false)).count(),
        "cache_hit": build_reports.iter().all(|report| report["cache_hit"].as_bool().unwrap_or(false)),
        "artifacts": build_reports,
        "skipped_targets": [],
        "output_files": {
            "artifact_set": discovered_dir.join("artifact_set.json").display().to_string(),
            "discover_report": discovered_dir.join("discover_report.json").display().to_string(),
        }
    });
    write_json_pretty(
        &discovered_dir.join("artifact_set.json"),
        &serde_json::to_value(&artifact_set).into_diagnostic()?,
    )?;
    write_json_pretty(
        &discovered_dir.join("discover_report.json"),
        &discover_report,
    )?;
    Ok(artifact_set)
}

fn build_waf_learned_pipeline(
    artifact_set: &ArtifactSet,
    observer_manifest_path: &Path,
    route_audit_manifest_path: &Path,
) -> Value {
    let artifacts = artifact_set
        .binary_targets
        .iter()
        .map(|descriptor| (descriptor.name.as_str(), descriptor.artifact.clone()))
        .collect::<HashMap<_, _>>();

    json!({
      "pipeline_version": "1.0",
      "pipeline_id": "waf_edge_learned_v1",
      "entrypoint": "input",
      "stages": [
        {
          "id": "observer",
          "kind": "observer_plugin",
          "plugin_manifest": observer_manifest_path.display().to_string(),
          "input": {
            "method": "$.method",
            "path": "$.path",
            "source_zone": "$.source_zone",
            "headers": "$.headers",
            "query": "$.query",
            "body": "$.body",
            "raw_request": "$.raw_request",
            "modsecurity_meta": "$.modsecurity_meta"
          },
          "export": {
            "contains_sqli_signature": "$.features.contains_sqli_signature",
            "contains_xss_signature": "$.features.contains_xss_signature",
            "contains_path_traversal": "$.features.contains_path_traversal",
            "contains_server_include": "$.features.contains_server_include",
            "contains_php_injection": "$.features.contains_php_injection",
            "sqli_marker_count": "$.features.sqli_marker_count",
            "xss_marker_count": "$.features.xss_marker_count",
            "traversal_marker_count": "$.features.traversal_marker_count",
            "php_injection_marker_count": "$.features.php_injection_marker_count",
            "contains_waitfor_delay": "$.features.contains_waitfor_delay",
            "contains_union_select": "$.features.contains_union_select",
            "contains_quote": "$.features.contains_quote",
            "contains_comment_sequence": "$.features.contains_comment_sequence",
            "contains_script_tag": "$.features.contains_script_tag",
            "contains_event_handler": "$.features.contains_event_handler",
            "contains_dotdot": "$.features.contains_dotdot",
            "targets_sensitive_route": "$.features.targets_sensitive_route",
            "sensitive_route_marker_count": "$.features.sensitive_route_marker_count",
            "path_targets_admin": "$.features.path_targets_admin",
            "path_targets_hidden": "$.features.path_targets_hidden",
            "contains_restricted_extension": "$.features.contains_restricted_extension",
            "origin_outside_trust_zone": "$.features.origin_outside_trust_zone",
            "has_scanner_fingerprint": "$.features.has_scanner_fingerprint",
            "scanner_marker_count": "$.features.scanner_marker_count",
            "has_malformed_encoding": "$.features.has_malformed_encoding",
            "meta_reports_sqli": "$.features.meta_reports_sqli",
            "meta_reports_xss": "$.features.meta_reports_xss",
            "meta_reports_restricted_resource": "$.features.meta_reports_restricted_resource",
            "meta_reports_bad_bot": "$.features.meta_reports_bad_bot",
            "meta_reports_protocol_violation": "$.features.meta_reports_protocol_violation",
            "meta_reports_command_injection": "$.features.meta_reports_command_injection",
            "meta_reports_php_injection": "$.features.meta_reports_php_injection",
            "request_has_query": "$.features.request_has_query",
            "request_has_body": "$.features.request_has_body",
            "path_depth": "$.features.path_depth",
            "query_key_count": "$.features.query_key_count",
            "body_key_count": "$.features.body_key_count",
            "percent_encoding_count": "$.features.percent_encoding_count",
            "suspicious_token_count": "$.features.suspicious_token_count",
            "likely_benign_request": "$.features.likely_benign_request",
            "risk_score": "$.features.risk_score"
          }
        },
        {
          "id": "target_injection_payload",
          "kind": "pearl",
          "artifact": artifacts["target_injection_payload"],
          "input": {
            "contains_sqli_signature": "@observer.contains_sqli_signature",
            "contains_xss_signature": "@observer.contains_xss_signature",
            "contains_path_traversal": "@observer.contains_path_traversal",
            "contains_server_include": "@observer.contains_server_include",
            "contains_php_injection": "@observer.contains_php_injection",
            "sqli_marker_count": "@observer.sqli_marker_count",
            "xss_marker_count": "@observer.xss_marker_count",
            "traversal_marker_count": "@observer.traversal_marker_count",
            "php_injection_marker_count": "@observer.php_injection_marker_count",
            "contains_waitfor_delay": "@observer.contains_waitfor_delay",
            "contains_union_select": "@observer.contains_union_select",
            "contains_quote": "@observer.contains_quote",
            "contains_comment_sequence": "@observer.contains_comment_sequence",
            "contains_script_tag": "@observer.contains_script_tag",
            "contains_event_handler": "@observer.contains_event_handler",
            "contains_dotdot": "@observer.contains_dotdot",
            "meta_reports_sqli": "@observer.meta_reports_sqli",
            "meta_reports_xss": "@observer.meta_reports_xss",
            "meta_reports_command_injection": "@observer.meta_reports_command_injection",
            "meta_reports_php_injection": "@observer.meta_reports_php_injection",
            "percent_encoding_count": "@observer.percent_encoding_count",
            "suspicious_token_count": "@observer.suspicious_token_count",
            "risk_score": "@observer.risk_score"
          },
          "export": {
            "bitmask": "$.bitmask",
            "allow": "$.allow"
          }
        },
        {
          "id": "target_sensitive_surface",
          "kind": "pearl",
          "artifact": artifacts["target_sensitive_surface"],
          "input": {
            "targets_sensitive_route": "@observer.targets_sensitive_route",
            "sensitive_route_marker_count": "@observer.sensitive_route_marker_count",
            "path_targets_admin": "@observer.path_targets_admin",
            "path_targets_hidden": "@observer.path_targets_hidden",
            "contains_restricted_extension": "@observer.contains_restricted_extension",
            "origin_outside_trust_zone": "@observer.origin_outside_trust_zone",
            "meta_reports_restricted_resource": "@observer.meta_reports_restricted_resource",
            "path_depth": "@observer.path_depth",
            "query_key_count": "@observer.query_key_count",
            "body_key_count": "@observer.body_key_count",
            "percent_encoding_count": "@observer.percent_encoding_count",
            "suspicious_token_count": "@observer.suspicious_token_count",
            "risk_score": "@observer.risk_score"
          },
          "export": {
            "bitmask": "$.bitmask",
            "allow": "$.allow"
          }
        },
        {
          "id": "target_suspicious_request",
          "kind": "pearl",
          "artifact": artifacts["target_suspicious_request"],
          "input": {
            "has_scanner_fingerprint": "@observer.has_scanner_fingerprint",
            "scanner_marker_count": "@observer.scanner_marker_count",
            "has_malformed_encoding": "@observer.has_malformed_encoding",
            "meta_reports_bad_bot": "@observer.meta_reports_bad_bot",
            "meta_reports_protocol_violation": "@observer.meta_reports_protocol_violation",
            "request_has_query": "@observer.request_has_query",
            "request_has_body": "@observer.request_has_body",
            "path_depth": "@observer.path_depth",
            "query_key_count": "@observer.query_key_count",
            "body_key_count": "@observer.body_key_count",
            "percent_encoding_count": "@observer.percent_encoding_count",
            "suspicious_token_count": "@observer.suspicious_token_count",
            "likely_benign_request": "@observer.likely_benign_request",
            "risk_score": "@observer.risk_score"
          },
          "export": {
            "bitmask": "$.bitmask",
            "allow": "$.allow"
          }
        },
        {
          "id": "audit",
          "kind": "verify_plugin",
          "plugin_manifest": route_audit_manifest_path.display().to_string(),
          "input": {
            "target_injection_payload_bitmask": "@target_injection_payload.bitmask",
            "target_sensitive_surface_bitmask": "@target_sensitive_surface.bitmask",
            "target_suspicious_request_bitmask": "@target_suspicious_request.bitmask",
            "has_scanner_fingerprint": "@observer.has_scanner_fingerprint",
            "has_malformed_encoding": "@observer.has_malformed_encoding",
            "risk_score": "@observer.risk_score",
            "likely_benign_request": "@observer.likely_benign_request"
          },
          "export": {
            "route_status": "$.route_status",
            "decision_basis": "$.decision_basis",
            "explanation": "$.explanation",
            "counterfactual": "$.counterfactual",
            "allow": "$.summary.allow",
            "consistent": "$.summary.consistent"
          }
        }
      ],
      "output": {
        "route_status": "@audit.route_status",
        "decision_basis": "@audit.decision_basis",
        "explanation": "@audit.explanation",
        "counterfactual": "@audit.counterfactual",
        "allow": "@audit.allow",
        "consistent": "@audit.consistent",
        "risk_score": "@observer.risk_score",
        "target_injection_payload_bitmask": "@target_injection_payload.bitmask",
        "target_sensitive_surface_bitmask": "@target_sensitive_surface.bitmask",
        "target_suspicious_request_bitmask": "@target_suspicious_request.bitmask"
      }
    })
}

fn git_output(repo_root: &Path, args: &[&str]) -> Result<String> {
    let completed = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .into_diagnostic()?;
    if !completed.status.success() {
        return Err(miette::miette!(
            "git command failed: git -C {} {}",
            repo_root.display(),
            args.join(" ")
        ));
    }
    Ok(String::from_utf8(completed.stdout)
        .into_diagnostic()?
        .trim()
        .to_string())
}

fn observer_target_goal_name(goal: &ObserverTargetGoalArg) -> &'static str {
    match goal {
        ObserverTargetGoalArg::ParityFirst => "parity-first",
        ObserverTargetGoalArg::ProtectiveGate => "protective-gate",
        ObserverTargetGoalArg::CustomerSafe => "customer-safe",
        ObserverTargetGoalArg::Balanced => "balanced",
        ObserverTargetGoalArg::ReviewQueue => "review-queue",
    }
}

#[cfg(test)]
mod tests {
    use super::commands::find_repo_root;

    #[test]
    fn finds_repo_root_from_cli_subdirectory() {
        let cli_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let repo_root = find_repo_root(&cli_src).expect("repo root should be found");
        assert!(repo_root.join("scripts/guardrails").exists());
        assert!(repo_root.join("scripts/waf").exists());
    }
}
