use super::*;
use logicpearl_benchmark::{load_benchmark_cases, write_benchmark_cases_jsonl};
use logicpearl_discovery::ArtifactSet;
use logicpearl_ir::{EvaluationConfig, LogicPearlGateIr, Provenance, VerificationConfig};
use logicpearl_runtime::evaluate_gate;
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const FAILURE_TAIL_LINES: usize = 40;
const DEFAULT_DATASETS_ENV: &str = "LOGICPEARL_DATASETS";
const BENCHMARK_BATCH_SAMPLE: usize = 200;

const TRACE_PROJECTION_GUARDRAILS: &str =
    "benchmarks/guardrails/prep/trace_projection.guardrails_v1.json";
const TRACE_PROJECTION_WAF: &str = "benchmarks/waf/prep/trace_projection.waf_v1.json";
const OBSERVER_MANIFEST_WAF: &str = "examples/waf_edge/plugins/observer/manifest.json";
const ROUTE_AUDIT_MANIFEST_WAF: &str = "examples/waf_edge/plugins/route_audit/manifest.json";
const SCORE_MODEL_PATH: &str = "scripts/scoreboard/score_model.json";
const CONTRIBUTOR_POINTS_PATH: &str = "scripts/scoreboard/contributor_points.json";
const CONTRIBUTOR_SUMMARY_PATH: &str = "scripts/scoreboard/contributor_summary.json";
const SCORES_PATH: &str = "SCORES.json";
const GETTING_STARTED_CSV: &str = "examples/getting_started/decision_traces.csv";
const GETTING_STARTED_INPUT: &str = "examples/getting_started/new_input.json";

const PARTICIPATION_POINTS_PER_COMMIT: f64 = 1.0;

const DEMO_CASES: [(&str, &str); 3] = [
    ("access_control", "examples/demos/access_control/traces.csv"),
    (
        "content_moderation",
        "examples/demos/content_moderation/traces.csv",
    ),
    ("loan_approval", "examples/demos/loan_approval/traces.csv"),
];

const GUARDRAIL_SIGNALS: [&str; 3] = ["instruction-override", "secret-exfiltration", "tool-misuse"];

const WAF_TARGETS: [(&str, &str); 3] = [
    (
        "target_injection_payload",
        "target_injection_payload_traces.csv",
    ),
    (
        "target_sensitive_surface",
        "target_sensitive_surface_traces.csv",
    ),
    (
        "target_suspicious_request",
        "target_suspicious_request_traces.csv",
    ),
];

const SCORING_TERMS: &[(&str, &str, &str)] = &[
    (
        "participation_points",
        "shells",
        "Base credit for anything that lands on main.",
    ),
    (
        "improvement_points",
        "pearls",
        "Extra credit earned by improving measured scores.",
    ),
    (
        "total_points",
        "treasure",
        "Total score, combining shells and pearls.",
    ),
];

#[derive(Debug, Clone)]
struct RefreshStep {
    id: &'static str,
    title: &'static str,
    command: Vec<String>,
    env: Vec<(String, String)>,
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
                "Run `logicpearl refresh benchmarks` from inside the checked-out LogicPearl repo.",
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

    for step in build_refresh_steps(&repo_root, &args)? {
        run_refresh_step(&repo_root, &logs_dir, &step, args.verbose)?;
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
        "Score ledger".bright_black(),
        repo_root.join(SCORES_PATH).display()
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

    let train_observed = train_dir.join("observed.jsonl");
    run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "observe",
                &dev_cases.display().to_string(),
                "--plugin-manifest",
                &observer_manifest.display().to_string(),
                "--output",
                &train_observed.display().to_string(),
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
                "emit-traces",
                &train_observed.display().to_string(),
                "--config",
                &trace_projection.display().to_string(),
                "--output-dir",
                &train_dir.join("traces").display().to_string(),
                "--json",
            ],
        ),
    )?;

    let discovered_dir = train_dir.join("discovered");
    fs::create_dir_all(&discovered_dir).into_diagnostic()?;
    let artifact_set = build_waf_target_artifact_set(
        &repo_root,
        &cli,
        &train_dir.join("traces"),
        &discovered_dir,
        args.residual_pass,
        args.refine,
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
    run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "observe",
                &final_holdout_cases.display().to_string(),
                "--plugin-manifest",
                &observer_manifest.display().to_string(),
                "--output",
                &holdout_observed.display().to_string(),
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
                "emit-traces",
                &holdout_observed.display().to_string(),
                "--config",
                &trace_projection.display().to_string(),
                "--output-dir",
                &holdout_dir.join("traces").display().to_string(),
                "--json",
            ],
        ),
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
    let exact = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "run",
                &learned_pipeline_path.display().to_string(),
                &final_holdout_cases.display().to_string(),
                "--output",
                &holdout_dir.join("exact_routes.json").display().to_string(),
                "--json",
            ],
        ),
    )?;
    let collapsed = run_json_command(
        &repo_root,
        &build_nested_command(
            &cli,
            &[
                "benchmark",
                "run",
                &learned_pipeline_path.display().to_string(),
                &final_holdout_cases.display().to_string(),
                "--collapse-non-allow-to-deny",
                "--output",
                &holdout_dir
                    .join("collapsed_allow_deny.json")
                    .display()
                    .to_string(),
                "--json",
            ],
        ),
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

pub(crate) fn run_refresh_scoreboard_update(args: RefreshScoreboardUpdateArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    let output_path = args.output.unwrap_or_else(|| repo_root.join(SCORES_PATH));
    let guardrail_bundle_dir = args.guardrail_bundle_dir.unwrap_or_else(|| {
        std::env::var(DEFAULT_DATASETS_ENV)
            .ok()
            .map(PathBuf::from)
            .map(|_| PathBuf::from("/private/tmp/guardrails_bundle"))
            .unwrap_or_else(|| PathBuf::from("/private/tmp/guardrails_bundle"))
    });

    let (getting_started_suite, getting_started_metrics) =
        measure_getting_started(&repo_root, &cli)?;
    let (demos_suite, demo_metrics) = measure_demos(&repo_root, &cli)?;
    let mut metrics = getting_started_metrics
        .as_object()
        .cloned()
        .unwrap_or_default();
    metrics.extend(demo_metrics.as_object().cloned().unwrap_or_default());
    let (guardrails_suite, guardrail_metrics) =
        measure_guardrails(&repo_root, &cli, &guardrail_bundle_dir)?;
    metrics.extend(guardrail_metrics.as_object().cloned().unwrap_or_default());

    let suites = json!({
        "getting_started": getting_started_suite,
        "demos": demos_suite,
        "guardrails_open_sample200": guardrails_suite,
    });
    let available_suites = suites
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(suite_id, suite)| {
            (suite.get("status") == Some(&Value::String("ok".to_string())))
                .then_some(suite_id.clone())
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "schema_version": "1.0",
        "generated_by": "logicpearl refresh scoreboard-update",
        "generated_at": unix_timestamp(),
        "author": author_identity(&repo_root)?,
        "revision": revision_summary(&repo_root)?,
        "suites": suites,
        "metrics": Value::Object(metrics.clone()),
        "summary": {
            "suite_count": suites.as_object().map(|map| map.len()).unwrap_or(0),
            "metric_count": metrics.len(),
            "available_suites": available_suites,
        }
    });
    write_json_pretty(&output_path, &payload)?;
    let _ = args.pretty;
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).into_diagnostic()?
    );
    Ok(())
}

pub(crate) fn run_refresh_contributor_points(args: RefreshContributorPointsArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let output_path = args
        .output
        .unwrap_or_else(|| repo_root.join(CONTRIBUTOR_POINTS_PATH));
    let score_model: Value = read_json(&repo_root.join(SCORE_MODEL_PATH))?;
    let score_commits = git_output(
        &repo_root,
        &["log", "--reverse", "--format=%H", "--", SCORES_PATH],
    )?
    .lines()
    .map(str::to_string)
    .collect::<Vec<_>>();
    if score_commits.is_empty() {
        return Err(miette::miette!("no SCORES.json history found"));
    }
    let first_score_commit = &score_commits[0];
    let log_lines = git_output(
        &repo_root,
        &[
            "log",
            "--reverse",
            "--format=%H\t%an\t%ae\t%aI",
            &format!("{first_score_commit}^..HEAD"),
        ],
    )?;

    let mut commits = Vec::new();
    let mut contributors: BTreeMap<String, Value> = BTreeMap::new();
    let mut previous_scores: Option<Value> = None;

    for line in log_lines.lines() {
        let mut parts = line.splitn(4, '\t');
        let commit = parts.next().unwrap_or_default().to_string();
        let author_name = parts.next().unwrap_or_default().to_string();
        let author_email = parts.next().unwrap_or_default().to_string();
        let authored_at = parts.next().unwrap_or_default().to_string();
        let github_login = infer_github_login(&author_email);
        let contributor_key = github_login.clone().unwrap_or_else(|| author_email.clone());
        let current_scores =
            load_scores_for_commit(&repo_root, &commit)?.or(previous_scores.clone());

        let mut suite_changes = Map::new();
        let mut improvement_points = 0.0;
        if let (Some(previous_scores), Some(current_scores)) = (&previous_scores, &current_scores) {
            for suite_model in score_model["suites"].as_array().unwrap_or(&Vec::new()) {
                let suite_id = suite_model["id"].as_str().unwrap_or_default();
                let previous_suite_score = suite_score(previous_scores, suite_model);
                let current_suite_score = suite_score(current_scores, suite_model);
                let delta = current_suite_score - previous_suite_score;
                if delta.abs() < 1e-12 {
                    continue;
                }
                let points_budget = suite_model["points_budget"].as_f64().unwrap_or(0.0);
                let weighted_points = delta.max(0.0) * points_budget;
                suite_changes.insert(
                    suite_id.to_string(),
                    json!({
                        "previous_score": previous_suite_score,
                        "current_score": current_suite_score,
                        "delta": delta,
                        "points_budget": points_budget,
                        "target_goal": suite_model.get("target_goal").cloned().unwrap_or(Value::Null),
                        "weighted_points": weighted_points,
                        "metrics": suite_model["metrics"].clone(),
                    }),
                );
                improvement_points += weighted_points;
            }
        }

        let participation_points = PARTICIPATION_POINTS_PER_COMMIT;
        let total_points = participation_points + improvement_points;
        let commit_entry = json!({
            "commit": commit,
            "author_name": author_name,
            "author_email": author_email,
            "github_login": github_login,
            "authored_at": authored_at,
            "participation_points": participation_points,
            "improvement_points": improvement_points,
            "total_points": total_points,
            "shells": participation_points,
            "pearls": improvement_points,
            "treasure": total_points,
            "suite_changes": suite_changes,
        });
        commits.push(commit_entry);

        let contributor = contributors.entry(contributor_key).or_insert_with(|| {
            json!({
                "author_name": author_name,
                "author_email": author_email,
                "github_login": github_login,
                "participation_points": 0.0,
                "improvement_points": 0.0,
                "total_points": 0.0,
                "shells": 0.0,
                "pearls": 0.0,
                "treasure": 0.0,
                "points": 0.0,
                "commits": [],
            })
        });
        contributor["author_name"] = Value::String(author_name);
        contributor["author_email"] = Value::String(author_email);
        contributor["github_login"] = github_login.map(Value::String).unwrap_or(Value::Null);
        contributor["participation_points"] = json!(
            contributor["participation_points"].as_f64().unwrap_or(0.0) + participation_points
        );
        contributor["improvement_points"] =
            json!(contributor["improvement_points"].as_f64().unwrap_or(0.0) + improvement_points);
        contributor["total_points"] =
            json!(contributor["total_points"].as_f64().unwrap_or(0.0) + total_points);
        contributor["shells"] = contributor["participation_points"].clone();
        contributor["pearls"] = contributor["improvement_points"].clone();
        contributor["treasure"] = contributor["total_points"].clone();
        contributor["points"] = contributor["total_points"].clone();
        contributor["commits"].as_array_mut().unwrap().push(json!({
            "commit": commit,
            "authored_at": authored_at,
            "participation_points": participation_points,
            "improvement_points": improvement_points,
            "total_points": total_points,
            "shells": participation_points,
            "pearls": improvement_points,
            "treasure": total_points,
        }));

        if let Some(current_scores) = current_scores {
            previous_scores = Some(current_scores);
        }
    }

    let mut contributor_rows = contributors.into_values().collect::<Vec<_>>();
    contributor_rows.sort_by(|left, right| {
        let left_points = left["total_points"].as_f64().unwrap_or(0.0);
        let right_points = right["total_points"].as_f64().unwrap_or(0.0);
        right_points
            .partial_cmp(&left_points)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let left_key = left["github_login"]
                    .as_str()
                    .or_else(|| left["author_email"].as_str())
                    .unwrap_or_default();
                let right_key = right["github_login"]
                    .as_str()
                    .or_else(|| right["author_email"].as_str())
                    .unwrap_or_default();
                left_key.cmp(right_key)
            })
    });

    let payload = json!({
        "schema_version": "1.0",
        "generated_by": "logicpearl refresh contributor-points",
        "participation_points_per_commit": PARTICIPATION_POINTS_PER_COMMIT,
        "scoring_terms": scoring_terms_json(),
        "score_model": score_model,
        "commits": commits,
        "contributors": contributor_rows,
    });
    write_json_pretty(&output_path, &payload)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).into_diagnostic()?
    );
    Ok(())
}

pub(crate) fn run_refresh_contributor_summary(args: RefreshContributorSummaryArgs) -> Result<()> {
    let repo_root = require_repo_root()?;
    let input_path = args
        .input
        .unwrap_or_else(|| repo_root.join(CONTRIBUTOR_POINTS_PATH));
    let output_path = args
        .output
        .unwrap_or_else(|| repo_root.join(CONTRIBUTOR_SUMMARY_PATH));
    let contributor_points: Value = read_json(&input_path)?;
    let contributors = contributor_points["contributors"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut summary_rows = Vec::new();
    for (index, contributor) in contributors.iter().enumerate() {
        let commits = contributor["commits"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let latest_commit = commits.last().cloned().unwrap_or(Value::Null);
        summary_rows.push(json!({
            "rank": index + 1,
            "author_name": contributor["author_name"].clone(),
            "author_email": contributor["author_email"].clone(),
            "github_login": contributor["github_login"].clone(),
            "participation_points": contributor["participation_points"].clone(),
            "improvement_points": contributor["improvement_points"].clone(),
            "total_points": contributor["total_points"].clone(),
            "shells": contributor["shells"].clone(),
            "pearls": contributor["pearls"].clone(),
            "treasure": contributor["treasure"].clone(),
            "points": contributor["total_points"].clone(),
            "commit_count": commits.len(),
            "latest_commit": latest_commit,
        }));
    }

    let payload = json!({
        "schema_version": "1.0",
        "generated_by": "logicpearl refresh contributor-summary",
        "scoring_terms": contributor_points["scoring_terms"].clone(),
        "contributors": summary_rows,
    });
    write_json_pretty(&output_path, &payload)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).into_diagnostic()?
    );
    Ok(())
}

fn build_refresh_steps(repo_root: &Path, args: &RefreshBenchmarksArgs) -> Result<Vec<RefreshStep>> {
    let refresh_cli = refresh_front_door(args.use_installed_cli)?;
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
    guardrails_freeze.extend(["refresh".to_string(), "guardrails-freeze".to_string()]);
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
        "refresh".to_string(),
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
        "refresh".to_string(),
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
        "refresh".to_string(),
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
        "refresh".to_string(),
        "waf-build".to_string(),
        "--output-dir".to_string(),
        args.waf_bundle_dir.display().to_string(),
        "--benchmark-dir".to_string(),
        args.waf_benchmark_dir.display().to_string(),
        "--residual-pass".to_string(),
        "--refine".to_string(),
    ]);
    if args.resume {
        waf_build.push("--resume".to_string());
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

    let mut scoreboard = refresh_cli.clone();
    scoreboard.extend([
        "refresh".to_string(),
        "scoreboard-update".to_string(),
        "--guardrail-bundle-dir".to_string(),
        args.guardrail_bundle_dir.display().to_string(),
    ]);
    if args.use_installed_cli {
        scoreboard.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "08_scores",
        title: "Refresh score ledger",
        command: scoreboard,
        env: Vec::new(),
    });

    let mut contributor_points = refresh_cli.clone();
    contributor_points.extend(["refresh".to_string(), "contributor-points".to_string()]);
    steps.push(RefreshStep {
        id: "09_contributor_points",
        title: "Rebuild contributor points",
        command: contributor_points,
        env: Vec::new(),
    });

    let mut contributor_summary = refresh_cli;
    contributor_summary.extend(["refresh".to_string(), "contributor-summary".to_string()]);
    steps.push(RefreshStep {
        id: "10_contributor_summary",
        title: "Rebuild contributor summary",
        command: contributor_summary,
        env: Vec::new(),
    });

    let _ = repo_root;
    Ok(steps)
}

fn run_refresh_step(
    repo_root: &Path,
    logs_dir: &Path,
    step: &RefreshStep,
    verbose: bool,
) -> Result<()> {
    let log_path = logs_dir.join(format!("{}.log", step.id));
    println!();
    println!("[{}] {}", simple_timestamp(), step.title.bold());
    println!("  {} {}", "Log".bright_black(), log_path.display());

    if verbose {
        println!("  {} {}", "Command".bright_black(), step.command.join(" "));
        let mut command = Command::new(&step.command[0]);
        command
            .args(&step.command[1..])
            .current_dir(repo_root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (key, value) in &step.env {
            command.env(key, value);
        }
        let status = command.status().into_diagnostic()?;
        ensure_step_success(step, status, &log_path)?;
        println!(
            "  {} {}",
            "Status".bright_black(),
            "completed".bright_green()
        );
        return Ok(());
    }

    let log_file = File::create(&log_path).into_diagnostic()?;
    let stderr_file = log_file.try_clone().into_diagnostic()?;
    let mut command = Command::new(&step.command[0]);
    command
        .args(&step.command[1..])
        .current_dir(repo_root)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file));
    for (key, value) in &step.env {
        command.env(key, value);
    }

    let mut child = command.spawn().into_diagnostic()?;
    let started = Instant::now();
    let mut last_heartbeat = Duration::ZERO;
    loop {
        if let Some(status) = child.try_wait().into_diagnostic()? {
            ensure_step_success(step, status, &log_path)?;
            println!(
                "  {} {}s",
                "Completed in".bright_black(),
                started.elapsed().as_secs()
            );
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= last_heartbeat + HEARTBEAT_INTERVAL {
            println!(
                "  {} {}s",
                "Still running".bright_black(),
                elapsed.as_secs()
            );
            last_heartbeat = elapsed;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn ensure_step_success(step: &RefreshStep, status: ExitStatus, log_path: &Path) -> Result<()> {
    if status.success() {
        return Ok(());
    }
    eprintln!("  {} {}", "Failed".bright_red(), step.title);
    if log_path.exists() {
        eprintln!(
            "  {} {}",
            "Last log lines".bright_black(),
            log_path.display()
        );
        for line in tail_lines(log_path, FAILURE_TAIL_LINES)? {
            eprintln!("    {line}");
        }
    }
    Err(miette::miette!(
        "{} failed with status {}",
        step.title,
        status
    ))
}

fn tail_lines(path: &Path, max_lines: usize) -> Result<Vec<String>> {
    let file = File::open(path).into_diagnostic()?;
    let lines = BufReader::new(file)
        .lines()
        .collect::<std::io::Result<Vec<_>>>()
        .into_diagnostic()?;
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].to_vec())
}

fn require_repo_root() -> Result<PathBuf> {
    find_repo_root(&std::env::current_dir().into_diagnostic()?).ok_or_else(|| {
        guidance(
            "could not find the LogicPearl repo root from the current directory",
            "Run this command from inside the checked-out LogicPearl repo.",
        )
    })
}

fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join("Cargo.toml").exists()
            && path.join("scripts/guardrails").exists()
            && path.join("scripts/waf").exists()
        {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
}

fn default_refresh_logs_dir() -> PathBuf {
    std::env::temp_dir()
        .join("logicpearl_refresh_logs")
        .join(unix_timestamp())
}

fn unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn simple_timestamp() -> String {
    unix_timestamp()
}

fn refresh_front_door(use_installed_cli: bool) -> Result<Vec<String>> {
    if use_installed_cli {
        Ok(vec!["logicpearl".to_string()])
    } else {
        Ok(vec![std::env::current_exe()
            .into_diagnostic()?
            .display()
            .to_string()])
    }
}

fn nested_logicpearl_base_command(use_installed_cli: bool) -> Result<Vec<String>> {
    refresh_front_door(use_installed_cli)
}

fn build_nested_command(base: &[String], args: &[&str]) -> Vec<String> {
    let mut command = base.to_vec();
    command.extend(args.iter().map(|value| value.to_string()));
    command
}

fn build_nested_command_with_paths(
    base: &[String],
    top_level: &str,
    subcommand: &str,
    paths: &[PathBuf],
    output: &Path,
) -> Vec<String> {
    let mut command = base.to_vec();
    command.push(top_level.to_string());
    command.push(subcommand.to_string());
    command.extend(paths.iter().map(|path| path.display().to_string()));
    command.push("--output".to_string());
    command.push(output.display().to_string());
    command.push("--json".to_string());
    command
}

fn run_json_command(repo_root: &Path, command: &[String]) -> Result<Value> {
    let completed = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .into_diagnostic()?;
    if !completed.status.success() {
        return Err(miette::miette!(
            "command failed with status {}: {}",
            completed.status,
            command.join(" ")
        ));
    }
    let stdout = String::from_utf8(completed.stdout).into_diagnostic()?;
    serde_json::from_str(stdout.trim())
        .into_diagnostic()
        .wrap_err_with(|| format!("command returned invalid JSON: {}", command.join(" ")))
}

fn run_plain_command(repo_root: &Path, command: &[String]) -> Result<()> {
    let status = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(repo_root)
        .status()
        .into_diagnostic()?;
    if !status.success() {
        return Err(miette::miette!(
            "command failed with status {}: {}",
            status,
            command.join(" ")
        ));
    }
    Ok(())
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

fn path_from_json(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| miette::miette!("expected JSON string path, found {value}"))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_str(&fs::read_to_string(path).into_diagnostic()?).into_diagnostic()
}

fn write_json_pretty(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(value).into_diagnostic()?
        ),
    )
    .into_diagnostic()?;
    Ok(())
}

fn copy_dir_all(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).into_diagnostic()?;
    for entry in fs::read_dir(source).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let file_type = entry.file_type().into_diagnostic()?;
        let dest_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path).into_diagnostic()?;
        }
    }
    Ok(())
}

fn copy_plugin_bundle(source_manifest: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let source_dir = source_manifest.parent().ok_or_else(|| {
        miette::miette!(
            "plugin manifest has no parent: {}",
            source_manifest.display()
        )
    })?;
    if dest_dir.exists() {
        fs::remove_dir_all(dest_dir).into_diagnostic()?;
    }
    copy_dir_all(source_dir, dest_dir)?;
    Ok(dest_dir.join("manifest.json"))
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
    format!("{:x}:{case_id}", hasher.finalize())
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
        gate_type: "bitmask_gate".to_string(),
        input_schema: logicpearl_ir::InputSchema {
            features: ordered_features,
        },
        rules: combined_rules,
        evaluation: EvaluationConfig {
            combine: "bitwise_or".to_string(),
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
            generator: Some("logicpearl refresh guardrails-build".to_string()),
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

fn build_artifact_hashes(bundle_dir: &Path) -> Result<Value> {
    let mut hashes = BTreeMap::new();
    for path in walk_files(bundle_dir)? {
        let relative = path.strip_prefix(bundle_dir).into_diagnostic()?;
        hashes.insert(relative.display().to_string(), sha256_file(&path)?);
    }
    serde_json::to_value(hashes).into_diagnostic()
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        let file_type = entry.file_type().into_diagnostic()?;
        if file_type.is_dir() {
            files.extend(walk_files(&path)?);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).into_diagnostic()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer).into_diagnostic()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
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

fn read_jsonl_rows<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = File::open(path).into_diagnostic()?;
    let mut rows = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.into_diagnostic()?;
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(&line).into_diagnostic()?);
    }
    Ok(rows)
}

fn build_waf_target_artifact_set(
    repo_root: &Path,
    cli: &[String],
    train_traces_dir: &Path,
    discovered_dir: &Path,
    residual_pass: bool,
    refine: bool,
) -> Result<ArtifactSet> {
    let artifacts_dir = discovered_dir.join("artifacts");
    fs::create_dir_all(&artifacts_dir).into_diagnostic()?;
    let mut descriptors = Vec::new();
    let mut build_reports = Vec::new();

    for (target, trace_file) in WAF_TARGETS {
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
                "--json",
            ],
        );
        if residual_pass {
            command.push("--residual-pass".to_string());
        }
        if refine {
            command.push("--refine".to_string());
        }
        let build_report = run_json_command(repo_root, &command)?;
        build_reports.push(build_report);
        descriptors.push(logicpearl_discovery::ArtifactDescriptor {
            name: target.to_string(),
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
        "targets": WAF_TARGETS.iter().map(|(target, _)| *target).collect::<Vec<_>>(),
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

fn measure_getting_started(repo_root: &Path, cli: &[String]) -> Result<(Value, Value)> {
    let temp_dir = unique_temp_dir("logicpearl_scores_getting_started");
    fs::create_dir_all(&temp_dir).into_diagnostic()?;
    let output_dir = temp_dir.join("artifact");
    let build = run_json_command(
        repo_root,
        &build_nested_command(
            cli,
            &[
                "build",
                &repo_root.join(GETTING_STARTED_CSV).display().to_string(),
                "--output-dir",
                &output_dir.display().to_string(),
                "--json",
            ],
        ),
    )?;
    let binary_path = build["output_files"]["native_binary"]
        .as_str()
        .ok_or_else(|| miette::miette!("missing native binary in build output"))?;
    let actual_bitmask = run_binary(
        Path::new(binary_path),
        &repo_root.join(GETTING_STARTED_INPUT),
    )?;
    let suite = json!({
        "status": "ok",
        "csv": stable_path(repo_root, &repo_root.join(GETTING_STARTED_CSV)),
        "input": stable_path(repo_root, &repo_root.join(GETTING_STARTED_INPUT)),
        "build": summarize_build(&build),
        "expected_bitmask": "0",
        "actual_bitmask": actual_bitmask,
        "artifact_emitted": true,
        "run_passed": actual_bitmask == "0",
    });
    let metrics = json!({
        "getting_started.training_parity": metric(build["training_parity"].as_f64().unwrap_or(0.0), "max", 100.0, "getting_started", None),
        "getting_started.run_passed": metric(if actual_bitmask == "0" { 1.0 } else { 0.0 }, "max", 25.0, "getting_started", None),
    });
    Ok((suite, metrics))
}

fn measure_demos(repo_root: &Path, cli: &[String]) -> Result<(Value, Value)> {
    let temp_dir = unique_temp_dir("logicpearl_scores_demos");
    fs::create_dir_all(&temp_dir).into_diagnostic()?;
    let mut cases = Map::new();
    let mut metrics = Map::new();
    for (demo_id, rel_path) in DEMO_CASES {
        let build = run_json_command(
            repo_root,
            &build_nested_command(
                cli,
                &[
                    "build",
                    &repo_root.join(rel_path).display().to_string(),
                    "--output-dir",
                    &temp_dir.join(demo_id).display().to_string(),
                    "--json",
                ],
            ),
        )?;
        cases.insert(
            demo_id.to_string(),
            json!({
                "status": "ok",
                "csv": stable_path(repo_root, &repo_root.join(rel_path)),
                "build": summarize_build(&build),
            }),
        );
        metrics.insert(
            format!("demos.{demo_id}.training_parity"),
            metric(
                build["training_parity"].as_f64().unwrap_or(0.0),
                "max",
                100.0,
                "demos",
                None,
            ),
        );
        metrics.insert(
            format!("demos.{demo_id}.rules_discovered"),
            metric(
                build["rules_discovered"].as_f64().unwrap_or(0.0),
                "max",
                5.0,
                "demos",
                None,
            ),
        );
    }
    Ok((
        json!({"status": "ok", "cases": cases}),
        Value::Object(metrics),
    ))
}

fn measure_guardrails(
    repo_root: &Path,
    cli: &[String],
    bundle_dir: &Path,
) -> Result<(Value, Value)> {
    if !bundle_dir.exists() {
        return Ok((
            json!({
                "status": "unavailable",
                "reason": format!("guardrail bundle not found: {}", bundle_dir.display()),
                "bundle_dir": bundle_dir.display().to_string(),
            }),
            json!({}),
        ));
    }
    let target_goal = detect_bundle_target_goal(bundle_dir)?;
    let temp_dir = unique_temp_dir("logicpearl_scores_guardrails");
    fs::create_dir_all(&temp_dir).into_diagnostic()?;
    let output_dir = temp_dir.join("guardrails");
    let summary = run_json_command(
        repo_root,
        &build_nested_command(
            cli,
            &[
                "refresh",
                "guardrails-eval",
                "--bundle-dir",
                &bundle_dir.display().to_string(),
                "--output-dir",
                &output_dir.display().to_string(),
                "--input-split",
                "final_holdout",
                "--sample-size",
                &BENCHMARK_BATCH_SAMPLE.to_string(),
                "--target-goal",
                &target_goal,
                "--baseline",
                "",
            ],
        ),
    )?;
    let benchmarks = summary["benchmarks"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| {
            item["benchmark"]
                .as_str()
                .map(|benchmark_id| (benchmark_id.to_string(), item["summary"].clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut metrics = Map::new();
    for (benchmark_id, benchmark_summary) in &benchmarks {
        let prefix = format!("guardrails.{benchmark_id}");
        metrics.insert(
            format!("{prefix}.exact_match_rate"),
            metric(
                benchmark_summary["exact_match_rate"]
                    .as_f64()
                    .unwrap_or(0.0),
                "max",
                100.0,
                "guardrails",
                Some(&target_goal),
            ),
        );
        metrics.insert(
            format!("{prefix}.attack_catch_rate"),
            metric(
                benchmark_summary["attack_catch_rate"]
                    .as_f64()
                    .unwrap_or(0.0),
                "max",
                125.0,
                "guardrails",
                Some(&target_goal),
            ),
        );
        metrics.insert(
            format!("{prefix}.benign_pass_rate"),
            metric(
                benchmark_summary["benign_pass_rate"]
                    .as_f64()
                    .unwrap_or(0.0),
                "max",
                60.0,
                "guardrails",
                Some(&target_goal),
            ),
        );
        metrics.insert(
            format!("{prefix}.false_positive_rate"),
            metric(
                benchmark_summary["false_positive_rate"]
                    .as_f64()
                    .unwrap_or(0.0),
                "min",
                80.0,
                "guardrails",
                Some(&target_goal),
            ),
        );
    }

    let baseline_path = repo_root.join("scripts").join("guardrails").join(format!(
        "open_guardrail_regression_baseline.sample{}.{}.json",
        BENCHMARK_BATCH_SAMPLE, target_goal
    ));
    let lane = json!({
        "status": "ok",
        "bundle_dir": stable_path(repo_root, bundle_dir),
        "baseline": if baseline_path.exists() { stable_path(repo_root, &baseline_path) } else { String::new() },
        "input_split": summary["input_split"].clone(),
        "sample_size": summary["sample_size"].clone(),
        "target_goal": target_goal,
        "benchmarks": benchmarks,
    });
    let suite = json!({
        "status": "ok",
        "bundle_dir": stable_path(repo_root, bundle_dir),
        "default_target_goal": lane["target_goal"].clone(),
        "by_target_goal": {
            lane["target_goal"].as_str().unwrap_or("parity-first"): lane.clone()
        },
        "input_split": lane["input_split"].clone(),
        "sample_size": lane["sample_size"].clone(),
        "target_goal": lane["target_goal"].clone(),
        "benchmarks": lane["benchmarks"].clone(),
    });
    Ok((suite, Value::Object(metrics)))
}

fn summarize_build(build: &Value) -> Value {
    json!({
        "gate_id": build["gate_id"].clone(),
        "rows": build["rows"].clone(),
        "label_column": build["label_column"].clone(),
        "rules_discovered": build["rules_discovered"].clone(),
        "residual_rules_discovered": build["residual_rules_discovered"].clone(),
        "refined_rules_applied": build["refined_rules_applied"].clone(),
        "pinned_rules_applied": build["pinned_rules_applied"].clone(),
        "selected_features": build["selected_features"].clone(),
        "training_parity": build["training_parity"].clone(),
        "native_binary_emitted": build["output_files"]["native_binary"].is_string(),
        "wasm_emitted": build["output_files"]["wasm_module"].is_string(),
    })
}

fn run_binary(binary_path: &Path, input_path: &Path) -> Result<String> {
    let completed = Command::new(binary_path)
        .arg(input_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .into_diagnostic()?;
    if !completed.status.success() {
        return Err(miette::miette!(
            "compiled artifact failed with status {}: {}",
            completed.status,
            binary_path.display()
        ));
    }
    Ok(String::from_utf8(completed.stdout)
        .into_diagnostic()?
        .trim()
        .to_string())
}

fn metric(value: f64, goal: &str, weight: f64, suite: &str, target_goal: Option<&str>) -> Value {
    let mut payload = json!({
        "value": value,
        "goal": goal,
        "weight": weight,
        "suite": suite,
    });
    if let Some(target_goal) = target_goal {
        payload["target_goal"] = Value::String(target_goal.to_string());
    }
    payload
}

fn stable_path(repo_root: &Path, path: &Path) -> String {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if let Ok(relative) = resolved.strip_prefix(repo_root) {
        return relative.display().to_string();
    }
    let display = resolved.display().to_string();
    if display.starts_with("/tmp/") || display.starts_with("/private/tmp/") {
        return format!("<tmp>/{}", resolved.file_name().unwrap().to_string_lossy());
    }
    resolved
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or(display)
}

fn author_identity(repo_root: &Path) -> Result<Value> {
    let git_var = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("var")
        .arg("GIT_AUTHOR_IDENT")
        .output()
        .into_diagnostic()?;
    let raw = if git_var.status.success() {
        String::from_utf8(git_var.stdout)
            .into_diagnostic()?
            .trim()
            .to_string()
    } else {
        String::new()
    };
    if let Some((name, email)) = parse_git_author_ident(&raw) {
        return Ok(json!({ "name": name, "email": email }));
    }
    if let Ok(actor) = std::env::var("GITHUB_ACTOR") {
        if !actor.trim().is_empty() {
            return Ok(json!({
                "name": actor,
                "email": format!("{}@users.noreply.github.com", actor),
            }));
        }
    }
    Ok(json!({
        "name": git_output(repo_root, &["config", "--get", "user.name"]).unwrap_or_else(|_| "unknown".to_string()),
        "email": git_output(repo_root, &["config", "--get", "user.email"]).unwrap_or_else(|_| "unknown@local".to_string()),
    }))
}

fn parse_git_author_ident(raw: &str) -> Option<(String, String)> {
    if raw.contains('<') && raw.contains('>') {
        let name = raw.split('<').next()?.trim().to_string();
        let email = raw.split('<').nth(1)?.split('>').next()?.trim().to_string();
        Some((name, email))
    } else {
        None
    }
}

fn revision_summary(repo_root: &Path) -> Result<Value> {
    Ok(json!({
        "head": git_output(repo_root, &["rev-parse", "HEAD"])?,
        "dirty": !git_output(repo_root, &["status", "--short"])?.is_empty(),
    }))
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

fn load_scores_for_commit(repo_root: &Path, commit: &str) -> Result<Option<Value>> {
    let completed = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("show")
        .arg(format!("{commit}:{SCORES_PATH}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .into_diagnostic()?;
    if !completed.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8(completed.stdout).into_diagnostic()?;
    if stdout.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(stdout.trim()).into_diagnostic()?))
}

fn infer_github_login(email: &str) -> Option<String> {
    let lowered = email.trim().to_lowercase();
    let suffix = "@users.noreply.github.com";
    if !lowered.ends_with(suffix) {
        return None;
    }
    let local = lowered.trim_end_matches(suffix);
    if let Some((_, login)) = local.split_once('+') {
        if !login.is_empty() {
            return Some(login.to_string());
        }
    }
    (!local.is_empty()).then(|| local.to_string())
}

fn suite_score(scores: &Value, suite_model: &Value) -> f64 {
    let metrics = scores["metrics"].as_object().cloned().unwrap_or_default();
    let target_goal = suite_model["target_goal"].as_str();
    let mut total = 0.0;
    for metric_spec in suite_model["metrics"].as_array().unwrap_or(&Vec::new()) {
        let Some(id) = metric_spec["id"].as_str() else {
            continue;
        };
        let Some(metric) = metrics.get(id) else {
            continue;
        };
        if let Some(target_goal) = target_goal {
            if let Some(metric_target_goal) = metric.get("target_goal").and_then(Value::as_str) {
                if metric_target_goal != target_goal {
                    continue;
                }
            }
        }
        total +=
            metric["value"].as_f64().unwrap_or(0.0) * metric_spec["weight"].as_f64().unwrap_or(0.0);
    }
    total
}

fn scoring_terms_json() -> Value {
    let mut map = Map::new();
    for (id, display_name, description) in SCORING_TERMS {
        map.insert(
            (*id).to_string(),
            json!({
                "display_name": display_name,
                "description": description,
            }),
        );
    }
    Value::Object(map)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}_{}", prefix, unix_timestamp()))
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
    use super::find_repo_root;

    #[test]
    fn finds_repo_root_from_cli_subdirectory() {
        let cli_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let repo_root = find_repo_root(&cli_src).expect("repo root should be found");
        assert!(repo_root.join("scripts/guardrails").exists());
        assert!(repo_root.join("scripts/waf").exists());
    }
}
