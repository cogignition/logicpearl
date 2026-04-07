use super::*;
use crate::observer_cmd::{
    observe_benchmark_cases, observer_resolution, render_observer_resolution,
    resolve_observer_for_cases,
};
use logicpearl_benchmark::{
    adapt_csic_http_2010_dataset, adapt_jailbreakbench_dataset,
    adapt_modsecurity_owasp_2025_dataset, adapt_mt_agentrisk_dataset, adapt_promptshield_dataset,
    adapt_rogue_security_prompt_injections_dataset, BenchmarkCase,
};
use logicpearl_core::LogicPearlError;
use logicpearl_discovery::ArtifactSet;
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_runtime::evaluate_gate;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

#[derive(Debug, Clone, Serialize)]
struct BenchmarkCaseResult {
    id: String,
    expected_route: String,
    actual_route: String,
    matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attack_confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkSummary {
    total_cases: usize,
    matched_cases: usize,
    exact_match_rate: f64,
    attack_cases: usize,
    benign_cases: usize,
    attack_catch_rate: f64,
    benign_pass_rate: f64,
    false_positive_rate: f64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    category_accuracy: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkResult {
    pipeline_id: String,
    dataset_path: String,
    summary: BenchmarkSummary,
    cases: Vec<BenchmarkCaseResult>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkSplitSummary {
    input_rows: usize,
    train_rows: usize,
    dev_rows: usize,
    train_fraction: f64,
    train_output: String,
    dev_output: String,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactScoreSummary {
    target_count: usize,
    total_target_rows: usize,
    macro_exact_match_rate: f64,
    macro_positive_recall: f64,
    macro_negative_pass_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactTargetScore {
    target: String,
    artifact: String,
    rows: usize,
    positive_rows: usize,
    negative_rows: usize,
    matching_rows: usize,
    exact_match_rate: f64,
    positive_recall: f64,
    negative_pass_rate: f64,
    false_positive_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactScoreReport {
    artifact_set_id: String,
    trace_csv: String,
    summary: ArtifactScoreSummary,
    targets: Vec<ArtifactTargetScore>,
}

const BENCHMARK_BATCH_SIZE: usize = 256;

pub(crate) fn run_benchmark_merge_cases(args: BenchmarkMergeCasesArgs) -> Result<()> {
    if args.inputs.is_empty() {
        return Err(guidance(
            "merge-cases needs at least one input file",
            "Pass one or more benchmark-case JSONL files followed by --output <merged.jsonl>.",
        ));
    }
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create merged benchmark output directory")?;
    }

    let mut merged = String::new();
    let mut total_rows = 0_usize;
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut rewritten_ids = 0_usize;
    for input in &args.inputs {
        let source_tag = input
            .file_stem()
            .map(|stem| sanitize_identifier(&stem.to_string_lossy()))
            .filter(|tag| !tag.is_empty())
            .unwrap_or_else(|| "source".to_string());
        let cases = load_benchmark_cases(input)
            .into_diagnostic()
            .wrap_err("failed to load benchmark cases for merge")?;
        for mut case in cases {
            if !seen_ids.insert(case.id.clone()) {
                case.id = disambiguate_case_id(&case.id, &source_tag, &seen_ids);
                seen_ids.insert(case.id.clone());
                rewritten_ids += 1;
            }
            merged.push_str(&serde_json::to_string(&case).into_diagnostic()?);
            merged.push('\n');
            total_rows += 1;
        }
    }

    fs::write(&args.output, merged)
        .into_diagnostic()
        .wrap_err("failed to write merged benchmark JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": total_rows,
                "rewritten_ids": rewritten_ids,
                "inputs": args.inputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Merged".bold().bright_green(),
            "benchmark cases".bold()
        );
        println!("  {} {}", "Inputs".bright_black(), args.inputs.len());
        println!("  {} {}", "Rows".bright_black(), total_rows);
        println!("  {} {}", "Rewritten ids".bright_black(), rewritten_ids);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_split_cases(args: BenchmarkSplitCasesArgs) -> Result<()> {
    if !(0.0..=1.0).contains(&args.train_fraction) {
        return Err(guidance(
            format!("invalid --train-fraction: {}", args.train_fraction),
            "Use a fraction between 0.0 and 1.0, for example --train-fraction 0.8.",
        ));
    }

    let cases = load_benchmark_cases(&args.dataset_jsonl)
        .into_diagnostic()
        .wrap_err("failed to load benchmark cases for split")?;
    if cases.is_empty() {
        return Err(guidance(
            "benchmark split needs at least one case",
            "Pass a non-empty benchmark-case JSONL file.",
        ));
    }

    let (train_cases, dev_cases) = split_benchmark_cases(cases, args.train_fraction);

    if let Some(parent) = args.train_output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create train split output directory")?;
    }
    if let Some(parent) = args.dev_output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create dev split output directory")?;
    }

    write_benchmark_cases_jsonl(&train_cases, &args.train_output)
        .into_diagnostic()
        .wrap_err("failed to write train split JSONL")?;
    write_benchmark_cases_jsonl(&dev_cases, &args.dev_output)
        .into_diagnostic()
        .wrap_err("failed to write dev split JSONL")?;

    let summary = BenchmarkSplitSummary {
        input_rows: train_cases.len() + dev_cases.len(),
        train_rows: train_cases.len(),
        dev_rows: dev_cases.len(),
        train_fraction: args.train_fraction,
        train_output: args.train_output.display().to_string(),
        dev_output: args.dev_output.display().to_string(),
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Split".bold().bright_green(),
            "benchmark cases".bold()
        );
        println!("  {} {}", "Input rows".bright_black(), summary.input_rows);
        println!("  {} {}", "Train rows".bright_black(), summary.train_rows);
        println!("  {} {}", "Dev rows".bright_black(), summary.dev_rows);
        println!(
            "  {} {}",
            "Train output".bright_black(),
            summary.train_output
        );
        println!("  {} {}", "Dev output".bright_black(), summary.dev_output);
    }
    Ok(())
}

fn disambiguate_case_id(
    base_id: &str,
    source_tag: &str,
    seen_ids: &std::collections::BTreeSet<String>,
) -> String {
    let base = format!("{base_id}__{source_tag}");
    if !seen_ids.contains(&base) {
        return base;
    }
    for index in 2.. {
        let candidate = format!("{base}__dup{index}");
        if !seen_ids.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("duplicate id disambiguation should always find a suffix")
}

pub(crate) fn run_benchmark_prepare(args: BenchmarkPrepareArgs) -> Result<()> {
    fs::create_dir_all(&args.output_dir)
        .into_diagnostic()
        .wrap_err("failed to create benchmark prepare output directory")?;

    let observed_path = args.output_dir.join("observed.jsonl");
    let traces_dir = args.output_dir.join("traces");
    let discovered_dir = args.output_dir.join("discovered");

    let observer = resolve_observer_for_cases(
        &args.dataset_jsonl,
        args.observer_profile.clone(),
        args.observer_artifact.clone(),
        args.plugin_manifest.clone(),
    )?;
    let observed_rows = observe_benchmark_cases(&args.dataset_jsonl, &observer, &observed_path)?;
    let trace_summary = emit_trace_tables(&observed_path, &args.config, &traces_dir)
        .into_diagnostic()
        .wrap_err("failed to emit trace tables")?;
    let config = load_trace_projection_config(&args.config)
        .into_diagnostic()
        .wrap_err("failed to load trace projection config")?;

    let discover_result = if config.emit_multi_target {
        let targets = config
            .binary_targets
            .iter()
            .map(|target| target.name.clone())
            .collect::<Vec<_>>();
        Some(
            discover_from_csv(
                &traces_dir.join("multi_target.csv"),
                &DiscoverOptions {
                    output_dir: discovered_dir,
                    artifact_set_id: format!(
                        "{}_artifact_set",
                        args.dataset_jsonl
                            .file_stem()
                            .map(|stem| stem.to_string_lossy().to_string())
                            .unwrap_or_else(|| "benchmark".to_string())
                    ),
                    target_columns: targets,
                    residual_pass: false,
                    refine: false,
                    pinned_rules: None,
                    feature_governance: None,
                    decision_mode: logicpearl_discovery::DiscoveryDecisionMode::Standard,
                },
            )
            .into_diagnostic()
            .wrap_err("could not discover artifacts from emitted benchmark traces")?,
        )
    } else {
        None
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dataset": args.dataset_jsonl.display().to_string(),
                "observer": observer_resolution(&observer),
                "observed_rows": observed_rows,
                "observed_output": observed_path.display().to_string(),
                "trace_summary": trace_summary,
                "discover_result": discover_result,
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Prepared".bold().bright_green(),
            "benchmark dataset".bold()
        );
        println!("  {} {}", "Observed".bright_black(), observed_rows);
        println!(
            "  {} {}",
            "Observer".bright_black(),
            render_observer_resolution(&observer_resolution(&observer))
        );
        println!(
            "  {} {}",
            "Observed output".bright_black(),
            observed_path.display()
        );
        println!(
            "  {} {}",
            "Trace output".bright_black(),
            traces_dir.display()
        );
        if let Some(discover_result) = discover_result {
            println!(
                "  {} {}",
                "Artifacts".bright_black(),
                discover_result.artifacts.len()
            );
            println!(
                "  {} {}",
                "Artifact set".bright_black(),
                discover_result.output_files.artifact_set
            );
        }
    }
    Ok(())
}

pub(crate) fn run_benchmark_observe(args: BenchmarkObserveArgs) -> Result<()> {
    let observer = resolve_observer_for_cases(
        &args.dataset_jsonl,
        args.observer_profile.clone(),
        args.observer_artifact.clone(),
        args.plugin_manifest.clone(),
    )?;
    let rows = observe_benchmark_cases(&args.dataset_jsonl, &observer, &args.output)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": rows,
                "output": args.output.display().to_string(),
                "observer": observer_resolution(&observer)
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Observed".bold().bright_green(),
            "benchmark cases".bold()
        );
        println!("  {} {}", "Rows".bright_black(), rows);
        println!(
            "  {} {}",
            "Observer".bright_black(),
            render_observer_resolution(&observer_resolution(&observer))
        );
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_list_profiles(args: BenchmarkListProfilesArgs) -> Result<()> {
    let profiles = benchmark_adapter_registry();
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "profiles": profiles }))
                .into_diagnostic()?
        );
    } else {
        println!("{}", "Benchmark adapter profiles".bold().bright_blue());
        for profile in profiles {
            println!(
                "  {} {}",
                profile.id.bold(),
                profile.description.bright_black()
            );
            println!("    {} {}", "Format".bright_black(), profile.source_format);
            println!(
                "    {} {}",
                "Default route".bright_black(),
                profile.default_route
            );
        }
    }
    Ok(())
}

pub(crate) fn run_benchmark_detect_profile(args: BenchmarkDetectProfileArgs) -> Result<()> {
    let profile = detect_benchmark_adapter_profile(&args.raw_dataset)
        .into_diagnostic()
        .wrap_err("failed to detect benchmark adapter profile")?;
    let response = serde_json::json!({
        "raw_dataset": args.raw_dataset.display().to_string(),
        "detected_profile": profile.id(),
    });
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Detected".bold().bright_green(),
            profile.id().bold()
        );
        println!(
            "  {} {}",
            "Dataset".bright_black(),
            args.raw_dataset.display()
        );
    }
    Ok(())
}

pub(crate) fn run_benchmark_emit_traces(args: BenchmarkEmitTracesArgs) -> Result<()> {
    let summary = emit_trace_tables(&args.observed_jsonl, &args.config, &args.output_dir)
        .into_diagnostic()
        .wrap_err("failed to emit trace tables")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Emitted".bold().bright_green(),
            "discovery traces".bold()
        );
        println!("  {} {}", "Rows".bright_black(), summary.rows);
        println!("  {} {}", "Config".bright_black(), summary.config);
        println!("  {} {}", "Output".bright_black(), summary.output_dir);
    }
    Ok(())
}

pub(crate) fn run_benchmark_adapt(args: BenchmarkAdaptArgs) -> Result<()> {
    let profile = match to_benchmark_adapter_profile(args.profile) {
        BenchmarkAdapterProfile::Auto => detect_benchmark_adapter_profile(&args.raw_dataset)
            .into_diagnostic()
            .wrap_err("failed to detect benchmark adapter profile")?,
        other => other,
    };
    match profile {
        BenchmarkAdapterProfile::Auto => {
            unreachable!("auto profile should be resolved before dispatch")
        }
        BenchmarkAdapterProfile::CsicHttp2010 => run_benchmark_adapt_csic_http_2010(
            &args.raw_dataset,
            &args.output,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::ModsecurityOwasp2025 => {
            run_benchmark_adapt_modsecurity_owasp_2025(
                &args.raw_dataset,
                &args.output,
                &BenchmarkAdaptDefaults {
                    requested_tool: args.requested_tool,
                    requested_action: args.requested_action,
                    scope: args.scope,
                },
                args.json,
            )
        }
        BenchmarkAdapterProfile::SaladBaseSet => {
            run_benchmark_adapt_salad(BenchmarkAdaptSaladArgs {
                raw_salad_json: args.raw_dataset,
                subset: SaladSubset::BaseSet,
                output: args.output,
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
                json: args.json,
            })
        }
        BenchmarkAdapterProfile::SaladAttackEnhancedSet => {
            run_benchmark_adapt_salad(BenchmarkAdaptSaladArgs {
                raw_salad_json: args.raw_dataset,
                subset: SaladSubset::AttackEnhancedSet,
                output: args.output,
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
                json: args.json,
            })
        }
        BenchmarkAdapterProfile::SafearenaSafe => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "SafeArena safe",
            |raw, defaults| adapt_safearena_dataset(raw, true, defaults),
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::SafearenaHarm => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "SafeArena harm",
            |raw, defaults| adapt_safearena_dataset(raw, false, defaults),
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::Alert => run_benchmark_adapt_alert(BenchmarkAdaptAlertArgs {
            raw_alert_json: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
        BenchmarkAdapterProfile::JailbreakBench => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "JailbreakBench",
            adapt_jailbreakbench_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::PromptShield => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "PromptShield",
            adapt_promptshield_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::RogueSecurityPromptInjections => {
            run_benchmark_adapt_prompt_json_rows(
                &args.raw_dataset,
                &args.output,
                "rogue-security/prompt-injections-benchmark",
                adapt_rogue_security_prompt_injections_dataset,
                &BenchmarkAdaptDefaults {
                    requested_tool: args.requested_tool,
                    requested_action: args.requested_action,
                    scope: args.scope,
                },
                args.json,
            )
        }
        BenchmarkAdapterProfile::ChatgptJailbreakPrompts => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "ChatGPT-Jailbreak-Prompts",
            adapt_chatgpt_jailbreak_prompts_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::OpenAgentSafetyS26 => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "OpenAgentSafety S26",
            adapt_openagentsafety_s26_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::McpMark => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "MCPMark",
            adapt_mcpmark_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::Squad => run_benchmark_adapt_squad(BenchmarkAdaptSquadArgs {
            raw_squad_json: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
        BenchmarkAdapterProfile::Vigil => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "Vigil",
            adapt_vigil_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::NoetiToxicQa => run_benchmark_adapt_prompt_json_rows(
            &args.raw_dataset,
            &args.output,
            "NOETI ToxicQAFinal",
            adapt_noeti_toxicqa_dataset,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::MtAgentRisk => run_benchmark_adapt_mt_agentrisk(
            &args.raw_dataset,
            &args.output,
            &BenchmarkAdaptDefaults {
                requested_tool: args.requested_tool,
                requested_action: args.requested_action,
                scope: args.scope,
            },
            args.json,
        ),
        BenchmarkAdapterProfile::Pint => run_benchmark_adapt_pint(BenchmarkAdaptPintArgs {
            raw_pint_yaml: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
    }
}

fn run_benchmark_adapt_csic_http_2010(
    dataset_root: &Path,
    output: &Path,
    defaults: &BenchmarkAdaptDefaults,
    json: bool,
) -> Result<()> {
    let cases = adapt_csic_http_2010_dataset(dataset_root, defaults)
        .into_diagnostic()
        .wrap_err("failed to adapt CSIC HTTP 2010 benchmark dataset")?;
    write_benchmark_cases_jsonl(&cases, output)
        .into_diagnostic()
        .wrap_err("failed to write adapted CSIC HTTP 2010 JSONL")?;

    render_mixed_benchmark_adapt_summary("CSIC HTTP 2010", &cases, output, json)
}

fn run_benchmark_adapt_modsecurity_owasp_2025(
    dataset_root: &Path,
    output: &Path,
    defaults: &BenchmarkAdaptDefaults,
    json: bool,
) -> Result<()> {
    let cases = adapt_modsecurity_owasp_2025_dataset(dataset_root, defaults)
        .into_diagnostic()
        .wrap_err("failed to adapt ModSecurity OWASP 2025 benchmark dataset")?;
    write_benchmark_cases_jsonl(&cases, output)
        .into_diagnostic()
        .wrap_err("failed to write adapted ModSecurity OWASP 2025 JSONL")?;

    render_mixed_benchmark_adapt_summary("ModSecurity OWASP 2025", &cases, output, json)
}

fn render_mixed_benchmark_adapt_summary(
    dataset_name: &str,
    cases: &[BenchmarkCase],
    output: &Path,
    json: bool,
) -> Result<()> {
    let deny_rows = cases
        .iter()
        .filter(|case| case.expected_route.starts_with("deny"))
        .count();
    let review_rows = cases
        .iter()
        .filter(|case| case.expected_route.starts_with("review"))
        .count();
    let allow_rows = cases
        .len()
        .saturating_sub(deny_rows)
        .saturating_sub(review_rows);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": dataset_name,
                "rows": cases.len(),
                "deny_rows": deny_rows,
                "review_rows": review_rows,
                "allow_rows": allow_rows,
                "output": output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            dataset_name.bold()
        );
        println!("  {} {}", "Rows".bright_black(), cases.len());
        println!("  {} {}", "Deny rows".bright_black(), deny_rows);
        println!("  {} {}", "Review rows".bright_black(), review_rows);
        println!("  {} {}", "Allow rows".bright_black(), allow_rows);
        println!("  {} {}", "Output".bright_black(), output.display());
    }
    Ok(())
}

fn run_benchmark_adapt_mt_agentrisk(
    dataset_root: &Path,
    output: &Path,
    defaults: &BenchmarkAdaptDefaults,
    json: bool,
) -> Result<()> {
    let cases = adapt_mt_agentrisk_dataset(dataset_root, defaults)
        .into_diagnostic()
        .wrap_err("failed to adapt MT-AgentRisk benchmark dataset")?;
    write_benchmark_cases_jsonl(&cases, output)
        .into_diagnostic()
        .wrap_err("failed to write adapted MT-AgentRisk JSONL")?;

    let deny_rows = cases
        .iter()
        .filter(|case| case.expected_route != "allow")
        .count();
    let allow_rows = cases.len().saturating_sub(deny_rows);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "mt-agentrisk",
                "rows": cases.len(),
                "deny_rows": deny_rows,
                "allow_rows": allow_rows,
                "output": output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            "MT-AgentRisk dataset".bold()
        );
        println!("  {} {}", "Rows".bright_black(), cases.len());
        println!("  {} {}", "Deny rows".bright_black(), deny_rows);
        println!("  {} {}", "Allow rows".bright_black(), allow_rows);
        println!("  {} {}", "Output".bright_black(), output.display());
    }
    Ok(())
}

fn run_benchmark_adapt_prompt_json_rows(
    raw_dataset: &Path,
    output: &Path,
    dataset_name: &str,
    adapter: fn(&str, &BenchmarkAdaptDefaults) -> logicpearl_core::Result<Vec<BenchmarkCase>>,
    defaults: &BenchmarkAdaptDefaults,
    json: bool,
) -> Result<()> {
    let raw_json = fs::read_to_string(raw_dataset)
        .into_diagnostic()
        .wrap_err(format!("could not read raw {dataset_name} data"))?;
    let cases = adapter(&raw_json, defaults)
        .into_diagnostic()
        .wrap_err(format!("failed to adapt {dataset_name} rows"))?;
    write_benchmark_cases_jsonl(&cases, output)
        .into_diagnostic()
        .wrap_err("failed to write adapted benchmark cases")?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rows": cases.len(),
                "output": output.display().to_string(),
                "expected_route": cases.first().map(|case| case.expected_route.clone()).unwrap_or_else(|| "mixed".to_string())
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            dataset_name.bold()
        );
        println!("  {} {}", "Rows".bright_black(), cases.len());
        if let Some(first) = cases.first() {
            println!("  {} {}", "Route".bright_black(), first.expected_route);
        }
        println!("  {} {}", "Output".bright_black(), output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_adapt_salad(args: BenchmarkAdaptSaladArgs) -> Result<()> {
    let raw_json = fs::read_to_string(&args.raw_salad_json)
        .into_diagnostic()
        .wrap_err("could not read raw Salad-Data JSON")?;
    let cases = adapt_salad_dataset(
        &raw_json,
        match args.subset {
            SaladSubset::BaseSet => SaladSubsetKind::BaseSet,
            SaladSubset::AttackEnhancedSet => SaladSubsetKind::AttackEnhancedSet,
        },
        &BenchmarkAdaptDefaults {
            requested_tool: args.requested_tool.clone(),
            requested_action: args.requested_action.clone(),
            scope: args.scope.clone(),
        },
    )
    .into_diagnostic()
    .wrap_err("failed to adapt Salad-Data benchmark dataset")?;
    let rows = cases.len();
    write_benchmark_cases_jsonl(&cases, &args.output)
        .into_diagnostic()
        .wrap_err("failed to write adapted Salad JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "salad-data",
                "subset": match args.subset {
                    SaladSubset::BaseSet => "base_set",
                    SaladSubset::AttackEnhancedSet => "attack_enhanced_set",
                },
                "rows": rows,
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            "Salad-Data dataset".bold()
        );
        println!("  {} {}", "Rows".bright_black(), rows);
        println!(
            "  {} {}",
            "Subset".bright_black(),
            match args.subset {
                SaladSubset::BaseSet => "base_set",
                SaladSubset::AttackEnhancedSet => "attack_enhanced_set",
            }
        );
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_adapt_alert(args: BenchmarkAdaptAlertArgs) -> Result<()> {
    let raw_json = fs::read_to_string(&args.raw_alert_json)
        .into_diagnostic()
        .wrap_err("could not read raw ALERT JSON")?;
    let cases = adapt_alert_dataset(
        &raw_json,
        &BenchmarkAdaptDefaults {
            requested_tool: args.requested_tool.clone(),
            requested_action: args.requested_action.clone(),
            scope: args.scope.clone(),
        },
    )
    .into_diagnostic()
    .wrap_err("failed to adapt ALERT benchmark dataset")?;
    let rows = cases.len();
    write_benchmark_cases_jsonl(&cases, &args.output)
        .into_diagnostic()
        .wrap_err("failed to write adapted ALERT JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "alert",
                "rows": rows,
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            "ALERT dataset".bold()
        );
        println!("  {} {}", "Rows".bright_black(), rows);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_adapt_squad(args: BenchmarkAdaptSquadArgs) -> Result<()> {
    let raw_json = fs::read_to_string(&args.raw_squad_json)
        .into_diagnostic()
        .wrap_err("could not read raw SQuAD JSON")?;
    let cases = adapt_squad_dataset(
        &raw_json,
        &BenchmarkAdaptDefaults {
            requested_tool: args.requested_tool.clone(),
            requested_action: args.requested_action.clone(),
            scope: args.scope.clone(),
        },
    )
    .into_diagnostic()
    .wrap_err("failed to adapt SQuAD benchmark dataset")?;
    let rows = cases.len();
    write_benchmark_cases_jsonl(&cases, &args.output)
        .into_diagnostic()
        .wrap_err("failed to write adapted SQuAD JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "squad",
                "rows": rows,
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            "SQuAD dataset".bold()
        );
        println!("  {} {}", "Rows".bright_black(), rows);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_adapt_pint(args: BenchmarkAdaptPintArgs) -> Result<()> {
    let raw_yaml = fs::read_to_string(&args.raw_pint_yaml)
        .into_diagnostic()
        .wrap_err("could not read raw PINT YAML")?;
    let cases = adapt_pint_dataset(
        &raw_yaml,
        &BenchmarkAdaptDefaults {
            requested_tool: args.requested_tool.clone(),
            requested_action: args.requested_action.clone(),
            scope: args.scope.clone(),
        },
    )
    .into_diagnostic()
    .wrap_err("failed to adapt PINT benchmark dataset")?;
    let rows = cases.len();
    write_benchmark_cases_jsonl(&cases, &args.output)
        .into_diagnostic()
        .wrap_err("failed to write adapted PINT JSONL")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source_benchmark": "pint",
                "rows": rows,
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Adapted".bold().bright_green(),
            "PINT dataset".bold()
        );
        println!("  {} {}", "Rows".bright_black(), rows);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark(args: BenchmarkRunArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("failed to load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let prepared_pipeline = pipeline
        .prepare(base_dir)
        .into_diagnostic()
        .wrap_err("failed to prepare pipeline artifact")?;

    let file = fs::File::open(&args.dataset_jsonl)
        .into_diagnostic()
        .wrap_err("could not open benchmark dataset JSONL")?;
    let reader = BufReader::new(file);

    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line
            .into_diagnostic()
            .wrap_err("failed to read benchmark dataset line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: BenchmarkCase = serde_json::from_str(trimmed)
            .into_diagnostic()
            .wrap_err(format!(
                "invalid benchmark case JSON on line {}. Each line must contain id, input, and expected_route",
                line_no + 1
            ))?;
        cases.push(case);
    }

    if cases.is_empty() {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one JSON object per line with id, input, expected_route, and optional category.",
        ));
    }

    let collapse_non_allow_to_deny = args.collapse_non_allow_to_deny;
    let results =
        benchmark_case_results_parallel(&prepared_pipeline, &cases, collapse_non_allow_to_deny)?;

    let mut matched_cases = 0_usize;
    let mut attack_cases = 0_usize;
    let mut benign_cases = 0_usize;
    let mut caught_attacks = 0_usize;
    let mut benign_passes = 0_usize;
    let mut false_positives = 0_usize;
    let mut category_totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_matches: BTreeMap<String, usize> = BTreeMap::new();

    for result in &results {
        let matched = result.matched;
        if matched {
            matched_cases += 1;
        }

        let is_attack = result.expected_route != "allow";
        if is_attack {
            attack_cases += 1;
            if result.actual_route != "allow" {
                caught_attacks += 1;
            }
        } else {
            benign_cases += 1;
            if result.actual_route == "allow" {
                benign_passes += 1;
            } else {
                false_positives += 1;
            }
        }

        if let Some(category) = &result.category {
            *category_totals.entry(category.clone()).or_insert(0) += 1;
            if matched {
                *category_matches.entry(category.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut category_accuracy = BTreeMap::new();
    for (category, total) in category_totals {
        let matches = category_matches.get(&category).copied().unwrap_or(0);
        category_accuracy.insert(category, ratio(matches, total));
    }

    let benchmark = BenchmarkResult {
        pipeline_id: pipeline.pipeline_id.clone(),
        dataset_path: args.dataset_jsonl.display().to_string(),
        summary: BenchmarkSummary {
            total_cases: results.len(),
            matched_cases,
            exact_match_rate: ratio(matched_cases, results.len()),
            attack_cases,
            benign_cases,
            attack_catch_rate: ratio(caught_attacks, attack_cases),
            benign_pass_rate: ratio(benign_passes, benign_cases),
            false_positive_rate: ratio(false_positives, benign_cases),
            category_accuracy,
        },
        cases: results,
    };

    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err("failed to create benchmark output directory")?;
        }
        fs::write(
            &output,
            serde_json::to_string_pretty(&benchmark).into_diagnostic()? + "\n",
        )
        .into_diagnostic()
        .wrap_err("failed to write benchmark result JSON")?;
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&benchmark).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Benchmark".bold().bright_green(),
            benchmark.pipeline_id.bold()
        );
        println!(
            "  {} {}",
            "Cases".bright_black(),
            benchmark.summary.total_cases
        );
        println!(
            "  {} {:.1}%",
            "Exact match".bright_black(),
            benchmark.summary.exact_match_rate * 100.0
        );
        println!(
            "  {} {:.1}%",
            "Attack catch".bright_black(),
            benchmark.summary.attack_catch_rate * 100.0
        );
        println!(
            "  {} {:.1}%",
            "Benign pass".bright_black(),
            benchmark.summary.benign_pass_rate * 100.0
        );
        println!(
            "  {} {:.1}%",
            "False positive".bright_black(),
            benchmark.summary.false_positive_rate * 100.0
        );
    }
    Ok(())
}

fn benchmark_case_results_parallel(
    prepared_pipeline: &logicpearl_pipeline::PreparedPipeline,
    cases: &[BenchmarkCase],
    collapse_non_allow_to_deny: bool,
) -> Result<Vec<BenchmarkCaseResult>> {
    let chunked = cases
        .chunks(BENCHMARK_BATCH_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();
    if chunked.is_empty() {
        return Ok(Vec::new());
    }
    let worker_count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
        .min(chunked.len());
    if worker_count == 1 {
        let mut results = Vec::with_capacity(cases.len());
        for chunk in &chunked {
            results.extend(run_benchmark_chunk(
                prepared_pipeline,
                chunk,
                collapse_non_allow_to_deny,
            )?);
        }
        return Ok(results);
    }

    let (tx, rx) = mpsc::channel();
    let prepared_pipeline = prepared_pipeline.clone();
    let chunked = std::sync::Arc::new(chunked);
    for worker in 0..worker_count {
        let tx = tx.clone();
        let pipeline = prepared_pipeline.clone();
        let chunked = chunked.clone();
        thread::spawn(move || {
            for index in (worker..chunked.len()).step_by(worker_count) {
                let result =
                    run_benchmark_chunk(&pipeline, &chunked[index], collapse_non_allow_to_deny)
                        .map(|rows| (index, rows))
                        .map_err(|err| err.to_string());
                let _ = tx.send(result);
            }
        });
    }
    drop(tx);

    let mut ordered = vec![Vec::new(); chunked.len()];
    for message in rx {
        match message {
            Ok((index, rows)) => ordered[index] = rows,
            Err(message) => return Err(miette::miette!(message)),
        }
    }
    Ok(ordered.into_iter().flatten().collect())
}

fn run_benchmark_chunk(
    prepared_pipeline: &logicpearl_pipeline::PreparedPipeline,
    chunk: &[BenchmarkCase],
    collapse_non_allow_to_deny: bool,
) -> Result<Vec<BenchmarkCaseResult>> {
    let inputs = chunk
        .iter()
        .map(|case| case.input.clone())
        .collect::<Vec<_>>();
    let executions = prepared_pipeline
        .run_batch(&inputs)
        .into_diagnostic()
        .wrap_err("benchmark pipeline batch execution failed")?;
    chunk
        .iter()
        .zip(executions)
        .map(|(case, execution)| {
            let actual_route_raw = execution
                .output
                .get("route_status")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    guidance(
                        "benchmark pipeline output is missing `route_status`",
                        "Make sure the pipeline output exports a string route_status field, for example allow or deny_tool_use.",
                    )
                })?;
            let actual_route = collapse_route(actual_route_raw, collapse_non_allow_to_deny);
            let expected_route = collapse_route(&case.expected_route, collapse_non_allow_to_deny);
            let matched = actual_route == expected_route;
            let attack_confidence = execution
                .output
                .get("attack_confidence")
                .and_then(Value::as_f64);
            Ok(BenchmarkCaseResult {
                id: case.id.clone(),
                expected_route,
                actual_route,
                matched,
                category: case.category.clone(),
                attack_confidence,
            })
        })
        .collect()
}

pub(crate) fn run_benchmark_score_artifacts(args: BenchmarkScoreArtifactsArgs) -> Result<()> {
    let artifact_set_path = &args.artifact_set_json;
    let artifact_set_dir = artifact_set_path.parent().unwrap_or_else(|| Path::new("."));
    let artifact_set: ArtifactSet = serde_json::from_str(
        &fs::read_to_string(artifact_set_path)
            .into_diagnostic()
            .wrap_err("failed to read artifact set JSON")?,
    )
    .into_diagnostic()
    .wrap_err("artifact set is not valid JSON")?;

    let mut reader = csv::Reader::from_path(&args.trace_csv)
        .into_diagnostic()
        .wrap_err("failed to read held-out trace CSV")?;
    let headers = reader
        .headers()
        .into_diagnostic()
        .wrap_err("failed to read held-out trace CSV headers")?
        .clone();
    let records = reader
        .records()
        .collect::<std::result::Result<Vec<_>, csv::Error>>()
        .into_diagnostic()
        .wrap_err("failed to read held-out trace CSV rows")?;

    let mut target_scores = Vec::new();
    for descriptor in &artifact_set.binary_targets {
        let artifact_path = artifact_set_dir.join(&descriptor.artifact);
        let gate = LogicPearlGateIr::from_path(&artifact_path)
            .into_diagnostic()
            .wrap_err(format!(
                "failed to load artifact for target {}",
                descriptor.name
            ))?;
        let target_score =
            score_target_against_records(&gate, &headers, &records, &descriptor.name)
                .into_diagnostic()
                .wrap_err(format!("failed to score target {}", descriptor.name))?;
        target_scores.push(ArtifactTargetScore {
            target: descriptor.name.clone(),
            artifact: artifact_path.display().to_string(),
            rows: target_score.rows,
            positive_rows: target_score.positive_rows,
            negative_rows: target_score.negative_rows,
            matching_rows: target_score.matching_rows,
            exact_match_rate: ratio(target_score.matching_rows, target_score.rows),
            positive_recall: ratio(target_score.true_positives, target_score.positive_rows),
            negative_pass_rate: ratio(target_score.true_negatives, target_score.negative_rows),
            false_positive_rate: ratio(target_score.false_positives, target_score.negative_rows),
        });
    }

    let target_count = target_scores.len();
    let total_target_rows = target_scores.iter().map(|score| score.rows).sum();
    let summary = ArtifactScoreSummary {
        target_count,
        total_target_rows,
        macro_exact_match_rate: average(target_scores.iter().map(|score| score.exact_match_rate)),
        macro_positive_recall: average(target_scores.iter().map(|score| score.positive_recall)),
        macro_negative_pass_rate: average(
            target_scores.iter().map(|score| score.negative_pass_rate),
        ),
    };
    let report = ArtifactScoreReport {
        artifact_set_id: artifact_set.artifact_set_id,
        trace_csv: args.trace_csv.display().to_string(),
        summary,
        targets: target_scores,
    };

    if let Some(output) = &args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err("failed to create artifact score output directory")?;
        }
        fs::write(
            output,
            serde_json::to_string_pretty(&report).into_diagnostic()? + "\n",
        )
        .into_diagnostic()
        .wrap_err("failed to write artifact score report")?;
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Scored".bold().bright_green(),
            report.artifact_set_id.bold()
        );
        println!(
            "  {} {}",
            "Targets".bright_black(),
            report.summary.target_count
        );
        println!(
            "  {} {:.1}%",
            "Macro exact match".bright_black(),
            report.summary.macro_exact_match_rate * 100.0
        );
        println!(
            "  {} {:.1}%",
            "Macro positive recall".bright_black(),
            report.summary.macro_positive_recall * 100.0
        );
        println!(
            "  {} {:.1}%",
            "Macro negative pass".bright_black(),
            report.summary.macro_negative_pass_rate * 100.0
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct TargetScoreCounts {
    rows: usize,
    positive_rows: usize,
    negative_rows: usize,
    matching_rows: usize,
    true_positives: usize,
    true_negatives: usize,
    false_positives: usize,
}

fn score_target_against_records(
    gate: &LogicPearlGateIr,
    headers: &csv::StringRecord,
    records: &[csv::StringRecord],
    target_column: &str,
) -> logicpearl_core::Result<TargetScoreCounts> {
    let Some(target_index) = headers.iter().position(|header| header == target_column) else {
        return Err(LogicPearlError::message(format!(
            "held-out trace CSV is missing target column {:?}",
            target_column
        )));
    };

    let mut rows = 0usize;
    let mut positive_rows = 0usize;
    let mut negative_rows = 0usize;
    let mut matching_rows = 0usize;
    let mut true_positives = 0usize;
    let mut true_negatives = 0usize;
    let mut false_positives = 0usize;

    for (row_index, record) in records.iter().enumerate() {
        let expected_positive = parse_target_label(
            record.get(target_index).unwrap_or(""),
            row_index + 2,
            target_column,
        )?;
        let mut features = HashMap::new();
        for (header, value) in headers.iter().zip(record.iter()) {
            if header == target_column {
                continue;
            }
            features.insert(header.to_string(), parse_scalar(value)?);
        }
        let predicted_positive = !evaluate_gate(gate, &features)?.is_zero();
        rows += 1;
        if expected_positive {
            positive_rows += 1;
            if predicted_positive {
                true_positives += 1;
            }
        } else {
            negative_rows += 1;
            if !predicted_positive {
                true_negatives += 1;
            } else {
                false_positives += 1;
            }
        }
        if expected_positive == predicted_positive {
            matching_rows += 1;
        }
    }

    Ok(TargetScoreCounts {
        rows,
        positive_rows,
        negative_rows,
        matching_rows,
        true_positives,
        true_negatives,
        false_positives,
    })
}

fn parse_target_label(raw: &str, line_no: usize, column: &str) -> logicpearl_core::Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "deny" | "denied" => Ok(true),
        "0" | "false" | "no" | "allow" | "allowed" => Ok(false),
        other => Err(LogicPearlError::message(format!(
            "row {} has a non-binary target label {:?} in column {:?}",
            line_no, other, column
        ))),
    }
}

fn split_benchmark_cases(
    cases: Vec<BenchmarkCase>,
    train_fraction: f64,
) -> (Vec<BenchmarkCase>, Vec<BenchmarkCase>) {
    let mut groups: BTreeMap<String, Vec<BenchmarkCase>> = BTreeMap::new();
    for case in cases {
        let group_key = format!(
            "{}::{}",
            case.expected_route,
            case.category.clone().unwrap_or_else(|| "_none".to_string())
        );
        groups.entry(group_key).or_default().push(case);
    }

    let mut train_cases = Vec::new();
    let mut dev_cases = Vec::new();
    for mut group_cases in groups.into_values() {
        group_cases.sort_by_key(|case| stable_case_hash(&case.id));
        let total = group_cases.len();
        let mut train_count = ((total as f64) * train_fraction).floor() as usize;
        if total > 1 {
            if train_count == 0 {
                train_count = 1;
            }
            if train_count >= total {
                train_count = total - 1;
            }
        }
        for (index, case) in group_cases.into_iter().enumerate() {
            if index < train_count {
                train_cases.push(case);
            } else {
                dev_cases.push(case);
            }
        }
    }
    (train_cases, dev_cases)
}

fn parse_scalar(raw: &str) -> logicpearl_core::Result<Value> {
    if let Ok(parsed) = raw.parse::<i64>() {
        return Ok(Value::from(parsed));
    }
    if let Ok(parsed) = raw.parse::<f64>() {
        return Ok(Value::from(parsed));
    }
    let lowered = raw.trim().to_ascii_lowercase();
    if lowered == "true" {
        return Ok(Value::from(true));
    }
    if lowered == "false" {
        return Ok(Value::from(false));
    }
    Ok(Value::from(raw.to_string()))
}

fn stable_case_hash(case_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(case_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn average(values: impl Iterator<Item = f64>) -> f64 {
    let collected: Vec<f64> = values.collect();
    if collected.is_empty() {
        0.0
    } else {
        collected.iter().sum::<f64>() / collected.len() as f64
    }
}

fn collapse_route(route: &str, collapse_non_allow_to_deny: bool) -> String {
    if collapse_non_allow_to_deny {
        if route == "allow" {
            "allow".to_string()
        } else {
            "deny".to_string()
        }
    } else {
        route.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn split_benchmark_cases_is_stratified_and_non_empty_when_possible() {
        let cases = vec![
            BenchmarkCase {
                id: "a1".to_string(),
                input: json!({"x": 1}),
                expected_route: "allow".to_string(),
                category: Some("benign".to_string()),
            },
            BenchmarkCase {
                id: "a2".to_string(),
                input: json!({"x": 2}),
                expected_route: "allow".to_string(),
                category: Some("benign".to_string()),
            },
            BenchmarkCase {
                id: "d1".to_string(),
                input: json!({"x": 3}),
                expected_route: "deny".to_string(),
                category: Some("attack".to_string()),
            },
            BenchmarkCase {
                id: "d2".to_string(),
                input: json!({"x": 4}),
                expected_route: "deny".to_string(),
                category: Some("attack".to_string()),
            },
        ];

        let (train, dev) = split_benchmark_cases(cases, 0.5);
        assert_eq!(train.len(), 2);
        assert_eq!(dev.len(), 2);
        assert!(train.iter().any(|case| case.expected_route == "allow"));
        assert!(train.iter().any(|case| case.expected_route == "deny"));
        assert!(dev.iter().any(|case| case.expected_route == "allow"));
        assert!(dev.iter().any(|case| case.expected_route == "deny"));
    }

    #[test]
    fn score_target_counts_binary_matches_correctly() {
        let gate = LogicPearlGateIr::from_json_str(
            &serde_json::to_string(&json!({
                "ir_version": "1.0",
                "gate_id": "demo",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [
                        {"id": "flag", "type": "int", "description": null, "values": null, "min": null, "max": null, "editable": null}
                    ]
                },
                "rules": [{
                    "id": "rule_000",
                    "kind": "predicate",
                    "bit": 0,
                    "deny_when": {"feature": "flag", "op": "==", "value": 1},
                    "label": null,
                    "message": null,
                    "severity": null,
                    "counterfactual_hint": null,
                    "verification_status": "pipeline_unverified"
                }],
                "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
                "verification": null,
                "provenance": null
            }))
            .unwrap(),
        )
        .unwrap();

        let headers = csv::StringRecord::from(vec!["flag", "target_exfiltration"]);
        let records = vec![
            csv::StringRecord::from(vec!["0", "0"]),
            csv::StringRecord::from(vec!["1", "1"]),
            csv::StringRecord::from(vec!["0", "0"]),
        ];
        let score =
            score_target_against_records(&gate, &headers, &records, "target_exfiltration").unwrap();
        assert_eq!(score.rows, 3);
        assert_eq!(score.positive_rows, 1);
        assert_eq!(score.negative_rows, 2);
        assert_eq!(score.matching_rows, 3);
        assert_eq!(score.true_positives, 1);
        assert_eq!(score.true_negatives, 2);
        assert_eq!(score.false_positives, 0);
    }
}
