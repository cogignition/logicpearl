use super::*;
use crate::observer_cmd::{
    observe_benchmark_cases, observer_resolution, render_observer_resolution, resolve_observer_for_cases,
};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};

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
    for input in &args.inputs {
        let cases = load_benchmark_cases(input)
            .into_diagnostic()
            .wrap_err("failed to load benchmark cases for merge")?;
        for case in cases {
            if !seen_ids.insert(case.id.clone()) {
                return Err(guidance(
                    format!("duplicate benchmark case id detected: {}", case.id),
                    "Make sure merged benchmark-case files have unique ids before combining them.",
                ));
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
                "inputs": args.inputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "output": args.output.display().to_string()
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Merged".bold().bright_green(), "benchmark cases".bold());
        println!("  {} {}", "Inputs".bright_black(), args.inputs.len());
        println!("  {} {}", "Rows".bright_black(), total_rows);
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
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
        println!("{} {}", "Prepared".bold().bright_green(), "benchmark dataset".bold());
        println!("  {} {}", "Observed".bright_black(), observed_rows);
        println!(
            "  {} {}",
            "Observer".bright_black(),
            render_observer_resolution(&observer_resolution(&observer))
        );
        println!("  {} {}", "Observed output".bright_black(), observed_path.display());
        println!("  {} {}", "Trace output".bright_black(), traces_dir.display());
        if let Some(discover_result) = discover_result {
            println!("  {} {}", "Artifacts".bright_black(), discover_result.artifacts.len());
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
        println!("{} {}", "Observed".bold().bright_green(), "benchmark cases".bold());
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
            println!("  {} {}", profile.id.bold(), profile.description.bright_black());
            println!("    {} {}", "Format".bright_black(), profile.source_format);
            println!("    {} {}", "Default route".bright_black(), profile.default_route);
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
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    } else {
        println!("{} {}", "Detected".bold().bright_green(), profile.id().bold());
        println!("  {} {}", "Dataset".bright_black(), args.raw_dataset.display());
    }
    Ok(())
}

pub(crate) fn run_benchmark_emit_traces(args: BenchmarkEmitTracesArgs) -> Result<()> {
    let summary = emit_trace_tables(&args.observed_jsonl, &args.config, &args.output_dir)
        .into_diagnostic()
        .wrap_err("failed to emit trace tables")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary).into_diagnostic()?);
    } else {
        println!("{} {}", "Emitted".bold().bright_green(), "discovery traces".bold());
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
        BenchmarkAdapterProfile::Auto => unreachable!("auto profile should be resolved before dispatch"),
        BenchmarkAdapterProfile::SaladBaseSet => run_benchmark_adapt_salad(BenchmarkAdaptSaladArgs {
            raw_salad_json: args.raw_dataset,
            subset: SaladSubset::BaseSet,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
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
        BenchmarkAdapterProfile::Alert => run_benchmark_adapt_alert(BenchmarkAdaptAlertArgs {
            raw_alert_json: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
        BenchmarkAdapterProfile::Squad => run_benchmark_adapt_squad(BenchmarkAdaptSquadArgs {
            raw_squad_json: args.raw_dataset,
            output: args.output,
            requested_tool: args.requested_tool,
            requested_action: args.requested_action,
            scope: args.scope,
            json: args.json,
        }),
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
        println!("{} {}", "Adapted".bold().bright_green(), "Salad-Data dataset".bold());
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
        println!("{} {}", "Adapted".bold().bright_green(), "ALERT dataset".bold());
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
        println!("{} {}", "Adapted".bold().bright_green(), "SQuAD dataset".bold());
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
        println!("{} {}", "Adapted".bold().bright_green(), "PINT dataset".bold());
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

    let mut results = Vec::with_capacity(cases.len());
    let mut matched_cases = 0_usize;
    let mut attack_cases = 0_usize;
    let mut benign_cases = 0_usize;
    let mut caught_attacks = 0_usize;
    let mut benign_passes = 0_usize;
    let mut false_positives = 0_usize;
    let mut category_totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_matches: BTreeMap<String, usize> = BTreeMap::new();

    for case in cases {
        let execution = pipeline
            .run(base_dir, &case.input)
            .into_diagnostic()
            .wrap_err(format!("benchmark pipeline execution failed for case {}", case.id))?;

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
        let actual_route = collapse_route(actual_route_raw, args.collapse_non_allow_to_deny);
        let expected_route = collapse_route(&case.expected_route, args.collapse_non_allow_to_deny);
        let matched = actual_route == expected_route;
        if matched {
            matched_cases += 1;
        }

        let attack_confidence = execution.output.get("attack_confidence").and_then(Value::as_f64);

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

        if let Some(category) = &case.category {
            *category_totals.entry(category.clone()).or_insert(0) += 1;
            if matched {
                *category_matches.entry(category.clone()).or_insert(0) += 1;
            }
        }

        results.push(BenchmarkCaseResult {
            id: case.id,
            expected_route,
            actual_route,
            matched,
            category: case.category,
            attack_confidence,
        });
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
        println!("{}", serde_json::to_string_pretty(&benchmark).into_diagnostic()?);
    } else {
        println!("{} {}", "Benchmark".bold().bright_green(), benchmark.pipeline_id.bold());
        println!("  {} {}", "Cases".bright_black(), benchmark.summary.total_cases);
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

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
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
