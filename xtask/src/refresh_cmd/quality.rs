// SPDX-License-Identifier: MIT
use super::{
    commands::{
        build_nested_command, nested_logicpearl_base_command, run_json_command, unix_timestamp,
    },
    detect_bundle_target_goal, git_output,
    io::write_json_pretty,
    BENCHMARK_BATCH_SAMPLE, DEFAULT_DATASETS_ENV, DEMO_CASES, GETTING_STARTED_CSV,
    GETTING_STARTED_INPUT, QUALITY_REPORT_PATH,
};
use crate::RefreshQualityReportArgs;
use miette::{IntoDiagnostic, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(crate) fn run_refresh_quality_report(args: RefreshQualityReportArgs) -> Result<()> {
    let repo_root = super::commands::require_repo_root()?;
    let cli = nested_logicpearl_base_command(args.use_installed_cli)?;
    let output_path = args
        .output
        .unwrap_or_else(|| repo_root.join(QUALITY_REPORT_PATH));
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
        "generated_by": "cargo xtask quality-report",
        "generated_at": unix_timestamp(),
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

fn measure_getting_started(repo_root: &Path, cli: &[String]) -> Result<(Value, Value)> {
    let temp_dir = unique_temp_dir("logicpearl_quality_getting_started");
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
                "--compile",
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
    let temp_dir = unique_temp_dir("logicpearl_quality_demos");
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
    let temp_dir = unique_temp_dir("logicpearl_quality_guardrails");
    fs::create_dir_all(&temp_dir).into_diagnostic()?;
    let output_dir = temp_dir.join("guardrails");
    let summary = match run_json_command(
        repo_root,
        &build_nested_command(
            cli,
            &[
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
    ) {
        Ok(summary) => summary,
        Err(err) => {
            return Ok((
                json!({
                    "status": "unavailable",
                    "reason": err.to_string(),
                    "bundle_dir": stable_path(repo_root, bundle_dir),
                    "target_goal": target_goal,
                }),
                json!({}),
            ));
        }
    };
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

fn revision_summary(repo_root: &Path) -> Result<Value> {
    Ok(json!({
        "head": git_output(repo_root, &["rev-parse", "HEAD"])?,
    }))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}_{}", prefix, unix_timestamp()))
}
