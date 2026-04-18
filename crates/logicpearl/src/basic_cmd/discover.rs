// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_discovery::{
    discover_from_csv_with_progress, discover_result_for_report, DiscoverOptions,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;

use super::{
    feature_column_selection, finish_progress, guidance, progress_callback, progress_enabled,
    start_progress, to_discovery_decision_mode, DiscoverArgs,
};

pub(crate) fn run_discover(args: DiscoverArgs) -> Result<()> {
    let mut targets = args.targets;
    if let Some(target) = args.target {
        targets.push(target);
    }
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(guidance(
            "discover needs at least one explicit target column",
            "Use --target <column> for one binary target or --targets <a,b,c> for multiple targets.",
        ));
    }
    let feature_selection = feature_column_selection(&args.feature_columns, &args.exclude_columns)?;

    let output_dir = args.output_dir.clone().unwrap_or_else(|| {
        args.dataset_csv
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("discovered")
    });
    let artifact_set_id = args.artifact_set_id.unwrap_or_else(|| {
        args.dataset_csv
            .file_stem()
            .map(|stem| format!("{}_artifact_set", stem.to_string_lossy()))
            .unwrap_or_else(|| "artifact_set".to_string())
    });

    let spinner = start_progress(
        progress_enabled(args.json, args.progress),
        format!(
            "discover: building artifacts from {}",
            args.dataset_csv.display()
        ),
    );
    let progress = progress_callback(spinner.as_ref());
    let result = discover_from_csv_with_progress(
        &args.dataset_csv,
        &DiscoverOptions {
            output_dir,
            artifact_set_id,
            target_columns: targets,
            feature_selection,
            residual_pass: args.residual_pass,
            refine: args.refine,
            pinned_rules: args.pinned_rules.clone(),
            feature_dictionary: args.feature_dictionary.clone(),
            feature_governance: args.feature_governance.clone(),
            decision_mode: to_discovery_decision_mode(args.discovery_mode),
        },
        progress.as_deref(),
    )
    .into_diagnostic()
    .wrap_err("could not discover artifacts from the dataset")?;
    finish_progress(spinner);

    if args.json {
        let report = discover_result_for_report(&result);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Discovered".bold().bright_green(),
            result.artifact_set_id.bold()
        );
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!(
            "  {} {}",
            "Features".bright_black(),
            result.features.join(", ")
        );
        println!(
            "  {} {}",
            "Targets".bright_black(),
            result.targets.join(", ")
        );
        println!(
            "  {} {}",
            "Artifacts".bright_black(),
            result.artifacts.len()
        );
        let residual_rules: usize = result
            .artifacts
            .iter()
            .map(|artifact| artifact.residual_rules_discovered)
            .sum();
        let refined_rules: usize = result
            .artifacts
            .iter()
            .map(|artifact| artifact.refined_rules_applied)
            .sum();
        let pinned_rules: usize = result
            .artifacts
            .iter()
            .map(|artifact| artifact.pinned_rules_applied)
            .sum();
        if result.cache_hit {
            println!(
                "  {} {}",
                "Cache".bright_black(),
                "reused full discover output".bold()
            );
        } else if result.cached_artifacts > 0 {
            println!(
                "  {} {}",
                "Cached artifacts".bright_black(),
                result.cached_artifacts
            );
        }
        if residual_rules > 0 {
            println!("  {} {}", "Residual rules".bright_black(), residual_rules);
        }
        if refined_rules > 0 {
            println!("  {} {}", "Refined rules".bright_black(), refined_rules);
        }
        if pinned_rules > 0 {
            println!("  {} {}", "Pinned rules".bright_black(), pinned_rules);
        }
        if !result.skipped_targets.is_empty() {
            for skipped in &result.skipped_targets {
                println!(
                    "  {} {} ({})",
                    "Skipped".bright_black(),
                    skipped.name,
                    skipped.reason
                );
            }
        }
        println!(
            "  {} {}",
            "Artifact set".bright_black(),
            result.output_files.artifact_set
        );
        println!(
            "  {} {}",
            "Discover report".bright_black(),
            result.output_files.discover_report
        );
    }
    Ok(())
}
