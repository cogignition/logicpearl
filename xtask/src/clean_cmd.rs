// SPDX-License-Identifier: MIT
use clap::Args;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::repo_root;

#[derive(Debug, Args)]
pub(crate) struct CleanGeneratedArgs {
    /// Actually remove the generated paths. Without this flag, the command is a dry run.
    #[arg(long)]
    apply: bool,
    /// Also include the full root target/ Cargo build cache.
    #[arg(long)]
    include_cargo_target: bool,
}

#[derive(Debug, Clone)]
struct CleanupCandidate {
    path: PathBuf,
    reason: &'static str,
}

pub(crate) fn run_clean_generated(args: CleanGeneratedArgs) -> Result<()> {
    let repo_root = repo_root();
    let candidates = cleanup_candidates(&repo_root, args.include_cargo_target)?;
    let existing = candidates
        .into_iter()
        .filter(|candidate| cleanup_candidate_exists(&candidate.path))
        .collect::<Vec<_>>();
    let existing = prune_nested_cleanup_candidates(existing);

    if existing.is_empty() {
        println!("{}", "No generated paths found.".green());
        return Ok(());
    }

    let action = if args.apply {
        "Removing"
    } else {
        "Would remove"
    };
    println!(
        "{}",
        format!("{action} {} generated paths:", existing.len()).bold()
    );
    for candidate in &existing {
        let path = repo_relative_display(&repo_root, &candidate.path);
        println!(
            "  {} {}",
            path.bold(),
            format!("({})", candidate.reason).dimmed()
        );
    }

    if !args.apply {
        println!(
            "{}",
            "Dry run only; pass --apply to remove these paths.".yellow()
        );
        if !args.include_cargo_target {
            println!(
                "{}",
                "Pass --include-cargo-target to include the full root target/ build cache."
                    .dimmed()
            );
        }
        return Ok(());
    }

    for candidate in &existing {
        remove_cleanup_candidate(&candidate.path)?;
    }
    println!("{}", "Generated paths removed.".green());
    Ok(())
}

fn cleanup_candidates(
    repo_root: &Path,
    include_cargo_target: bool,
) -> Result<Vec<CleanupCandidate>> {
    let mut candidates = BTreeMap::new();

    if include_cargo_target {
        add_cleanup_candidate(
            &mut candidates,
            repo_root.join("target"),
            "root Cargo build cache",
        );
    } else {
        add_cleanup_candidate(
            &mut candidates,
            repo_root.join("target/generated"),
            "generated native/wasm compile crates",
        );
        add_cleanup_candidate(
            &mut candidates,
            repo_root.join("target/package"),
            "cargo package staging",
        );
        add_cleanup_candidate(
            &mut candidates,
            repo_root.join("target/compare-selection-backends"),
            "selection backend comparison output",
        );
        collect_child_dirs_with_prefix(
            &repo_root.join("target"),
            "install-smoke-",
            &mut candidates,
            "installer smoke test staging",
        )?;
    }

    add_cleanup_candidate(
        &mut candidates,
        repo_root.join("reserved-python/logicpearl/target"),
        "reserved Python package Cargo build cache",
    );
    collect_direct_child_targets(
        &repo_root.join("reserved-crates"),
        &mut candidates,
        "reserved crate Cargo build cache",
    )?;
    collect_named_dirs(
        &repo_root.join("benchmarks"),
        "output",
        &mut candidates,
        "benchmark generated output",
    )?;
    collect_getting_started_outputs(&repo_root.join("examples/getting_started"), &mut candidates)?;
    collect_named_dirs(
        &repo_root.join("demos"),
        "data",
        &mut candidates,
        "demo generated data",
    )?;
    collect_named_dirs(
        &repo_root.join("benchmarks"),
        "__pycache__",
        &mut candidates,
        "Python bytecode cache",
    )?;
    collect_named_dirs(
        &repo_root.join("examples"),
        "__pycache__",
        &mut candidates,
        "Python bytecode cache",
    )?;
    collect_named_dirs(
        &repo_root.join("scripts"),
        "__pycache__",
        &mut candidates,
        "Python bytecode cache",
    )?;
    add_cleanup_candidate(
        &mut candidates,
        repo_root.join("fixtures/ir/eval/.generated-inputs"),
        "generated conformance inputs",
    );
    add_cleanup_candidate(
        &mut candidates,
        repo_root.join("scripts/scoreboard"),
        "generated scoreboard output",
    );
    collect_files_with_suffix(
        &repo_root.join("examples/pipelines/generated"),
        ".pipeline.json",
        &mut candidates,
        "generated pipeline manifest",
    )?;

    Ok(candidates
        .into_iter()
        .map(|(path, reason)| CleanupCandidate { path, reason })
        .collect())
}

fn add_cleanup_candidate(
    candidates: &mut BTreeMap<PathBuf, &'static str>,
    path: PathBuf,
    reason: &'static str,
) {
    candidates.insert(path, reason);
}

fn collect_child_dirs_with_prefix(
    parent: &Path,
    prefix: &str,
    candidates: &mut BTreeMap<PathBuf, &'static str>,
    reason: &'static str,
) -> Result<()> {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).into_diagnostic(),
    };
    for entry in entries {
        let entry = entry.into_diagnostic()?;
        if !entry.file_type().into_diagnostic()?.is_dir() {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            add_cleanup_candidate(candidates, entry.path(), reason);
        }
    }
    Ok(())
}

fn collect_direct_child_targets(
    parent: &Path,
    candidates: &mut BTreeMap<PathBuf, &'static str>,
    reason: &'static str,
) -> Result<()> {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).into_diagnostic(),
    };
    for entry in entries {
        let entry = entry.into_diagnostic()?;
        if !entry.file_type().into_diagnostic()?.is_dir() {
            continue;
        }
        add_cleanup_candidate(candidates, entry.path().join("target"), reason);
    }
    Ok(())
}

fn collect_named_dirs(
    root: &Path,
    name: &str,
    candidates: &mut BTreeMap<PathBuf, &'static str>,
    reason: &'static str,
) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).into_diagnostic(),
    };
    for entry in entries {
        let entry = entry.into_diagnostic()?;
        if !entry.file_type().into_diagnostic()?.is_dir() {
            continue;
        }

        let path = entry.path();
        if entry.file_name() == name {
            add_cleanup_candidate(candidates, path, reason);
        } else {
            collect_named_dirs(&path, name, candidates, reason)?;
        }
    }
    Ok(())
}

fn collect_getting_started_outputs(
    root: &Path,
    candidates: &mut BTreeMap<PathBuf, &'static str>,
) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).into_diagnostic(),
    };
    for entry in entries {
        let entry = entry.into_diagnostic()?;
        if !entry.file_type().into_diagnostic()?.is_dir() {
            continue;
        }

        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name == "output" || file_name.starts_with("output-") {
            add_cleanup_candidate(
                candidates,
                entry.path(),
                "getting-started generated artifact output",
            );
        }
    }
    Ok(())
}

fn collect_files_with_suffix(
    root: &Path,
    suffix: &str,
    candidates: &mut BTreeMap<PathBuf, &'static str>,
    reason: &'static str,
) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).into_diagnostic(),
    };
    for entry in entries {
        let entry = entry.into_diagnostic()?;
        let file_type = entry.file_type().into_diagnostic()?;
        if file_type.is_dir() {
            collect_files_with_suffix(&entry.path(), suffix, candidates, reason)?;
        } else if entry.file_name().to_string_lossy().ends_with(suffix) {
            add_cleanup_candidate(candidates, entry.path(), reason);
        }
    }
    Ok(())
}

fn cleanup_candidate_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn prune_nested_cleanup_candidates(mut candidates: Vec<CleanupCandidate>) -> Vec<CleanupCandidate> {
    candidates.sort_by_key(|candidate| candidate.path.components().count());

    let mut kept = Vec::<CleanupCandidate>::new();
    for candidate in candidates {
        if kept
            .iter()
            .any(|kept_candidate| candidate.path.starts_with(&kept_candidate.path))
        {
            continue;
        }
        kept.push(candidate);
    }
    kept.sort_by(|left, right| left.path.cmp(&right.path));
    kept
}

fn remove_cleanup_candidate(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to inspect {}", path.display()))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    } else {
        fs::remove_file(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

fn repo_relative_display(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
}
