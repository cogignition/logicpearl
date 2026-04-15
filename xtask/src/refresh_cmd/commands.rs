// SPDX-License-Identifier: MIT
use super::guidance;
use miette::{IntoDiagnostic, Result, WrapErr};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn require_repo_root() -> Result<PathBuf> {
    find_repo_root(&std::env::current_dir().into_diagnostic()?).ok_or_else(|| {
        guidance(
            "could not find the LogicPearl repo root from the current directory",
            "Run this command from inside the checked-out LogicPearl repo.",
        )
    })
}

pub(super) fn find_repo_root(start: &Path) -> Option<PathBuf> {
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

pub(super) fn default_refresh_logs_dir() -> PathBuf {
    std::env::temp_dir()
        .join("logicpearl_refresh_logs")
        .join(unix_timestamp())
}

pub(super) fn unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

pub(super) fn simple_timestamp() -> String {
    unix_timestamp()
}

pub(super) fn refresh_front_door() -> Result<Vec<String>> {
    Ok(vec![std::env::current_exe()
        .into_diagnostic()?
        .display()
        .to_string()])
}

pub(super) fn nested_logicpearl_base_command(use_installed_cli: bool) -> Result<Vec<String>> {
    if use_installed_cli {
        Ok(vec!["logicpearl".to_string()])
    } else {
        let repo_root = require_repo_root()?;
        Ok(vec![
            "cargo".to_string(),
            "run".to_string(),
            "--manifest-path".to_string(),
            repo_root.join("Cargo.toml").display().to_string(),
            "-p".to_string(),
            "logicpearl".to_string(),
            "--".to_string(),
        ])
    }
}

pub(super) fn build_nested_command(base: &[String], args: &[&str]) -> Vec<String> {
    let mut command = base.to_vec();
    command.extend(args.iter().map(|value| value.to_string()));
    command
}

pub(super) fn build_nested_command_with_paths(
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

pub(super) fn run_json_command(repo_root: &Path, command: &[String]) -> Result<Value> {
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

pub(super) fn run_json_commands_parallel(
    repo_root: &Path,
    commands: Vec<(String, Vec<String>)>,
) -> Result<Vec<(String, Value)>> {
    if commands.is_empty() {
        return Ok(Vec::new());
    }

    let (tx, rx) = mpsc::channel();
    let repo_root = repo_root.to_path_buf();
    for (index, (label, command)) in commands.into_iter().enumerate() {
        let tx = tx.clone();
        let repo_root = repo_root.clone();
        thread::spawn(move || {
            let result = run_json_command(&repo_root, &command)
                .map(|value| (index, label, value))
                .map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
    }
    drop(tx);

    let mut completed = Vec::new();
    for message in rx {
        match message {
            Ok(item) => completed.push(item),
            Err(message) => return Err(miette::miette!(message)),
        }
    }
    completed.sort_by_key(|(index, _, _)| *index);
    Ok(completed
        .into_iter()
        .map(|(_, label, value)| (label, value))
        .collect())
}

pub(super) fn run_plain_command(repo_root: &Path, command: &[String]) -> Result<()> {
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
