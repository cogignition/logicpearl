// SPDX-License-Identifier: MIT
use clap::{Args, Subcommand};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use super::{
    command_available, repo_root, run_command, run_install_smoke_test, run_repo_command,
    run_repo_command_with_env,
};

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub(crate) struct VerifyArgs {
    #[command(subcommand)]
    suite: VerifySuite,
}

#[derive(Debug, Subcommand)]
enum VerifySuite {
    /// Fast local checks for each commit.
    PreCommit,
    /// Full local gate before pushing. Includes the CI suite.
    PrePush,
    /// The same verification suite used in GitHub Actions.
    Ci,
    /// Targeted solver parity checks across available backends.
    SolverBackends,
}

fn staged_rust_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let output = ProcessCommand::new("git")
        .current_dir(repo_root)
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "--",
            "*.rs",
        ])
        .output()
        .into_diagnostic()
        .wrap_err("failed to inspect staged Rust files")?;
    if !output.status.success() {
        return Err(miette::miette!(
            "git diff --cached failed while collecting staged Rust files"
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .into_diagnostic()
        .wrap_err("git diff output was not valid UTF-8")?;
    Ok(stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect())
}

fn run_staged_rustfmt_check(repo_root: &Path) -> Result<()> {
    let staged_files = staged_rust_files(repo_root)?;
    if staged_files.is_empty() {
        println!("{}", "No staged Rust files to format-check.".dimmed());
        return Ok(());
    }

    let mut command = ProcessCommand::new("rustfmt");
    command
        .current_dir(repo_root)
        .arg("--check")
        .args(&staged_files);
    run_command(&mut command)
}

fn run_workspace_rustfmt_check(repo_root: &Path) -> Result<()> {
    run_repo_command(repo_root, "cargo", &["fmt", "--all", "--", "--check"])
}

fn run_public_path_hygiene(repo_root: &Path) -> Result<()> {
    let patterns = [
        format!("/{}{}{}", "Users", "/[A-Za-z0-9._-]+", "/"),
        format!("/{}{}{}", "home", "/[A-Za-z0-9._-]+", "/"),
        format!(
            "{}{}{}",
            "[A-Za-z]:", "\\\\Users\\\\[A-Za-z0-9._-]+", "\\\\"
        ),
    ];
    let mut command = ProcessCommand::new("git");
    command
        .current_dir(repo_root)
        .args(["grep", "-n", "-I", "-E"]);
    for pattern in &patterns {
        command.arg("-e").arg(pattern);
    }
    command.args(["--", "."]);

    let output = command
        .output()
        .into_diagnostic()
        .wrap_err("failed to scan tracked files for local absolute paths")?;
    if output.status.code() == Some(1) {
        return Ok(());
    }
    if output.status.success() {
        return Err(miette::miette!(
            "tracked files contain local absolute paths; sanitize fixtures or docs before publishing:\n{}",
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    Err(miette::miette!(
        "local path hygiene scan failed with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_spdx_header_check(repo_root: &Path) -> Result<()> {
    let dirs = ["crates", "xtask/src"];
    let mut missing = Vec::new();
    for dir in &dirs {
        let dir_path = repo_root.join(dir);
        if !dir_path.exists() {
            continue;
        }
        for entry in walkdir(&dir_path) {
            let path = entry.as_path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let content = fs::read_to_string(path).into_diagnostic()?;
            if !content.starts_with("// SPDX-License-Identifier: MIT") {
                if let Ok(rel) = path.strip_prefix(repo_root) {
                    missing.push(rel.display().to_string());
                } else {
                    missing.push(path.display().to_string());
                }
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        missing.sort();
        Err(miette::miette!(
            "the following .rs files are missing the SPDX-License-Identifier: MIT header on line 1:\n  {}",
            missing.join("\n  ")
        ))
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                results.extend(walkdir(&path));
            } else {
                results.push(path);
            }
        }
    }
    results
}

fn run_verify_ci_internal(repo_root: &Path) -> Result<()> {
    run_repo_command(repo_root, "sh", &["-n", "install.sh"])?;
    run_workspace_rustfmt_check(repo_root)?;
    run_public_path_hygiene(repo_root)?;
    run_spdx_header_check(repo_root)?;
    run_workspace_clippy(repo_root)?;
    run_workspace_tests(repo_root)?;
    run_browser_runtime_tests(repo_root)?;
    run_python_runtime_checks(repo_root)?;
    run_install_smoke_test(repo_root)?;
    run_repo_command(
        repo_root,
        "python3",
        &["scripts/release/check_publish_ready.py"],
    )?;
    Ok(())
}

fn run_verify_pre_commit(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl pre-commit checks".bold());
    run_staged_rustfmt_check(repo_root)?;
    run_public_path_hygiene(repo_root)?;
    run_spdx_header_check(repo_root)?;
    run_workspace_clippy(repo_root)?;
    run_pre_commit_contract_tests(repo_root)?;
    run_browser_runtime_tests(repo_root)?;
    run_python_runtime_checks(repo_root)?;
    Ok(())
}

fn run_workspace_clippy(repo_root: &Path) -> Result<()> {
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn run_workspace_tests(repo_root: &Path) -> Result<()> {
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "test",
            "--manifest-path",
            "Cargo.toml",
            "--workspace",
            "--all-targets",
        ],
    )
}

fn run_pre_commit_contract_tests(repo_root: &Path) -> Result<()> {
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "test",
            "--manifest-path",
            "Cargo.toml",
            "-p",
            "logicpearl",
            "--test",
            "e2e_artifact_entrypoints",
        ],
    )?;
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "test",
            "--manifest-path",
            "Cargo.toml",
            "-p",
            "logicpearl",
            "--test",
            "e2e_build_provenance",
        ],
    )?;
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "test",
            "--manifest-path",
            "Cargo.toml",
            "-p",
            "logicpearl",
            "--test",
            "e2e_plugins",
        ],
    )?;
    run_repo_command(
        repo_root,
        "cargo",
        &["test", "--manifest-path", "domains/healthcare/Cargo.toml"],
    )
}

fn run_browser_runtime_tests(repo_root: &Path) -> Result<()> {
    run_repo_command(
        repo_root,
        "node",
        &[
            "--test",
            "packages/logicpearl-browser/test/browser-runtime.test.mjs",
        ],
    )
}

fn run_python_runtime_checks(repo_root: &Path) -> Result<()> {
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "clippy",
            "--manifest-path",
            "packages/logicpearl-python/Cargo.toml",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run_repo_command(
        repo_root,
        "cargo",
        &[
            "test",
            "--manifest-path",
            "packages/logicpearl-python/Cargo.toml",
        ],
    )
}

fn run_verify_pre_push(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl pre-push checks".bold());
    run_verify_ci_internal(repo_root)?;
    run_solver_backend_parity(repo_root, false)
}

fn run_verify_ci(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl CI checks".bold());
    run_verify_ci_internal(repo_root)
}

fn run_verify_solver_backends(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl solver backend checks".bold());
    run_solver_backend_parity(repo_root, true)
}

fn run_solver_backend_parity(repo_root: &Path, include_default_backend: bool) -> Result<()> {
    let solver_targets = [
        "test",
        "--manifest-path",
        "Cargo.toml",
        "-p",
        "logicpearl-solver",
        "-p",
        "logicpearl-verify",
        "-p",
        "logicpearl-discovery",
        "-p",
        "logicpearl-observer-synthesis",
    ];

    if include_default_backend {
        run_repo_command(repo_root, "cargo", &solver_targets)?;
    }

    if !command_available("cvc5") {
        println!(
            "{}",
            "Skipping cvc5 parity run because `cvc5` is not available on PATH.".yellow()
        );
        return Ok(());
    }

    run_repo_command_with_env(
        repo_root,
        "cargo",
        &solver_targets,
        &[("LOGICPEARL_SOLVER_BACKEND", "cvc5")],
    )?;
    Ok(())
}

pub(crate) fn run_verify(args: VerifyArgs) -> Result<()> {
    let repo_root = repo_root();
    match args.suite {
        VerifySuite::PreCommit => run_verify_pre_commit(&repo_root),
        VerifySuite::PrePush => run_verify_pre_push(&repo_root),
        VerifySuite::Ci => run_verify_ci(&repo_root),
        VerifySuite::SolverBackends => run_verify_solver_backends(&repo_root),
    }
}
