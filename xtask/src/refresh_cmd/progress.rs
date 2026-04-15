// SPDX-License-Identifier: MIT
use super::{commands::simple_timestamp, RefreshProgress, RefreshStep, GUARDRAIL_SIGNALS};
use miette::{IntoDiagnostic, Result};
use owo_colors::OwoColorize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const FAILURE_TAIL_LINES: usize = 40;

pub(super) fn run_refresh_step(
    repo_root: &Path,
    logs_dir: &Path,
    step: &RefreshStep,
    verbose: bool,
    step_index: usize,
    total_steps: usize,
) -> Result<()> {
    let log_path = logs_dir.join(format!("{}.log", step.id));
    println!();
    println!(
        "[{}] ({}/{}) {}",
        simple_timestamp(),
        step_index,
        total_steps,
        step.title.bold()
    );
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
            let progress = refresh_progress_snapshot(step, &log_path, elapsed)?;
            if let Some(progress) = progress {
                if let Some(eta) = progress.eta {
                    println!(
                        "  {} {}s  {}  {}~{}",
                        "Still running".bright_black(),
                        elapsed.as_secs(),
                        progress.detail.bright_black(),
                        "eta".bright_black(),
                        format_short_duration(eta).bright_black()
                    );
                } else {
                    println!(
                        "  {} {}s  {}",
                        "Still running".bright_black(),
                        elapsed.as_secs(),
                        progress.detail.bright_black()
                    );
                }
            } else {
                println!(
                    "  {} {}s",
                    "Still running".bright_black(),
                    elapsed.as_secs()
                );
            }
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

fn refresh_progress_snapshot(
    step: &RefreshStep,
    log_path: &Path,
    elapsed: Duration,
) -> Result<Option<RefreshProgress>> {
    if !log_path.exists() {
        return Ok(None);
    }
    let lines = tail_lines(log_path, 400)?;
    match step.id {
        "04_guardrails_build" => Ok(guardrails_build_progress(&lines, elapsed)),
        "05_guardrails_eval" => Ok(last_meaningful_log_line(&lines)),
        "06_waf_cases" => Ok(last_meaningful_log_line(&lines)),
        "07_waf_build" => Ok(last_meaningful_log_line(&lines)),
        _ => Ok(last_meaningful_log_line(&lines)),
    }
}

fn guardrails_build_progress(lines: &[String], elapsed: Duration) -> Option<RefreshProgress> {
    let mut selected_signals = BTreeSet::new();
    let mut current_signal = None::<String>;
    let mut current_mode = None::<String>;
    let mut current_cap = None::<String>;
    let mut last_phase = None::<&str>;

    for line in lines {
        if let Some(signal) = extract_between(line, "signal=", " ") {
            current_signal = Some(signal.to_string());
        }
        if let Some(mode) = extract_between(line, "mode=", " ") {
            current_mode = Some(
                mode.trim_matches(|c| c == '{' || c == '}' || c == ',')
                    .to_string(),
            );
        }
        if let Some(cap) = extract_between(line, "cap=", " ") {
            current_cap = Some(cap.to_string());
        }
        if line.contains("selected cap=") {
            if let Some(signal) = extract_between(line, "signal=", " ") {
                selected_signals.insert(signal.to_string());
            }
        }
        if line.contains(" benchmark learn ") {
            last_phase = Some("learn");
        } else if line.contains(" benchmark observe ") {
            last_phase = Some("observe");
        } else if line.contains(" benchmark emit-traces ") {
            last_phase = Some("emit-traces");
        } else if line.contains(" benchmark score-artifacts ") {
            last_phase = Some("score-artifacts");
        } else if line.contains(" -- compile ") && line.contains(".pearl.wasm") {
            last_phase = Some("compile-wasm");
        } else if line.contains(" -- compile ") {
            last_phase = Some("compile-native");
        }
    }

    let selected = selected_signals.len();
    if selected >= GUARDRAIL_SIGNALS.len() {
        let detail = match last_phase {
            Some("prepare") => "phase=prepare projected traces".to_string(),
            Some("observe") => "phase=observe final holdout".to_string(),
            Some("emit-traces") => "phase=emit traces".to_string(),
            Some("score-artifacts") => "phase=score artifacts".to_string(),
            Some("compile-native") => "phase=compile native artifact".to_string(),
            Some("compile-wasm") => "phase=compile wasm artifact".to_string(),
            _ => "phase=post-synthesis finalize".to_string(),
        };
        let fraction = match last_phase {
            Some("prepare") => 0.86,
            Some("observe") => 0.96,
            Some("emit-traces") => 0.98,
            Some("score-artifacts") => 0.985,
            Some("compile-native") => 0.99,
            Some("compile-wasm") => 0.995,
            _ => 0.82,
        };
        return Some(RefreshProgress {
            detail,
            eta: estimate_remaining(elapsed, fraction),
        });
    }

    if let Some(signal) = current_signal {
        let mut parts = vec![format!(
            "phase=synthesize signal={}/{}:{}",
            selected + 1,
            GUARDRAIL_SIGNALS.len(),
            signal
        )];
        if let Some(mode) = current_mode {
            parts.push(format!("mode={mode}"));
        }
        if let Some(cap) = current_cap {
            parts.push(format!("cap={cap}"));
        }
        let fraction = match selected {
            0 => 0.33,
            1 => 0.70,
            2 => 0.80,
            _ => 0.82,
        };
        return Some(RefreshProgress {
            detail: parts.join("  "),
            eta: estimate_remaining(elapsed, fraction),
        });
    }

    if selected > 0 {
        return Some(RefreshProgress {
            detail: format!(
                "phase=synthesize completed_signals={}/{}",
                selected,
                GUARDRAIL_SIGNALS.len()
            ),
            eta: estimate_remaining(
                elapsed,
                match selected {
                    1 => 0.68,
                    2 => 0.79,
                    _ => 0.82,
                },
            ),
        });
    }

    last_meaningful_log_line(lines)
}

fn last_meaningful_log_line(lines: &[String]) -> Option<RefreshProgress> {
    lines.iter().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed == "{" || trimmed == "}" || trimmed == "[" || trimmed == "]" {
            return None;
        }
        if trimmed.starts_with('"') || trimmed.starts_with("},") || trimmed.starts_with("],") {
            return None;
        }
        if trimmed.starts_with("[logicpearl ") || trimmed.starts_with("Compiling ") {
            return Some(RefreshProgress {
                detail: trimmed.to_string(),
                eta: None,
            });
        }
        if trimmed.starts_with("Running `") || trimmed.starts_with("Finished `") {
            return Some(RefreshProgress {
                detail: trimmed.to_string(),
                eta: None,
            });
        }
        None
    })
}

fn estimate_remaining(elapsed: Duration, fraction_complete: f64) -> Option<Duration> {
    if elapsed < Duration::from_secs(90) {
        return None;
    }
    if !(0.05..0.995).contains(&fraction_complete) {
        return None;
    }
    let elapsed_secs = elapsed.as_secs_f64();
    let remaining_secs = (elapsed_secs * (1.0 - fraction_complete) / fraction_complete).round();
    if remaining_secs <= 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(remaining_secs))
}

fn format_short_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    if total_secs >= 3600 {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        format!("{hours}h{minutes:02}m")
    } else if total_secs >= 60 {
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{total_secs}s")
    }
}

fn extract_between<'a>(line: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_index = line.find(start)? + start.len();
    let remainder = &line[start_index..];
    let end_index = remainder.find(end).unwrap_or(remainder.len());
    Some(&remainder[..end_index])
}
