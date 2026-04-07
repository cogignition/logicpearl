use super::*;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const FAILURE_TAIL_LINES: usize = 40;

#[derive(Debug, Clone)]
struct RefreshStep {
    id: &'static str,
    title: &'static str,
    command: Vec<String>,
    env: Vec<(&'static str, String)>,
}

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

    for step in build_refresh_steps(&repo_root, &args) {
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
        repo_root.join("SCORES.json").display()
    );
    Ok(())
}

fn build_refresh_steps(repo_root: &Path, args: &RefreshBenchmarksArgs) -> Vec<RefreshStep> {
    let mut steps = Vec::new();
    let guardrail_bundle_dir = args.guardrail_bundle_dir.display().to_string();
    let waf_benchmark_dir = args.waf_benchmark_dir.display().to_string();
    let waf_bundle_dir = args.waf_bundle_dir.display().to_string();
    let target_goal = observer_target_goal_name(&args.target_goal).to_string();

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

    steps.push(RefreshStep {
        id: "03_guardrails_freeze",
        title: "Freeze guardrail holdouts",
        command: vec![
            "python3".to_string(),
            repo_root
                .join("scripts/guardrails/freeze_guardrail_holdouts.py")
                .display()
                .to_string(),
        ],
        env: Vec::new(),
    });

    let mut guardrail_build = vec![
        "python3".to_string(),
        repo_root
            .join("scripts/guardrails/build_guardrail_bundle.py")
            .display()
            .to_string(),
        "--output-dir".to_string(),
        guardrail_bundle_dir.clone(),
        "--target-goal".to_string(),
        target_goal,
    ];
    if args.resume {
        guardrail_build.push("--resume".to_string());
    }
    if args.use_installed_cli {
        guardrail_build.push("--use-installed-cli".to_string());
    }
    steps.push(RefreshStep {
        id: "04_guardrails_build",
        title: "Build guardrail bundle",
        command: guardrail_build,
        env: Vec::new(),
    });

    let mut guardrail_eval = vec![
        "python3".to_string(),
        repo_root
            .join("scripts/guardrails/run_open_guardrail_benchmarks.py")
            .display()
            .to_string(),
        "--bundle-dir".to_string(),
        guardrail_bundle_dir.clone(),
        "--input-split".to_string(),
        "final_holdout".to_string(),
        "--output-dir".to_string(),
        args.guardrail_bundle_dir
            .join("open_benchmarks_final_holdout")
            .display()
            .to_string(),
    ];
    if let Some(sample_size) = args.guardrail_sample_size {
        guardrail_eval.push("--sample-size".to_string());
        guardrail_eval.push(sample_size.to_string());
    }
    steps.push(RefreshStep {
        id: "05_guardrails_eval",
        title: "Evaluate open guardrail benchmarks",
        command: guardrail_eval,
        env: Vec::new(),
    });

    steps.push(RefreshStep {
        id: "06_waf_cases",
        title: "Build WAF benchmark cases",
        command: vec![
            "python3".to_string(),
            repo_root
                .join("scripts/waf/build_waf_benchmark_cases.py")
                .display()
                .to_string(),
            "--output-dir".to_string(),
            waf_benchmark_dir.clone(),
        ],
        env: Vec::new(),
    });

    let mut waf_build = vec![
        "python3".to_string(),
        repo_root
            .join("scripts/waf/build_waf_learned_bundle.py")
            .display()
            .to_string(),
        "--output-dir".to_string(),
        waf_bundle_dir,
        "--benchmark-dir".to_string(),
        waf_benchmark_dir,
        "--residual-pass".to_string(),
        "--refine".to_string(),
    ];
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

    steps.push(RefreshStep {
        id: "08_scores",
        title: "Refresh score ledger",
        command: vec![
            "python3".to_string(),
            repo_root
                .join("scripts/scoreboard/update_scores.py")
                .display()
                .to_string(),
        ],
        env: vec![(
            "LOGICPEARL_GUARDRAIL_BUNDLE_DIR",
            guardrail_bundle_dir.clone(),
        )],
    });
    steps.push(RefreshStep {
        id: "09_contributor_points",
        title: "Rebuild contributor points",
        command: vec![
            "python3".to_string(),
            repo_root
                .join("scripts/scoreboard/compute_contributor_points.py")
                .display()
                .to_string(),
        ],
        env: Vec::new(),
    });
    steps.push(RefreshStep {
        id: "10_contributor_summary",
        title: "Rebuild contributor summary",
        command: vec![
            "python3".to_string(),
            repo_root
                .join("scripts/scoreboard/build_contributor_summary.py")
                .display()
                .to_string(),
        ],
        env: Vec::new(),
    });

    steps
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
        let status = command
            .status()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to start {}", step.title))?;
        ensure_step_success(step, status, &log_path)?;
        println!(
            "  {} {}",
            "Status".bright_black(),
            "completed".bright_green()
        );
        return Ok(());
    }

    let log_file = File::create(&log_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create log file for {}", step.title))?;
    let stderr_file = log_file
        .try_clone()
        .into_diagnostic()
        .wrap_err("failed to clone log file handle")?;
    let mut command = Command::new(&step.command[0]);
    command
        .args(&step.command[1..])
        .current_dir(repo_root)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file));
    for (key, value) in &step.env {
        command.env(key, value);
    }
    let mut child = command
        .spawn()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to start {}", step.title))?;
    let started = Instant::now();
    let mut last_heartbeat = Duration::ZERO;
    loop {
        if let Some(status) = child
            .try_wait()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed while waiting for {}", step.title))?
        {
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
    let file = File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read log tail from {}", path.display()))?;
    let lines = BufReader::new(file)
        .lines()
        .collect::<std::io::Result<Vec<_>>>()
        .into_diagnostic()
        .wrap_err("failed to read log lines")?;
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].to_vec())
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

fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join("Cargo.toml").exists()
            && path
                .join("scripts/guardrails/build_guardrail_bundle.py")
                .exists()
            && path
                .join("scripts/waf/build_waf_learned_bundle.py")
                .exists()
        {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
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
        assert!(repo_root
            .join("scripts/guardrails/build_guardrail_bundle.py")
            .exists());
        assert!(repo_root
            .join("scripts/waf/build_waf_learned_bundle.py")
            .exists());
    }
}
