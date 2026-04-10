#![recursion_limit = "256"]

use clap::{Args, Parser, Subcommand};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

#[path = "../../crates/logicpearl/src/refresh_cmd.rs"]
mod refresh_cmd;

use refresh_cmd::{
    run_refresh_benchmarks, run_refresh_contributor_points, run_refresh_contributor_summary,
    run_refresh_guardrails_build, run_refresh_guardrails_eval, run_refresh_guardrails_freeze,
    run_refresh_scoreboard_update, run_refresh_waf_benchmark_cases, run_refresh_waf_build,
};

const XTASK_LONG_ABOUT: &str = "\
LogicPearl project automation lives here.

Use xtask for local verification, benchmark refresh flows, bundle rebuilds, and score-ledger maintenance.
This surface is intentionally separate from the `logicpearl` product CLI.";

const XTASK_AFTER_HELP: &str = "\
Examples:
  cargo xtask verify pre-commit
  cargo xtask verify pre-push
  cargo xtask verify ci
  cargo xtask verify solver-backends
  cargo xtask package-release-bundle --logicpearl-binary target/release/logicpearl --z3-binary /usr/bin/z3 --target-triple x86_64-unknown-linux-gnu --output-dir dist
  cargo xtask refresh-benchmarks
  cargo xtask refresh-benchmarks --resume
  cargo xtask refresh-benchmarks --guardrail-sample-size 2000
  cargo xtask refresh-benchmarks --skip-validate";

#[derive(Debug, Parser)]
#[command(name = "xtask", long_about = XTASK_LONG_ABOUT, after_help = XTASK_AFTER_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the shared local and CI verification suites.
    Verify(VerifyArgs),
    /// Package a distributable LogicPearl CLI bundle with a bundled solver.
    PackageReleaseBundle(PackageReleaseBundleArgs),
    /// Refresh public benchmark bundles, evals, and score ledgers.
    RefreshBenchmarks(RefreshBenchmarksArgs),
    #[command(hide = true)]
    GuardrailsFreeze(RefreshGuardrailsFreezeArgs),
    #[command(hide = true)]
    GuardrailsBuild(RefreshGuardrailsBuildArgs),
    #[command(hide = true)]
    GuardrailsEval(RefreshGuardrailsEvalArgs),
    #[command(hide = true)]
    WafCases(RefreshWafBenchmarkCasesArgs),
    #[command(hide = true)]
    WafBuild(RefreshWafBuildArgs),
    #[command(hide = true)]
    ScoreboardUpdate(RefreshScoreboardUpdateArgs),
    #[command(hide = true)]
    ContributorPoints(RefreshContributorPointsArgs),
    #[command(hide = true)]
    ContributorSummary(RefreshContributorSummaryArgs),
}

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
struct VerifyArgs {
    #[command(subcommand)]
    suite: VerifySuite,
}

#[derive(Debug, Args)]
struct PackageReleaseBundleArgs {
    /// Compiled logicpearl binary to bundle.
    #[arg(long)]
    logicpearl_binary: PathBuf,
    /// Z3 binary to bundle alongside logicpearl.
    #[arg(long)]
    z3_binary: PathBuf,
    /// Optional cvc5 binary to bundle alongside logicpearl.
    #[arg(long)]
    cvc5_binary: Option<PathBuf>,
    /// Target triple label used in the archive name.
    #[arg(long)]
    target_triple: String,
    /// Directory to write the staged bundle and archive into.
    #[arg(long)]
    output_dir: PathBuf,
    /// Override bundle version. Defaults to the workspace version.
    #[arg(long)]
    version: Option<String>,
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

#[derive(Debug, Args)]
struct RefreshBenchmarksArgs {
    /// Resume long-running bundle rebuilds where supported.
    #[arg(long)]
    resume: bool,
    /// Skip cargo clippy and cargo test.
    #[arg(long)]
    skip_validate: bool,
    /// Use `logicpearl` from PATH for nested refresh steps instead of `cargo run -p logicpearl --`.
    #[arg(long)]
    use_installed_cli: bool,
    /// Guardrail target goal to use during frozen bundle synthesis.
    #[arg(long, value_enum, default_value_t = ObserverTargetGoalArg::ProtectiveGate)]
    target_goal: ObserverTargetGoalArg,
    /// Directory for the frozen guardrail bundle.
    #[arg(long, default_value = "/private/tmp/guardrails_bundle")]
    guardrail_bundle_dir: PathBuf,
    /// Directory for the adapted WAF benchmark corpus.
    #[arg(long, default_value = "/private/tmp/waf_benchmark")]
    waf_benchmark_dir: PathBuf,
    /// Directory for the learned WAF bundle.
    #[arg(long, default_value = "/private/tmp/waf_learned_bundle")]
    waf_bundle_dir: PathBuf,
    /// Skip native and Wasm compilation during the WAF learned bundle build.
    #[arg(long)]
    waf_skip_compile: bool,
    /// Optional sampled guardrail eval size instead of the full final-holdout run.
    #[arg(long)]
    guardrail_sample_size: Option<usize>,
    /// Directory to write per-step refresh logs into.
    #[arg(long)]
    logs_dir: Option<PathBuf>,
    /// Stream full child command output instead of concise phase logging.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Args)]
struct RefreshGuardrailsFreezeArgs {
    #[arg(long)]
    datasets_root: Option<PathBuf>,
    #[arg(long, default_value_t = 0.9)]
    dev_fraction: f64,
    #[arg(long)]
    use_installed_cli: bool,
}

#[derive(Debug, Args)]
struct RefreshGuardrailsBuildArgs {
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    datasets_root: Option<PathBuf>,
    #[arg(long, default_value_t = 0.9)]
    dev_fraction: f64,
    #[arg(long)]
    use_installed_cli: bool,
    #[arg(long, value_enum, default_value_t = ObserverTargetGoalArg::ParityFirst)]
    target_goal: ObserverTargetGoalArg,
    #[arg(long)]
    resume: bool,
    #[arg(long, default_value_t = 0)]
    dev_case_limit: usize,
    #[arg(long, default_value_t = 0)]
    final_holdout_case_limit: usize,
}

#[derive(Debug, Args)]
struct RefreshGuardrailsEvalArgs {
    #[arg(long)]
    bundle_dir: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    datasets_root: Option<PathBuf>,
    #[arg(long)]
    use_installed_cli: bool,
    #[arg(long, default_value = "final_holdout")]
    input_split: String,
    #[arg(long, default_value_t = 0)]
    sample_size: usize,
    #[arg(long, default_value = "")]
    baseline: String,
    #[arg(long, default_value_t = 0.0)]
    tolerance: f64,
    #[arg(long, default_value = "")]
    target_goal: String,
}

#[derive(Debug, Args)]
struct RefreshWafBenchmarkCasesArgs {
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    datasets_root: Option<PathBuf>,
    #[arg(long)]
    csic_root: Option<PathBuf>,
    #[arg(long)]
    modsecurity_root: Option<PathBuf>,
    #[arg(long, default_value_t = 0.8)]
    dev_fraction: f64,
    #[arg(long)]
    use_installed_cli: bool,
}

#[derive(Debug, Args)]
struct RefreshWafBuildArgs {
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    benchmark_dir: PathBuf,
    #[arg(long)]
    datasets_root: Option<PathBuf>,
    #[arg(long, default_value_t = 0.8)]
    dev_fraction: f64,
    #[arg(long)]
    use_installed_cli: bool,
    #[arg(long)]
    resume: bool,
    #[arg(long, default_value_t = true)]
    refine: bool,
    #[arg(long)]
    skip_compile: bool,
}

#[derive(Debug, Args)]
struct RefreshScoreboardUpdateArgs {
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    pretty: bool,
    #[arg(long)]
    guardrail_bundle_dir: Option<PathBuf>,
    #[arg(long)]
    use_installed_cli: bool,
}

#[derive(Debug, Args)]
struct RefreshContributorPointsArgs {
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RefreshContributorSummaryArgs {
    #[arg(long)]
    input: Option<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ObserverTargetGoalArg {
    ParityFirst,
    ProtectiveGate,
    CustomerSafe,
    Balanced,
    ReviewQueue,
}

fn guidance(message: impl AsRef<str>, hint: impl AsRef<str>) -> miette::Report {
    miette::miette!("{}\n\nHint: {}", message.as_ref(), hint.as_ref())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate should live under the repository root")
        .to_path_buf()
}

fn command_display(command: &ProcessCommand) -> String {
    let program = command.get_program().to_string_lossy();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if args.is_empty() {
        program.into_owned()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

fn run_command(command: &mut ProcessCommand) -> Result<()> {
    let display = command_display(command);
    println!("{}", format!("==> {display}").bold().blue());
    let status = command
        .status()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to start `{display}`"))?;
    if status.success() {
        return Ok(());
    }

    Err(miette::miette!("command failed: {display}"))
}

fn command_available(program: &str) -> bool {
    ProcessCommand::new(program)
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_repo_command(repo_root: &Path, program: &str, args: &[&str]) -> Result<()> {
    let mut command = ProcessCommand::new(program);
    command.current_dir(repo_root).args(args);
    run_command(&mut command)
}

fn run_repo_command_with_env(
    repo_root: &Path,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<()> {
    let mut command = ProcessCommand::new(program);
    command
        .current_dir(repo_root)
        .args(args)
        .envs(envs.iter().copied());
    run_command(&mut command)
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

fn run_verify_ci_internal(repo_root: &Path) -> Result<()> {
    run_repo_command(repo_root, "sh", &["-n", "install.sh"])?;
    run_repo_command(
        repo_root,
        "cargo",
        &["test", "--manifest-path", "Cargo.toml", "--workspace"],
    )?;
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
        &[
            "test",
            "--manifest-path",
            "Cargo.toml",
            "-p",
            "logicpearl",
            "--test",
            "e2e_healthcare_contracts",
        ],
    )?;
    run_repo_command(
        repo_root,
        "node",
        &[
            "--test",
            "packages/logicpearl-browser/test/browser-runtime.test.mjs",
        ],
    )?;
    Ok(())
}

fn run_verify_pre_push(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl pre-push checks".bold());
    run_verify_ci_internal(repo_root)?;
    run_repo_command(
        repo_root,
        "node",
        &[
            "--test",
            "packages/logicpearl-browser/test/browser-runtime.test.mjs",
        ],
    )?;
    Ok(())
}

fn run_verify_ci(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl CI checks".bold());
    run_verify_ci_internal(repo_root)
}

fn run_verify_solver_backends(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl solver backend checks".bold());

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
    run_repo_command(repo_root, "cargo", &solver_targets)?;

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

fn run_verify(args: VerifyArgs) -> Result<()> {
    let repo_root = repo_root();
    match args.suite {
        VerifySuite::PreCommit => run_verify_pre_commit(&repo_root),
        VerifySuite::PrePush => run_verify_pre_push(&repo_root),
        VerifySuite::Ci => run_verify_ci(&repo_root),
        VerifySuite::SolverBackends => run_verify_solver_backends(&repo_root),
    }
}

#[derive(Debug, Serialize)]
struct ReleaseBundleManifest {
    bundle_version: String,
    artifact_name: String,
    target_triple: String,
    included_binaries: Vec<String>,
}

fn bundle_version(version: Option<String>) -> String {
    version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

fn version_tag(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn bundle_root_name(version: &str, target_triple: &str) -> String {
    format!("logicpearl-{}-{target_triple}", version_tag(version))
}

fn archive_name(target_triple: &str) -> String {
    format!("logicpearl-{target_triple}.tar.gz")
}

fn bundle_readme(target_triple: &str, includes_cvc5: bool) -> String {
    let mut readme = format!(
        "LogicPearl install bundle\n\n\
Target: {target_triple}\n\n\
This bundle includes:\n\
- logicpearl\n\
- z3\n"
    );
    if includes_cvc5 {
        readme.push_str("- cvc5\n");
    }
    readme.push_str(
        "\nInstall by copying the contents of `bin/` onto your PATH, or use the repo installer script:\n\
  curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh\n",
    );
    readme
}

fn third_party_notices(includes_cvc5: bool) -> String {
    let mut notices = String::from(
        "Bundled third-party components\n\n\
logicpearl bundles may include upstream solver binaries.\n\n\
- z3\n\
  - upstream: https://github.com/Z3Prover/z3\n\
  - license: MIT\n",
    );
    if includes_cvc5 {
        notices.push_str(
            "\n- cvc5\n\
  - upstream: https://github.com/cvc5/cvc5\n\
  - license: BSD-3-Clause\n",
        );
    }
    notices
}

fn copy_bundle_binary(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_file() {
        return Err(miette::miette!(
            "bundle input binary does not exist: {}",
            source.display()
        ));
    }
    std::fs::copy(source, destination)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to copy {} to bundle", source.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(destination)
            .into_diagnostic()
            .wrap_err("failed to stat bundled binary")?
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(destination, permissions)
            .into_diagnostic()
            .wrap_err("failed to mark bundled binary executable")?;
    }
    Ok(())
}

fn run_package_release_bundle(args: PackageReleaseBundleArgs) -> Result<()> {
    let repo_root = repo_root();
    let version = bundle_version(args.version);
    let bundle_dir_name = bundle_root_name(&version, &args.target_triple);
    let archive_name = archive_name(&args.target_triple);
    let staging_dir = args.output_dir.join(&bundle_dir_name);
    let archive_path = args.output_dir.join(&archive_name);
    let bin_dir = staging_dir.join("bin");
    let share_dir = staging_dir.join("share");
    let licenses_dir = share_dir.join("licenses").join("logicpearl");

    if staging_dir.exists() {
        std::fs::remove_dir_all(&staging_dir)
            .into_diagnostic()
            .wrap_err("failed to clear previous staged release bundle")?;
    }
    if archive_path.exists() {
        std::fs::remove_file(&archive_path)
            .into_diagnostic()
            .wrap_err("failed to clear previous release archive")?;
    }

    std::fs::create_dir_all(&bin_dir)
        .into_diagnostic()
        .wrap_err("failed to create bundle bin directory")?;
    std::fs::create_dir_all(&licenses_dir)
        .into_diagnostic()
        .wrap_err("failed to create bundle license directory")?;

    let logicpearl_binary_name = args
        .logicpearl_binary
        .file_name()
        .ok_or_else(|| miette::miette!("logicpearl binary path must include a file name"))?;
    let z3_binary_name = args
        .z3_binary
        .file_name()
        .ok_or_else(|| miette::miette!("z3 binary path must include a file name"))?;

    copy_bundle_binary(
        &args.logicpearl_binary,
        &bin_dir.join(logicpearl_binary_name),
    )?;
    copy_bundle_binary(&args.z3_binary, &bin_dir.join(z3_binary_name))?;

    let mut included_binaries = vec![
        logicpearl_binary_name.to_string_lossy().to_string(),
        z3_binary_name.to_string_lossy().to_string(),
    ];

    if let Some(cvc5_binary) = &args.cvc5_binary {
        let cvc5_binary_name = cvc5_binary
            .file_name()
            .ok_or_else(|| miette::miette!("cvc5 binary path must include a file name"))?;
        copy_bundle_binary(cvc5_binary, &bin_dir.join(cvc5_binary_name))?;
        included_binaries.push(cvc5_binary_name.to_string_lossy().to_string());
    }

    std::fs::copy(repo_root.join("LICENSE"), licenses_dir.join("LICENSE"))
        .into_diagnostic()
        .wrap_err("failed to copy LogicPearl license into bundle")?;

    std::fs::write(
        staging_dir.join("README.txt"),
        bundle_readme(&args.target_triple, args.cvc5_binary.is_some()),
    )
    .into_diagnostic()
    .wrap_err("failed to write bundle README")?;
    std::fs::write(
        staging_dir.join("THIRD_PARTY_NOTICES.txt"),
        third_party_notices(args.cvc5_binary.is_some()),
    )
    .into_diagnostic()
    .wrap_err("failed to write third-party notices")?;

    let manifest = ReleaseBundleManifest {
        bundle_version: version_tag(&version),
        artifact_name: archive_name.clone(),
        target_triple: args.target_triple.clone(),
        included_binaries,
    };
    std::fs::write(
        staging_dir.join("bundle_manifest.json"),
        serde_json::to_string_pretty(&manifest).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write bundle manifest")?;

    std::fs::create_dir_all(&args.output_dir)
        .into_diagnostic()
        .wrap_err("failed to create bundle output directory")?;

    let mut tar = ProcessCommand::new("tar");
    tar.current_dir(&args.output_dir)
        .args(["-czf", &archive_name, &bundle_dir_name]);
    run_command(&mut tar)?;

    println!(
        "{} {}",
        "Packaged".bold().bright_green(),
        archive_path.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify(args) => run_verify(args),
        Commands::PackageReleaseBundle(args) => run_package_release_bundle(args),
        Commands::RefreshBenchmarks(args) => run_refresh_benchmarks(args),
        Commands::GuardrailsFreeze(args) => run_refresh_guardrails_freeze(args),
        Commands::GuardrailsBuild(args) => run_refresh_guardrails_build(args),
        Commands::GuardrailsEval(args) => run_refresh_guardrails_eval(args),
        Commands::WafCases(args) => run_refresh_waf_benchmark_cases(args),
        Commands::WafBuild(args) => run_refresh_waf_build(args),
        Commands::ScoreboardUpdate(args) => run_refresh_scoreboard_update(args),
        Commands::ContributorPoints(args) => run_refresh_contributor_points(args),
        Commands::ContributorSummary(args) => run_refresh_contributor_summary(args),
    }
}
