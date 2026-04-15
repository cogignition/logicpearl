// SPDX-License-Identifier: MIT
#![recursion_limit = "256"]

use clap::{Args, Parser, Subcommand};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod clean_cmd;
mod compare_cmd;
mod refresh_cmd;
mod verify_cmd;

use clean_cmd::{run_clean_generated, CleanGeneratedArgs};
use compare_cmd::{run_compare_selection_backends, CompareSelectionBackendsArgs};
use refresh_cmd::{
    run_refresh_benchmarks, run_refresh_guardrails_build, run_refresh_guardrails_eval,
    run_refresh_guardrails_freeze, run_refresh_quality_report, run_refresh_waf_benchmark_cases,
    run_refresh_waf_build,
};
use verify_cmd::{run_verify, VerifyArgs};

const XTASK_LONG_ABOUT: &str = "\
LogicPearl project automation lives here.

Use xtask for local verification, benchmark refresh flows, bundle rebuilds, and local quality reports.
This surface is intentionally separate from the user-facing `logicpearl` CLI.";
const XTASK_AFTER_HELP: &str = "\
Examples:
  cargo xtask verify pre-commit
  cargo xtask verify pre-push
  cargo xtask verify ci
  cargo xtask verify solver-backends
  cargo xtask clean-generated
  cargo xtask clean-generated --apply
  cargo xtask compare-selection-backends
  cargo xtask package-release-bundle --logicpearl-binary target/release/logicpearl --z3-binary /usr/bin/z3 --target-triple x86_64-unknown-linux-gnu --output-dir dist
  cargo xtask generate-homebrew-formula --version 0.1.5 --dist-dir dist --output packaging/homebrew/Formula/logicpearl.rb
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
    /// Inspect or remove ignored generated output from local development runs.
    CleanGenerated(CleanGeneratedArgs),
    /// Compare selection backend behavior across representative workloads.
    CompareSelectionBackends(CompareSelectionBackendsArgs),
    /// Package a distributable LogicPearl CLI bundle with a bundled solver.
    PackageReleaseBundle(PackageReleaseBundleArgs),
    /// Generate a tap-ready Homebrew formula from release bundle checksum files.
    GenerateHomebrewFormula(GenerateHomebrewFormulaArgs),
    /// Refresh public benchmark bundles, evals, and a local quality report.
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
    QualityReport(RefreshQualityReportArgs),
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

#[derive(Debug, Args)]
struct GenerateHomebrewFormulaArgs {
    /// Directory containing logicpearl-<target>.tar.gz.sha256 files.
    #[arg(long, default_value = "dist")]
    dist_dir: PathBuf,
    /// Where to write the generated Formula/logicpearl.rb file.
    #[arg(long)]
    output: PathBuf,
    /// Release version. Defaults to the workspace version.
    #[arg(long)]
    version: Option<String>,
    /// GitHub repository that owns release assets.
    #[arg(long, default_value = "LogicPearlHQ/logicpearl")]
    repo: String,
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
struct RefreshQualityReportArgs {
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    pretty: bool,
    #[arg(long)]
    guardrail_bundle_dir: Option<PathBuf>,
    #[arg(long)]
    use_installed_cli: bool,
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

fn now_unix_millis() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .into_diagnostic()?
        .as_millis())
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

fn checksum_name(target_triple: &str) -> String {
    format!("{}.sha256", archive_name(target_triple))
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
        "\nInstall by copying the contents of `bin/` onto your PATH. \
For persistent install options, see docs/install.md in the LogicPearl repository.\n",
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

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {} while hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
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

fn validate_bundled_command(binary_path: &Path, bin_dir: &Path, label: &str) -> Result<()> {
    let output = ProcessCommand::new(binary_path)
        .arg("--version")
        .env("PATH", bin_dir)
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to run bundled {label} for validation"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() || stdout.trim().is_empty() && stderr.trim().is_empty() {
        return Err(miette::miette!(
            "bundled {label} did not run as a self-contained executable: {}\nstdout:\n{}\nstderr:\n{}",
            binary_path.display(),
            stdout,
            stderr
        ));
    }
    Ok(())
}

fn run_package_release_bundle(args: PackageReleaseBundleArgs) -> Result<()> {
    let repo_root = repo_root();
    let version = bundle_version(args.version);
    let bundle_dir_name = bundle_root_name(&version, &args.target_triple);
    let archive_name = archive_name(&args.target_triple);
    let checksum_name = checksum_name(&args.target_triple);
    let staging_dir = args.output_dir.join(&bundle_dir_name);
    let archive_path = args.output_dir.join(&archive_name);
    let checksum_path = args.output_dir.join(&checksum_name);
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
    if checksum_path.exists() {
        std::fs::remove_file(&checksum_path)
            .into_diagnostic()
            .wrap_err("failed to clear previous release checksum")?;
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
    let bundled_z3 = bin_dir.join(z3_binary_name);
    copy_bundle_binary(&args.z3_binary, &bundled_z3)?;
    validate_bundled_command(&bundled_z3, &bin_dir, "z3")?;

    let mut included_binaries = vec![
        logicpearl_binary_name.to_string_lossy().to_string(),
        z3_binary_name.to_string_lossy().to_string(),
    ];

    if let Some(cvc5_binary) = &args.cvc5_binary {
        let cvc5_binary_name = cvc5_binary
            .file_name()
            .ok_or_else(|| miette::miette!("cvc5 binary path must include a file name"))?;
        let bundled_cvc5 = bin_dir.join(cvc5_binary_name);
        copy_bundle_binary(cvc5_binary, &bundled_cvc5)?;
        validate_bundled_command(&bundled_cvc5, &bin_dir, "cvc5")?;
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

    let checksum = sha256_file(&archive_path)?;
    std::fs::write(&checksum_path, format!("{checksum}  {archive_name}\n"))
        .into_diagnostic()
        .wrap_err("failed to write release checksum")?;

    println!(
        "{} {}",
        "Packaged".bold().bright_green(),
        archive_path.display()
    );
    println!(
        "{} {}",
        "Checksummed".bold().bright_green(),
        checksum_path.display()
    );
    Ok(())
}

fn read_release_bundle_checksum(dist_dir: &Path, target_triple: &str) -> Result<String> {
    let checksum_path = dist_dir.join(checksum_name(target_triple));
    let payload = std::fs::read_to_string(&checksum_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", checksum_path.display()))?;
    let checksum = payload
        .split_whitespace()
        .next()
        .ok_or_else(|| miette::miette!("checksum file was empty: {}", checksum_path.display()))?
        .to_ascii_lowercase();
    let valid = checksum.len() == 64 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err(miette::miette!(
            "checksum file did not start with a SHA-256 hex digest: {}",
            checksum_path.display()
        ));
    }
    Ok(checksum)
}

fn release_asset_url(repo: &str, version: &str, target_triple: &str) -> String {
    format!(
        "https://github.com/{repo}/releases/download/{}/{}",
        version_tag(version),
        archive_name(target_triple)
    )
}

fn homebrew_formula(
    version: &str,
    repo: &str,
    checksums: &BTreeMap<&str, String>,
) -> Result<String> {
    let linux = checksums
        .get("x86_64-unknown-linux-gnu")
        .ok_or_else(|| miette::miette!("missing checksum for x86_64-unknown-linux-gnu"))?;
    let mac_intel = checksums
        .get("x86_64-apple-darwin")
        .ok_or_else(|| miette::miette!("missing checksum for x86_64-apple-darwin"))?;
    let mac_arm = checksums
        .get("aarch64-apple-darwin")
        .ok_or_else(|| miette::miette!("missing checksum for aarch64-apple-darwin"))?;

    let linux_url = release_asset_url(repo, version, "x86_64-unknown-linux-gnu");
    let mac_intel_url = release_asset_url(repo, version, "x86_64-apple-darwin");
    let mac_arm_url = release_asset_url(repo, version, "aarch64-apple-darwin");

    Ok(format!(
        r##"# typed: false
# frozen_string_literal: true

class Logicpearl < Formula
  desc "Deterministic policy artifacts from observed decision traces"
  homepage "https://logicpearl.com"
  version "{version}"
  license "MIT"

  depends_on "z3"

  on_macos do
    if Hardware::CPU.arm?
      url "{mac_arm_url}"
      sha256 "{mac_arm}"
    else
      url "{mac_intel_url}"
      sha256 "{mac_intel}"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "{linux_url}"
      sha256 "{linux}"
    end
  end

  def install
    bundle = if (buildpath/"bin/logicpearl").exist?
      buildpath
    else
      Pathname.glob(buildpath/"logicpearl-v*-*").first
    end
    odie "LogicPearl bundle directory was not found" if bundle.nil?

    bin.install bundle/"bin/logicpearl"
    pkgshare.install bundle/"bundle_manifest.json" if (bundle/"bundle_manifest.json").exist?
    doc.install bundle/"README.txt" if (bundle/"README.txt").exist?
    doc.install bundle/"THIRD_PARTY_NOTICES.txt" if (bundle/"THIRD_PARTY_NOTICES.txt").exist?
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/logicpearl --version")
    assert_match "quickstart", shell_output("#{{bin}}/logicpearl --help")
  end
end
"##
    ))
}

fn run_generate_homebrew_formula(args: GenerateHomebrewFormulaArgs) -> Result<()> {
    let version = bundle_version(args.version);
    let mut checksums = BTreeMap::new();
    for target in [
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        checksums.insert(
            target,
            read_release_bundle_checksum(&args.dist_dir, target)?,
        );
    }

    let formula = homebrew_formula(&version, &args.repo, &checksums)?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&args.output, formula)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", args.output.display()))?;
    println!(
        "{} {}",
        "Generated".bold().bright_green(),
        args.output.display()
    );
    Ok(())
}

fn detect_bundle_target_triple() -> Result<String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin".to_string()),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin".to_string()),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu".to_string()),
        (os, arch) => Err(miette::miette!(
            "installer smoke test does not support this host target: {arch}-{os}"
        )),
    }
}

fn resolve_binary_on_path(program: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| miette::miette!("PATH is not set while resolving `{program}`"))?;
    let mut shim_fallback = None;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            if candidate.components().any(|component| {
                component.as_os_str() == std::ffi::OsStr::new(".pyenv")
                    || component.as_os_str() == std::ffi::OsStr::new("shims")
            }) {
                shim_fallback.get_or_insert(candidate);
                continue;
            }
            return Ok(candidate);
        }
    }
    if let Some(candidate) = shim_fallback {
        return Ok(candidate);
    }
    Err(miette::miette!(
        "required binary `{program}` was not found on PATH"
    ))
}

fn run_install_smoke_test(repo_root: &Path) -> Result<()> {
    println!("{}", "Running LogicPearl installer smoke test".bold());
    let target_triple = match detect_bundle_target_triple() {
        Ok(target_triple) => target_triple,
        Err(error) => {
            println!(
                "{}",
                format!("Skipping installer smoke test: {error}").yellow()
            );
            return Ok(());
        }
    };
    run_repo_command(
        repo_root,
        "cargo",
        &["build", "--manifest-path", "Cargo.toml", "-p", "logicpearl"],
    )?;

    let smoke_root = repo_root
        .join("target")
        .join(format!("install-smoke-{}", now_unix_millis()?));
    let dist_dir = smoke_root.join("dist");
    let install_root = smoke_root.join("install-root");
    let bin_dir = smoke_root.join("bin");
    let fixture_dir = smoke_root.join("fixture");
    let output_dir = smoke_root.join("getting-started-output");
    let archive_path = dist_dir.join(archive_name(&target_triple));
    let checksum_path = dist_dir.join(checksum_name(&target_triple));

    run_package_release_bundle(PackageReleaseBundleArgs {
        logicpearl_binary: repo_root.join("target").join("debug").join("logicpearl"),
        z3_binary: resolve_binary_on_path("z3")?,
        cvc5_binary: None,
        target_triple: target_triple.clone(),
        output_dir: dist_dir.clone(),
        version: Some("0.0.0-smoke".to_string()),
    })?;

    let archive_arg = archive_path.display().to_string();
    let checksum_arg = checksum_path.display().to_string();
    let install_root_arg = install_root.display().to_string();
    let bin_dir_arg = bin_dir.display().to_string();

    let mut installer = ProcessCommand::new("sh");
    installer.current_dir(repo_root).args([
        "install.sh",
        "--archive-url",
        &archive_arg,
        "--checksum-url",
        &checksum_arg,
        "--install-root",
        &install_root_arg,
        "--bin-dir",
        &bin_dir_arg,
    ]);
    run_command(&mut installer)?;

    let installed_logicpearl = bin_dir.join("logicpearl");
    let installed_z3 = bin_dir.join("z3");
    if !installed_logicpearl.exists() || !installed_z3.exists() {
        return Err(miette::miette!(
            "installer smoke test did not create expected symlinks under {}",
            bin_dir.display()
        ));
    }

    let mut quickstart = ProcessCommand::new(&installed_logicpearl);
    quickstart
        .current_dir(&smoke_root)
        .env("PATH", &bin_dir)
        .arg("quickstart");
    run_command(&mut quickstart)?;

    fs::create_dir_all(&fixture_dir)
        .into_diagnostic()
        .wrap_err("failed to create installer smoke fixture directory")?;
    fs::copy(
        repo_root.join("examples/getting_started/decision_traces.csv"),
        fixture_dir.join("decision_traces.csv"),
    )
    .into_diagnostic()
    .wrap_err("failed to stage installer smoke trace fixture")?;
    fs::copy(
        repo_root.join("examples/getting_started/new_input.json"),
        fixture_dir.join("new_input.json"),
    )
    .into_diagnostic()
    .wrap_err("failed to stage installer smoke input fixture")?;

    let output_arg = output_dir.display().to_string();
    let mut build = ProcessCommand::new(&installed_logicpearl);
    build
        .current_dir(&smoke_root)
        .env("PATH", &bin_dir)
        .env("LOGICPEARL_SOLVER_BACKEND", "z3")
        .env("LOGICPEARL_SOLVER_DIR", &bin_dir)
        .args([
            "build",
            "fixture/decision_traces.csv",
            "--output-dir",
            &output_arg,
        ]);
    run_command(&mut build)?;

    if !output_dir.join("artifact.json").exists() || !output_dir.join("pearl.ir.json").exists() {
        return Err(miette::miette!(
            "installer smoke test build did not emit the expected artifact bundle in {}",
            output_dir.display()
        ));
    }
    let build_report_path = output_dir.join("build_report.json");
    let build_report: Value = serde_json::from_str(
        &fs::read_to_string(&build_report_path)
            .into_diagnostic()
            .wrap_err("failed to read installer smoke build report")?,
    )
    .into_diagnostic()
    .wrap_err("installer smoke build report was invalid JSON")?;
    if build_report["exact_selection"]["backend"].as_str() != Some("smt")
        || build_report["exact_selection"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("failed"))
    {
        return Err(miette::miette!(
            "installer smoke test did not use the bundled z3 cleanly; exact_selection={}",
            build_report["exact_selection"]
        ));
    }

    let mut inspect = ProcessCommand::new(&installed_logicpearl);
    inspect
        .current_dir(&smoke_root)
        .env("PATH", &bin_dir)
        .args(["inspect", &output_arg, "--json"]);
    run_command(&mut inspect)?;

    let mut run = ProcessCommand::new(&installed_logicpearl);
    run.current_dir(&smoke_root).env("PATH", &bin_dir).args([
        "run",
        &output_arg,
        "fixture/new_input.json",
    ]);
    run_command(&mut run)?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify(args) => run_verify(args),
        Commands::CleanGenerated(args) => run_clean_generated(args),
        Commands::CompareSelectionBackends(args) => run_compare_selection_backends(args),
        Commands::PackageReleaseBundle(args) => run_package_release_bundle(args),
        Commands::GenerateHomebrewFormula(args) => run_generate_homebrew_formula(args),
        Commands::RefreshBenchmarks(args) => run_refresh_benchmarks(args),
        Commands::GuardrailsFreeze(args) => run_refresh_guardrails_freeze(args),
        Commands::GuardrailsBuild(args) => run_refresh_guardrails_build(args),
        Commands::GuardrailsEval(args) => run_refresh_guardrails_eval(args),
        Commands::WafCases(args) => run_refresh_waf_benchmark_cases(args),
        Commands::WafBuild(args) => run_refresh_waf_build(args),
        Commands::QualityReport(args) => run_refresh_quality_report(args),
    }
}
