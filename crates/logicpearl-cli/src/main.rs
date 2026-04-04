use clap::{Args, Parser, Subcommand};
use logicpearl_core::ArtifactRenderer;
use logicpearl_discovery::{build_pearl_from_rows, BuildOptions, DecisionTraceRow};
use logicpearl_ir::LogicPearlGateIr;
use logicpearl_pipeline::PipelineDefinition;
use logicpearl_plugin::{run_plugin, PluginManifest, PluginRequest, PluginStage};
use logicpearl_observer::status as observer_status;
use logicpearl_render::TextInspector;
use logicpearl_runtime::{evaluate_gate, parse_input_payload};
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "logicpearl",
    version,
    about = "Build, inspect, and run deterministic LogicPearl artifacts.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Build(BuildArgs),
    Compile(CompileArgs),
    Run(RunArgs),
    Inspect(InspectArgs),
    Verify(VerifyArgs),
    Pipeline {
        #[command(subcommand)]
        command: PipelineCommand,
    },
    Observer {
        #[command(subcommand)]
        command: ObserverCommand,
    },
}

#[derive(Debug, Args)]
struct BuildArgs {
    /// Path to a CSV file of labeled decision traces.
    decision_traces: Option<PathBuf>,
    /// Directory to write pearl.ir.json and build_report.json into.
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Gate ID to embed in the emitted pearl.
    #[arg(long)]
    gate_id: Option<String>,
    /// Column name for the decision label.
    #[arg(long, default_value = "allowed")]
    label_column: String,
    /// Plugin manifest for a trace-source plugin that emits decision traces over JSON.
    #[arg(long)]
    trace_plugin_manifest: Option<PathBuf>,
    /// Source passed to the trace-source plugin.
    #[arg(long)]
    trace_plugin_input: Option<String>,
    /// Plugin manifest for an enricher plugin that transforms decision traces over JSON.
    #[arg(long)]
    enricher_plugin_manifest: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    pearl_ir: PathBuf,
    input_json: PathBuf,
}

#[derive(Debug, Args)]
struct CompileArgs {
    pearl_ir: PathBuf,
    /// Rust target triple, for example x86_64-unknown-linux-gnu or x86_64-pc-windows-msvc.
    #[arg(long)]
    target: Option<String>,
    /// Pearl artifact name. Defaults to the gate id.
    #[arg(long)]
    name: Option<String>,
    /// Output executable path. Defaults to <name>.pearl or <name>.pearl.exe for Windows targets.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct InspectArgs {
    pearl_ir: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    pearl_ir: PathBuf,
    /// Plugin manifest for the verifier backend.
    #[arg(long)]
    plugin_manifest: PathBuf,
    /// Optional fixtures or cases payload passed through to the verifier.
    #[arg(long)]
    fixtures: Option<PathBuf>,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum PipelineCommand {
    Validate(PipelineValidateArgs),
    Inspect(PipelineInspectArgs),
    Run(PipelineRunArgs),
}

#[derive(Debug, Args)]
struct PipelineValidateArgs {
    pipeline_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PipelineInspectArgs {
    pipeline_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PipelineRunArgs {
    pipeline_json: PathBuf,
    input_json: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ObserverCommand {
    Validate(ObserverValidateArgs),
    Run(ObserverRunArgs),
}

#[derive(Debug, Args)]
struct ObserverValidateArgs {
    target: PathBuf,
    /// Validate a plugin manifest instead of a static observer artifact.
    #[arg(long)]
    plugin_manifest: bool,
}

#[derive(Debug, Args)]
struct ObserverRunArgs {
    /// Plugin manifest for the observer plugin to execute.
    #[arg(long)]
    plugin_manifest: PathBuf,
    /// Raw input JSON to send to the plugin.
    #[arg(long)]
    input: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => run_build(args),
        Commands::Compile(args) => run_compile(args),
        Commands::Run(args) => run_eval(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Verify(args) => run_verify(args),
        Commands::Pipeline {
            command: PipelineCommand::Validate(args),
        } => run_pipeline_validate(args),
        Commands::Pipeline {
            command: PipelineCommand::Inspect(args),
        } => run_pipeline_inspect(args),
        Commands::Pipeline {
            command: PipelineCommand::Run(args),
        } => run_pipeline_run(args),
        Commands::Observer {
            command: ObserverCommand::Validate(args),
        } => run_observer_validate(args),
        Commands::Observer {
            command: ObserverCommand::Run(args),
        } => run_observer_run(args),
    }
}

fn run_compile(args: CompileArgs) -> Result<()> {
    let gate = LogicPearlGateIr::from_path(&args.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load pearl IR for compilation")?;

    compile_native_runner(
        &args.pearl_ir,
        &gate.gate_id,
        args.name,
        args.target,
        args.output,
    )
}

fn run_build(args: BuildArgs) -> Result<()> {
    let output_dir = args
        .output_dir
        .unwrap_or_else(|| {
            args.decision_traces
                .as_deref()
                .and_then(|path| path.parent())
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("output")
        });
    let gate_id = args
        .gate_id
        .unwrap_or_else(|| {
            args.decision_traces
                .as_deref()
                .and_then(|path| path.file_stem())
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_else(|| "decision_traces".to_string())
        });

    let build_options = BuildOptions {
        output_dir,
        gate_id,
        label_column: args.label_column.clone(),
    };

    let mut rows = match (&args.trace_plugin_manifest, &args.decision_traces) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            let source = args.trace_plugin_input.ok_or_else(|| {
                miette::miette!("--trace-plugin-input is required when using --trace-plugin-manifest")
            })?;
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::TraceSource,
                payload: serde_json::json!({
                    "source": source,
                    "options": {
                        "label_column": build_options.label_column,
                    }
                }),
            };
            let response = run_plugin(&manifest, &request)
                .into_diagnostic()
                .wrap_err("trace plugin execution failed")?;
            let traces_value = response
                .extra
                .get("decision_traces")
                .cloned()
                .ok_or_else(|| miette::miette!("trace plugin response is missing decision_traces"))?;
            let rows: Vec<DecisionTraceRow> = serde_json::from_value(traces_value)
                .into_diagnostic()
                .wrap_err("trace plugin decision_traces payload was invalid")?;
            rows
        }
        (None, Some(decision_traces)) => logicpearl_discovery::load_decision_traces(decision_traces, &build_options.label_column)
            .into_diagnostic()
            .wrap_err("failed to load decision traces")?,
        (Some(_), Some(_)) => {
            return Err(miette::miette!(
                "use either a decision trace CSV positional argument or --trace-plugin-manifest, not both"
            ));
        }
        (None, None) => {
            return Err(miette::miette!(
                "missing input: provide <decision_traces.csv> or --trace-plugin-manifest"
            ));
        }
    };

    if let Some(manifest_path) = &args.enricher_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to load enricher plugin manifest")?;
        if manifest.stage != PluginStage::Enricher {
            return Err(miette::miette!(
                "plugin manifest stage must be enricher, got {:?}",
                manifest.stage
            ));
        }
        let request = PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Enricher,
            payload: serde_json::json!({
                "records": rows,
            }),
        };
        let response = run_plugin(&manifest, &request)
            .into_diagnostic()
            .wrap_err("enricher plugin execution failed")?;
        let records_value = response
            .extra
            .get("records")
            .cloned()
            .ok_or_else(|| miette::miette!("enricher plugin response is missing records"))?;
        rows = serde_json::from_value(records_value)
            .into_diagnostic()
            .wrap_err("enricher plugin records payload was invalid")?;
    }

    let source_name = if let Some(manifest) = &args.trace_plugin_manifest {
        format!(
            "plugin:{}",
            PluginManifest::from_path(manifest)
                .into_diagnostic()
                .wrap_err("failed to reload trace plugin manifest")?
                .name
        )
    } else {
        args.decision_traces
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "decision_traces".to_string())
    };

    let result = build_pearl_from_rows(&rows, source_name, &build_options)
        .into_diagnostic()
        .wrap_err("failed to build pearl from decision traces")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result).into_diagnostic()?);
    } else {
        println!("{} {}", "Built".bold().bright_green(), result.gate_id.bold());
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!("  {} {}", "Rules".bright_black(), result.rules_discovered);
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", result.training_parity * 100.0).bold()
        );
        println!("  {} {}", "Pearl IR".bright_black(), result.output_files.pearl_ir);
        println!(
            "  {} {}",
            "Build report".bright_black(),
            PathBuf::from(&result.output_files.pearl_ir)
                .parent()
                .unwrap()
                .join("build_report.json")
                .display()
        );
    }
    Ok(())
}

fn run_eval(args: RunArgs) -> Result<()> {
    let gate = LogicPearlGateIr::from_path(&args.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load pearl IR")?;
    let payload: Value = serde_json::from_str(
        &fs::read_to_string(&args.input_json)
            .into_diagnostic()
            .wrap_err("failed to read input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse input JSON")?;

    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("failed to normalize runtime input")?;
    let mut outputs = Vec::with_capacity(parsed.len());
    for input in parsed {
        outputs.push(
            evaluate_gate(&gate, &input)
                .into_diagnostic()
                .wrap_err("failed to evaluate pearl")?,
        );
    }
    if outputs.len() == 1 {
        println!("{}", outputs[0]);
    } else {
        println!("{}", serde_json::to_string_pretty(&outputs).into_diagnostic()?);
    }
    Ok(())
}

fn compile_native_runner(
    pearl_ir: &PathBuf,
    gate_id: &str,
    name: Option<String>,
    target_triple: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let pearl_name = name.unwrap_or_else(|| gate_id.to_string());
    let output_path = output.unwrap_or_else(|| default_compiled_output_path(pearl_ir, &pearl_name, target_triple.as_deref()));
    let workspace_root = workspace_root();
    let crate_name = format!("logicpearl_compiled_{}", sanitize_identifier(&pearl_name));
    let build_dir = workspace_root
        .join("target")
        .join("generated")
        .join(&crate_name);
    let src_dir = build_dir.join("src");
    fs::create_dir_all(&src_dir)
        .into_diagnostic()
        .wrap_err("failed to create generated compile directory")?;

    let cargo_toml = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nlogicpearl-ir = {{ path = \"{}\" }}\nlogicpearl-runtime = {{ path = \"{}\" }}\nserde_json = \"1\"\n",
        workspace_root.join("crates/logicpearl-ir").display(),
        workspace_root.join("crates/logicpearl-runtime").display(),
    );
    fs::write(build_dir.join("Cargo.toml"), cargo_toml)
        .into_diagnostic()
        .wrap_err("failed to write generated Cargo.toml")?;

    let escaped_pearl_path = pearl_ir.display().to_string().replace('\\', "\\\\").replace('\"', "\\\"");
    let main_rs = format!(
        "use logicpearl_ir::LogicPearlGateIr;\nuse logicpearl_runtime::{{evaluate_gate, parse_input_payload}};\nuse serde_json::Value;\nuse std::fs;\nuse std::process::ExitCode;\n\nconst PEARL_JSON: &str = include_str!(\"{escaped_pearl_path}\");\n\nfn main() -> ExitCode {{\n    match run() {{\n        Ok(()) => ExitCode::SUCCESS,\n        Err(err) => {{\n            eprintln!(\"{{}}\", err);\n            ExitCode::FAILURE\n        }}\n    }}\n}}\n\nfn run() -> Result<(), Box<dyn std::error::Error>> {{\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() != 2 {{\n        return Err(\"usage: compiled-pearl <input.json>\".into());\n    }}\n    let gate = LogicPearlGateIr::from_json_str(PEARL_JSON)?;\n    let payload: Value = serde_json::from_str(&fs::read_to_string(&args[1])?)?;\n    let parsed = parse_input_payload(payload)?;\n    let mut outputs = Vec::with_capacity(parsed.len());\n    for input in parsed {{\n        outputs.push(evaluate_gate(&gate, &input)?);\n    }}\n    if outputs.len() == 1 {{\n        println!(\"{{}}\", outputs[0]);\n    }} else {{\n        println!(\"{{}}\", serde_json::to_string_pretty(&outputs)?);\n    }}\n    Ok(())\n}}\n"
    );
    fs::write(src_dir.join("main.rs"), main_rs)
        .into_diagnostic()
        .wrap_err("failed to write generated runner source")?;

    let mut command = std::process::Command::new("cargo");
    command
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--manifest-path")
        .arg(build_dir.join("Cargo.toml"));
    if let Some(target_triple) = &target_triple {
        command.arg("--target").arg(target_triple);
    }
    let status = command
        .status()
        .into_diagnostic()
        .wrap_err("failed to invoke cargo for native pearl compilation")?;
    if !status.success() {
        return Err(miette::miette!(
            "native pearl compilation failed with status {status}. If this is a cross-compile target, make sure the Rust target and linker/toolchain are installed."
        ));
    }

    let built_binary = build_dir
        .join("target")
        .join(target_triple.as_deref().unwrap_or(""))
        .join("release")
        .join(binary_file_name(&crate_name, target_triple.as_deref()));
    fs::create_dir_all(
        output_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )
    .into_diagnostic()
    .wrap_err("failed to create output directory")?;
    fs::copy(&built_binary, &output_path)
        .into_diagnostic()
        .wrap_err("failed to copy compiled pearl binary")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output_path)
            .into_diagnostic()
            .wrap_err("failed to read compiled pearl permissions")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&output_path, perms)
            .into_diagnostic()
            .wrap_err("failed to mark compiled pearl executable")?;
    }

    println!(
        "{} {}",
        "Compiled".bold().bright_green(),
        output_path.display()
    );
    Ok(())
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    let gate = LogicPearlGateIr::from_path(&args.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load pearl IR")?;
    if args.json {
        let summary = serde_json::json!({
            "gate_id": gate.gate_id,
            "ir_version": gate.ir_version,
            "features": gate.input_schema.features.len(),
            "rules": gate.rules.len(),
            "correctness_scope": gate.verification.as_ref().and_then(|verification| verification.correctness_scope.clone()),
            "verification_summary": gate.verification.as_ref().and_then(|verification| verification.verification_summary.clone()),
        });
        println!("{}", serde_json::to_string_pretty(&summary).into_diagnostic()?);
    } else {
        let inspector = TextInspector;
        println!(
            "{}\n{}",
            "LogicPearl Artifact".bold().bright_blue(),
            inspector.render(&gate).into_diagnostic()?
        );
    }
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load verify plugin manifest")?;
    if manifest.stage != PluginStage::Verify {
        return Err(miette::miette!(
            "plugin manifest stage must be verify, got {:?}",
            manifest.stage
        ));
    }
    let pearl_ir: Value = serde_json::from_str(
        &fs::read_to_string(&args.pearl_ir)
            .into_diagnostic()
            .wrap_err("failed to read pearl IR")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse pearl IR JSON")?;
    let fixtures = match args.fixtures {
        Some(path) => Some(
            serde_json::from_str::<Value>(
                &fs::read_to_string(path)
                    .into_diagnostic()
                    .wrap_err("failed to read verifier fixtures")?,
            )
            .into_diagnostic()
            .wrap_err("failed to parse verifier fixtures JSON")?,
        ),
        None => None,
    };
    let request = PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Verify,
        payload: serde_json::json!({
            "pearl_ir": pearl_ir,
            "fixtures": fixtures,
            "constraints": [],
        }),
    };
    let response = run_plugin(&manifest, &request)
        .into_diagnostic()
        .wrap_err("verify plugin execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    } else {
        println!("{} {}", "Verify plugin".bold().bright_yellow(), manifest.name.bold());
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    }
    Ok(())
}

fn run_pipeline_validate(args: PipelineValidateArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("failed to load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let validated = pipeline
        .validate(base_dir)
        .into_diagnostic()
        .wrap_err("pipeline validation failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&validated).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Pipeline".bold().bright_cyan(),
            format!("manifest is valid ({})", validated.pipeline_id).bright_black()
        );
        println!("  {} {}", "Stages".bright_black(), validated.stage_count);
        println!(
            "  {} {}",
            "Exports".bright_black(),
            validated.exports.join(", ")
        );
        for stage in &validated.stages {
            println!(
                "  {} {} {}",
                "-".bright_black(),
                stage.id.bold(),
                format!("{:?}", stage.kind).bright_black()
            );
        }
    }
    Ok(())
}

fn run_pipeline_inspect(args: PipelineInspectArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("failed to load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let validated = pipeline
        .inspect(base_dir)
        .into_diagnostic()
        .wrap_err("pipeline inspection failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&validated).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "String Of Pearls".bold().bright_blue(),
            validated.pipeline_id.bold()
        );
        println!("  {} {}", "Entrypoint".bright_black(), validated.entrypoint);
        println!("  {} {}", "Stages".bright_black(), validated.stage_count);
        println!("  {} {}", "Final exports".bright_black(), validated.exports.join(", "));
        for stage in &validated.stages {
            println!(
                "  {} {} {}",
                "-".bright_black(),
                stage.id.bold(),
                format!("{:?}", stage.kind).bright_black()
            );
            if let Some(artifact) = &stage.artifact {
                println!("    {} {}", "Artifact".bright_black(), artifact);
            }
            if let Some(plugin_manifest) = &stage.plugin_manifest {
                println!("    {} {}", "Plugin".bright_black(), plugin_manifest);
            }
            if !stage.exports.is_empty() {
                println!("    {} {}", "Exports".bright_black(), stage.exports.join(", "));
            }
        }
    }
    Ok(())
}

fn run_pipeline_run(args: PipelineRunArgs) -> Result<()> {
    let pipeline = PipelineDefinition::from_path(&args.pipeline_json)
        .into_diagnostic()
        .wrap_err("failed to load pipeline artifact")?;
    let base_dir = args
        .pipeline_json
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input_json)
            .into_diagnostic()
            .wrap_err("failed to read pipeline input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse pipeline input JSON")?;
    let execution = pipeline
        .run(base_dir, &input)
        .into_diagnostic()
        .wrap_err("pipeline execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&execution).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Pipeline".bold().bright_green(),
            execution.pipeline_id.bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&execution.output).into_diagnostic()?
        );
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("logicpearl-cli crate should live under workspace/crates/logicpearl-cli")
}

fn sanitize_identifier(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "pearl".to_string()
    } else {
        out
    }
}

fn default_compiled_output_path(
    pearl_ir: &PathBuf,
    pearl_name: &str,
    target_triple: Option<&str>,
) -> PathBuf {
    pearl_ir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(binary_file_name(&format!("{pearl_name}.pearl"), target_triple))
}

fn binary_file_name(base: &str, target_triple: Option<&str>) -> String {
    if target_is_windows(target_triple) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn target_is_windows(target_triple: Option<&str>) -> bool {
    target_triple
        .map(|target| target.contains("windows"))
        .unwrap_or(cfg!(target_os = "windows"))
}

fn run_observer_validate(args: ObserverValidateArgs) -> Result<()> {
    if args.plugin_manifest {
        let manifest = PluginManifest::from_path(&args.target)
            .into_diagnostic()
            .wrap_err("failed to load plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(miette::miette!(
                "plugin manifest stage must be observer, got {:?}",
                manifest.stage
            ));
        }
        println!(
            "{} {}",
            "Observer plugin".bold().bright_magenta(),
            format!("manifest is valid ({})", manifest.name).bright_black()
        );
    } else {
        let _payload = fs::read_to_string(&args.target)
            .into_diagnostic()
            .wrap_err("failed to read observer JSON")?;
        let status = observer_status().into_diagnostic()?;
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            format!("validation entrypoint ready ({status})").bright_black()
        );
    }
    Ok(())
}

fn run_observer_run(args: ObserverRunArgs) -> Result<()> {
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load observer plugin manifest")?;
    if manifest.stage != PluginStage::Observer {
        return Err(miette::miette!(
            "plugin manifest stage must be observer, got {:?}",
            manifest.stage
        ));
    }
    let raw_input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input)
            .into_diagnostic()
            .wrap_err("failed to read observer input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("failed to parse observer input JSON")?;

    let request = PluginRequest {
        protocol_version: "1".to_string(),
        stage: PluginStage::Observer,
        payload: serde_json::json!({
            "raw_input": raw_input,
        }),
    };
    let response = run_plugin(&manifest, &request)
        .into_diagnostic()
        .wrap_err("observer plugin execution failed")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Observer plugin".bold().bright_magenta(),
            manifest.name.bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    }
    Ok(())
}
