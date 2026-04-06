use super::*;

pub(crate) fn run_quickstart(args: QuickstartArgs) -> Result<()> {
    match args.topic {
        None => {
            println!("{}", "LogicPearl Quickstart".bold().bright_blue());
            println!(
                "  {}",
                "Choose the shortest path for what you want to prove first:".bright_black()
            );
            println!(
                "  {} {}",
                "Build".bold(),
                "learn one pearl from labeled traces".bright_black()
            );
            println!("    logicpearl quickstart build");
            println!(
                "  {} {}",
                "Pipeline".bold(),
                "run a string-of-pearls artifact".bright_black()
            );
            println!("    logicpearl quickstart pipeline");
            println!(
                "  {} {}",
                "Benchmark".bold(),
                "score a guardrail benchmark slice".bright_black()
            );
            println!("    logicpearl quickstart benchmark");
        }
        Some(QuickstartTopic::Build) => {
            println!("{}", "Quickstart: Build".bold().bright_green());
            println!("  {}", "Build your first pearl:".bright_black());
            println!(
                "  logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output"
            );
            println!("  {}", "Then inspect and run it:".bright_black());
            println!("  logicpearl inspect examples/getting_started/output");
            println!("  logicpearl run examples/getting_started/output examples/getting_started/new_input.json");
        }
        Some(QuickstartTopic::Pipeline) => {
            println!("{}", "Quickstart: Pipeline".bold().bright_green());
            println!(
                "  {}",
                "Run a public string-of-pearls example:".bright_black()
            );
            println!(
                "  logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
            );
            println!(
                "  {}",
                "Trace the full stage-by-stage execution:".bright_black()
            );
            println!(
                "  logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
            );
        }
        Some(QuickstartTopic::Benchmark) => {
            println!("{}", "Quickstart: Benchmark".bold().bright_green());
            println!(
                "  {}",
                "Score the public guardrail benchmark slice:".bright_black()
            );
            println!(
                "  logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json"
            );
            println!(
                "  {}",
                "Inspect the benchmark pipeline if you want the artifact view:".bright_black()
            );
            println!(
                "  logicpearl pipeline inspect benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json"
            );
        }
    }
    Ok(())
}

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

    let output_dir = args.output_dir.unwrap_or_else(|| {
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

    let result = discover_from_csv(
        &args.dataset_csv,
        &DiscoverOptions {
            output_dir,
            artifact_set_id,
            target_columns: targets,
            residual_pass: args.residual_pass,
            refine: args.refine,
            pinned_rules: args.pinned_rules.clone(),
        },
    )
    .into_diagnostic()
    .wrap_err("could not discover artifacts from the dataset")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).into_diagnostic()?
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

pub(crate) fn run_compose(args: ComposeArgs) -> Result<()> {
    if args.artifacts.is_empty() {
        return Err(guidance(
            "compose needs at least one pearl artifact path",
            "Pass one or more pearl.ir.json files after the --output flag.",
        ));
    }
    let base_dir = args
        .output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let plan = compose_pipeline(args.pipeline_id, &args.artifacts, base_dir)
        .into_diagnostic()
        .wrap_err("failed to compose starter pipeline")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create compose output directory")?;
    }
    plan.pipeline
        .write_pretty(&args.output)
        .into_diagnostic()
        .wrap_err("failed to write composed pipeline artifact")?;

    println!(
        "{} {}",
        "Composed".bold().bright_green(),
        args.output.display()
    );
    for note in &plan.notes {
        println!("  {} {}", "Note".bright_black(), note);
    }
    Ok(())
}

pub(crate) fn run_compile(args: CompileArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("failed to load pearl IR for compilation")?;
    if args.target.as_deref() == Some("wasm32-unknown-unknown") {
        let output = compile_wasm_module(
            &resolved.pearl_ir,
            &resolved.artifact_dir,
            &gate.gate_id,
            args.name,
            args.output,
        )?;
        println!(
            "{} {}",
            "Compiled".bold().bright_green(),
            output.module_path.display()
        );
        println!(
            "  {} {}",
            "Wasm metadata".bright_black(),
            output.sidecar_path.display()
        );
    } else {
        let output_path = compile_native_runner(
            &resolved.pearl_ir,
            &resolved.artifact_dir,
            &gate.gate_id,
            args.name,
            args.target,
            args.output,
        )?;
        println!(
            "{} {}",
            "Compiled".bold().bright_green(),
            output_path.display()
        );
    }
    Ok(())
}

pub(crate) fn run_build(args: BuildArgs) -> Result<()> {
    let output_dir = args.output_dir.unwrap_or_else(|| {
        args.decision_traces
            .as_deref()
            .and_then(|path| path.parent())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("output")
    });
    let gate_id = args.gate_id.unwrap_or_else(|| {
        args.decision_traces
            .as_deref()
            .and_then(|path| path.file_stem())
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "decision_traces".to_string())
    });

    let (mut rows, resolved_label_column) = match (
        &args.trace_plugin_manifest,
        &args.decision_traces,
    ) {
        (Some(manifest_path), None) => {
            let manifest = PluginManifest::from_path(manifest_path)
                .into_diagnostic()
                .wrap_err("failed to load trace plugin manifest")?;
            let plugin_label_column = args
                .label_column
                .clone()
                .unwrap_or_else(|| "allowed".to_string());
            let source = args.trace_plugin_input.ok_or_else(|| {
                guidance(
                    "--trace-plugin-manifest was provided without --trace-plugin-input",
                    "Pass the raw source string or path with --trace-plugin-input when using a trace_source plugin.",
                )
            })?;
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::TraceSource,
                payload: serde_json::json!({
                    "source": source,
                    "options": {
                        "label_column": plugin_label_column,
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
                .ok_or_else(|| {
                    guidance(
                        "trace plugin response is missing `decision_traces`",
                        "A trace_source plugin must return a top-level decision_traces array.",
                    )
                })?;
            let rows: Vec<DecisionTraceRow> = serde_json::from_value(traces_value)
                .into_diagnostic()
                .wrap_err("trace plugin decision_traces payload was invalid")?;
            (rows, plugin_label_column)
        }
        (None, Some(decision_traces)) => {
            let loaded = load_decision_traces_auto(
                decision_traces,
                args.label_column.as_deref(),
                args.positive_label.as_deref(),
                args.negative_label.as_deref(),
            )
            .into_diagnostic()
            .wrap_err("failed to load decision traces")?;
            (loaded.rows, loaded.label_column)
        }
        (Some(_), Some(_)) => {
            return Err(guidance(
                "build received both a CSV path and a trace plugin",
                "Use either the positional decision trace dataset input or --trace-plugin-manifest, not both.",
            ));
        }
        (None, None) => {
            return Err(guidance(
                "build is missing an input source",
                "Provide a decision trace dataset path (.csv, .jsonl, or .json) or use --trace-plugin-manifest with --trace-plugin-input.",
            ));
        }
    };

    let build_options = BuildOptions {
        output_dir,
        gate_id,
        label_column: resolved_label_column,
        positive_label: args.positive_label.clone(),
        negative_label: args.negative_label.clone(),
        residual_pass: args.residual_pass,
        refine: args.refine,
        pinned_rules: args.pinned_rules.clone(),
    };

    if let Some(manifest_path) = &args.enricher_plugin_manifest {
        let manifest = PluginManifest::from_path(manifest_path)
            .into_diagnostic()
            .wrap_err("failed to load enricher plugin manifest")?;
        if manifest.stage != PluginStage::Enricher {
            return Err(guidance(
                format!(
                    "plugin manifest stage mismatch: expected enricher, got {:?}",
                    manifest.stage
                ),
                "Use an enricher-stage manifest with --enricher-plugin-manifest.",
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
        let records_value = response.extra.get("records").cloned().ok_or_else(|| {
            guidance(
                "enricher plugin response is missing `records`",
                "An enricher plugin must return a top-level records array compatible with decision traces.",
            )
        })?;
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

    let mut result = build_pearl_from_rows(&rows, source_name, &build_options)
        .into_diagnostic()
        .wrap_err("failed to build pearl from decision traces")?;

    let artifact_dir = PathBuf::from(&result.output_files.artifact_dir);
    let pearl_ir_path = PathBuf::from(&result.output_files.pearl_ir);
    let artifact_name = result.gate_id.clone();
    let native_binary_path = result
        .output_files
        .native_binary
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| native_artifact_output_path(&artifact_dir, &artifact_name, None));
    let native_binary = if native_binary_path.exists() {
        native_binary_path
    } else {
        compile_native_runner(
            &pearl_ir_path,
            &artifact_dir,
            &result.gate_id,
            Some(artifact_name.clone()),
            None,
            Some(native_binary_path),
        )?
    };
    result.output_files.native_binary = Some(native_binary.display().to_string());

    let wasm_output = if is_rust_target_installed("wasm32-unknown-unknown") {
        let wasm_output_path = result
            .output_files
            .wasm_module
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| wasm_artifact_output_path(&artifact_dir, &artifact_name));
        let wasm_sidecar_path = result
            .output_files
            .wasm_sidecar
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| wasm_sidecar_output_path(&artifact_dir, &artifact_name));
        Some(if wasm_output_path.exists() {
            WasmArtifactOutput {
                module_path: wasm_output_path,
                sidecar_path: wasm_sidecar_path,
            }
        } else {
            compile_wasm_module(
                &pearl_ir_path,
                &artifact_dir,
                &result.gate_id,
                Some(artifact_name.clone()),
                Some(wasm_output_path),
            )?
        })
    } else {
        None
    };
    result.output_files.wasm_module = wasm_output
        .as_ref()
        .map(|output| output.module_path.display().to_string());
    result.output_files.wasm_sidecar = wasm_output
        .as_ref()
        .map(|output| output.sidecar_path.display().to_string());
    persist_build_report(&result)?;
    write_named_artifact_manifest(
        &artifact_dir,
        &artifact_name,
        &result.gate_id,
        &result.output_files,
    )?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Built".bold().bright_green(),
            result.gate_id.bold()
        );
        if result.cache_hit {
            println!(
                "  {} {}",
                "Cache".bright_black(),
                "reused prior build output".bold()
            );
        }
        println!("  {} {}", "Rows".bright_black(), result.rows);
        println!("  {} {}", "Rules".bright_black(), result.rules_discovered);
        if result.residual_rules_discovered > 0 {
            println!(
                "  {} {}",
                "Residual rules".bright_black(),
                result.residual_rules_discovered
            );
        }
        if result.refined_rules_applied > 0 {
            println!(
                "  {} {}",
                "Refined rules".bright_black(),
                result.refined_rules_applied
            );
        }
        if result.pinned_rules_applied > 0 {
            println!(
                "  {} {}",
                "Pinned rules".bright_black(),
                result.pinned_rules_applied
            );
        }
        println!(
            "  {} {}",
            "Training parity".bright_black(),
            format!("{:.1}%", result.training_parity * 100.0).bold()
        );
        println!(
            "  {} {}",
            "Artifact bundle".bright_black(),
            result.output_files.artifact_dir
        );
        println!(
            "  {} {}",
            "CLI entrypoint".bright_black(),
            result.output_files.artifact_manifest
        );
        println!(
            "  {} {}",
            "Pearl IR".bright_black(),
            result.output_files.pearl_ir
        );
        println!(
            "  {} {}",
            "Build report".bright_black(),
            result.output_files.build_report
        );
        if let Some(native_binary) = &result.output_files.native_binary {
            println!("  {} {}", "Deployable".bright_black(), native_binary);
        }
        if let Some(wasm_module) = &result.output_files.wasm_module {
            println!("  {} {}", "Deployable".bright_black(), wasm_module);
            if let Some(wasm_sidecar) = &result.output_files.wasm_sidecar {
                println!("  {} {}", "Wasm metadata".bright_black(), wasm_sidecar);
            }
        } else {
            println!(
                "  {} {}",
                "Wasm module".bright_black(),
                "skipped (install wasm32-unknown-unknown to emit it)".bright_black()
            );
        }
    }
    Ok(())
}

pub(crate) fn run_eval(args: RunArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let payload: Value = serde_json::from_str(
        &fs::read_to_string(&args.input_json)
            .into_diagnostic()
            .wrap_err("failed to read input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("input JSON is not valid JSON")?;

    let parsed = parse_input_payload(payload)
        .into_diagnostic()
        .wrap_err("runtime input shape is invalid")?;
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
        println!(
            "{}",
            serde_json::to_string_pretty(&outputs).into_diagnostic()?
        );
    }
    Ok(())
}

pub(crate) fn run_inspect(args: InspectArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let bundle = load_artifact_bundle_descriptor(&resolved.artifact_dir)
        .wrap_err("could not load artifact bundle metadata")?;
    if args.json {
        let summary = serde_json::json!({
            "artifact_dir": resolved.artifact_dir,
            "pearl_ir": resolved.pearl_ir,
            "gate_id": gate.gate_id,
            "ir_version": gate.ir_version,
            "features": gate.input_schema.features.len(),
            "rules": gate.rules.len(),
            "correctness_scope": gate.verification.as_ref().and_then(|verification| verification.correctness_scope.clone()),
            "verification_summary": gate.verification.as_ref().and_then(|verification| verification.verification_summary.clone()),
            "bundle": bundle,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).into_diagnostic()?
        );
    } else {
        let inspector = TextInspector;
        println!("{}", "LogicPearl Artifact".bold().bright_blue());
        if let Some(bundle) = bundle {
            println!(
                "  {} {}",
                "Bundle".bright_black(),
                resolved.artifact_dir.display()
            );
            println!(
                "  {} {}",
                "CLI entrypoint".bright_black(),
                resolved.artifact_dir.join(&bundle.cli_entrypoint).display()
            );
            if let Some(primary_runtime) = &bundle.primary_runtime {
                println!("  {} {}", "Primary runtime".bright_black(), primary_runtime);
            }
            for deployable in &bundle.deployables {
                println!(
                    "  {} {}",
                    "Deployable".bright_black(),
                    resolved.artifact_dir.join(&deployable.path).display()
                );
            }
            for sidecar in &bundle.metadata_sidecars {
                println!(
                    "  {} {}",
                    "Wasm metadata".bright_black(),
                    resolved.artifact_dir.join(&sidecar.path).display()
                );
            }
            println!();
        }
        println!("{}", inspector.render(&gate).into_diagnostic()?);
    }
    Ok(())
}

pub(crate) fn run_verify(args: VerifyArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let manifest = PluginManifest::from_path(&args.plugin_manifest)
        .into_diagnostic()
        .wrap_err("failed to load verify plugin manifest")?;
    if manifest.stage != PluginStage::Verify {
        return Err(guidance(
            format!(
                "plugin manifest stage mismatch: expected verify, got {:?}",
                manifest.stage
            ),
            "Use a verify-stage manifest with `logicpearl verify`.",
        ));
    }
    let pearl_ir: Value = serde_json::from_str(
        &fs::read_to_string(&resolved.pearl_ir)
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
        println!(
            "{} {}",
            "Verify plugin".bold().bright_yellow(),
            manifest.name.bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&response.extra).into_diagnostic()?
        );
    }
    Ok(())
}
