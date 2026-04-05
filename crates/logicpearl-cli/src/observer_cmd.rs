use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ObserverResolution {
    NativeProfile { profile: String },
    NativeArtifact { observer_id: String },
    Plugin { name: String },
}

#[derive(Debug, Clone)]
pub(crate) enum ResolvedObserver {
    NativeProfile(NativeObserverProfile),
    NativeArtifact(NativeObserverArtifact),
    Plugin(PluginManifest),
}

pub(crate) fn to_native_profile(profile: ObserverProfileArg) -> Result<NativeObserverProfile> {
    match profile {
        ObserverProfileArg::GuardrailsV1 => Ok(NativeObserverProfile::GuardrailsV1),
        ObserverProfileArg::Auto => Err(guidance(
            "`auto` is only valid when LogicPearl can inspect input examples",
            "Use a concrete profile like --observer-profile guardrails-v1 or let benchmark observe/prepare auto-detect from dataset input.",
        )),
    }
}

pub(crate) fn to_guardrails_signal(signal: ObserverSignalArg) -> GuardrailsSignal {
    match signal {
        ObserverSignalArg::InstructionOverride => GuardrailsSignal::InstructionOverride,
        ObserverSignalArg::SystemPrompt => GuardrailsSignal::SystemPrompt,
        ObserverSignalArg::SecretExfiltration => GuardrailsSignal::SecretExfiltration,
        ObserverSignalArg::ToolMisuse => GuardrailsSignal::ToolMisuse,
        ObserverSignalArg::DataAccessOutsideScope => GuardrailsSignal::DataAccessOutsideScope,
        ObserverSignalArg::IndirectDocumentAuthority => GuardrailsSignal::IndirectDocumentAuthority,
        ObserverSignalArg::BenignQuestion => GuardrailsSignal::BenignQuestion,
    }
}

pub(crate) fn observer_resolution(observer: &ResolvedObserver) -> ObserverResolution {
    match observer {
        ResolvedObserver::NativeProfile(profile) => ObserverResolution::NativeProfile {
            profile: native_profile_name(*profile).to_string(),
        },
        ResolvedObserver::NativeArtifact(artifact) => ObserverResolution::NativeArtifact {
            observer_id: artifact.observer_id.clone(),
        },
        ResolvedObserver::Plugin(manifest) => ObserverResolution::Plugin {
            name: manifest.name.clone(),
        },
    }
}

pub(crate) fn native_profile_name(profile: NativeObserverProfile) -> &'static str {
    native_profile_id(profile)
}

pub(crate) fn render_observer_resolution(resolution: &ObserverResolution) -> String {
    match resolution {
        ObserverResolution::NativeProfile { profile } => format!("native profile {profile}"),
        ObserverResolution::NativeArtifact { observer_id } => format!("native artifact {observer_id}"),
        ObserverResolution::Plugin { name } => format!("plugin {name}"),
    }
}

pub(crate) fn resolve_observer_for_cases(
    dataset_jsonl: &PathBuf,
    observer_profile: Option<ObserverProfileArg>,
    observer_artifact: Option<PathBuf>,
    plugin_manifest: Option<PathBuf>,
) -> Result<ResolvedObserver> {
    let explicit_count = usize::from(observer_profile.is_some())
        + usize::from(observer_artifact.is_some())
        + usize::from(plugin_manifest.is_some());
    if explicit_count > 1 {
        return Err(guidance(
            "choose only one observer source",
            "Use one of --observer-profile, --observer-artifact, or --plugin-manifest.",
        ));
    }

    if let Some(path) = plugin_manifest {
        let manifest = PluginManifest::from_path(&path)
            .into_diagnostic()
            .wrap_err("failed to load observer plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
                "Use an observer-stage manifest.",
            ));
        }
        return Ok(ResolvedObserver::Plugin(manifest));
    }

    if let Some(path) = observer_artifact {
        let artifact = load_artifact(&path)
            .into_diagnostic()
            .wrap_err("failed to load native observer artifact")?;
        return Ok(ResolvedObserver::NativeArtifact(artifact));
    }

    if let Some(profile) = observer_profile {
        return match profile {
            ObserverProfileArg::Auto => {
                let cases = load_benchmark_cases(dataset_jsonl)
                    .into_diagnostic()
                    .wrap_err("failed to load benchmark dataset for observer auto-detection")?;
                let sample = cases.first().ok_or_else(|| {
                    guidance(
                        "benchmark dataset is empty",
                        "Add at least one case before using --observer-profile auto.",
                    )
                })?;
                let detected = detect_profile_from_input(&sample.input).ok_or_else(|| {
                    guidance(
                        "could not auto-detect a built-in observer profile",
                        "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
                    )
                })?;
                Ok(ResolvedObserver::NativeProfile(detected))
            }
            other => Ok(ResolvedObserver::NativeProfile(to_native_profile(other)?)),
        };
    }

    let cases = load_benchmark_cases(dataset_jsonl)
        .into_diagnostic()
        .wrap_err("failed to load benchmark dataset for observer auto-detection")?;
    let sample = cases.first().ok_or_else(|| {
        guidance(
            "benchmark dataset is empty",
            "Add at least one case before running benchmark observe.",
        )
    })?;
    let detected = detect_profile_from_input(&sample.input).ok_or_else(|| {
        guidance(
            "no observer source was provided and no built-in profile could be auto-detected",
            "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
        )
    })?;
    Ok(ResolvedObserver::NativeProfile(detected))
}

pub(crate) fn resolve_observer_from_input(
    raw_input: &Value,
    observer_profile: Option<ObserverProfileArg>,
    observer_artifact: Option<PathBuf>,
    plugin_manifest: Option<PathBuf>,
) -> Result<ResolvedObserver> {
    let explicit_count = usize::from(observer_profile.is_some())
        + usize::from(observer_artifact.is_some())
        + usize::from(plugin_manifest.is_some());
    if explicit_count > 1 {
        return Err(guidance(
            "choose only one observer source",
            "Use one of --observer-profile, --observer-artifact, or --plugin-manifest.",
        ));
    }

    if let Some(path) = plugin_manifest {
        let manifest = PluginManifest::from_path(&path)
            .into_diagnostic()
            .wrap_err("failed to load observer plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
                "Use an observer-stage manifest.",
            ));
        }
        return Ok(ResolvedObserver::Plugin(manifest));
    }

    if let Some(path) = observer_artifact {
        let artifact = load_artifact(&path)
            .into_diagnostic()
            .wrap_err("failed to load native observer artifact")?;
        return Ok(ResolvedObserver::NativeArtifact(artifact));
    }

    if let Some(profile) = observer_profile {
        return match profile {
            ObserverProfileArg::Auto => {
                let detected = detect_profile_from_input(raw_input).ok_or_else(|| {
                    guidance(
                        "could not auto-detect a built-in observer profile",
                        "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
                    )
                })?;
                Ok(ResolvedObserver::NativeProfile(detected))
            }
            other => Ok(ResolvedObserver::NativeProfile(to_native_profile(other)?)),
        };
    }

    let detected = detect_profile_from_input(raw_input).ok_or_else(|| {
        guidance(
            "no observer source was provided and no built-in profile could be auto-detected",
            "Use --observer-profile <profile>, --observer-artifact, or --plugin-manifest.",
        )
    })?;
    Ok(ResolvedObserver::NativeProfile(detected))
}

pub(crate) fn observe_benchmark_cases(
    dataset_jsonl: &PathBuf,
    observer: &ResolvedObserver,
    output: &PathBuf,
) -> Result<usize> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observed benchmark output directory")?;
    }

    let mut rows = 0_usize;
    let mut out = String::new();
    for case in load_benchmark_cases(dataset_jsonl)
        .into_diagnostic()
        .wrap_err("failed to load benchmark cases for observation")?
    {
        let features = observe_features(observer, &case.input)
            .wrap_err(format!("observer execution failed for case {}", case.id))?;
        let observed = ObservedBenchmarkCase {
            id: case.id,
            input: case.input,
            expected_route: case.expected_route,
            category: case.category,
            features,
        };
        out.push_str(&serde_json::to_string(&observed).into_diagnostic()?);
        out.push('\n');
        rows += 1;
    }

    if rows == 0 {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one benchmark case JSON object per line before running benchmark observe.",
        ));
    }

    fs::write(output, out)
        .into_diagnostic()
        .wrap_err("failed to write observed benchmark JSONL")?;
    Ok(rows)
}

pub(crate) fn observe_features(observer: &ResolvedObserver, raw_input: &Value) -> Result<Map<String, Value>> {
    match observer {
        ResolvedObserver::NativeProfile(profile) => observe_with_profile(*profile, raw_input)
            .into_diagnostic()
            .wrap_err("native observer profile execution failed"),
        ResolvedObserver::NativeArtifact(artifact) => observe_with_artifact(artifact, raw_input)
            .into_diagnostic()
            .wrap_err("native observer artifact execution failed"),
        ResolvedObserver::Plugin(manifest) => {
            let request = PluginRequest {
                protocol_version: "1".to_string(),
                stage: PluginStage::Observer,
                payload: serde_json::json!({
                    "raw_input": raw_input,
                }),
            };
            let response = run_plugin(manifest, &request)
                .into_diagnostic()
                .wrap_err("observer plugin execution failed")?;
            response
                .extra
                .get("features")
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| {
                    guidance(
                        "observer plugin response is missing `features`",
                        "An observer plugin used for benchmark observation must return a top-level features object.",
                    )
                })
        }
    }
}

pub(crate) fn run_observer_validate(args: ObserverValidateArgs) -> Result<()> {
    if args.plugin_manifest {
        let manifest = PluginManifest::from_path(&args.target)
            .into_diagnostic()
            .wrap_err("failed to load plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!("plugin manifest stage mismatch: expected observer, got {:?}", manifest.stage),
                "Use an observer-stage manifest with --plugin-manifest.",
            ));
        }
        println!(
            "{} {}",
            "Observer plugin".bold().bright_magenta(),
            format!("manifest is valid ({})", manifest.name).bright_black()
        );
    } else {
        let artifact = load_artifact(&args.target)
            .into_diagnostic()
            .wrap_err("failed to read native observer artifact")?;
        let status = observer_status().into_diagnostic()?;
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            format!("artifact is valid ({}, id={})", status, artifact.observer_id).bright_black()
        );
    }
    Ok(())
}

pub(crate) fn run_observer_list(args: ObserverListArgs) -> Result<()> {
    let profiles = profile_registry();
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "profiles": profiles }))
                .into_diagnostic()?
        );
    } else {
        println!("{}", "Native Observer Profiles".bold().bright_blue());
        for profile in profiles {
            println!("  {} {}", profile.id.bold(), profile.description.bright_black());
        }
    }
    Ok(())
}

pub(crate) fn run_observer_run(args: ObserverRunArgs) -> Result<()> {
    let raw_input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input)
            .into_diagnostic()
            .wrap_err("failed to read observer input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("observer input JSON is not valid JSON")?;
    let observer = resolve_observer_from_input(
        &raw_input,
        args.observer_profile.clone(),
        args.observer_artifact.clone(),
        args.plugin_manifest.clone(),
    )?;
    let features = observe_features(&observer, &raw_input)?;
    let response = serde_json::json!({
        "features": features,
        "observer": observer_resolution(&observer)
    });
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    } else {
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            render_observer_resolution(&observer_resolution(&observer)).bold()
        );
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    }
    Ok(())
}

pub(crate) fn run_observer_detect(args: ObserverDetectArgs) -> Result<()> {
    let raw_input: Value = serde_json::from_str(
        &fs::read_to_string(&args.input)
            .into_diagnostic()
            .wrap_err("failed to read observer input JSON")?,
    )
    .into_diagnostic()
    .wrap_err("observer input JSON is not valid JSON")?;
    let detected = detect_profile_from_input(&raw_input).map(|profile| ObserverResolution::NativeProfile {
        profile: native_profile_name(profile).to_string(),
    });
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "detected": detected
            }))
            .into_diagnostic()?
        );
    } else if let Some(resolution) = detected {
        println!(
            "{} {}",
            "Detected".bold().bright_green(),
            render_observer_resolution(&resolution)
        );
    } else {
        println!("{}", "No built-in observer profile detected".bright_yellow());
    }
    Ok(())
}

pub(crate) fn run_observer_scaffold(args: ObserverScaffoldArgs) -> Result<()> {
    let profile = to_native_profile(args.profile)?;
    let artifact = default_artifact_for_profile(profile);
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observer scaffold output directory")?;
    }
    fs::write(
        &args.output,
        serde_json::to_string_pretty(&artifact).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write observer artifact")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": args.output.display().to_string(),
                "observer": artifact
            }))
            .into_diagnostic()?
        );
    } else {
        println!("{} {}", "Scaffolded".bold().bright_green(), artifact.observer_id.bold());
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_observer_synthesize(args: ObserverSynthesizeArgs) -> Result<()> {
    let artifact = resolve_synthesis_artifact(args.profile, args.artifact.as_ref())?;
    let signal = to_guardrails_signal(args.signal);
    let cases = load_synthesis_cases(&args.benchmark_cases)
        .into_diagnostic()
        .wrap_err("failed to load synthesis benchmark cases")?;
    if cases.is_empty() {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one benchmark case JSON object per line before running observer synthesize.",
        ));
    }
    let (synthesized, report) = synthesize_guardrails_artifact(
        &artifact,
        signal,
        &cases,
        to_observer_bootstrap_strategy(args.bootstrap),
        &args.positive_routes,
        args.max_candidates,
    )
    .into_diagnostic()
    .wrap_err("failed to synthesize observer artifact")?;

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observer synthesize output directory")?;
    }
    fs::write(
        &args.output,
        serde_json::to_string_pretty(&synthesized).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write synthesized observer artifact")?;

    let response = serde_json::json!({
        "signal": report.signal,
        "bootstrap_mode": report.bootstrap_mode,
        "positive_case_count": report.positive_case_count,
        "negative_case_count": report.negative_case_count,
        "candidate_count": report.candidate_count,
        "phrases_before": report.phrases_before,
        "phrases_after": report.phrases_after,
        "output": args.output.display().to_string(),
        "matched_positives_after": report.matched_positives_after,
        "matched_negatives_after": report.matched_negatives_after,
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    } else {
        println!("{} {}", "Synthesized".bold().bright_green(), report.signal.bold());
        println!("  {} {}", "Output".bright_black(), args.output.display());
        println!("  {} {}", "Candidates".bright_black(), report.candidate_count);
        println!("  {} {}", "Selected".bright_black(), report.phrases_after.join(", "));
    }
    Ok(())
}

pub(crate) fn run_observer_repair(args: ObserverRepairArgs) -> Result<()> {
    let artifact = load_artifact(&args.artifact)
        .into_diagnostic()
        .wrap_err("failed to read native observer artifact")?;
    let signal = to_guardrails_signal(args.signal);
    let cases = load_synthesis_cases(&args.benchmark_cases)
        .into_diagnostic()
        .wrap_err("failed to load synthesis benchmark cases")?;
    if cases.is_empty() {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one benchmark case JSON object per line before running observer repair.",
        ));
    }
    let (repaired, report) = repair_guardrails_artifact(
        &artifact,
        signal,
        &cases,
        to_observer_bootstrap_strategy(args.bootstrap),
        &args.positive_routes,
    )
    .into_diagnostic()
    .wrap_err("failed to repair observer artifact")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observer repair output directory")?;
    }
    fs::write(
        &args.output,
        serde_json::to_string_pretty(&repaired).into_diagnostic()? + "\n",
    )
    .into_diagnostic()
    .wrap_err("failed to write repaired observer artifact")?;

    let response = serde_json::json!({
        "signal": report.signal,
        "input_artifact": args.artifact.display().to_string(),
        "output": args.output.display().to_string(),
        "phrases_before": report.phrases_before,
        "phrases_after": report.phrases_after,
        "removed_phrases": report.removed_phrases,
        "bootstrap_mode": report.bootstrap_mode,
        "positives_preserved": {
            "before": report.before_positive_hits,
            "after": report.after_positive_hits
        },
        "negative_hits": {
            "before": report.before_negative_hits,
            "after": report.after_negative_hits
        },
        "matched_case_counts": {
            "positive": report.matched_positive_cases,
            "negative": report.matched_negative_cases
        }
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response).into_diagnostic()?);
    } else {
        println!("{} {}", "Repaired".bold().bright_green(), report.signal.bold());
        println!("  {} {}", "Output".bright_black(), args.output.display());
        println!(
            "  {} {} -> {}",
            "Negative hits".bright_black(),
            report.before_negative_hits,
            report.after_negative_hits
        );
        println!(
            "  {} {} -> {}",
            "Preserved denied coverage".bright_black(),
            report.before_positive_hits,
            report.after_positive_hits
        );
    }
    Ok(())
}

pub(crate) fn resolve_synthesis_artifact(
    profile: Option<ObserverProfileArg>,
    artifact_path: Option<&PathBuf>,
) -> Result<NativeObserverArtifact> {
    if let Some(path) = artifact_path {
        return load_artifact(path)
            .into_diagnostic()
            .wrap_err("failed to load native observer artifact");
    }
    let profile = match profile {
        Some(ObserverProfileArg::Auto) => {
            return Err(guidance(
                "`auto` is not valid for observer synthesize",
                "Use a concrete profile like --profile guardrails-v1 or provide --artifact.",
            ))
        }
        Some(profile) => to_native_profile(profile)?,
        None => NativeObserverProfile::GuardrailsV1,
    };
    Ok(default_artifact_for_profile(profile))
}
