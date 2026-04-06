use super::*;
use logicpearl_observer::guardrails_signal_phrases;
use logicpearl_observer_synthesis::{evaluate_guardrails_artifact_signal, ObserverSynthesisReport};
use std::path::Path;

const AUTO_SYNTHESIZE_TRAIN_FRACTION: f64 = 0.9;
const MIN_AUTO_SYNTHESIS_CASES: usize = 40;
const PLUGIN_BATCH_SIZE: usize = 256;

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
        ObserverResolution::NativeArtifact { observer_id } => {
            format!("native artifact {observer_id}")
        }
        ObserverResolution::Plugin { name } => format!("plugin {name}"),
    }
}

pub(crate) fn resolve_observer_for_cases(
    dataset_jsonl: &Path,
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
                format!(
                    "plugin manifest stage mismatch: expected observer, got {:?}",
                    manifest.stage
                ),
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
                format!(
                    "plugin manifest stage mismatch: expected observer, got {:?}",
                    manifest.stage
                ),
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
    dataset_jsonl: &Path,
    observer: &ResolvedObserver,
    output: &PathBuf,
) -> Result<usize> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("failed to create observed benchmark output directory")?;
    }

    let cases = load_benchmark_cases(dataset_jsonl)
        .into_diagnostic()
        .wrap_err("failed to load benchmark cases for observation")?;
    let observed_cases: Vec<ObservedBenchmarkCase> = match observer {
        ResolvedObserver::Plugin(manifest) if manifest.supports_capability("batch_requests") => {
            let mut observed = Vec::with_capacity(cases.len());
            for chunk in cases.chunks(PLUGIN_BATCH_SIZE) {
                let payloads = chunk
                    .iter()
                    .map(|case| {
                        serde_json::json!({
                            "raw_input": case.input
                        })
                    })
                    .collect::<Vec<_>>();
                let responses = run_plugin_batch(manifest, PluginStage::Observer, &payloads)
                    .into_diagnostic()
                    .wrap_err("observer plugin batch execution failed")?;
                for (case, response) in chunk.iter().zip(responses) {
                    let features = response
                        .extra
                        .get("features")
                        .and_then(Value::as_object)
                        .cloned()
                        .ok_or_else(|| {
                            guidance(
                                "observer plugin batch response is missing `features`",
                                "An observer plugin used for benchmark observation must return a top-level features object.",
                            )
                        })?;
                    observed.push(ObservedBenchmarkCase {
                        id: case.id.clone(),
                        input: case.input.clone(),
                        expected_route: case.expected_route.clone(),
                        category: case.category.clone(),
                        features,
                    });
                }
            }
            observed
        }
        _ => cases
            .into_iter()
            .map(|case| {
                let features = observe_features(observer, &case.input)
                    .wrap_err(format!("observer execution failed for case {}", case.id))?;
                Ok(ObservedBenchmarkCase {
                    id: case.id,
                    input: case.input,
                    expected_route: case.expected_route,
                    category: case.category,
                    features,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let rows = observed_cases.len();

    if rows == 0 {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one benchmark case JSON object per line before running benchmark observe.",
        ));
    }

    let mut out = String::new();
    for observed in observed_cases {
        out.push_str(&serde_json::to_string(&observed).into_diagnostic()?);
        out.push('\n');
    }

    fs::write(output, out)
        .into_diagnostic()
        .wrap_err("failed to write observed benchmark JSONL")?;
    Ok(rows)
}

pub(crate) fn observe_features(
    observer: &ResolvedObserver,
    raw_input: &Value,
) -> Result<Map<String, Value>> {
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

fn stable_bucket(key: &str) -> u64 {
    let mut hash = 1469598103934665603_u64;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211_u64);
    }
    hash
}

fn split_synthesis_case_rows(
    rows: Vec<SynthesisCaseRow>,
    train_fraction: f64,
) -> (Vec<SynthesisCase>, Vec<SynthesisCase>) {
    let threshold = (train_fraction.clamp(0.0, 1.0) * 10_000.0).round() as u64;
    let mut grouped: std::collections::BTreeMap<String, Vec<SynthesisCaseRow>> =
        std::collections::BTreeMap::new();
    for row in rows {
        grouped
            .entry(row.case.expected_route.clone())
            .or_default()
            .push(row);
    }

    let mut train = Vec::new();
    let mut dev = Vec::new();
    for (_route, mut group) in grouped {
        group.sort_by(|left, right| left.id.cmp(&right.id));
        let mut group_train = Vec::new();
        let mut group_dev = Vec::new();
        for row in group {
            let bucket = stable_bucket(&row.id) % 10_000;
            if bucket < threshold {
                group_train.push(row.case);
            } else {
                group_dev.push(row.case);
            }
        }
        if group_train.is_empty() && !group_dev.is_empty() {
            group_train.push(group_dev.remove(0));
        } else if group_dev.is_empty() && !group_train.is_empty() {
            group_dev.push(group_train.remove(0));
        }
        train.extend(group_train);
        dev.extend(group_dev);
    }
    (train, dev)
}

fn choose_synthesis_train_and_dev(
    case_rows: Vec<SynthesisCaseRow>,
    dev_cases_path: Option<&PathBuf>,
) -> Result<Option<(Vec<SynthesisCase>, Vec<SynthesisCase>)>> {
    if let Some(dev_cases_path) = dev_cases_path {
        let train_cases = case_rows
            .into_iter()
            .map(|row| row.case)
            .collect::<Vec<_>>();
        let dev_cases = load_synthesis_cases(dev_cases_path)
            .into_diagnostic()
            .wrap_err("failed to load held-out dev benchmark cases for observer synthesize")?;
        if dev_cases.is_empty() {
            return Err(guidance(
                "held-out dev benchmark dataset is empty",
                "Add one benchmark case JSON object per line before using automatic candidate selection.",
            ));
        }
        return Ok(Some((train_cases, dev_cases)));
    }

    if case_rows.len() < MIN_AUTO_SYNTHESIS_CASES {
        return Ok(None);
    }

    Ok(Some(split_synthesis_case_rows(
        case_rows,
        AUTO_SYNTHESIZE_TRAIN_FRACTION,
    )))
}

pub(crate) fn run_observer_validate(args: ObserverValidateArgs) -> Result<()> {
    if args.plugin_manifest {
        let manifest = PluginManifest::from_path(&args.target)
            .into_diagnostic()
            .wrap_err("failed to load plugin manifest")?;
        if manifest.stage != PluginStage::Observer {
            return Err(guidance(
                format!(
                    "plugin manifest stage mismatch: expected observer, got {:?}",
                    manifest.stage
                ),
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
            format!(
                "artifact is valid ({}, id={})",
                status, artifact.observer_id
            )
            .bright_black()
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
            println!(
                "  {} {}",
                profile.id.bold(),
                profile.description.bright_black()
            );
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
        println!(
            "{}",
            serde_json::to_string_pretty(&response).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Observer".bold().bright_magenta(),
            render_observer_resolution(&observer_resolution(&observer)).bold()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&response).into_diagnostic()?
        );
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
    let detected =
        detect_profile_from_input(&raw_input).map(|profile| ObserverResolution::NativeProfile {
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
        println!(
            "{}",
            "No built-in observer profile detected".bright_yellow()
        );
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
        println!(
            "{} {}",
            "Scaffolded".bold().bright_green(),
            artifact.observer_id.bold()
        );
        println!("  {} {}", "Output".bright_black(), args.output.display());
    }
    Ok(())
}

pub(crate) fn run_observer_synthesize(args: ObserverSynthesizeArgs) -> Result<()> {
    let artifact = resolve_synthesis_artifact(args.profile, args.artifact.as_ref())?;
    let signal = to_guardrails_signal(args.signal);
    let case_rows = load_synthesis_case_rows(&args.benchmark_cases)
        .into_diagnostic()
        .wrap_err("failed to load synthesis benchmark cases")?;
    if case_rows.is_empty() {
        return Err(guidance(
            "benchmark dataset is empty",
            "Add one benchmark case JSON object per line before running observer synthesize.",
        ));
    }
    let bootstrap = to_observer_bootstrap_strategy(args.bootstrap);
    let target_goal = to_observer_target_goal(args.target_goal);
    eprintln!(
        "[logicpearl observer synthesize] loaded {} cases for signal={} target_goal={}",
        case_rows.len(),
        logicpearl_observer::guardrails_signal_label(signal),
        serde_json::to_string(&target_goal)
            .into_diagnostic()?
            .trim_matches('"')
    );
    let mut carried_forward_empty = false;
    let (synthesized, report) = if let Some((train_cases, dev_cases)) =
        choose_synthesis_train_and_dev(case_rows.clone(), args.dev_benchmark_cases.as_ref())?
    {
        if train_cases.is_empty() || dev_cases.is_empty() {
            return Err(guidance(
                "automatic candidate selection needs non-empty train and dev splits",
                "Pass --dev-benchmark-cases explicitly or provide a larger benchmark-case JSONL file.",
            ));
        }
        eprintln!(
            "[logicpearl observer synthesize] using auto selection with train_cases={} dev_cases={} frontier={:?}",
            train_cases.len(),
            dev_cases.len(),
            args.candidate_frontier
        );
        match synthesize_guardrails_artifact_auto(
            &artifact,
            signal,
            ObserverAutoSynthesisOptions {
                train_cases: &train_cases,
                dev_cases: &dev_cases,
                bootstrap,
                target_goal,
                positive_routes: &args.positive_routes,
                candidate_frontier: &args.candidate_frontier,
                tolerance: args.selection_tolerance,
            },
        ) {
            Ok(result) => result,
            Err(error) if args.allow_empty && is_empty_synthesis_error(&error) => {
                carried_forward_empty = true;
                eprintln!(
                    "[logicpearl observer synthesize] signal={} produced no usable variants; carrying input artifact forward unchanged",
                    logicpearl_observer::guardrails_signal_label(signal),
                );
                (
                    artifact.clone(),
                    carried_forward_synthesis_report(
                        &artifact,
                        signal,
                        &train_cases,
                        bootstrap,
                        &args.positive_routes,
                    )?,
                )
            }
            Err(error) => {
                return Err(miette::miette!(
                    "failed to auto-select observer candidate capacity: {error}"
                ));
            }
        }
    } else {
        let cases = case_rows
            .into_iter()
            .map(|row| row.case)
            .collect::<Vec<_>>();
        eprintln!(
            "[logicpearl observer synthesize] dataset too small for auto holdout; using single pass with max_candidates={}",
            args.max_candidates
        );
        match synthesize_guardrails_artifact(
            &artifact,
            signal,
            &cases,
            bootstrap,
            &args.positive_routes,
            args.max_candidates,
        ) {
            Ok(result) => result,
            Err(error) if args.allow_empty && is_empty_synthesis_error(&error) => {
                carried_forward_empty = true;
                eprintln!(
                    "[logicpearl observer synthesize] signal={} produced no usable variants; carrying input artifact forward unchanged",
                    logicpearl_observer::guardrails_signal_label(signal),
                );
                (
                    artifact.clone(),
                    carried_forward_synthesis_report(
                        &artifact,
                        signal,
                        &cases,
                        bootstrap,
                        &args.positive_routes,
                    )?,
                )
            }
            Err(error) => {
                return Err(miette::miette!(
                    "failed to synthesize observer artifact: {error}"
                ));
            }
        }
    };

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
        "target_goal": target_goal,
        "positive_case_count": report.positive_case_count,
        "negative_case_count": report.negative_case_count,
        "candidate_count": report.candidate_count,
        "selected_max_candidates": report.selected_max_candidates,
        "phrases_before": report.phrases_before,
        "phrases_after": report.phrases_after,
        "output": args.output.display().to_string(),
        "matched_positives_after": report.matched_positives_after,
        "matched_negatives_after": report.matched_negatives_after,
        "auto_selection": report.auto_selection,
        "status": if carried_forward_empty { "carried_forward_no_candidates" } else { "synthesized" },
    });

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Synthesized".bold().bright_green(),
            report.signal.bold()
        );
        println!("  {} {}", "Output".bright_black(), args.output.display());
        println!(
            "  {} {}",
            "Target goal".bright_black(),
            serde_json::to_string(&target_goal)
                .into_diagnostic()?
                .trim_matches('"')
        );
        println!(
            "  {} {}",
            "Candidates".bright_black(),
            report.candidate_count
        );
        if let Some(selected) = report.selected_max_candidates {
            println!("  {} {}", "Selected cap".bright_black(), selected);
        }
        println!(
            "  {} {}",
            "Selected".bright_black(),
            report.phrases_after.join(", ")
        );
        if carried_forward_empty {
            println!(
                "  {} carried input artifact forward because no candidates were available",
                "Status".bright_black()
            );
        }
    }
    Ok(())
}

fn is_empty_synthesis_error(error: &logicpearl_core::LogicPearlError) -> bool {
    let text = error.to_string();
    text.contains("could not synthesize any observer variants")
        || text.contains("could not generate candidate phrases")
        || text.contains("z3 could not synthesize a useful phrase subset")
}

fn carried_forward_synthesis_report(
    artifact: &NativeObserverArtifact,
    signal: GuardrailsSignal,
    cases: &[SynthesisCase],
    bootstrap: ObserverBootstrapStrategy,
    positive_routes: &[String],
) -> Result<ObserverSynthesisReport> {
    let score =
        evaluate_guardrails_artifact_signal(artifact, signal, cases, bootstrap, positive_routes)
            .into_diagnostic()?;
    let phrases = artifact
        .guardrails
        .as_ref()
        .map(|config| guardrails_signal_phrases(config, signal).to_vec())
        .unwrap_or_default();
    Ok(ObserverSynthesisReport {
        signal: logicpearl_observer::guardrails_signal_label(signal).to_string(),
        bootstrap_mode: score.bootstrap_mode,
        positive_case_count: score.positive_case_count,
        negative_case_count: score.negative_case_count,
        candidate_count: 0,
        phrases_before: phrases.clone(),
        phrases_after: phrases,
        matched_positives_after: score.true_positive_count,
        matched_negatives_after: score.false_positive_count,
        selected_max_candidates: None,
        auto_selection: None,
    })
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
        println!(
            "{}",
            serde_json::to_string_pretty(&response).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Repaired".bold().bright_green(),
            report.signal.bold()
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn synthesis_row(id: &str, route: &str) -> SynthesisCaseRow {
        SynthesisCaseRow {
            id: id.to_string(),
            case: SynthesisCase {
                prompt: format!("prompt {id}"),
                expected_route: route.to_string(),
                features: None,
            },
        }
    }

    #[test]
    fn auto_synthesis_defaults_to_deterministic_holdout_when_large_enough() {
        let rows = (0..50)
            .map(|idx| {
                let route = if idx % 2 == 0 { "allow" } else { "deny" };
                synthesis_row(&format!("case-{idx}"), route)
            })
            .collect::<Vec<_>>();

        let splits = choose_synthesis_train_and_dev(rows, None)
            .expect("should choose auto train/dev split")
            .expect("should auto split when dataset is large enough");
        let (train, dev) = splits;

        assert!(!train.is_empty());
        assert!(!dev.is_empty());
        assert_eq!(train.len() + dev.len(), 50);
    }

    #[test]
    fn auto_synthesis_falls_back_to_single_pass_when_dataset_is_small() {
        let rows = (0..10)
            .map(|idx| synthesis_row(&format!("case-{idx}"), "allow"))
            .collect::<Vec<_>>();

        let splits =
            choose_synthesis_train_and_dev(rows, None).expect("small datasets should not error");
        assert!(splits.is_none());
    }
}
