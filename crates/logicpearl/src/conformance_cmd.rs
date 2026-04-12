use super::*;
use logicpearl_conformance::{
    build_artifact_manifest, compare_runtime_parity, validate_artifact_manifest,
    write_artifact_manifest, DecisionTraceRow as ConformanceDecisionTraceRow,
};
use logicpearl_verify::{load_formal_spec, verify_gate_against_formal_spec};
use std::collections::BTreeMap;

pub(crate) fn run_conformance_write_manifest(args: ConformanceWriteManifestArgs) -> Result<()> {
    let source_control = parse_key_value_entries(&args.source_control, "source-control")?;
    let source_files = parse_key_value_entries(&args.source, "source")?;
    let data_files = parse_key_value_entries(&args.data, "data")?;
    let artifacts = parse_key_value_entries(&args.artifact, "artifact")?;
    let manifest = build_artifact_manifest(
        generated_at_string(),
        source_control,
        source_files,
        data_files,
        artifacts,
    )
    .into_diagnostic()
    .wrap_err("could not build artifact manifest")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err("could not create manifest output directory")?;
    }
    write_artifact_manifest(&manifest, &args.output)
        .into_diagnostic()
        .wrap_err("could not write artifact manifest")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&manifest).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Wrote".bold().bright_green(),
            args.output.display()
        );
    }
    Ok(())
}

pub(crate) fn run_conformance_validate_artifacts(
    args: ConformanceValidateArtifactsArgs,
) -> Result<()> {
    let report = validate_artifact_manifest(&args.manifest_json)
        .into_diagnostic()
        .wrap_err("could not validate artifact manifest")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else if report.fresh {
        println!(
            "{} {}",
            "Fresh".bold().bright_green(),
            args.manifest_json.display()
        );
    } else {
        println!(
            "{} {}",
            "Stale".bold().bright_red(),
            args.manifest_json.display()
        );
        for problem in &report.problems {
            println!("  {} {}", "Problem".bright_black(), problem);
        }
    }
    Ok(())
}

pub(crate) fn run_conformance_runtime_parity(args: ConformanceRuntimeParityArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let loaded = logicpearl_discovery::load_decision_traces_auto(
        &args.decision_traces_csv,
        args.label_column.as_deref(),
        args.default_label.as_deref(),
        args.rule_label.as_deref(),
    )
    .into_diagnostic()
    .wrap_err("could not load labeled decision traces")?;
    let rows = loaded.rows;
    let conformance_rows: Vec<ConformanceDecisionTraceRow> = rows
        .into_iter()
        .map(|row| ConformanceDecisionTraceRow {
            features: row.features.into_iter().collect(),
            allowed: row.allowed,
        })
        .collect();
    let report = compare_runtime_parity(&gate, &conformance_rows)
        .into_diagnostic()
        .wrap_err("could not compare runtime parity")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Parity".bold().bright_green(),
            resolved.artifact_dir.display()
        );
        println!("  {} {}", "Rows".bright_black(), report.total_rows);
        println!(
            "  {} {}",
            "Matching rows".bright_black(),
            report.matching_rows
        );
        println!(
            "  {} {}",
            "Runtime parity".bright_black(),
            format!("{:.1}%", report.parity * 100.0).bold()
        );
    }
    Ok(())
}

pub(crate) fn run_conformance_spec_verify(args: ConformanceSpecVerifyArgs) -> Result<()> {
    let resolved = resolve_artifact_input(&args.pearl_ir)?;
    let gate = LogicPearlGateIr::from_path(&resolved.pearl_ir)
        .into_diagnostic()
        .wrap_err("could not load pearl IR")?;
    let spec = load_formal_spec(&args.spec_json)
        .into_diagnostic()
        .wrap_err("could not load formal spec")?;
    let report = verify_gate_against_formal_spec(&gate, &spec)
        .into_diagnostic()
        .wrap_err("could not verify pearl against formal spec")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Spec verify".bold().bright_green(),
            resolved.artifact_dir.display()
        );
        println!(
            "  {} {}",
            "Spec rules".bright_black(),
            report.spec_rule_count
        );
        println!(
            "  {} {}",
            "Gate rules".bright_black(),
            report.gate_rule_count
        );
        println!(
            "  {} {}",
            "Complete".bright_black(),
            if report.complete { "yes" } else { "no" }
        );
        println!(
            "  {} {}",
            "No spurious rules".bright_black(),
            if report.no_spurious_rules {
                "yes"
            } else {
                "no"
            }
        );
        if let Some(witness) = &report.overall_spec_gap_witness {
            println!("  {} {}", "Spec gap witness".bright_black(), witness);
        }
        if let Some(witness) = &report.overall_spurious_witness {
            println!("  {} {}", "Spurious witness".bright_black(), witness);
        }
    }
    Ok(())
}

fn parse_key_value_entries(
    entries: &[String],
    flag_name: &str,
) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(guidance(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        };
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(guidance(
                format!("invalid --{flag_name} entry: {entry:?}"),
                format!("Use repeated --{flag_name} key=value entries."),
            ));
        }
        parsed.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(parsed)
}

fn generated_at_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("unix:{}", duration.as_secs()),
        Err(_) => "unix:0".to_string(),
    }
}
