// SPDX-License-Identifier: MIT
use super::{BuildArgs, ProposalPolicyArg, SelectionPolicyArg};
use miette::{IntoDiagnostic, Result, WrapErr};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct LogicPearlProjectConfig {
    #[serde(default)]
    build: Option<LogicPearlBuildConfig>,
    #[serde(default)]
    run: Option<LogicPearlRunConfig>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct LogicPearlBuildConfig {
    traces: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    gate_id: Option<String>,
    label_column: Option<String>,
    action_column: Option<String>,
    feature_columns: Option<Vec<String>>,
    exclude_columns: Option<Vec<String>>,
    default_label: Option<String>,
    rule_label: Option<String>,
    default_action: Option<String>,
    no_match_action: Option<String>,
    action_max_rules: Option<usize>,
    max_rules: Option<usize>,
    proposal_policy: Option<ProposalPolicyArg>,
    selection_policy: Option<SelectionPolicyArg>,
    deny_recall_target: Option<f64>,
    max_false_positive_rate: Option<f64>,
    action_priority: Option<String>,
    #[serde(default)]
    raw_feature_ids: bool,
    feature_dictionary: Option<PathBuf>,
    source_manifest: Option<PathBuf>,
    feature_governance: Option<PathBuf>,
    #[serde(default)]
    show_conflicts: bool,
    conflict_report: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct LogicPearlRunConfig {
    pub(super) artifact: Option<PathBuf>,
    pub(super) example_input: Option<PathBuf>,
}

pub(super) enum ConfiguredInspectArtifact {
    MissingConfig,
    MissingArtifact,
    Found(PathBuf),
}

fn load_project_config() -> Result<Option<(PathBuf, LogicPearlProjectConfig)>> {
    for name in ["logicpearl.yaml", "logicpearl.yml"] {
        let path = PathBuf::from(name);
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err("failed to read logicpearl project config")?;
        let config = serde_norway::from_str(&content)
            .into_diagnostic()
            .wrap_err("failed to parse logicpearl project config")?;
        return Ok(Some((path, config)));
    }
    Ok(None)
}

pub(super) fn resolve_config_path(config_path: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(path)
}

pub(super) fn apply_build_config(args: &mut BuildArgs) -> Result<()> {
    let Some((config_path, config)) = load_project_config()? else {
        return Ok(());
    };
    let Some(build) = config.build else {
        return Ok(());
    };
    if args.decision_traces.is_none() {
        args.decision_traces = build
            .traces
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.output_dir.is_none() {
        args.output_dir = build
            .output_dir
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.gate_id.is_none() {
        args.gate_id = build.gate_id;
    }
    if args.label_column.is_none() {
        args.label_column = build.label_column;
    }
    if args.action_column.is_none() {
        args.action_column = build.action_column;
    }
    if args.feature_columns.is_empty() && args.exclude_columns.is_empty() {
        args.feature_columns = build.feature_columns.unwrap_or_default();
        args.exclude_columns = build.exclude_columns.unwrap_or_default();
    }
    if args.default_label.is_none() {
        args.default_label = build.default_label;
    }
    if args.rule_label.is_none() {
        args.rule_label = build.rule_label;
    }
    if args.default_action.is_none() {
        args.default_action = build.default_action;
    }
    if args.no_match_action.is_none() {
        args.no_match_action = build.no_match_action;
    }
    if args.action_max_rules.is_none() {
        args.action_max_rules = build.action_max_rules;
    }
    if args.max_rules.is_none() {
        args.max_rules = build.max_rules;
    }
    if args.proposal_policy.is_none() {
        args.proposal_policy = build.proposal_policy;
    }
    if args.selection_policy.is_none() {
        args.selection_policy = build.selection_policy;
    }
    if args.deny_recall_target.is_none() {
        args.deny_recall_target = build.deny_recall_target;
    }
    if args.max_false_positive_rate.is_none() {
        args.max_false_positive_rate = build.max_false_positive_rate;
    }
    if args.action_priority.is_none() {
        args.action_priority = build.action_priority;
    }
    if !args.raw_feature_ids {
        args.raw_feature_ids = build.raw_feature_ids;
    }
    if args.feature_dictionary.is_none() {
        args.feature_dictionary = build
            .feature_dictionary
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.source_manifest.is_none() {
        args.source_manifest = build
            .source_manifest
            .map(|path| resolve_config_path(&config_path, path));
    }
    if args.feature_governance.is_none() {
        args.feature_governance = build
            .feature_governance
            .map(|path| resolve_config_path(&config_path, path));
    }
    if !args.show_conflicts {
        args.show_conflicts = build.show_conflicts;
    }
    if args.conflict_report.is_none() {
        args.conflict_report = build
            .conflict_report
            .map(|path| resolve_config_path(&config_path, path));
    }
    Ok(())
}

pub(super) fn configured_run_defaults() -> Result<Option<(PathBuf, LogicPearlRunConfig)>> {
    let Some((config_path, config)) = load_project_config()? else {
        return Ok(None);
    };
    Ok(config.run.map(|run| (config_path, run)))
}

pub(super) fn configured_inspect_artifact() -> Result<ConfiguredInspectArtifact> {
    let Some((config_path, config)) = load_project_config()? else {
        return Ok(ConfiguredInspectArtifact::MissingConfig);
    };
    if let Some(run) = config.run {
        if let Some(artifact) = run.artifact {
            return Ok(ConfiguredInspectArtifact::Found(resolve_config_path(
                &config_path,
                artifact,
            )));
        }
    }
    if let Some(build) = config.build {
        if let Some(output_dir) = build.output_dir {
            return Ok(ConfiguredInspectArtifact::Found(resolve_config_path(
                &config_path,
                output_dir,
            )));
        }
    }
    Ok(ConfiguredInspectArtifact::MissingArtifact)
}
