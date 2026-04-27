// SPDX-License-Identifier: MIT
use super::*;
use logicpearl_discovery::{ProposalPolicy, SelectionPolicy};

pub(super) const QUICKSTART_AFTER_HELP: &str = "\
Examples:
  logicpearl quickstart
  logicpearl quickstart traces
  logicpearl quickstart garden
  logicpearl quickstart build
  logicpearl quickstart pipeline
  logicpearl quickstart benchmark";

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum QuickstartTopic {
    Traces,
    Garden,
    Build,
    Pipeline,
    Benchmark,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProposalPolicyArg {
    AutoAdoptSafe,
    ReportOnly,
}

impl From<ProposalPolicyArg> for ProposalPolicy {
    fn from(value: ProposalPolicyArg) -> Self {
        match value {
            ProposalPolicyArg::AutoAdoptSafe => ProposalPolicy::AutoAdoptSafe,
            ProposalPolicyArg::ReportOnly => ProposalPolicy::ReportOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum DiscoveryDecisionModeArg {
    Standard,
    Review,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActionSelectionArg {
    FirstMatch,
    WeightedVote,
}

impl From<ActionSelectionArg> for logicpearl_ir::ActionSelectionStrategy {
    fn from(value: ActionSelectionArg) -> Self {
        match value {
            ActionSelectionArg::FirstMatch => logicpearl_ir::ActionSelectionStrategy::FirstMatch,
            ActionSelectionArg::WeightedVote => {
                logicpearl_ir::ActionSelectionStrategy::WeightedVote
            }
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectionPolicyArg {
    Balanced,
    RecallBiased,
}

pub(crate) fn to_discovery_decision_mode(arg: DiscoveryDecisionModeArg) -> DiscoveryDecisionMode {
    match arg {
        DiscoveryDecisionModeArg::Standard => DiscoveryDecisionMode::Standard,
        DiscoveryDecisionModeArg::Review => DiscoveryDecisionMode::Review,
    }
}

pub(crate) fn selection_policy_from_args(
    policy: Option<SelectionPolicyArg>,
    deny_recall_target: Option<f64>,
    max_false_positive_rate: Option<f64>,
) -> Result<SelectionPolicy, String> {
    match policy.unwrap_or(SelectionPolicyArg::Balanced) {
        SelectionPolicyArg::Balanced => {
            if deny_recall_target.is_some() || max_false_positive_rate.is_some() {
                return Err(
                    "use --selection-policy recall-biased when setting recall/false-positive targets"
                        .to_string(),
                );
            }
            Ok(SelectionPolicy::Balanced)
        }
        SelectionPolicyArg::RecallBiased => {
            let deny_recall_target = deny_recall_target.ok_or_else(|| {
                "--selection-policy recall-biased requires --deny-recall-target".to_string()
            })?;
            let max_false_positive_rate = max_false_positive_rate.ok_or_else(|| {
                "--selection-policy recall-biased requires --max-false-positive-rate".to_string()
            })?;
            SelectionPolicy::RecallBiased {
                deny_recall_target,
                max_false_positive_rate,
            }
            .validate()
            .map_err(|err| err.to_string())
        }
    }
}
