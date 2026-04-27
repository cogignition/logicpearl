// SPDX-License-Identifier: MIT
use super::*;

mod args;
mod compare;
mod load;
mod model;
mod render;
mod semantics;
mod signatures;
mod snapshots;
#[cfg(test)]
mod tests;

pub(crate) use args::DiffArgs;
use compare::{diff_action_policies, diff_gates};
use load::load_diff_pearl;
use model::DiffPearl;
use render::{render_action_diff_report, render_gate_diff_report};

pub(crate) fn run_diff(args: DiffArgs) -> Result<()> {
    let old_resolved = resolve_artifact_input(&args.old_artifact)?;
    let new_resolved = resolve_artifact_input(&args.new_artifact)?;
    let old_pearl = load_diff_pearl(&old_resolved.pearl_ir).wrap_err("failed to load old pearl")?;
    let new_pearl = load_diff_pearl(&new_resolved.pearl_ir).wrap_err("failed to load new pearl")?;

    match (old_pearl, new_pearl) {
        (DiffPearl::Gate(old_gate), DiffPearl::Gate(new_gate)) => {
            let report = diff_gates(&old_gate, &new_gate, &old_resolved, &new_resolved)
                .wrap_err("failed to diff artifacts")?;
            render_gate_diff_report(&report, args.json)
        }
        (DiffPearl::Action(old_policy), DiffPearl::Action(new_policy)) => {
            let report =
                diff_action_policies(&old_policy, &new_policy, &old_resolved, &new_resolved)
                    .wrap_err("failed to diff action policies")?;
            render_action_diff_report(&report, args.json)
        }
        _ => Err(CommandCoaching::simple(
            "cannot diff different decision artifact kinds",
            "Diff two gate artifacts or two action-policy artifacts.",
        )),
    }
}
