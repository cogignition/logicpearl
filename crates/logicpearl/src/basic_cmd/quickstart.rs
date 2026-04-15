// SPDX-License-Identifier: MIT
use anstream::println;
use miette::Result;
use owo_colors::OwoColorize;

use super::{QuickstartArgs, QuickstartTopic};

pub(crate) fn run_quickstart(args: QuickstartArgs) -> Result<()> {
    match args.topic {
        None => {
            println!();
            println!("{}", "━━ LogicPearl Quickstart ━━".bold().bright_blue());
            println!();
            println!(
                "  {}",
                "Choose the shortest path for what you want to prove first:".bright_black()
            );
            println!(
                "  {}",
                "Use these commands with the checked-in examples, or copy the shape for your own traces."
                    .bright_black()
            );
            println!();
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "traces".bold().bright_cyan(),
                "generate clean synthetic traces from declarative policy".bright_black()
            );
            println!("    {}", "logicpearl quickstart traces".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "garden".bold().bright_cyan(),
                "learn a small action policy from garden-care examples".bright_black()
            );
            println!("    {}", "logicpearl quickstart garden".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "build".bold().bright_cyan(),
                "learn one pearl from labeled traces".bright_black()
            );
            println!("    {}", "logicpearl quickstart build".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "pipeline".bold().bright_cyan(),
                "run a string-of-pearls artifact".bright_black()
            );
            println!("    {}", "logicpearl quickstart pipeline".bright_black());
            println!(
                "  {} {} {}",
                "▸".bright_cyan(),
                "benchmark".bold().bright_cyan(),
                "score a guardrail benchmark slice".bright_black()
            );
            println!("    {}", "logicpearl quickstart benchmark".bright_black());
            println!();
        }
        Some(QuickstartTopic::Traces) => {
            println!();
            println!("{}", "━━ Quickstart: Traces ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Generate synthetic traces with nuisance fields balanced by construction:"
                    .bright_black()
            );
            println!(
                "     {}",
                "logicpearl traces generate examples/getting_started/synthetic_access_policy.tracegen.json --output /tmp/synthetic_traces.jsonl"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Audit the generated traces:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl traces audit /tmp/synthetic_traces.jsonl --spec examples/getting_started/synthetic_access_policy.tracegen.json"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "3.".bold().bright_cyan(),
                "Build a pearl from them:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl build /tmp/synthetic_traces.jsonl --output-dir /tmp/synthetic_access_policy"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Garden) => {
            println!();
            println!(
                "{}",
                "━━ Quickstart: Garden Actions ━━".bold().bright_green()
            );
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Build a multi-action pearl from reviewed garden-care traces:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl build examples/demos/garden_actions/traces.csv --action-column next_action --default-action do_nothing --gate-id garden_actions --output-dir /tmp/garden-actions"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Inspect the learned action rules:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl inspect /tmp/garden-actions".bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "3.".bold().bright_cyan(),
                "Run today's garden input with an explanation:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl run /tmp/garden-actions examples/demos/garden_actions/today.json --explain"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Build) => {
            println!();
            println!("{}", "━━ Quickstart: Build ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Build your first pearl:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Inspect what it learned:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl inspect examples/getting_started/output".bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "3.".bold().bright_cyan(),
                "Run it on new input:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl run examples/getting_started/output examples/getting_started/new_input.json"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Pipeline) => {
            println!();
            println!("{}", "━━ Quickstart: Pipeline ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Run a public string-of-pearls example:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl pipeline run examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Trace the full stage-by-stage execution:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json examples/pipelines/observer_membership_verify/input.json --json"
                    .bright_cyan()
            );
            println!();
        }
        Some(QuickstartTopic::Benchmark) => {
            println!();
            println!("{}", "━━ Quickstart: Benchmark ━━".bold().bright_green());
            println!();
            println!(
                "  {} {}",
                "1.".bold().bright_cyan(),
                "Run the checked-in guardrail benchmark slice:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl benchmark run benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl --json"
                    .bright_cyan()
            );
            println!();
            println!(
                "  {} {}",
                "2.".bold().bright_cyan(),
                "Inspect the benchmark pipeline:".bright_black()
            );
            println!(
                "     {}",
                "logicpearl pipeline inspect benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json"
                    .bright_cyan()
            );
            println!();
        }
    }
    Ok(())
}
