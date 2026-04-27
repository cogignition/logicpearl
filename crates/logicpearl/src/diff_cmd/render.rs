// SPDX-License-Identifier: MIT
use super::model::{
    ActionPolicyDiffReport, ArtifactDiffReport, RuleChange, RulePairChange, RuleSnapshot,
};
use crate::Result;
use anstream::println;
use miette::IntoDiagnostic;
use owo_colors::OwoColorize;

pub(super) fn render_gate_diff_report(report: &ArtifactDiffReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", "━━ LogicPearl Diff ━━".bold().bright_blue());
        println!("  {} {}", "Old".bright_black(), report.old_artifact);
        println!("  {} {}", "New".bright_black(), report.new_artifact);
        if report.old_gate_id != report.new_gate_id {
            println!(
                "  {} {} → {}",
                "Gate IDs".bright_black(),
                report.old_gate_id,
                report.new_gate_id
            );
        } else {
            println!("  {} {}", "Gate ID".bright_black(), report.old_gate_id);
        }
        println!(
            "  {} {} / {}",
            "Features".bright_black(),
            format!("+{}", report.feature_changes.added.len()).green(),
            format!("-{}", report.feature_changes.removed.len()).red()
        );
        println!(
            "  {} changed={} reordered={} {} {}",
            "Rules".bright_black(),
            report.summary.changed_rules,
            report.summary.reordered_rules,
            format!("+{}", report.summary.added_rules).green(),
            format!("-{}", report.summary.removed_rules).red()
        );
        println!(
            "  {} source_schema={} learned_rule={} rule_explanation={} rule_evidence={}",
            "Change classes".bright_black(),
            report.summary.source_schema_changed,
            report.summary.learned_rule_changed,
            report.summary.rule_explanation_changed,
            report.summary.rule_evidence_changed
        );

        render_changed_rules("Changed Rules", &report.changed_rules);
        render_reordered_rules("Reordered Or Renamed Rules", &report.reordered_rules);
        render_changed_rules("Evidence Changed Rules", &report.evidence_changed_rules);
        render_rule_snapshots("Added Rules", &report.added_rules, "Added");
        render_rule_snapshots("Removed Rules", &report.removed_rules, "Removed");
    }
    Ok(())
}

pub(super) fn render_action_diff_report(report: &ActionPolicyDiffReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", "━━ LogicPearl Action Diff ━━".bold().bright_blue());
        println!("  {} {}", "Old".bright_black(), report.old_artifact);
        println!("  {} {}", "New".bright_black(), report.new_artifact);
        if report.old_action_policy_id != report.new_action_policy_id {
            println!(
                "  {} {} → {}",
                "Action policy IDs".bright_black(),
                report.old_action_policy_id,
                report.new_action_policy_id
            );
        } else {
            println!(
                "  {} {}",
                "Action policy ID".bright_black(),
                report.old_action_policy_id
            );
        }
        if report.old_default_action != report.new_default_action {
            println!(
                "  {} {} → {}",
                "Default action".bright_black(),
                report.old_default_action,
                report.new_default_action
            );
        } else {
            println!(
                "  {} {}",
                "Default action".bright_black(),
                report.old_default_action
            );
        }
        if report.old_no_match_action != report.new_no_match_action {
            println!(
                "  {} {} → {}",
                "No-match action".bright_black(),
                report
                    .old_no_match_action
                    .as_deref()
                    .unwrap_or("<default-action>"),
                report
                    .new_no_match_action
                    .as_deref()
                    .unwrap_or("<default-action>")
            );
        } else if let Some(no_match_action) = &report.old_no_match_action {
            println!("  {} {}", "No-match action".bright_black(), no_match_action);
        }
        println!(
            "  {} {} / {}",
            "Actions".bright_black(),
            format!("+{}", report.action_changes.added.len()).green(),
            format!("-{}", report.action_changes.removed.len()).red()
        );
        println!(
            "  {} {} / {}",
            "Features".bright_black(),
            format!("+{}", report.feature_changes.added.len()).green(),
            format!("-{}", report.feature_changes.removed.len()).red()
        );
        println!(
            "  {} changed={} reordered={} {} {}",
            "Rules".bright_black(),
            report.summary.changed_rules,
            report.summary.reordered_rules,
            format!("+{}", report.summary.added_rules).green(),
            format!("-{}", report.summary.removed_rules).red()
        );
        println!(
            "  {} source_schema={} action_set={} default_action={} no_match_action={} rule_predicate={} rule_priority={} learned_rule={} rule_explanation={} rule_evidence={}",
            "Change classes".bright_black(),
            report.summary.source_schema_changed,
            report.summary.action_set_changed,
            report.summary.default_action_changed,
            report.summary.no_match_action_changed,
            report.summary.rule_predicate_changed,
            report.summary.rule_priority_changed,
            report.summary.learned_rule_changed,
            report.summary.rule_explanation_changed,
            report.summary.rule_evidence_changed
        );

        render_changed_rules("Changed Rules", &report.changed_rules);
        render_reordered_rules("Reordered Or Renamed Rules", &report.reordered_rules);
        render_changed_rules("Evidence Changed Rules", &report.evidence_changed_rules);
        render_rule_snapshots("Added Rules", &report.added_rules, "Added");
        render_rule_snapshots("Removed Rules", &report.removed_rules, "Removed");
    }
    Ok(())
}

fn render_changed_rules(header: &str, changes: &[RuleChange]) {
    if changes.is_empty() {
        return;
    }
    println!();
    println!("{}", format!("━━ {header} ━━").bold().yellow());
    for change in changes {
        println!(
            "  {} {} {} (bit {} → {})",
            "~".yellow(),
            change.change_kind.bold().yellow(),
            change.rule_id,
            change.old_rule.bit,
            change.new_rule.bit
        );
        println!(
            "    {} {}",
            "-".red(),
            rule_display_meaning(&change.old_rule).red()
        );
        render_rule_feature(&change.old_rule);
        println!(
            "    {} {}",
            "+".green(),
            rule_display_meaning(&change.new_rule).green()
        );
        render_rule_feature(&change.new_rule);
    }
}

fn render_reordered_rules(header: &str, changes: &[RulePairChange]) {
    if changes.is_empty() {
        return;
    }
    println!();
    println!("{}", format!("━━ {header} ━━").bold().cyan());
    for change in changes {
        println!(
            "  {} {} {}:{} → {}:{}",
            "→".bright_cyan(),
            change.change_kind.bold(),
            change.old_rule.id,
            change.old_rule.bit,
            change.new_rule.id,
            change.new_rule.bit
        );
        println!(
            "    {} {}",
            "Semantics".bright_black(),
            rule_display_meaning(&change.new_rule)
        );
        render_rule_feature(&change.new_rule);
    }
}

fn render_rule_snapshots(header: &str, rules: &[RuleSnapshot], prefix: &str) {
    if rules.is_empty() {
        return;
    }
    let is_added = prefix == "Added";
    let header_styled = if is_added {
        format!("{}", format!("━━ {header} ━━").bold().green())
    } else {
        format!("{}", format!("━━ {header} ━━").bold().red())
    };
    println!();
    println!("{header_styled}");
    for rule in rules {
        let (symbol, styled_prefix) = if is_added {
            (
                format!("{}", "+".green()),
                format!("{}", prefix.bold().green()),
            )
        } else {
            (format!("{}", "-".red()), format!("{}", prefix.bold().red()))
        };
        println!("  {} {} {}:{}", symbol, styled_prefix, rule.id, rule.bit);
        println!(
            "    {} {}",
            "Semantics".bright_black(),
            rule_display_meaning(rule)
        );
        render_rule_feature(rule);
    }
}

fn rule_display_meaning(rule: &RuleSnapshot) -> &str {
    rule.meaning
        .as_deref()
        .or(rule.label.as_deref())
        .unwrap_or(&rule.semantic_signature)
}

fn render_rule_feature(rule: &RuleSnapshot) {
    match (&rule.action, rule.priority) {
        (Some(action), Some(priority)) => println!(
            "    {} {} (priority {})",
            "Action".bright_black(),
            action,
            priority
        ),
        (Some(action), None) => println!("    {} {}", "Action".bright_black(), action),
        _ => {}
    }
    let Some(feature) = &rule.feature else {
        return;
    };
    let feature_label = feature.label.as_deref().unwrap_or(&feature.id);
    match (&feature.source_id, &feature.source_anchor) {
        (Some(source_id), Some(source_anchor)) => println!(
            "    {} {} ({}, {})",
            "Feature".bright_black(),
            feature_label,
            source_id,
            source_anchor
        ),
        (Some(source_id), None) => println!(
            "    {} {} ({})",
            "Feature".bright_black(),
            feature_label,
            source_id
        ),
        _ => println!("    {} {}", "Feature".bright_black(), feature_label),
    }
}
