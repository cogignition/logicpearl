// SPDX-License-Identifier: MIT
use std::cmp::Ordering;
use std::collections::BTreeMap;

use logicpearl_ir::{Expression, RuleDefinition, RuleVerificationStatus};

use super::super::PinnedRuleSet;

pub(crate) fn merge_discovered_and_pinned_rules(
    discovered: Vec<RuleDefinition>,
    pinned: &PinnedRuleSet,
) -> Vec<RuleDefinition> {
    let mut merged = discovered;
    merged.extend(pinned.rules.clone());
    dedupe_rules_by_signature(merged)
}

pub(crate) fn dedupe_rules_by_signature(rules: Vec<RuleDefinition>) -> Vec<RuleDefinition> {
    let mut by_signature: BTreeMap<String, RuleDefinition> = BTreeMap::new();
    for rule in rules {
        let signature = rule_signature(&rule);
        match by_signature.get(&signature) {
            None => {
                by_signature.insert(signature, rule);
            }
            Some(existing) => {
                if prefer_rule(&rule, existing) == Ordering::Greater {
                    by_signature.insert(signature, rule);
                }
            }
        }
    }

    by_signature
        .into_values()
        .enumerate()
        .map(|(index, mut rule)| {
            rule.bit = index as u32;
            rule.id = format!("rule_{index:03}");
            rule
        })
        .collect()
}

fn prefer_rule(left: &RuleDefinition, right: &RuleDefinition) -> Ordering {
    verification_rank(left)
        .cmp(&verification_rank(right))
        .then_with(|| {
            expression_complexity(&right.deny_when).cmp(&expression_complexity(&left.deny_when))
        })
}

fn verification_rank(rule: &RuleDefinition) -> i32 {
    match rule
        .verification_status
        .as_ref()
        .unwrap_or(&RuleVerificationStatus::PipelineUnverified)
    {
        RuleVerificationStatus::SolverVerified => 4,
        RuleVerificationStatus::RefinedUnverified => 3,
        RuleVerificationStatus::PipelineUnverified => 2,
        RuleVerificationStatus::HeuristicUnverified => 1,
    }
}

fn expression_complexity(expression: &Expression) -> usize {
    match expression {
        Expression::Comparison(_) => 1,
        Expression::All { all } => all.iter().map(expression_complexity).sum(),
        Expression::Any { any } => any.iter().map(expression_complexity).sum(),
        Expression::Not { expr } => expression_complexity(expr),
    }
}

fn rule_signature(rule: &RuleDefinition) -> String {
    let mut normalized = rule.clone();
    normalized.id = String::new();
    normalized.bit = 0;
    normalized.verification_status = None;
    serde_json::to_string(&normalized).expect("rule signature serialization")
}
