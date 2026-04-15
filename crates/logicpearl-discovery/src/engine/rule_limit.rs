// SPDX-License-Identifier: MIT
use std::cmp::Ordering;

use logicpearl_ir::RuleDefinition;

use super::super::canonicalize::expression_matches;
use super::super::DecisionTraceRow;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleLimitScore {
    new_denied_hits: usize,
    total_denied_hits: usize,
    false_positives: usize,
    expression_size: usize,
    original_index: usize,
}

pub(super) fn limit_rules_by_training_coverage(
    rows: &[DecisionTraceRow],
    rules: Vec<RuleDefinition>,
    max_rules: usize,
) -> Vec<RuleDefinition> {
    if rules.len() <= max_rules {
        return rules;
    }

    let mut remaining = rules.into_iter().enumerate().collect::<Vec<_>>();
    let mut selected = Vec::new();
    let mut covered_denied = vec![false; rows.len()];
    while selected.len() < max_rules && !remaining.is_empty() {
        let Some((best_remaining_index, best_score)) = remaining
            .iter()
            .enumerate()
            .map(|(remaining_index, (original_index, rule))| {
                (
                    remaining_index,
                    score_rule_for_limit(rows, &covered_denied, rule, *original_index),
                )
            })
            .max_by(|(_, left), (_, right)| compare_rule_limit_score(left, right))
        else {
            break;
        };
        if best_score.new_denied_hits == 0 && !selected.is_empty() {
            break;
        }

        let (_, rule) = remaining.remove(best_remaining_index);
        for (row_index, row) in rows.iter().enumerate() {
            if !row.allowed && expression_matches(&rule.deny_when, &row.features) {
                covered_denied[row_index] = true;
            }
        }
        selected.push(rule);
    }

    if selected.is_empty() {
        let mut fallback = remaining
            .into_iter()
            .take(max_rules)
            .map(|(_, rule)| rule)
            .collect::<Vec<_>>();
        reindex_rules(&mut fallback);
        return fallback;
    }

    reindex_rules(&mut selected);
    selected
}

fn reindex_rules(rules: &mut [RuleDefinition]) {
    for (index, rule) in rules.iter_mut().enumerate() {
        rule.bit = index as u32;
        rule.id = format!("rule_{index:03}");
    }
}

fn score_rule_for_limit(
    rows: &[DecisionTraceRow],
    covered_denied: &[bool],
    rule: &RuleDefinition,
    original_index: usize,
) -> RuleLimitScore {
    let mut new_denied_hits = 0usize;
    let mut total_denied_hits = 0usize;
    let mut false_positives = 0usize;
    for (row_index, row) in rows.iter().enumerate() {
        if !expression_matches(&rule.deny_when, &row.features) {
            continue;
        }
        if row.allowed {
            false_positives += 1;
        } else {
            total_denied_hits += 1;
            if !covered_denied[row_index] {
                new_denied_hits += 1;
            }
        }
    }
    RuleLimitScore {
        new_denied_hits,
        total_denied_hits,
        false_positives,
        expression_size: serde_json::to_string(&rule.deny_when)
            .map(|payload| payload.len())
            .unwrap_or(usize::MAX),
        original_index,
    }
}

fn compare_rule_limit_score(left: &RuleLimitScore, right: &RuleLimitScore) -> Ordering {
    left.new_denied_hits
        .cmp(&right.new_denied_hits)
        .then_with(|| right.false_positives.cmp(&left.false_positives))
        .then_with(|| left.total_denied_hits.cmp(&right.total_denied_hits))
        .then_with(|| right.expression_size.cmp(&left.expression_size))
        .then_with(|| right.original_index.cmp(&left.original_index))
}
