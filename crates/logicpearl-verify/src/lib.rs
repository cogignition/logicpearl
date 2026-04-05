use logicpearl_core::{LogicPearlError, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct BooleanConjunctionSearchOptions {
    pub max_conditions: usize,
    pub min_positive_support: usize,
    pub max_negative_hits: usize,
    pub max_rules: usize,
}

#[derive(Debug, Clone)]
pub struct BooleanSearchExample {
    pub features: BTreeMap<String, bool>,
    pub positive: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BooleanConjunctionCandidate {
    pub required_true_features: Vec<String>,
    pub positive_hits: usize,
    pub negative_hits: usize,
}

pub fn status() -> Result<&'static str> {
    Ok("solver-backed verification helpers available")
}

pub fn synthesize_boolean_conjunctions(
    examples: &[BooleanSearchExample],
    options: &BooleanConjunctionSearchOptions,
) -> Result<Vec<BooleanConjunctionCandidate>> {
    if examples.is_empty() {
        return Ok(Vec::new());
    }
    if options.max_conditions == 0 {
        return Err(LogicPearlError::message(
            "max_conditions must be at least 1 for boolean conjunction synthesis",
        ));
    }
    if options.max_rules == 0 {
        return Ok(Vec::new());
    }

    let feature_names = candidate_feature_names(examples, options.min_positive_support);
    if feature_names.is_empty() {
        return Ok(Vec::new());
    }

    let positives: Vec<&BooleanSearchExample> = examples.iter().filter(|example| example.positive).collect();
    let negatives: Vec<&BooleanSearchExample> = examples.iter().filter(|example| !example.positive).collect();
    if positives.len() < options.min_positive_support {
        return Ok(Vec::new());
    }

    let mut uncovered_positive_indexes: Vec<usize> = (0..positives.len()).collect();
    let mut discovered = Vec::new();

    for _ in 0..options.max_rules {
        if uncovered_positive_indexes.len() < options.min_positive_support {
            break;
        }

        let candidate = solve_best_conjunction(
            &feature_names,
            &positives,
            &negatives,
            &uncovered_positive_indexes,
            options,
        )?;
        let Some(candidate) = candidate else {
            break;
        };
        if candidate.positive_hits < options.min_positive_support {
            break;
        }

        let covered_positive_indexes: Vec<usize> = uncovered_positive_indexes
            .iter()
            .copied()
            .filter(|index| conjunction_matches(&positives[*index].features, &candidate.required_true_features))
            .collect();
        if covered_positive_indexes.is_empty() {
            break;
        }

        uncovered_positive_indexes.retain(|index| !covered_positive_indexes.contains(index));
        discovered.push(candidate);
    }

    Ok(discovered)
}

fn candidate_feature_names(
    examples: &[BooleanSearchExample],
    min_positive_support: usize,
) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for example in examples.iter().filter(|example| example.positive) {
        seen.clear();
        for (feature, value) in &example.features {
            if *value && seen.insert(feature.clone()) {
                *counts.entry(feature.clone()).or_default() += 1;
            }
        }
    }
    counts
        .into_iter()
        .filter_map(|(feature, count)| (count >= min_positive_support).then_some(feature))
        .collect()
}

fn solve_best_conjunction(
    feature_names: &[String],
    positives: &[&BooleanSearchExample],
    negatives: &[&BooleanSearchExample],
    uncovered_positive_indexes: &[usize],
    options: &BooleanConjunctionSearchOptions,
) -> Result<Option<BooleanConjunctionCandidate>> {
    let mut smt = String::from("(set-option :opt.priority lex)\n");
    for index in 0..feature_names.len() {
        smt.push_str(&format!("(declare-fun keep_{index} () Bool)\n"));
    }
    smt.push_str(&format!(
        "(assert (<= {} {}))\n",
        keep_sum(feature_names.len()),
        options.max_conditions
    ));
    smt.push_str(&format!(
        "(assert (>= {} 1))\n",
        keep_sum(feature_names.len())
    ));

    for (position, index) in uncovered_positive_indexes.iter().enumerate() {
        let expression = example_match_expression(&positives[*index].features, feature_names);
        smt.push_str(&format!("(declare-fun pos_{position} () Bool)\n"));
        smt.push_str(&format!("(assert (= pos_{position} {expression}))\n"));
    }
    for (index, example) in negatives.iter().enumerate() {
        let expression = example_match_expression(&example.features, feature_names);
        smt.push_str(&format!("(declare-fun neg_{index} () Bool)\n"));
        smt.push_str(&format!("(assert (= neg_{index} {expression}))\n"));
    }

    smt.push_str(&format!(
        "(assert (<= {} {}))\n",
        hit_sum("neg", negatives.len(), true),
        options.max_negative_hits
    ));
    smt.push_str(&format!(
        "(assert (>= {} {}))\n",
        hit_sum("pos", uncovered_positive_indexes.len(), true),
        options.min_positive_support
    ));
    smt.push_str(&format!(
        "(maximize {})\n",
        hit_sum("pos", uncovered_positive_indexes.len(), true)
    ));
    smt.push_str(&format!(
        "(minimize {})\n",
        hit_sum("neg", negatives.len(), true)
    ));
    smt.push_str(&format!("(minimize {})\n", keep_sum(feature_names.len())));
    smt.push_str("(check-sat)\n(get-model)\n");

    let selected_indexes = solve_selected_feature_indexes_with_z3(feature_names.len(), smt)?;
    if selected_indexes.is_empty() {
        return Ok(None);
    }
    let selected_features: Vec<String> = selected_indexes
        .iter()
        .map(|index| feature_names[*index].clone())
        .collect();

    let positive_hits = uncovered_positive_indexes
        .iter()
        .filter(|index| conjunction_matches(&positives[**index].features, &selected_features))
        .count();
    let negative_hits = negatives
        .iter()
        .filter(|example| conjunction_matches(&example.features, &selected_features))
        .count();

    Ok(Some(BooleanConjunctionCandidate {
        required_true_features: selected_features,
        positive_hits,
        negative_hits,
    }))
}

fn example_match_expression(features: &BTreeMap<String, bool>, feature_names: &[String]) -> String {
    let clauses: Vec<String> = feature_names
        .iter()
        .enumerate()
        .map(|(index, feature)| {
            if *features.get(feature).unwrap_or(&false) {
                format!("(=> keep_{index} true)")
            } else {
                format!("(=> keep_{index} false)")
            }
        })
        .collect();
    if clauses.is_empty() {
        "true".to_string()
    } else if clauses.len() == 1 {
        clauses[0].clone()
    } else {
        format!("(and {})", clauses.join(" "))
    }
}

fn hit_sum(prefix: &str, count: usize, when_true: bool) -> String {
    if count == 0 {
        return "0".to_string();
    }
    format!(
        "(+ {})",
        (0..count)
            .map(|index| {
                if when_true {
                    format!("(ite {prefix}_{index} 1 0)")
                } else {
                    format!("(ite {prefix}_{index} 0 1)")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn keep_sum(count: usize) -> String {
    if count == 0 {
        return "0".to_string();
    }
    format!(
        "(+ {})",
        (0..count)
            .map(|index| format!("(ite keep_{index} 1 0)"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn conjunction_matches(features: &BTreeMap<String, bool>, required_true_features: &[String]) -> bool {
    required_true_features
        .iter()
        .all(|feature| features.get(feature).copied().unwrap_or(false))
}

fn solve_selected_feature_indexes_with_z3(feature_count: usize, smt: String) -> Result<Vec<usize>> {
    let smt_path = std::env::temp_dir().join(format!(
        "logicpearl-verify-{}-{}.smt2",
        std::process::id(),
        unique_suffix()
    ));
    fs::write(&smt_path, smt)?;

    let output = Command::new("z3")
        .arg("-smt2")
        .arg(&smt_path)
        .output()
        .map_err(|err| {
            LogicPearlError::message(format!(
                "failed to launch z3; make sure Z3 is installed and on PATH: {err}"
            ))
        })?;
    let _ = fs::remove_file(&smt_path);

    if !output.status.success() {
        return Err(LogicPearlError::message(format!(
            "z3 failed while solving boolean conjunction synthesis: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        LogicPearlError::message(format!("z3 output was not valid UTF-8: {err}"))
    })?;
    if !stdout.lines().next().unwrap_or_default().contains("sat") {
        return Ok(Vec::new());
    }

    let mut selected = Vec::new();
    for index in 0..feature_count {
        let needle = format!("(define-fun keep_{index} () Bool");
        if let Some(position) = stdout.find(&needle) {
            let remainder = &stdout[position + needle.len()..];
            if remainder.trim_start().starts_with("true") {
                selected.push(index);
            }
        }
    }
    Ok(selected)
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        synthesize_boolean_conjunctions, BooleanConjunctionSearchOptions, BooleanSearchExample,
    };
    use std::collections::BTreeMap;

    #[test]
    fn synthesizes_exact_two_feature_conjunction() {
        if std::process::Command::new("z3").arg("-version").output().is_err() {
            return;
        }

        let examples = vec![
            example(&[("a", true), ("b", true), ("c", false)], true),
            example(&[("a", true), ("b", true), ("c", true)], true),
            example(&[("a", true), ("b", false), ("c", true)], false),
            example(&[("a", false), ("b", true), ("c", true)], false),
        ];
        let candidates = synthesize_boolean_conjunctions(
            &examples,
            &BooleanConjunctionSearchOptions {
                max_conditions: 2,
                min_positive_support: 2,
                max_negative_hits: 0,
                max_rules: 1,
            },
        )
        .unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].required_true_features, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(candidates[0].positive_hits, 2);
        assert_eq!(candidates[0].negative_hits, 0);
    }

    fn example(features: &[(&str, bool)], positive: bool) -> BooleanSearchExample {
        BooleanSearchExample {
            features: features
                .iter()
                .map(|(name, value)| ((*name).to_string(), *value))
                .collect::<BTreeMap<_, _>>(),
            positive,
        }
    }
}
