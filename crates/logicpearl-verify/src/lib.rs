use logicpearl_core::{LogicPearlError, Result};
use logicpearl_ir::{
    validate_expression_against_schema, ComparisonOperator, ComparisonValue,
    DerivedFeatureOperator, Expression, FeatureDefinition, FeatureType, LogicPearlGateIr,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormalSpec {
    #[serde(default = "default_spec_version")]
    pub spec_version: String,
    pub rules: Vec<FormalSpecRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormalSpecRule {
    pub id: String,
    pub deny_when: Expression,
    pub label: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormalSpecVerificationReport {
    pub spec_rule_count: usize,
    pub gate_rule_count: usize,
    pub complete: bool,
    pub no_spurious_rules: bool,
    pub fully_verified: bool,
    pub spec_rule_checks: Vec<FormalSpecRuleCheck>,
    pub gate_rule_checks: Vec<GateRuleCheck>,
    pub overall_spec_gap_witness: Option<String>,
    pub overall_spurious_witness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormalSpecRuleCheck {
    pub id: String,
    pub satisfied_by_gate: bool,
    pub witness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GateRuleCheck {
    pub id: String,
    pub implied_by_spec: bool,
    pub witness: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SolverCheckResult {
    unsat: bool,
    witness: Option<String>,
}

#[derive(Debug, Clone)]
struct FormalSpecSmtContext {
    declarations: String,
    assertions: Vec<String>,
    value_symbols: Vec<String>,
}

pub fn load_formal_spec(path: impl AsRef<std::path::Path>) -> Result<FormalSpec> {
    let payload = fs::read_to_string(path)?;
    let spec: FormalSpec = serde_json::from_str(&payload)?;
    validate_formal_spec(&spec)?;
    Ok(spec)
}

pub fn validate_formal_spec(spec: &FormalSpec) -> Result<()> {
    if spec.spec_version != "1.0" {
        return Err(LogicPearlError::message(format!(
            "unsupported spec_version: {}",
            spec.spec_version
        )));
    }
    if spec.rules.is_empty() {
        return Err(LogicPearlError::message(
            "formal spec must define at least one rule",
        ));
    }
    let mut ids = BTreeSet::new();
    for rule in &spec.rules {
        if rule.id.is_empty() {
            return Err(LogicPearlError::message(
                "formal spec rule id must be non-empty",
            ));
        }
        if !ids.insert(rule.id.clone()) {
            return Err(LogicPearlError::message(format!(
                "duplicate formal spec rule ids: {}",
                rule.id
            )));
        }
    }
    Ok(())
}

pub fn verify_gate_against_formal_spec(
    gate: &LogicPearlGateIr,
    spec: &FormalSpec,
) -> Result<FormalSpecVerificationReport> {
    validate_formal_spec(spec)?;
    for rule in &spec.rules {
        validate_expression_against_schema(&rule.deny_when, &gate.input_schema)?;
    }
    let context = build_formal_spec_smt_context(gate)?;
    let gate_expr = union_expression(gate, gate.rules.iter().map(|rule| &rule.deny_when))?;
    let spec_expr = union_expression(gate, spec.rules.iter().map(|rule| &rule.deny_when))?;

    let overall_spec_gap_witness =
        check_formula_with_witness(&context, &format!("(and {spec_expr} (not {gate_expr}))"))?;
    let overall_spurious_witness =
        check_formula_with_witness(&context, &format!("(and {gate_expr} (not {spec_expr}))"))?;

    let spec_rule_checks = spec
        .rules
        .iter()
        .map(|rule| {
            let result = check_formula_with_witness(
                &context,
                &format!(
                    "(and {} (not {}))",
                    emit_expression_smt(&rule.deny_when, gate)?,
                    gate_expr
                ),
            )?;
            Ok(FormalSpecRuleCheck {
                id: rule.id.clone(),
                satisfied_by_gate: result.unsat,
                witness: result.witness,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let gate_rule_checks = gate
        .rules
        .iter()
        .map(|rule| {
            let result = check_formula_with_witness(
                &context,
                &format!(
                    "(and {} (not {}))",
                    emit_expression_smt(&rule.deny_when, gate)?,
                    spec_expr
                ),
            )?;
            Ok(GateRuleCheck {
                id: rule.id.clone(),
                implied_by_spec: result.unsat,
                witness: result.witness,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let complete = overall_spec_gap_witness.unsat;
    let no_spurious_rules = overall_spurious_witness.unsat;
    Ok(FormalSpecVerificationReport {
        spec_rule_count: spec.rules.len(),
        gate_rule_count: gate.rules.len(),
        complete,
        no_spurious_rules,
        fully_verified: complete && no_spurious_rules,
        spec_rule_checks,
        gate_rule_checks,
        overall_spec_gap_witness: overall_spec_gap_witness.witness,
        overall_spurious_witness: overall_spurious_witness.witness,
    })
}

fn default_spec_version() -> String {
    "1.0".to_string()
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

    let positives: Vec<&BooleanSearchExample> =
        examples.iter().filter(|example| example.positive).collect();
    let negatives: Vec<&BooleanSearchExample> = examples
        .iter()
        .filter(|example| !example.positive)
        .collect();
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
            .filter(|index| {
                conjunction_matches(
                    &positives[*index].features,
                    &candidate.required_true_features,
                )
            })
            .collect();
        if covered_positive_indexes.is_empty() {
            break;
        }

        uncovered_positive_indexes.retain(|index| !covered_positive_indexes.contains(index));
        discovered.push(candidate);
    }

    Ok(discovered)
}

fn build_formal_spec_smt_context(gate: &LogicPearlGateIr) -> Result<FormalSpecSmtContext> {
    let mut declarations = String::from("(set-option :produce-models true)\n");
    let mut assertions = Vec::new();
    let mut value_symbols = Vec::new();

    for feature in gate
        .input_schema
        .features
        .iter()
        .filter(|feature| feature.derived.is_none())
    {
        let symbol = smt_symbol(&feature.id);
        declarations.push_str(&format!(
            "(declare-fun {symbol} () {})\n",
            smt_sort(&feature.feature_type)
        ));
        value_symbols.push(symbol.clone());

        if matches!(feature.feature_type, FeatureType::Int) {
            assertions.push(format!("(is_int {symbol})"));
        }
        if let Some(min) = feature.min {
            assertions.push(format!("(>= {symbol} {})", smt_real_literal(min)));
        }
        if let Some(max) = feature.max {
            assertions.push(format!("(<= {symbol} {})", smt_real_literal(max)));
        }
        if matches!(feature.feature_type, FeatureType::Enum) {
            if let Some(values) = &feature.values {
                assertions.push(format!(
                    "(or {})",
                    values
                        .iter()
                        .map(|value| format!("(= {symbol} {})", smt_literal(feature, value)))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
        }
    }

    if let Some(verification) = &gate.verification {
        if let Some(domain_constraints) = &verification.domain_constraints {
            for constraint in domain_constraints {
                assertions.push(emit_comparison_smt(constraint, gate)?);
            }
        }
    }

    Ok(FormalSpecSmtContext {
        declarations,
        assertions,
        value_symbols,
    })
}

fn check_formula_with_witness(
    context: &FormalSpecSmtContext,
    formula: &str,
) -> Result<SolverCheckResult> {
    let status = run_z3_smt(
        build_check_sat_script(context, formula, false),
        "formal spec verification",
    )?;
    let status_line = status.lines().next().unwrap_or_default().trim().to_string();
    match status_line.as_str() {
        "unsat" => Ok(SolverCheckResult {
            unsat: true,
            witness: None,
        }),
        "sat" => {
            let witness_output = if context.value_symbols.is_empty() {
                String::new()
            } else {
                run_z3_smt(
                    build_check_sat_script(context, formula, true),
                    "formal spec verification witness",
                )?
            };
            let witness = witness_output
                .lines()
                .skip(1)
                .collect::<Vec<_>>()
                .join("\n")
                .trim()
                .to_string();
            Ok(SolverCheckResult {
                unsat: false,
                witness: (!witness.is_empty()).then_some(witness),
            })
        }
        other => Err(LogicPearlError::message(format!(
            "z3 returned unexpected status during formal spec verification: {other}"
        ))),
    }
}

fn build_check_sat_script(
    context: &FormalSpecSmtContext,
    formula: &str,
    include_values: bool,
) -> String {
    let mut smt = String::new();
    smt.push_str(&context.declarations);
    for assertion in &context.assertions {
        smt.push_str(&format!("(assert {assertion})\n"));
    }
    smt.push_str(&format!("(assert {formula})\n"));
    smt.push_str("(check-sat)\n");
    if include_values && !context.value_symbols.is_empty() {
        smt.push_str(&format!(
            "(get-value ({}))\n",
            context.value_symbols.join(" ")
        ));
    }
    smt
}

fn union_expression<'a>(
    gate: &LogicPearlGateIr,
    expressions: impl Iterator<Item = &'a Expression>,
) -> Result<String> {
    let rendered = expressions
        .map(|expression| emit_expression_smt(expression, gate))
        .collect::<Result<Vec<_>>>()?;
    Ok(if rendered.is_empty() {
        "false".to_string()
    } else if rendered.len() == 1 {
        rendered[0].clone()
    } else {
        format!("(or {})", rendered.join(" "))
    })
}

fn emit_expression_smt(expression: &Expression, gate: &LogicPearlGateIr) -> Result<String> {
    match expression {
        Expression::Comparison(comparison) => emit_comparison_smt(comparison, gate),
        Expression::All { all } => Ok(if all.is_empty() {
            "true".to_string()
        } else {
            format!(
                "(and {})",
                all.iter()
                    .map(|child| emit_expression_smt(child, gate))
                    .collect::<Result<Vec<_>>>()?
                    .join(" ")
            )
        }),
        Expression::Any { any } => Ok(if any.is_empty() {
            "false".to_string()
        } else {
            format!(
                "(or {})",
                any.iter()
                    .map(|child| emit_expression_smt(child, gate))
                    .collect::<Result<Vec<_>>>()?
                    .join(" ")
            )
        }),
        Expression::Not { expr } => Ok(format!("(not {})", emit_expression_smt(expr, gate)?)),
    }
}

fn emit_comparison_smt(
    comparison: &logicpearl_ir::ComparisonExpression,
    gate: &LogicPearlGateIr,
) -> Result<String> {
    let feature = gate
        .input_schema
        .features
        .iter()
        .find(|feature| feature.id == comparison.feature)
        .ok_or_else(|| {
            LogicPearlError::message(format!(
                "unknown feature referenced in formal spec verification: {}",
                comparison.feature
            ))
        })?;
    let left = emit_feature_term(&comparison.feature, gate)?;
    let right = match &comparison.value {
        ComparisonValue::FeatureRef { feature_ref } => emit_feature_term(feature_ref, gate)?,
        ComparisonValue::Literal(value) => smt_literal(feature, value),
    };

    Ok(match comparison.op {
        ComparisonOperator::Eq => format!("(= {left} {right})"),
        ComparisonOperator::Ne => format!("(not (= {left} {right}))"),
        ComparisonOperator::Gt => format!("(> {left} {right})"),
        ComparisonOperator::Gte => format!("(>= {left} {right})"),
        ComparisonOperator::Lt => format!("(< {left} {right})"),
        ComparisonOperator::Lte => format!("(<= {left} {right})"),
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let values = comparison
                .value
                .literal()
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    LogicPearlError::message(
                        "formal spec verification requires array literal for in/not_in",
                    )
                })?;
            let membership = if values.is_empty() {
                "false".to_string()
            } else {
                format!(
                    "(or {})",
                    values
                        .iter()
                        .map(|value| format!("(= {left} {})", smt_literal(feature, value)))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };
            if matches!(comparison.op, ComparisonOperator::NotIn) {
                format!("(not {membership})")
            } else {
                membership
            }
        }
    })
}

fn emit_feature_term(feature_id: &str, gate: &LogicPearlGateIr) -> Result<String> {
    let feature = gate
        .input_schema
        .features
        .iter()
        .find(|feature| feature.id == feature_id)
        .ok_or_else(|| {
            LogicPearlError::message(format!(
                "unknown feature referenced in formal spec verification: {feature_id}"
            ))
        })?;
    match &feature.derived {
        None => Ok(smt_symbol(&feature.id)),
        Some(derived) => {
            let left = emit_feature_term(&derived.left_feature, gate)?;
            let right = emit_feature_term(&derived.right_feature, gate)?;
            Ok(match derived.op {
                DerivedFeatureOperator::Difference => format!("(- {left} {right})"),
                DerivedFeatureOperator::Ratio => {
                    format!("(ite (= {right} 0.0) 0.0 (/ {left} {right}))")
                }
            })
        }
    }
}

fn smt_sort(feature_type: &FeatureType) -> &'static str {
    match feature_type {
        FeatureType::Bool => "Bool",
        FeatureType::Int | FeatureType::Float => "Real",
        FeatureType::String | FeatureType::Enum => "String",
    }
}

fn smt_symbol(feature_id: &str) -> String {
    let mut sanitized = String::from("f_");
    sanitized.push_str(
        &feature_id
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
            .collect::<String>(),
    );
    sanitized
}

fn smt_literal(feature: &FeatureDefinition, value: &Value) -> String {
    match feature.feature_type {
        FeatureType::Bool => {
            if value.as_bool().unwrap_or(false) {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        FeatureType::Int | FeatureType::Float => smt_real_literal(value.as_f64().unwrap_or(0.0)),
        FeatureType::String | FeatureType::Enum => {
            smt_string_literal(value.as_str().unwrap_or(&value.to_string()))
        }
    }
}

fn smt_real_literal(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        format!("{value:?}")
    }
}

fn smt_string_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\"\""))
}

fn run_z3_smt(smt: String, context: &str) -> Result<String> {
    let smt_path = std::env::temp_dir().join(format!(
        "logicpearl-verify-{}-{}.smt2",
        std::process::id(),
        unique_suffix()
    ));
    fs::write(&smt_path, &smt)?;

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
            "z3 failed during {context}: stderr=`{}` stdout=`{}` smt=`{}`",
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim(),
            smt.replace('\n', "\\n")
        )));
    }

    String::from_utf8(output.stdout)
        .map_err(|err| LogicPearlError::message(format!("z3 output was not valid UTF-8: {err}")))
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

fn conjunction_matches(
    features: &BTreeMap<String, bool>,
    required_true_features: &[String],
) -> bool {
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

    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| LogicPearlError::message(format!("z3 output was not valid UTF-8: {err}")))?;
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
        synthesize_boolean_conjunctions, verify_gate_against_formal_spec,
        BooleanConjunctionSearchOptions, BooleanSearchExample, FormalSpec, FormalSpecRule,
    };
    use logicpearl_ir::LogicPearlGateIr;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn synthesizes_exact_two_feature_conjunction() {
        if std::process::Command::new("z3")
            .arg("-version")
            .output()
            .is_err()
        {
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
        assert_eq!(
            candidates[0].required_true_features,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(candidates[0].positive_hits, 2);
        assert_eq!(candidates[0].negative_hits, 0);
    }

    #[test]
    fn formal_spec_verification_reports_complete_and_non_spurious_gate() {
        if std::process::Command::new("z3")
            .arg("-version")
            .output()
            .is_err()
        {
            return;
        }

        let gate = sample_gate();
        let spec = FormalSpec {
            spec_version: "1.0".to_string(),
            rules: vec![
                FormalSpecRule {
                    id: "minor".to_string(),
                    deny_when: serde_json::from_value(json!({
                        "feature": "age",
                        "op": "<",
                        "value": 18
                    }))
                    .unwrap(),
                    label: None,
                    message: None,
                },
                FormalSpecRule {
                    id: "viewer_write".to_string(),
                    deny_when: serde_json::from_value(json!({
                        "all": [
                            {"feature": "role", "op": "==", "value": "viewer"},
                            {"feature": "action", "op": "==", "value": "write"}
                        ]
                    }))
                    .unwrap(),
                    label: None,
                    message: None,
                },
            ],
        };

        let report = verify_gate_against_formal_spec(&gate, &spec).unwrap();
        assert!(report.complete);
        assert!(report.no_spurious_rules);
        assert!(report.fully_verified);
    }

    #[test]
    fn formal_spec_verification_reports_missing_and_spurious_rules() {
        if std::process::Command::new("z3")
            .arg("-version")
            .output()
            .is_err()
        {
            return;
        }

        let gate = sample_gate();
        let spec = FormalSpec {
            spec_version: "1.0".to_string(),
            rules: vec![FormalSpecRule {
                id: "minor_only".to_string(),
                deny_when: serde_json::from_value(json!({
                    "feature": "age",
                    "op": "<",
                    "value": 18
                }))
                .unwrap(),
                label: None,
                message: None,
            }],
        };

        let report = verify_gate_against_formal_spec(&gate, &spec).unwrap();
        assert!(report.complete);
        assert!(!report.no_spurious_rules);
        assert!(report
            .gate_rule_checks
            .iter()
            .any(|check| check.id == "viewer_write" && !check.implied_by_spec));
        assert!(report.overall_spurious_witness.is_some());
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

    fn sample_gate() -> LogicPearlGateIr {
        LogicPearlGateIr::from_json_str(
            &json!({
                "ir_version": "1.0",
                "gate_id": "sample_gate",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [
                        {"id": "age", "type": "int", "description": null, "values": null, "min": 0, "max": 120, "editable": null},
                        {"id": "role", "type": "enum", "description": null, "values": ["viewer", "editor"], "min": null, "max": null, "editable": null},
                        {"id": "action", "type": "enum", "description": null, "values": ["read", "write"], "min": null, "max": null, "editable": null}
                    ]
                },
                "rules": [
                    {
                        "id": "minor",
                        "kind": "predicate",
                        "bit": 0,
                        "deny_when": {"feature": "age", "op": "<", "value": 18},
                        "verification_status": "pipeline_unverified"
                    },
                    {
                        "id": "viewer_write",
                        "kind": "predicate",
                        "bit": 1,
                        "deny_when": {
                            "all": [
                                {"feature": "role", "op": "==", "value": "viewer"},
                                {"feature": "action", "op": "==", "value": "write"}
                            ]
                        },
                        "verification_status": "pipeline_unverified"
                    }
                ],
                "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
                "verification": null,
                "provenance": null
            })
            .to_string(),
        )
        .unwrap()
    }
}
