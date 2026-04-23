// SPDX-License-Identifier: MIT
//! Deterministic runtime evaluation for LogicPearl artifacts.
//!
//! Use this crate when an application already has a validated gate or action
//! policy IR and wants to evaluate normalized JSON input. It owns input
//! coercion, derived-feature evaluation, bitmask computation, explanation
//! assembly, runtime JSON schema identifiers, and artifact hashing. It does
//! not perform discovery, plugin execution, or artifact bundle loading.

pub use logicpearl_core::{artifact_hash, sha256_prefixed};
use logicpearl_core::{LogicPearlError, Result, RuleMask};
use logicpearl_ir::{
    derived_feature_evaluation_order, ActionSelectionStrategy, ComparisonExpression,
    ComparisonOperator, ComparisonValue, DerivedFeatureOperator, Expression, FeatureDefinition,
    InputSchema, LogicPearlActionIr, LogicPearlGateIr,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::HashMap;

pub const LOGICPEARL_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GATE_RESULT_SCHEMA_VERSION: &str = "logicpearl.gate_result.v1";
pub const ACTION_RESULT_SCHEMA_VERSION: &str = "logicpearl.action_result.v1";
pub const PIPELINE_RESULT_SCHEMA_VERSION: &str = "logicpearl.pipeline_result.v1";
pub const ARTIFACT_ERROR_SCHEMA_VERSION: &str = "logicpearl.artifact_error.v1";

/// Result of evaluating an action policy artifact.
///
/// `artifact_id`, `policy_id`, and `action_policy_id` currently resolve
/// to the same value. See `GateEvaluationResult` for rationale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionEvaluationResult {
    pub schema_version: String,
    pub engine_version: String,
    pub artifact_hash: String,
    pub artifact_id: String,
    pub policy_id: String,
    pub action_policy_id: String,
    pub decision_kind: String,
    pub action: String,
    #[serde(default)]
    pub default_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_match_action: Option<String>,
    pub bitmask: RuleMask,
    pub defaulted: bool,
    #[serde(default)]
    pub no_match: bool,
    #[serde(default)]
    pub selected_rules: Vec<ActionRuleMatch>,
    #[serde(default)]
    pub matched_rules: Vec<ActionRuleMatch>,
    #[serde(default)]
    pub candidate_actions: Vec<String>,
    #[serde(default)]
    pub ambiguity: Option<String>,
}

/// Details of a single action rule that matched during evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionRuleMatch {
    pub id: String,
    pub bit: u32,
    pub action: String,
    pub priority: u32,
    pub label: Option<String>,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub counterfactual_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<RuleFeatureExplanation>,
}

/// Details of a single gate rule that matched during evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GateRuleMatch {
    pub id: String,
    pub bit: u32,
    pub label: Option<String>,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub counterfactual_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<RuleFeatureExplanation>,
}

/// Result of evaluating a gate artifact against an input.
///
/// `artifact_id`, `policy_id`, and `gate_id` currently resolve to the same
/// value (`gate.gate_id`). They are separate fields to support future scenarios
/// where a single artifact contains multiple policies or where policy identity
/// differs from artifact identity (e.g., versioned artifact bundles).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GateEvaluationResult {
    pub schema_version: String,
    pub engine_version: String,
    pub artifact_hash: String,
    pub artifact_id: String,
    pub policy_id: String,
    pub gate_id: String,
    pub decision_kind: String,
    pub allow: bool,
    pub bitmask: RuleMask,
    pub defaulted: bool,
    #[serde(default)]
    pub ambiguity: Option<String>,
    #[serde(default)]
    pub matched_rules: Vec<GateRuleMatch>,
}

/// Per-feature explanation for why a rule matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleFeatureExplanation {
    pub feature_id: String,
    pub feature_label: Option<String>,
    pub source_id: Option<String>,
    pub source_anchor: Option<String>,
    pub state_label: Option<String>,
    pub state_message: Option<String>,
    pub counterfactual_hint: Option<String>,
}

/// Stable runtime error payload for integrations that need a JSON contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactError {
    pub schema_version: String,
    pub engine_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    pub error_code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl ArtifactError {
    pub fn new(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            schema_version: ARTIFACT_ERROR_SCHEMA_VERSION.to_string(),
            engine_version: LOGICPEARL_ENGINE_VERSION.to_string(),
            artifact_id: None,
            artifact_hash: None,
            error_code: error_code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_artifact(
        mut self,
        artifact_id: impl Into<String>,
        artifact_hash: impl Into<String>,
    ) -> Self {
        self.artifact_id = Some(artifact_id.into());
        self.artifact_hash = Some(artifact_hash.into());
        self
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Evaluate a gate artifact against input features and return the matched-rule bitmask.
pub fn evaluate_gate(
    gate: &LogicPearlGateIr,
    features: &HashMap<String, Value>,
) -> Result<RuleMask> {
    let features = resolve_gate_features(gate, features)?;
    let mut bitmask = RuleMask::zero();
    for rule in &gate.rules {
        if evaluate_expression(&rule.deny_when, &features)? {
            bitmask.set_bit(rule.bit);
        }
    }
    Ok(bitmask)
}

/// Evaluate a gate and return a full explanation including matched rules.
pub fn evaluate_gate_with_explanation(
    gate: &LogicPearlGateIr,
    features: &HashMap<String, Value>,
) -> Result<GateEvaluationResult> {
    let bitmask = evaluate_gate(gate, features)?;
    Ok(explain_gate_result(gate, bitmask))
}

/// Evaluate an action policy against input features and return the selected action.
pub fn evaluate_action_policy(
    policy: &LogicPearlActionIr,
    features: &HashMap<String, Value>,
) -> Result<ActionEvaluationResult> {
    let features = resolve_action_features(policy, features)?;
    let mut rules = policy.rules.iter().collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule.priority);

    let mut matched_rules = Vec::new();
    let mut candidate_actions = Vec::new();
    let mut weighted_votes: HashMap<String, u64> = HashMap::new();
    let mut bitmask = RuleMask::zero();
    for rule in &rules {
        if !evaluate_expression(&rule.predicate, &features)? {
            continue;
        }
        bitmask.set_bit(rule.bit);
        if !candidate_actions
            .iter()
            .any(|action| action == &rule.action)
        {
            candidate_actions.push(rule.action.clone());
        }
        // Weighted-vote strategy needs a per-rule weight. We use
        // `denied_trace_count` — the number of training rows that both
        // fired this rule AND carried this action as the correct label.
        // Rules without evidence (e.g. pinned rules) contribute a weight
        // of 1 so they still participate.
        let weight = rule
            .evidence
            .as_ref()
            .map(|e| e.support.denied_trace_count.max(1) as u64)
            .unwrap_or(1);
        *weighted_votes.entry(rule.action.clone()).or_insert(0) += weight;
        matched_rules.push(ActionRuleMatch {
            id: rule.id.clone(),
            bit: rule.bit,
            action: rule.action.clone(),
            priority: rule.priority,
            label: rule.label.clone(),
            message: rule.message.clone(),
            severity: rule.severity.clone(),
            counterfactual_hint: rule.counterfactual_hint.clone(),
            features: explain_rule_features(&policy.input_schema, &rule.predicate),
        });
    }

    let no_match = candidate_actions.is_empty();
    let action = if no_match {
        policy
            .no_match_action
            .clone()
            .unwrap_or_else(|| policy.default_action.clone())
    } else {
        match policy.evaluation.selection {
            ActionSelectionStrategy::FirstMatch => candidate_actions[0].clone(),
            ActionSelectionStrategy::WeightedVote => {
                // Winner is the action with the largest total weighted
                // vote. Ties break by priority order — whichever action
                // shows up first in `candidate_actions` (which mirrors
                // rules iterated in priority order) wins the tie.
                candidate_actions
                    .iter()
                    .max_by_key(|a| {
                        (
                            *weighted_votes.get(*a).unwrap_or(&0),
                            usize::MAX
                                - candidate_actions.iter().position(|x| x == *a).unwrap_or(0),
                        )
                    })
                    .cloned()
                    .unwrap_or_else(|| candidate_actions[0].clone())
            }
        }
    };
    let defaulted = no_match;
    let selected_rules = matched_rules
        .iter()
        .filter(|rule| rule.action == action)
        .cloned()
        .collect::<Vec<_>>();
    let ambiguity = (candidate_actions.len() > 1).then(|| {
        format!(
            "multiple action rules matched: {}",
            candidate_actions.join(", ")
        )
    });

    Ok(ActionEvaluationResult {
        schema_version: ACTION_RESULT_SCHEMA_VERSION.to_string(),
        engine_version: LOGICPEARL_ENGINE_VERSION.to_string(),
        artifact_hash: artifact_hash(policy),
        artifact_id: policy.action_policy_id.clone(),
        policy_id: policy.action_policy_id.clone(),
        action_policy_id: policy.action_policy_id.clone(),
        decision_kind: "action".to_string(),
        action,
        default_action: policy.default_action.clone(),
        no_match_action: policy.no_match_action.clone(),
        bitmask,
        defaulted,
        no_match,
        selected_rules,
        matched_rules,
        candidate_actions,
        ambiguity,
    })
}

/// Build a full gate evaluation result from a pre-computed bitmask.
pub fn explain_gate_result(gate: &LogicPearlGateIr, bitmask: RuleMask) -> GateEvaluationResult {
    GateEvaluationResult {
        schema_version: GATE_RESULT_SCHEMA_VERSION.to_string(),
        engine_version: LOGICPEARL_ENGINE_VERSION.to_string(),
        artifact_hash: artifact_hash(gate),
        artifact_id: gate.gate_id.clone(),
        policy_id: gate.gate_id.clone(),
        gate_id: gate.gate_id.clone(),
        decision_kind: "gate".to_string(),
        allow: bitmask.is_zero(),
        matched_rules: explain_gate_matches(gate, bitmask.clone()),
        bitmask,
        defaulted: false,
        ambiguity: None,
    }
}

/// Extract the list of matched gate rules from a bitmask.
pub fn explain_gate_matches(gate: &LogicPearlGateIr, bitmask: RuleMask) -> Vec<GateRuleMatch> {
    gate.rules
        .iter()
        .filter(|rule| bitmask.test_bit(rule.bit))
        .map(|rule| GateRuleMatch {
            id: rule.id.clone(),
            bit: rule.bit,
            label: rule.label.clone(),
            message: rule.message.clone(),
            severity: rule.severity.clone(),
            counterfactual_hint: rule.counterfactual_hint.clone(),
            features: explain_rule_features(&gate.input_schema, &rule.deny_when),
        })
        .collect()
}

/// Build per-feature explanations for a rule expression from input-schema semantics.
pub fn explain_rule_features(
    input_schema: &InputSchema,
    expression: &Expression,
) -> Vec<RuleFeatureExplanation> {
    let feature_defs = input_schema
        .features
        .iter()
        .map(|feature| (feature.id.as_str(), feature))
        .collect::<HashMap<_, _>>();
    let mut comparisons = Vec::new();
    collect_rule_comparisons(expression, &mut comparisons);

    let mut explanations = Vec::new();
    for comparison in comparisons {
        let Some(feature) = feature_defs.get(comparison.feature.as_str()) else {
            continue;
        };
        let semantics = feature.semantics.as_ref();
        let state = semantics.and_then(|semantics| {
            semantics.states.values().find(|state| {
                state.predicate.op == comparison.op && state.predicate.value == comparison.value
            })
        });
        let explanation = RuleFeatureExplanation {
            feature_id: feature.id.clone(),
            feature_label: semantics.and_then(|semantics| semantics.label.clone()),
            source_id: semantics.and_then(|semantics| semantics.source_id.clone()),
            source_anchor: semantics.and_then(|semantics| semantics.source_anchor.clone()),
            state_label: state.and_then(|state| state.label.clone()),
            state_message: state.and_then(|state| state.message.clone()),
            counterfactual_hint: state.and_then(|state| state.counterfactual_hint.clone()),
        };
        if !explanations
            .iter()
            .any(|existing: &RuleFeatureExplanation| {
                existing.feature_id == explanation.feature_id
                    && existing.state_label == explanation.state_label
                    && existing.state_message == explanation.state_message
            })
        {
            explanations.push(explanation);
        }
    }
    explanations
}

fn collect_rule_comparisons<'a>(
    expression: &'a Expression,
    comparisons: &mut Vec<&'a ComparisonExpression>,
) {
    match expression {
        Expression::Comparison(comparison) => comparisons.push(comparison),
        Expression::All { all } => {
            for child in all {
                collect_rule_comparisons(child, comparisons);
            }
        }
        Expression::Any { any } => {
            for child in any {
                collect_rule_comparisons(child, comparisons);
            }
        }
        Expression::Not { expr } => collect_rule_comparisons(expr, comparisons),
    }
}

/// Parse a JSON object or array of objects into normalized feature maps.
pub fn parse_input_payload(payload: Value) -> Result<Vec<HashMap<String, Value>>> {
    match payload {
        Value::Object(object) => Ok(vec![normalize_input_object(object)?]),
        Value::Array(items) => {
            let mut parsed = Vec::with_capacity(items.len());
            for item in items {
                let object = item.as_object().ok_or_else(|| {
                    LogicPearlError::message("input JSON array must contain only feature objects")
                })?;
                parsed.push(normalize_input_object(object.clone())?);
            }
            Ok(parsed)
        }
        _ => Err(LogicPearlError::message(
            "input JSON must be an object or an array of feature objects",
        )),
    }
}

fn normalize_input_object(object: Map<String, Value>) -> Result<HashMap<String, Value>> {
    object
        .into_iter()
        .map(|(key, value)| Ok((key, normalize_input_scalar(value)?)))
        .collect()
}

fn normalize_input_scalar(value: Value) -> Result<Value> {
    match value {
        Value::String(raw) => parse_runtime_scalar(&raw),
        other => Ok(other),
    }
}

fn parse_runtime_scalar(raw: &str) -> Result<Value> {
    let value = raw.trim();
    let lowered = value.to_ascii_lowercase();
    match lowered.as_str() {
        "true" | "yes" | "y" | "on" => return Ok(Value::Bool(true)),
        "false" | "no" | "n" | "off" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if let Some(number) = parse_runtime_number(value)? {
        return Ok(number);
    }
    Ok(Value::String(value.to_string()))
}

fn parse_runtime_number(raw: &str) -> Result<Option<Value>> {
    let mut candidate = raw.trim();
    let mut is_percent = false;
    if let Some(stripped) = candidate.strip_suffix('%') {
        candidate = stripped.trim();
        is_percent = true;
    }
    candidate = candidate
        .strip_prefix('$')
        .or_else(|| candidate.strip_prefix('€'))
        .or_else(|| candidate.strip_prefix('£'))
        .or_else(|| candidate.strip_prefix('¥'))
        .unwrap_or(candidate)
        .trim();
    let negative_wrapped = candidate.starts_with('(') && candidate.ends_with(')');
    if negative_wrapped {
        candidate = candidate
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or(candidate)
            .trim();
    }
    let mut normalized = candidate.replace(',', "");
    if negative_wrapped {
        normalized = format!("-{normalized}");
    }

    if !is_percent {
        if let Ok(parsed) = normalized.parse::<i64>() {
            return Ok(Some(Value::Number(Number::from(parsed))));
        }
    }
    if let Ok(mut parsed) = normalized.parse::<f64>() {
        if is_percent {
            parsed /= 100.0;
        }
        return Ok(Some(Value::Number(Number::from_f64(parsed).ok_or_else(
            || LogicPearlError::message("encountered non-finite float"),
        )?)));
    }
    Ok(None)
}

/// Evaluate a rule expression against already-resolved input features.
///
/// Callers evaluating a full gate or action policy should prefer
/// [`evaluate_gate`] or [`evaluate_action_policy`], which also resolve derived
/// features. This helper is exposed for diagnostics that need per-rule detail.
pub fn evaluate_expression(
    expression: &Expression,
    features: &HashMap<String, Value>,
) -> Result<bool> {
    match expression {
        Expression::Comparison(comparison) => evaluate_comparison(comparison, features),
        Expression::All { all } => {
            for child in all {
                if !evaluate_expression(child, features)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Expression::Any { any } => {
            for child in any {
                if evaluate_expression(child, features)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Expression::Not { expr } => Ok(!evaluate_expression(expr, features)?),
    }
}

fn resolve_derived_features(
    features: &[FeatureDefinition],
    input: &HashMap<String, Value>,
) -> Result<HashMap<String, Value>> {
    let derived_features = derived_feature_evaluation_order(features)?;
    for feature in &derived_features {
        let derived = feature
            .derived
            .as_ref()
            .expect("derived feature evaluation order should contain only derived features");
        if input.contains_key(&feature.id) {
            return Err(LogicPearlError::message(format!(
                "runtime input must not include derived feature {}; supply source features {} and {}",
                feature.id, derived.left_feature, derived.right_feature
            )));
        }
    }

    let mut resolved = input.clone();
    for feature in derived_features {
        let derived = feature
            .derived
            .as_ref()
            .expect("derived feature evaluation order should contain only derived features");
        let left = numeric_feature_value(&resolved, &derived.left_feature)?;
        let right = numeric_feature_value(&resolved, &derived.right_feature)?;
        let value = match derived.op {
            DerivedFeatureOperator::Difference => left - right,
            DerivedFeatureOperator::Ratio => {
                if left.is_nan() || right.is_nan() || right.abs() < f64::EPSILON {
                    0.0
                } else {
                    left / right
                }
            }
        };
        let sanitized = if value.is_finite() { value } else { 0.0 };
        resolved.insert(
            feature.id.clone(),
            Value::Number(Number::from_f64(sanitized).ok_or_else(|| {
                LogicPearlError::message(format!(
                    "derived feature {} could not be represented as a JSON number",
                    feature.id
                ))
            })?),
        );
    }
    Ok(resolved)
}

/// Resolve derived gate features into a copy of the runtime input.
pub fn resolve_gate_features(
    gate: &LogicPearlGateIr,
    features: &HashMap<String, Value>,
) -> Result<HashMap<String, Value>> {
    resolve_derived_features(&gate.input_schema.features, features)
}

/// Resolve derived action-policy features into a copy of the runtime input.
pub fn resolve_action_features(
    policy: &LogicPearlActionIr,
    features: &HashMap<String, Value>,
) -> Result<HashMap<String, Value>> {
    resolve_derived_features(&policy.input_schema.features, features)
}

fn numeric_feature_value(features: &HashMap<String, Value>, feature: &str) -> Result<f64> {
    features
        .get(feature)
        .and_then(Value::as_f64)
        .ok_or_else(|| LogicPearlError::message(format!("missing runtime feature: {feature}")))
}

fn evaluate_comparison(
    expression: &ComparisonExpression,
    features: &HashMap<String, Value>,
) -> Result<bool> {
    let left = features.get(&expression.feature).ok_or_else(|| {
        LogicPearlError::message(format!("missing runtime feature: {}", expression.feature))
    })?;
    let right = resolve_comparison_value(&expression.value, features)?;

    match expression.op {
        ComparisonOperator::Eq => Ok(values_equal(left, right)),
        ComparisonOperator::Ne => Ok(!values_equal(left, right)),
        ComparisonOperator::Gt => compare_numbers(left, right, |l, r| l > r),
        ComparisonOperator::Gte => compare_numbers(left, right, |l, r| l >= r),
        ComparisonOperator::Lt => compare_numbers(left, right, |l, r| l < r),
        ComparisonOperator::Lte => compare_numbers(left, right, |l, r| l <= r),
        ComparisonOperator::In => value_in(left, right),
        ComparisonOperator::NotIn => Ok(!value_in(left, right)?),
    }
}

fn resolve_comparison_value<'a>(
    value: &'a ComparisonValue,
    features: &'a HashMap<String, Value>,
) -> Result<&'a Value> {
    match value {
        ComparisonValue::Literal(literal) => Ok(literal),
        ComparisonValue::FeatureRef { feature_ref } => features.get(feature_ref).ok_or_else(|| {
            LogicPearlError::message(format!("missing runtime feature: {}", feature_ref))
        }),
    }
}

fn compare_numbers(
    left: &Value,
    right: &Value,
    predicate: impl Fn(f64, f64) -> bool,
) -> Result<bool> {
    let left = left
        .as_f64()
        .ok_or_else(|| LogicPearlError::message("runtime numeric comparison requires number"))?;
    let right = right
        .as_f64()
        .ok_or_else(|| LogicPearlError::message("runtime numeric comparison requires number"))?;
    Ok(predicate(left, right))
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(l), Some(r)) => (l - r).abs() < f64::EPSILON,
        _ => left == right,
    }
}

fn value_in(left: &Value, right: &Value) -> Result<bool> {
    let items = right
        .as_array()
        .ok_or_else(|| LogicPearlError::message("runtime membership comparison requires array"))?;
    Ok(items.iter().any(|item| values_equal(item, left)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use logicpearl_ir::{
        ActionEvaluationConfig, ActionRuleDefinition, ActionSelectionStrategy, CombineStrategy,
        EvaluationConfig, FeatureDefinition, FeatureType, GateType, InputSchema, Provenance,
        RuleDefinition, RuleKind, RuleVerificationStatus, VerificationConfig,
    };
    use serde_json::json;

    fn gate_for_eq_test(value: Value) -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "eq_test".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "flag".to_string(),
                    feature_type: FeatureType::Int,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                }],
            },
            rules: vec![RuleDefinition {
                id: "rule_000".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "flag".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(value),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
                evidence: None,
            }],
            evaluation: EvaluationConfig {
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: Some(VerificationConfig {
                domain_constraints: None,
                correctness_scope: None,
                verification_summary: Some(std::collections::HashMap::new()),
            }),
            provenance: Some(Provenance {
                generator: Some("test".to_string()),
                generator_version: Some("test".to_string()),
                source_commit: None,
                created_at: None,
            }),
        }
    }

    #[test]
    fn action_policy_selects_first_matching_action_and_reports_reasons() {
        let policy = LogicPearlActionIr {
            ir_version: "1.0".to_string(),
            action_policy_id: "garden_actions".to_string(),
            action_policy_type: "priority_rules".to_string(),
            action_column: "next_action".to_string(),
            default_action: "do_nothing".to_string(),
            no_match_action: None,
            actions: vec![
                "do_nothing".to_string(),
                "water".to_string(),
                "fertilize".to_string(),
            ],
            input_schema: InputSchema {
                features: vec![
                    FeatureDefinition {
                        id: "soil_moisture_pct".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "leaf_paleness_score".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                ],
            },
            rules: vec![
                ActionRuleDefinition {
                    id: "rule_000".to_string(),
                    bit: 0,
                    action: "water".to_string(),
                    priority: 0,
                    predicate: Expression::Comparison(ComparisonExpression {
                        feature: "soil_moisture_pct".to_string(),
                        op: ComparisonOperator::Lte,
                        value: ComparisonValue::Literal(json!(0.18)),
                    }),
                    label: Some("Soil is dry".to_string()),
                    message: None,
                    severity: None,
                    counterfactual_hint: None,
                    verification_status: None,
                    evidence: None,
                },
                ActionRuleDefinition {
                    id: "rule_001".to_string(),
                    bit: 1,
                    action: "fertilize".to_string(),
                    priority: 1,
                    predicate: Expression::Comparison(ComparisonExpression {
                        feature: "leaf_paleness_score".to_string(),
                        op: ComparisonOperator::Gte,
                        value: ComparisonValue::Literal(json!(4.0)),
                    }),
                    label: Some("Leaves are pale".to_string()),
                    message: None,
                    severity: None,
                    counterfactual_hint: None,
                    verification_status: None,
                    evidence: None,
                },
            ],
            evaluation: ActionEvaluationConfig {
                selection: ActionSelectionStrategy::FirstMatch,
            },
            verification: None,
            provenance: None,
        };
        policy
            .validate()
            .expect("test action policy should validate");
        let features = HashMap::from([
            ("soil_moisture_pct".to_string(), json!(0.14)),
            ("leaf_paleness_score".to_string(), json!(5.0)),
        ]);

        let result = evaluate_action_policy(&policy, &features).expect("policy should evaluate");

        assert_eq!(result.action, "water");
        assert_eq!(result.default_action, "do_nothing");
        assert_eq!(result.no_match_action, None);
        assert!(!result.no_match);
        assert_eq!(result.bitmask.as_u64(), Some(3));
        assert_eq!(result.selected_rules.len(), 1);
        assert_eq!(result.selected_rules[0].id, "rule_000");
        assert_eq!(result.selected_rules[0].bit, 0);
        assert_eq!(result.candidate_actions, vec!["water", "fertilize"]);
        assert!(result
            .ambiguity
            .as_deref()
            .is_some_and(|message| message.contains("water, fertilize")));

        let mut no_match_policy = policy.clone();
        no_match_policy
            .actions
            .push("insufficient_context".to_string());
        no_match_policy.no_match_action = Some("insufficient_context".to_string());
        let no_match_features = HashMap::from([
            ("soil_moisture_pct".to_string(), json!(0.4)),
            ("leaf_paleness_score".to_string(), json!(1.0)),
        ]);
        let no_match = evaluate_action_policy(&no_match_policy, &no_match_features)
            .expect("no-match policy should evaluate");
        assert_eq!(no_match.action, "insufficient_context");
        assert_eq!(no_match.default_action, "do_nothing");
        assert_eq!(
            no_match.no_match_action.as_deref(),
            Some("insufficient_context")
        );
        assert!(no_match.defaulted);
        assert!(no_match.no_match);
        assert!(no_match.selected_rules.is_empty());
        assert!(no_match.candidate_actions.is_empty());
    }

    #[test]
    fn weighted_vote_picks_action_with_largest_summed_support() {
        // Two rules match the same input:
        //   rule A: action=water, support=3 (low-support, first by priority)
        //   rule B: action=fertilize, support=40 (high-support, second by priority)
        // First-match would pick water; weighted-vote should pick fertilize.
        let policy = LogicPearlActionIr {
            ir_version: "1.0".to_string(),
            action_policy_id: "vote_test".to_string(),
            action_policy_type: "priority_rules".to_string(),
            action_column: "next_action".to_string(),
            default_action: "do_nothing".to_string(),
            no_match_action: None,
            actions: vec![
                "do_nothing".to_string(),
                "water".to_string(),
                "fertilize".to_string(),
            ],
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "x".to_string(),
                    feature_type: FeatureType::Int,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                }],
            },
            rules: vec![
                ActionRuleDefinition {
                    id: "rule_000".to_string(),
                    bit: 0,
                    action: "water".to_string(),
                    priority: 0,
                    predicate: Expression::Comparison(ComparisonExpression {
                        feature: "x".to_string(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(json!(1)),
                    }),
                    label: None,
                    message: None,
                    severity: None,
                    counterfactual_hint: None,
                    verification_status: None,
                    evidence: Some(logicpearl_ir::RuleEvidence {
                        schema_version: "logicpearl.rule_evidence.v1".to_string(),
                        support: logicpearl_ir::RuleSupportEvidence {
                            denied_trace_count: 3,
                            allowed_trace_count: 0,
                            example_traces: vec![],
                        },
                    }),
                },
                ActionRuleDefinition {
                    id: "rule_001".to_string(),
                    bit: 1,
                    action: "fertilize".to_string(),
                    priority: 1,
                    predicate: Expression::Comparison(ComparisonExpression {
                        feature: "x".to_string(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(json!(1)),
                    }),
                    label: None,
                    message: None,
                    severity: None,
                    counterfactual_hint: None,
                    verification_status: None,
                    evidence: Some(logicpearl_ir::RuleEvidence {
                        schema_version: "logicpearl.rule_evidence.v1".to_string(),
                        support: logicpearl_ir::RuleSupportEvidence {
                            denied_trace_count: 40,
                            allowed_trace_count: 0,
                            example_traces: vec![],
                        },
                    }),
                },
            ],
            evaluation: ActionEvaluationConfig {
                selection: ActionSelectionStrategy::WeightedVote,
            },
            verification: None,
            provenance: None,
        };
        policy.validate().expect("policy validates");
        let features = HashMap::from([("x".to_string(), json!(1))]);
        let result = evaluate_action_policy(&policy, &features).expect("eval");
        assert_eq!(result.action, "fertilize", "higher-support rule should win");
        assert_eq!(result.candidate_actions, vec!["water", "fertilize"]);
    }

    #[test]
    fn numeric_equality_matches_int_and_float_forms() {
        let gate = gate_for_eq_test(json!(1.0));
        let features = HashMap::from([("flag".to_string(), json!(1))]);
        let bitmask = evaluate_gate(&gate, &features).expect("runtime evaluation should succeed");
        assert_eq!(bitmask.as_u64(), Some(1));
    }

    #[test]
    fn parse_input_payload_normalizes_human_numeric_strings() {
        let parsed = parse_input_payload(json!({
            "soil_moisture_pct": "14%",
            "cost": "$1,200",
            "flag": "yes",
            "label": "fern"
        }))
        .expect("input should parse");
        let row = &parsed[0];
        assert_eq!(row["soil_moisture_pct"], json!(0.14));
        assert_eq!(row["cost"], json!(1200));
        assert_eq!(row["flag"], json!(true));
        assert_eq!(row["label"], json!("fern"));
    }

    #[test]
    fn parse_input_payload_matches_shared_coercion_fixtures() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/runtime/input_coercion_cases.json"
        ))
        .expect("coercion fixture should parse");
        let cases = fixture["cases"]
            .as_array()
            .expect("coercion fixture should define cases");

        for fixture_case in cases {
            let parsed = parse_input_payload(fixture_case["input"].clone())
                .expect("coercion fixture input should parse");
            let expected = fixture_case["expected_normalized"]
                .as_object()
                .expect("coercion fixture should define expected normalized object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>();
            assert_eq!(
                parsed[0],
                expected,
                "coercion case {} diverged",
                fixture_case["id"].as_str().unwrap_or("<unknown>")
            );
        }
    }

    #[test]
    fn numeric_membership_matches_int_and_float_forms() {
        let mut features = HashMap::new();
        features.insert("flag".to_string(), json!(2));
        let expression = ComparisonExpression {
            feature: "flag".to_string(),
            op: ComparisonOperator::In,
            value: ComparisonValue::Literal(json!([1.0, 2.0])),
        };
        assert!(evaluate_comparison(&expression, &features).expect("membership should evaluate"));
    }

    #[test]
    fn numeric_feature_reference_comparison_evaluates() {
        let expression = ComparisonExpression {
            feature: "clearance".to_string(),
            op: ComparisonOperator::Lt,
            value: ComparisonValue::FeatureRef {
                feature_ref: "sensitivity".to_string(),
            },
        };
        let features = HashMap::from([
            ("clearance".to_string(), json!(2)),
            ("sensitivity".to_string(), json!(4)),
        ]);
        assert!(evaluate_comparison(&expression, &features)
            .expect("feature ref comparison should evaluate"));
    }

    #[test]
    fn feature_semantics_do_not_change_runtime_evaluation() {
        let plain_gate = gate_for_eq_test(json!(1));
        let mut annotated_gate = plain_gate.clone();
        annotated_gate.input_schema.features[0].semantics = Some(
            serde_json::from_value(json!({
                "label": "Risk flag",
                "states": {
                    "present": {
                        "when": {"op": "==", "value": 1},
                        "label": "Risk flag is present",
                        "message": "This rule fires when the risk flag is present.",
                        "counterfactual_hint": "Remove the risk flag."
                    }
                }
            }))
            .unwrap(),
        );
        let features = HashMap::from([("flag".to_string(), json!(1))]);

        assert_eq!(
            evaluate_gate(&plain_gate, &features).unwrap(),
            evaluate_gate(&annotated_gate, &features).unwrap()
        );
    }

    fn derived_ratio_gate() -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "ratio_gate".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![
                    FeatureDefinition {
                        id: "debt".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "income".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "debt_to_income".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: Some(logicpearl_ir::DerivedFeatureDefinition {
                            op: logicpearl_ir::DerivedFeatureOperator::Ratio,
                            left_feature: "debt".to_string(),
                            right_feature: "income".to_string(),
                        }),
                    },
                ],
            },
            rules: vec![RuleDefinition {
                id: "rule_000".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "debt_to_income".to_string(),
                    op: ComparisonOperator::Gte,
                    value: ComparisonValue::Literal(json!(0.5)),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
                evidence: None,
            }],
            evaluation: EvaluationConfig {
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: Some(VerificationConfig {
                domain_constraints: None,
                correctness_scope: None,
                verification_summary: Some(std::collections::HashMap::new()),
            }),
            provenance: Some(Provenance {
                generator: Some("test".to_string()),
                generator_version: Some("test".to_string()),
                source_commit: None,
                created_at: None,
            }),
        }
    }

    #[test]
    fn derived_ratio_feature_evaluates_from_raw_inputs() {
        let gate = derived_ratio_gate();
        let features = HashMap::from([
            ("debt".to_string(), json!(55.0)),
            ("income".to_string(), json!(100.0)),
        ]);
        let bitmask = evaluate_gate(&gate, &features).expect("derived ratio should evaluate");
        assert_eq!(bitmask.as_u64(), Some(1));
    }

    #[test]
    fn chained_derived_features_evaluate_in_dependency_order() {
        let gate = LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "derived_chain".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![
                    FeatureDefinition {
                        id: "risk_margin".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: Some(logicpearl_ir::DerivedFeatureDefinition {
                            op: logicpearl_ir::DerivedFeatureOperator::Difference,
                            left_feature: "debt_to_income".to_string(),
                            right_feature: "limit".to_string(),
                        }),
                    },
                    FeatureDefinition {
                        id: "debt_to_income".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: Some(logicpearl_ir::DerivedFeatureDefinition {
                            op: logicpearl_ir::DerivedFeatureOperator::Ratio,
                            left_feature: "debt".to_string(),
                            right_feature: "income".to_string(),
                        }),
                    },
                    FeatureDefinition {
                        id: "limit".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "debt".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                    FeatureDefinition {
                        id: "income".to_string(),
                        feature_type: FeatureType::Float,
                        description: None,
                        values: None,
                        min: None,
                        max: None,
                        editable: None,
                        semantics: None,
                        governance: None,
                        derived: None,
                    },
                ],
            },
            rules: vec![RuleDefinition {
                id: "rule_000".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "risk_margin".to_string(),
                    op: ComparisonOperator::Gte,
                    value: ComparisonValue::Literal(json!(0.0)),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::PipelineUnverified),
                evidence: None,
            }],
            evaluation: EvaluationConfig {
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        };
        let features = HashMap::from([
            ("debt".to_string(), json!(55.0)),
            ("income".to_string(), json!(100.0)),
            ("limit".to_string(), json!(0.5)),
        ]);

        let bitmask = evaluate_gate(&gate, &features).expect("derived chain should evaluate");
        assert_eq!(bitmask.as_u64(), Some(1));
    }

    #[test]
    fn runtime_rejects_inputs_that_override_derived_features() {
        let gate = derived_ratio_gate();
        let features = HashMap::from([
            ("debt".to_string(), json!(55.0)),
            ("income".to_string(), json!(100.0)),
            ("debt_to_income".to_string(), json!(0.0)),
        ]);

        let err = evaluate_gate(&gate, &features)
            .expect_err("runtime input should not be able to override derived features");
        let message = err.to_string();
        assert!(message.contains("must not include derived feature debt_to_income"));
        assert!(message.contains("supply source features debt and income"));
    }

    /// Helper: build a minimal valid gate for runtime tests.
    fn minimal_runtime_gate() -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "runtime_test".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "age".to_string(),
                    feature_type: FeatureType::Int,
                    description: None,
                    values: None,
                    min: None,
                    max: None,
                    editable: None,
                    semantics: None,
                    governance: None,
                    derived: None,
                }],
            },
            rules: vec![RuleDefinition {
                id: "rule_1".to_string(),
                kind: RuleKind::Predicate,
                bit: 0,
                deny_when: Expression::Comparison(ComparisonExpression {
                    feature: "age".to_string(),
                    op: ComparisonOperator::Lt,
                    value: ComparisonValue::Literal(json!(18)),
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: None,
                evidence: None,
            }],
            evaluation: EvaluationConfig {
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        }
    }

    #[test]
    fn evaluate_gate_allows_when_no_rules_match() {
        let gate = minimal_runtime_gate();
        // age=25 does NOT satisfy deny_when (age < 18), so no rules match
        let features = HashMap::from([("age".to_string(), json!(25))]);
        let result =
            evaluate_gate_with_explanation(&gate, &features).expect("evaluation should succeed");
        assert!(result.allow, "gate should allow when no rules match");
        assert!(result.bitmask.is_zero());
        assert!(result.matched_rules.is_empty());
    }

    #[test]
    fn evaluate_gate_denies_when_rule_matches() {
        let gate = minimal_runtime_gate();
        // age=15 satisfies deny_when (age < 18), so rule matches
        let features = HashMap::from([("age".to_string(), json!(15))]);
        let result =
            evaluate_gate_with_explanation(&gate, &features).expect("evaluation should succeed");
        assert!(!result.allow, "gate should deny when a rule matches");
        assert!(!result.bitmask.is_zero());
        assert_eq!(result.matched_rules.len(), 1);
        assert_eq!(result.matched_rules[0].id, "rule_1");
    }

    #[test]
    fn parse_input_payload_single_object() {
        let payload = json!({"age": 25});
        let parsed = parse_input_payload(payload).expect("single object should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["age"], json!(25));
    }

    #[test]
    fn parse_input_payload_array() {
        let payload = json!([{"age": 25}, {"age": 17}]);
        let parsed = parse_input_payload(payload).expect("array should parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["age"], json!(25));
        assert_eq!(parsed[1]["age"], json!(17));
    }
}
