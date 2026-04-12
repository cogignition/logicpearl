// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

/// The type of gate evaluation strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GateType {
    /// Evaluate rules into a bitmask where each bit represents one rule.
    BitmaskGate,
}

/// Strategy for combining per-rule bitmask results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CombineStrategy {
    /// OR all matched rule bits together.
    BitwiseOr,
}
/// Intermediate representation of a LogicPearl gate artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogicPearlGateIr {
    pub ir_version: String,
    pub gate_id: String,
    pub gate_type: GateType,
    pub input_schema: InputSchema,
    pub rules: Vec<RuleDefinition>,
    pub evaluation: EvaluationConfig,
    pub verification: Option<VerificationConfig>,
    pub provenance: Option<Provenance>,
}

/// Intermediate representation of a LogicPearl action policy artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogicPearlActionIr {
    pub ir_version: String,
    pub action_policy_id: String,
    pub action_policy_type: String,
    pub action_column: String,
    pub default_action: String,
    pub actions: Vec<String>,
    pub input_schema: InputSchema,
    pub rules: Vec<ActionRuleDefinition>,
    pub evaluation: ActionEvaluationConfig,
    pub verification: Option<VerificationConfig>,
    pub provenance: Option<Provenance>,
}

/// Schema describing the input features expected by an artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputSchema {
    pub features: Vec<FeatureDefinition>,
}

/// Definition of a single input feature, including type, bounds, and optional derived logic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureDefinition {
    pub id: String,
    #[serde(rename = "type")]
    pub feature_type: FeatureType,
    pub description: Option<String>,
    pub values: Option<Vec<Value>>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub editable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<FeatureSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<FeatureGovernance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived: Option<DerivedFeatureDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureSemantics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub higher_is_better: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub states: BTreeMap<String, FeatureStateSemantics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureStateSemantics {
    #[serde(rename = "when")]
    pub predicate: FeatureStatePredicate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, alias = "fix", skip_serializing_if = "Option::is_none")]
    pub counterfactual_hint: Option<String>,
}

/// Predicate that defines when a feature state applies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureStatePredicate {
    pub op: ComparisonOperator,
    pub value: ComparisonValue,
}

/// Governance constraints on how a feature may be used in rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureGovernance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_boolean_evidence: Option<BooleanEvidencePolicy>,
}

/// Controls which boolean evidence values a feature may use in deny rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BooleanEvidencePolicy {
    Either,
    TrueOnly,
    FalseOnly,
    Never,
}

/// A feature computed at runtime from two other features.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedFeatureDefinition {
    pub op: DerivedFeatureOperator,
    pub left_feature: String,
    pub right_feature: String,
}

/// Arithmetic operator used when computing a derived feature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DerivedFeatureOperator {
    Difference,
    Ratio,
}

/// The data type of a feature value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeatureType {
    Bool,
    Int,
    Float,
    String,
    Enum,
}

/// A single deny rule within a gate artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleDefinition {
    pub id: String,
    pub kind: RuleKind,
    pub bit: u32,
    pub deny_when: Expression,
    pub label: Option<String>,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub counterfactual_hint: Option<String>,
    pub verification_status: Option<RuleVerificationStatus>,
}

/// A single rule within an action policy artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionRuleDefinition {
    pub id: String,
    pub bit: u32,
    pub action: String,
    pub priority: u32,
    #[serde(rename = "when")]
    pub predicate: Expression,
    pub label: Option<String>,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub counterfactual_hint: Option<String>,
    pub verification_status: Option<RuleVerificationStatus>,
}

/// Classification of how a rule's condition is expressed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Predicate,
    Threshold,
    WeightedSum,
}

/// Tracks how a rule was verified during the build pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerificationStatus {
    SolverVerified,
    PipelineUnverified,
    HeuristicUnverified,
    RefinedUnverified,
}

/// Configuration controlling how gate evaluation produces a final decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationConfig {
    pub combine: CombineStrategy,
    pub allow_when_bitmask: u64,
}

/// Configuration controlling how action policy evaluation selects an action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionEvaluationConfig {
    pub selection: ActionSelectionStrategy,
}

/// Strategy for choosing among matched action rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionSelectionStrategy {
    FirstMatch,
}

/// Optional verification metadata attached to a gate artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationConfig {
    pub domain_constraints: Option<Vec<ComparisonExpression>>,
    pub correctness_scope: Option<String>,
    pub verification_summary: Option<HashMap<String, u64>>,
}

/// Build-time provenance metadata describing how an artifact was produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    pub generator: Option<String>,
    pub generator_version: Option<String>,
    pub source_commit: Option<String>,
    pub created_at: Option<String>,
}

/// Boolean expression tree used in rule predicates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Expression {
    Comparison(ComparisonExpression),
    All {
        all: Vec<Expression>,
    },
    Any {
        any: Vec<Expression>,
    },
    Not {
        #[serde(rename = "not")]
        expr: Box<Expression>,
    },
}

/// A leaf comparison: feature op value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparisonExpression {
    pub feature: String,
    pub op: ComparisonOperator,
    pub value: ComparisonValue,
}

/// The right-hand side of a comparison: either a literal or a reference to another feature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ComparisonValue {
    FeatureRef { feature_ref: String },
    Literal(Value),
}

/// Relational operator used in a comparison expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComparisonOperator {
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Gte,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Lte,
    #[serde(rename = "in")]
    In,
    #[serde(rename = "not_in")]
    NotIn,
}

impl LogicPearlGateIr {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let gate: Self = serde_json::from_str(input)?;
        gate.validate()?;
        Ok(gate)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    pub fn write_pretty(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.ir_version != "1.0" {
            return Err(LogicPearlError::message(format!(
                "unsupported ir_version: {}",
                self.ir_version
            )));
        }
        if self.evaluation.allow_when_bitmask != 0 {
            return Err(LogicPearlError::message(
                "evaluation.allow_when_bitmask must be 0",
            ));
        }
        if self.gate_id.is_empty() {
            return Err(LogicPearlError::message("gate id must be non-empty"));
        }
        if self.input_schema.features.is_empty() {
            return Err(LogicPearlError::message(
                "input schema must define at least one feature",
            ));
        }
        if self.rules.is_empty() {
            return Err(LogicPearlError::message(
                "gate must define at least one rule",
            ));
        }

        let known_features = validate_input_schema(&self.input_schema)?;

        let mut rule_ids = BTreeSet::new();
        let mut rule_bits = BTreeSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() {
                return Err(LogicPearlError::message("rule id must be non-empty"));
            }
            if !rule_ids.insert(rule.id.clone()) {
                return Err(LogicPearlError::message(format!(
                    "duplicate rule ids: {}",
                    rule.id
                )));
            }
            if !rule_bits.insert(rule.bit) {
                return Err(LogicPearlError::message(format!(
                    "duplicate rule bits: {}",
                    rule.bit
                )));
            }
            validate_expression(&rule.deny_when, &known_features)?;
        }

        validate_verification(self.verification.as_ref(), &known_features)?;

        Ok(())
    }
}

impl LogicPearlActionIr {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let policy: Self = serde_json::from_str(input)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    pub fn write_pretty(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.ir_version != "1.0" {
            return Err(LogicPearlError::message(format!(
                "unsupported ir_version: {}",
                self.ir_version
            )));
        }
        if self.action_policy_type != "priority_rules" {
            return Err(LogicPearlError::message(format!(
                "unsupported action_policy_type: {}",
                self.action_policy_type
            )));
        }
        if self.action_policy_id.is_empty() {
            return Err(LogicPearlError::message(
                "action policy id must be non-empty",
            ));
        }
        if self.action_column.is_empty() {
            return Err(LogicPearlError::message("action column must be non-empty"));
        }
        if self.default_action.is_empty() {
            return Err(LogicPearlError::message("default action must be non-empty"));
        }
        if self.actions.is_empty() {
            return Err(LogicPearlError::message(
                "action policy must define at least one action",
            ));
        }
        if self.rules.is_empty() {
            return Err(LogicPearlError::message(
                "action policy must define at least one rule",
            ));
        }

        let known_features = validate_input_schema(&self.input_schema)?;
        let mut actions = BTreeSet::new();
        for action in &self.actions {
            if action.trim().is_empty() {
                return Err(LogicPearlError::message("actions must be non-empty"));
            }
            if !actions.insert(action.clone()) {
                return Err(LogicPearlError::message(format!(
                    "duplicate actions: {action}"
                )));
            }
        }
        if !actions.contains(&self.default_action) {
            return Err(LogicPearlError::message(format!(
                "default action is not listed in actions: {}",
                self.default_action
            )));
        }

        let mut rule_ids = BTreeSet::new();
        let mut rule_bits = BTreeSet::new();
        let mut priorities = BTreeSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() {
                return Err(LogicPearlError::message("rule id must be non-empty"));
            }
            if !rule_ids.insert(rule.id.clone()) {
                return Err(LogicPearlError::message(format!(
                    "duplicate rule ids: {}",
                    rule.id
                )));
            }
            if !rule_bits.insert(rule.bit) {
                return Err(LogicPearlError::message(format!(
                    "duplicate action rule bits: {}",
                    rule.bit
                )));
            }
            if !actions.contains(&rule.action) {
                return Err(LogicPearlError::message(format!(
                    "rule {} references unknown action {}",
                    rule.id, rule.action
                )));
            }
            if !priorities.insert(rule.priority) {
                return Err(LogicPearlError::message(format!(
                    "duplicate action rule priorities: {}",
                    rule.priority
                )));
            }
            validate_optional_non_empty(&rule.label, "rule label")?;
            validate_optional_non_empty(&rule.message, "rule message")?;
            validate_optional_non_empty(&rule.severity, "rule severity")?;
            validate_optional_non_empty(&rule.counterfactual_hint, "rule counterfactual_hint")?;
            validate_expression(&rule.predicate, &known_features)?;
        }

        validate_verification(self.verification.as_ref(), &known_features)?;

        Ok(())
    }
}

pub fn validate_expression_against_schema(
    expression: &Expression,
    input_schema: &InputSchema,
) -> Result<()> {
    let known_features = input_schema
        .features
        .iter()
        .map(|feature| (feature.id.clone(), feature))
        .collect::<HashMap<_, _>>();
    validate_expression(expression, &known_features)
}

fn validate_input_schema(
    input_schema: &InputSchema,
) -> Result<HashMap<String, &FeatureDefinition>> {
    if input_schema.features.is_empty() {
        return Err(LogicPearlError::message(
            "input schema must define at least one feature",
        ));
    }

    let mut feature_ids = BTreeSet::new();
    let mut known_features = HashMap::new();
    for feature in &input_schema.features {
        if feature.id.is_empty() {
            return Err(LogicPearlError::message("feature id must be non-empty"));
        }
        if !feature_ids.insert(feature.id.clone()) {
            return Err(LogicPearlError::message(format!(
                "duplicate feature ids: {}",
                feature.id
            )));
        }
        feature.validate()?;
        if let Some(derived) = &feature.derived {
            validate_derived_feature(feature, derived, &known_features)?;
        }
        known_features.insert(feature.id.clone(), feature);
    }
    for feature in &input_schema.features {
        if let Some(semantics) = &feature.semantics {
            validate_feature_semantics(feature, semantics, &known_features)?;
        }
    }
    Ok(known_features)
}

fn validate_verification(
    verification: Option<&VerificationConfig>,
    known_features: &HashMap<String, &FeatureDefinition>,
) -> Result<()> {
    if let Some(verification) = verification {
        if let Some(constraints) = &verification.domain_constraints {
            for constraint in constraints {
                let feature = known_features.get(&constraint.feature).ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "unknown features referenced: {}",
                        constraint.feature
                    ))
                })?;
                validate_comparison(constraint, feature, known_features)?;
            }
        }
    }
    Ok(())
}

impl FeatureDefinition {
    fn validate(&self) -> Result<()> {
        if self.derived.is_some() && !matches!(self.feature_type, FeatureType::Float) {
            return Err(LogicPearlError::message(
                "derived features must use float type",
            ));
        }
        match self.feature_type {
            FeatureType::Enum => {
                if self.values.as_ref().is_none_or(|values| values.is_empty()) {
                    return Err(LogicPearlError::message("enum features must define values"));
                }
            }
            _ => {
                if self.values.is_some() {
                    return Err(LogicPearlError::message(
                        "only enum features may define values",
                    ));
                }
            }
        }
        if let (Some(min), Some(max)) = (self.min, self.max) {
            if min > max {
                return Err(LogicPearlError::message("feature min cannot exceed max"));
            }
        }
        if self
            .governance
            .as_ref()
            .and_then(|governance| governance.deny_boolean_evidence.as_ref())
            .is_some()
            && !matches!(self.feature_type, FeatureType::Bool)
        {
            return Err(LogicPearlError::message(
                "deny_boolean_evidence governance requires bool feature type",
            ));
        }
        Ok(())
    }
}

fn validate_feature_semantics(
    feature: &FeatureDefinition,
    semantics: &FeatureSemantics,
    known_features: &HashMap<String, &FeatureDefinition>,
) -> Result<()> {
    validate_optional_non_empty(&semantics.label, "feature semantics label")?;
    validate_optional_non_empty(&semantics.kind, "feature semantics kind")?;
    validate_optional_non_empty(&semantics.unit, "feature semantics unit")?;
    validate_optional_non_empty(&semantics.source_id, "feature semantics source_id")?;
    validate_optional_non_empty(&semantics.source_anchor, "feature semantics source_anchor")?;
    for (state_id, state) in &semantics.states {
        if state_id.trim().is_empty() {
            return Err(LogicPearlError::message(
                "feature semantics state ids must be non-empty",
            ));
        }
        validate_optional_non_empty(&state.label, "feature semantics state label")?;
        validate_optional_non_empty(&state.message, "feature semantics state message")?;
        validate_optional_non_empty(
            &state.counterfactual_hint,
            "feature semantics state counterfactual_hint",
        )?;
        let comparison = ComparisonExpression {
            feature: feature.id.clone(),
            op: state.predicate.op.clone(),
            value: state.predicate.value.clone(),
        };
        validate_comparison(&comparison, feature, known_features)?;
    }
    Ok(())
}

fn validate_optional_non_empty(value: &Option<String>, field: &str) -> Result<()> {
    if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
        return Err(LogicPearlError::message(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_derived_feature(
    feature: &FeatureDefinition,
    derived: &DerivedFeatureDefinition,
    known_features: &HashMap<String, &FeatureDefinition>,
) -> Result<()> {
    let left = known_features.get(&derived.left_feature).ok_or_else(|| {
        LogicPearlError::message(format!(
            "unknown features referenced by derived feature {}: {}",
            feature.id, derived.left_feature
        ))
    })?;
    let right = known_features.get(&derived.right_feature).ok_or_else(|| {
        LogicPearlError::message(format!(
            "unknown features referenced by derived feature {}: {}",
            feature.id, derived.right_feature
        ))
    })?;
    for source in [left, right] {
        if !matches!(source.feature_type, FeatureType::Int | FeatureType::Float) {
            return Err(LogicPearlError::message(format!(
                "derived feature {} requires numeric inputs: {}",
                feature.id, source.id
            )));
        }
    }
    Ok(())
}

fn validate_expression(
    expression: &Expression,
    known_features: &HashMap<String, &FeatureDefinition>,
) -> Result<()> {
    match expression {
        Expression::Comparison(comparison) => {
            let feature = known_features.get(&comparison.feature).ok_or_else(|| {
                LogicPearlError::message(format!(
                    "unknown features referenced: {}",
                    comparison.feature
                ))
            })?;
            validate_comparison(comparison, feature, known_features)
        }
        Expression::All { all } => {
            if all.is_empty() {
                return Err(LogicPearlError::message(
                    "all expressions must contain at least one child",
                ));
            }
            for child in all {
                validate_expression(child, known_features)?;
            }
            Ok(())
        }
        Expression::Any { any } => {
            if any.is_empty() {
                return Err(LogicPearlError::message(
                    "any expressions must contain at least one child",
                ));
            }
            for child in any {
                validate_expression(child, known_features)?;
            }
            Ok(())
        }
        Expression::Not { expr } => validate_expression(expr, known_features),
    }
}

fn validate_comparison(
    expression: &ComparisonExpression,
    feature: &FeatureDefinition,
    known_features: &HashMap<String, &FeatureDefinition>,
) -> Result<()> {
    if let Some(feature_ref) = expression.value.feature_ref() {
        let rhs_feature = known_features.get(feature_ref).ok_or_else(|| {
            LogicPearlError::message(format!("unknown features referenced: {}", feature_ref))
        })?;
        ensure_feature_reference_comparison(feature, rhs_feature, &expression.op)?;
        return Ok(());
    }

    let literal = expression.value.literal().ok_or_else(|| {
        LogicPearlError::message("comparison value must be a literal or feature reference")
    })?;

    match feature.feature_type {
        FeatureType::Bool => {
            ensure_op(
                &expression.op,
                &[ComparisonOperator::Eq, ComparisonOperator::Ne],
                "bool",
            )?;
            if !literal.is_boolean() {
                return Err(LogicPearlError::message(format!(
                    "requires bool value for feature {}",
                    feature.id
                )));
            }
        }
        FeatureType::Enum => {
            let allowed = feature.values.as_ref().expect("enum values validated");
            match expression.op {
                ComparisonOperator::In | ComparisonOperator::NotIn => {
                    let items = literal.as_array().ok_or_else(|| {
                        LogicPearlError::message(format!(
                            "requires array value for enum feature {}",
                            feature.id
                        ))
                    })?;
                    for item in items {
                        if !allowed.contains(item) {
                            return Err(LogicPearlError::message(format!(
                                "unsupported enum value {} for feature {}",
                                item, feature.id
                            )));
                        }
                    }
                }
                _ => {
                    if !allowed.contains(literal) {
                        return Err(LogicPearlError::message(format!(
                            "unsupported enum value {} for feature {}",
                            literal, feature.id
                        )));
                    }
                }
            }
        }
        FeatureType::String => match expression.op {
            ComparisonOperator::Eq
            | ComparisonOperator::Ne
            | ComparisonOperator::In
            | ComparisonOperator::NotIn => {}
            _ => {
                return Err(LogicPearlError::message(format!(
                    "unsupported operator {} for string feature",
                    expression.op.as_str()
                )));
            }
        },
        FeatureType::Int | FeatureType::Float => {
            ensure_op(
                &expression.op,
                &[
                    ComparisonOperator::Eq,
                    ComparisonOperator::Ne,
                    ComparisonOperator::Gt,
                    ComparisonOperator::Gte,
                    ComparisonOperator::Lt,
                    ComparisonOperator::Lte,
                    ComparisonOperator::In,
                    ComparisonOperator::NotIn,
                ],
                "numeric",
            )?;
        }
    }
    Ok(())
}

fn ensure_feature_reference_comparison(
    feature: &FeatureDefinition,
    rhs_feature: &FeatureDefinition,
    op: &ComparisonOperator,
) -> Result<()> {
    match (&feature.feature_type, &rhs_feature.feature_type) {
        (FeatureType::Bool, FeatureType::Bool) => {
            ensure_op(
                op,
                &[ComparisonOperator::Eq, ComparisonOperator::Ne],
                "bool",
            )?;
        }
        (FeatureType::String, FeatureType::String) | (FeatureType::Enum, FeatureType::Enum) => {
            ensure_op(
                op,
                &[ComparisonOperator::Eq, ComparisonOperator::Ne],
                "feature_ref",
            )?;
        }
        (FeatureType::Int | FeatureType::Float, FeatureType::Int | FeatureType::Float) => {
            ensure_op(
                op,
                &[
                    ComparisonOperator::Eq,
                    ComparisonOperator::Ne,
                    ComparisonOperator::Gt,
                    ComparisonOperator::Gte,
                    ComparisonOperator::Lt,
                    ComparisonOperator::Lte,
                ],
                "numeric feature_ref",
            )?;
        }
        _ => {
            return Err(LogicPearlError::message(format!(
                "feature reference comparison requires compatible feature types: {} vs {}",
                feature.id, rhs_feature.id
            )));
        }
    }
    if matches!(op, ComparisonOperator::In | ComparisonOperator::NotIn) {
        return Err(LogicPearlError::message(
            "feature reference comparisons do not support in/not_in",
        ));
    }
    Ok(())
}

fn ensure_op(
    actual: &ComparisonOperator,
    allowed: &[ComparisonOperator],
    kind: &str,
) -> Result<()> {
    if allowed.contains(actual) {
        return Ok(());
    }
    Err(LogicPearlError::message(format!(
        "unsupported operator {} for {kind} feature",
        actual.as_str()
    )))
}

impl ComparisonOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComparisonOperator::Eq => "==",
            ComparisonOperator::Ne => "!=",
            ComparisonOperator::Gt => ">",
            ComparisonOperator::Gte => ">=",
            ComparisonOperator::Lt => "<",
            ComparisonOperator::Lte => "<=",
            ComparisonOperator::In => "in",
            ComparisonOperator::NotIn => "not_in",
        }
    }
}

impl ComparisonValue {
    pub fn literal(&self) -> Option<&Value> {
        match self {
            ComparisonValue::Literal(value) => Some(value),
            ComparisonValue::FeatureRef { .. } => None,
        }
    }

    pub fn feature_ref(&self) -> Option<&str> {
        match self {
            ComparisonValue::Literal(_) => None,
            ComparisonValue::FeatureRef { feature_ref } => Some(feature_ref.as_str()),
        }
    }
}

pub fn canonicalize_expression(expression: &Expression) -> Expression {
    match expression {
        Expression::Comparison(comparison) => Expression::Comparison(ComparisonExpression {
            feature: comparison.feature.clone(),
            op: comparison.op.clone(),
            value: canonicalize_comparison_value(&comparison.op, &comparison.value),
        }),
        Expression::All { all } => canonicalize_logical_expression(all, LogicalKind::All),
        Expression::Any { any } => canonicalize_logical_expression(any, LogicalKind::Any),
        Expression::Not { expr } => {
            let normalized = canonicalize_expression(expr);
            match normalized {
                Expression::Not { expr } => *expr,
                other => Expression::Not {
                    expr: Box::new(other),
                },
            }
        }
    }
}

pub fn canonical_expression_key(expression: &Expression) -> String {
    canonical_expression_key_inner(&canonicalize_expression(expression))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogicalKind {
    All,
    Any,
}

fn canonicalize_logical_expression(items: &[Expression], kind: LogicalKind) -> Expression {
    let mut normalized = Vec::new();
    for item in items {
        match canonicalize_expression(item) {
            Expression::All { all } if kind == LogicalKind::All => normalized.extend(all),
            Expression::Any { any } if kind == LogicalKind::Any => normalized.extend(any),
            other => normalized.push(other),
        }
    }

    let mut keyed = normalized
        .into_iter()
        .map(|expr| (canonical_expression_key_inner(&expr), expr))
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);

    let mut normalized = keyed.into_iter().map(|(_, expr)| expr).collect::<Vec<_>>();
    match normalized.len() {
        0 => match kind {
            LogicalKind::All => Expression::All { all: Vec::new() },
            LogicalKind::Any => Expression::Any { any: Vec::new() },
        },
        1 => normalized
            .pop()
            .expect("single normalized expression should exist"),
        _ => match kind {
            LogicalKind::All => Expression::All { all: normalized },
            LogicalKind::Any => Expression::Any { any: normalized },
        },
    }
}

fn canonicalize_comparison_value(
    op: &ComparisonOperator,
    value: &ComparisonValue,
) -> ComparisonValue {
    match value {
        ComparisonValue::FeatureRef { feature_ref } => ComparisonValue::FeatureRef {
            feature_ref: feature_ref.clone(),
        },
        ComparisonValue::Literal(value) => {
            ComparisonValue::Literal(canonicalize_literal_value(op, value))
        }
    }
}

fn canonicalize_literal_value(op: &ComparisonOperator, value: &Value) -> Value {
    if matches!(op, ComparisonOperator::In | ComparisonOperator::NotIn) {
        if let Some(items) = value.as_array() {
            let mut keyed = items
                .iter()
                .map(|item| (canonical_json_value_key(item), item.clone()))
                .collect::<Vec<_>>();
            keyed.sort_by(|left, right| left.0.cmp(&right.0));
            keyed.dedup_by(|left, right| left.0 == right.0);
            return Value::Array(keyed.into_iter().map(|(_, item)| item).collect());
        }
    }
    value.clone()
}

fn canonical_expression_key_inner(expression: &Expression) -> String {
    match expression {
        Expression::Comparison(comparison) => {
            format!(
                "cmp({}|{}|{})",
                comparison.feature,
                comparison.op.as_str(),
                canonical_comparison_value_key(&comparison.op, &comparison.value)
            )
        }
        Expression::All { all } => format!(
            "all({})",
            all.iter()
                .map(canonical_expression_key_inner)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Expression::Any { any } => format!(
            "any({})",
            any.iter()
                .map(canonical_expression_key_inner)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Expression::Not { expr } => format!("not({})", canonical_expression_key_inner(expr)),
    }
}

fn canonical_comparison_value_key(op: &ComparisonOperator, value: &ComparisonValue) -> String {
    match canonicalize_comparison_value(op, value) {
        ComparisonValue::FeatureRef { feature_ref } => format!("@{feature_ref}"),
        ComparisonValue::Literal(value) => canonical_json_value_key(&value),
    }
}

fn canonical_json_value_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn simple_gate(
        expression: ComparisonExpression,
        rhs_feature_type: FeatureType,
    ) -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "test_gate".to_string(),
            gate_type: GateType::BitmaskGate,
            input_schema: InputSchema {
                features: vec![
                    FeatureDefinition {
                        id: "left".to_string(),
                        feature_type: FeatureType::Int,
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
                        id: "right".to_string(),
                        feature_type: rhs_feature_type,
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
                deny_when: Expression::Comparison(expression),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: None,
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
    fn validates_numeric_feature_reference_comparison() {
        let gate = simple_gate(
            ComparisonExpression {
                feature: "left".to_string(),
                op: ComparisonOperator::Lt,
                value: ComparisonValue::FeatureRef {
                    feature_ref: "right".to_string(),
                },
            },
            FeatureType::Int,
        );
        gate.validate()
            .expect("numeric feature references should validate");
    }

    #[test]
    fn rejects_incompatible_feature_reference_comparison() {
        let gate = simple_gate(
            ComparisonExpression {
                feature: "left".to_string(),
                op: ComparisonOperator::Lt,
                value: ComparisonValue::FeatureRef {
                    feature_ref: "right".to_string(),
                },
            },
            FeatureType::String,
        );
        let err = gate
            .validate()
            .expect_err("mixed numeric/string feature refs should fail");
        assert!(err.to_string().contains("compatible feature types"));
    }

    #[test]
    fn validates_derived_numeric_feature() {
        let gate = LogicPearlGateIr::from_json_str(
            &json!({
                "ir_version": "1.0",
                "gate_id": "derived",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [
                        {"id": "debt", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null},
                        {"id": "income", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null},
                        {"id": "debt_to_income", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null,
                         "derived": {"op": "ratio", "left_feature": "debt", "right_feature": "income"}}
                    ]
                },
                "rules": [
                    {"id": "rule_000", "kind": "predicate", "bit": 0,
                     "deny_when": {"feature": "debt_to_income", "op": ">=", "value": 0.5}}
                ],
                "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
                "verification": null,
                "provenance": null
            })
            .to_string(),
        )
        .expect("derived numeric features should validate");
        assert_eq!(gate.input_schema.features.len(), 3);
    }

    #[test]
    fn rejects_derived_feature_with_non_numeric_source() {
        let err = LogicPearlGateIr::from_json_str(
            &json!({
                "ir_version": "1.0",
                "gate_id": "derived_bad",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [
                        {"id": "path", "type": "string", "description": null, "values": null, "min": null, "max": null, "editable": null},
                        {"id": "score", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null},
                        {"id": "bad_ratio", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null,
                         "derived": {"op": "ratio", "left_feature": "score", "right_feature": "path"}}
                    ]
                },
                "rules": [
                    {"id": "rule_000", "kind": "predicate", "bit": 0,
                     "deny_when": {"feature": "bad_ratio", "op": ">=", "value": 0.5}}
                ],
                "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
                "verification": null,
                "provenance": null
            })
            .to_string(),
        )
        .expect_err("non-numeric derived feature source should fail");
        assert!(err.to_string().contains("requires numeric inputs"));
    }

    #[test]
    fn parses_literal_comparison_shape() {
        let gate = LogicPearlGateIr::from_json_str(
            &json!({
                "ir_version": "1.0",
                "gate_id": "literal_value",
                "gate_type": "bitmask_gate",
                "input_schema": {
                    "features": [
                        {"id": "flag", "type": "int", "description": null, "values": null, "min": null, "max": null, "editable": null}
                    ]
                },
                "rules": [
                    {"id": "rule_000", "kind": "predicate", "bit": 0, "deny_when": {"feature": "flag", "op": "==", "value": 1}}
                ],
                "evaluation": {"combine": "bitwise_or", "allow_when_bitmask": 0},
                "verification": null,
                "provenance": null
            })
            .to_string(),
        )
        .expect("literal comparison shape should parse");
        let Expression::Comparison(comparison) = &gate.rules[0].deny_when else {
            panic!("expected comparison expression");
        };
        assert_eq!(comparison.value, ComparisonValue::Literal(json!(1)));
    }

    #[test]
    fn serializes_solver_verified_status_with_backend_neutral_name() {
        let encoded = serde_json::to_string(&RuleVerificationStatus::SolverVerified)
            .expect("verification status should serialize");
        assert_eq!(encoded, "\"solver_verified\"");

        let decoded: RuleVerificationStatus =
            serde_json::from_str(&encoded).expect("verification status should deserialize");
        assert_eq!(decoded, RuleVerificationStatus::SolverVerified);
    }

    #[test]
    fn feature_semantics_round_trips_and_validates() {
        let mut gate = simple_gate(
            ComparisonExpression {
                feature: "left".to_string(),
                op: ComparisonOperator::Lte,
                value: ComparisonValue::Literal(json!(0.0)),
            },
            FeatureType::Int,
        );
        gate.input_schema.features[0].semantics = Some(
            serde_json::from_value(json!({
                "label": "Failed conservative therapy",
                "kind": "evidence",
                "source_id": "req-003",
                "source_anchor": "page-1",
                "states": {
                    "missing": {
                        "when": {"op": "<=", "value": 0.0},
                        "label": "Failed conservative therapy is missing",
                        "message": "This rule fires when the packet does not support failed conservative therapy.",
                        "counterfactual_hint": "Add evidence showing failed conservative therapy."
                    }
                }
            }))
            .unwrap(),
        );

        gate.validate().expect("feature semantics should validate");
        let serialized = serde_json::to_string(&gate).unwrap();
        let parsed = LogicPearlGateIr::from_json_str(&serialized).unwrap();
        let semantics = parsed.input_schema.features[0]
            .semantics
            .as_ref()
            .expect("semantics should survive serialization");
        assert_eq!(
            semantics.label.as_deref(),
            Some("Failed conservative therapy")
        );
        assert!(semantics.states.contains_key("missing"));
    }

    #[test]
    fn old_artifact_without_feature_semantics_still_deserializes() {
        let payload = json!({
            "ir_version": "1.0",
            "gate_id": "old_gate",
            "gate_type": "bitmask_gate",
            "input_schema": {
                "features": [{
                    "id": "age",
                    "type": "int",
                    "description": null,
                    "values": null,
                    "min": null,
                    "max": null,
                    "editable": null
                }]
            },
            "rules": [{
                "id": "rule_000",
                "kind": "predicate",
                "bit": 0,
                "deny_when": {"feature": "age", "op": "<", "value": 18},
                "label": null,
                "message": null,
                "severity": null,
                "counterfactual_hint": null,
                "verification_status": null
            }],
            "evaluation": {
                "combine": "bitwise_or",
                "allow_when_bitmask": 0
            },
            "verification": null,
            "provenance": null
        });

        let parsed = LogicPearlGateIr::from_json_str(&payload.to_string()).unwrap();
        assert!(parsed.input_schema.features[0].semantics.is_none());
    }

    #[test]
    fn canonicalize_expression_flattens_sorts_and_dedupes_boolean_groups() {
        let normalized = canonicalize_expression(&Expression::All {
            all: vec![
                Expression::Comparison(ComparisonExpression {
                    feature: "z".to_string(),
                    op: ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(json!(1)),
                }),
                Expression::All {
                    all: vec![
                        Expression::Comparison(ComparisonExpression {
                            feature: "a".to_string(),
                            op: ComparisonOperator::Eq,
                            value: ComparisonValue::Literal(json!(2)),
                        }),
                        Expression::Comparison(ComparisonExpression {
                            feature: "z".to_string(),
                            op: ComparisonOperator::Eq,
                            value: ComparisonValue::Literal(json!(1)),
                        }),
                    ],
                },
            ],
        });

        let Expression::All { all } = normalized else {
            panic!("expected normalized all expression");
        };
        assert_eq!(all.len(), 2);
        let features = all
            .iter()
            .map(|expr| match expr {
                Expression::Comparison(comparison) => comparison.feature.as_str(),
                _ => panic!("expected comparisons after normalization"),
            })
            .collect::<Vec<_>>();
        assert_eq!(features, vec!["a", "z"]);
    }

    #[test]
    fn canonicalize_expression_eliminates_double_negation_and_normalizes_membership_literals() {
        let normalized = canonicalize_expression(&Expression::Not {
            expr: Box::new(Expression::Not {
                expr: Box::new(Expression::Comparison(ComparisonExpression {
                    feature: "role".to_string(),
                    op: ComparisonOperator::In,
                    value: ComparisonValue::Literal(json!(["viewer", "admin", "viewer"])),
                })),
            }),
        });

        let Expression::Comparison(comparison) = normalized else {
            panic!("expected double negation to collapse");
        };
        assert_eq!(comparison.feature, "role");
        assert_eq!(
            comparison.value,
            ComparisonValue::Literal(json!(["admin", "viewer"]))
        );
    }

    #[test]
    fn validates_action_policy_ir() {
        let policy = LogicPearlActionIr::from_json_str(
            &json!({
                "ir_version": "1.0",
                "action_policy_id": "garden_actions",
                "action_policy_type": "priority_rules",
                "action_column": "next_action",
                "default_action": "do_nothing",
                "actions": ["do_nothing", "water"],
                "input_schema": {
                    "features": [
                        {"id": "soil_moisture_pct", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null}
                    ]
                },
                "rules": [
                    {
                        "id": "rule_000",
                        "bit": 0,
                        "action": "water",
                        "priority": 0,
                        "when": {"feature": "soil_moisture_pct", "op": "<=", "value": 0.18},
                        "label": "Water dry plants",
                        "message": null,
                        "severity": null,
                        "counterfactual_hint": null,
                        "verification_status": null
                    }
                ],
                "evaluation": {"selection": "first_match"},
                "verification": null,
                "provenance": null
            })
            .to_string(),
        )
        .expect("action policy should validate");

        assert_eq!(policy.default_action, "do_nothing");
        assert_eq!(policy.rules[0].action, "water");
    }

    #[test]
    fn rejects_action_policy_rule_for_unknown_action() {
        let err = LogicPearlActionIr::from_json_str(
            &json!({
                "ir_version": "1.0",
                "action_policy_id": "garden_actions",
                "action_policy_type": "priority_rules",
                "action_column": "next_action",
                "default_action": "do_nothing",
                "actions": ["do_nothing", "water"],
                "input_schema": {
                    "features": [
                        {"id": "soil_moisture_pct", "type": "float", "description": null, "values": null, "min": null, "max": null, "editable": null}
                    ]
                },
                "rules": [
                    {
                        "id": "rule_000",
                        "bit": 0,
                        "action": "repot",
                        "priority": 0,
                        "when": {"feature": "soil_moisture_pct", "op": "<=", "value": 0.18},
                        "label": null,
                        "message": null,
                        "severity": null,
                        "counterfactual_hint": null,
                        "verification_status": null
                    }
                ],
                "evaluation": {"selection": "first_match"},
                "verification": null,
                "provenance": null
            })
            .to_string(),
        )
        .expect_err("unknown action should fail");

        assert!(err.to_string().contains("unknown action"));
    }

    /// Helper: build a minimal valid gate with one feature and one rule.
    fn minimal_valid_gate() -> LogicPearlGateIr {
        LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "test_gate".to_string(),
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
    fn valid_minimal_gate_passes_validation() {
        let gate = minimal_valid_gate();
        gate.validate()
            .expect("minimal valid gate should pass validation");
    }

    #[test]
    fn rejects_empty_gate_id() {
        let mut gate = minimal_valid_gate();
        gate.gate_id = String::new();
        let err = gate.validate().expect_err("empty gate_id should fail");
        assert!(err.to_string().contains("gate id"));
    }

    #[test]
    fn rejects_empty_rules() {
        let mut gate = minimal_valid_gate();
        gate.rules.clear();
        let err = gate.validate().expect_err("empty rules should fail");
        assert!(err.to_string().contains("at least one rule"));
    }

    #[test]
    fn rejects_empty_features() {
        let mut gate = minimal_valid_gate();
        gate.input_schema.features.clear();
        let err = gate.validate().expect_err("empty features should fail");
        assert!(err.to_string().contains("at least one feature"));
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let mut gate = minimal_valid_gate();
        let mut second_rule = gate.rules[0].clone();
        second_rule.bit = 1; // different bit, same id
        gate.rules.push(second_rule);
        let err = gate.validate().expect_err("duplicate rule ids should fail");
        assert!(err.to_string().contains("duplicate rule ids"));
    }

    #[test]
    fn rejects_duplicate_rule_bits() {
        let mut gate = minimal_valid_gate();
        let mut second_rule = gate.rules[0].clone();
        second_rule.id = "rule_2".to_string(); // different id, same bit
        gate.rules.push(second_rule);
        let err = gate
            .validate()
            .expect_err("duplicate rule bits should fail");
        assert!(err.to_string().contains("duplicate rule bits"));
    }

    #[test]
    fn roundtrip_gate_serialization() {
        let gate = minimal_valid_gate();
        let json_str = serde_json::to_string(&gate).expect("gate should serialize");
        let deserialized: LogicPearlGateIr =
            serde_json::from_str(&json_str).expect("gate should deserialize");
        assert_eq!(gate, deserialized);
        assert_eq!(deserialized.gate_id, "test_gate");
        assert_eq!(deserialized.gate_type, GateType::BitmaskGate);
        assert_eq!(deserialized.evaluation.combine, CombineStrategy::BitwiseOr);
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.rules[0].id, "rule_1");
    }
}
