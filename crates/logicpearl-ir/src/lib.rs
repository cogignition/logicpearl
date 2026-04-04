use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogicPearlGateIr {
    pub ir_version: String,
    pub gate_id: String,
    pub gate_type: String,
    pub input_schema: InputSchema,
    pub rules: Vec<RuleDefinition>,
    pub evaluation: EvaluationConfig,
    pub verification: Option<VerificationConfig>,
    pub provenance: Option<Provenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputSchema {
    pub features: Vec<FeatureDefinition>,
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeatureType {
    Bool,
    Int,
    Float,
    String,
    Enum,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Predicate,
    Threshold,
    WeightedSum,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerificationStatus {
    Z3Verified,
    PipelineUnverified,
    HeuristicUnverified,
    RefinedUnverified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationConfig {
    pub combine: String,
    pub allow_when_bitmask: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationConfig {
    pub domain_constraints: Option<Vec<ComparisonExpression>>,
    pub correctness_scope: Option<String>,
    pub verification_summary: Option<HashMap<String, u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    pub generator: Option<String>,
    pub generator_version: Option<String>,
    pub source_commit: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Expression {
    Comparison(ComparisonExpression),
    All { all: Vec<Expression> },
    Any { any: Vec<Expression> },
    Not {
        #[serde(rename = "not")]
        expr: Box<Expression>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparisonExpression {
    pub feature: String,
    pub op: ComparisonOperator,
    pub value: Value,
}

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
        if self.gate_type != "bitmask_gate" {
            return Err(LogicPearlError::message(format!(
                "unsupported gate_type: {}",
                self.gate_type
            )));
        }
        if self.evaluation.combine != "bitwise_or" {
            return Err(LogicPearlError::message(format!(
                "unsupported evaluation.combine: {}",
                self.evaluation.combine
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
            return Err(LogicPearlError::message("gate must define at least one rule"));
        }

        let mut feature_ids = BTreeSet::new();
        let mut known_features = HashMap::new();
        for feature in &self.input_schema.features {
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
            known_features.insert(feature.id.clone(), feature);
        }

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

        if let Some(verification) = &self.verification {
            if let Some(constraints) = &verification.domain_constraints {
                for constraint in constraints {
                    let feature = known_features.get(&constraint.feature).ok_or_else(|| {
                        LogicPearlError::message(format!(
                            "unknown features referenced: {}",
                            constraint.feature
                        ))
                    })?;
                    validate_comparison(constraint, feature)?;
                }
            }
        }

        Ok(())
    }
}

impl FeatureDefinition {
    fn validate(&self) -> Result<()> {
        match self.feature_type {
            FeatureType::Enum => {
                if self.values.as_ref().is_none_or(|values| values.is_empty()) {
                    return Err(LogicPearlError::message(
                        "enum features must define values",
                    ));
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
        Ok(())
    }
}

fn validate_expression(
    expression: &Expression,
    known_features: &HashMap<String, &FeatureDefinition>,
) -> Result<()> {
    match expression {
        Expression::Comparison(comparison) => {
            let feature = known_features.get(&comparison.feature).ok_or_else(|| {
                LogicPearlError::message(format!("unknown features referenced: {}", comparison.feature))
            })?;
            validate_comparison(comparison, feature)
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

fn validate_comparison(expression: &ComparisonExpression, feature: &FeatureDefinition) -> Result<()> {
    match feature.feature_type {
        FeatureType::Bool => {
            ensure_op(&expression.op, &[ComparisonOperator::Eq, ComparisonOperator::Ne], "bool")?;
            if !expression.value.is_boolean() {
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
                    let items = expression.value.as_array().ok_or_else(|| {
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
                    if !allowed.contains(&expression.value) {
                        return Err(LogicPearlError::message(format!(
                            "unsupported enum value {} for feature {}",
                            expression.value, feature.id
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

fn ensure_op(actual: &ComparisonOperator, allowed: &[ComparisonOperator], kind: &str) -> Result<()> {
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
