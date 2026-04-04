use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct InputSchema {
    pub features: Vec<FeatureDefinition>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeatureType {
    Bool,
    Int,
    Float,
    String,
    Enum,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Predicate,
    Threshold,
    WeightedSum,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerificationStatus {
    Z3Verified,
    PipelineUnverified,
    HeuristicUnverified,
    RefinedUnverified,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct EvaluationConfig {
    pub combine: String,
    pub allow_when_bitmask: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct VerificationConfig {
    pub domain_constraints: Option<Vec<ComparisonExpression>>,
    pub correctness_scope: Option<String>,
    pub verification_summary: Option<HashMap<String, u64>>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Provenance {
    pub generator: Option<String>,
    pub generator_version: Option<String>,
    pub source_commit: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ComparisonExpression {
    pub feature: String,
    pub op: ComparisonOperator,
    pub value: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    pub fn from_json_str(input: &str) -> Result<Self, IrError> {
        let gate: Self = serde_json::from_str(input)?;
        gate.validate()?;
        Ok(gate)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, IrError> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    pub fn validate(&self) -> Result<(), IrError> {
        if self.ir_version != "1.0" {
            return Err(IrError::validation(format!(
                "unsupported ir_version: {}",
                self.ir_version
            )));
        }
        if self.gate_type != "bitmask_gate" {
            return Err(IrError::validation(format!(
                "unsupported gate_type: {}",
                self.gate_type
            )));
        }
        if self.evaluation.combine != "bitwise_or" {
            return Err(IrError::validation(format!(
                "unsupported evaluation.combine: {}",
                self.evaluation.combine
            )));
        }
        if self.evaluation.allow_when_bitmask != 0 {
            return Err(IrError::validation(
                "evaluation.allow_when_bitmask must be 0".to_string(),
            ));
        }
        if self.gate_id.is_empty() {
            return Err(IrError::validation("gate id must be non-empty".to_string()));
        }
        if self.input_schema.features.is_empty() {
            return Err(IrError::validation(
                "input schema must define at least one feature".to_string(),
            ));
        }
        if self.rules.is_empty() {
            return Err(IrError::validation(
                "gate must define at least one rule".to_string(),
            ));
        }

        let mut feature_ids = BTreeSet::new();
        let mut known_features = HashMap::new();
        for feature in &self.input_schema.features {
            if feature.id.is_empty() {
                return Err(IrError::validation("feature id must be non-empty".to_string()));
            }
            if !feature_ids.insert(feature.id.clone()) {
                return Err(IrError::validation(format!(
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
                return Err(IrError::validation("rule id must be non-empty".to_string()));
            }
            if !rule_ids.insert(rule.id.clone()) {
                return Err(IrError::validation(format!(
                    "duplicate rule ids: {}",
                    rule.id
                )));
            }
            if !rule_bits.insert(rule.bit) {
                return Err(IrError::validation(format!(
                    "duplicate rule bits: {}",
                    rule.bit
                )));
            }
            validate_expression(&rule.deny_when, &known_features, &format!("rule {}", rule.id))?;
        }

        if let Some(verification) = &self.verification {
            if let Some(constraints) = &verification.domain_constraints {
                for constraint in constraints {
                    let feature = known_features.get(&constraint.feature).ok_or_else(|| {
                        IrError::validation(format!(
                            "unknown features referenced: {}",
                            constraint.feature
                        ))
                    })?;
                    validate_comparison(constraint, feature, "verification.domain_constraints")?;
                }
            }
        }

        Ok(())
    }

    pub fn evaluate(&self, features: &HashMap<String, Value>) -> Result<u64, IrError> {
        let mut bitmask = 0_u64;
        for rule in &self.rules {
            if evaluate_expression(&rule.deny_when, features)? {
                bitmask |= 1_u64 << rule.bit;
            }
        }
        Ok(bitmask)
    }
}

impl FeatureDefinition {
    fn validate(&self) -> Result<(), IrError> {
        match self.feature_type {
            FeatureType::Enum => {
                if self.values.as_ref().is_none_or(|values| values.is_empty()) {
                    return Err(IrError::validation(
                        "enum features must define values".to_string(),
                    ));
                }
            }
            _ => {
                if self.values.is_some() {
                    return Err(IrError::validation(
                        "only enum features may define values".to_string(),
                    ));
                }
            }
        }
        if let (Some(min), Some(max)) = (self.min, self.max) {
            if min > max {
                return Err(IrError::validation("feature min cannot exceed max".to_string()));
            }
        }
        Ok(())
    }
}

fn validate_expression(
    expression: &Expression,
    known_features: &HashMap<String, &FeatureDefinition>,
    context: &str,
) -> Result<(), IrError> {
    match expression {
        Expression::Comparison(comparison) => {
            let feature = known_features.get(&comparison.feature).ok_or_else(|| {
                IrError::validation(format!("unknown features referenced: {}", comparison.feature))
            })?;
            validate_comparison(comparison, feature, context)
        }
        Expression::All { all } => {
            if all.is_empty() {
                return Err(IrError::validation(
                    "all expressions must contain at least one child".to_string(),
                ));
            }
            for child in all {
                validate_expression(child, known_features, context)?;
            }
            Ok(())
        }
        Expression::Any { any } => {
            if any.is_empty() {
                return Err(IrError::validation(
                    "any expressions must contain at least one child".to_string(),
                ));
            }
            for child in any {
                validate_expression(child, known_features, context)?;
            }
            Ok(())
        }
        Expression::Not { expr } => validate_expression(expr, known_features, context),
    }
}

fn evaluate_expression(
    expression: &Expression,
    features: &HashMap<String, Value>,
) -> Result<bool, IrError> {
    match expression {
        Expression::Comparison(comparison) => evaluate_comparison_runtime(comparison, features),
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

fn evaluate_comparison_runtime(
    expression: &ComparisonExpression,
    features: &HashMap<String, Value>,
) -> Result<bool, IrError> {
    let left = features.get(&expression.feature).ok_or_else(|| {
        IrError::validation(format!("missing runtime feature: {}", expression.feature))
    })?;
    let right = &expression.value;

    match expression.op {
        ComparisonOperator::Eq => Ok(left == right),
        ComparisonOperator::Ne => Ok(left != right),
        ComparisonOperator::Gt => compare_numbers(left, right, |l, r| l > r),
        ComparisonOperator::Gte => compare_numbers(left, right, |l, r| l >= r),
        ComparisonOperator::Lt => compare_numbers(left, right, |l, r| l < r),
        ComparisonOperator::Lte => compare_numbers(left, right, |l, r| l <= r),
        ComparisonOperator::In => value_in(left, right),
        ComparisonOperator::NotIn => Ok(!value_in(left, right)?),
    }
}

fn compare_numbers(
    left: &Value,
    right: &Value,
    predicate: impl Fn(f64, f64) -> bool,
) -> Result<bool, IrError> {
    let left = left
        .as_f64()
        .ok_or_else(|| IrError::validation("runtime numeric comparison requires number".to_string()))?;
    let right = right
        .as_f64()
        .ok_or_else(|| IrError::validation("runtime numeric comparison requires number".to_string()))?;
    Ok(predicate(left, right))
}

fn value_in(left: &Value, right: &Value) -> Result<bool, IrError> {
    let items = right
        .as_array()
        .ok_or_else(|| IrError::validation("runtime membership comparison requires array".to_string()))?;
    Ok(items.iter().any(|item| item == left))
}

fn validate_comparison(
    expression: &ComparisonExpression,
    feature: &FeatureDefinition,
    context: &str,
) -> Result<(), IrError> {
    match feature.feature_type {
        FeatureType::Bool => {
            ensure_op(
                &expression.op,
                &[ComparisonOperator::Eq, ComparisonOperator::Ne],
                context,
                "bool",
            )?;
            if !expression.value.is_boolean() {
                return Err(IrError::validation(format!(
                    "{context} requires bool value for feature {}",
                    feature.id
                )));
            }
        }
        FeatureType::Enum => validate_enum_comparison(expression, feature, context)?,
        FeatureType::String => {
            ensure_op(
                &expression.op,
                &[
                    ComparisonOperator::Eq,
                    ComparisonOperator::Ne,
                    ComparisonOperator::In,
                    ComparisonOperator::NotIn,
                ],
                context,
                "string",
            )?;
            validate_string_value(&expression.value, &expression.op, &feature.id, context)?;
        }
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
                context,
                "numeric",
            )?;
            validate_numeric_value(&expression.value, &expression.op, &feature.id, context)?;
        }
    }
    Ok(())
}

fn validate_enum_comparison(
    expression: &ComparisonExpression,
    feature: &FeatureDefinition,
    context: &str,
) -> Result<(), IrError> {
    let allowed = feature.values.as_ref().expect("enum values validated");
    match expression.op {
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let items = expression.value.as_array().ok_or_else(|| {
                IrError::validation(format!(
                    "{context} requires array value for enum feature {}",
                    feature.id
                ))
            })?;
            for item in items {
                if !allowed.contains(item) {
                    return Err(IrError::validation(format!(
                        "{context} references enum feature {} with unsupported value {}",
                        feature.id, item
                    )));
                }
            }
        }
        _ => {
            if !allowed.contains(&expression.value) {
                return Err(IrError::validation(format!(
                    "{context} references enum feature {} with unsupported value {}",
                    feature.id, expression.value
                )));
            }
        }
    }
    Ok(())
}

fn validate_string_value(
    value: &Value,
    op: &ComparisonOperator,
    feature_id: &str,
    context: &str,
) -> Result<(), IrError> {
    match op {
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let items = value.as_array().ok_or_else(|| {
                IrError::validation(format!(
                    "{context} requires string array values for feature {feature_id}"
                ))
            })?;
            if !items.iter().all(Value::is_string) {
                return Err(IrError::validation(format!(
                    "{context} requires string array values for feature {feature_id}"
                )));
            }
        }
        _ => {
            if !value.is_string() {
                return Err(IrError::validation(format!(
                    "{context} requires string value for feature {feature_id}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_numeric_value(
    value: &Value,
    op: &ComparisonOperator,
    feature_id: &str,
    context: &str,
) -> Result<(), IrError> {
    match op {
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let items = value.as_array().ok_or_else(|| {
                IrError::validation(format!(
                    "{context} requires numeric array values for feature {feature_id}"
                ))
            })?;
            if !items.iter().all(Value::is_number) {
                return Err(IrError::validation(format!(
                    "{context} requires numeric array values for feature {feature_id}"
                )));
            }
        }
        _ => {
            if !value.is_number() {
                return Err(IrError::validation(format!(
                    "{context} requires numeric value for feature {feature_id}"
                )));
            }
        }
    }
    Ok(())
}

fn ensure_op(
    actual: &ComparisonOperator,
    allowed: &[ComparisonOperator],
    context: &str,
    feature_kind: &str,
) -> Result<(), IrError> {
    if allowed.contains(actual) {
        return Ok(());
    }
    Err(IrError::validation(format!(
        "{context} uses unsupported operator {} for {feature_kind} feature",
        actual.as_str()
    )))
}

impl ComparisonOperator {
    fn as_str(&self) -> &'static str {
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

#[derive(Debug)]
pub enum IrError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Validation(String),
}

impl IrError {
    fn validation(message: String) -> Self {
        Self::Validation(message)
    }
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Validation(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for IrError {}

impl From<std::io::Error> for IrError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for IrError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[cfg(test)]
mod tests {
    use super::LogicPearlGateIr;
    use serde::Deserialize;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures")
            .join(relative)
    }

    #[derive(Debug, Deserialize)]
    struct EvalFixture {
        gate_fixture: String,
        cases: Vec<EvalCase>,
    }

    #[derive(Debug, Deserialize)]
    struct EvalCase {
        id: String,
        input: HashMap<String, Value>,
        expected_bitmask: u64,
    }

    #[test]
    fn loads_valid_fixture() {
        let gate = LogicPearlGateIr::from_path(fixture_path("ir/valid/auth-demo-v1.json")).unwrap();
        assert_eq!(gate.gate_id, "auth_demo_v1");
        assert_eq!(gate.rules.len(), 3);
        assert_eq!(gate.rules.iter().map(|rule| rule.bit).collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn rejects_duplicate_rule_bits() {
        let err = LogicPearlGateIr::from_path(fixture_path("ir/invalid/duplicate-bit.json")).unwrap_err();
        assert!(err.to_string().contains("duplicate rule bits"));
    }

    #[test]
    fn evaluates_shared_parity_cases() {
        let eval_fixture_path = fixture_path("ir/eval/auth-demo-v1-cases.json");
        let payload = fs::read_to_string(eval_fixture_path).unwrap();
        let eval_fixture: EvalFixture = serde_json::from_str(&payload).unwrap();
        let gate = LogicPearlGateIr::from_path(fixture_path(&eval_fixture.gate_fixture)).unwrap();

        for case in eval_fixture.cases {
            let bitmask = gate.evaluate(&case.input).unwrap();
            assert_eq!(bitmask, case.expected_bitmask, "{}", case.id);
        }
    }
}
