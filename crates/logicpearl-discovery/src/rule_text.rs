use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, ComparisonValue, Expression, FeatureSemantics,
    FeatureStateSemantics,
};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(super) struct GeneratedRuleText {
    pub label: Option<String>,
    pub message: Option<String>,
    pub counterfactual_hint: Option<String>,
}

pub(super) struct RuleTextContext<'a> {
    feature_semantics: Option<&'a BTreeMap<String, FeatureSemantics>>,
}

impl<'a> RuleTextContext<'a> {
    pub(super) fn empty() -> Self {
        Self {
            feature_semantics: None,
        }
    }

    pub(super) fn with_feature_semantics(
        feature_semantics: &'a BTreeMap<String, FeatureSemantics>,
    ) -> Self {
        Self {
            feature_semantics: Some(feature_semantics),
        }
    }

    fn feature_semantics(&self, feature: &str) -> Option<&'a FeatureSemantics> {
        self.feature_semantics
            .and_then(|semantics| semantics.get(feature))
    }
}

pub(super) fn generate_rule_text(
    expression: &Expression,
    context: &RuleTextContext<'_>,
) -> GeneratedRuleText {
    let label = Some(expression_label(expression, context));
    let message = match expression {
        Expression::Comparison(comparison) => comparison_state_match(comparison, context)
            .and_then(|(_, state)| state.message.clone())
            .or_else(|| label.as_ref().map(|label| format!("{label}."))),
        _ => label.as_ref().map(|label| format!("{label}.")),
    };
    let counterfactual_hint = Some(expression_counterfactual_hint(expression, context));
    GeneratedRuleText {
        label,
        message,
        counterfactual_hint,
    }
}

fn expression_label(expression: &Expression, context: &RuleTextContext<'_>) -> String {
    match expression {
        Expression::Comparison(comparison) => comparison_label(comparison, context),
        Expression::All { all } => join_child_labels(all, " and ", context),
        Expression::Any { any } => join_child_labels(any, " or ", context),
        Expression::Not { expr } => format!("Not ({})", expression_label(expr, context)),
    }
}

fn expression_counterfactual_hint(
    expression: &Expression,
    context: &RuleTextContext<'_>,
) -> String {
    match expression {
        Expression::Comparison(comparison) => comparison_counterfactual_hint(comparison, context),
        Expression::All { all } => format!(
            "Break at least one condition: {}",
            all.iter()
                .map(|expression| expression_counterfactual_hint(expression, context))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Expression::Any { any } => format!(
            "Resolve all of: {}",
            any.iter()
                .map(|expression| expression_counterfactual_hint(expression, context))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Expression::Not { expr } => {
            format!(
                "Reverse this negated condition: {}",
                expression_label(expr, context)
            )
        }
    }
}

fn join_child_labels(
    children: &[Expression],
    joiner: &str,
    context: &RuleTextContext<'_>,
) -> String {
    children
        .iter()
        .map(|expression| expression_label(expression, context))
        .collect::<Vec<_>>()
        .join(joiner)
}

fn comparison_label(comparison: &ComparisonExpression, context: &RuleTextContext<'_>) -> String {
    if let Some((semantics, state)) = comparison_state_match(comparison, context) {
        if let Some(label) = state.label.as_ref() {
            return label.clone();
        }
        if let Some(label) = semantics.label.as_ref() {
            return comparison_label_with_feature(comparison, label, Some(semantics));
        }
    }
    let semantics = context.feature_semantics(&comparison.feature);
    let feature = semantics
        .and_then(|semantics| semantics.label.clone())
        .unwrap_or_else(|| humanize_feature_name(&comparison.feature));
    comparison_label_with_feature(comparison, &feature, semantics)
}

fn comparison_label_with_feature(
    comparison: &ComparisonExpression,
    feature: &str,
    semantics: Option<&FeatureSemantics>,
) -> String {
    match (&comparison.op, &comparison.value) {
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(true))) => {
            positive_boolean_label(&comparison.feature, feature)
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(false))) => {
            format!("{feature} Is False")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(true))) => {
            format!("{feature} Is False")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(false))) => {
            positive_boolean_label(&comparison.feature, feature)
        }
        (ComparisonOperator::Eq, ComparisonValue::FeatureRef { feature_ref }) => {
            format!("{feature} equals {}", humanize_feature_name(feature_ref))
        }
        (ComparisonOperator::Ne, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "{feature} differs from {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Lt, ComparisonValue::FeatureRef { feature_ref }) => {
            format!("{feature} below {}", humanize_feature_name(feature_ref))
        }
        (ComparisonOperator::Lte, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "{feature} at or below {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Gt, ComparisonValue::FeatureRef { feature_ref }) => {
            format!("{feature} above {}", humanize_feature_name(feature_ref))
        }
        (ComparisonOperator::Gte, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "{feature} at or above {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} equals {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} differs from {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Lt, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} below {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Lte, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} at or below {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Gt, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} above {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Gte, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} at or above {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::In, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} is in {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::NotIn, ComparisonValue::Literal(value)) => {
            format!(
                "{feature} is outside {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::In, ComparisonValue::FeatureRef { feature_ref }) => {
            format!("{feature} is in {}", humanize_feature_name(feature_ref))
        }
        (ComparisonOperator::NotIn, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "{feature} is outside {}",
                humanize_feature_name(feature_ref)
            )
        }
    }
}

fn comparison_counterfactual_hint(
    comparison: &ComparisonExpression,
    context: &RuleTextContext<'_>,
) -> String {
    if let Some((_, state)) = comparison_state_match(comparison, context) {
        if let Some(hint) = state.counterfactual_hint.as_ref() {
            return hint.clone();
        }
    }
    let semantics = context.feature_semantics(&comparison.feature);
    let feature = semantics
        .and_then(|semantics| semantics.label.clone())
        .unwrap_or_else(|| humanize_feature_name(&comparison.feature));
    comparison_counterfactual_hint_with_feature(comparison, &feature, semantics)
}

fn comparison_counterfactual_hint_with_feature(
    comparison: &ComparisonExpression,
    feature: &str,
    semantics: Option<&FeatureSemantics>,
) -> String {
    match (&comparison.op, &comparison.value) {
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(true))) => {
            positive_boolean_counterfactual(&comparison.feature, feature)
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(false))) => {
            format!("Keep {feature} true")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(true))) => {
            format!("Keep {feature} false")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(false))) => {
            positive_boolean_counterfactual(&comparison.feature, feature)
        }
        (ComparisonOperator::Lt, ComparisonValue::Literal(value)) => {
            format!(
                "Keep {feature} at or above {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Lte, ComparisonValue::Literal(value)) => {
            format!(
                "Keep {feature} above {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Gt, ComparisonValue::Literal(value)) => {
            format!(
                "Keep {feature} at or below {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Gte, ComparisonValue::Literal(value)) => {
            format!(
                "Keep {feature} below {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(value)) => {
            format!(
                "Change {feature} away from {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(value)) => {
            format!(
                "Set {feature} to {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::Lt, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Keep {feature} at or above {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Lte, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Keep {feature} above {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Gt, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Keep {feature} at or below {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Gte, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Keep {feature} below {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Eq, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Change {feature} away from {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::Ne, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Set {feature} equal to {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::In, ComparisonValue::Literal(value)) => {
            format!(
                "Keep {feature} outside {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::NotIn, ComparisonValue::Literal(value)) => {
            format!(
                "Set {feature} inside {}",
                render_value_for_feature(value, semantics)
            )
        }
        (ComparisonOperator::In, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Keep {feature} outside {}",
                humanize_feature_name(feature_ref)
            )
        }
        (ComparisonOperator::NotIn, ComparisonValue::FeatureRef { feature_ref }) => {
            format!(
                "Set {feature} inside {}",
                humanize_feature_name(feature_ref)
            )
        }
    }
}

fn comparison_state_match<'a>(
    comparison: &ComparisonExpression,
    context: &'a RuleTextContext<'a>,
) -> Option<(&'a FeatureSemantics, &'a FeatureStateSemantics)> {
    let semantics = context.feature_semantics(&comparison.feature)?;
    semantics
        .states
        .values()
        .find(|state| {
            state.predicate.op == comparison.op
                && comparison_values_match(&state.predicate.value, &comparison.value)
        })
        .map(|state| (semantics, state))
}

fn comparison_values_match(left: &ComparisonValue, right: &ComparisonValue) -> bool {
    match (left, right) {
        (
            ComparisonValue::FeatureRef { feature_ref: left },
            ComparisonValue::FeatureRef { feature_ref: right },
        ) => left == right,
        (ComparisonValue::Literal(left), ComparisonValue::Literal(right)) => {
            literal_values_match(left, right)
        }
        _ => false,
    }
}

fn literal_values_match(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => (left - right).abs() < f64::EPSILON,
        _ => left == right,
    }
}

fn positive_boolean_label(feature_id: &str, feature: &str) -> String {
    if let Some(rest) = feature_id.strip_prefix("contains_") {
        format!("{} Detected", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("has_") {
        format!("{} Present", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("targets_") {
        format!("Targets {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("path_targets_") {
        format!("Path Targets {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("request_has_") {
        format!("Request Has {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("meta_reports_") {
        format!("Meta Reports {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("origin_outside_") {
        format!("Origin Outside {}", humanize_feature_name(rest))
    } else {
        format!("{feature} Is True")
    }
}

fn positive_boolean_counterfactual(feature_id: &str, feature: &str) -> String {
    if let Some(rest) = feature_id.strip_prefix("contains_") {
        format!("Remove {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("has_") {
        format!("Remove {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("targets_") {
        format!("Avoid {}", humanize_feature_name(rest))
    } else if let Some(rest) = feature_id.strip_prefix("path_targets_") {
        format!(
            "Avoid paths targeting {}",
            humanize_feature_name(rest).to_lowercase()
        )
    } else if let Some(rest) = feature_id.strip_prefix("request_has_") {
        format!("Remove {}", humanize_feature_name(rest).to_lowercase())
    } else if let Some(rest) = feature_id.strip_prefix("meta_reports_") {
        format!(
            "Avoid behavior that triggers {}",
            humanize_feature_name(rest).to_lowercase()
        )
    } else if let Some(rest) = feature_id.strip_prefix("origin_outside_") {
        format!(
            "Keep origin inside {}",
            humanize_feature_name(rest).to_lowercase()
        )
    } else {
        format!("Keep {feature} false")
    }
}

fn humanize_feature_name(feature_id: &str) -> String {
    feature_id
        .replace('.', " ")
        .split('_')
        .filter(|token| !token.is_empty())
        .map(humanize_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn humanize_token(token: &str) -> String {
    match token {
        "xss" => "XSS".to_string(),
        "sqli" => "SQLi".to_string(),
        "sql" => "SQL".to_string(),
        "php" => "PHP".to_string(),
        "mfa" => "MFA".to_string(),
        "id" => "ID".to_string(),
        "ip" => "IP".to_string(),
        "url" => "URL".to_string(),
        "api" => "API".to_string(),
        "http" => "HTTP".to_string(),
        "https" => "HTTPS".to_string(),
        "ua" => "UA".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => {
                    let mut rendered = String::new();
                    rendered.extend(first.to_uppercase());
                    rendered.push_str(&chars.as_str().to_lowercase());
                    rendered
                }
                None => String::new(),
            }
        }
    }
}

fn render_value_for_feature(value: &Value, semantics: Option<&FeatureSemantics>) -> String {
    if semantics.and_then(|semantics| semantics.unit.as_deref()) == Some("percent") {
        if let Some(number) = value.as_f64() {
            let percent = if number.abs() <= 1.0 {
                number * 100.0
            } else {
                number
            };
            return format!("{}%", render_number(percent));
        }
    }
    render_value(value)
}

fn render_number(value: f64) -> String {
    if (value.fract()).abs() < f64::EPSILON {
        return format!("{value:.0}");
    }
    let rendered = format!("{value:.3}");
    rendered
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(boolean) => {
            if *boolean {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::Array(values) => {
            let rendered = values
                .iter()
                .map(render_value)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{rendered}]")
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_rule_text, RuleTextContext};
    use logicpearl_ir::{Expression, FeatureSemantics};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn generates_boolean_detection_label_and_hint() {
        let expression: Expression = serde_json::from_value(json!({
            "feature": "contains_xss_signature",
            "op": "==",
            "value": true
        }))
        .unwrap();

        let generated = generate_rule_text(&expression, &RuleTextContext::empty());
        assert_eq!(generated.label.as_deref(), Some("XSS Signature Detected"));
        assert_eq!(
            generated.counterfactual_hint.as_deref(),
            Some("Remove XSS Signature")
        );
    }

    #[test]
    fn generates_numeric_threshold_hint() {
        let expression: Expression = serde_json::from_value(json!({
            "feature": "clearance_level",
            "op": "<",
            "value": 5
        }))
        .unwrap();

        let generated = generate_rule_text(&expression, &RuleTextContext::empty());
        assert_eq!(generated.label.as_deref(), Some("Clearance Level below 5"));
        assert_eq!(
            generated.counterfactual_hint.as_deref(),
            Some("Keep Clearance Level at or above 5")
        );
    }

    #[test]
    fn percent_unit_renders_fractional_threshold_as_percent() {
        let expression: Expression = serde_json::from_value(json!({
            "feature": "soil_moisture_pct",
            "op": "<=",
            "value": 0.18
        }))
        .unwrap();
        let mut feature_semantics = BTreeMap::new();
        feature_semantics.insert(
            "soil_moisture_pct".to_string(),
            serde_json::from_value::<FeatureSemantics>(json!({
                "label": "Soil moisture",
                "unit": "percent"
            }))
            .unwrap(),
        );
        let context = RuleTextContext::with_feature_semantics(&feature_semantics);

        let generated = generate_rule_text(&expression, &context);
        assert_eq!(
            generated.label.as_deref(),
            Some("Soil moisture at or below 18%")
        );
        assert_eq!(
            generated.counterfactual_hint.as_deref(),
            Some("Keep Soil moisture above 18%")
        );
    }

    #[test]
    fn annotated_missing_requirement_generates_readable_rule_text() {
        let expression: Expression = serde_json::from_value(json!({
            "feature": "requirement__req-abc__satisfied",
            "op": "<=",
            "value": 0.0
        }))
        .unwrap();
        let mut feature_semantics = BTreeMap::new();
        feature_semantics.insert(
            "requirement__req-abc__satisfied".to_string(),
            serde_json::from_value::<FeatureSemantics>(json!({
                "label": "Failed conservative therapy",
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
        let context = RuleTextContext::with_feature_semantics(&feature_semantics);

        let generated = generate_rule_text(&expression, &context);
        assert_eq!(
            generated.label.as_deref(),
            Some("Failed conservative therapy is missing")
        );
        assert!(!generated.label.unwrap().contains("req-abc"));
        assert_eq!(
            generated.message.as_deref(),
            Some("This rule fires when the packet does not support failed conservative therapy.")
        );
        assert_eq!(
            generated.counterfactual_hint.as_deref(),
            Some("Add evidence showing failed conservative therapy.")
        );
    }
}
