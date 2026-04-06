use logicpearl_ir::{ComparisonExpression, ComparisonOperator, ComparisonValue, Expression};
use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct GeneratedRuleText {
    pub label: Option<String>,
    pub message: Option<String>,
    pub counterfactual_hint: Option<String>,
}

pub(super) fn generate_rule_text(expression: &Expression) -> GeneratedRuleText {
    let label = Some(expression_label(expression));
    let message = label.as_ref().map(|label| format!("{label}."));
    let counterfactual_hint = Some(expression_counterfactual_hint(expression));
    GeneratedRuleText {
        label,
        message,
        counterfactual_hint,
    }
}

fn expression_label(expression: &Expression) -> String {
    match expression {
        Expression::Comparison(comparison) => comparison_label(comparison),
        Expression::All { all } => join_child_labels(all, " and "),
        Expression::Any { any } => join_child_labels(any, " or "),
        Expression::Not { expr } => format!("Not ({})", expression_label(expr)),
    }
}

fn expression_counterfactual_hint(expression: &Expression) -> String {
    match expression {
        Expression::Comparison(comparison) => comparison_counterfactual_hint(comparison),
        Expression::All { all } => format!(
            "Break at least one condition: {}",
            all.iter()
                .map(expression_counterfactual_hint)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Expression::Any { any } => format!(
            "Resolve all of: {}",
            any.iter()
                .map(expression_counterfactual_hint)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Expression::Not { expr } => {
            format!("Reverse this negated condition: {}", expression_label(expr))
        }
    }
}

fn join_child_labels(children: &[Expression], joiner: &str) -> String {
    children
        .iter()
        .map(expression_label)
        .collect::<Vec<_>>()
        .join(joiner)
}

fn comparison_label(comparison: &ComparisonExpression) -> String {
    let feature = humanize_feature_name(&comparison.feature);
    match (&comparison.op, &comparison.value) {
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(true))) => {
            positive_boolean_label(&comparison.feature)
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(false))) => {
            format!("{feature} Is False")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(true))) => {
            format!("{feature} Is False")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(false))) => {
            positive_boolean_label(&comparison.feature)
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
            format!("{feature} equals {}", render_value(value))
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(value)) => {
            format!("{feature} differs from {}", render_value(value))
        }
        (ComparisonOperator::Lt, ComparisonValue::Literal(value)) => {
            format!("{feature} below {}", render_value(value))
        }
        (ComparisonOperator::Lte, ComparisonValue::Literal(value)) => {
            format!("{feature} at or below {}", render_value(value))
        }
        (ComparisonOperator::Gt, ComparisonValue::Literal(value)) => {
            format!("{feature} above {}", render_value(value))
        }
        (ComparisonOperator::Gte, ComparisonValue::Literal(value)) => {
            format!("{feature} at or above {}", render_value(value))
        }
        (ComparisonOperator::In, ComparisonValue::Literal(value)) => {
            format!("{feature} is in {}", render_value(value))
        }
        (ComparisonOperator::NotIn, ComparisonValue::Literal(value)) => {
            format!("{feature} is outside {}", render_value(value))
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

fn comparison_counterfactual_hint(comparison: &ComparisonExpression) -> String {
    let feature = humanize_feature_name(&comparison.feature);
    match (&comparison.op, &comparison.value) {
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(true))) => {
            positive_boolean_counterfactual(&comparison.feature)
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(Value::Bool(false))) => {
            format!("Keep {feature} true")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(true))) => {
            format!("Keep {feature} false")
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(Value::Bool(false))) => {
            positive_boolean_counterfactual(&comparison.feature)
        }
        (ComparisonOperator::Lt, ComparisonValue::Literal(value)) => {
            format!("Keep {feature} at or above {}", render_value(value))
        }
        (ComparisonOperator::Lte, ComparisonValue::Literal(value)) => {
            format!("Keep {feature} above {}", render_value(value))
        }
        (ComparisonOperator::Gt, ComparisonValue::Literal(value)) => {
            format!("Keep {feature} at or below {}", render_value(value))
        }
        (ComparisonOperator::Gte, ComparisonValue::Literal(value)) => {
            format!("Keep {feature} below {}", render_value(value))
        }
        (ComparisonOperator::Eq, ComparisonValue::Literal(value)) => {
            format!("Change {feature} away from {}", render_value(value))
        }
        (ComparisonOperator::Ne, ComparisonValue::Literal(value)) => {
            format!("Set {feature} to {}", render_value(value))
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
            format!("Keep {feature} outside {}", render_value(value))
        }
        (ComparisonOperator::NotIn, ComparisonValue::Literal(value)) => {
            format!("Set {feature} inside {}", render_value(value))
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

fn positive_boolean_label(feature_id: &str) -> String {
    let feature = humanize_feature_name(feature_id);
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

fn positive_boolean_counterfactual(feature_id: &str) -> String {
    let feature = humanize_feature_name(feature_id);
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
    use super::generate_rule_text;
    use logicpearl_ir::Expression;
    use serde_json::json;

    #[test]
    fn generates_boolean_detection_label_and_hint() {
        let expression: Expression = serde_json::from_value(json!({
            "feature": "contains_xss_signature",
            "op": "==",
            "value": true
        }))
        .unwrap();

        let generated = generate_rule_text(&expression);
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

        let generated = generate_rule_text(&expression);
        assert_eq!(generated.label.as_deref(), Some("Clearance Level below 5"));
        assert_eq!(
            generated.counterfactual_hint.as_deref(),
            Some("Keep Clearance Level at or above 5")
        );
    }
}
