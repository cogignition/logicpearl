use logicpearl_core::{ArtifactRenderer, Result};
use logicpearl_ir::{LogicPearlGateIr, RuleVerificationStatus};

pub struct TextInspector;

impl ArtifactRenderer<LogicPearlGateIr> for TextInspector {
    fn render(&self, gate: &LogicPearlGateIr) -> Result<String> {
        let mut lines = vec![
            format!("Gate ID: {}", gate.gate_id),
            format!("IR version: {}", gate.ir_version),
            format!("Features: {}", gate.input_schema.features.len()),
            format!("Rules: {}", gate.rules.len()),
        ];
        if let Some(verification) = &gate.verification {
            if let Some(scope) = &verification.correctness_scope {
                lines.push(format!("Correctness scope: {scope}"));
            }
        }
        let semantic_features = gate
            .input_schema
            .features
            .iter()
            .filter(|feature| feature.semantics.is_some())
            .count();
        if semantic_features > 0 {
            lines.push(format!("Feature dictionary entries: {semantic_features}"));
        }
        lines.push("Rule details:".to_string());
        for rule in &gate.rules {
            let status = match &rule.verification_status {
                Some(RuleVerificationStatus::SolverVerified) => "solver_verified",
                Some(RuleVerificationStatus::PipelineUnverified) => "pipeline_unverified",
                Some(RuleVerificationStatus::HeuristicUnverified) => "heuristic_unverified",
                Some(RuleVerificationStatus::RefinedUnverified) => "refined_unverified",
                None => "unknown",
            };
            lines.push(format!("  bit {}: {} [{}]", rule.bit, rule.id, status));
            if let Some(label) = &rule.label {
                lines.push(format!("    label: {label}"));
            }
            if let Some(message) = &rule.message {
                lines.push(format!("    message: {message}"));
            }
            if let Some(hint) = &rule.counterfactual_hint {
                lines.push(format!("    counterfactual: {hint}"));
            }
        }
        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::TextInspector;
    use logicpearl_core::ArtifactRenderer;
    use logicpearl_ir::{
        ComparisonExpression, ComparisonOperator, ComparisonValue, EvaluationConfig, Expression,
        FeatureDefinition, FeatureType, InputSchema, LogicPearlGateIr, RuleDefinition, RuleKind,
        RuleVerificationStatus,
    };

    #[test]
    fn renders_backend_neutral_solver_verified_status() {
        let gate = LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "demo_gate".to_string(),
            gate_type: "bitmask_gate".to_string(),
            input_schema: InputSchema {
                features: vec![FeatureDefinition {
                    id: "f_age".to_string(),
                    feature_type: FeatureType::Int,
                    description: Some("age".to_string()),
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
                    feature: "f_age".to_string(),
                    op: ComparisonOperator::Lt,
                    value: ComparisonValue::FeatureRef {
                        feature_ref: "f_age".to_string(),
                    },
                }),
                label: None,
                message: None,
                severity: None,
                counterfactual_hint: None,
                verification_status: Some(RuleVerificationStatus::SolverVerified),
            }],
            evaluation: EvaluationConfig {
                combine: "bitwise_or".to_string(),
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        };

        let rendered = TextInspector
            .render(&gate)
            .expect("text inspector should render a simple gate");
        assert!(rendered.contains("solver_verified"));
        assert!(!rendered.contains("z3_verified"));
    }
}
