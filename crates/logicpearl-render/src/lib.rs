// SPDX-License-Identifier: MIT
//! Human-readable rendering for LogicPearl artifacts.
//!
//! This crate converts validated artifact IR into terminal-oriented text for
//! inspection. It intentionally renders existing metadata and rules instead
//! of inferring domain meaning that should have been supplied by feature
//! dictionaries or integrations.

use logicpearl_core::{ArtifactRenderer, Result};
use logicpearl_ir::{LogicPearlGateIr, RuleVerificationStatus};
use owo_colors::OwoColorize;

pub struct TextInspector;

impl ArtifactRenderer<LogicPearlGateIr> for TextInspector {
    fn render(&self, gate: &LogicPearlGateIr) -> Result<String> {
        let mut lines = Vec::new();

        // Gate header
        lines.push(format!(
            "{} {}",
            "━━ Gate:".bold(),
            gate.gate_id.bold().bright_green()
        ));
        lines.push(format!(
            "  {} {}",
            "IR version".bright_black(),
            gate.ir_version
        ));
        lines.push(format!(
            "  {} {}",
            "Features".bright_black(),
            gate.input_schema.features.len()
        ));
        lines.push(format!("  {} {}", "Rules".bright_black(), gate.rules.len()));

        if let Some(verification) = &gate.verification {
            if let Some(scope) = &verification.correctness_scope {
                lines.push(format!(
                    "  {} {}",
                    "Correctness scope".bright_black(),
                    scope
                ));
            }
        }

        let semantic_features = gate
            .input_schema
            .features
            .iter()
            .filter(|feature| feature.semantics.is_some())
            .count();
        if semantic_features > 0 {
            lines.push(format!(
                "  {} {}",
                "Feature dictionary".bright_black(),
                semantic_features
            ));
        }

        // Rules section
        lines.push(String::new());
        lines.push(format!("{}", "━━ Rules ━━".bold()));

        let rule_count = gate.rules.len();
        for (i, rule) in gate.rules.iter().enumerate() {
            let is_last = i == rule_count - 1;
            let branch = if is_last { "└─" } else { "├─" };
            let continuation = if is_last { "   " } else { "│  " };

            let (symbol, status_text) = match &rule.verification_status {
                Some(RuleVerificationStatus::SolverVerified) => (
                    format!("{}", "✓".green()),
                    format!("{}", "solver_verified".green()),
                ),
                Some(RuleVerificationStatus::PipelineUnverified) => (
                    format!("{}", "⚠".yellow()),
                    format!("{}", "pipeline_unverified".yellow()),
                ),
                Some(RuleVerificationStatus::HeuristicUnverified) => (
                    format!("{}", "⚠".yellow()),
                    format!("{}", "heuristic_unverified".yellow()),
                ),
                Some(RuleVerificationStatus::RefinedUnverified) => (
                    format!("{}", "⚠".yellow()),
                    format!("{}", "refined_unverified".yellow()),
                ),
                None => (format!("{}", "✗".red()), format!("{}", "unknown".red())),
            };

            lines.push(format!(
                "  {} {} {} {} {} {}",
                branch.bright_black(),
                format!("bit {}", rule.bit).bright_cyan(),
                rule.id.bold(),
                "→".bright_black(),
                symbol,
                status_text,
            ));

            if let Some(label) = &rule.label {
                lines.push(format!(
                    "  {} {} {}",
                    continuation.bright_black(),
                    "label:".bright_black(),
                    label
                ));
            }
            if let Some(message) = &rule.message {
                lines.push(format!(
                    "  {} {} {}",
                    continuation.bright_black(),
                    "message:".bright_black(),
                    message
                ));
            }
            if let Some(hint) = &rule.counterfactual_hint {
                lines.push(format!(
                    "  {} {} {}",
                    continuation.bright_black(),
                    "counterfactual:".bright_black(),
                    hint
                ));
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
        CombineStrategy, ComparisonExpression, ComparisonOperator, ComparisonValue,
        EvaluationConfig, Expression, FeatureDefinition, FeatureType, GateType, InputSchema,
        LogicPearlGateIr, RuleDefinition, RuleKind, RuleVerificationStatus,
    };

    #[test]
    fn renders_backend_neutral_solver_verified_status() {
        // Disable colors so assertions can match plain text.
        owo_colors::set_override(false);

        let gate = LogicPearlGateIr {
            ir_version: "1.0".to_string(),
            gate_id: "demo_gate".to_string(),
            gate_type: GateType::BitmaskGate,
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
                combine: CombineStrategy::BitwiseOr,
                allow_when_bitmask: 0,
            },
            verification: None,
            provenance: None,
        };

        let rendered = TextInspector
            .render(&gate)
            .expect("text inspector should render a simple gate");
        assert!(
            rendered.contains("solver_verified"),
            "should contain solver_verified: {rendered}"
        );
        assert!(
            rendered.contains("✓"),
            "should contain check mark: {rendered}"
        );
        assert!(
            rendered.contains("demo_gate"),
            "should contain gate id: {rendered}"
        );
        assert!(!rendered.contains("z3_verified"));
    }
}
