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
        lines.push("Rule details:".to_string());
        for rule in &gate.rules {
            let status = match &rule.verification_status {
                Some(RuleVerificationStatus::Z3Verified) => "z3_verified",
                Some(RuleVerificationStatus::PipelineUnverified) => "pipeline_unverified",
                Some(RuleVerificationStatus::HeuristicUnverified) => "heuristic_unverified",
                Some(RuleVerificationStatus::RefinedUnverified) => "refined_unverified",
                None => "unknown",
            };
            lines.push(format!("  bit {}: {} [{}]", rule.bit, rule.id, status));
        }
        Ok(lines.join("\n"))
    }
}
