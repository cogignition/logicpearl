// SPDX-License-Identifier: MIT
use logicpearl_ir::{Expression, InputSchema, LogicPearlActionIr, LogicPearlGateIr};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub(super) enum CompilablePearl {
    Gate(LogicPearlGateIr),
    Action(LogicPearlActionIr),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WasmRuleView<'a> {
    pub(super) id: &'a str,
    pub(super) bit: u32,
    pub(super) expression: &'a Expression,
    pub(super) action: Option<&'a str>,
    pub(super) priority: Option<u32>,
    pub(super) label: Option<&'a String>,
    pub(super) message: Option<&'a String>,
    pub(super) severity: Option<&'a String>,
    pub(super) counterfactual_hint: Option<&'a String>,
}

impl CompilablePearl {
    pub(super) fn from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err("failed to read pearl IR")?;
        Self::from_json_str(&content)
    }

    pub(super) fn from_json_str(input: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(input)
            .into_diagnostic()
            .wrap_err("pearl IR is not valid JSON")?;
        if value.get("action_policy_id").is_some() {
            let policy = LogicPearlActionIr::from_json_str(input)
                .into_diagnostic()
                .wrap_err("pearl IR is not a valid action policy")?;
            Ok(Self::Action(policy))
        } else {
            let gate = LogicPearlGateIr::from_json_str(input)
                .into_diagnostic()
                .wrap_err("pearl IR is not a valid gate")?;
            Ok(Self::Gate(gate))
        }
    }

    pub(super) fn artifact_id(&self) -> &str {
        match self {
            Self::Gate(gate) => &gate.gate_id,
            Self::Action(policy) => &policy.action_policy_id,
        }
    }

    pub(super) fn decision_kind(&self) -> &'static str {
        match self {
            Self::Gate(_) => "gate",
            Self::Action(_) => "action",
        }
    }

    pub(super) fn input_schema(&self) -> &InputSchema {
        match self {
            Self::Gate(gate) => &gate.input_schema,
            Self::Action(policy) => &policy.input_schema,
        }
    }

    pub(super) fn wasm_rules(&self) -> Vec<WasmRuleView<'_>> {
        match self {
            Self::Gate(gate) => gate
                .rules
                .iter()
                .map(|rule| WasmRuleView {
                    id: &rule.id,
                    bit: rule.bit,
                    expression: &rule.deny_when,
                    action: None,
                    priority: None,
                    label: rule.label.as_ref(),
                    message: rule.message.as_ref(),
                    severity: rule.severity.as_ref(),
                    counterfactual_hint: rule.counterfactual_hint.as_ref(),
                })
                .collect(),
            Self::Action(policy) => policy
                .rules
                .iter()
                .map(|rule| WasmRuleView {
                    id: &rule.id,
                    bit: rule.bit,
                    expression: &rule.predicate,
                    action: Some(&rule.action),
                    priority: Some(rule.priority),
                    label: rule.label.as_ref(),
                    message: rule.message.as_ref(),
                    severity: rule.severity.as_ref(),
                    counterfactual_hint: rule.counterfactual_hint.as_ref(),
                })
                .collect(),
        }
    }

    pub(super) fn default_action(&self) -> Option<&str> {
        match self {
            Self::Gate(_) => None,
            Self::Action(policy) => Some(&policy.default_action),
        }
    }

    pub(super) fn actions(&self) -> &[String] {
        match self {
            Self::Gate(_) => &[],
            Self::Action(policy) => &policy.actions,
        }
    }
}
