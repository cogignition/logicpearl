from __future__ import annotations

from logicpearl.engine.gate_ir import serialize_rules_to_gate_ir
from logicpearl.ir import LogicPearlGateIR

from .evaluator import build_requirement_gate, requirement_feature_id
from .models import HealthcarePolicySlice


def compile_healthcare_policy_to_gate_ir(policy: HealthcarePolicySlice) -> LogicPearlGateIR:
    rules = build_requirement_gate(policy)
    feature_sample = {
        requirement_feature_id(requirement.requirement_id): 0.0
        for requirement in policy.requirements
    }
    return serialize_rules_to_gate_ir(
        rules,
        gate_id=policy.policy_id,
        feature_sample=feature_sample,
        generator="logicpearl.healthcare_policy_compiler",
        generator_version="0.1.0",
        correctness_scope="draft healthcare policy requirement gate",
    )
