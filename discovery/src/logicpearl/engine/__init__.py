from .boolean_mining import BooleanMiningConfig, mine_exact_boolean_rules, mine_targeted_exact_boolean_rules
from .feature_governance import (
    FeatureGovernanceConfig,
    FeatureGovernanceReport,
    FeatureTier,
    classify_feature_tier,
    compute_feature_governance_report,
    should_scan_feature,
)
from .gate import CompiledGate, compile_gate
from .gate_ir import (
    build_input_schema_from_feature_sample,
    infer_feature_type,
    serialize_rules_to_gate_ir,
)
from .pipeline import (
    DiscoveryPipelineConfig,
    DiscoveryPipelineResult,
    coerce_discovery_result,
    discover_rules,
)
from .layering import load_pinned_rules, merge_rule_layers, rule_signature
from .rule_pruning import prune_redundant_rules, prune_rules_by_marginal_accuracy
from .rules import Condition, Rule, RuleSource, VerificationStatus, coerce_condition, coerce_rule, coerce_rules
from .trace_quality import (
    TraceIssueCode,
    TracePartition,
    TraceQualityConfig,
    TraceQualityIssue,
    TraceQualityReport,
    TraceTrustTier,
    assess_trace_quality,
    partition_traces_by_quality,
    summarize_trace_partition,
)
from .wasm import WasmCompilationResult, compile_gate_to_wasm
from .circuit_compiler import compile_ensemble_to_circuit, verify_circuit_equivalence

__all__ = [
    "CompiledGate",
    "BooleanMiningConfig",
    "Condition",
    "FeatureGovernanceConfig",
    "FeatureGovernanceReport",
    "FeatureTier",
    "DiscoveryPipelineConfig",
    "DiscoveryPipelineResult",
    "Rule",
    "RuleSource",
    "VerificationStatus",
    "WasmCompilationResult",
    "build_input_schema_from_feature_sample",
    "classify_feature_tier",
    "coerce_discovery_result",
    "coerce_condition",
    "coerce_rule",
    "coerce_rules",
    "compile_gate",
    "compile_gate_to_wasm",
    "compile_ensemble_to_circuit",
    "compute_feature_governance_report",
    "discover_rules",
    "infer_feature_type",
    "load_pinned_rules",
    "merge_rule_layers",
    "mine_exact_boolean_rules",
    "mine_targeted_exact_boolean_rules",
    "prune_rules_by_marginal_accuracy",
    "prune_redundant_rules",
    "rule_signature",
    "serialize_rules_to_gate_ir",
    "should_scan_feature",
    "summarize_trace_partition",
    "TraceIssueCode",
    "TracePartition",
    "TraceQualityConfig",
    "TraceQualityIssue",
    "TraceQualityReport",
    "TraceTrustTier",
    "assess_trace_quality",
    "partition_traces_by_quality",
    "verify_circuit_equivalence",
]
