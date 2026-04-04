from __future__ import annotations

from pydantic import Field

from logicpearl.ir import LogicPearlGateIR, evaluate_gate
from logicpearl.ir.models import LogicPearlModel

from .evaluator import evaluate_case_against_policy, requirement_feature_id
from .models import ClinicalEvent, ClinicalEventType, HealthcarePolicySlice, PatientCase


class PolicySampleCaseSet(LogicPearlModel):
    policy_id: str
    cases: list[PatientCase]


class SampleExecutionResult(LogicPearlModel):
    case_id: str
    expected_missing_requirement_ids: list[str] = Field(default_factory=list)
    actual_missing_rule_ids: list[str] = Field(default_factory=list)
    expected_bitmask: int
    actual_bitmask: int
    parity_ok: bool


class PolicySampleExecutionSummary(LogicPearlModel):
    policy_id: str
    case_count: int
    parity_ok: bool
    results: list[SampleExecutionResult]


def generate_sample_cases_for_policy(policy: HealthcarePolicySlice) -> PolicySampleCaseSet:
    cases = [
        PatientCase(
            case_id=f"{policy.policy_id}__complete",
            member_id="sample-member-complete",
            requested_service=policy.title,
            events=[_cluster_event(policy, cluster.cluster_id) for cluster in policy.clusters],
        ),
        PatientCase(
            case_id=f"{policy.policy_id}__empty",
            member_id="sample-member-empty",
            requested_service=policy.title,
            events=[],
        ),
    ]

    for missing_requirement in policy.requirements:
        cases.append(
            PatientCase(
                case_id=f"{policy.policy_id}__missing__{missing_requirement.requirement_id}",
                member_id=f"sample-member-missing-{missing_requirement.requirement_id}",
                requested_service=policy.title,
                events=[
                    _cluster_event(policy, cluster.cluster_id)
                    for cluster in policy.clusters
                    if cluster.cluster_id != missing_requirement.cluster_id
                ],
            )
        )

    return PolicySampleCaseSet(policy_id=policy.policy_id, cases=cases)


def execute_sample_cases_for_policy(
    policy: HealthcarePolicySlice,
    gate: LogicPearlGateIR,
    case_set: PolicySampleCaseSet,
) -> PolicySampleExecutionSummary:
    results: list[SampleExecutionResult] = []
    for case in case_set.cases:
        evaluation = evaluate_case_against_policy(policy, case)
        actual_bitmask = evaluate_gate(gate, evaluation.features)
        expected_missing_requirement_ids = [
            requirement.requirement_id
            for requirement in policy.requirements
            if evaluation.features[requirement_feature_id(requirement.requirement_id)] <= 0.5
        ]
        expected_bitmask = _expected_bitmask(policy, expected_missing_requirement_ids)
        actual_missing_rule_ids = [
            rule.id
            for rule in gate.rules
            if actual_bitmask & (1 << rule.bit)
        ]
        results.append(
            SampleExecutionResult(
                case_id=case.case_id,
                expected_missing_requirement_ids=expected_missing_requirement_ids,
                actual_missing_rule_ids=actual_missing_rule_ids,
                expected_bitmask=expected_bitmask,
                actual_bitmask=actual_bitmask,
                parity_ok=expected_bitmask == actual_bitmask,
            )
        )

    return PolicySampleExecutionSummary(
        policy_id=policy.policy_id,
        case_count=len(results),
        parity_ok=all(result.parity_ok for result in results),
        results=results,
    )


def _expected_bitmask(policy: HealthcarePolicySlice, missing_requirement_ids: list[str]) -> int:
    missing = set(missing_requirement_ids)
    bitmask = 0
    for index, requirement in enumerate(policy.requirements):
        if requirement.requirement_id in missing:
            bitmask |= 1 << index
    return bitmask


def _cluster_event(policy: HealthcarePolicySlice, cluster_id: str) -> ClinicalEvent:
    cluster = next(cluster for cluster in policy.clusters if cluster.cluster_id == cluster_id)
    code = cluster.codes[0] if cluster.codes else cluster.cluster_id.upper()
    return ClinicalEvent(
        event_id=f"{policy.policy_id}__{cluster.cluster_id}",
        event_type=_event_type_for_cluster(cluster.kind),
        code=code,
        label=cluster.label,
        source="synthetic_sample_case",
    )


def _event_type_for_cluster(cluster_kind: str) -> ClinicalEventType:
    if cluster_kind == "diagnosis":
        return ClinicalEventType.DIAGNOSIS
    if cluster_kind == "procedure":
        return ClinicalEventType.PROCEDURE
    if cluster_kind == "note_assertion":
        return ClinicalEventType.NOTE_ASSERTION
    return ClinicalEventType.MEDICATION
