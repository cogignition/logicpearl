from __future__ import annotations

from dataclasses import dataclass

from logicpearl.engine import Condition, Rule, RuleSource, VerificationStatus

from .models import (
    ClinicalEvent,
    ClinicalEventType,
    EvidenceRequirementKind,
    HealthcarePolicySlice,
    PatientCase,
    RequirementEvaluation,
)


@dataclass(frozen=True)
class CaseEvaluation:
    features: dict[str, float]
    requirement_results: list[RequirementEvaluation]


def evaluate_case_against_policy(policy: HealthcarePolicySlice, patient_case: PatientCase) -> CaseEvaluation:
    cluster_index = {cluster.cluster_id: cluster for cluster in policy.clusters}
    features: dict[str, float] = {}
    requirement_results: list[RequirementEvaluation] = []

    for requirement in policy.requirements:
        cluster = cluster_index[requirement.cluster_id]
        matched_events = _match_events(cluster.kind, cluster.codes, patient_case.events)
        satisfied = bool(matched_events)
        feature_id = requirement_feature_id(requirement.requirement_id)
        features[feature_id] = 1.0 if satisfied else 0.0
        requirement_results.append(
            RequirementEvaluation(
                requirement_id=requirement.requirement_id,
                label=requirement.label,
                question_text=requirement.question_text,
                satisfied=satisfied,
                evidence_status="found" if satisfied else "not_found",
                source_excerpt=requirement.source_excerpt,
                source_id=requirement.source_id,
                cluster_id=requirement.cluster_id,
                matched_events=[event.event_id for event in matched_events],
            )
        )

    return CaseEvaluation(features=features, requirement_results=requirement_results)


def build_requirement_gate(policy: HealthcarePolicySlice) -> list[Rule]:
    rules: list[Rule] = []
    for requirement in policy.requirements:
        rules.append(
            Rule(
                rule_id=f"missing_{requirement.requirement_id}",
                source=RuleSource.PINNED,
                verification_status=VerificationStatus.HEURISTIC_UNVERIFIED,
                conditions=[
                    Condition(
                        feature=requirement_feature_id(requirement.requirement_id),
                        operator="<=",
                        threshold=0.5,
                    )
                ],
            )
        )
    return rules


def summarize_requirement_results(results: list[RequirementEvaluation]) -> dict[str, int]:
    satisfied = sum(1 for result in results if result.satisfied)
    unsatisfied = sum(1 for result in results if not result.satisfied)
    return {
        "satisfied": satisfied,
        "unsatisfied": unsatisfied,
        "total": len(results),
    }


def requirement_feature_id(requirement_id: str) -> str:
    return f"requirement__{requirement_id}__satisfied"


def _match_events(cluster_kind: str, cluster_codes: list[str], events: list[ClinicalEvent]) -> list[ClinicalEvent]:
    expected_event_type = _cluster_kind_to_event_type(cluster_kind)
    accepted_codes = {code.strip().upper() for code in cluster_codes}
    return [
        event
        for event in events
        if event.event_type == expected_event_type and event.code.strip().upper() in accepted_codes
    ]


def _cluster_kind_to_event_type(cluster_kind: str) -> ClinicalEventType:
    mapping = {
        "diagnosis": ClinicalEventType.DIAGNOSIS,
        "procedure": ClinicalEventType.PROCEDURE,
        "medication": ClinicalEventType.MEDICATION,
        "note_assertion": ClinicalEventType.NOTE_ASSERTION,
    }
    return mapping[cluster_kind]
