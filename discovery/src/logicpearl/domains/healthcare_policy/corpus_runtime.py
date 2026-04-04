from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel

from .compiler import compile_healthcare_policy_to_gate_ir
from .request_eval import (
    HealthcarePolicyRequest,
    HealthcarePolicyResponse,
    PolicyContext,
    PolicySourceRef,
    QuestionEvaluationResult,
    RoutingStatus,
)
from .request_pearl import RequestPearlArtifact, assemble_request_pearl
from .selector import PolicySelectionResult, select_applicable_policies
from .models import HealthcarePolicySlice


class CorpusRuntimeBitMapping(LogicPearlModel):
    bit: int
    bit_kind: Literal["requirement", "documentation"]
    policy_id: str
    requirement_id: str
    question_id: str
    question_text: str
    cluster_id: str


class HealthcareCorpusEvaluation(LogicPearlModel):
    request_id: str
    selected_policy_ids: list[str] = Field(default_factory=list)
    ambiguous_policy_ids: list[str] = Field(default_factory=list)
    selector_result: PolicySelectionResult
    request_pearl: RequestPearlArtifact
    response: HealthcarePolicyResponse
    logic_bitmask: int
    documentation_bitmask: int
    bitmask: int
    bit_mappings: list[CorpusRuntimeBitMapping] = Field(default_factory=list)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if not value:
            raise ValueError("request_id must be non-empty")
        return value


def evaluate_request_against_corpus(
    request: HealthcarePolicyRequest,
    policies: list[HealthcarePolicySlice],
) -> HealthcareCorpusEvaluation:
    selector_result = select_applicable_policies(request, policies)
    selected_policies = [policy for policy in policies if policy.policy_id in selector_result.selected_policy_ids]
    request_pearl = assemble_request_pearl(request, selected_policies, selector_result)
    gate = compile_healthcare_policy_to_gate_ir(request_pearl.composed_policy)
    composed_request = request.model_copy(
        update={
            "policy_context": PolicyContext(
                policy_id=request_pearl.composed_policy.policy_id,
                policy_sources=[
                    PolicySourceRef(source_id=source.source_id, title=source.title, url=source.url)
                    for source in request_pearl.composed_policy.sources
                ],
            ),
            "guided_questions": [],
        }
    )
    from .request_eval import evaluate_request_against_policy

    response = evaluate_request_against_policy(request_pearl.composed_policy, composed_request, gate=gate)
    logic_bitmask = int(response.summary.bitmask or 0)
    bit_mappings = _build_dynamic_bit_mappings(request_pearl, response.questions)
    documentation_bitmask = _documentation_bitmask(bit_mappings, response.questions)
    return HealthcareCorpusEvaluation(
        request_id=request.request.request_id,
        selected_policy_ids=selector_result.selected_policy_ids,
        ambiguous_policy_ids=selector_result.ambiguous_policy_ids,
        selector_result=selector_result,
        request_pearl=request_pearl,
        response=response,
        logic_bitmask=logic_bitmask,
        documentation_bitmask=documentation_bitmask,
        bitmask=logic_bitmask | documentation_bitmask,
        bit_mappings=bit_mappings,
    )


def _build_dynamic_bit_mappings(
    request_pearl: RequestPearlArtifact,
    questions: list[QuestionEvaluationResult],
) -> list[CorpusRuntimeBitMapping]:
    mappings: list[CorpusRuntimeBitMapping] = []
    reference_by_request_requirement = {
        reference.request_requirement_id: reference for reference in request_pearl.requirement_references
    }
    for bit, question in enumerate(questions):
        reference = reference_by_request_requirement[question.requirement_id]
        mappings.append(
            CorpusRuntimeBitMapping(
                bit=bit,
                bit_kind="requirement",
                policy_id=reference.source_policy_id,
                requirement_id=question.requirement_id,
                question_id=question.question_id,
                question_text=question.question_text,
                cluster_id=question.cluster_id,
            )
        )
    offset = len(questions)
    for index, question in enumerate(questions):
        mappings.append(
            CorpusRuntimeBitMapping(
                bit=offset + index,
                bit_kind="documentation",
                policy_id=reference_by_request_requirement[question.requirement_id].source_policy_id,
                requirement_id=question.requirement_id,
                question_id=question.question_id,
                question_text=question.question_text,
                cluster_id=question.cluster_id,
            )
        )
    return mappings


def _documentation_bitmask(
    bit_mappings: list[CorpusRuntimeBitMapping],
    questions: list[QuestionEvaluationResult],
) -> int:
    documentation_bits = 0
    question_by_id = {question.question_id: question for question in questions}
    for mapping in bit_mappings:
        if mapping.bit_kind != "documentation":
            continue
        question = question_by_id[mapping.question_id]
        if question.documentation_status == "missing_required_documentation":
            documentation_bits |= 1 << mapping.bit
    return documentation_bits
