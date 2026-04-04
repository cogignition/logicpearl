import json
import subprocess

from logicpearl.domains.healthcare_policy.compiler import compile_healthcare_policy_to_gate_ir
from logicpearl.domains.healthcare_policy.deployment import (
    build_runtime_bit_mappings,
    build_runtime_input_from_response,
    export_runtime_artifacts,
)
from logicpearl.domains.healthcare_policy.request_eval import (
    CandidateAssertion,
    EvidenceDocument,
    HealthcarePolicyRequest,
    MemberEvidence,
    PolicyContext,
    PolicySourceRef,
    RequestContext,
    RequestedService,
    evaluate_request_against_policy,
    review_candidate_assertions,
)

from test_healthcare_policy_request_eval import _final_spec


def _request_with_reviewed_assertion(policy):
    reviewed = review_candidate_assertions(
        policy,
        [
            CandidateAssertion(
                assertion_id="a1",
                cluster_id="diagnosis_requirement__qualifying_diagnosis",
                value="present",
                confidence=0.95,
                source_document_id="note-1",
                source_snippet="Patient has enthesitis-related arthritis.",
                citation="note-1#line-1",
                extractor="llm_observer_v1",
            )
        ],
    )
    return HealthcarePolicyRequest(
        request=RequestContext(
            request_id="req-123",
            payer="BCBSMA",
            member_id="member-1",
            requested_service=RequestedService(kind="drug", code="NDC-1", label="Requested Drug"),
        ),
        policy_context=PolicyContext(
            policy_id=policy.policy_id,
            policy_sources=[
                PolicySourceRef(
                    source_id=policy.sources[0].source_id,
                    title=policy.sources[0].title,
                    url=policy.sources[0].url,
                )
            ],
        ),
        member_evidence=MemberEvidence(
            structured_events=[],
            unstructured_documents=[
                EvidenceDocument(
                    document_id="note-1",
                    kind="clinical_note",
                    text="Patient has enthesitis-related arthritis.",
                    source="ehr",
                )
            ],
            candidate_assertions=[],
            reviewed_assertions=reviewed,
        ),
    )


def test_build_runtime_bit_mappings_tracks_requirement_questions() -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)

    mappings = build_runtime_bit_mappings(policy, gate)

    assert len(mappings) == 1
    assert mappings[0].bit == 0
    assert mappings[0].rule_id == "missing_req-1"
    assert mappings[0].requirement_id == "req-1"
    assert "diagnosis" in (mappings[0].question_text or "").lower()


def test_export_runtime_artifacts_writes_ir_rust_and_bit_manifest(tmp_path) -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)

    bundle = export_runtime_artifacts(policy, gate, output_dir=tmp_path, artifact_name="pearl")

    assert bundle.policy_id == policy.policy_id
    assert (tmp_path / "pearl.ir.json").exists()
    assert (tmp_path / "pearl.rs").exists()
    assert (tmp_path / "pearl.bit_manifest.json").exists()
    assert (tmp_path / "pearl.pearl").exists()
    assert bundle.bit_mappings[0].rule_id == "missing_req-1"


def test_build_runtime_input_from_response_matches_found_question_features() -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)
    request = _request_with_reviewed_assertion(policy)

    response = evaluate_request_against_policy(policy, request, gate=gate)
    runtime_input = build_runtime_input_from_response(response)

    assert response.summary.bitmask == 0
    assert runtime_input == {"requirement__req-1__satisfied": 1.0}


def test_generated_pearl_describe_mode_is_agent_friendly(tmp_path) -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)

    export_runtime_artifacts(policy, gate, output_dir=tmp_path, artifact_name="pearl")
    result = subprocess.run(
        [str(tmp_path / "pearl.pearl"), "describe"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["artifact_id"] == policy.policy_id
    assert "evaluate" in payload["modes"]
    assert "explain" in payload["modes"]


def test_generated_pearl_validate_reports_specific_error_codes(tmp_path) -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)

    export_runtime_artifacts(policy, gate, output_dir=tmp_path, artifact_name="pearl")
    invalid_payload = tmp_path / "invalid.json"
    invalid_payload.write_text(json.dumps({"input": {"features": {"unknown_feature": 1.0}}}), encoding="utf-8")
    result = subprocess.run(
        [str(tmp_path / "pearl.pearl"), "validate", "--input", str(invalid_payload)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error_code"] == "missing_required_features"


def test_generated_pearl_explain_and_counterfactual_modes_are_structured(tmp_path) -> None:
    policy = _final_spec()
    gate = compile_healthcare_policy_to_gate_ir(policy)
    request = _request_with_reviewed_assertion(policy)
    response = evaluate_request_against_policy(policy, request, gate=gate)

    export_runtime_artifacts(policy, gate, output_dir=tmp_path, artifact_name="pearl")
    good_payload = tmp_path / "good.json"
    good_payload.write_text(
        json.dumps({"input": {"features": build_runtime_input_from_response(response)}}),
        encoding="utf-8",
    )
    explain_result = subprocess.run(
        [str(tmp_path / "pearl.pearl"), "explain", "--input", str(good_payload)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert explain_result.returncode == 0
    explain_payload = json.loads(explain_result.stdout)
    assert "explanation" in explain_payload
    assert explain_payload["explanation"]["fired_rule_count"] == 0

    failing_payload = tmp_path / "failing.json"
    failing_payload.write_text(
        json.dumps({"input": {"features": {"requirement__req-1__satisfied": 0.0}}}),
        encoding="utf-8",
    )
    counterfactual_result = subprocess.run(
        [str(tmp_path / "pearl.pearl"), "counterfactual", "--input", str(failing_payload)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert counterfactual_result.returncode == 0
    counterfactual_payload = json.loads(counterfactual_result.stdout)
    assert counterfactual_payload["recommended_action"] == "clear_all_fired_bits"
    assert counterfactual_payload["counterfactuals"][0]["set_features"][0]["set_to"] == 1.0
