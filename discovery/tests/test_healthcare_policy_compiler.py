from logicpearl.domains.healthcare_policy.assembly import assemble_draft_logic_specs
from logicpearl.domains.healthcare_policy.compiler import compile_healthcare_policy_to_gate_ir


def test_compile_healthcare_policy_to_gate_ir_compiles_requirement_bits() -> None:
    specs = assemble_draft_logic_specs(
        documents=[
            {
                "document_id": "004-immune-modulating-drugs-prn",
                "filename": "004.pdf",
                "title_guess": "004 Immune Modulating Drugs prn",
                "document_kind": "medication_policy",
                "source_url": "https://example.com/004.pdf",
            }
        ],
        requirement_records=[
            {
                "requirement_id": "req-1",
                "document_id": "004-immune-modulating-drugs-prn",
                "requirement_family": "diagnosis_requirement",
                "cluster_placeholder_id": "diagnosis_requirement__qualifying_diagnosis",
                "status": "normalized",
                "source_snippet": "Enthesitis-Related Arthritis: Requires diagnosis only.",
                "source_section_heading": "Policy",
                "page_number": 2,
                "evidence_hint": "qualifying_diagnosis",
            }
        ],
        cluster_mappings=[
            {
                "cluster_id": "diagnosis_requirement__qualifying_diagnosis",
                "label": "Diagnosis Requirement: qualifying diagnosis",
                "alias_candidates": [{"alias": "Enthesitis-Related Arthritis", "count": 1}],
            }
        ],
        ranked_examples={
            "diagnosis_requirement": {
                "document_id": "004-immune-modulating-drugs-prn",
            }
        },
    )
    ir = compile_healthcare_policy_to_gate_ir(specs[0])

    assert ir.gate_id == specs[0].policy_id
    assert len(ir.rules) == 1
    assert ir.rules[0].id == "missing_req-1"
