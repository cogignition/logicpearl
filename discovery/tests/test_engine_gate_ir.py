from logicpearl.engine import Condition, Rule, VerificationStatus, serialize_rules_to_gate_ir


def test_serialize_rules_to_gate_ir_emits_valid_gate() -> None:
    rules = [
        Rule(
            conditions=[Condition("late_filing", ">", 0.5)],
            verification_status=VerificationStatus.Z3_VERIFIED,
        ),
        Rule(
            conditions=[Condition("is_unlisted_code", ">", 0.5), Condition("prior_auth", "<=", 0.5)],
            verification_status=VerificationStatus.HEURISTIC_UNVERIFIED,
        ),
    ]

    gate = serialize_rules_to_gate_ir(
        rules,
        gate_id="claims_test",
        feature_sample={
            "late_filing": 1.0,
            "is_unlisted_code": 0.0,
            "prior_auth": 0.0,
        },
        correctness_scope="heuristic_unverified=1, z3_verified=1",
        verification_summary={"heuristic_unverified": 1, "z3_verified": 1},
    )

    assert gate.gate_id == "claims_test"
    assert gate.rules[0].bit == 0
    assert gate.rules[1].bit == 1
    assert gate.rules[0].deny_when.feature == "late_filing"
    assert gate.rules[1].deny_when.all[1].feature == "prior_auth"
    assert gate.rules[0].verification_status == "z3_verified"
    assert gate.rules[1].verification_status == "heuristic_unverified"
    assert gate.verification.verification_summary == {"heuristic_unverified": 1, "z3_verified": 1}
