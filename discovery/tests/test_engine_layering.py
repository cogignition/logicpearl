from logicpearl.engine import Condition, Rule, RuleSource, VerificationStatus, merge_rule_layers


def test_merge_rule_layers_prefers_pinned_rule_on_duplicate_signature() -> None:
    discovered = Rule(
        rule_id="discovered_r05",
        source=RuleSource.DISCOVERED,
        verification_status=VerificationStatus.Z3_VERIFIED,
        conditions=[
            Condition("is_surgery", ">", 0.5),
            Condition("multiple_surgical_codes", ">", 0.5),
        ],
    )
    pinned = Rule(
        rule_id="pinned_r05",
        source=RuleSource.PINNED,
        verification_status=VerificationStatus.PIPELINE_UNVERIFIED,
        conditions=[
            Condition("is_surgery", ">", 0.5),
            Condition("multiple_surgical_codes", ">", 0.5),
        ],
    )

    merged = merge_rule_layers(discovered_rules=[discovered], pinned_rules=[pinned])

    assert len(merged) == 1
    assert merged[0].rule_id == "pinned_r05"
    assert merged[0].source == RuleSource.PINNED


def test_merge_rule_layers_keeps_distinct_rules() -> None:
    discovered = Rule(
        rule_id="discovered_r22",
        source=RuleSource.DISCOVERED,
        conditions=[Condition("is_new_patient_em", ">", 0.5)],
    )
    pinned = Rule(
        rule_id="pinned_r05",
        source=RuleSource.PINNED,
        conditions=[
            Condition("is_surgery", ">", 0.5),
            Condition("multiple_surgical_codes", ">", 0.5),
            Condition("is_first_line", "<=", 0.5),
            Condition("has_modifier_59", "<=", 0.5),
        ],
    )

    merged = merge_rule_layers(discovered_rules=[discovered], pinned_rules=[pinned])

    assert len(merged) == 2
    assert {rule.rule_id for rule in merged} == {"discovered_r22", "pinned_r05"}
