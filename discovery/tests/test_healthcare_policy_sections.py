from logicpearl.domains.healthcare_policy.sections import extract_policy_sections, match_section_heading


def test_match_section_heading_identifies_known_headings() -> None:
    assert match_section_heading("Policy") == "policy"
    assert match_section_heading("Prior Authorization Information") == "prior_authorization_information"
    assert match_section_heading("Coding Information") == "coding_information"
    assert match_section_heading("Unrelated Heading") is None


def test_extract_policy_sections_splits_common_policy_structure() -> None:
    payload = """=== Page 1 ===
Medical Policy

Policy
This service may be considered medically necessary.

Prior Authorization Information
Prior authorization is required.

Coding Information
CPT 12345
"""

    sections = extract_policy_sections(payload)

    assert [section.section_kind for section in sections] == [
        "document_body",
        "policy",
        "prior_authorization_information",
        "coding_information",
    ]
    assert sections[1].text == "This service may be considered medically necessary."
    assert sections[2].page_start == 1
