from logicpearl.domains.healthcare_policy.corpus import (
    CorpusDocumentKind,
    classify_corpus_document,
    decode_bcbsma_filename,
    derive_document_id,
    extract_policy_number,
    guess_title_from_filename,
    is_decision_bearing,
)


def test_filename_decoding_and_document_id_are_stable() -> None:
    filename = "014_20Veozah_20Step_20Policy.pdf"

    assert decode_bcbsma_filename(filename) == "014 Veozah Step Policy"
    assert guess_title_from_filename(filename) == "014 Veozah Step Policy"
    assert derive_document_id(filename) == "014-veozah-step-policy"
    assert extract_policy_number(filename) == "014"


def test_classify_corpus_document_identifies_prior_auth_form() -> None:
    kind, signals = classify_corpus_document(
        "129_20Prior_20Authorization_20Request_20Form_20for_20Treatment_20of_20Varicose_20Veins.pdf",
        "Prior Authorization Request Form for Treatment of Varicose Veins",
    )

    assert kind is CorpusDocumentKind.PRIOR_AUTH_FORM
    assert "prior_auth_form_title" in signals
    assert not is_decision_bearing(kind)


def test_classify_corpus_document_identifies_code_reference() -> None:
    kind, signals = classify_corpus_document(
        "932_20Carelon_20Chest_20Imaging_20CPT_20and_20Diagnoses_20Codes_20prn.pdf",
        "Carelon Chest Imaging CPT and Diagnoses Codes",
    )

    assert kind is CorpusDocumentKind.CODE_REFERENCE
    assert "code_reference_title" in signals


def test_classify_corpus_document_identifies_medication_policy() -> None:
    kind, signals = classify_corpus_document(
        "014_20Veozah_20Step_20Policy.pdf",
        "Step Therapy Policy Criteria for Veozah.",
    )

    assert kind is CorpusDocumentKind.MEDICATION_POLICY
    assert "medication_policy_phrase" in signals
    assert is_decision_bearing(kind)


def test_classify_corpus_document_identifies_medical_policy() -> None:
    kind, signals = classify_corpus_document(
        "583_20Tibial_20Nerve_20Stimulation.pdf",
        "Medical Policy Statement: Tibial Nerve Stimulation may be medically necessary.",
    )

    assert kind is CorpusDocumentKind.MEDICAL_POLICY
    assert "medical_policy_header" in signals
    assert is_decision_bearing(kind)


def test_classify_corpus_document_treats_management_program_as_administrative() -> None:
    kind, signals = classify_corpus_document(
        "099_20Carelon_20Oncology_20Medication_20Management_20Program.pdf",
        "",
    )

    assert kind is CorpusDocumentKind.ADMINISTRATIVE
    assert "administrative_title" in signals
    assert "empty_text" in signals
    assert not is_decision_bearing(kind)
