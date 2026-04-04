from __future__ import annotations

import re
from enum import Enum

from pydantic import Field, field_validator

from logicpearl.ir.models import LogicPearlModel

from .models import CodeCluster, EvidenceRequirementKind, HealthcarePolicySlice
from .request_eval import EvidenceDocument, extract_candidate_assertions


class MappingValidationExpectation(str, Enum):
    SHOULD_MATCH = "should_match"
    SHOULD_NOT_MATCH = "should_not_match"
    SHOULD_AMBIGUOUS_OR_NOT_MATCH = "should_ambiguous_or_not_match"


class MappingValidationFixtureKind(str, Enum):
    POSITIVE_CLEAR = "positive_clear"
    POSITIVE_CODE_ONLY = "positive_code_only"
    POSITIVE_ALIAS_ONLY = "positive_alias_only"
    NEGATIVE_BOILERPLATE = "negative_boilerplate"
    NEGATIVE_FUTURE_PLAN = "negative_future_plan"
    NEGATIVE_SIBLING_CLUSTER = "negative_sibling_cluster"
    AMBIGUOUS_WEAK_EVIDENCE = "ambiguous_weak_evidence"


class MappingValidationFixture(LogicPearlModel):
    fixture_id: str
    cluster_id: str
    kind: MappingValidationFixtureKind
    expectation: MappingValidationExpectation
    text: str
    note: str

    @field_validator("fixture_id", "cluster_id", "text", "note")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("mapping validation fixture fields must be non-empty")
        return value


class MappingValidationResult(LogicPearlModel):
    fixture_id: str
    cluster_id: str
    kind: MappingValidationFixtureKind
    expectation: MappingValidationExpectation
    matched: bool
    passed: bool
    matched_assertion_ids: list[str] = Field(default_factory=list)
    note: str

    @field_validator("fixture_id", "cluster_id", "note")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        if not value:
            raise ValueError("mapping validation result fields must be non-empty")
        return value


class MappingValidationSuite(LogicPearlModel):
    policy_id: str
    fixture_count: int
    passed_count: int
    failed_count: int
    results: list[MappingValidationResult]

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        if not value:
            raise ValueError("policy_id must be non-empty")
        return value


def build_mapping_validation_fixtures(policy: HealthcarePolicySlice) -> list[MappingValidationFixture]:
    fixtures: list[MappingValidationFixture] = []
    for cluster in policy.clusters:
        fixtures.extend(_fixtures_for_cluster(policy, cluster))
    return fixtures


def validate_cluster_mappings(
    policy: HealthcarePolicySlice,
    fixtures: list[MappingValidationFixture],
) -> MappingValidationSuite:
    results: list[MappingValidationResult] = []
    for fixture in fixtures:
        document = EvidenceDocument(
            document_id=fixture.fixture_id,
            kind="validation_fixture",
            text=fixture.text,
            source="mapping_validation",
            citation=f"{fixture.fixture_id}#text",
        )
        matched_assertions = [
            assertion.assertion_id
            for assertion in extract_candidate_assertions(policy, [document])
            if assertion.cluster_id == fixture.cluster_id
        ]
        matched = bool(matched_assertions)
        if fixture.expectation == MappingValidationExpectation.SHOULD_MATCH:
            passed = matched
        elif fixture.expectation == MappingValidationExpectation.SHOULD_NOT_MATCH:
            passed = not matched
        else:
            passed = not matched
        results.append(
            MappingValidationResult(
                fixture_id=fixture.fixture_id,
                cluster_id=fixture.cluster_id,
                kind=fixture.kind,
                expectation=fixture.expectation,
                matched=matched,
                passed=passed,
                matched_assertion_ids=matched_assertions,
                note=fixture.note,
            )
        )
    passed_count = sum(1 for result in results if result.passed)
    return MappingValidationSuite(
        policy_id=policy.policy_id,
        fixture_count=len(results),
        passed_count=passed_count,
        failed_count=len(results) - passed_count,
        results=results,
    )


def _positive_fixture_text(cluster: CodeCluster) -> str:
    alias = cluster.aliases[0] if cluster.aliases else cluster.label
    code = cluster.codes[0] if cluster.codes else alias.upper().replace(" ", "_")
    if cluster.kind == "diagnosis":
        return f"Clinical review note documents diagnosis of {alias}. Supporting diagnosis code {code} is present."
    if cluster.kind == "procedure":
        return f"Office note documents prior completion of {alias}. Procedure history shows code {code}."
    if cluster.kind == "medication":
        return f"Medication history documents prior trial of {alias}. Pharmacy evidence includes code {code}."
    return f"Clinical documentation records {alias}. Supporting evidence code {code} is present."


def _fixtures_for_cluster(
    policy: HealthcarePolicySlice,
    cluster: CodeCluster,
) -> list[MappingValidationFixture]:
    alias = _preferred_alias(cluster)
    code = _preferred_code(cluster)
    sibling_alias = _sibling_alias(policy, cluster)

    fixtures = [
        MappingValidationFixture(
            fixture_id=f"{cluster.cluster_id}__positive_clear",
            cluster_id=cluster.cluster_id,
            kind=MappingValidationFixtureKind.POSITIVE_CLEAR,
            expectation=MappingValidationExpectation.SHOULD_MATCH,
            text=_positive_fixture_text(cluster),
            note="Strong positive control with evidence wording plus alias and code.",
        ),
        MappingValidationFixture(
            fixture_id=f"{cluster.cluster_id}__positive_code_only",
            cluster_id=cluster.cluster_id,
            kind=MappingValidationFixtureKind.POSITIVE_CODE_ONLY,
            expectation=MappingValidationExpectation.SHOULD_MATCH,
            text=_code_only_positive_text(cluster, code),
            note="Positive control where only machine-code style evidence is present.",
        ),
        MappingValidationFixture(
            fixture_id=f"{cluster.cluster_id}__positive_alias_only",
            cluster_id=cluster.cluster_id,
            kind=MappingValidationFixtureKind.POSITIVE_ALIAS_ONLY,
            expectation=MappingValidationExpectation.SHOULD_MATCH,
            text=_alias_only_positive_text(cluster, alias),
            note="Positive control using reviewed alias text without machine code.",
        ),
        MappingValidationFixture(
            fixture_id=f"{cluster.cluster_id}__negative_boilerplate",
            cluster_id=cluster.cluster_id,
            kind=MappingValidationFixtureKind.NEGATIVE_BOILERPLATE,
            expectation=MappingValidationExpectation.SHOULD_NOT_MATCH,
            text=_negative_boilerplate_text(cluster),
            note="Negative control containing generic payer/workflow boilerplate only.",
        ),
        MappingValidationFixture(
            fixture_id=f"{cluster.cluster_id}__negative_future_plan",
            cluster_id=cluster.cluster_id,
            kind=MappingValidationFixtureKind.NEGATIVE_FUTURE_PLAN,
            expectation=MappingValidationExpectation.SHOULD_NOT_MATCH,
            text=_future_plan_negative_text(cluster, alias),
            note="Near-miss negative where the note plans future action instead of documenting prior evidence.",
        ),
        MappingValidationFixture(
            fixture_id=f"{cluster.cluster_id}__ambiguous_weak_evidence",
            cluster_id=cluster.cluster_id,
            kind=MappingValidationFixtureKind.AMBIGUOUS_WEAK_EVIDENCE,
            expectation=MappingValidationExpectation.SHOULD_AMBIGUOUS_OR_NOT_MATCH,
            text=_ambiguous_text(cluster, alias),
            note="Weak evidence control that should not silently validate as a clean match.",
        ),
    ]
    if sibling_alias:
        fixtures.append(
            MappingValidationFixture(
                fixture_id=f"{cluster.cluster_id}__negative_sibling_cluster",
                cluster_id=cluster.cluster_id,
                kind=MappingValidationFixtureKind.NEGATIVE_SIBLING_CLUSTER,
                expectation=MappingValidationExpectation.SHOULD_NOT_MATCH,
                text=_sibling_negative_text(cluster, sibling_alias),
                note="Negative control with evidence for a related cluster, not this cluster.",
            )
        )
    return fixtures


def _negative_boilerplate_text(cluster: CodeCluster) -> str:
    return (
        "Administrative cover sheet only. "
        "Clinical attachments are pending and no clinical evidence text is present in this packet."
    )


def _code_only_positive_text(cluster: CodeCluster, code: str) -> str:
    if cluster.kind == "diagnosis":
        return f"Diagnosis history confirms qualifying evidence with code {code}."
    if cluster.kind == "procedure":
        return f"Procedure history confirms qualifying prior service with code {code}."
    if cluster.kind == "medication":
        return f"Medication history confirms qualifying prior therapy with code {code}."
    return f"Supporting documentation references validated evidence code {code}."


def _alias_only_positive_text(cluster: CodeCluster, alias: str) -> str:
    if cluster.kind == "diagnosis":
        return f"Clinical review note documents diagnosis of {alias}."
    if cluster.kind == "procedure":
        return f"Office note documents prior completion of {alias}."
    if cluster.kind == "medication":
        return f"Medication history documents prior trial of {alias}."
    return f"Clinical documentation records {alias} in the supporting packet."


def _future_plan_negative_text(cluster: CodeCluster, alias: str) -> str:
    if cluster.kind == "diagnosis":
        return f"Provider plans to evaluate the member for possible {alias} at a future visit."
    if cluster.kind == "procedure":
        return f"Provider plans to try {alias} next if symptoms persist."
    if cluster.kind == "medication":
        return f"Provider plans to start {alias} next month if current treatment fails."
    return f"Provider requests future documentation for possible {alias} if needed."


def _ambiguous_text(cluster: CodeCluster, alias: str) -> str:
    if cluster.kind == "diagnosis":
        return f"Outside records possibly mention {alias}, but the diagnosis is not confirmed in the packet."
    if cluster.kind == "procedure":
        return f"Outside note suggests prior {alias}, but there is no confirmed report attached."
    if cluster.kind == "medication":
        return f"Outside note suggests possible prior {alias}, but the history is incomplete."
    return f"Packet may contain reference to {alias}, but supporting evidence is incomplete."


def _sibling_negative_text(cluster: CodeCluster, sibling_alias: str) -> str:
    return f"Clinical note documents {sibling_alias}. No other relevant evidence is present."


def _preferred_alias(cluster: CodeCluster) -> str:
    aliases = _filtered_aliases(cluster)
    if aliases:
        return aliases[0]
    return cluster.label.replace(":", "").strip()


def _preferred_code(cluster: CodeCluster) -> str:
    for code in cluster.codes:
        normalized = code.strip()
        if normalized:
            return normalized
    return re.sub(r"[^A-Z0-9]+", "_", cluster.cluster_id.upper()).strip("_")


def _sibling_alias(policy: HealthcarePolicySlice, cluster: CodeCluster) -> str | None:
    for sibling in policy.clusters:
        if sibling.cluster_id == cluster.cluster_id:
            continue
        aliases = _filtered_aliases(sibling)
        if aliases:
            return aliases[0]
    return None


def _filtered_aliases(cluster: CodeCluster) -> list[str]:
    blocked = {
        "pa, qcd",
        "step therapy",
        "managed care",
        "ppo/epo",
        "medex with rx plans",
        "medex with rx plans*",
        "indemnity",
        "ndemnity",
        "clinical documentation",
        "references from consensus documents and/or nationally sanctioned guidelines",
        "a clinician’s or physician’s office",
        "a clinician's or physician's office",
        "a home health care provider",
        "a home infusion therapy provider",
        "outpatient hospital and dialysis settings",
        "surgical day care",
        "policy does not apply to",
    }
    aliases: list[str] = []
    seen: set[str] = set()
    for alias in cluster.aliases:
        normalized = " ".join(alias.split()).strip()
        lowered = normalized.lower()
        if not normalized or lowered in blocked:
            continue
        if len(re.findall(r"[a-z0-9]+", lowered)) < 2 and not re.search(r"\d", lowered):
            continue
        if len(normalized) < 8:
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        aliases.append(normalized)
    return aliases
