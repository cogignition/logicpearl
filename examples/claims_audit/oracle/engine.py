"""Mock claims adjudication engine — 25 real Medicare rules + 2 planted bugs.

This simulates an MHK-style rules engine. Each claim line is evaluated against
ALL rules. A line is denied if ANY rule fires. ALL firing rules and their CARC
codes are collected (not first-match-wins).

This oracle previously supported deterministic noise injection:
  - denied lines overridden to paid (supervisor override)
  - clean lines incorrectly denied (system error, CARC 16)

That noise path is currently disabled in code so the benchmark can report clean
oracle-reconstruction accuracy explicitly.

Ground truth for LogicPearl to reverse-engineer.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import hashlib

# NCCI edit pairs (subset of real CMS NCCI PTP edits)
NCCI_PAIRS = {
    ("99213", "36415"), ("99214", "36415"), ("99215", "36415"),  # E&M + venipuncture
    ("99213", "93000"), ("99214", "93000"), ("99215", "93000"),  # E&M + EKG
    ("80053", "80048"), ("80053", "85025"), ("80061", "82465"),  # Lab panels
    ("85025", "85027"), ("93000", "93010"),                       # Overlapping diagnostics
}

# Medicare approximate fee schedule (RVU-based)
FEE_SCHEDULE = {
    "99201": 45, "99202": 75, "99203": 110, "99204": 170, "99205": 225,
    "99211": 25, "99212": 50, "99213": 95, "99214": 140, "99215": 195,
    "99231": 40, "99232": 75, "99233": 105, "99354": 110, "99355": 55,
    "36415": 5, "85025": 12, "80053": 15, "85610": 8, "80061": 20,
    "84443": 25, "80048": 12, "83036": 15, "93000": 20, "93010": 10,
    "71010": 25, "71020": 30, "70553": 450, "72148": 350,
    "97110": 35, "97140": 35, "97530": 40, "97001": 80,
    "90834": 110, "90837": 155, "27447": 1200, "29881": 650,
    "43239": 800, "27130": 1500, "88305": 75,
    "92014": 100, "99308": 75,
    "93303": 250, "93306": 300, "93312": 200, "93320": 150, "93325": 100,
    "90935": 200, "90937": 250, "90945": 180, "90947": 220,  # Dialysis
    "29999": 600, "43499": 700, "49999": 550, "64999": 500,  # Unlisted codes
}

SURGICAL_RANGE = range(10004, 69991)
LAB_RANGE = range(80047, 89399)
EM_CODES = set(str(c) for c in range(99201, 99500))
NEW_PATIENT_EM_CODES = set(str(c) for c in range(99201, 99206))
THERAPY_CODES = {"97001", "97002", "97110", "97112", "97116", "97140", "97150", "97530"}
CARDIOLOGY_CODES = set(str(c) for c in range(93000, 93800))

# EM level ordering for multiple-EM adjudication (R23)
EM_LEVEL = {
    "99211": 1, "99212": 2, "99213": 3, "99214": 4, "99215": 5,
    "99201": 1, "99202": 2, "99203": 3, "99204": 4, "99205": 5,
    "99231": 1, "99232": 2, "99233": 3,
}


@dataclass
class ClaimLine:
    hcpcs: str
    modifier: str = ""          # "25", "59", "50", "80", "81", "82", "24", ""
    diagnosis: str = ""         # ICD-10 code
    submitted_charge: float = 0
    prior_auth: bool = False
    line_number: int = 1
    line_role: str = "primary"  # "primary" or "assistant"


@dataclass
class Claim:
    claim_id: str
    service_date: str           # YYYYMMDD
    provider_specialty: str     # "internal_medicine", "cardiology", "orthopedic_surgery", "nurse_practitioner", etc.
    place_of_service: str       # "11" (office), "21" (inpatient), "22" (outpatient), "24" (ASC), "23" (ER)
    primary_diagnosis: str      # ICD-10 code
    lines: list[ClaimLine] = field(default_factory=list)
    bene_age: int = 75
    bene_sex: int = 1
    bene_state: str = "CO"
    bene_esrd: bool = False
    bene_hmo_months: int = 0
    days_since_service: int = 30
    chronic_condition_count: int = 2
    in_global_surgery_period: bool = False


@dataclass
class RuleFiring:
    """A single rule that fired on a claim line."""
    rule_id: str
    carc: str
    carc_desc: str


@dataclass
class AdjudicationResult:
    line_number: int
    hcpcs: str
    paid: bool
    carc: str = ""              # Primary CARC (first firing rule)
    carc_desc: str = ""
    allowed_amount: float = 0
    payment_amount: float = 0
    rule_id: str = ""           # Primary rule ID
    all_carcs: list[str] = field(default_factory=list)
    all_rule_ids: list[str] = field(default_factory=list)
    noise_type: str = ""        # "", "supervisor_override", "system_error"


def _claim_line_hash(claim_id: str, line_number: int) -> int:
    """Deterministic hash for noise injection. Returns 0-999."""
    h = hashlib.md5(f"{claim_id}:{line_number}".encode()).hexdigest()
    return int(h[:8], 16) % 1000


def adjudicate_claim(claim: Claim) -> list[AdjudicationResult]:
    """Run the mock adjudication engine on a single claim.

    Every rule is evaluated for every line. A line is denied if ANY rule fires.
    All firing rules are recorded. The optional deterministic noise path is
    currently disabled.
    """
    results = []
    all_codes = [line.hcpcs for line in claim.lines]
    all_modifiers = {line.hcpcs: line.modifier for line in claim.lines}
    has_em = any(c in EM_CODES for c in all_codes)
    has_procedure = any(_is_surgical(c) for c in all_codes)

    # Pre-compute: which EM code is highest level on this claim?
    em_codes_on_claim = [c for c in all_codes if c in EM_CODES
                         and c not in ("99354", "99355", "99356", "99357")]
    if em_codes_on_claim:
        highest_em_level = max(EM_LEVEL.get(c, 0) for c in em_codes_on_claim)
    else:
        highest_em_level = 0

    # Pre-compute: does claim have a surgical code? (for global surgery R20)
    surgical_codes_on_claim = [c for c in all_codes if _is_surgical(c)]

    for line in claim.lines:
        firings = _collect_all_firings(
            claim, line, all_codes, all_modifiers, has_em, has_procedure,
            highest_em_level, em_codes_on_claim, surgical_codes_on_claim,
        )
        fee = _get_fee(line.hcpcs)

        if firings:
            # Denied — collect all CARC codes
            result = AdjudicationResult(
                line_number=line.line_number,
                hcpcs=line.hcpcs,
                paid=False,
                carc=firings[0].carc,
                carc_desc=firings[0].carc_desc,
                rule_id=firings[0].rule_id,
                all_carcs=list(dict.fromkeys(f.carc for f in firings)),  # Dedupe, preserve order
                all_rule_ids=[f.rule_id for f in firings],
            )
        else:
            # Paid
            allowed = fee
            payment = fee * 0.80
            result = AdjudicationResult(
                line_number=line.line_number,
                hcpcs=line.hcpcs,
                paid=True,
                allowed_amount=allowed,
                payment_amount=payment,
                rule_id="PAID",
                all_carcs=[],
                all_rule_ids=["PAID"],
            )

        # ── Noise injection ──
        noise_val = _claim_line_hash(claim.claim_id, line.line_number)

        # Noise injection DISABLED — testing if pipeline can reach 100% on clean data
        # if not result.paid and noise_val < 30:
        #     result.paid = True
        #     result.noise_type = "supervisor_override"
        # elif result.paid and noise_val >= 980:
        #     result.paid = False
        #     result.noise_type = "system_error"
        pass

        results.append(result)

    return results


def _is_surgical(code: str) -> bool:
    try:
        return int(code) in SURGICAL_RANGE
    except ValueError:
        return False


def _is_lab(code: str) -> bool:
    try:
        return int(code) in LAB_RANGE
    except ValueError:
        return False


def _is_unlisted(code: str) -> bool:
    """Unlisted procedure codes end in 99 within surgical range."""
    try:
        num = int(code)
        return num in SURGICAL_RANGE and code.endswith("99")
    except ValueError:
        return False


def _get_fee(code: str) -> float:
    return FEE_SCHEDULE.get(code, 50)


def _collect_all_firings(
    claim: Claim,
    line: ClaimLine,
    all_codes: list[str],
    all_modifiers: dict[str, str],
    has_em: bool,
    has_procedure: bool,
    highest_em_level: int,
    em_codes_on_claim: list[str],
    surgical_codes_on_claim: list[str],
) -> list[RuleFiring]:
    """Apply all 25 rules + 2 bugs to a single line. Return ALL that fire."""

    firings: list[RuleFiring] = []
    code = line.hcpcs
    fee = _get_fee(code)

    # ── Rule 1: NCCI bundling (venipuncture with E&M, lab panel overlap) ──
    for other in all_codes:
        if other == code:
            continue
        pair = (other, code)
        reverse = (code, other)
        if pair in NCCI_PAIRS or reverse in NCCI_PAIRS:
            if line.modifier not in ("59", "XE", "XS", "XP", "XU"):
                firings.append(RuleFiring(
                    rule_id="R01_ncci_bundling",
                    carc="97",
                    carc_desc="NCCI bundling — included in another service",
                ))
                break  # One NCCI firing per line is enough

    # ── Rule 3: Duplicate code ──
    # Assistant surgeon lines are not duplicate billing. They are separately
    # identified supporting lines and must bypass duplicate logic; otherwise
    # they shadow the assistant surgeon rule entirely.
    if all_codes.count(code) > 1 and line.line_number > 1:
        if line.line_role != "assistant" and line.modifier not in ("76", "77", "50", "80", "81", "82", "AS"):
            firings.append(RuleFiring(
                rule_id="R03_duplicate",
                carc="18",
                carc_desc="Duplicate claim/service",
            ))

    # ── Rule 4: Modifier 25 required (E&M + procedure, no mod 25) ──
    if code in EM_CODES and has_procedure and line.modifier != "25":
        firings.append(RuleFiring(
            rule_id="R04_mod25_required",
            carc="4",
            carc_desc="Modifier required — E&M with procedure needs modifier 25",
        ))

    # ── Rule 5: Modifier 59 required (two procedures, no mod 59) ──
    if _is_surgical(code) and sum(1 for c in all_codes if _is_surgical(c)) > 1:
        if line.line_number > 1 and line.modifier not in ("59", "XE", "XS", "XP", "XU"):
            firings.append(RuleFiring(
                rule_id="R05_mod59_required",
                carc="97",
                carc_desc="Modifier 59 required for distinct procedure",
            ))

    # ── Rule 6: POS restriction (surgery in office) ──
    if _is_surgical(code) and claim.place_of_service == "11":
        firings.append(RuleFiring(
            rule_id="R06_pos_restriction",
            carc="204",
            carc_desc="Service not covered in this place of service",
        ))

    # ── Rule 7: Provider specialty (NP/PA can't bill surgery) ──
    if _is_surgical(code) and claim.provider_specialty in ("nurse_practitioner", "physician_assistant"):
        firings.append(RuleFiring(
            rule_id="R07_specialty_restriction",
            carc="185",
            carc_desc="Provider not certified for this procedure",
        ))

    # ── Rule 8: Quality measures not separately payable ──
    if code.startswith("G") and not code.startswith("G0"):
        firings.append(RuleFiring(
            rule_id="R08_quality_measure",
            carc="96",
            carc_desc="Quality measure — not separately payable",
        ))

    # ── Rule 9: Medical necessity (lab + Z-code) ──
    diag = line.diagnosis or claim.primary_diagnosis
    if _is_lab(code) and diag.startswith("Z"):
        firings.append(RuleFiring(
            rule_id="R09_medical_necessity",
            carc="167",
            carc_desc="Diagnosis does not support medical necessity",
        ))

    # ── Rule 10: E-code as primary ──
    if claim.primary_diagnosis.startswith(("V", "W", "X", "Y")) and len(claim.primary_diagnosis) > 3:
        if claim.primary_diagnosis[1:2].isdigit():
            firings.append(RuleFiring(
                rule_id="R10_external_cause",
                carc="50",
                carc_desc="External cause code as primary diagnosis",
            ))

    # ── Rule 11: Fee schedule cap ──
    if line.submitted_charge > fee * 3 and fee > 0:
        firings.append(RuleFiring(
            rule_id="R11_fee_cap",
            carc="45",
            carc_desc="Charge exceeds fee schedule maximum",
        ))

    # ── Rule 12: Timely filing ──
    if claim.days_since_service > 365:
        firings.append(RuleFiring(
            rule_id="R12_timely_filing",
            carc="29",
            carc_desc="Time limit for filing has expired",
        ))

    # ── Rule 13: Frequency limit (therapy) ──
    therapy_count = sum(1 for c in all_codes if c in THERAPY_CODES)
    if code in THERAPY_CODES and therapy_count > 4 and line.line_number > 4:
        firings.append(RuleFiring(
            rule_id="R13_frequency_limit",
            carc="119",
            carc_desc="Benefit maximum for this time period",
        ))

    # ── Rule 14: HMO exclusion ──
    if claim.bene_hmo_months > 6:
        firings.append(RuleFiring(
            rule_id="R14_hmo_exclusion",
            carc="22",
            carc_desc="Covered by another payer (Medicare Advantage)",
        ))

    # ── Rule 15: ESRD dialysis check ──
    if code in ("90935", "90937", "90945", "90947") and not claim.bene_esrd:
        firings.append(RuleFiring(
            rule_id="R15_esrd_check",
            carc="50",
            carc_desc="Dialysis code for non-ESRD patient",
        ))

    # ── Rule 16: High-cost surgery without prior auth ──
    if _is_surgical(code) and fee > 500 and not line.prior_auth:
        firings.append(RuleFiring(
            rule_id="R16_prior_auth",
            carc="197",
            carc_desc="Prior authorization required",
        ))

    # ── Rule 17: Prolonged E&M without base E&M ──
    if code in ("99354", "99355", "99356", "99357"):
        base_em = any(c in EM_CODES and c not in ("99354", "99355", "99356", "99357")
                      for c in all_codes)
        if not base_em:
            firings.append(RuleFiring(
                rule_id="R17_prolonged_no_base",
                carc="4",
                carc_desc="Prolonged service without base E&M code",
            ))

    # ── Rule 18: Bilateral without modifier 50 ──
    # Assistant surgeon lines must bypass this rule; otherwise an assistant
    # claim is mislabeled as bilateral and R19 can never surface as primary.
    if (_is_surgical(code) and all_codes.count(code) == 2
            and line.line_role != "assistant"
            and line.modifier not in ("50", "80", "81", "82", "AS")):
        if line.line_number > 1:
            firings.append(RuleFiring(
                rule_id="R18_bilateral",
                carc="4",
                carc_desc="Bilateral procedure requires modifier 50",
            ))

    # ── Rule 19: Assistant surgeon without modifier 80/81/82 ──
    # The previous demo encoded this as a duplicate-surgery proxy, which was
    # shadowed by the duplicate and bilateral rules above. The corrected version
    # uses an explicit assistant-line role so the rule is independently learnable.
    if (_is_surgical(code)
            and line.line_role == "assistant"
            and len(surgical_codes_on_claim) > 1
            and line.modifier not in ("80", "81", "82", "AS")):
        firings.append(RuleFiring(
            rule_id="R19_assistant_surgeon",
            carc="4",
            carc_desc="Assistant surgeon modifier 80/81/82 required",
        ))

    # ── Rule 20: Global surgery period — E&M within global period of surgery ──
    # The previous same-claim proxy overlapped with R04 modifier-25 logic and
    # made R20 unreachable as a primary label. The corrected version uses an
    # explicit claim-level global-period flag, which mirrors how real engines
    # reason across prior claims.
    if (code in EM_CODES
            and code not in ("99354", "99355", "99356", "99357")
            and claim.in_global_surgery_period
            and line.modifier != "24"):
        firings.append(RuleFiring(
            rule_id="R20_global_surgery",
            carc="97",
            carc_desc="E&M within global surgery period without modifier 24",
        ))

    # ── Rule 21: Unlisted procedure code requires documentation ──
    if _is_unlisted(code) and not line.prior_auth:
        # Unlisted codes require operative report / documentation.
        # Simplified: deny if no prior auth (proxy for documentation on file).
        firings.append(RuleFiring(
            rule_id="R21_unlisted_code",
            carc="16",
            carc_desc="Unlisted procedure code — documentation required",
        ))

    # ── Rule 22: New patient E&M, age > 85, high chronic burden ──
    if (code in NEW_PATIENT_EM_CODES
            and claim.bene_age > 85
            and claim.chronic_condition_count > 5):
        firings.append(RuleFiring(
            rule_id="R22_utilization_review",
            carc="119",
            carc_desc="Utilization review — new patient E&M for elderly with high chronic burden",
        ))

    # ── Rule 23: Multiple E&M codes on same claim — deny all but highest ──
    if (code in EM_CODES
            and code not in ("99354", "99355", "99356", "99357")
            and len(em_codes_on_claim) > 1):
        this_level = EM_LEVEL.get(code, 0)
        if this_level < highest_em_level:
            firings.append(RuleFiring(
                rule_id="R23_multiple_em",
                carc="97",
                carc_desc="Multiple E&M codes — only highest level payable",
            ))

    # ── PLANTED BUG 19: Cardiology + ASC incorrectly denied ──
    if (claim.provider_specialty == "cardiology"
            and claim.place_of_service == "24"
            and code in CARDIOLOGY_CODES):
        firings.append(RuleFiring(
            rule_id="BUG19_cardiology_asc",
            carc="204",
            carc_desc="Service not covered in this place of service",
        ))

    # ── PLANTED BUG 20: 7-line claim edge case ──
    if len(all_codes) == 7 and line.line_number >= 6:
        firings.append(RuleFiring(
            rule_id="BUG20_seven_line",
            carc="16",
            carc_desc="Claim lacks information for adjudication",
        ))

    return firings


# Rule manifest for verification
RULE_MANIFEST = {
    "R01_ncci_bundling": {"carc": "97", "desc": "NCCI bundling edit", "type": "billing"},
    "R03_duplicate": {"carc": "18", "desc": "Duplicate claim/service", "type": "billing"},
    "R04_mod25_required": {"carc": "4", "desc": "Modifier 25 required for E&M with procedure", "type": "billing"},
    "R05_mod59_required": {"carc": "97", "desc": "Modifier 59 required for distinct procedures", "type": "billing"},
    "R06_pos_restriction": {"carc": "204", "desc": "Surgery not covered in office setting", "type": "coverage"},
    "R07_specialty_restriction": {"carc": "185", "desc": "NP/PA cannot bill surgical codes", "type": "coverage"},
    "R08_quality_measure": {"carc": "96", "desc": "Quality measure not separately payable", "type": "coverage"},
    "R09_medical_necessity": {"carc": "167", "desc": "Lab with Z-code diagnosis — no medical necessity", "type": "coverage"},
    "R10_external_cause": {"carc": "50", "desc": "External cause code as primary diagnosis", "type": "coverage"},
    "R11_fee_cap": {"carc": "45", "desc": "Submitted charge exceeds 3x fee schedule", "type": "financial"},
    "R12_timely_filing": {"carc": "29", "desc": "Filed after 365-day limit", "type": "financial"},
    "R13_frequency_limit": {"carc": "119", "desc": "Therapy frequency exceeded (>4 per claim)", "type": "financial"},
    "R14_hmo_exclusion": {"carc": "22", "desc": "Patient in Medicare Advantage HMO", "type": "patient"},
    "R15_esrd_check": {"carc": "50", "desc": "Dialysis code for non-ESRD patient", "type": "patient"},
    "R16_prior_auth": {"carc": "197", "desc": "High-cost surgery without prior authorization", "type": "compound"},
    "R17_prolonged_no_base": {"carc": "4", "desc": "Prolonged service without base E&M", "type": "compound"},
    "R18_bilateral": {"carc": "4", "desc": "Bilateral procedure without modifier 50", "type": "compound"},
    "R19_assistant_surgeon": {"carc": "4", "desc": "Assistant surgeon without modifier 80/81/82", "type": "billing"},
    "R20_global_surgery": {"carc": "97", "desc": "E&M within global surgery period without modifier 24", "type": "billing"},
    "R21_unlisted_code": {"carc": "16", "desc": "Unlisted procedure code without documentation", "type": "coverage"},
    "R22_utilization_review": {"carc": "119", "desc": "New patient E&M, elderly with high chronic burden", "type": "coverage"},
    "R23_multiple_em": {"carc": "97", "desc": "Multiple E&M codes — only highest level payable", "type": "billing"},
    "BUG19_cardiology_asc": {"carc": "204", "desc": "BUG: Cardiology in ASC incorrectly denied", "type": "bug"},
    "BUG20_seven_line": {"carc": "16", "desc": "BUG: 7-line claim processing edge case", "type": "bug"},
}
