from __future__ import annotations

import hashlib
from typing import Any, Literal


ClaimsObserverMode = Literal["strict", "assisted"]

STRICT_BINARY_INTERACTION_KEYS = {
    "is_surgery",
    "is_em",
    "is_pathology",
    "is_g_code",
    "is_hcpcs_alpha",
    "pos_office",
    "pos_asc",
    "pos_snf",
    "spec_np_or_pa",
    "spec_cardiology",
    "line_role_assistant",
    "diag_is_z_code",
    "diag_is_external_cause",
    "has_modifier_25",
    "in_global_surgery_period",
    "ncci_conflict",
    "em_with_procedure",
    "duplicate_code_on_claim",
    "is_first_line",
    "in_hmo",
    "is_cardiology_code",
    "exactly_7_lines",
    "line_ge_6",
    "is_lower_em",
    "multiple_em_on_claim",
}

NCCI_PAIRS = {
    ("99213", "36415"),
    ("99214", "36415"),
    ("99215", "36415"),
    ("99213", "93000"),
    ("99214", "93000"),
    ("99215", "93000"),
    ("80053", "80048"),
    ("80053", "85025"),
    ("80061", "82465"),
    ("85025", "85027"),
    ("93000", "93010"),
}

_NCCI_SET: set[tuple[str, str]] = set()
for _left, _right in NCCI_PAIRS:
    _NCCI_SET.add((_left, _right))
    _NCCI_SET.add((_right, _left))

EM_CODES = {str(code) for code in range(99201, 99500)}
THERAPY_CODES = {"97001", "97002", "97110", "97112", "97116", "97140", "97150", "97530"}
PROLONGED_CODES = {"99354", "99355", "99356", "99357"}
DIALYSIS_CODES = {"90935", "90937", "90945", "90947"}

EM_LEVEL = {
    "99211": 1,
    "99212": 2,
    "99213": 3,
    "99214": 4,
    "99215": 5,
    "99201": 1,
    "99202": 2,
    "99203": 3,
    "99204": 4,
    "99205": 5,
    "99231": 1,
    "99232": 2,
    "99233": 3,
}

FEE_SCHEDULE = {
    "99201": 45,
    "99202": 75,
    "99203": 110,
    "99204": 170,
    "99205": 225,
    "99211": 25,
    "99212": 50,
    "99213": 95,
    "99214": 140,
    "99215": 195,
    "99231": 40,
    "99232": 75,
    "99233": 105,
    "99354": 110,
    "99355": 55,
    "36415": 5,
    "85025": 12,
    "80053": 15,
    "85610": 8,
    "80061": 20,
    "84443": 25,
    "80048": 12,
    "83036": 15,
    "93000": 20,
    "93010": 10,
    "71010": 25,
    "71020": 30,
    "70553": 450,
    "72148": 350,
    "97110": 35,
    "97140": 35,
    "97530": 40,
    "97001": 80,
    "90834": 110,
    "90837": 155,
    "27447": 1200,
    "29881": 650,
    "43239": 800,
    "27130": 1500,
    "88305": 75,
    "92014": 100,
    "99308": 75,
    "93303": 250,
    "93306": 300,
    "93312": 200,
    "93320": 150,
    "93325": 100,
    "90935": 200,
    "90937": 250,
    "90945": 180,
    "90947": 220,
    "29999": 600,
    "43499": 700,
    "49999": 550,
    "64999": 500,
}


def classify_code(code: str) -> dict[str, int]:
    try:
        numeric = int(code)
    except ValueError:
        return {
            "is_em": 0,
            "is_surgery": 0,
            "is_radiology": 0,
            "is_pathology": 0,
            "is_medicine": 0,
            "is_therapy": 0,
            "is_g_code": int(code.startswith("G")),
            "is_hcpcs_alpha": 1,
            "code_numeric": 0,
            "is_cardiology_code": 0,
            "is_new_patient_em": 0,
            "is_unlisted_code": 0,
        }

    return {
        "is_em": int(99201 <= numeric <= 99499),
        "is_surgery": int(10004 <= numeric <= 69990),
        "is_radiology": int(70010 <= numeric <= 79999),
        "is_pathology": int(80047 <= numeric <= 89398),
        "is_medicine": int(90281 <= numeric <= 99199),
        "is_therapy": int(numeric in (97001, 97002, 97110, 97112, 97116, 97140, 97150, 97530)),
        "is_g_code": 0,
        "is_hcpcs_alpha": 0,
        "code_numeric": numeric,
        "is_cardiology_code": int(93000 <= numeric <= 93799),
        "is_new_patient_em": int(99201 <= numeric <= 99205),
        "is_unlisted_code": int(10004 <= numeric <= 69990 and code.endswith("99")),
    }


def observe_claim(raw: dict[str, Any], mode: ClaimsObserverMode = "strict") -> dict[str, float]:
    if mode not in {"strict", "assisted"}:
        raise ValueError(f"unsupported observer mode: {mode}")

    features: dict[str, float] = {}
    code = str(raw["hcpcs_code"])
    modifier = str(raw.get("modifier", ""))
    primary_diag = str(raw.get("primary_diagnosis", ""))
    line_diag = str(raw.get("line_diagnosis", ""))
    pos = str(raw.get("place_of_service", ""))
    specialty = str(raw.get("provider_specialty", ""))
    all_codes = [str(item) for item in raw.get("all_codes_on_claim", [])]
    n_lines = int(raw.get("n_claim_lines", len(all_codes)))
    line_num = int(raw.get("line_number", 1))
    submitted = float(raw.get("submitted_charge", 0))
    prior_auth = int(raw.get("prior_auth", 0))
    days = int(raw.get("days_since_service", 30))
    service_date = str(raw.get("service_date", "20240115"))
    provider_npi = str(raw.get("provider_npi", "1234567890"))
    bene_state = str(raw.get("bene_state", "CO"))
    bene_age = int(raw.get("bene_age", 75))
    chronic_count = int(raw.get("chronic_condition_count", 2))
    line_role = str(raw.get("line_role", "primary"))
    in_global_period = int(raw.get("in_global_surgery_period", 0))

    code_flags = classify_code(code)
    features.update(code_flags)

    ncci_conflict = 0
    for other in all_codes:
        if other != code and (code, other) in _NCCI_SET:
            ncci_conflict = 1
            break
    features["ncci_conflict"] = ncci_conflict

    features["has_modifier_25"] = int(modifier == "25")
    features["has_modifier_59"] = int(modifier in ("59", "XE", "XS", "XP", "XU"))
    features["has_modifier_50"] = int(modifier == "50")
    features["has_modifier_76_77"] = int(modifier in ("76", "77"))
    features["has_modifier_80_81_82"] = int(modifier in ("80", "81", "82"))
    features["has_modifier_24"] = int(modifier == "24")
    features["has_modifier_AS"] = int(modifier == "AS")
    features["has_any_modifier"] = int(modifier != "")
    features["line_role_assistant"] = int(line_role == "assistant")
    features["line_role_primary"] = int(line_role == "primary")

    has_em_on_claim = any(item in EM_CODES for item in all_codes)
    has_surgery_on_claim = any(classify_code(item)["is_surgery"] for item in all_codes)
    features["em_with_procedure"] = int(has_em_on_claim and has_surgery_on_claim)

    features["pos_office"] = int(pos == "11")
    features["pos_outpatient"] = int(pos == "22")
    features["pos_inpatient"] = int(pos == "21")
    features["pos_asc"] = int(pos == "24")
    features["pos_er"] = int(pos == "23")
    features["pos_snf"] = int(pos == "31")

    features["spec_np_or_pa"] = int(specialty in ("nurse_practitioner", "physician_assistant"))
    features["spec_cardiology"] = int(specialty == "cardiology")
    features["spec_surgery"] = int(specialty in ("orthopedic_surgery", "general_surgery"))
    features["spec_primary_care"] = int(specialty in ("internal_medicine", "family_practice"))

    diagnosis = line_diag or primary_diag
    features["diag_is_z_code"] = int(diagnosis.startswith("Z"))
    features["diag_is_external_cause"] = int(
        diagnosis[:1] in ("V", "W", "X", "Y") and len(diagnosis) > 3 and diagnosis[1:2].isdigit()
    )
    features["claim_primary_is_external_cause"] = int(
        primary_diag[:1] in ("V", "W", "X", "Y")
        and len(primary_diag) > 3
        and primary_diag[1:2].isdigit()
    )

    fee = FEE_SCHEDULE.get(code, 50)
    features["fee_schedule_amount"] = fee
    features["submitted_to_fee_ratio"] = round(submitted / max(fee, 1), 2)
    features["charge_exceeds_3x_fee"] = int(submitted > fee * 3)
    features["is_high_cost_procedure"] = int(fee > 500)

    features["days_since_service"] = days
    features["late_filing"] = int(days > 365)

    features["n_claim_lines"] = n_lines
    features["is_first_line"] = int(line_num == 1)
    features["is_late_line"] = int(line_num > 5)
    features["duplicate_code_on_claim"] = int(all_codes.count(code) > 1)
    features["n_distinct_codes"] = len(set(all_codes))

    therapy_count = sum(1 for item in all_codes if item in THERAPY_CODES)
    features["therapy_count"] = therapy_count

    bene_hmo_months = int(raw.get("bene_hmo_months", 0))
    bene_esrd = int(raw.get("bene_esrd", 0))
    features["bene_hmo_months"] = bene_hmo_months
    features["in_hmo"] = int(bene_hmo_months > 6)
    features["bene_esrd"] = bene_esrd
    features["bene_age"] = bene_age

    features["prior_auth"] = prior_auth

    features["is_prolonged_code"] = int(code in PROLONGED_CODES)
    base_em_present = any(item in EM_CODES and item not in PROLONGED_CODES for item in all_codes)

    surgical_codes_on_claim = [item for item in all_codes if classify_code(item)["is_surgery"]]
    features["multiple_surgical_codes"] = int(len(surgical_codes_on_claim) > 1)
    features["has_surgery_on_claim"] = int(bool(surgical_codes_on_claim))
    features["in_global_surgery_period"] = int(bool(in_global_period))

    em_on_claim = [item for item in all_codes if item in EM_CODES and item not in PROLONGED_CODES]
    features["multiple_em_on_claim"] = int(len(em_on_claim) > 1)
    this_em_level = EM_LEVEL.get(code, 0)
    highest_em = max((EM_LEVEL.get(item, 0) for item in em_on_claim), default=0)
    features["em_level"] = this_em_level
    features["is_lower_em"] = int(this_em_level > 0 and this_em_level < highest_em)
    features["chronic_condition_count"] = chronic_count

    features["exactly_7_lines"] = int(n_lines == 7)
    features["line_ge_6"] = int(line_num >= 6)

    if mode == "assisted":
        features["duplicate_no_bypass_mod"] = int(
            all_codes.count(code) > 1 and line_num > 1 and modifier not in ("76", "77", "50")
        )
        features["therapy_over_limit"] = int(code in THERAPY_CODES and therapy_count > 4 and line_num > 4)
        features["is_dialysis_non_esrd"] = int(code in DIALYSIS_CODES and not bene_esrd)
        features["prolonged_without_base"] = int(code in PROLONGED_CODES and not base_em_present)
        features["surgery_duplicate_no_mod50"] = int(
            code_flags["is_surgery"] and all_codes.count(code) == 2 and modifier != "50" and line_num > 1
        )
        features["elderly_high_chronic"] = int(bene_age > 85 and chronic_count > 5)
        features["em_procedure_no_mod25"] = int(code_flags["is_em"] and has_surgery_on_claim and modifier != "25")
        features["surgery_by_np_pa"] = int(
            code_flags["is_surgery"] and specialty in ("nurse_practitioner", "physician_assistant")
        )
        features["surgery_in_office"] = int(code_flags["is_surgery"] and pos == "11")
        features["lab_with_z_code"] = int(
            code_flags["is_pathology"] and (diagnosis.startswith("Z") or primary_diag.startswith("Z"))
        )
        features["high_cost_no_auth"] = int(code_flags["is_surgery"] and fee > 500 and not prior_auth)
        features["unlisted_no_auth"] = int(code_flags["is_unlisted_code"] and not prior_auth)
        features["em_global_surgery_no_mod24"] = int(code_flags["is_em"] and in_global_period and modifier != "24")
        features["assistant_surgery_missing_modifier"] = int(
            code_flags["is_surgery"] and line_role == "assistant" and modifier not in ("80", "81", "82", "AS")
        )
        features["is_highest_em_on_claim"] = int(this_em_level > 0 and this_em_level >= highest_em)

    try:
        features["claim_month"] = int(service_date[4:6])
    except (TypeError, ValueError, IndexError):
        features["claim_month"] = 1

    try:
        features["claim_day_of_week"] = int(service_date[6:8]) % 7
    except (TypeError, ValueError, IndexError):
        features["claim_day_of_week"] = 0

    state_map = {
        "AL": 1,
        "AK": 2,
        "AZ": 3,
        "AR": 4,
        "CA": 5,
        "CO": 6,
        "CT": 7,
        "DE": 8,
        "FL": 9,
        "GA": 10,
        "HI": 11,
        "ID": 12,
        "IL": 13,
        "IN": 14,
        "IA": 15,
        "KS": 16,
        "KY": 17,
        "LA": 18,
        "ME": 19,
        "MD": 20,
        "MA": 21,
        "MI": 22,
        "MN": 23,
        "MS": 24,
        "MO": 25,
        "MT": 26,
        "NE": 27,
        "NV": 28,
        "NH": 29,
        "NJ": 30,
        "NM": 31,
        "NY": 32,
        "NC": 33,
        "ND": 34,
        "OH": 35,
        "OK": 36,
        "OR": 37,
        "PA": 38,
        "RI": 39,
        "SC": 40,
        "SD": 41,
        "TN": 42,
        "TX": 43,
        "UT": 44,
        "VT": 45,
        "VA": 46,
        "WA": 47,
        "WV": 48,
        "WI": 49,
        "WY": 50,
    }
    features["bene_state_code"] = state_map.get(bene_state, 0)
    features["provider_npi_hash"] = int(hashlib.md5(provider_npi.encode()).hexdigest()[:4], 16) % 100
    features["claim_amount_cents"] = int(round(submitted * 100)) % 100

    binary_features = {key: features[key] for key in STRICT_BINARY_INTERACTION_KEYS}
    if mode == "assisted":
        binary_features["assistant_surgery_missing_modifier"] = features["assistant_surgery_missing_modifier"]
        binary_features["em_global_surgery_no_mod24"] = features["em_global_surgery_no_mod24"]

    keys = sorted(binary_features)
    for index, left in enumerate(keys):
        for right in keys[index + 1 :]:
            features[f"x_{left}_x_{right}"] = binary_features[left] * binary_features[right]

    features["observer_mode_strict"] = int(mode == "strict")
    features["observer_mode_assisted"] = int(mode == "assisted")

    return features

