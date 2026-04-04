#!/usr/bin/env python3
"""Generate realistic claims, run through the adjudication engine, and export traces.

Generates 50,000 claims with realistic distributions of:
- Procedure codes, diagnoses, modifiers
- Provider specialties and places of service
- Beneficiary demographics
- Mix of clean claims (should pay) and claims that trigger various rules
"""

import json
import random
from pathlib import Path
from engine import Claim, ClaimLine, adjudicate_claim, FEE_SCHEDULE, RULE_MANIFEST

DATA_DIR = Path(__file__).parent / "data"

# Realistic distributions
SPECIALTIES = [
    ("internal_medicine", 25), ("family_practice", 20), ("cardiology", 10),
    ("orthopedic_surgery", 8), ("general_surgery", 5), ("dermatology", 5),
    ("ophthalmology", 5), ("nurse_practitioner", 8), ("physician_assistant", 4),
    ("psychiatry", 3), ("physical_therapy", 4), ("radiology", 3),
]

PLACES_OF_SERVICE = [
    ("11", 50),  # Office
    ("22", 20),  # Outpatient hospital
    ("21", 10),  # Inpatient
    ("23", 5),   # ER
    ("24", 8),   # ASC
    ("31", 4),   # SNF
    ("65", 3),   # ESRD facility
]

# Common procedure codes with realistic frequency
COMMON_CODES = [
    ("99213", 20), ("99214", 15), ("99212", 8), ("99215", 5), ("99211", 3),
    ("99232", 5), ("99233", 3), ("99231", 3),
    ("36415", 8), ("85025", 5), ("80053", 4), ("85610", 3), ("80061", 3),
    ("84443", 2), ("80048", 2), ("83036", 2),
    ("93000", 4), ("93010", 2), ("93303", 1), ("93306", 1),
    ("71010", 3), ("71020", 2), ("70553", 1), ("72148", 1),
    ("97110", 4), ("97140", 2), ("97530", 2), ("97001", 1),
    ("90834", 2), ("90837", 1),
    ("27447", 1), ("29881", 1), ("43239", 1), ("27130", 0.5),
    ("88305", 1), ("92014", 2), ("99308", 1),
    ("G8447", 1), ("G8453", 0.5), ("G9143", 0.5),
    ("99354", 0.5), ("99355", 0.3),
    ("93312", 1), ("93320", 1), ("93325", 1),
    ("64999", 0.2), ("49999", 0.2),
]

DIAGNOSES = [
    ("I10", 15),     # Hypertension
    ("E11.9", 10),   # Type 2 diabetes
    ("M54.5", 8),    # Low back pain
    ("J06.9", 5),    # Upper respiratory infection
    ("K21.0", 4),    # GERD
    ("M17.11", 3),   # Knee osteoarthritis
    ("F32.1", 3),    # Major depression
    ("G89.29", 2),   # Chronic pain
    ("N18.3", 2),    # CKD stage 3
    ("Z00.00", 4),   # Routine exam (Z-code)
    ("Z12.31", 2),   # Screening mammogram (Z-code)
    ("Z23", 2),      # Immunization encounter (Z-code)
    ("R10.9", 2),    # Abdominal pain
    ("R51", 2),      # Headache
    ("W19.XXXA", 1), # Fall (external cause)
    ("V43.12XA", 0.5), # Car accident (external cause)
]

STATES = ["CO", "CA", "TX", "FL", "NY", "PA", "OH", "IL", "MI", "NC"]


def weighted_choice(items, rng):
    """Choose from weighted list."""
    total = sum(w for _, w in items)
    r = rng.uniform(0, total)
    cumulative = 0
    for item, weight in items:
        cumulative += weight
        if r <= cumulative:
            return item
    return items[-1][0]


def generate_claims(n: int = 50000, seed: int = 42) -> list[dict]:
    """Generate n realistic claims and adjudicate them."""
    rng = random.Random(seed)
    all_results = []
    rule_counts = {}

    for i in range(n):
        specialty = weighted_choice(SPECIALTIES, rng)
        pos = weighted_choice(PLACES_OF_SERVICE, rng)
        primary_diag = weighted_choice(DIAGNOSES, rng)
        age = rng.randint(22, 95)  # Include disability Medicare
        hmo_months = rng.choice([0]*8 + [3, 6, 9, 12])  # 80% FFS, 20% HMO
        esrd = rng.random() < 0.03  # 3% ESRD
        days_since = rng.choice([rng.randint(10, 90)] * 9 + [rng.randint(300, 500)])  # 10% late filing

        # Generate 1-8 line items
        n_lines = rng.choices([1, 2, 3, 4, 5, 6, 7, 8],
                               weights=[20, 25, 20, 15, 10, 5, 3, 2])[0]

        lines = []
        for j in range(n_lines):
            code = weighted_choice(COMMON_CODES, rng)
            fee = FEE_SCHEDULE.get(code, 50)

            # Modifier logic
            modifier = ""
            if code in ("99213", "99214", "99215") and n_lines > 1:
                modifier = rng.choice(["25", "25", "25", ""])  # 75% have mod 25 when needed
            elif code in ("29881", "43239", "27447", "27130") and j > 0:
                modifier = rng.choice(["59", "59", ""])  # 67% have mod 59
            elif rng.random() < 0.05:
                modifier = rng.choice(["50", "76", ""])

            # Submitted charge (1.2-2.5x fee schedule, rarely above 3x)
            charge_multiplier = rng.choice([rng.uniform(1.2, 2.5)] * 9 + [rng.uniform(3.0, 5.0)])
            submitted = round(fee * charge_multiplier, 2)

            # Prior auth for surgical codes
            prior_auth = rng.random() < 0.7 if fee > 500 else False

            # Line diagnosis — sometimes different from primary
            line_diag = primary_diag if rng.random() < 0.7 else weighted_choice(DIAGNOSES, rng)

            lines.append(ClaimLine(
                hcpcs=code, modifier=modifier, diagnosis=line_diag,
                submitted_charge=submitted, prior_auth=prior_auth,
                line_number=j + 1,
            ))

        chronic_count = rng.randint(0, 8)
        claim = Claim(
            claim_id=f"CLM{i:06d}",
            service_date=f"2024{rng.randint(1,12):02d}{rng.randint(1,28):02d}",
            provider_specialty=specialty,
            place_of_service=pos,
            primary_diagnosis=primary_diag,
            lines=lines,
            bene_age=age,
            bene_sex=rng.choice([1, 2]),
            bene_state=rng.choice(STATES),
            bene_esrd=esrd,
            bene_hmo_months=hmo_months,
            days_since_service=days_since,
            chronic_condition_count=chronic_count,
            in_global_surgery_period=False,
        )

        # Adjudicate
        results = adjudicate_claim(claim)

        for line, result in zip(claim.lines, results):
            rule_counts[result.rule_id] = rule_counts.get(result.rule_id, 0) + 1

            all_results.append({
                "input": {
                    # Claim-level
                    "provider_specialty": specialty,
                    "place_of_service": pos,
                    "primary_diagnosis": primary_diag,
                    "bene_age": age,
                    "bene_sex": claim.bene_sex,
                    "bene_state": claim.bene_state,
                    "bene_esrd": int(esrd),
                    "bene_hmo_months": hmo_months,
                    "days_since_service": days_since,
                    "n_claim_lines": n_lines,
                    "chronic_condition_count": claim.chronic_condition_count,
                    "service_date": claim.service_date,
                    "provider_npi": f"NPI{rng.randint(1000000, 9999999)}",
                    # Line-level
                    "hcpcs_code": line.hcpcs,
                    "modifier": line.modifier,
                    "line_diagnosis": line.diagnosis,
                    "submitted_charge": line.submitted_charge,
                    "prior_auth": int(line.prior_auth),
                    "line_number": line.line_number,
                    "line_role": line.line_role,
                    "in_global_surgery_period": int(claim.in_global_surgery_period),
                    # Derived (observable from claim)
                    "all_codes_on_claim": [l.hcpcs for l in claim.lines],
                },
                "label": "allowed" if result.paid else "denied",
                "metadata": {
                    "claim_id": claim.claim_id,
                    "rule_id": result.rule_id,
                    "primary_rule_id": result.rule_id,
                    "carc": result.carc,
                    "carc_desc": result.carc_desc,
                    "all_carcs": result.all_carcs,
                    "all_rule_ids": result.all_rule_ids,
                    "allowed_amount": result.allowed_amount,
                    "payment_amount": result.payment_amount,
                    "noise_type": result.noise_type,
                },
            })

    # ── Generate targeted claims for rare scenarios ──
    # Ensures minimum coverage of every rule
    targeted = [
        # R05: Modifier 59 required (isolated)
        *[_make_mod59_claim(rng, f"CLMR05{j:04d}") for j in range(200)],
        # R19: Assistant surgeon modifier missing (isolated)
        *[_make_assistant_surgeon_claim(rng, f"CLMR19{j:04d}") for j in range(200)],
        # R20: Global surgery period E&M without modifier 24 (isolated)
        *[_make_global_surgery_claim(rng, f"CLMR20{j:04d}") for j in range(200)],
        # R21: Unlisted code without documentation/auth (isolated)
        *[_make_unlisted_code_claim(rng, f"CLMR21{j:04d}") for j in range(200)],
        # R22: Utilization review scenario (isolated)
        *[_make_utilization_review_claim(rng, f"CLMR22{j:04d}") for j in range(200)],
        # BUG19: cardiology in ASC bug (isolated)
        *[_make_bug19_claim(rng, f"CLMBUG19{j:04d}") for j in range(200)],
        # R13: Therapy frequency limit (>4 therapy codes per claim)
        *[_make_therapy_claim(rng, f"CLMT{j:04d}") for j in range(200)],
        # R15: ESRD dialysis check (dialysis for non-ESRD)
        *[_make_dialysis_claim(rng, f"CLMD{j:04d}") for j in range(200)],
        # R06: Surgery in office (more cases)
        *[_make_surgery_office_claim(rng, f"CLMS{j:04d}") for j in range(200)],
    ]

    for claim in targeted:
        results = adjudicate_claim(claim)
        for line, result in zip(claim.lines, results):
            rule_counts[result.rule_id] = rule_counts.get(result.rule_id, 0) + 1
            all_results.append({
                "input": {
                    "provider_specialty": claim.provider_specialty,
                    "place_of_service": claim.place_of_service,
                    "primary_diagnosis": claim.primary_diagnosis,
                    "bene_age": claim.bene_age,
                    "bene_sex": claim.bene_sex,
                    "bene_state": claim.bene_state,
                    "bene_esrd": int(claim.bene_esrd),
                    "bene_hmo_months": claim.bene_hmo_months,
                    "days_since_service": claim.days_since_service,
                    "n_claim_lines": len(claim.lines),
                    "chronic_condition_count": claim.chronic_condition_count,
                    "service_date": claim.service_date,
                    "provider_npi": f"NPI{hash(claim.claim_id) % 10000000:07d}",
                    "hcpcs_code": line.hcpcs,
                    "modifier": line.modifier,
                    "line_diagnosis": line.diagnosis,
                    "submitted_charge": line.submitted_charge,
                    "prior_auth": int(line.prior_auth),
                    "line_number": line.line_number,
                    "line_role": line.line_role,
                    "in_global_surgery_period": int(claim.in_global_surgery_period),
                    "all_codes_on_claim": [l.hcpcs for l in claim.lines],
                },
                "label": "allowed" if result.paid else "denied",
                "metadata": {
                    "claim_id": claim.claim_id,
                    "rule_id": result.rule_id,
                    "primary_rule_id": result.rule_id,
                    "carc": result.carc,
                    "carc_desc": result.carc_desc,
                    "all_carcs": result.all_carcs,
                    "all_rule_ids": result.all_rule_ids,
                    "allowed_amount": result.allowed_amount,
                    "payment_amount": result.payment_amount,
                    "noise_type": result.noise_type,
                },
            })

    return all_results, rule_counts


def _make_therapy_claim(rng, claim_id):
    """Generate a claim with 5-6 therapy codes to trigger R13."""
    n_therapy = rng.randint(5, 6)
    codes = [rng.choice(["97110", "97140", "97530", "97001"]) for _ in range(n_therapy)]
    lines = [ClaimLine(hcpcs=c, submitted_charge=rng.uniform(40, 80), line_number=i+1)
             for i, c in enumerate(codes)]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="physical_therapy", place_of_service="11",
        primary_diagnosis="M54.5", lines=lines,
        bene_age=70, days_since_service=30,
    )


def _make_mod59_claim(rng, claim_id):
    """Generate two distinct surgeries where the second needs modifier 59."""
    lines = [
        ClaimLine(hcpcs="29881", submitted_charge=900, prior_auth=True, line_number=1),
        ClaimLine(hcpcs="43239", submitted_charge=850, prior_auth=True, line_number=2),
    ]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="general_surgery", place_of_service="22",
        primary_diagnosis="K21.0", lines=lines,
        bene_age=67, days_since_service=30,
    )


def _make_assistant_surgeon_claim(rng, claim_id):
    """Generate an assistant surgeon line missing the required modifier."""
    lines = [
        ClaimLine(hcpcs="27447", submitted_charge=1500, prior_auth=True, line_number=1, line_role="primary"),
        ClaimLine(hcpcs="27447", submitted_charge=900, prior_auth=True, line_number=2, line_role="assistant"),
        ClaimLine(hcpcs="43239", submitted_charge=800, prior_auth=True, line_number=3, line_role="primary"),
    ]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="orthopedic_surgery", place_of_service="22",
        primary_diagnosis="M17.11", lines=lines,
        bene_age=70, days_since_service=30,
    )


def _make_global_surgery_claim(rng, claim_id):
    """Generate a postop E&M in the global period without modifier 24."""
    lines = [
        ClaimLine(hcpcs="99213", submitted_charge=110, prior_auth=False, line_number=1),
    ]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="internal_medicine", place_of_service="11",
        primary_diagnosis="M17.11", lines=lines,
        bene_age=72, days_since_service=14,
        in_global_surgery_period=True,
    )


def _make_unlisted_code_claim(rng, claim_id):
    """Generate an unlisted procedure without documentation/auth."""
    lines = [
        ClaimLine(hcpcs="64999", submitted_charge=550, prior_auth=False, line_number=1),
    ]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="general_surgery", place_of_service="22",
        primary_diagnosis="G89.29", lines=lines,
        bene_age=64, days_since_service=30,
    )


def _make_utilization_review_claim(rng, claim_id):
    """Generate an elderly new-patient E&M with high chronic burden."""
    lines = [
        ClaimLine(hcpcs="99205", submitted_charge=240, prior_auth=False, line_number=1),
    ]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="internal_medicine", place_of_service="11",
        primary_diagnosis="I10", lines=lines,
        bene_age=90, days_since_service=30, chronic_condition_count=7,
    )


def _make_bug19_claim(rng, claim_id):
    """Generate the planted cardiology-in-ASC bug without confounders."""
    lines = [
        ClaimLine(hcpcs="93306", submitted_charge=320, prior_auth=False, line_number=1),
    ]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="cardiology", place_of_service="24",
        primary_diagnosis="I10", lines=lines,
        bene_age=68, days_since_service=30,
    )


def _make_dialysis_claim(rng, claim_id):
    """Generate dialysis claims for non-ESRD patients to trigger R15."""
    code = rng.choice(["90935", "90937", "90945", "90947"])
    lines = [ClaimLine(hcpcs=code, submitted_charge=rng.uniform(200, 400), line_number=1)]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="internal_medicine", place_of_service="65",
        primary_diagnosis="N18.3", lines=lines,
        bene_age=72, bene_esrd=False, days_since_service=30,
    )


def _make_surgery_office_claim(rng, claim_id):
    """Generate surgery-in-office claims to trigger R06."""
    code = rng.choice(["29881", "27447", "43239", "27130"])
    lines = [ClaimLine(hcpcs=code, submitted_charge=rng.uniform(800, 2000),
                        prior_auth=True, line_number=1)]
    return Claim(
        claim_id=claim_id, service_date="20240315",
        provider_specialty="orthopedic_surgery", place_of_service="11",
        primary_diagnosis="M17.11", lines=lines,
        bene_age=68, days_since_service=30,
    )


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating 50,000 claims...")
    results, rule_counts = generate_claims(50000)

    n_paid = sum(1 for r in results if r["label"] == "allowed")
    n_denied = sum(1 for r in results if r["label"] == "denied")
    total = len(results)
    print(f"  Total line items: {total:,}")
    print(f"  Paid: {n_paid:,} ({n_paid/total*100:.1f}%)")
    print(f"  Denied: {n_denied:,} ({n_denied/total*100:.1f}%)")

    print(f"\n  Rule firing counts:")
    for rule_id, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        manifest = RULE_MANIFEST.get(rule_id, {})
        rtype = manifest.get("type", "")
        marker = " ← BUG" if "BUG" in rule_id else ""
        if rule_id != "PAID":
            print(f"    {rule_id:30s} {count:>6,}  ({count/total*100:.1f}%)  [{rtype}]{marker}")

    # Save
    (DATA_DIR / "adjudicated_claims.json").write_text(json.dumps(results, indent=2))
    print(f"\n  Saved to {DATA_DIR / 'adjudicated_claims.json'}")
    print(f"  File size: {(DATA_DIR / 'adjudicated_claims.json').stat().st_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
