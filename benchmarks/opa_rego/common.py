from __future__ import annotations

import csv
import random
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BENCHMARK_DIR / "output"
POLICY_PATH = BENCHMARK_DIR / "policy.rego"
OPA_ALLOW_QUERY = "data.authz.allow"

FEATURE_COLUMNS = [
    "is_admin",
    "is_contractor",
    "team_match",
    "is_public",
    "archived",
    "sensitivity",
    "action_read",
    "action_write",
    "action_delete",
    "is_authenticated",
]

ROLES = ["viewer", "editor", "admin", "contractor"]
ROLE_LEVELS = {"viewer": 0, "editor": 1, "admin": 2, "contractor": 0}
TEAMS = ["engineering", "finance", "legal"]
ACTIONS = ["read", "write", "delete"]


def generate_raw_requests(count: int, *, seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    return [_generate_raw_request(rng) for _ in range(count)]


def _generate_raw_request(rng: random.Random) -> dict:
    role = rng.choice(ROLES)
    team = rng.choice(TEAMS)
    owner_team = rng.choice(TEAMS)
    action = rng.choice(ACTIONS)
    return {
        "user": {
            "role": role,
            "role_level": ROLE_LEVELS[role],
            "team": team,
            "is_authenticated": rng.random() > 0.05,
        },
        "resource": {
            "owner_team": owner_team,
            "visibility": rng.choice(["public", "private"]),
            "archived": rng.random() < 0.1,
            "sensitivity": rng.randint(0, 3),
        },
        "action": action,
        "context": {
            "failed_attempts": rng.randint(0, 10),
            "concurrent_sessions": rng.randint(1, 6),
            "is_business_hours": rng.random() > 0.3,
        },
    }


def observe_authz_request(raw_input: dict) -> dict[str, float]:
    role = raw_input["user"]["role"]
    return {
        "is_admin": float(role == "admin"),
        "is_contractor": float(role == "contractor"),
        "team_match": float(raw_input["user"]["team"] == raw_input["resource"]["owner_team"]),
        "is_public": float(raw_input["resource"]["visibility"] == "public"),
        "archived": float(raw_input["resource"]["archived"]),
        "sensitivity": float(raw_input["resource"]["sensitivity"]),
        "action_read": float(raw_input["action"] == "read"),
        "action_write": float(raw_input["action"] == "write"),
        "action_delete": float(raw_input["action"] == "delete"),
        "is_authenticated": float(raw_input["user"]["is_authenticated"]),
    }


def write_decision_traces_csv(
    observed_rows: list[dict[str, float]], allowed_rows: list[bool], output_path: Path
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*FEATURE_COLUMNS, "allowed"])
        writer.writeheader()
        for observed, allowed in zip(observed_rows, allowed_rows):
            row = {column: observed[column] for column in FEATURE_COLUMNS}
            row["allowed"] = "true" if allowed else "false"
            writer.writerow(row)
