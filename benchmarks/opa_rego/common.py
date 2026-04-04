from __future__ import annotations

import random
from pathlib import Path

from logicpearl.engine import Condition, Rule, RuleSource, VerificationStatus

BENCHMARK_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BENCHMARK_DIR / "output"
POLICY_PATH = BENCHMARK_DIR / "policy.rego"

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
    failed = float(raw_input["context"]["failed_attempts"])
    concurrent = float(raw_input["context"]["concurrent_sessions"])
    role = raw_input["user"]["role"]
    return {
        "role_level": float(ROLE_LEVELS[role]),
        "is_admin": float(role == "admin"),
        "is_contractor": float(role == "contractor"),
        "team_match": float(raw_input["user"]["team"] == raw_input["resource"]["owner_team"]),
        "is_public": float(raw_input["resource"]["visibility"] == "public"),
        "archived": float(raw_input["resource"]["archived"]),
        "sensitivity": float(raw_input["resource"]["sensitivity"]),
        "action_read": float(raw_input["action"] == "read"),
        "action_write": float(raw_input["action"] == "write"),
        "action_delete": float(raw_input["action"] == "delete"),
        "failed_attempts": failed,
        "concurrent_sessions": concurrent,
        "is_business_hours": float(raw_input["context"]["is_business_hours"]),
        "is_authenticated": float(raw_input["user"]["is_authenticated"]),
        "risk_score": failed * 2 + concurrent * 3,
    }


def build_demo_rules() -> list[Rule]:
    return [
        _demo_rule(
            "archived_admin_requires_explicit_allow",
            [("archived", ">", 0.5), ("is_admin", ">", 0.5)],
        ),
        _demo_rule(
            "archived_read_only",
            [("archived", ">", 0.5), ("action_read", "<=", 0.5)],
        ),
        _demo_rule(
            "contractor_read_only",
            [("is_contractor", ">", 0.5), ("action_read", "<=", 0.5)],
        ),
        _demo_rule(
            "team_boundary_non_admin",
            [("team_match", "<=", 0.5), ("is_public", "<=", 0.5), ("is_admin", "<=", 0.5)],
        ),
        _demo_rule(
            "team_boundary_archived_admin",
            [("team_match", "<=", 0.5), ("is_public", "<=", 0.5), ("archived", ">", 0.5)],
        ),
        _demo_rule(
            "minimum_role_write",
            [("action_write", ">", 0.5), ("role_level", "<=", 0.5)],
        ),
        _demo_rule(
            "minimum_role_delete",
            [("action_delete", ">", 0.5), ("role_level", "<=", 1.5)],
        ),
        _demo_rule(
            "brute_force_non_admin",
            [("failed_attempts", ">", 5.0), ("concurrent_sessions", ">", 3.0), ("is_admin", "<=", 0.5)],
        ),
        _demo_rule(
            "brute_force_archived_admin",
            [("failed_attempts", ">", 5.0), ("concurrent_sessions", ">", 3.0), ("archived", ">", 0.5)],
        ),
        _demo_rule(
            "risk_score_exceeded_non_admin",
            [("risk_score", ">", 15.0), ("is_admin", "<=", 0.5)],
        ),
        _demo_rule(
            "risk_score_exceeded_archived_admin",
            [("risk_score", ">", 15.0), ("archived", ">", 0.5)],
        ),
        _demo_rule(
            "off_hours_sensitive",
            [("is_business_hours", "<=", 0.5), ("sensitivity", ">", 1.0), ("is_admin", "<=", 0.5)],
        ),
        _demo_rule(
            "unauthenticated_sensitive_non_admin",
            [("is_authenticated", "<=", 0.5), ("sensitivity", ">", 0.0), ("is_admin", "<=", 0.5)],
        ),
        _demo_rule(
            "unauthenticated_sensitive_archived_admin",
            [("is_authenticated", "<=", 0.5), ("sensitivity", ">", 0.0), ("archived", ">", 0.5)],
        ),
    ]


def condition_count(rules: list[Rule]) -> int:
    return sum(len(rule.conditions) for rule in rules)


def _demo_rule(rule_id: str, condition_specs: list[tuple[str, str, float]]) -> Rule:
    return Rule(
        rule_id=rule_id,
        source=RuleSource.PINNED,
        verification_status=VerificationStatus.HEURISTIC_UNVERIFIED,
        conditions=[
            Condition(feature=feature, operator=operator, threshold=threshold)
            for feature, operator, threshold in condition_specs
        ],
    )
