from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from logicpearl.domains.opa import evaluate_rego_query, infer_rego_policy_metadata


pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")


def test_infer_rego_policy_metadata_reads_package_and_rules() -> None:
    policy_path = Path(__file__).resolve().parents[2] / "benchmarks" / "opa_rego" / "policy.rego"
    metadata = infer_rego_policy_metadata(policy_path)
    assert metadata.package == "authz"
    assert "allow" in metadata.rule_names
    assert "deny" in metadata.rule_names
    assert "allow" in metadata.default_rules


def test_evaluate_rego_query_returns_boolean_allow() -> None:
    policy_path = Path(__file__).resolve().parents[2] / "benchmarks" / "opa_rego" / "policy.rego"
    allowed = evaluate_rego_query(
        policy_path,
        query="data.authz.allow",
        input_data={
            "user": {"role": "viewer", "role_level": 0, "team": "engineering", "is_authenticated": True},
            "resource": {"owner_team": "engineering", "visibility": "public", "archived": False, "sensitivity": 0},
            "action": "read",
            "context": {"failed_attempts": 0, "concurrent_sessions": 1, "is_business_hours": True},
        },
    )
    assert allowed is True
